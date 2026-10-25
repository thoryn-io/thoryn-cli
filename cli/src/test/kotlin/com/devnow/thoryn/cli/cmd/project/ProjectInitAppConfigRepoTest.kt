package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.cmd.provision.ProvisionYamlEdit
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3669 (ADR 2026-10-13 production-clients-declared-in-the-config-project §1) — `thoryn project init app
 * --config-repo <owner>/<name> --production-url <url>`: after the sandbox steps, the app's PRODUCTION client is
 * proposed as a pull request on the CONFIG repository from the deterministic branch `thoryn/app-<app repo>` — added to
 * `.thoryn/environments/production/provision.yaml`, converged by `name`, with its `publishTo` block — never merged,
 * never on the default branch, never a second pull request on a re-run, and nothing at all when the config repository
 * is unreachable or already declares the entry.
 */
class ProjectInitAppConfigRepoTest : ProjectTestBase() {

    private val json = JsonMapper.builder().build()
    private val path = ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE
    private val url = "https://web.acme.example"
    private val args = arrayOf("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--config-repo", "acme/platform", "--production-url", url)

    /** The config repository's production section as `thoryn project init config` seeds it: a comment header and the sandbox environment. */
    private val production = """
        |# Seeded by `thoryn project init config` (SSO-3435) for acme/platform — the PRODUCTION section.
        |apiVersion: thoryn.io/provision/v1
        |resources:
        |  # The workspace's sandbox, adopted by its slug.
        |  - kind: environment
        |    name: dev
        |    spec:
        |      slug: dev
        |      displayName: "Sandbox dev"
        |
    """.trimMargin()

    @BeforeEach
    fun seedConfigRepository() {
        api.seedSandbox("dev")
        gh.seedRepo("acme/platform")
        gh.files["acme/platform"] = mutableMapOf(path to production)
    }

    private fun branchFile(): String = gh.branches.getValue("acme/platform@thoryn/app-web").getValue(path)

    private fun pullRequestBody(): String =
        gh.calls.first { it.args.take(3) == listOf("api", "--method", "POST") && it.args[3] == "repos/acme/platform/pulls" }.args.first { it.startsWith("body=") }

    @Test
    fun `after the sandbox steps the production client is proposed on the config repository with the ADR entry and its publishTo block`() {
        val (exit, out, err) = runCli(*args, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        // One pull request, from the deterministic branch; the default branch untouched.
        assertThat(gh.pulls.getValue("acme/platform")).containsExactly(java.util.Map.entry("thoryn/app-web", "https://github.com/acme/platform/pull/1"))
        assertThat(gh.files.getValue("acme/platform").getValue(path)).isEqualTo(production)
        // The branch's file: everything that was there (comments included), then the entry.
        val content = branchFile()
        assertThat(content).startsWith(production).contains("# Production OAuth client of the application repository acme/web")
        val parsed = ProvisionFile.parse(content.toByteArray(), path)
        assertThat(parsed.resources.map { it.key }).containsExactly("environment/dev", "application/web")
        val app = parsed.resources[1]
        assertThat(app.environment).describedAs("no environment: the production plane").isNull()
        assertThat(app.spec).containsEntry("displayName", "acme/web").containsEntry("clientType", "public")
            .containsEntry("grantTypes", listOf("authorization_code")).containsEntry("scopes", listOf("openid", "profile", "email"))
            .containsEntry("redirectUris", listOf("$url/callback")).containsEntry("postLogoutRedirectUris", listOf("$url/signed-out"))
        assertThat(app.publishTo.single().label).isEqualTo("githubActionsVariable acme/web (environment production) THORYN_PRODUCTION_CLIENT_ID")
        // The reviewer is told what they approve.
        assertThat(pullRequestBody()).contains("PUBLIC client").contains("`$url/callback`").contains("`$url/signed-out`")
            .contains("`THORYN_PRODUCTION_CLIENT_ID` on the `production` environment of acme/web").contains("never opens a second one")
        // Order: the config repository is READ at pre-flight (before the app repository exists), WRITTEN only after the sandbox steps.
        val calls = gh.invocations
        val preflightRead = calls.indexOf("gh api repos/acme/platform/contents/$path")
        val generate = calls.indexOfFirst { it.contains("repos/thoryn-io/starter-express/generate") }
        val seeded = calls.indexOf("gh api --method PUT repos/acme/web/contents/.thoryn/provision.yaml --input -")
        val branch = calls.indexOf("gh api --method POST repos/acme/platform/git/refs -f ref=refs/heads/thoryn/app-web -f sha=commit-main")
        assertThat(preflightRead).isGreaterThan(calls.indexOf("gh api repos/acme/platform")).isLessThan(generate)
        assertThat(branch).isGreaterThan(seeded)
        assertThat(calls.drop(branch)).containsSubsequence(
            "gh api repos/acme/platform/contents/$path?ref=thoryn/app-web",
            "gh api --method PUT repos/acme/platform/contents/$path --input -",
            "gh api repos/acme/platform/pulls?head=acme:thoryn/app-web&state=open",
        )
        assertThat(api.trusts).allMatch { it["environment"] == "dev" } // the app still never gets a production trust
        // The report.
        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val cp = report["configProject"] as Map<String, Any?>
        assertThat(cp).containsEntry("repository", "acme/platform").containsEntry("file", path).containsEntry("branch", "thoryn/app-web")
            .containsEntry("pullRequest", "https://github.com/acme/platform/pull/1").containsEntry("outcome", "added").containsEntry("changed", true)
        @Suppress("UNCHECKED_CAST")
        assertThat((cp["application"] as Map<String, Any?>)["redirectUris"]).isEqualTo(listOf("$url/callback"))
        @Suppress("UNCHECKED_CAST")
        val steps = (report["steps"] as List<Map<String, Any?>>).associate { it["step"] as String to it["status"] as String }
        assertThat(steps).containsEntry("config-project", "pending review")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["nextSteps"] as List<String>).anyMatch { it.startsWith("Production client pending review: https://github.com/acme/platform/pull/1") && it.contains("THORYN_PRODUCTION_CLIENT_ID") }
    }

    @Test
    fun `a re-run updates the same branch and pull request and writes nothing when nothing changed`() {
        val first = runCli(*args)
        assertThat(first.exit).describedAs(first.err).isEqualTo(0)
        assertThat(first.out).startsWith("Set up the app project acme/web")
        val ghMutations = gh.mutations.size
        val apiWrites = api.writes.size
        val content = branchFile()

        val second = runCli(*args, "--json")

        assertThat(second.exit).describedAs(second.err).isEqualTo(0)
        assertThat(gh.mutations).describedAs("gh writes of the second run: ${gh.mutations.drop(ghMutations)}").hasSize(ghMutations)
        assertThat(api.writes).hasSize(apiWrites)
        assertThat(gh.pulls.getValue("acme/platform")).hasSize(1)
        assertThat(branchFile()).isEqualTo(content)
        val report = parseJson(second.out)
        @Suppress("UNCHECKED_CAST")
        val steps = (report["steps"] as List<Map<String, Any?>>).associate { it["step"] as String to it["status"] as String }
        assertThat(steps).containsEntry("config-project", "open")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["configProject"] as Map<String, Any?>).containsEntry("pullRequest", "https://github.com/acme/platform/pull/1").containsEntry("changed", false)
        // It did read: the branch, its copy of the file, and the open pull request.
        assertThat(gh.invocations.drop(gh.invocations.lastIndexOf("gh api repos/acme/platform/git/ref/heads/thoryn/app-web")))
            .contains("gh api repos/acme/platform/contents/$path?ref=thoryn/app-web", "gh api repos/acme/platform/pulls?head=acme:thoryn/app-web&state=open")

        val third = runCli(*args)
        assertThat(third.out).startsWith("Checked the app project acme/web")
        assertThat(gh.mutations).hasSize(ghMutations)
    }

    @Test
    fun `a config repository gh cannot see stops before any write with the by-hand steps, and is never created`() {
        val (exit, out, _) = runCli(
            "project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web",
            "--config-repo", "acme/nope", "--production-url", url, "--json",
        )

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "config_repository_not_found").containsEntry("changed", false).containsEntry("configRepository", "acme/nope")
        assertThat(body["hint"] as String).contains("never creates the config repository").contains("thoryn project init config --repo acme/nope")
        @Suppress("UNCHECKED_CAST")
        val manual = body["manualSteps"] as List<String>
        assertThat(manual).anyMatch { it.startsWith("gh repo clone acme/nope") && it.endsWith("git switch -c thoryn/app-web") }
            .anyMatch { it.startsWith("# append to $path") && it.contains("  - kind: application\n    name: web\n") && it.contains("THORYN_PRODUCTION_CLIENT_ID") && it.contains("$url/callback") }
            .anyMatch { it.contains("gh pr create --repo acme/nope") }
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
        assertThat(gh.repos).doesNotContainKeys("acme/web", "acme/nope")
        assertThat(gh.invocations).contains("gh api repos/acme/nope").noneMatch { it.contains("generate") }

        // gh signed out: the existing stop, and the config-repository pull request is one of the printed commands.
        gh.signedIn = false
        val signedOut = runCli(*args, "--json")
        assertThat(signedOut.exit).isEqualTo(ProjectInit.EXIT_CHECK)
        @Suppress("UNCHECKED_CAST")
        assertThat(parseJson(signedOut.out)["manualSteps"] as List<String>).anyMatch { it.contains("gh pr create --repo acme/platform") }
            .anyMatch { it.contains("name: web") && it.contains("repository: acme/web") }
        assertThat(gh.mutations).isEmpty()
    }

    @Test
    fun `a config repository that already declares the entry as it must be gets no pull request and no write`() {
        val entry = ProjectSeeds.productionClientEntry("acme/web", url)
        gh.files.getValue("acme/platform")[path] = production + ProvisionYamlEdit.fragment(json.createArrayNode().add(entry))

        val (exit, out, err) = runCli(*args, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.pulls).doesNotContainKey("acme/platform")
        assertThat(gh.mutations).noneMatch { it.contains("acme/platform") }
        assertThat(gh.branches).doesNotContainKey("acme/platform@thoryn/app-web")
        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val steps = (report["steps"] as List<Map<String, Any?>>).associate { it["step"] as String to it["status"] as String }
        assertThat(steps).containsEntry("config-project", "declared")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["configProject"] as Map<String, Any?>).containsEntry("outcome", "declared").containsEntry("pullRequest", null).containsEntry("changed", false)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["nextSteps"] as List<String>).anyMatch { it.startsWith("acme/platform already declares the production client of acme/web") }
    }

    @Test
    fun `a config repository whose entry differs gets it replaced on the branch, the other resources kept`() {
        val stale = ProjectSeeds.productionClientEntry("acme/web", "https://old.acme.example")
        gh.files.getValue("acme/platform")[path] = production + ProvisionYamlEdit.fragment(json.createArrayNode().add(stale))

        val (exit, out, err) = runCli(*args)

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.pulls.getValue("acme/platform")).containsKey("thoryn/app-web")
        val content = branchFile()
        assertThat(content).doesNotContain("old.acme.example")
        val parsed = ProvisionFile.parse(content.toByteArray(), path)
        assertThat(parsed.resources.map { it.key }).containsExactly("environment/dev", "application/web")
        assertThat(parsed.resources[0].spec).containsEntry("slug", "dev").containsEntry("displayName", "Sandbox dev")
        assertThat(parsed.resources[1].spec).containsEntry("redirectUris", listOf("$url/callback")).containsEntry("postLogoutRedirectUris", listOf("$url/signed-out"))
        assertThat(parsed.resources[1].publishTo.single().repository).isEqualTo("acme/web")
        assertThat(out).contains("config-project").contains("pending review").contains("application web updated in acme/platform:$path")
            .contains("the file was re-rendered and its comments are not kept")
        assertThat(gh.files.getValue("acme/platform").getValue(path)).contains("old.acme.example") // the default branch is never written
    }

    @Test
    fun `the two flags go together, the URL is https, and the config repository is not the app repository`() {
        val noUrl = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--config-repo", "acme/platform")
        assertThat(noUrl.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(noUrl.err).contains("--production-url https://<where the app runs>")

        val noRepo = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--production-url", url)
        assertThat(noRepo.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(noRepo.err).contains("--production-url goes with --config-repo")

        val http = runCli(*args.dropLast(1).toTypedArray(), "http://web.acme.example", "--json")
        assertThat(http.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(parseJson(http.out)).containsEntry("error", "invalid_production_url")

        val self = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--config-repo", "acme/web", "--production-url", url)
        assertThat(self.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(self.err).contains("names the app repository itself")

        assertThat(gh.calls).isEmpty()
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `a config repository whose production file is a TENANT file refuses the production client — an application belongs in the app project (SSO-3962)`() {
        gh.files["acme/platform"] = mutableMapOf(path to production.replace("apiVersion: thoryn.io/provision/v1", "apiVersion: thoryn.io/tenant/v1"))

        val (exit, out, _) = runCli(*args, "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "config_provision_file_unusable").containsEntry("changed", false)
        assertThat(body["errorDescription"] as String)
            .contains("`application` is application provisioning; this is a tenant file (thoryn.io/tenant/v1)")
            .contains("Declare it in the application's own project")
        // Nothing was proposed: no branch, no pull request, the default branch as it was.
        assertThat(gh.pulls["acme/platform"].orEmpty()).isEmpty()
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }
}
