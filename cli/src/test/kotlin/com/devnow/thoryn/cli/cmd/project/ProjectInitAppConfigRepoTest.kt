package com.devnow.thoryn.cli.cmd.project

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-4079 (oauthy ADR 2026-10-25 decision 3) — `thoryn project init app --config-repo <owner>/<name>`: the CONFIG repository
 * declares the app's CI trusts. A pull request from the deterministic branch `thoryn/app-<app repo>` adds one
 * `kind: workloadIdentityTrust` per app trust — rendered as `thoryn provision import` renders a live trust — the production
 * trust to the production section, the sandbox trust to the section whose connection is that sandbox; converged by name, never
 * merged, never on the default branch, never a second pull request on a re-run. The retired production client (`kind:
 * application` + `publishTo`) is never proposed again.
 */
class ProjectInitAppConfigRepoTest : AppConfigRepoTestBase() {

    @Test
    fun `the config repository is proposed both trusts as import renders them, each in its plane's section`() {
        publishProductionDeclaration()

        val (exit, out, err) = runCli(*withConfig, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val appId = gh.repoId("acme/web")
        // One pull request, from the deterministic branch; the default branch untouched.
        assertThat(gh.pulls.getValue("acme/platform")).containsExactly(java.util.Map.entry("thoryn/app-web", "https://github.com/acme/platform/pull/1"))
        assertThat(gh.files.getValue("acme/platform").getValue(productionFile)).isEqualTo(productionSection)
        assertThat(gh.files.getValue("acme/platform").getValue(sandboxFile)).isEqualTo(sandboxSection)

        // The production section: everything that was there (comments included), then the production trust — no environment.
        val production = onBranch(productionFile)
        assertThat(production).startsWith(productionSection).contains("# PRODUCTION CI identity of the application repository acme/web")
            .doesNotContain("publishTo").doesNotContain("kind: application")
        val prod = parsed(production, productionFile).resources.single { it.kind == "workloadIdentityTrust" }
        assertThat(prod.name).isEqualTo("starter-production-$appId")
        assertThat(prod.environment).describedAs("the production plane").isNull()
        assertThat(prod.spec).containsEntry("provider", "github_actions").containsEntry("confirmProduction", true)
            .containsEntry("scopes", ProductionDeclaration.SCOPES).doesNotContainKey("plan")
        assertThat(prod.spec["github"]).isEqualTo(
            mapOf("repository" to "acme/web", "ownerId" to 900, "repositoryId" to appId.toInt(), "environment" to "production", "ref" to "refs/heads/main"),
        )

        // The sandbox section (its connection signs in to `dev`): the sandbox trust, under the name the file gives that sandbox.
        val sandbox = onBranch(sandboxFile)
        assertThat(sandbox).startsWith(sandboxSection).contains("# Sandbox `dev` CI identity of the application repository acme/web")
        val sb = parsed(sandbox, sandboxFile).resources.single { it.kind == "workloadIdentityTrust" }
        assertThat(sb.name).isEqualTo("starter-sandbox-$appId")
        assertThat(sb.environment).isEqualTo("dev-sandbox")
        assertThat(sb.spec).doesNotContainKey("confirmProduction")
        assertThat(sb.spec["github"]).isEqualTo(mapOf("repository" to "acme/web", "ownerId" to 900, "repositoryId" to appId.toInt()))
        assertThat(sb.spec["scopes"]).isEqualTo(appTrust("dev")["scopes"])

        // The rendering IS the engine's import rendering of the live trust (one shape, never a fork).
        val live = com.devnow.thoryn.provision.ProvisionEngine.trustSpecOf(json.valueToTree(appTrust("production")), production = true).first
        assertThat(prod.spec).isEqualTo(json.readValue(json.writeValueAsString(live), Map::class.java))

        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val cp = report["configProject"] as Map<String, Any?>
        assertThat(cp).containsEntry("repository", "acme/platform").containsEntry("branch", "thoryn/app-web")
            .containsEntry("pullRequest", "https://github.com/acme/platform/pull/1").containsEntry("outcome", "added").containsEntry("changed", true)
            .containsEntry("files", listOf(productionFile, sandboxFile)).doesNotContainKey("application")
        assertThat(cp["trusts"]).isEqualTo(
            listOf(
                mapOf("name" to "starter-sandbox-$appId", "environment" to "dev", "file" to sandboxFile, "outcome" to "added"),
                mapOf("name" to "starter-production-$appId", "environment" to "production", "file" to productionFile, "outcome" to "added"),
            ).sortedBy { it["file"] != productionFile },
        )
        assertThat(steps(report)).containsEntry("config-project", "pending review")
        val body = gh.calls.first { it.args.take(4) == listOf("api", "--method", "POST", "repos/acme/platform/pulls") }.args.first { it.startsWith("body=") }
        assertThat(body).contains("`starter-production-$appId`").contains("GitHub environment `production`").contains("ref `refs/heads/main`")
            .contains("never opens a second one").doesNotContain("publishTo")
    }

    @Test
    fun `with no section for the app's sandbox the sandbox trust goes to the production section with environment, and the file loads`() {
        publishProductionDeclaration()
        // The config project's sandbox section is for another sandbox: `dev` has no section of its own.
        api.seedSandbox("staging")
        gh.files.getValue("acme/platform")[".thoryn/environments/sandbox/connection.json"] =
            gh.files.getValue("acme/platform").getValue(".thoryn/environments/sandbox/connection.json").replace("/dev\"", "/staging\"")

        val (exit, _, err) = runCli(*withConfig)

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.branches.getValue("acme/platform@thoryn/app-web").getValue(sandboxFile)).isEqualTo(sandboxSection)
        val appId = gh.repoId("acme/web")
        val production = parsed(onBranch(productionFile), productionFile)
        assertThat(production.resources.map { it.key }).containsExactlyInAnyOrder(
            "environment/dev", "workloadIdentityTrust/starter-production-$appId", "workloadIdentityTrust/starter-sandbox-$appId",
        )
        // `environment:` is the name this file gives the sandbox (here: its slug), as import renders it.
        assertThat(production.resources.single { it.name == "starter-sandbox-$appId" }.environment).isEqualTo("dev")
        assertThat(production.resources.single { it.name == "starter-production-$appId" }.environment).isNull()
    }

    @Test
    fun `a re-run converges the same branch and pull request and writes nothing`() {
        publishProductionDeclaration()
        val first = runCli(*withConfig)
        assertThat(first.exit).describedAs(first.err).isEqualTo(0)
        assertThat(first.out).startsWith("Set up the app project acme/web")
        val ghMutations = gh.mutations.size
        val apiWrites = api.writes.size
        val production = onBranch(productionFile)

        val second = runCli(*withConfig, "--json")

        assertThat(second.exit).describedAs(second.err).isEqualTo(0)
        assertThat(gh.mutations).describedAs("gh writes of the second run: ${gh.mutations.drop(ghMutations)}").hasSize(ghMutations)
        assertThat(api.writes).describedAs("api writes of the second run: ${api.writes.drop(apiWrites)}").hasSize(apiWrites)
        assertThat(gh.pulls.getValue("acme/platform")).hasSize(1)
        assertThat(onBranch(productionFile)).isEqualTo(production)
        val report = parseJson(second.out)
        assertThat(steps(report)).containsEntry("config-project", "open").containsEntry("owner", "existing,existing")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["configProject"] as Map<String, Any?>).containsEntry("pullRequest", "https://github.com/acme/platform/pull/1").containsEntry("changed", false)
        assertThat(runCli(*withConfig).out).startsWith("Checked the app project acme/web")
    }

    @Test
    fun `a config repository that already declares both trusts as they are live gets no pull request`() {
        publishProductionDeclaration()
        assertThat(runCli(*withConfig).exit).isEqualTo(0)
        // The reviewer merged it: the default branch now holds the branch's files.
        gh.files.getValue("acme/platform")[productionFile] = onBranch(productionFile)
        gh.files.getValue("acme/platform")[sandboxFile] = onBranch(sandboxFile)
        gh.pulls.getValue("acme/platform").clear()
        gh.branches.remove("acme/platform@thoryn/app-web")
        val mutations = gh.mutations.size

        val (exit, out, err) = runCli(*withConfig, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.mutations).hasSize(mutations)
        assertThat(gh.pulls.getValue("acme/platform")).isEmpty()
        val report = parseJson(out)
        assertThat(steps(report)).containsEntry("config-project", "declared")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["configProject"] as Map<String, Any?>).containsEntry("outcome", "declared").containsEntry("pullRequest", null)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["nextSteps"] as List<String>).anyMatch { it == "acme/platform already declares acme/web's workload identity trusts as they are live." }
    }

    @Test
    fun `an entry that differs from the live trust is replaced on the branch, the other resources kept`() {
        publishProductionDeclaration()
        assertThat(runCli(*withConfig).exit).isEqualTo(0)
        val stale = onBranch(productionFile).replace("tenant:access.read", "tenant:users.read")
        gh.files.getValue("acme/platform")[productionFile] = stale

        val (exit, out, err) = runCli(*withConfig)

        assertThat(exit).describedAs(err).isEqualTo(0)
        val content = onBranch(productionFile)
        assertThat(content).doesNotContain("tenant:users.read")
        assertThat(parsed(content, productionFile).resources.map { it.key }).hasSize(2).first().isEqualTo("environment/dev")
        assertThat(out).contains("updated in $productionFile").contains("its file was re-rendered and its comments are not kept")
        assertThat(gh.files.getValue("acme/platform").getValue(productionFile)).isEqualTo(stale) // the default branch is never written
    }

    @Test
    fun `a config repository gh cannot see stops before any write with the trust YAML as the by-hand steps`() {
        publishProductionDeclaration()

        val (exit, out, _) = runCli(*app, "--config-repo", "acme/nope", "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "config_repository_not_found").containsEntry("changed", false).containsEntry("configRepository", "acme/nope")
        @Suppress("UNCHECKED_CAST")
        val manual = body["manualSteps"] as List<String>
        assertThat(manual).anyMatch { it.startsWith("gh repo clone acme/nope") && it.endsWith("git switch -c thoryn/app-web") }
            .anyMatch { it.startsWith("# append to $productionFile") && it.contains("kind: workloadIdentityTrust") && it.contains("repository: acme/web") && it.contains("confirmProduction: true") }
            .anyMatch { it.contains("gh pr create --repo acme/nope") }
            .anyMatch { it.contains("owner trust:<trust id>") }
            .noneMatch { it.contains("publishTo") || it.contains("kind: application") }
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
        assertThat(gh.repos).doesNotContainKeys("acme/web", "acme/nope")
    }

    @Test
    fun `a config section that cannot take the trusts stops before any write`() {
        publishProductionDeclaration()
        gh.files.getValue("acme/platform")[productionFile] =
            "apiVersion: thoryn.io/tenant/v1\nresources:\n  - kind: environment\n    name: dev\n    spec: {slug: dev}\nextra: true\n"

        val (exit, out, _) = runCli(*withConfig, "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(parseJson(out)).containsEntry("error", "config_provision_file_unusable").containsEntry("changed", false)
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `the flags - --production-url and --reviewer need --config-repo, the URL is https, the config repository is not the app repository`() {
        val noRepo = runCli(*app, "--production-url", url)
        assertThat(noRepo.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(noRepo.err).contains("--production-url goes with --config-repo")

        val reviewer = runCli(*app, "--reviewer", "alice")
        assertThat(reviewer.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(reviewer.err).contains("--reviewer protects the production environment")

        val http = runCli(*withConfig, "--production-url", "http://web.acme.example", "--json")
        assertThat(http.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(parseJson(http.out)).containsEntry("error", "invalid_production_url")

        val self = runCli(*app, "--config-repo", "acme/web")
        assertThat(self.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(self.err).contains("names the app repository itself")

        assertThat(gh.calls).isEmpty()
        assertThat(api.requests).isEmpty()
    }
}
