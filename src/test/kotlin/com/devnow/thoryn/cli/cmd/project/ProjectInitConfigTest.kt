package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-3435 — `thoryn project init config`: the workspace's config project — a production connection behind
 * required reviewers (manager of the workspace) and a sandbox connection (manager of the sandbox).
 */
class ProjectInitConfigTest : ProjectTestBase() {

    private val base = arrayOf("project", "init", "config", "--reviewer", "alice", "--reviewer", "bob", "--confirm-production")

    @Test
    fun `config from a new repository protects production before its variable, creates the sandbox, two trusts and both grants`() {
        val (exit, out, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val repoId = gh.repoId("acme/platform")
        val env = "repos/acme/platform/environments/thoryn-production"
        assertThat(gh.invocations).containsExactly(
            "gh --version",
            "gh auth status",
            "gh api repos/thoryn-io/starter-config/contents/.thoryn/template.json",
            "gh api repos/acme/platform",
            "gh api users/acme",
            "gh api users/alice",
            "gh api users/bob",
            "gh api --method POST repos/thoryn-io/starter-config/generate -f owner=acme -f name=platform -F private=true -f description=Thoryn config project: workspace acme",
            "gh api repos/acme/platform/branches/main",
            "gh api repos/acme/platform/contents/.github/CODEOWNERS",
            "gh api repos/acme/platform/rulesets",
            "gh api --method POST repos/acme/platform/rulesets --input -", // created disabled: CODEOWNERS is committed first
            "gh api --method PUT repos/acme/platform/contents/.github/CODEOWNERS --input -",
            "gh api --method PUT repos/acme/platform/rulesets/4200 --input -", // then enforced
            "gh api --method PUT $env --input -",
            "gh api $env/deployment-branch-policies",
            "gh api --method POST $env/deployment-branch-policies -f name=main -f type=branch",
            "gh variable set THORYN_ISSUER --body https://auth.stg.thoryn.org --repo acme/platform",
            "gh variable set THORYN_WORKSPACE --body acme --repo acme/platform",
            "gh variable set THORYN_SANDBOX_ENVIRONMENT --body sandbox --repo acme/platform",
            "gh variable set THORYN_SANDBOX_WIF_CLIENT_ID --body wi_client1 --repo acme/platform",
            "gh api repos/acme/platform/rulesets/4200", // the approval verified before the production variable
            "gh api $env",
            "gh variable set THORYN_PRODUCTION_WIF_CLIENT_ID --body wi_client2 --repo acme/platform --env thoryn-production",
        )
        assertThat(parseJson(gh.calls.first { it.args.contains("PUT") && it.args.contains(env) }.stdin!!)).isEqualTo(
            mapOf(
                "reviewers" to listOf(mapOf("type" to "User", "id" to 501), mapOf("type" to "User", "id" to 502)),
                "prevent_self_review" to false,
                "deployment_branch_policy" to mapOf("protected_branches" to false, "custom_branch_policies" to true),
            ),
        )
        assertThat(api.writes.map { "${it.method} ${it.path}${it.env?.let { e -> " [$e]" } ?: ""}" }).containsExactly(
            "POST /api/v1/environments",
            "POST /api/v1/workload-identity/trusts [sandbox]",
            "POST /api/v1/workload-identity/trusts [production]",
            "POST /api/v1/access/grants",
            "POST /api/v1/access/grants",
        )
        val production = api.trustsIn("production").single()
        assertThat(production["name"]).isEqualTo("starter-production-$repoId")
        assertThat(production["scopes"]).isEqualTo(listOf("tenant:environments.read", "tenant:environments.write", "tenant:idp.read", "tenant:idp.write"))
        @Suppress("UNCHECKED_CAST")
        assertThat(production["github"] as Map<String, Any?>).containsEntry("environment", "thoryn-production").containsEntry("ref", "refs/heads/main")
        assertThat(api.writes.first { it.env == "production" }.body).containsEntry("confirmProduction", true)
        @Suppress("UNCHECKED_CAST")
        assertThat(api.trustsIn("sandbox").single()["github"] as Map<String, Any?>).doesNotContainKeys("environment", "ref")
        assertThat(api.grants).containsExactly(
            mapOf("subject" to "client:wi_client1", "relation" to "manager", "object" to "environment:env-sandbox"),
            mapOf("subject" to "client:wi_client2", "relation" to "manager", "object" to "workspace:${FakeProjectApi.TENANT_ID}"),
        )
        assertThat(out).contains("Set up the config project acme/platform for workspace acme")
            .contains("GitHub environment thoryn-production: deploys from main only; required reviewers alice, bob")
            .contains("thoryn-production-approval on main: pull request with 1 approval + code-owner review")
            .contains("each production run also waits for approval by: alice, bob")
        assertThat(gh.files.getValue("acme/platform")[".github/CODEOWNERS"])
            .contains("/.thoryn/environments/production/ @alice @bob").contains("/.github/workflows/ @alice @bob")
        assertThat(gh.rulesets.getValue("acme/platform").values.single()["enforcement"]).isEqualTo("active")
    }

    @Test
    fun `config in an existing clone uses the named existing sandbox and adds the files`() {
        api.seedSandbox("staging")
        api.seedSandbox("qa")
        val dir = clone("acme/platform")

        val (exit, out, err) = runCli(*base, "--sandbox", "qa", "--dir", dir.toString())

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.writes.none { it.path == "/api/v1/environments" }).isTrue()
        assertThat(api.trustsIn("qa")).hasSize(1)
        assertThat(gh.variables).containsEntry("acme/platform:THORYN_SANDBOX_ENVIRONMENT", "qa")
            .containsEntry("acme/platform@thoryn-production:THORYN_PRODUCTION_WIF_CLIENT_ID", "wi_client2")
        assertThat(Files.exists(dir.resolve(".thoryn/environments/production/provision.yaml"))).isTrue()
        assertThat(out).contains("files").contains("6 added")
        assertThat(Files.readString(dir.resolve(".github/CODEOWNERS"))).contains("/.github/workflows/ @alice @bob")
        assertThat(gh.files["acme/platform"].orEmpty()).doesNotContainKey(".github/CODEOWNERS") // not committed: it lands with the pull request
        assertThat(gh.invocations).contains("gh api --method POST repos/acme/platform/rulesets --input -") // active at once, nothing to commit
            .noneMatch { it.contains("contents/.github/CODEOWNERS") }
        assertThat(out).contains("git switch -c thoryn-config").contains("gh pr create --fill")
    }

    @Test
    fun `re-running config converges an existing protection to the required shape and creates nothing twice`() {
        assertThat(runCli(*base, "--repo", "acme/platform").exit).isEqualTo(0)
        // Someone loosened the environment in between: an extra branch policy and a different reviewer.
        val env = gh.environments.getValue("acme/platform/thoryn-production")
        env.policies += 99L to "release/*"
        env.reviewers = listOf(777L)
        val writes = api.writes.size

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.invocations.count { it.contains("generate") }).isEqualTo(1)
        assertThat(gh.invocations).contains("gh api --method DELETE repos/acme/platform/environments/thoryn-production/deployment-branch-policies/99")
        assertThat(env.reviewers).containsExactly(501L, 502L)
        assertThat(env.policies.map { it.second }).containsExactly("main")
        assertThat(api.trusts).hasSize(2)
        assertThat(api.environments.count { it["slug"] == "sandbox" }).isEqualTo(1)
        assertThat(api.writes.drop(writes).map { it.path }).containsOnly("/api/v1/access/grants")
    }

    @Test
    fun `config without reviewers or without the production confirmation is refused before any call`() {
        val noReviewer = runCli("project", "init", "config", "--confirm-production", "--repo", "acme/platform")
        assertThat(noReviewer.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(noReviewer.err).contains("Name at least one --reviewer")

        val noConfirm = runCli("project", "init", "config", "--reviewer", "alice", "--repo", "acme/platform", "--json")
        assertThat(noConfirm.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(parseJson(noConfirm.out)).containsEntry("error", "production_confirmation_required")

        assertThat(gh.calls).isEmpty()
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `a reviewer who is not a GitHub user is refused before any change`() {
        val (exit, _, err) = runCli("project", "init", "config", "--reviewer", "ghost", "--confirm-production", "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("Not a GitHub user: ghost")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a machine session cannot set up a config project`() {
        seedTokens(Tokens(accessToken = accessToken, gateway = baseUrl(), workspace = "acme", authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS, clientId = "cli-ci"))

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("only a person may grant that")
        assertThat(gh.calls).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a caller who does not manage the workspace is refused before any change`() {
        api.mine.clear()

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("needs you to manage the workspace (acme)")
        assertThat(gh.calls).isEmpty()
    }

    @Test
    fun `several sandboxes and no --sandbox asks which one`() {
        api.seedSandbox("staging")
        api.seedSandbox("qa")

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(err).contains("several sandboxes (staging, qa)").contains("--sandbox <slug>")
        assertThat(gh.calls).isEmpty()
    }

    @Test
    fun `before the platform can grant workspace management the run stops at that grant, with no variable set`() {
        api.workspaceGrantUnavailable = true

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_HTTP)
        assertThat(err).contains("cannot yet grant a machine client workspace-wide management")
            .contains("Done before this stop").contains("Re-run the same command")
        assertThat(gh.variables).isEmpty()
        assertThat(api.grants).hasSize(1) // the sandbox grant

        // Once the platform supports it, the same command finishes, adopting everything made before.
        api.workspaceGrantUnavailable = false
        val retry = runCli(*base, "--repo", "acme/platform")
        assertThat(retry.exit).describedAs(retry.err).isEqualTo(0)
        assertThat(api.trusts).hasSize(2)
        assertThat(gh.variables).hasSize(5)
    }
}
