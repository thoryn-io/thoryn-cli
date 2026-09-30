package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3435 — what `thoryn project init` refuses, and what it never does: no change when `gh` is missing or
 * signed out (the manual commands are printed instead), no v1 template, the scope ceiling (locally and as
 * product-api's 403), and no credential ever handed to `gh` or printed.
 */
class ProjectInitSafetyTest : ProjectTestBase() {

    @Test
    fun `gh missing prints the commands with the Thoryn values filled in and changes nothing`() {
        val envId = api.seedSandbox("dev")
        gh.installed = false

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("the GitHub CLI (gh) is not installed. Nothing was changed")
            .contains("Install gh (https://cli.github.com) and run `gh auth login`")
            .contains("then re-run: thoryn project init app --stack express --environment dev --repo acme/web")
            .contains("gh repo create acme/web --template thoryn-io/starter-express --private")
            .contains("thoryn access grant client:<sandbox client id> manager environment:$envId")
            .contains("gh variable set THORYN_ISSUER --body https://auth.stg.thoryn.org --repo acme/web")
            .contains("gh variable set THORYN_WORKSPACE --body acme --repo acme/web")
            .contains("gh variable set THORYN_ENVIRONMENT --body dev --repo acme/web")
        assertThat(api.writes).isEmpty()
        assertThat(gh.calls.map { it.args }).containsExactly(listOf("--version"))
    }

    @Test
    fun `gh signed out stops the config project before any change, with the manual steps as JSON`() {
        gh.signedIn = false

        val (exit, out, _) = runCli(
            "project", "init", "config", "--reviewer", "alice", "--confirm-production", "--repo", "acme/platform", "--json",
        )

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "gh_not_signed_in").containsEntry("changed", false)
        @Suppress("UNCHECKED_CAST")
        assertThat(body["manualSteps"] as List<String>).anyMatch { it.startsWith("gh api --method PUT repos/acme/platform/environments/thoryn-production") }
            .anyMatch { it == "thoryn access grant client:<production client id> manager workspace:${FakeProjectApi.TENANT_ID}" }
            .anyMatch { it.startsWith("thoryn env create --slug sandbox") }
        assertThat(api.writes).isEmpty()
        assertThat(gh.mutations).isEmpty()
    }

    @Test
    fun `a v1 template is refused before any change`() {
        api.seedSandbox("dev")
        publishTemplate("thoryn-io/starter-express", resource("template-v1.json"), APP_FILES)

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("declares apiVersion 'thoryn.io/starter-template/v1'; this CLI needs thoryn.io/starter-template/v2")
            .contains("Nothing was changed")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an empty, not yet published template repository is refused before any change`() {
        publishTemplate("thoryn-io/starter-config", null, emptyMap())

        val (exit, _, err) = runCli("project", "init", "config", "--reviewer", "alice", "--confirm-production", "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("has no .thoryn/template.json on its default branch").contains("may not be published yet")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a scope the session does not hold is refused locally before any change`() {
        api.seedSandbox("dev")
        val narrow = ALL_SCOPES.replace("tenant:users.write ", "")
        seedTokens(Tokens(accessToken = jwt(mapOf("tnt" to FakeProjectApi.TENANT_ID, "scope" to narrow)), gateway = baseUrl(), workspace = "acme"))

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("Your session does not hold tenant:users.write").contains("thoryn login")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `product-api's 403 scope_not_grantable is rendered with the transitive-scope explanation and the step`() {
        api.seedSandbox("dev")
        api.notGrantable += "tenant:users.write"
        val dir = clone("acme/web")

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())

        assertThat(exit).isEqualTo(ProjectInit.EXIT_HTTP)
        assertThat(err).contains("scope_not_grantable").contains("Caller does not hold these scopes and therefore cannot grant them: tenant:users.write")
            .contains("A trust can carry only tenant: scopes your own session holds")
            .contains("(during the workload-trust step)")
        assertThat(gh.variables).isEmpty()
    }

    @Test
    fun `no credential is ever passed to gh or printed, and a token in gh's error output is redacted`() {
        api.seedSandbox("dev")
        gh.failVariablesWith = "HTTP 403: Resource not accessible by integration (token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789)"

        val failed = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")
        gh.failVariablesWith = null
        val done = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--json")

        assertThat(failed.exit).isEqualTo(ProjectInit.EXIT_GH)
        assertThat(failed.err).contains("the variables step failed").contains("[redacted]").doesNotContain("ghp_AbCdEf")
        assertThat(done.exit).describedAs(done.err).isEqualTo(0)
        val sent = everythingSentToGh()
        listOf(accessToken, "RT-test-refresh", "AT-test").forEach { secret ->
            assertThat(sent).doesNotContain(secret)
            assertThat(failed.out + failed.err + done.out + done.err).doesNotContain(secret)
        }
        assertThat(sent).doesNotContainPattern("gh[pousr]_|github_pat_|--token|GH_TOKEN|GITHUB_TOKEN")
        assertThat(ProcessGhRunner.EXTRA_ENV.keys).containsExactly("GH_PROMPT_DISABLED")
        // Thoryn's own bearer only ever goes to product-api.
        assertThat(api.authorizations).allMatch { it == "Bearer $accessToken" }
    }

    @Test
    fun `flags that do not go together are refused as usage errors`() {
        val publicClone = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--public")
        assertThat(publicClone.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(publicClone.err).contains("--public applies when --repo creates a repository")

        val forceRepo = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--force")
        assertThat(forceRepo.exit).isEqualTo(ProjectInit.EXIT_USAGE)

        val badRepo = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "web")
        assertThat(badRepo.err).contains("--repo must be <owner>/<name>")
        assertThat(gh.calls).isEmpty()
    }

    @Test
    fun `outside a git clone and without --repo it is refused before any change`() {
        api.seedSandbox("dev")

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", tempHome.toString())

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("is not the root of a git clone")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `not signed in to Thoryn exits 1 before gh is touched`() {
        clearTokens()

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).isEqualTo(1)
        assertThat(err).contains("Not signed in")
        assertThat(gh.calls).isEmpty()
    }
}
