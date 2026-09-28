package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3308 — `thoryn workload-identity trusts create | list | get | delete` against a MockWebServer
 * standing in for the api-gateway → product-api `/api/v1/workload-identity/trusts` surface (oathy #3787,
 * SSO-3307). The fixtures under `src/test/resources/workload-identity/` follow product-api's
 * `WorkloadIdentityTrustResponse` / RFC 9457 problem shapes and error details on that branch.
 */
class WorkloadIdentityCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(fixture(name))

    private val trustId = "5b0f6c1e-8c2a-4f5e-9f3d-2a1b0c9d8e7f"

    // ── create ────────────────────────────────────────────────────────────────

    @Test
    fun `create sends the pins and scopes, and prints the binding plus a ready-to-paste workflow`() {
        server.enqueue(jsonResponse(201, fixture("trust-created")).setHeader("Location", "/api/v1/workload-identity/trusts/$trustId"))

        val (exit, out, _) = runCli(
            "workload-identity", "trusts", "create", "--name", "thoryn-cli-staging-check",
            "--repository", "thoryn-io/thoryn-cli", "--github-environment", "thoryn-staging-wif",
            "--github-hosted-runners-only", "--scope", "tenant:environments.read",
            "--environment", "cli-wif", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/workload-identity/trusts")
        assertThat(req.getHeader("X-Thoryn-Environment")).isEqualTo("cli-wif")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        val body = parseJson(req.body.readUtf8())
        assertThat(body).containsEntry("name", "thoryn-cli-staging-check")
            .containsEntry("provider", "github_actions")
            .containsEntry("scopes", listOf("tenant:environments.read"))
            .doesNotContainKey("confirmProduction") // omitted, not `null`/false
        @Suppress("UNCHECKED_CAST")
        val github = body["github"] as Map<String, Any?>
        assertThat(github).containsEntry("owner", "thoryn-io").containsEntry("repository", "thoryn-cli")
            .containsEntry("environment", "thoryn-staging-wif").containsEntry("githubHostedRunnersOnly", true)
            .doesNotContainKeys("ownerId", "repositoryId", "ref")

        assertThat(out)
            .contains("Workload identity trust 'thoryn-cli-staging-check' created")
            .contains("wi_3f0c9a1b2d4e5f6a7b8c9d0e")
            .contains("https://thoryn.auth.stg.thoryn.org/cli-wif")
            .contains("id-token: write")
            .contains("environment: thoryn-staging-wif")
            .contains(
                "thoryn login --workload-identity --client-id wi_3f0c9a1b2d4e5f6a7b8c9d0e " +
                    "--audience https://thoryn.auth.stg.thoryn.org/cli-wif --scope \"tenant:environments.read\"",
            )
            .contains("\"method\": \"workload_identity\"")
            .contains("\"slug\": \"thoryn\"")
            .doesNotContain("--token-endpoint") // the default one need not be passed
    }

    @Test
    fun `create passes both GitHub ids, the ref and the production confirmation`() {
        server.enqueue(jsonResponse(201, fixture("trust-created")))

        val (exit, _, _) = runCli(
            "workload-identity", "trusts", "create", "--name", "deploy", "--repository", "acme/billing",
            "--owner-id", "11", "--repository-id", "22", "--ref", "refs/heads/main", "--github-environment", "production",
            "--scope", "tenant:applications.write,tenant:applications.read", "--confirm-production", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val body = parseJson(server.takeRequest().body.readUtf8())
        assertThat(body).containsEntry("confirmProduction", true)
            .containsEntry("scopes", listOf("tenant:applications.write", "tenant:applications.read"))
        @Suppress("UNCHECKED_CAST")
        assertThat(body["github"] as Map<String, Any?>).containsEntry("ownerId", 11).containsEntry("repositoryId", 22)
            .containsEntry("ref", "refs/heads/main")
    }

    @Test
    fun `create refuses locally what the API would refuse — one id without the other, a non-tenant scope, a bad repository`() {
        val oneId = runCli("workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--owner-id", "1", "--scope", "tenant:x.read", "--gateway", baseUrl())
        assertThat(oneId.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(oneId.err).contains("--owner-id and --repository-id go together")

        val foreign = runCli("workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--scope", "openid", "--gateway", baseUrl())
        assertThat(foreign.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(foreign.err).contains("only workspace (tenant:) scopes")

        val badRepo = runCli("workload-identity", "trusts", "create", "--name", "n", "--repository", "billing", "--scope", "tenant:x.read", "--gateway", baseUrl())
        assertThat(badRepo.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(badRepo.err).contains("--repository must be <owner>/<repo>")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `403 scope_not_grantable explains the transitive rule instead of a login-scope hint`() {
        server.enqueue(problem(403, "problem-scope-not-grantable"))

        val (exit, _, err) = runCli(
            "workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--scope", "tenant:users.write", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("scope_not_grantable").contains("only tenant: scopes your own session holds")
            .doesNotContain("Required scope:")
    }

    @Test
    fun `400 production_confirmation_required points at --confirm-production, not the --confirm header guard`() {
        server.enqueue(problem(400, "problem-production-confirmation"))

        val (exit, _, err) = runCli(
            "workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--github-environment", "production",
            "--scope", "tenant:x.read", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Re-run with --confirm-production").doesNotContain("--confirm <your-workspace-slug>")
    }

    @Test
    fun `409 name taken is rendered with its errorCode and a hint, and --json carries the code`() {
        server.enqueue(problem(409, "problem-name-taken"))
        val table = runCli("workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--scope", "tenant:x.read", "--gateway", baseUrl())
        assertThat(table.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(table.err).contains("workload_identity_trust_name_taken").contains("Choose another --name")

        server.enqueue(problem(409, "problem-name-taken"))
        val json = runCli("workload-identity", "trusts", "create", "--name", "n", "--repository", "a/b", "--scope", "tenant:x.read", "--gateway", baseUrl(), "--json")
        assertThat(parseJson(json.out)).containsEntry("error", "workload_identity_trust_name_taken").containsEntry("httpStatus", 409)
    }

    // ── list / get / delete ───────────────────────────────────────────────────

    @Test
    fun `list prints one row per trust and the next-page cursor`() {
        server.enqueue(jsonResponse(200, fixture("trust-list")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "list", "--limit", "1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/workload-identity/trusts?limit=1")
        assertThat(out).contains("thoryn-cli-staging-check").contains("wi_3f0c9a1b2d4e5f6a7b8c9d0e")
            .contains("thoryn-io/thoryn-cli").contains("thoryn-staging-wif")
            .contains("thoryn workload-identity trusts list --cursor c-2")
    }

    @Test
    fun `get prints the trust and the exact sign-in line`() {
        server.enqueue(jsonResponse(200, fixture("trust-created")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", trustId, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/workload-identity/trusts/$trustId")
        assertThat(out).contains("owner 187654321 / repository 1044556677")
            .contains("thoryn login --workload-identity --client-id wi_3f0c9a1b2d4e5f6a7b8c9d0e --audience https://thoryn.auth.stg.thoryn.org/cli-wif")
    }

    @Test
    fun `get of an unknown or unreachable trust is a 404 with guidance`() {
        server.enqueue(problem(404, "problem-not-found"))

        val (exit, _, err) = runCli("workload-identity", "trusts", "get", trustId, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("workload_identity_trust_not_found").contains("trusts list")
    }

    @Test
    fun `delete --yes removes the trust and forwards a production confirmation`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("workload-identity", "trusts", "delete", trustId, "--yes", "--confirm", "thoryn", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("DELETE")
        assertThat(req.path).isEqualTo("/api/v1/workload-identity/trusts/$trustId")
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("thoryn")
        assertThat(out).contains("deleted")
    }

    @Test
    fun `delete without --yes on a non-interactive terminal refuses and sends nothing`() {
        val (exit, _, err) = runCli("workload-identity", "trusts", "delete", trustId, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("re-run with --yes")
        assertThat(server.requestCount).isZero()
    }
}
