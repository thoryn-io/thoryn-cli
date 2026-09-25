package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3303 — `thoryn domain add | status | verify | remove` against a MockWebServer standing in for the
 * api-gateway → product-api `/api/v1/custom-domain` surface (oathy SSO-3303).
 *
 * The response bodies under `src/test/resources/custom-domain/` are CAPTURED from product-api's real
 * `CustomDomainController` (MockMvc over the real security chain and Jackson), not hand-written — the
 * SSO-3082 lesson: a fixture fabricated in the wrong shape lets a parsing bug pass its own test.
 */
class DomainCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/custom-domain/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status)
            .setHeader("Content-Type", "application/problem+json")
            .setBody(fixture(name))

    // ── add ──────────────────────────────────────────────────────────────────

    @Test
    fun `add claims the host and prints the exact DNS records to create`() {
        server.enqueue(jsonResponse(200, fixture("claim-pending")))

        val (exit, out, _) = runCli("domain", "add", "auth.acme.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("auth.acme.com claimed (state: PENDING)")
            .contains("TXT").contains("_thoryn-verify.auth.acme.com").contains("thoryn-verify=tok")
            .contains("CNAME").contains("cd-ws.auth.thoryn.io")
            .contains("thoryn domain verify")
            .contains("2026-10-02T12:00:00Z")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("PUT")
        assertThat(req.path).isEqualTo("/api/v1/custom-domain")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        val body = parseJson(req.body.readUtf8())
        assertThat(body).containsEntry("domain", "auth.acme.com").containsEntry("acceptReSignIn", false)
    }

    @Test
    fun `add --accept-re-sign-in sends the explicit acceptance`() {
        server.enqueue(jsonResponse(200, fixture("claim-pending")))

        val (exit, _, _) = runCli("domain", "add", "auth.acme.com", "--accept-re-sign-in", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(server.takeRequest().body.readUtf8())).containsEntry("acceptReSignIn", true)
    }

    @Test
    fun `add --json emits the API response verbatim for scripts`() {
        server.enqueue(jsonResponse(200, fixture("claim-pending")))

        val (exit, out, _) = runCli("domain", "add", "auth.acme.com", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val parsed = parseJson(out)
        assertThat(parsed).containsEntry("state", "PENDING").containsEntry("domain", "auth.acme.com")
        @Suppress("UNCHECKED_CAST")
        val records = parsed["dnsRecords"] as List<Map<String, Any?>>
        assertThat(records.map { it["type"] }).containsExactly("TXT", "CNAME")
    }

    @Test
    fun `add with production users explains the re-sign-in flag`() {
        server.enqueue(problem(409, "problem-production-users"))

        val (exit, _, err) = runCli("domain", "add", "auth.acme.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("production_users_present").contains("--accept-re-sign-in")
    }

    @Test
    fun `add without the entitlement says so and does not suggest a scope login`() {
        server.enqueue(problem(403, "problem-entitlement"))

        val (exit, _, err) = runCli("domain", "add", "auth.acme.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("entitlement_required").contains("not enabled for this workspace")
        assertThat(err).doesNotContain("Required scope")
    }

    @Test
    fun `add of an apex domain surfaces domain_not_allowed with guidance`() {
        server.enqueue(problem(400, "problem-apex"))

        val (exit, _, err) = runCli("domain", "add", "acme.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("domain_not_allowed").contains("Apex domains are not supported")
    }

    @Test
    fun `add without write scope names the scope to log in with`() {
        server.enqueue(
            MockResponse().setResponseCode(403).setHeader("Content-Type", "application/json")
                .setBody("""{"errorCode":"insufficient_scope","detail":"Insufficient scope."}"""),
        )

        val (exit, _, err) = runCli("domain", "add", "auth.acme.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Required scope: tenant:domains.write")
    }

    // ── status ───────────────────────────────────────────────────────────────

    @Test
    fun `status with no domain says so and that the workspace is not entitled`() {
        server.enqueue(jsonResponse(200, fixture("status-none")))

        val (exit, out, _) = runCli("domain", "status", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("no custom domain").contains("not enabled for this workspace")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.path).isEqualTo("/api/v1/custom-domain")
    }

    @Test
    fun `status of a suspended domain shows the records, the issuer and why it stopped`() {
        server.enqueue(jsonResponse(200, fixture("status-suspended")))

        val (exit, out, _) = runCli("domain", "status", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("SUSPENDED")
            .contains("https://cd-ws.auth.thoryn.io")
            .contains("_thoryn-verify.auth.acme.com")
            .contains("CNAME points somewhere other than the workspace's platform host")
    }

    @Test
    fun `status --output yaml renders the record for scripts`() {
        server.enqueue(jsonResponse(200, fixture("status-suspended")))

        val (exit, out, _) = runCli("domain", "status", "--output", "yaml", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out.trimStart()).doesNotStartWith("{")
        assertThat(out).containsPattern("state: \"?SUSPENDED").containsPattern("reason: \"?cname_mismatch")
    }

    @Test
    fun `--json and a different --output are refused before any call`() {
        val (exit, _, err) = runCli("domain", "status", "--json", "--output", "yaml", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--json cannot be combined")
        assertThat(server.requestCount).isEqualTo(0)
    }

    // ── verify ───────────────────────────────────────────────────────────────

    @Test
    fun `verify reports VERIFIED and the pending certificate`() {
        server.enqueue(jsonResponse(200, fixture("verify-verified")))

        val (exit, out, _) = runCli("domain", "verify", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("VERIFIED").contains("certificate is being issued")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/custom-domain/verify")
    }

    @Test
    fun `verify that the DNS does not prove yet exits with the check-failed code`() {
        server.enqueue(problem(422, "problem-verification"))

        val (exit, _, err) = runCli("domain", "verify", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(err).contains("verification_failed").contains("no CNAME record")
    }

    @Test
    fun `verify failure in json mode is a structured error on stdout`() {
        server.enqueue(problem(422, "problem-verification"))

        val (exit, out, _) = runCli("domain", "verify", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(parseJson(out)).containsEntry("error", "verification_failed").containsEntry("httpStatus", 422)
    }

    // ── remove ───────────────────────────────────────────────────────────────

    @Test
    fun `remove --yes deletes without prompting`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("domain", "remove", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Custom domain removed.")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("DELETE")
        assertThat(req.path).isEqualTo("/api/v1/custom-domain")
    }

    @Test
    fun `remove without --yes and no terminal refuses and sends nothing`() {
        val (exit, _, err) = runCli("domain", "remove", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--yes")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `remove --yes --json emits a structured confirmation`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("domain", "remove", "--yes", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)).containsEntry("removed", true)
    }

    // ── session ──────────────────────────────────────────────────────────────

    @Test
    fun `without a session every subcommand asks you to sign in`() {
        clearTokens()

        val (exit, _, _) = runCli("domain", "status", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(server.requestCount).isEqualTo(0)
    }
}
