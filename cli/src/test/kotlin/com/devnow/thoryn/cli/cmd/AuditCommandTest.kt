package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-1552 — unit tests for `thoryn audit query` against a MockWebServer
 * standing in for the api-gateway → product-api `/audit/events` surface
 * (`tenant:audit.read`).
 */
class AuditCommandTest : CommandTestBase() {

    @Test
    fun `query hits the audit-events surface with filters as query params`() {
        server.enqueue(
            jsonResponse(
                200,
                """[
                  {"timestamp":"2026-06-09T10:00:00Z","action":"client.created","actorSub":"u-1","outcome":"OK","rowId":"r-1"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "audit", "query",
            "--from", "2026-06-01T00:00:00Z",
            "--event-type", "client.created",
            "--limit", "50",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("client.created").contains("u-1")

        val req = server.takeRequest()
        assertThat(req.path).startsWith("/api/v1/audit/events?")
        assertThat(req.path).contains("from=2026-06-01T00%3A00%3A00Z")
        assertThat(req.path).contains("eventType=client.created")
        assertThat(req.path).contains("limit=50")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `query with --output json prints the raw array`() {
        server.enqueue(jsonResponse(200, """[{"action":"login.success","actorSub":"u-2"}]"""))

        val (exit, out, _) = runCli("audit", "query", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("login.success")
        // Bare query with no filters → no query string.
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/audit/events")
    }

    @Test
    fun `a 501 not-implemented backend surfaces cleanly`() {
        // The audit-events query backend lands under epic SSO-725; until then the
        // server answers 501 and the thin CLI surfaces it without crashing.
        server.enqueue(
            jsonResponse(501, """{"error":"not_implemented","message":"audit query not yet implemented"}"""),
        )

        val (exit, _, err) = runCli("audit", "query", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not_implemented")
    }

    @Test
    fun `insufficient-scope prints the audit read-scope hint`() {
        server.enqueue(
            jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:audit.read"}"""),
        )

        val (exit, _, err) = runCli("audit", "query", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Run: oathy login --scope tenant:audit.read")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, err) = runCli("audit", "query", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }
}
