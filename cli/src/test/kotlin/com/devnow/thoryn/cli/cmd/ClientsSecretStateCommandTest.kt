package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

/**
 * SSO-3957 — `thoryn clients secret-state` and the legible `409 rotation_in_flight` on
 * `thoryn clients rotate-secret`, against a MockWebServer standing in for the api-gateway →
 * product-api `/api/v1/applications/{id}/secrets/state` surface (SSO-1028).
 *
 * The load-bearing assertions:
 *  - the state is read from the server and said in plain words (until when the previous secret works,
 *    whether a rotation is allowed now, from when otherwise), while `--output json` keeps the body as
 *    it arrived;
 *  - a 409 names the time the next rotation is allowed — from the 409's own hint when it has one and
 *    with NO extra request, from `secrets/state` when it has none — says the previous secret keeps
 *    working until then, points at the incident path, and keeps exit code 2.
 */
class ClientsSecretStateCommandTest : CommandTestBase() {

    private val inFlight = """{"previousSecretId":"sid-1","previousExpiresAt":"2026-06-10T10:00:00Z",
        "rotationAvailable":false,"rotationAvailableAt":"2026-06-10T10:00:00Z"}""".trimIndent()

    private val idle = """{"previousSecretId":null,"previousExpiresAt":null,"rotationAvailable":true,"rotationAvailableAt":null}"""

    // ── secret-state ────────────────────────────────────────────────────────────────────────────

    @Test
    fun `secret-state GETs the secrets state and says until when the previous secret works and from when a rotation is allowed`() {
        server.enqueue(jsonResponse(200, inFlight))

        val (exit, out, err) = runCli("clients", "secret-state", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(err).isEmpty()
        assertThat(out).contains("previousSecretId").contains("sid-1")
        assertThat(out).contains("previousExpiresAt").contains("2026-06-10T10:00:00Z")
        assertThat(out).contains("rotationAvailable").contains("false")
        assertThat(out).contains("A rotation is in flight")
        assertThat(out).contains("the previous secret keeps working until 2026-06-10T10:00:00Z")
        assertThat(out).contains("The next rotation is allowed from then")

        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1/secrets/state")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `secret-state with no rotation in flight says you can rotate now and shows absent fields as a dash`() {
        server.enqueue(jsonResponse(200, idle))

        val (exit, out, _) = runCli("clients", "secret-state", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("No rotation is in flight").contains("you can rotate now")
        assertThat(out).doesNotContain("keeps working until")
        // `previousSecretId` / `previousExpiresAt` / `rotationAvailableAt` are JSON null → `-`, never "(null)".
        assertThat(out).doesNotContain("(null)").doesNotContain("null")
        assertThat(out).contains("previousSecretId    = -")
    }

    @Test
    fun `secret-state --output json prints the server body as it arrived`() {
        server.enqueue(jsonResponse(200, inFlight))

        val (exit, out, _) = runCli("clients", "secret-state", "app-1", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val body = parseJson(out)
        assertThat(body.keys).containsExactlyInAnyOrder("previousSecretId", "previousExpiresAt", "rotationAvailable", "rotationAvailableAt")
        assertThat(body["previousSecretId"]).isEqualTo("sid-1")
        assertThat(body["previousExpiresAt"]).isEqualTo("2026-06-10T10:00:00Z")
        assertThat(body["rotationAvailable"]).isEqualTo(false)
        // No prose in the machine view — the summary is a table-only reading.
        assertThat(out).doesNotContain("rotation is in flight")
    }

    @Test
    fun `secret-state cross-tenant renders the 404 not_found problem detail`() {
        server.enqueue(jsonResponse(404, """{"errorCode":"not_found","detail":"Application 'app-x' does not exist for this tenant."}"""))

        val (exit, _, err) = runCli("clients", "secret-state", "app-x", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not_found")
    }

    @Test
    fun `secret-state is a read and names the read scope on insufficient_scope`() {
        server.enqueue(jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:applications.read"}"""))

        val (exit, _, err) = runCli("clients", "secret-state", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Required scope: tenant:applications.read")
    }

    @Test
    fun `clients usage advertises secret-state`() {
        val (exit, _, err) = runCli("clients")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("secret-state")
    }

    // ── rotate-secret: 409 rotation_in_flight ────────────────────────────────────────────────────

    @Test
    fun `rotate-secret 409 with the server's hint says from when, that the previous secret keeps working, and the incident path, with no second request`() {
        server.enqueue(
            jsonResponse(
                409,
                """{"errorCode":"rotation_in_flight",
                    "detail":"A rotation is already in flight for this client. The next rotation is available at 2026-06-10T10:00:00Z."}""".trimIndent(),
            ),
        )

        val (exit, out, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out).isEmpty()
        assertThat(err).contains("rotation_in_flight")
        assertThat(err).contains("The previous secret keeps working until 2026-06-10T10:00:00Z")
        assertThat(err).contains("The next rotation is allowed from then")
        assertThat(err).contains("To end the previous secret now: `thoryn clients revoke-previous-secret app-1`")
        assertThat(err).contains("To replace a lost new secret: `thoryn clients rotate-secret app-1 --replace`")
        assertThat(err).doesNotContain("README").doesNotContain("SSO-3956")
        // The hint was in the 409 itself — the CLI did not go back for the state.
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-1/secret/rotate")
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNull()
    }

    @Test
    fun `rotate-secret 409 without a hint reads secret-state for the time`() {
        server.enqueue(jsonResponse(409, """{"errorCode":"rotation_in_flight","detail":"A rotation is already in flight for this client."}"""))
        server.enqueue(jsonResponse(200, inFlight))

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("The previous secret keeps working until 2026-06-10T10:00:00Z")
        assertThat(err).contains("The next rotation is allowed from then")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-1/secret/rotate")
        val state = server.takeRequest()
        assertThat(state.method).isEqualTo("GET")
        assertThat(state.path).isEqualTo("/api/v1/applications/app-1/secrets/state")
    }

    @Test
    fun `rotate-secret 409 with neither a hint nor a readable state still says the previous secret works and names secret-state`() {
        server.enqueue(jsonResponse(409, """{"errorCode":"rotation_in_flight","detail":"A rotation is already in flight for this client."}"""))
        server.enqueue(jsonResponse(502, """{"errorCode":"hub_unavailable","detail":"hub call failed"}"""))

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("rotation_in_flight")
        assertThat(err).contains("The previous secret keeps working until its overlap window ends")
        assertThat(err).contains("thoryn clients secret-state app-1")
        assertThat(err).contains("To end the previous secret now: `thoryn clients revoke-previous-secret app-1`")
        // The failed state read is not a second error story.
        assertThat(err).doesNotContain("hub_unavailable")
    }

    @Test
    fun `rotate-secret 409 with a structured rotationAvailableAt member uses it ahead of the prose`() {
        server.enqueue(
            jsonResponse(
                409,
                """{"errorCode":"rotation_in_flight","detail":"A rotation is already in flight for this client.",
                    "rotationAvailableAt":"2026-07-01T08:30:00Z"}""".trimIndent(),
            ),
        )

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("The previous secret keeps working until 2026-07-01T08:30:00Z")
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNotNull()
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNull()
    }

    @Test
    fun `rotate-secret 409 in json output carries rotationAvailableAt and the hint next to the stable error`() {
        server.enqueue(
            jsonResponse(
                409,
                """{"errorCode":"rotation_in_flight",
                    "detail":"A rotation is already in flight for this client. The next rotation is available at 2026-06-10T10:00:00Z."}""".trimIndent(),
            ),
        )

        val (exit, out, err) = runCli("clients", "rotate-secret", "app-1", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).isEmpty()
        val body = parseJson(out)
        assertThat(body["error"]).isEqualTo("rotation_in_flight")
        assertThat(body["httpStatus"]).isEqualTo(409)
        assertThat(body["rotationAvailableAt"]).isEqualTo("2026-06-10T10:00:00Z")
        assertThat(body["hint"].toString())
            .contains("keeps working until 2026-06-10T10:00:00Z")
            .contains("To end the previous secret now: `thoryn clients revoke-previous-secret app-1`")
            .contains("To replace a lost new secret: `thoryn clients rotate-secret app-1 --replace`")
    }

    @Test
    fun `a 409 that is not rotation_in_flight keeps the generic error rendering`() {
        server.enqueue(jsonResponse(409, """{"errorCode":"some_other_conflict","detail":"Nope."}"""))

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: some_other_conflict — Nope.")
        assertThat(err).doesNotContain("keeps working")
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNotNull()
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNull()
    }
}
