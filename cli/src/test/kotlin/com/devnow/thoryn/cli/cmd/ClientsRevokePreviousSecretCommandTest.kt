package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

/**
 * SSO-3967 — `thoryn clients revoke-previous-secret` and `thoryn clients rotate-secret --replace`,
 * against a MockWebServer standing in for the api-gateway → product-api surface of SSO-3956
 * (`POST /api/v1/applications/{id}/secret/revoke-previous`, `…/secret/rotate` with `replaceInFlight`).
 *
 * The load-bearing assertions:
 *  - the wire shape: the path, the `revokeTokens` / `replaceInFlight` body flags, the production
 *    confirmation header (and no header when none is given), and an unchanged empty body for an
 *    ordinary rotation;
 *  - the words: what no longer works and what still does, from the SERVER's booleans (idempotent 200,
 *    tokens revoked and how many), with `--output json` carrying the body verbatim;
 *  - the two elevated-act refusals: `403 insufficient_user_authentication` names the exact re-login
 *    (the same guidance `trusts set-scopes` prints) and `403 elevated_action_requires_person` says a
 *    machine identity cannot do this — neither claims a missing caller scope;
 *  - `404` cross-tenant, `428` without `--confirm` — the same as every other destructive act.
 */
class ClientsRevokePreviousSecretCommandTest : CommandTestBase() {

    private val revoked = """{"previousSecretId":"sid-1","previousSecretRevoked":true,"tokensRevoked":false,
        "revokedAuthorizations":0,"rotationAvailable":true}""".trimIndent()

    private val revokedWithTokens = """{"previousSecretId":"sid-1","previousSecretRevoked":true,"tokensRevoked":true,
        "revokedAuthorizations":3,"rotationAvailable":true}""".trimIndent()

    private val nothingInFlight = """{"previousSecretId":null,"previousSecretRevoked":false,"tokensRevoked":false,
        "revokedAuthorizations":0,"rotationAvailable":true}""".trimIndent()

    private val rotated = """{"newSecret":"replacement-once","newSecretId":"sid-3","previousSecretId":"sid-1",
        "oldSecretExpiresAt":"2026-06-10T10:00:00Z"}""".trimIndent()

    private fun stepUpChallenge(): MockResponse =
        jsonResponse(
            403,
            """{"errorCode":"insufficient_user_authentication","detail":"A higher level of authentication is required."}""",
        ).setHeader(
            "WWW-Authenticate",
            "Bearer error=\"insufficient_user_authentication\", error_description=\"A higher level of authentication is required\", " +
                "acr_values=\"urn:thoryn:acr:phishing_resistant\", max_age=\"300\"",
        )

    private fun personOnly(): MockResponse =
        jsonResponse(
            403,
            """{"errorCode":"elevated_action_requires_person","detail":"This action requires a person's sign-in."}""",
        )

    // ── revoke-previous-secret: the wire ─────────────────────────────────────────────────────────

    @Test
    fun `revoke-previous-secret POSTs revoke-previous with revokeTokens false, the confirmation header, and says only the current secret signs in`() {
        server.enqueue(jsonResponse(200, revoked))

        val (exit, out, err) = runCli("clients", "revoke-previous-secret", "app-1", "--confirm", "acme-prod", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(err).isEmpty()
        assertThat(out).contains("The previous secret no longer works. Only the current secret signs in.")
        assertThat(out).doesNotContain("live sessions/tokens")

        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1/secret/revoke-previous")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("acme-prod")
        assertThat(parseJson(req.body.readUtf8())).isEqualTo(mapOf("revokeTokens" to false))
    }

    @Test
    fun `revoke-previous-secret without --confirm sends no confirmation header (sandbox stays frictionless)`() {
        server.enqueue(jsonResponse(200, revoked))

        val (exit, _, _) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().getHeader("X-Thoryn-Confirm")).isNull()
    }

    @Test
    fun `revoke-previous-secret --revoke-tokens sends revokeTokens true and counts what was revoked`() {
        server.enqueue(jsonResponse(200, revokedWithTokens))

        val (exit, out, _) = runCli("clients", "revoke-previous-secret", "app-1", "--revoke-tokens", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("The previous secret no longer works. Only the current secret signs in.")
        assertThat(out).contains(
            "3 live sessions/tokens of this client were revoked (self-contained access tokens already issued stay valid until they expire).",
        )
        assertThat(parseJson(server.takeRequest().body.readUtf8())).isEqualTo(mapOf("revokeTokens" to true))
    }

    @Test
    fun `revoke-previous-secret with nothing in flight is idempotent and says nothing changed`() {
        server.enqueue(jsonResponse(200, nothingInFlight))

        val (exit, out, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(err).isEmpty()
        assertThat(out).contains("There was no previous secret; nothing changed.")
        assertThat(out).doesNotContain("no longer works")
    }

    @Test
    fun `revoke-previous-secret reports token revocation from the server, not from the flag`() {
        // --revoke-tokens asked, but nothing was in flight so the server revoked no tokens either.
        server.enqueue(jsonResponse(200, nothingInFlight))

        val (exit, out, _) = runCli("clients", "revoke-previous-secret", "app-1", "--revoke-tokens", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("There was no previous secret; nothing changed.")
        assertThat(out).doesNotContain("live sessions/tokens")
    }

    @Test
    fun `revoke-previous-secret --output json prints the server body as it arrived`() {
        server.enqueue(jsonResponse(200, revokedWithTokens))

        val (exit, out, err) = runCli("clients", "revoke-previous-secret", "app-1", "--revoke-tokens", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(err).isEmpty()
        val body = parseJson(out)
        assertThat(body.keys).containsExactlyInAnyOrder(
            "previousSecretId", "previousSecretRevoked", "tokensRevoked", "revokedAuthorizations", "rotationAvailable",
        )
        assertThat(body["previousSecretId"]).isEqualTo("sid-1")
        assertThat(body["previousSecretRevoked"]).isEqualTo(true)
        assertThat(body["tokensRevoked"]).isEqualTo(true)
        assertThat(body["revokedAuthorizations"]).isEqualTo(3)
        assertThat(body["rotationAvailable"]).isEqualTo(true)
        // No prose in the machine view.
        assertThat(out).doesNotContain("no longer works")
    }

    // ── revoke-previous-secret: the refusals ─────────────────────────────────────────────────────

    @Test
    fun `revoke-previous-secret without a fresh passkey sign-in prints the RFC 9470 re-login and no scope hint`() {
        server.enqueue(stepUpChallenge())

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("insufficient_user_authentication")
            .contains("Ending the previous secret now needs a passkey sign-in from the last 5 minutes. Sign in again, then retry:")
            .contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .doesNotContain("Required scope")
            .doesNotContain("thoryn login --scope")
    }

    @Test
    fun `revoke-previous-secret by a machine identity says a workspace admin must do it and no scope hint`() {
        server.enqueue(personOnly())

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("elevated_action_requires_person")
            .contains("a machine identity (API key, workload identity) cannot do this")
            .contains("A workspace admin must run it")
            .doesNotContain("Required scope")
            .doesNotContain("thoryn login --scope")
    }

    @Test
    fun `revoke-previous-secret with a missing scope still names the write scope`() {
        server.enqueue(jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:applications.write"}"""))

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Required scope: tenant:applications.write")
        assertThat(err).doesNotContain("passkey")
    }

    @Test
    fun `revoke-previous-secret cross-tenant renders the 404 not_found problem detail`() {
        server.enqueue(jsonResponse(404, """{"errorCode":"not_found","detail":"Application 'app-x' does not exist for this tenant."}"""))

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-x", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not_found")
    }

    @Test
    fun `revoke-previous-secret on a production workspace without --confirm surfaces the 428 guidance`() {
        server.enqueue(
            jsonResponse(
                428,
                """{"errorCode":"production_confirmation_required","title":"Production Confirmation Required",
                    "detail":"This action targets your production environment."}""".trimIndent(),
            ),
        )

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("production workspace").contains("--confirm")
    }

    @Test
    fun `revoke-previous-secret 403 step-up in json output carries the stable error and no scope fields`() {
        server.enqueue(stepUpChallenge())

        val (exit, out, _) = runCli("clients", "revoke-previous-secret", "app-1", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val body = parseJson(out)
        assertThat(body["error"]).isEqualTo("insufficient_user_authentication")
        assertThat(body["httpStatus"]).isEqualTo(403)
        assertThat(body).doesNotContainKeys("requiredScope", "loginHint")
    }

    // ── rotate-secret --replace ──────────────────────────────────────────────────────────────────

    @Test
    fun `rotate-secret --replace sends replaceInFlight true and emits the replacement through the secret path`() {
        server.enqueue(jsonResponse(200, rotated))
        val secretFile = tempHome.resolve("replacement.txt").toFile()

        val (exit, out, _) = runCli(
            "clients", "rotate-secret", "app-1", "--replace",
            "--confirm", "acme-prod",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("newSecretId").contains("sid-3")
        assertThat(out).contains("previousSecretId").contains("sid-1")
        assertThat(out).contains("oldSecretExpiresAt").contains("2026-06-10T10:00:00Z")
        assertThat(out).doesNotContain("replacement-once")
        assertThat(secretFile.readText().trim()).isEqualTo("replacement-once")

        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1/secret/rotate")
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("acme-prod")
        assertThat(parseJson(req.body.readUtf8())).isEqualTo(mapOf("replaceInFlight" to true))
    }

    @Test
    fun `rotate-secret without --replace keeps sending the empty body the ordinary rotation always sent`() {
        server.enqueue(jsonResponse(200, rotated))
        val secretFile = tempHome.resolve("rotated.txt").toFile()

        val (exit, _, _) = runCli("clients", "rotate-secret", "app-1", "--secret-file", secretFile.path, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(server.takeRequest().body.readUtf8())).isEmpty()
    }

    @Test
    fun `rotate-secret --replace without a fresh passkey sign-in prints the RFC 9470 re-login and no scope hint`() {
        server.enqueue(stepUpChallenge())

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--replace", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("insufficient_user_authentication")
            .contains("Replacing a rotation in flight needs a passkey sign-in from the last 5 minutes. Sign in again, then retry:")
            .contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .doesNotContain("Required scope")
        // The 403 is rendered as a step-up, not as a 409: no state read follows.
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNotNull()
        assertThat(server.takeRequest(200, TimeUnit.MILLISECONDS)).isNull()
    }

    @Test
    fun `rotate-secret --replace by a machine identity says a workspace admin must do it`() {
        server.enqueue(personOnly())

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--replace", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("elevated_action_requires_person")
            .contains("Replacing a rotation in flight is a person's act")
            .doesNotContain("Required scope")
    }

    @Test
    fun `the step-up guidance follows the challenge's own acr_values and max_age when they differ`() {
        server.enqueue(
            jsonResponse(403, """{"errorCode":"insufficient_user_authentication","detail":"Step up."}""").setHeader(
                "WWW-Authenticate",
                "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:example:acr:hardware\", max_age=\"120\"",
            ),
        )

        val (exit, _, err) = runCli("clients", "revoke-previous-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("from the last 2 minutes")
            .contains("thoryn login --acr-values urn:example:acr:hardware --max-age 120")
    }

    // ── the hint replacement (SSO-3957 → SSO-3967) ───────────────────────────────────────────────

    @Test
    fun `an in-flight secret-state names the two commands that end the window early`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"previousSecretId":"sid-1","previousExpiresAt":"2026-06-10T10:00:00Z",
                    "rotationAvailable":false,"rotationAvailableAt":"2026-06-10T10:00:00Z"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("clients", "secret-state", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("A rotation is in flight")
            .contains("To end the previous secret now: `thoryn clients revoke-previous-secret app-1`")
            .contains("To replace a lost new secret: `thoryn clients rotate-secret app-1 --replace`")
    }

    @Test
    fun `an idle secret-state does not name the incident commands`() {
        server.enqueue(jsonResponse(200, """{"previousSecretId":null,"previousExpiresAt":null,"rotationAvailable":true,"rotationAvailableAt":null}"""))

        val (exit, out, _) = runCli("clients", "secret-state", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("you can rotate now").doesNotContain("revoke-previous-secret")
    }

    @Test
    fun `the clients usage line and help list revoke-previous-secret and --replace`() {
        val (_, _, usageErr) = runCli("clients")
        assertThat(usageErr).contains("revoke-previous-secret")

        val (helpExit, helpOut, _) = runCli("clients", "rotate-secret", "--help")
        assertThat(helpExit).isEqualTo(0)
        assertThat(helpOut).contains("--replace").contains("the superseded")

        val (revokeHelpExit, revokeHelpOut, _) = runCli("clients", "revoke-previous-secret", "--help")
        assertThat(revokeHelpExit).isEqualTo(0)
        assertThat(revokeHelpOut).contains("--revoke-tokens").contains("--confirm")
    }
}
