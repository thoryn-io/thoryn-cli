package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-3568 — **once the CLI has said "sign in again", that must be the last thing it says.**
 *
 * The reported run was `thoryn provision apply` against staging with a session the hub refused to
 * renew. It printed the correct, actionable line and then carried on with the dead session:
 *
 * ```
 * Could not renew your sign-in session (Hub returned 400: invalid_grant). Run `thoryn login --workspace thoryn` to sign in again.
 * Error: application/forge-oauth2-proxy: could not read live state (HTTP 401: invalid_token - DPoP proof has already been used.)
 * ```
 *
 * The last line is the one a reader keeps, and it points at an RFC 9449 protocol fault — an hour in
 * the hub's replay cache before noticing the line above it. These tests pin the three things that
 * stops: the resource call is never attempted, the exit is non-zero, and the final diagnostic is the
 * sign-in instruction.
 *
 * **The DPoP half of that output was NOT the CLI's fault** and is not re-litigated here (see
 * [com.devnow.thoryn.cli.auth.DpopProofUniquenessTest] for the CLI-side invariant that settles it).
 */
class CommandSupportDeadSessionTest : CommandTestBase() {

    private val expired = System.currentTimeMillis() / 1000 - 60

    @BeforeEach
    fun warmTheKeyStore() {
        // `client()` / `gatewayClient()` resolve `Dpop.session()` eagerly, and the first resolution in
        // a JVM logs the plaintext-key-store warning through java.util.logging — straight at whatever
        // `System.err` is installed, which inside `runCli` is the stream these tests read. Resolving it
        // here, OUTSIDE the captured window, makes it land on the real stderr once and keeps the
        // assertions about what the COMMAND said. Without this the last line a test sees depends on
        // which test in the class happened to run first.
        Dpop.session()
    }

    private fun deadSession() = Tokens(
        accessToken = "AT-expired",
        refreshToken = "RT-refused",
        expiresAtEpochSecond = expired,
        issuer = baseUrl(),
        gateway = baseUrl(),
        clientId = "cli",
        workspace = "thoryn",
    )

    /**
     * The last DIAGNOSTIC on stderr — what the user is left holding.
     *
     * Environment notices are filtered out: the plaintext-key-store `WARNING:` (this fixture has no
     * keychain) and the `Note:` the DPoP degrade prints are statements about the machine, emitted
     * once per process whenever a client happens to be built first, not answers about this command.
     * Including them would make the assertion depend on test-execution order rather than on the
     * behaviour under test.
     */
    private fun finalMessage(err: String): String =
        err.trim().lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("WARNING:") && !it.startsWith("Note:") }
            .last()

    @Test
    fun `a renewal refused with invalid_grant stops before the resource call`() {
        seedTokens(deadSession())
        // The ONLY response this fixture offers is the refusal of the renewal. A command that goes on
        // to call the gateway therefore has nothing to consume — and `takeRequest` below proves it
        // never tried, rather than inferring it from whatever a second response would have produced.
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}"""))

        val (exit, _, err) = runCli("clients", "list", "--gateway", baseUrl())

        assertThat(exit).isNotZero()
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/token")

        assertThat(finalMessage(err))
            .contains("Could not renew your sign-in session")
            .contains("thoryn login --workspace thoryn")
        // The whole point: no second, more-memorable, wronger story after it.
        assertThat(err).doesNotContain("Error:").doesNotContain("Request failed")
    }

    @Test
    fun `provision apply on a refused renewal ends on the sign-in instruction, not on a live-state read`() {
        // The reported command. `ProvisionEngine` wraps a refused read into "<resource>: could not read
        // live state (…)", which is right for a real API failure and was the misleading final line here.
        seedTokens(deadSession())
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}""")) // the renewal
        // The reported second error, queued so the unfixed path CAN reach it. With the fix it is never
        // consumed — `requestCount` below is what proves the resource call was not attempted, rather
        // than an empty queue making the test pass for the wrong reason.
        server.enqueue(jsonResponse(401, """{"error":"invalid_token","error_description":"DPoP proof has already been used."}"""))
        val file = tempHome.resolve("provision.yaml")
        file.toFile().writeText(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-oauth2-proxy
                spec: { displayName: "Forge OAuth2 Proxy", redirectUris: ["https://forge.example.org/oauth2/callback"] }
            """.trimIndent(),
        )

        val (exit, _, err) = runCli("provision", "apply", "--file", file.toString(), "--yes", "--gateway", baseUrl())

        assertThat(exit).isNotZero()
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/token")
        assertThat(err).contains("Could not renew your sign-in session").contains("thoryn login --workspace thoryn")
        // The regression itself: the wrapper that made a dead session look like a DPoP protocol fault.
        assertThat(err)
            .doesNotContain("could not read live state")
            .doesNotContain("DPoP proof has already been used")
            .doesNotContain("Error:")
    }

    @Test
    fun `a renewal refused on the reactive 401 path also ends on the sign-in instruction`() {
        // The access token still looks fresh, so nothing is renewed up front: the gateway rejects it,
        // the on-401 reauthenticator runs, and THAT is refused. Before SSO-3568 the original 401 was
        // re-raised and rendered, putting `Error: invalid_token` after the guidance.
        seedTokens(deadSession().copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900))
        server.enqueue(jsonResponse(401, """{"error":"invalid_token","error_description":"DPoP proof has already been used."}"""))
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}"""))

        val (exit, _, err) = runCli("clients", "list", "--gateway", baseUrl())

        assertThat(exit).isNotZero()
        assertThat(finalMessage(err)).contains("thoryn login --workspace thoryn")
        // The misleading description the hub sent must not be the CLI's closing word.
        assertThat(err).doesNotContain("DPoP proof has already been used")
    }

    @Test
    fun `a refused renewal carries the guidance as a structured hint under --output json`() {
        // A script cannot read a stderr line. JSON/YAML keep the stable `errorCode` + `hint` so
        // `thoryn … --output json` can branch on "go and sign in" rather than on a 401.
        seedTokens(deadSession())
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}"""))

        val (exit, out, _) = runCli("clients", "list", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isNotZero()
        val body = parseJson(out)
        assertThat(body["error"]).isEqualTo("session_cannot_be_renewed")
        assertThat(body["hint"] as String).contains("thoryn login --workspace thoryn")
    }

    @Test
    fun `a session that renews normally is untouched by the refusal path`() {
        // The guard must not fire on the happy path: a renewable session renews and the call proceeds.
        seedTokens(deadSession())
        server.enqueue(jsonResponse(200, """{"access_token":"AT-new","refresh_token":"RT-2","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"data":[],"pagination":{}}"""))

        val (exit, _, err) = runCli("clients", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(server.requestCount).isEqualTo(2)
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/token")
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer AT-new")
        assertThat(err).isEmpty()
    }
}
