package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLDecoder

/**
 * SSO-3182 — session renewal for a THORYN-HOMED interactive session.
 *
 * The reported symptom: after the ~15-minute access token expired, `thoryn workspace list` answered a
 * bare `Error: HTTP 401` and `provision apply` stopped with "Could not enter workspace … your session
 * may have expired", with no hint that a fresh sign-in was the fix. These tests pin the three paths:
 * a refreshable session renews itself (and re-enters the workspace), a rejected refresh names the exact
 * re-login command, and a session that never received a refresh token says so instead of failing mute.
 */
class CommandSupportRefreshTest : CommandTestBase() {

    private val expired = System.currentTimeMillis() / 1000 - 60

    @BeforeEach
    fun resetHint() {
        CommandSupport.resetSessionHintForTest()
    }

    private fun err() = ByteArrayOutputStream()

    @Test
    fun `an expired home token is refreshed, then the workspace re-entry exchange succeeds`() {
        val base = Tokens(
            accessToken = "AT-old",
            refreshToken = "RT-1",
            expiresAtEpochSecond = expired,
            issuer = baseUrl(),
            gateway = baseUrl(),
            clientId = "cli",
            workspace = "thoryn",
        )
        seedTokens(base)
        val selected = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selected.write(SelectedWorkspace(tenantId = "t-1", slug = "examples", tenantHubIssuer = "https://examples.hub.example.org"))

        // 1) refresh_token redemption, 2) the workspace token exchange, 3) the gateway call.
        server.enqueue(jsonResponse(200, """{"access_token":"AT-new","refresh_token":"RT-2","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"data":[],"pagination":{}}"""))

        val out = err()
        CommandSupport.gatewayClient(baseUrl(), base, selected, PrintStream(out)).listApplications()

        val refresh = server.takeRequest()
        assertThat(refresh.path).isEqualTo("/oauth2/token")
        val refreshBody = URLDecoder.decode(refresh.body.readUtf8(), Charsets.UTF_8)
        assertThat(refreshBody).contains("grant_type=refresh_token").contains("refresh_token=RT-1").contains("client_id=cli")

        // The exchange used the REFRESHED access token as the subject, and the gateway call the switched one.
        assertThat(URLDecoder.decode(server.takeRequest().body.readUtf8(), Charsets.UTF_8)).contains("subject_token=AT-new")
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer switched")

        // The renewed bundle was persisted, keeping the CLI-local session fields.
        val stored = FileTokenStore().read()!!
        assertThat(stored.accessToken).isEqualTo("AT-new")
        assertThat(stored.refreshToken).isEqualTo("RT-2")
        assertThat(stored.issuer).isEqualTo(baseUrl())
        assertThat(stored.workspace).isEqualTo("thoryn")
        assertThat(out.toString()).isEmpty()
    }

    @Test
    fun `a rejected refresh names the workspace to sign in on again, and the workspace entry says so too`() {
        val base = Tokens(
            accessToken = "AT-old",
            refreshToken = "RT-dead",
            expiresAtEpochSecond = expired,
            issuer = baseUrl(),
            gateway = baseUrl(),
            workspace = "thoryn",
        )
        seedTokens(base)
        val selected = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selected.write(SelectedWorkspace(tenantId = "t-1", slug = "examples", tenantHubIssuer = "https://examples.hub.example.org"))

        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}""")) // the refresh is refused
        server.enqueue(jsonResponse(401, """{"error":"invalid_token"}""")) // …so the exchange fails too

        val out = err()
        CommandSupport.gatewayClient(baseUrl(), base, selected, PrintStream(out))

        val printed = out.toString()
        assertThat(printed).contains("Could not renew your sign-in session").contains("invalid_grant")
        assertThat(printed).contains("thoryn login --workspace thoryn")
        assertThat(printed).contains("Could not enter workspace 'examples'")
    }

    @Test
    fun `a session with no refresh token says it cannot be renewed instead of a bare HTTP 401`() {
        // The hub issues NO refresh token to a PUBLIC client on the authorization-code grant, so a
        // loopback `thoryn login` session has none. The on-401 retry lands here: it must SAY that
        // rather than return null silently (which surfaced as the reported bare `Error: HTTP 401`).
        seedTokens(Tokens(accessToken = "AT", issuer = baseUrl(), gateway = baseUrl(), workspace = "thoryn"))

        val out = err()
        val renewed = CommandSupport.forceRefresh(PrintStream(out))

        assertThat(renewed).isNull()
        assertThat(out.toString())
            .contains("carries no refresh token")
            .contains("thoryn login --workspace thoryn")
        // No round-trip was attempted — there is nothing to redeem.
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `the session-expiry hint is printed once per process, not once per retried request`() {
        seedTokens(Tokens(accessToken = "AT", issuer = baseUrl(), workspace = "thoryn"))
        val out = err()
        CommandSupport.forceRefresh(PrintStream(out))
        CommandSupport.forceRefresh(PrintStream(out))
        assertThat(out.toString().lines().filter { it.contains("no refresh token") }).hasSize(1)
    }

    @Test
    fun `a confidential login client refreshes with its client secret, like the login and the switch exchange`() {
        // SSO-3182 — the refresh used to send `client_id` only, so a confidential client's renewal was
        // refused with invalid_client while the workspace-switch exchange (which does send the secret)
        // worked. Resolution is env/-D only, never argv.
        System.setProperty("THORYN_CLIENT_SECRET", "s3cret")
        try {
            seedTokens(
                Tokens(accessToken = "AT-old", refreshToken = "RT-1", expiresAtEpochSecond = expired, issuer = baseUrl(), clientId = "ci-bot"),
            )
            server.enqueue(jsonResponse(200, """{"access_token":"AT-new","token_type":"Bearer","expires_in":900}"""))

            assertThat(CommandSupport.forceRefresh(PrintStream(err()))!!.accessToken).isEqualTo("AT-new")

            val request = server.takeRequest()
            assertThat(request.getHeader("Authorization")).startsWith("Basic ")
            // The secret never rides in the body or the path.
            assertThat(request.body.readUtf8()).doesNotContain("s3cret")
            assertThat(request.path).doesNotContain("s3cret")
        } finally {
            System.clearProperty("THORYN_CLIENT_SECRET")
        }
    }
}
