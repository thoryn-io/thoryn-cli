package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3377 — a command running on a session REMEMBERED from before the SSO-3297 auth-host cutover.
 *
 * The session's issuer answers `410 issuer_retired` to every token round-trip. Before this, a refresh
 * printed "Could not renew your sign-in session (Hub returned 410: issuer_retired). Run `thoryn login
 * --workspace thoryn`" — and that `thoryn login` reused the same retired issuer. Now every renewal path
 * (refresh, API-key re-mint, workspace exchange) and a hub call answering 410 name the retired issuer
 * and the `thoryn login --issuer <successor>` line.
 *
 * The session's hosts are this [server] so the token requests are real; [Tokens.platformIssuer] names
 * the retired `hub.stg` base the successor is inferred from (the field SSO-3379 records at login).
 */
class CommandSupportRetiredIssuerTest : CommandTestBase() {

    private val expired = System.currentTimeMillis() / 1000 - 60

    @BeforeEach
    fun resetHint() {
        CommandSupport.resetSessionHintForTest()
    }

    @AfterEach
    fun clearApiKey() {
        System.clearProperty(ThorynConfig.API_KEY_ENV)
    }

    private fun retired(): MockResponse =
        MockResponse()
            .setResponseCode(410)
            .setHeader("Content-Type", "application/problem+json;charset=UTF-8")
            .setBody(LoginRetiredIssuerTest.RETIRED_BODY)

    private fun rememberedSession(
        refreshToken: String? = "RT-1",
        authMode: String? = null,
        clientId: String? = "cli",
    ) = Tokens(
        accessToken = "AT-old",
        refreshToken = refreshToken,
        expiresAtEpochSecond = expired,
        issuer = baseUrl(),
        platformIssuer = "https://hub.stg.thoryn.org",
        gateway = baseUrl(),
        clientId = clientId,
        workspace = "thoryn",
        authMode = authMode,
    )

    @Test
    fun `a refresh refused because the issuer is retired names the successor issuer, not a plain re-login`() {
        val session = rememberedSession()
        seedTokens(session)
        server.enqueue(retired())

        val out = ByteArrayOutputStream()
        val renewed = CommandSupport.forceRefresh(PrintStream(out))

        assertThat(renewed).isNull()
        assertThat(out.toString())
            .contains("Your sign-in session belongs to ${baseUrl()}, which has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
            .doesNotContain("Could not renew your sign-in session")
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/token")
        // The remembered session is not rewritten.
        assertThat(FileTokenStore().read()).isEqualTo(session)
    }

    @Test
    fun `an API-key re-mint at a retired issuer says so instead of blaming the credentials`() {
        seedTokens(rememberedSession(refreshToken = null, authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS, clientId = "ci-bot"))
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:not-a-real-secret")
        server.enqueue(retired())

        val out = ByteArrayOutputStream()
        val renewed = CommandSupport.forceRefresh(PrintStream(out))

        assertThat(renewed).isNull()
        assertThat(out.toString())
            .contains("has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --client-credentials --issuer https://auth.stg.thoryn.org")
            .doesNotContain("--workspace")
            .doesNotContain("check the credentials")
    }

    @Test
    fun `entering a switched workspace on a retired session prints the guidance once, not the renewal line`() {
        val session = rememberedSession()
        seedTokens(session)
        val selected = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selected.write(SelectedWorkspace(tenantId = "t-1", slug = "examples", tenantHubIssuer = "https://examples.hub.stg.thoryn.org"))
        server.enqueue(retired()) // the refresh
        server.enqueue(retired()) // the workspace exchange

        val out = ByteArrayOutputStream()
        CommandSupport.gatewayClient(baseUrl(), session, selected, PrintStream(out))

        val printed = out.toString()
        assertThat(printed).contains("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
        assertThat(Regex("has been retired").findAll(printed).count()).isEqualTo(1)
        assertThat(printed).doesNotContain("Could not enter workspace")
    }

    @Test
    fun `a gateway call on a retired session surfaces the guidance when the renewal is refused`() {
        // A still-valid token from the retired issuer: the gateway refuses it, the CLI tries to renew,
        // and the hub answers 410 — the user sees why, not just `HTTP 401`.
        seedTokens(rememberedSession().copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900))
        server.enqueue(jsonResponse(401, """{"error":"invalid_token"}""")) // gateway
        server.enqueue(retired()) // refresh at the retired issuer

        val (exit, _, err) = runCli("clients", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("which has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
    }

    @Test
    fun `a hub call answering 410 issuer_retired renders the guidance instead of a raw error`() {
        seedTokens(rememberedSession().copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900))
        server.enqueue(retired())

        val (exit, _, err) = runCli("workspace", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("which has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
            .doesNotContain("Error: issuer_retired")
    }

    @Test
    fun `a hub call answering 410 issuer_retired carries the guidance as a hint in json output`() {
        seedTokens(rememberedSession().copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900))
        server.enqueue(retired())

        val (exit, out, _) = runCli("workspace", "list", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val body = parseJson(out)
        assertThat(body["error"]).isEqualTo("issuer_retired")
        assertThat(body["httpStatus"]).isEqualTo(410)
        assertThat(body["hint"] as String).contains("thoryn login --issuer https://auth.stg.thoryn.org")
    }
}
