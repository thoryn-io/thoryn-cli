package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-2941 — re-mint-on-expiry for an API-key / client-credentials session.
 *
 * A client-credentials grant returns NO refresh token (RFC 6749 §4.4.3), so
 * [CommandSupport.forceRefresh] / [CommandSupport.ensureFresh] cannot use the
 * refresh_token path. Instead they re-run the RFC 6749 §4.4 grant with the stored
 * client id + the env-supplied secret. These tests drive that against a MockWebServer
 * standing in for the hub token endpoint; the secret is supplied via the
 * `THORYN_API_KEY` / `THORYN_CLIENT_SECRET` **system property**, never argv.
 */
class CommandSupportClientCredentialsReMintTest : CommandTestBase() {

    @BeforeEach
    fun clearSecrets() {
        System.clearProperty(ThorynConfig.API_KEY_ENV)
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    @AfterEach
    fun clearSecretsAfter() {
        System.clearProperty(ThorynConfig.API_KEY_ENV)
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    private fun now(): Long = System.currentTimeMillis() / 1000

    /** Seed an expired API-key session pointed at the mock hub. */
    private fun seedExpiredApiKeySession() {
        seedTokens(
            Tokens(
                accessToken = "AT-old",
                refreshToken = null,
                expiresAtEpochSecond = now() - 10, // already expired
                scope = "tenant:applications.write",
                issuer = baseUrl(),
                gateway = "http://gw.local",
                authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                clientId = "ci-bot",
            ),
        )
    }

    @Test
    fun `forceRefresh re-mints a client-credentials session from THORYN_API_KEY`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:ci-bot-secret")
        seedExpiredApiKeySession()
        server.enqueue(
            jsonResponse(200, """{"access_token":"AT-new","token_type":"Bearer","expires_in":3600,"scope":"tenant:applications.write"}"""),
        )

        val refreshed = CommandSupport.forceRefresh()

        assertThat(refreshed).isNotNull
        assertThat(refreshed!!.accessToken).isEqualTo("AT-new")
        // Session hosts + API-key markers are preserved across the re-mint.
        assertThat(refreshed.issuer).isEqualTo(baseUrl())
        assertThat(refreshed.gateway).isEqualTo("http://gw.local")
        assertThat(refreshed.authMode).isEqualTo(Tokens.AUTH_MODE_CLIENT_CREDENTIALS)
        assertThat(refreshed.clientId).isEqualTo("ci-bot")

        // The re-minted bundle was written back to the store.
        assertThat(FileTokenStore().read()!!.accessToken).isEqualTo("AT-new")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/oauth2/token")
        val body = req.body.readUtf8()
        assertThat(body).contains("grant_type=client_credentials")
        // The stored (granted) scope is re-requested.
        assertThat(body).contains("scope=tenant%3Aapplications.write")
        // Secret safety: never in the body/URI — only the Basic header.
        assertThat(body).doesNotContain("ci-bot-secret")
        assertThat(req.path).doesNotContain("ci-bot-secret")
        assertThat(req.getHeader("Authorization")).startsWith("Basic ")
    }

    @Test
    fun `forceRefresh re-mints using THORYN_CLIENT_SECRET when no API key is set`() {
        System.setProperty("THORYN_CLIENT_SECRET", "ci-bot-secret")
        seedExpiredApiKeySession()
        server.enqueue(jsonResponse(200, """{"access_token":"AT-new","token_type":"Bearer","expires_in":3600}"""))

        val refreshed = CommandSupport.forceRefresh()

        assertThat(refreshed!!.accessToken).isEqualTo("AT-new")
    }

    @Test
    fun `ensureFresh re-mints a near-expiry client-credentials token`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:ci-bot-secret")
        // Within the 60s refresh skew → ensureFresh proactively re-mints.
        seedTokens(
            Tokens(
                accessToken = "AT-old",
                expiresAtEpochSecond = now() + 5,
                scope = "tenant:applications.write",
                issuer = baseUrl(),
                authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                clientId = "ci-bot",
            ),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"AT-fresh","token_type":"Bearer","expires_in":3600}"""))

        val fresh = CommandSupport.ensureFresh(FileTokenStore().read()!!)

        assertThat(fresh.accessToken).isEqualTo("AT-fresh")
    }

    @Test
    fun `forceRefresh returns null with a hint when no secret is available to re-mint`() {
        // No THORYN_API_KEY / THORYN_CLIENT_SECRET in the environment.
        seedExpiredApiKeySession()
        val err = java.io.ByteArrayOutputStream()

        val result = CommandSupport.forceRefresh(java.io.PrintStream(err))

        assertThat(result).isNull()
        assertThat(err.toString())
            .contains("ci-bot")
            .contains(ThorynConfig.API_KEY_ENV)
        // The stale token is left untouched for the caller to surface the real 401.
        assertThat(FileTokenStore().read()!!.accessToken).isEqualTo("AT-old")
        // No request was made (server has nothing enqueued).
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `forceRefresh returns null on a rejected re-mint grant`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:wrong-secret")
        seedExpiredApiKeySession()
        server.enqueue(jsonResponse(401, """{"error":"invalid_client"}"""))
        val err = java.io.ByteArrayOutputStream()

        val result = CommandSupport.forceRefresh(java.io.PrintStream(err))

        assertThat(result).isNull()
        assertThat(err.toString()).contains("invalid_client")
        // The stale token remains; nothing overwrote it.
        assertThat(FileTokenStore().read()!!.accessToken).isEqualTo("AT-old")
    }

    @Test
    fun `a session with a refresh token still uses the refresh path, not re-mint`() {
        // A normal interactive login: refresh token present, no API-key markers.
        seedTokens(
            Tokens(
                accessToken = "AT-old",
                refreshToken = "RT-1",
                expiresAtEpochSecond = now() - 10,
                issuer = baseUrl(),
            ),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"AT-refreshed","token_type":"Bearer","expires_in":3600}"""))

        val refreshed = CommandSupport.forceRefresh()

        assertThat(refreshed!!.accessToken).isEqualTo("AT-refreshed")
        val req = server.takeRequest()
        assertThat(req.body.readUtf8()).contains("grant_type=refresh_token")
    }
}
