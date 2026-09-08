package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-2941 — `thoryn login --client-credentials` driven by the single-knob
 * `THORYN_API_KEY=<client-id>:<client-secret>` env var (supplied here via the system
 * property the resolver reads first, never argv).
 *
 * Asserts: the key supplies BOTH the client id and the secret; the minted session is
 * stamped as a client-credentials / API-key session (so it can later re-mint on expiry);
 * and the secret never appears in the request URI or body.
 */
class LoginApiKeyTest : CommandTestBase() {

    @BeforeEach
    fun clearStore() {
        clearTokens()
        System.clearProperty("THORYN_CLIENT_SECRET")
        System.clearProperty(ThorynConfig.API_KEY_ENV)
    }

    @AfterEach
    fun clearApiKey() {
        System.clearProperty(ThorynConfig.API_KEY_ENV)
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    @Test
    fun `THORYN_API_KEY supplies both client id and secret and marks the session for re-mint`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:ci-bot-secret")
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"AT-api","token_type":"Bearer","expires_in":3600,"scope":"tenant:applications.write"}""",
            ),
        )

        // No --client-id / --client-secret-file: the API key is self-contained.
        val (exit, out, _) = runCli("login", "--client-credentials", "--issuer", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Signed in").contains("ci-bot")

        val stored = FileTokenStore().read()!!
        assertThat(stored.accessToken).isEqualTo("AT-api")
        assertThat(stored.refreshToken).isNull()
        // SSO-2941 — the markers that let CommandSupport re-mint on expiry.
        assertThat(stored.authMode).isEqualTo(Tokens.AUTH_MODE_CLIENT_CREDENTIALS)
        assertThat(stored.clientId).isEqualTo("ci-bot")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/oauth2/token")
        val body = req.body.readUtf8()
        assertThat(body).contains("grant_type=client_credentials")
        // The secret rode in the Basic header, never the body/URI.
        assertThat(body).doesNotContain("ci-bot-secret")
        assertThat(req.path).doesNotContain("ci-bot-secret")
        assertThat(req.getHeader("Authorization")).startsWith("Basic ")
    }

    @Test
    fun `an explicit --client-id conflicting with THORYN_API_KEY is a usage error`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:ci-bot-secret")

        val (exit, _, err) = runCli(
            "login", "--client-credentials",
            "--client-id", "someone-else",
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(65) // EXIT_USAGE
        assertThat(err).contains("conflicts").contains(ThorynConfig.API_KEY_ENV)
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `a --client-id matching the THORYN_API_KEY client id is accepted`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:ci-bot-secret")
        server.enqueue(jsonResponse(200, """{"access_token":"AT-api","token_type":"Bearer","expires_in":3600}"""))

        val (exit, _, _) = runCli(
            "login", "--client-credentials",
            "--client-id", "ci-bot",
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(FileTokenStore().read()!!.clientId).isEqualTo("ci-bot")
    }
}
