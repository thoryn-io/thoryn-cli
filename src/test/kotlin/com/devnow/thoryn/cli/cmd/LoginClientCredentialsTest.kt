package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-1553 — `thoryn login --client-credentials` against a MockWebServer
 * standing in for the hub token endpoint.
 *
 * The client secret is supplied via the `THORYN_CLIENT_SECRET` system property
 * (the no-argv knob `ThorynConfig.resolveClientSecret` reads first) — never as
 * a command-line argument. The test asserts the grant is non-interactive, the
 * minted access token is persisted, and the secret never appears in the request
 * URI.
 */
class LoginClientCredentialsTest : CommandTestBase() {

    @BeforeEach
    fun clearStoreAndSetSecret() {
        // Start from a clean store so we can prove the token was written by login.
        clearTokens()
        System.setProperty("THORYN_CLIENT_SECRET", "ci-bot-secret")
    }

    @AfterEach
    fun clearSecret() {
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    @Test
    fun `client-credentials login persists the minted access token`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"AT-cc","token_type":"Bearer","expires_in":3600,
                    "scope":"tenant:applications.write"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "login", "--client-credentials",
            "--client-id", "ci-bot",
            "--issuer", baseUrl(),
            "--scope", "tenant:applications.write",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Signed in").contains("ci-bot")

        // The token was written to the (plaintext, @TempDir-sandboxed) store.
        val stored = FileTokenStore().read()
        assertThat(stored).isNotNull
        assertThat(stored!!.accessToken).isEqualTo("AT-cc")
        // client_credentials yields no refresh token.
        assertThat(stored.refreshToken).isNull()

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/oauth2/token")
        assertThat(req.method).isEqualTo("POST")
        val body = req.body.readUtf8()
        assertThat(body).contains("grant_type=client_credentials")
        // The secret rode in the Basic header, not the body/URI.
        assertThat(body).doesNotContain("ci-bot-secret")
        assertThat(req.path).doesNotContain("ci-bot-secret")
    }

    @Test
    fun `client-credentials login fails with a clear error on invalid_client`() {
        server.enqueue(jsonResponse(401, """{"error":"invalid_client"}"""))

        val (exit, _, err) = runCli(
            "login", "--client-credentials",
            "--client-id", "ci-bot",
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(70 + 1) // EXIT_CLIENT_CREDENTIALS_FAILED = 71
        assertThat(err).contains("Sign-in failed").contains("invalid_client")
        // No token was stored on failure.
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `client-credentials and device-code are mutually exclusive`() {
        val (exit, _, err) = runCli(
            "login", "--client-credentials", "--device-code",
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(65) // EXIT_USAGE
        assertThat(err).contains("mutually exclusive")
    }

    @Test
    fun `client-credentials login reads the secret from --client-secret-file`() {
        System.clearProperty("THORYN_CLIENT_SECRET")
        val secretFile = tempHome.resolve("cli.secret")
        Files.writeString(secretFile, "secret-from-file\n")
        server.enqueue(
            jsonResponse(200, """{"access_token":"AT-cc","token_type":"Bearer","expires_in":3600}"""),
        )

        val (exit, _, _) = runCli(
            "login", "--client-credentials",
            "--client-id", "ci-bot",
            "--client-secret-file", secretFile.toString(),
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(FileTokenStore().read()!!.accessToken).isEqualTo("AT-cc")
    }

    @Test
    fun `client-credentials login with no resolvable secret is a usage error`() {
        System.clearProperty("THORYN_CLIENT_SECRET")
        // No env/property, no --client-secret-file, no TTY → cannot resolve.
        val (exit, _, err) = runCli(
            "login", "--client-credentials",
            "--client-id", "ci-bot",
            "--issuer", baseUrl(),
        )

        assertThat(exit).isEqualTo(65) // EXIT_USAGE
        assertThat(err).contains("client secret")
    }
}
