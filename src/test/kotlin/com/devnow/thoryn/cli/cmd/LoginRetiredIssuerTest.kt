package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.RetiredIssuer
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files

/**
 * SSO-3377 — `thoryn login` from a remembered (or given) issuer that the SSO-3297 auth-host cutover
 * retired.
 *
 * Reported by the product owner on 0.28.0: `thoryn login` printed "Using hub https://hub.stg.thoryn.org
 * (from your previous sign-in)" and opened `https://thoryn.hub.stg.thoryn.org/oauth2/authorize…`, a host
 * that answers every request with `410 issuer_retired`. Every login mode now asks the issuer's discovery
 * document first and stops — before a browser opens or a grant is posted — naming the retired issuer and
 * the `auth.<env>` successor to pass with `--issuer`. The saved issuer is never rewritten.
 *
 * The `hub.stg.thoryn.org` names cannot resolve to the [server], so [routeToServer] points the probe's
 * fetch at it: the request, the 410 and its body are real HTTP; only the host is swapped.
 */
class LoginRetiredIssuerTest : CommandTestBase() {

    /** Discovery URLs the probe asked for, under their ORIGINAL (pre-routing) names. */
    private val probed = mutableListOf<String>()

    @BeforeEach
    fun cleanEnvironment() {
        assumeTrue(System.getenv(ThorynConfig.HUB_ENV) == null, "THORYN_HUB is set in this environment")
        assumeTrue(System.getenv(ThorynConfig.ISSUER_ENV) == null, "THORYN_ISSUER is set in this environment")
        System.setProperty("THORYN_NO_BROWSER", "1")
    }

    @AfterEach
    fun clearProperties() {
        ThorynConfig.ISSUER_ENV_NAMES.forEach { System.clearProperty(it) }
        System.clearProperty("THORYN_NO_BROWSER")
        System.clearProperty(ThorynConfig.API_KEY_ENV)
        System.clearProperty(CONNECTION_HUB_ENV)
        System.clearProperty(CONNECTION_SECRET_ENV)
    }

    /** Send the probe's GET to the mock server, whatever host it named. */
    private fun routeToServer() {
        RetiredIssuer.fetcher = { url ->
            probed += url
            val path = URI(url).rawPath
            val response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(baseUrl() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString(),
            )
            RetiredIssuer.Answer(response.statusCode(), response.body())
        }
    }

    private fun retired(): MockResponse =
        MockResponse()
            .setResponseCode(410)
            .setHeader("Content-Type", "application/problem+json;charset=UTF-8")
            .setBody(RETIRED_BODY)

    @Test
    fun `login from a remembered retired issuer stops before opening a browser and suggests the auth-host issuer`() {
        val remembered = Tokens(
            accessToken = "AT-old",
            refreshToken = "RT-old",
            issuer = "https://thoryn.hub.stg.thoryn.org",
            platformIssuer = "https://hub.stg.thoryn.org",
            gateway = "https://api.stg.thoryn.org",
            workspace = "thoryn",
        )
        seedTokens(remembered)
        routeToServer()
        server.enqueue(retired())

        val (exit, out, err) = runCli("login", "--workspace", "thoryn")

        assertThat(exit).withFailMessage("stderr was:\n%s", err).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("Using hub https://hub.stg.thoryn.org (from your previous sign-in")
            .contains("Error: the issuer https://thoryn.hub.stg.thoryn.org has been retired (HTTP 410 issuer_retired)")
            .contains("This host has been retired.")
            .contains("https://hub.stg.thoryn.org was remembered from your previous sign-in")
            .contains("does not change a saved issuer")
            .contains("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
        // Nothing was opened: no authorize URL, no loopback wait — the probe was the only request.
        assertThat(out).doesNotContain("Opening your browser").doesNotContain("/oauth2/authorize")
        assertThat(probed).containsExactly("https://thoryn.hub.stg.thoryn.org/.well-known/openid-configuration")
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(server.takeRequest().path).isEqualTo("/.well-known/openid-configuration")
        // The saved issuer is left exactly as it was.
        assertThat(FileTokenStore().read()).isEqualTo(remembered)
    }

    @Test
    fun `an explicit retired --issuer gets the same guidance, with the device-code line`() {
        clearTokens()
        routeToServer()
        server.enqueue(retired())

        val (exit, out, err) = runCli("login", "--device-code", "--issuer", "https://hub.stg.thoryn.org", "--workspace", "acme")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("Error: the issuer https://acme.hub.stg.thoryn.org has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --device-code --issuer https://auth.stg.thoryn.org --workspace acme")
            // The user named it — nothing was "remembered".
            .doesNotContain("remembered")
        assertThat(out).doesNotContain("enter the code")
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `a retired issuer on a host the CLI cannot infer a successor for asks for --issuer`() {
        // Real probe, real HTTP: a local issuer has no `hub.` label, so there is nothing to suggest.
        RetiredIssuer.resetForTest()
        seedTokens(Tokens(accessToken = "AT", issuer = baseUrl(), platformIssuer = baseUrl()))
        server.enqueue(retired())

        val (exit, out, err) = runCli("login", "--workspace", "thoryn")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("Error: the issuer ${baseUrl()} has been retired (HTTP 410 issuer_retired)")
            .contains("thoryn login --issuer <issuer>")
            .doesNotContain("auth.")
        assertThat(out).doesNotContain("/oauth2/authorize")
        assertThat(server.takeRequest().path).isEqualTo("/.well-known/openid-configuration")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `a healthy issuer proceeds to the sign-in unchanged`() {
        RetiredIssuer.resetForTest()
        clearTokens()
        server.enqueue(jsonResponse(200, """{"issuer":"${baseUrl()}","token_endpoint":"${baseUrl()}/oauth2/token"}"""))
        server.enqueue(jsonResponse(400, """{"error":"invalid_client"}"""))

        val (exit, _, err) = runCli("login", "--device-code", "--issuer", baseUrl(), "--workspace", "acme")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_DEVICE_CODE_FAILED)
        assertThat(err).doesNotContain("retired").contains("invalid_client")
        assertThat(server.takeRequest().path).isEqualTo("/.well-known/openid-configuration")
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/device_authorization")
    }

    @Test
    fun `a 410 without the issuer_retired errorCode is reported generically`() {
        RetiredIssuer.resetForTest()
        clearTokens()
        server.enqueue(
            MockResponse()
                .setResponseCode(410)
                .setHeader("Content-Type", "application/problem+json")
                .setBody("""{"type":"about:blank","title":"Gone","status":410,"detail":"This workspace was deleted."}"""),
        )

        val (exit, out, err) = runCli("login", "--issuer", baseUrl(), "--workspace", "acme")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("the issuer ${baseUrl()} answered HTTP 410 Gone to its discovery document — This workspace was deleted.")
            .contains("--issuer <issuer>")
            .doesNotContain("issuer_retired")
            .doesNotContain("auth.")
        assertThat(out).doesNotContain("/oauth2/authorize")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `client-credentials at a retired issuer stops before the grant and suggests the client-credentials line`() {
        clearTokens()
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:not-a-real-secret")
        routeToServer()
        server.enqueue(retired())

        val (exit, _, err) = runCli("login", "--client-credentials", "--issuer", "https://hub.stg.thoryn.org")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("the issuer https://hub.stg.thoryn.org has been retired")
            .contains("thoryn login --client-credentials --issuer https://auth.stg.thoryn.org")
            .doesNotContain("not-a-real-secret")
        assertThat(probed).containsExactly("https://hub.stg.thoryn.org/.well-known/openid-configuration")
        assertThat(server.requestCount).isEqualTo(1) // no /oauth2/token
    }

    @Test
    fun `workload identity at a retired issuer stops before the exchange`() {
        clearTokens()
        routeToServer()
        server.enqueue(retired())

        val (exit, _, err) = runCli(
            "login", "--workload-identity", "--issuer", "https://hub.stg.thoryn.org",
            "--wif-signing-key-file", writeTestSigningKey(), "--subject-token", "gh-oidc-token",
        )

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("thoryn login --workload-identity --issuer https://auth.stg.thoryn.org")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `a connection contract whose issuer env var names a retired issuer says which env var to change`() {
        clearTokens()
        System.setProperty(CONNECTION_HUB_ENV, "https://hub.stg.thoryn.org")
        System.setProperty(CONNECTION_SECRET_ENV, "not-a-real-secret")
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "acme", "hubBaseUrlEnv": "$CONNECTION_HUB_ENV" },
              "auth": { "method": "client_credentials", "clientId": "ci-bot", "secretEnv": "$CONNECTION_SECRET_ENV",
                        "scopes": ["tenant:applications.read"] }
            }
            """.trimIndent(),
        )
        routeToServer()
        server.enqueue(retired())

        val (exit, _, err) = runCli("login", "--connection", file.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("the issuer https://acme.hub.stg.thoryn.org has been retired")
            .contains("Set $CONNECTION_HUB_ENV=https://auth.stg.thoryn.org and run `thoryn login --connection")
        assertThat(server.requestCount).isEqualTo(1)
    }

    /** A throwaway P-256 key: the WIF path parses it before it probes. */
    private fun writeTestSigningKey(): String {
        val generator = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        val pkcs8 = java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(generator.generateKeyPair().private.encoded)
        val file = tempHome.resolve("wif-key.pem")
        Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n$pkcs8\n-----END PRIVATE KEY-----\n")
        return file.toString()
    }

    companion object {
        /** The body staging's retired hosts answer with (captured 2026-09-27). */
        const val RETIRED_BODY: String =
            """{"detail":"This host has been retired. Use the issuer advertised in the current discovery document.",""" +
                """"instance":"/.well-known/openid-configuration","status":410,"title":"Gone",""" +
                """"type":"https://thoryn.io/problems/issuer_retired","errorCode":"issuer_retired"}"""

        private const val CONNECTION_HUB_ENV = "THORYN_TEST_RETIRED_HUB"
        private const val CONNECTION_SECRET_ENV = "THORYN_TEST_RETIRED_SECRET"
    }
}
