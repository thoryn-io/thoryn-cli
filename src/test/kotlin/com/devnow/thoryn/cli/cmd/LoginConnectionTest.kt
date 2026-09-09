package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-2948 (epic SSO-2947) — `thoryn login --connection <file>` against a MockWebServer standing in
 * for the (derived) tenant hub token endpoint.
 *
 * The connection contract carries the workspace slug, the machine client id, and the NAMES of the env
 * vars holding the hub base URL and the client secret — never the secret value. The tests assert the
 * flow reads those env vars (supplied as `-D` system properties, the no-argv knob), requests EXACTLY
 * the declared scopes (no default-scope leakage, no wildcard expansion), stamps the derived
 * issuer/gateway onto the session, and fails closed when the named secret var is unset.
 */
class LoginConnectionTest : CommandTestBase() {

    private val hubEnvName = "THORYN_TEST_HUB"
    private val secretEnvName = "THORYN_TEST_CI_SECRET"

    @BeforeEach
    fun clearStore() {
        clearTokens()
        // The hub base + client secret arrive by NAME via the contract; supply them as -D properties.
        System.setProperty(hubEnvName, baseUrl())
        System.setProperty(secretEnvName, "ci-bot-secret")
    }

    @AfterEach
    fun clearProps() {
        System.clearProperty(hubEnvName)
        System.clearProperty(secretEnvName)
    }

    private fun writeConnection(
        slug: String = "thoryn",
        scopes: String = """["tenant:applications.write", "tenant:applications.read"]""",
    ): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "$slug", "hubBaseUrlEnv": "$hubEnvName" },
              "auth": {
                "method": "client_credentials",
                "clientId": "thoryn-cli-ci",
                "secretEnv": "$secretEnvName",
                "scopes": $scopes
              }
            }
            """.trimIndent(),
        )
        return file
    }

    @Test
    fun `login --connection mints and persists a token requesting exactly the declared scopes`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"AT-conn","token_type":"Bearer","expires_in":3600,
                    "scope":"tenant:applications.write tenant:applications.read"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Signed in").contains("thoryn-cli")

        val stored = FileTokenStore().read()
        assertThat(stored).isNotNull
        assertThat(stored!!.accessToken).isEqualTo("AT-conn")
        assertThat(stored.refreshToken).isNull()
        // The session was stamped with the derived issuer + gateway (local hub base => no-op derive).
        assertThat(stored.issuer).isEqualTo(baseUrl())

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/oauth2/token")
        val body = req.body.readUtf8()
        assertThat(body).contains("grant_type=client_credentials")
        // EXACTLY the two declared scopes — no default-scope leakage, no expansion.
        val requested = body.split("&").first { it.startsWith("scope=") }.removePrefix("scope=")
        val decoded = URLDecoder.decode(requested, Charsets.UTF_8).split(" ").filter { it.isNotBlank() }
        assertThat(decoded).containsExactlyInAnyOrder("tenant:applications.write", "tenant:applications.read")
        // The secret rode in the Basic header, never the URI/body.
        assertThat(body).doesNotContain("ci-bot-secret")
        assertThat(req.path).doesNotContain("ci-bot-secret")
    }

    @Test
    fun `login --connection fails closed when the named secret env var is unset`() {
        System.clearProperty(secretEnvName)
        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(71) // EXIT_CLIENT_CREDENTIALS_FAILED
        assertThat(err).contains(secretEnvName).contains("unset or empty")
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `login --connection is mutually exclusive with the manual scope flag`() {
        val (exit, _, err) = runCli(
            "login", "--connection", writeConnection().toString(),
            "--scope", "tenant:applications.read",
        )

        assertThat(exit).isEqualTo(65) // EXIT_USAGE
        assertThat(err).contains("mutually exclusive").contains("--scope")
    }

    @Test
    fun `login --connection reports a clear error on an invalid contract`() {
        val file = tempHome.resolve("bad.json")
        Files.writeString(file, """{ "apiVersion": "thoryn.io/connection/v1", "workspace": {} }""")

        val (exit, _, err) = runCli("login", "--connection", file.toString())

        assertThat(exit).isEqualTo(65) // EXIT_USAGE
        assertThat(err).contains("invalid connection").contains("workspace.slug is required")
    }

    @Test
    fun `the tenant issuer and gateway derivation the flow reuses matches ThorynConfig for a hub host`() {
        // The connection flow derives issuer/gateway from the hub base via these same helpers; assert
        // the hub.<env> -> <slug>.hub.<env> / api.<env> derivation directly (no network).
        val hubBase = "https://hub.stg.thoryn.org"
        assertThat(ThorynConfig.tenantIssuer(hubBase, "thoryn")).isEqualTo("https://thoryn.hub.stg.thoryn.org")
        assertThat(ThorynConfig.gatewayForIssuer(hubBase)).isEqualTo("https://api.stg.thoryn.org")
    }
}
