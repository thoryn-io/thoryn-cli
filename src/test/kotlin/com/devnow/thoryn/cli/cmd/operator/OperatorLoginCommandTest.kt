package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.ParCapability
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * SSO-3356 — `thoryn operator login`: loopback PKCE with the operator client on the `thoryn` home,
 * `prompt=login`, and the result stored in the OPERATOR slot only. The MockWebServer is the hub's
 * token endpoint; the "browser" follows the authorize URL's redirect straight back to the loopback
 * listener, exactly as the hub would after a passkey sign-in.
 */
class OperatorLoginCommandTest : CommandTestBase() {

    private val originalBrowser = OperatorLoginCommand.browser
    private val originalSender = OperatorLoginCommand.sender
    private var openedUrl: String? = null

    @BeforeEach
    fun seams() {
        ParCapability.probe = { null } // no discovery document on the mock → front-channel authorize
        OperatorLoginCommand.sender = {
            val client = HttpClient.newHttpClient()
            HttpSender { request, handler -> client.send(request, handler) }
        }
    }

    @AfterEach
    fun restore() {
        OperatorLoginCommand.browser = originalBrowser
        OperatorLoginCommand.sender = originalSender
        ParCapability.resetForTest()
    }

    @Test
    fun `authorize parameters carry the operator client, the operator scopes, PKCE and prompt=login`() {
        val params = OperatorLoginCommand.authorizeParameters(
            clientId = OperatorSession.CLIENT_ID,
            redirectUri = "http://127.0.0.1:5555/callback",
            scope = OperatorSession.DEFAULT_SCOPE,
            codeChallenge = "chal",
            state = "st",
            dpopJkt = null,
        ).toMap()

        assertThat(params["client_id"]).isEqualTo("thoryn-operator")
        assertThat(params["scope"]).isEqualTo("openid admin:custom-domains.manage admin:custom-domains.read")
        assertThat(params["code_challenge_method"]).isEqualTo("S256")
        assertThat(params["prompt"]).isEqualTo("login")
        assertThat(params).doesNotContainKey("dpop_jkt")
    }

    @Test
    fun `a passkey sign-in is stored in the operator slot and the customer session is untouched`() {
        followRedirectWith { redirect, state -> "$redirect?code=op-code&state=$state" }
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"${OperatorCustomDomainCommandTest.operatorJwt()}","token_type":"Bearer",""" +
                    """"expires_in":900,"scope":"openid admin:custom-domains.manage admin:custom-domains.read"}""",
            ),
        )

        val result = runCli("operator", "login", "--issuer", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        assertThat(result.out).contains("A PASSKEY sign-in is required").contains("Signed in as an operator")
            .contains("op-subject-1")
        val authorize = query(openedUrl!!)
        assertThat(authorize["client_id"]).isEqualTo("thoryn-operator")
        assertThat(authorize["prompt"]).isEqualTo("login")
        assertThat(authorize["scope"]).isEqualTo(OperatorSession.DEFAULT_SCOPE)
        assertThat(authorize["redirect_uri"]).matches("http://(127\\.0\\.0\\.1|\\[::1]):\\d+/callback")

        val token = server.takeRequest()
        assertThat(token.path).isEqualTo("/oauth2/token")
        val form = token.body.readUtf8()
        assertThat(form).contains("grant_type=authorization_code").contains("code=op-code")
            .contains("client_id=thoryn-operator").doesNotContain("client_secret")
        assertThat(token.getHeader("Authorization")).isNull() // public client: no Basic auth

        val stored = FileTokenStore(FileTokenStore.operatorPath()).read()!!
        assertThat(stored.clientId).isEqualTo("thoryn-operator")
        assertThat(stored.workspace).isEqualTo("thoryn")
        assertThat(stored.refreshToken).isNull()
        assertThat(FileTokenStore().read()?.accessToken).isEqualTo("AT-test")

        val status = runCli("operator", "login", "--status")
        assertThat(status.exit).isEqualTo(0)
        assertThat(status.out).contains("Operator session valid").contains("Passkey: yes")
    }

    @Test
    fun `invalid_scope from the hub explains standing and passkey, and stores nothing`() {
        followRedirectWith { redirect, state -> "$redirect?error=invalid_scope&state=$state" }

        val result = runCli("operator", "login", "--issuer", baseUrl())

        assertThat(result.exit).isEqualTo(72)
        assertThat(result.err).contains("invalid_scope").contains("operator standing").contains("passkey")
        assertThat(FileTokenStore(FileTokenStore.operatorPath()).read()).isNull()
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a token without a passkey amr is stored but flagged`() {
        followRedirectWith { redirect, state -> "$redirect?code=pw-code&state=$state" }
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"${OperatorCustomDomainCommandTest.operatorJwt(listOf("pwd"))}","token_type":"Bearer",""" +
                    """"expires_in":900,"scope":"openid admin:custom-domains.manage admin:custom-domains.read"}""",
            ),
        )

        val result = runCli("operator", "login", "--issuer", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        assertThat(result.err).contains("did not use a passkey").contains("operator_passkey_required")
    }

    @Test
    fun `logout clears only the operator session`() {
        FileTokenStore(FileTokenStore.operatorPath()).write(OperatorCustomDomainCommandTest.operatorTokens())

        val result = runCli("operator", "logout")

        assertThat(result.exit).isEqualTo(0)
        assertThat(FileTokenStore(FileTokenStore.operatorPath()).read()).isNull()
        assertThat(FileTokenStore().read()?.accessToken).isEqualTo("AT-test")
    }

    /** Stand in for the browser: record the authorize URL and hit the loopback redirect like the hub would. */
    private fun followRedirectWith(callback: (redirectUri: String, state: String) -> String) {
        OperatorLoginCommand.browser = { url ->
            openedUrl = url
            val q = query(url)
            val target = callback(q.getValue("redirect_uri"), q.getValue("state"))
            HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(target)).GET().build(),
                HttpResponse.BodyHandlers.discarding(),
            )
        }
    }

    private fun query(url: String): Map<String, String> =
        URI(url).rawQuery.split('&').associate {
            val (k, v) = it.split('=', limit = 2)
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }
}
