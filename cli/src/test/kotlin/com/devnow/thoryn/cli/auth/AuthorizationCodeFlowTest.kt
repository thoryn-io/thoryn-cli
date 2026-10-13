package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.URI
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.util.Base64
import java.util.Optional
import java.util.concurrent.Flow
import javax.net.ssl.SSLSession

/**
 * SSO-2820 — unit tests for [AuthorizationCodeFlow], the RFC 6749 §4.1 code redemption leg of the
 * interactive loopback `thoryn login`, with a stubbed [HttpSender].
 *
 * Load-bearing assertions: the exchange is a `grant_type=authorization_code` POST to `/oauth2/token`
 * carrying `code`, the byte-matching `redirect_uri`, and the PKCE `code_verifier`; a PUBLIC client
 * (no secret) sends `client_id` in the body and NO `Authorization` header; a CONFIDENTIAL client
 * (secret) sends HTTP Basic and no body `client_id`; and a non-200 surfaces the OAuth2 error code.
 */
class AuthorizationCodeFlowTest {

    private val tokenResponse = """
        {
          "access_token": "AT-ac",
          "refresh_token": "RT-ac",
          "id_token": "ID-ac",
          "token_type": "Bearer",
          "expires_in": 900,
          "scope": "openid profile"
        }
    """.trimIndent()

    private fun flow(sender: HttpSender, secret: String? = null) = AuthorizationCodeFlow(
        issuer = "https://acme.hub.example.com/",
        clientId = "thoryn-cli",
        clientSecret = secret,
        redirectUri = "http://127.0.0.1:49821/callback",
        codeVerifier = "verifier-1234567890",
        sender = sender,
    )

    @Test
    fun `successful exchange returns access + refresh + id tokens`() {
        val tokens = flow(CapturingSender(stub(200, tokenResponse))).exchange("AUTH-CODE")

        assertThat(tokens.accessToken).isEqualTo("AT-ac")
        assertThat(tokens.refreshToken).isEqualTo("RT-ac")
        assertThat(tokens.idToken).isEqualTo("ID-ac")
        assertThat(tokens.tokenType).isEqualTo("Bearer")
        assertThat(tokens.scope).isEqualTo("openid profile")
        assertThat(tokens.expiresAtEpochSecond).isNotNull()
    }

    @Test
    fun `public client sends code, redirect_uri, verifier and client_id in the body with no basic auth`() {
        val captured = CapturingSender(stub(200, tokenResponse))

        flow(captured).exchange("AUTH-CODE")

        val req = captured.lastRequest!!
        assertThat(req.uri().toString()).isEqualTo("https://acme.hub.example.com/oauth2/token")
        assertThat(req.method()).isEqualTo("POST")
        assertThat(req.headers().firstValue("Authorization")).isEmpty()

        val body = captured.lastBody!!
        assertThat(body).contains("grant_type=authorization_code")
        assertThat(body).contains("code=AUTH-CODE")
        assertThat(body).contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A49821%2Fcallback")
        assertThat(body).contains("code_verifier=verifier-1234567890")
        assertThat(body).contains("client_id=thoryn-cli")
    }

    @Test
    fun `confidential client authenticates with basic auth and omits body client_id`() {
        val captured = CapturingSender(stub(200, tokenResponse))

        flow(captured, secret = "s3cret").exchange("AUTH-CODE")

        val expectedBasic = "Basic " + Base64.getEncoder()
            .encodeToString("thoryn-cli:s3cret".toByteArray(Charsets.UTF_8))
        assertThat(captured.lastRequest!!.headers().firstValue("Authorization")).hasValue(expectedBasic)
        assertThat(captured.lastBody!!).doesNotContain("client_id=")
    }

    @Test
    fun `invalid_grant surfaces the OAuth2 error code`() {
        val flow = flow(CapturingSender(stub(400, """{"error":"invalid_grant"}""")))

        assertThatThrownBy { flow.exchange("STALE-CODE") }
            .isInstanceOf(AuthorizationCodeException::class.java)
            .hasMessageContaining("400")
            .extracting { (it as AuthorizationCodeException).oauthError }
            .isEqualTo("invalid_grant")
    }

    @Test
    fun `unparseable error body falls back to unknown`() {
        val flow = flow(CapturingSender(stub(500, "not json")))

        assertThatThrownBy { flow.exchange("CODE") }
            .extracting { (it as AuthorizationCodeException).oauthError }
            .isEqualTo("unknown")
    }

    // ── helpers (mirror ClientCredentialsFlowTest) ─────────────────────

    private fun stub(status: Int, body: String): HttpResponse<String> = StubResponse(status, body)

    private class CapturingSender(private val response: HttpResponse<String>) : HttpSender {
        var lastRequest: HttpRequest? = null
        var lastBody: String? = null

        override fun send(
            request: HttpRequest,
            bodyHandler: HttpResponse.BodyHandler<String>,
        ): HttpResponse<String> {
            if (lastRequest != null) throw IOException("code exchange must be a single round-trip")
            lastRequest = request
            lastBody = request.bodyPublisher().map { readBody(it) }.orElse(null)
            return response
        }

        private fun readBody(publisher: HttpRequest.BodyPublisher): String {
            val sb = StringBuilder()
            publisher.subscribe(object : Flow.Subscriber<ByteBuffer> {
                override fun onSubscribe(subscription: Flow.Subscription) =
                    subscription.request(Long.MAX_VALUE)

                override fun onNext(item: ByteBuffer) {
                    val bytes = ByteArray(item.remaining())
                    item.get(bytes)
                    sb.append(String(bytes, Charsets.UTF_8))
                }

                override fun onError(throwable: Throwable) = Unit
                override fun onComplete() = Unit
            })
            return sb.toString()
        }
    }

    private class StubResponse(private val status: Int, private val body: String) : HttpResponse<String> {
        override fun statusCode(): Int = status
        override fun request(): HttpRequest = throw UnsupportedOperationException()
        override fun previousResponse(): Optional<HttpResponse<String>> = Optional.empty()
        override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
        override fun body(): String = body
        override fun sslSession(): Optional<SSLSession> = Optional.empty()
        override fun uri(): URI = URI.create("http://test")
        override fun version(): java.net.http.HttpClient.Version = java.net.http.HttpClient.Version.HTTP_1_1
    }
}
