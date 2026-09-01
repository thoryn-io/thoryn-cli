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
import java.util.Optional
import java.util.concurrent.Flow
import javax.net.ssl.SSLSession

/**
 * SSO-2834 — [RefreshTokenFlow] (RFC 6749 §6 refresh-token grant) with a stubbed [HttpSender].
 *
 * Covers: a successful refresh returns a fresh access token; the refresh token is retained when the
 * response omits one and replaced when it rotates; the request is `grant_type=refresh_token` with the
 * public `client_id` in the body and no basic auth; and a non-200 surfaces the OAuth2 error code as a
 * [RefreshTokenException].
 */
class RefreshTokenFlowTest {

    private val rotatedResponse = """
        {
          "access_token": "AT-new",
          "refresh_token": "RT-new",
          "token_type": "Bearer",
          "expires_in": 900,
          "scope": "openid offline_access"
        }
    """.trimIndent()

    private val noRotationResponse = """
        {
          "access_token": "AT-new",
          "token_type": "Bearer",
          "expires_in": 900
        }
    """.trimIndent()

    private fun flow(sender: HttpSender) = RefreshTokenFlow(
        issuer = "https://acme.hub.example.com/",
        sender = sender,
    )

    @Test
    fun `successful refresh returns a fresh access token and future expiry`() {
        val tokens = flow(CapturingSender(stub(200, rotatedResponse))).refresh("RT-old")

        assertThat(tokens.accessToken).isEqualTo("AT-new")
        assertThat(tokens.tokenType).isEqualTo("Bearer")
        assertThat(tokens.scope).isEqualTo("openid offline_access")
        val now = System.currentTimeMillis() / 1000
        assertThat(tokens.expiresAtEpochSecond!!).isGreaterThan(now)
    }

    @Test
    fun `a rotated refresh token in the response replaces the old one`() {
        val tokens = flow(CapturingSender(stub(200, rotatedResponse))).refresh("RT-old")
        assertThat(tokens.refreshToken).isEqualTo("RT-new")
    }

    @Test
    fun `the previous refresh token is retained when the response omits one`() {
        val tokens = flow(CapturingSender(stub(200, noRotationResponse))).refresh("RT-old")
        assertThat(tokens.refreshToken).isEqualTo("RT-old")
    }

    @Test
    fun `the request is grant_type=refresh_token with the public client_id and no basic auth`() {
        val captured = CapturingSender(stub(200, rotatedResponse))

        flow(captured).refresh("RT-old")

        val req = captured.lastRequest!!
        assertThat(req.uri().toString()).isEqualTo("https://acme.hub.example.com/oauth2/token")
        assertThat(req.method()).isEqualTo("POST")
        assertThat(req.headers().firstValue("Authorization")).isEmpty()

        val body = captured.lastBody!!
        assertThat(body).contains("grant_type=refresh_token")
        assertThat(body).contains("refresh_token=RT-old")
        assertThat(body).contains("client_id=thoryn-cli")
    }

    @Test
    fun `invalid_grant surfaces the OAuth2 error code`() {
        assertThatThrownBy { flow(CapturingSender(stub(400, """{"error":"invalid_grant"}"""))).refresh("STALE") }
            .isInstanceOf(RefreshTokenException::class.java)
            .hasMessageContaining("400")
            .extracting { (it as RefreshTokenException).oauthError }
            .isEqualTo("invalid_grant")
    }

    @Test
    fun `unparseable error body falls back to unknown`() {
        assertThatThrownBy { flow(CapturingSender(stub(500, "not json"))).refresh("RT") }
            .extracting { (it as RefreshTokenException).oauthError }
            .isEqualTo("unknown")
    }

    // ── helpers (mirror AuthorizationCodeFlowTest) ─────────────────────

    private fun stub(status: Int, body: String): HttpResponse<String> = StubResponse(status, body)

    private class CapturingSender(private val response: HttpResponse<String>) : HttpSender {
        var lastRequest: HttpRequest? = null
        var lastBody: String? = null

        override fun send(
            request: HttpRequest,
            bodyHandler: HttpResponse.BodyHandler<String>,
        ): HttpResponse<String> {
            if (lastRequest != null) throw IOException("refresh must be a single round-trip")
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
