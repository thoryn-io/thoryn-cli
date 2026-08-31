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
 * SSO-1553 — unit tests for [ClientCredentialsFlow], the non-interactive
 * RFC 6749 §4.4 grant, with a stubbed [HttpSender].
 *
 * The load-bearing assertions: the request is a `grant_type=client_credentials`
 * POST to `/oauth2/token` carrying HTTP Basic client auth and the requested
 * scope; the response parses into [Tokens] with NO refresh token; and a non-200
 * surfaces the parsed OAuth2 error code.
 */
class ClientCredentialsFlowTest {

    private val tokenResponse = """
        {
          "access_token": "AT-cc",
          "token_type": "Bearer",
          "expires_in": 3600,
          "scope": "tenant:applications.write tenant:federation.write"
        }
    """.trimIndent()

    @Test
    fun `successful grant returns an access token with no refresh token`() {
        val captured = CapturingSender(stub(200, tokenResponse))

        val flow = ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com",
            clientId = "ci-bot",
            clientSecret = "s3cret",
            sender = captured,
        )

        val tokens = flow.run("tenant:applications.write tenant:federation.write")

        assertThat(tokens.accessToken).isEqualTo("AT-cc")
        assertThat(tokens.refreshToken).isNull()
        assertThat(tokens.idToken).isNull()
        assertThat(tokens.tokenType).isEqualTo("Bearer")
        assertThat(tokens.scope).isEqualTo("tenant:applications.write tenant:federation.write")
        assertThat(tokens.expiresAtEpochSecond).isNotNull()
    }

    @Test
    fun `request is a client_credentials POST to the token endpoint with basic auth`() {
        val captured = CapturingSender(stub(200, tokenResponse))

        ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com/",
            clientId = "ci-bot",
            clientSecret = "s3cret",
            sender = captured,
        ).run("openid tenant:applications.write")

        val req = captured.lastRequest!!
        assertThat(req.uri().toString()).isEqualTo("https://acme.hub.example.com/oauth2/token")
        assertThat(req.method()).isEqualTo("POST")

        // The client secret never appears in the URI; it is in the Basic header.
        val expectedBasic = "Basic " + Base64.getEncoder()
            .encodeToString("ci-bot:s3cret".toByteArray(Charsets.UTF_8))
        assertThat(req.headers().firstValue("Authorization")).hasValue(expectedBasic)

        val body = captured.lastBody!!
        assertThat(body).contains("grant_type=client_credentials")
        // Scope is form-encoded: space → +, `:` → %3A.
        assertThat(body).contains("scope=openid+tenant%3Aapplications.write")
    }

    @Test
    fun `omits the scope parameter when scope is blank`() {
        val captured = CapturingSender(stub(200, """{"access_token":"AT","token_type":"Bearer"}"""))

        ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com",
            clientId = "ci-bot",
            clientSecret = "s3cret",
            sender = captured,
        ).run("")

        val body = captured.lastBody!!
        assertThat(body).isEqualTo("grant_type=client_credentials")
        assertThat(body).doesNotContain("scope=")
    }

    @Test
    fun `invalid_client surfaces the OAuth2 error code`() {
        val sender = CapturingSender(stub(401, """{"error":"invalid_client"}"""))

        val flow = ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com",
            clientId = "ci-bot",
            clientSecret = "wrong",
            sender = sender,
        )

        assertThatThrownBy { flow.run("openid") }
            .isInstanceOf(ClientCredentialsException::class.java)
            .hasMessageContaining("401")
            .extracting { (it as ClientCredentialsException).oauthError }
            .isEqualTo("invalid_client")
    }

    @Test
    fun `unparseable error body falls back to unknown error`() {
        val sender = CapturingSender(stub(500, "not json"))

        val flow = ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com",
            clientId = "ci-bot",
            clientSecret = "s3cret",
            sender = sender,
        )

        assertThatThrownBy { flow.run("openid") }
            .isInstanceOf(ClientCredentialsException::class.java)
            .extracting { (it as ClientCredentialsException).oauthError }
            .isEqualTo("unknown")
    }

    @Test
    fun `RFC 9457 problem-detail errorCode is surfaced when present`() {
        val sender = CapturingSender(stub(400, """{"errorCode":"invalid_scope","detail":"bad scope"}"""))

        val flow = ClientCredentialsFlow(
            issuer = "https://acme.hub.example.com",
            clientId = "ci-bot",
            clientSecret = "s3cret",
            sender = sender,
        )

        assertThatThrownBy { flow.run("admin:everything") }
            .extracting { (it as ClientCredentialsException).oauthError }
            .isEqualTo("invalid_scope")
    }

    // ── helpers ────────────────────────────────────────────────────────

    private fun stub(status: Int, body: String): HttpResponse<String> = StubResponse(status, body)

    /** Captures the single request the flow sends so the test can assert on it. */
    private class CapturingSender(private val response: HttpResponse<String>) : HttpSender {
        var lastRequest: HttpRequest? = null
        var lastBody: String? = null

        override fun send(
            request: HttpRequest,
            bodyHandler: HttpResponse.BodyHandler<String>,
        ): HttpResponse<String> {
            if (lastRequest != null) throw IOException("client_credentials must be a single round-trip")
            lastRequest = request
            lastBody = request.bodyPublisher().map { readBody(it) }.orElse(null)
            return response
        }

        /** Drain a [HttpRequest.BodyPublisher] (a `Flow.Publisher`) to a UTF-8 string. */
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
