package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.util.concurrent.Flow
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSession
import java.net.URI
import java.util.Optional

/**
 * Unit tests for [DeviceCodeFlow] — the RFC 8628 polling loop with stubbed
 * HTTP responses and a counting sleeper.
 */
class DeviceCodeFlowTest {

    private val authorizationResponse = """
        {
          "device_code": "DC-1",
          "user_code": "ABCD-1234",
          "verification_uri": "https://hub.example.com/activate",
          "verification_uri_complete": "https://hub.example.com/activate?user_code=ABCD-1234",
          "expires_in": 1800,
          "interval": 1
        }
    """.trimIndent()

    private val tokenResponse = """
        {
          "access_token": "AT-1",
          "refresh_token": "RT-1",
          "id_token": "IT-1",
          "token_type": "Bearer",
          "expires_in": 3600,
          "scope": "openid tenant:clients.read"
        }
    """.trimIndent()

    @Test
    fun `successful flow returns tokens after one pending and one success`() {
        val sender = scriptedSender(
            // 1) device authorization
            stub(200, authorizationResponse),
            // 2) first poll: pending
            stub(400, """{"error":"authorization_pending"}"""),
            // 3) second poll: success
            stub(200, tokenResponse),
        )
        val sleeper = CountingSleeper()

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = sleeper,
        )

        var observedAuthorization: DeviceAuthorizationResponse? = null
        val tokens = flow.run("openid tenant:clients.read") { observedAuthorization = it }

        assertThat(tokens.accessToken).isEqualTo("AT-1")
        assertThat(tokens.refreshToken).isEqualTo("RT-1")
        assertThat(tokens.scope).isEqualTo("openid tenant:clients.read")
        assertThat(observedAuthorization?.userCode).isEqualTo("ABCD-1234")
        assertThat(observedAuthorization?.verificationUriComplete).contains("ABCD-1234")
        assertThat(sleeper.totalSeconds()).isGreaterThanOrEqualTo(2L) // at least 2 polls × 1s interval
    }

    @Test
    fun `slow_down increases the polling interval by 5 seconds`() {
        val sender = scriptedSender(
            stub(200, authorizationResponse), // interval=1
            stub(400, """{"error":"slow_down"}"""),
            stub(400, """{"error":"authorization_pending"}"""),
            stub(200, tokenResponse),
        )
        val sleeper = CountingSleeper()

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = sleeper,
        )

        flow.run("openid") { /* nothing */ }

        // interval was 1, then bumped to 6 after slow_down, then 6 again before success.
        // sleeper records: 1 (first poll) + 6 (after slow_down) + 6 (before success) = 13
        assertThat(sleeper.totalSeconds()).isEqualTo(13L)
    }

    @Test
    fun `access_denied throws ACCESS_DENIED`() {
        val sender = scriptedSender(
            stub(200, authorizationResponse),
            stub(400, """{"error":"access_denied"}"""),
        )

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = CountingSleeper(),
        )

        assertThatThrownBy { flow.run("openid") { } }
            .isInstanceOf(DeviceCodeException::class.java)
            .hasMessageContaining("denied")
            .extracting { (it as DeviceCodeException).error }
            .isEqualTo(DeviceCodeError.ACCESS_DENIED)
    }

    @Test
    fun `expired_token from server throws EXPIRED_TOKEN`() {
        val sender = scriptedSender(
            stub(200, authorizationResponse),
            stub(400, """{"error":"expired_token"}"""),
        )

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = CountingSleeper(),
        )

        assertThatThrownBy { flow.run("openid") { } }
            .isInstanceOf(DeviceCodeException::class.java)
            .extracting { (it as DeviceCodeException).error }
            .isEqualTo(DeviceCodeError.EXPIRED_TOKEN)
    }

    @Test
    fun `unparseable error body fails with AUTHORIZATION_FAILED`() {
        val sender = scriptedSender(
            stub(200, authorizationResponse),
            stub(500, "not json"),
        )

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = CountingSleeper(),
        )

        assertThatThrownBy { flow.run("openid") { } }
            .isInstanceOf(DeviceCodeException::class.java)
            .extracting { (it as DeviceCodeException).error }
            .isEqualTo(DeviceCodeError.AUTHORIZATION_FAILED)
    }

    @Test
    fun `device-authorization 401 fails before polling`() {
        val sender = scriptedSender(
            stub(401, """{"error":"invalid_client"}"""),
        )

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "oathy-cli",
            clientSecret = "test-secret",
            sender = sender,
            sleeper = CountingSleeper(),
        )

        assertThatThrownBy { flow.run("openid") { } }
            .isInstanceOf(DeviceCodeException::class.java)
            .hasMessageContaining("401")
    }

    // ── SSO-1993: transport-security issuer guard (defence-in-depth) ────
    //
    // The URL-parsing rules themselves are exhaustively covered by
    // IssuerUrlValidatorTest (SSO-1145). These tests assert only that
    // DeviceCodeFlow enforces that guard on ITSELF at construction — before any
    // device-code request can be sent — so the class is safe regardless of
    // whether its caller happened to validate the issuer first.

    @Test
    fun `construction rejects a non-loopback http issuer before any request`() {
        assertThatThrownBy {
            DeviceCodeFlow(
                issuer = "http://hub.example.com",
                clientId = "oathy-cli",
                clientSecret = "test-secret",
                sender = scriptedSender(),
                sleeper = CountingSleeper(),
            )
        }.isInstanceOf(IssuerUrlValidationException::class.java)
            .hasMessageContaining("loopback")
    }

    @Test
    fun `construction allows an http loopback issuer`() {
        assertThatCode {
            DeviceCodeFlow(
                issuer = "http://127.0.0.1:8080",
                clientId = "oathy-cli",
                clientSecret = "test-secret",
                sender = scriptedSender(),
                sleeper = CountingSleeper(),
            )
        }.doesNotThrowAnyException()
    }

    @Test
    fun `construction allows an https issuer`() {
        assertThatCode {
            DeviceCodeFlow(
                issuer = "https://hub.example.com",
                clientId = "oathy-cli",
                clientSecret = "test-secret",
                sender = scriptedSender(),
                sleeper = CountingSleeper(),
            )
        }.doesNotThrowAnyException()
    }

    @Test
    fun `construction allows a non-loopback http issuer when devMode is true`() {
        assertThatCode {
            DeviceCodeFlow(
                issuer = "http://hub.example.com",
                clientId = "oathy-cli",
                clientSecret = "test-secret",
                sender = scriptedSender(),
                devMode = true,
                sleeper = CountingSleeper(),
            )
        }.doesNotThrowAnyException()
    }

    @Test
    fun `public client (no secret) authenticates with client_id in the body and no Basic auth`() {
        // SSO-2822: thoryn-cli is a public native client — device-code sends client_id in the form
        // body (RFC 8628 §3.1) on BOTH requests and NO Authorization header.
        val requests = mutableListOf<HttpRequest>()
        val bodies = mutableListOf<String>()
        val queue = mutableListOf(stub(200, authorizationResponse), stub(200, tokenResponse))
        val sender = HttpSender { req, _ ->
            requests += req
            bodies += req.bodyPublisher().map { readBody(it) }.orElse("")
            if (queue.isEmpty()) throw IOException("Test ran out of scripted responses")
            queue.removeFirst()
        }

        val flow = DeviceCodeFlow(
            issuer = "https://hub.example.com",
            clientId = "thoryn-cli",
            clientSecret = null,
            sender = sender,
            sleeper = CountingSleeper(),
        )
        flow.run("openid") { /* nothing */ }

        // device_authorization request
        assertThat(requests[0].headers().firstValue("Authorization")).isEmpty()
        assertThat(bodies[0]).contains("client_id=thoryn-cli")
        // token poll
        assertThat(requests[1].headers().firstValue("Authorization")).isEmpty()
        assertThat(bodies[1]).contains("client_id=thoryn-cli")
    }

    // ── helpers ────────────────────────────────────────────────────────

    private fun readBody(publisher: HttpRequest.BodyPublisher): String {
        val sb = StringBuilder()
        publisher.subscribe(object : Flow.Subscriber<ByteBuffer> {
            override fun onSubscribe(subscription: Flow.Subscription) = subscription.request(Long.MAX_VALUE)
            override fun onNext(item: ByteBuffer) {
                val bytes = ByteArray(item.remaining()); item.get(bytes); sb.append(String(bytes, Charsets.UTF_8))
            }
            override fun onError(throwable: Throwable) = Unit
            override fun onComplete() = Unit
        })
        return sb.toString()
    }

    private fun scriptedSender(vararg responses: HttpResponse<String>): HttpSender {
        val queue = responses.toMutableList()
        return HttpSender { _, _ ->
            if (queue.isEmpty()) throw IOException("Test ran out of scripted responses")
            queue.removeFirst()
        }
    }

    private fun stub(status: Int, body: String): HttpResponse<String> = StubResponse(status, body)

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

    private class CountingSleeper : Sleeper {
        private val total = AtomicLong(0)
        override fun sleepSeconds(seconds: Long) {
            total.addAndGet(seconds)
        }
        fun totalSeconds(): Long = total.get()
    }
}
