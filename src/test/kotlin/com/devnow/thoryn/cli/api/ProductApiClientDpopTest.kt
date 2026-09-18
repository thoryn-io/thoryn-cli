package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.DpopKey
import com.devnow.thoryn.cli.auth.DpopSession
import com.devnow.thoryn.cli.auth.Tokens
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.util.Base64

/**
 * SSO-3199 — how the CLI presents a token to the hub / gateway (RFC 9449 §7, §8).
 *
 * The compatibility contract lives here: the CLI attaches a DPoP proof to every API call, but the
 * `Authorization` scheme is **server-driven** — `DPoP` only once the token endpoint answered
 * `token_type: DPoP`, `Bearer` otherwise. So against today's hub and today's (DPoP-unaware) resource
 * servers the wire shape is unchanged, and it flips by itself when the hub marks the `cli` client
 * `dpop_required`.
 */
class ProductApiClientDpopTest {

    private lateinit var server: MockWebServer
    private val key = DpopKey.generate()
    private val session = DpopSession(key)
    private val mapper = ObjectMapper()

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun json(status: Int, body: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)

    private fun baseUrl(): String = server.url("/").toString().trimEnd('/')

    @Test
    fun `a bearer token is still presented as Bearer, with a proof attached`() {
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-1"), // tokenType defaults to Bearer
            dpop = session,
        ).listApplications()

        val request = server.takeRequest()
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer AT-1")
        assertThat(request.getHeader("DPoP")).isNotBlank()
    }

    @Test
    fun `a DPoP token is presented with the DPoP scheme and an ath-bound proof`() {
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-bound", tokenType = "DPoP"),
            dpop = session,
        ).listApplications()

        val request = server.takeRequest()
        assertThat(request.getHeader("Authorization")).isEqualTo("DPoP AT-bound")

        val claims = claims(request.getHeader("DPoP")!!)
        assertThat(claims["htm"].asString()).isEqualTo("GET")
        assertThat(claims["htu"].asString()).isEqualTo("${baseUrl()}/api/v1/applications")
        assertThat(claims["ath"].asString()).isEqualTo(sha256B64u("AT-bound"))
    }

    @Test
    fun `htu carries no query string`() {
        server.enqueue(json(200, """{"items":[]}"""))

        ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-1"), dpop = session)
            .listUsers(email = "a@b.test", limit = 5)

        val request = server.takeRequest()
        assertThat(request.path).contains("?") // the request itself is query-bearing …
        assertThat(claims(request.getHeader("DPoP")!!)["htu"].asString())
            .isEqualTo("${baseUrl()}/api/v1/users") // … but htu is not (RFC 9449 §4.2)
    }

    @Test
    fun `a use_dpop_nonce challenge is retried once with the server nonce`() {
        server.enqueue(
            MockResponse().setResponseCode(401)
                .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce", error_description="nonce required"""")
                .setHeader("DPoP-Nonce", "nonce-from-server"),
        )
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        val result = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-bound", tokenType = "DPoP"),
            dpop = session,
        ).listApplications()

        assertThat(result["data"].size()).isZero()
        assertThat(server.requestCount).isEqualTo(2)
        assertThat(claims(server.takeRequest().getHeader("DPoP")!!)["nonce"]).isNull()
        assertThat(claims(server.takeRequest().getHeader("DPoP")!!)["nonce"].asString())
            .isEqualTo("nonce-from-server")
    }

    @Test
    fun `a nonce challenge is retried exactly once — a repeat challenge surfaces`() {
        repeat(2) {
            server.enqueue(
                MockResponse().setResponseCode(401)
                    .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                    .setHeader("DPoP-Nonce", "nonce-$it")
                    .setBody("""{"error":"use_dpop_nonce"}"""),
            )
        }

        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-bound", tokenType = "DPoP"),
            dpop = session,
        )

        org.assertj.core.api.Assertions.assertThatThrownBy { client.listApplications() }
            .isInstanceOf(ProductApiException::class.java)
        // One original + one retry. No loop, and the 401-refresh path is not wired here.
        assertThat(server.requestCount).isEqualTo(2)
    }

    @Test
    fun `a plain 401 without a nonce still reaches the refresh-and-retry path`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        var refreshes = 0
        ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old", tokenType = "DPoP"),
            reauthenticate = { refreshes++; Tokens(accessToken = "AT-new", tokenType = "DPoP") },
            dpop = session,
        ).listApplications()

        assertThat(refreshes).isEqualTo(1)
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("DPoP AT-old")
        val retry = server.takeRequest()
        assertThat(retry.getHeader("Authorization")).isEqualTo("DPoP AT-new")
        // The retry's proof is re-signed for the NEW token, or the resource server would reject `ath`.
        assertThat(claims(retry.getHeader("DPoP")!!)["ath"].asString()).isEqualTo(sha256B64u("AT-new"))
    }

    @Test
    fun `without a DPoP session the wire shape is exactly the pre-SSO-3199 one`() {
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-1")).listApplications()

        val request = server.takeRequest()
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer AT-1")
        assertThat(request.getHeader("DPoP")).isNull()
    }

    private fun claims(proof: String) = mapper.readTree(
        String(Base64.getUrlDecoder().decode(pad(proof.split(".")[1])), Charsets.UTF_8),
    )

    private fun pad(segment: String) = segment + "=".repeat((4 - segment.length % 4) % 4)

    private fun sha256B64u(value: String) = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII)))
}
