package com.devnow.thoryn.cli.auth

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.util.Base64

/**
 * SSO-3199 — the token endpoint over [Dpop.sender], which is the sender every token flow
 * ([RefreshTokenFlow], [AuthorizationCodeFlow], [TokenExchangeFlow], [DeviceCodeFlow],
 * [ClientCredentialsFlow]) is wired with in production.
 *
 * Proves the two things that must hold at `/oauth2/token`: a proof rides on the request (so the hub can
 * bind `cnf.jkt` into the issued token), and the authorization server's `400 use_dpop_nonce` challenge
 * (RFC 9449 §8) is answered once with the supplied nonce rather than surfacing as a failed refresh.
 */
class DpopTokenEndpointTest {

    private lateinit var server: MockWebServer
    private val mapper = ObjectMapper()

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
        Dpop.resetForTest()
        Dpop.storeProvider = { InMemoryStore() }
        // SSO-3221 — a proof now rides only on a hub that ADVERTISES DPoP. This suite is about the
        // shape of the proof once it is sent, so it declares the platform supports it rather than
        // enqueueing a discovery document ahead of every token response. Whether the CLI asks at
        // all, and what it does with each answer, is `DpopCapabilityGateTest`.
        DpopCapability.resetForTest()
        DpopCapability.seedForTest(issuer(), advertised = true)
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        Dpop.resetForTest()
        DpopCapability.resetForTest()
    }

    private fun issuer(): String = server.url("/").toString().trimEnd('/')

    private fun tokenResponse(tokenType: String = "Bearer"): MockResponse =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(
            """{"access_token":"AT-new","refresh_token":"RT-new","token_type":"$tokenType","expires_in":900}""",
        )

    @Test
    fun `a refresh carries a DPoP proof bound to the token endpoint`() {
        server.enqueue(tokenResponse())

        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        val request = server.takeRequest()
        val claims = claims(request.getHeader("DPoP")!!)
        assertThat(claims["htm"].asString()).isEqualTo("POST")
        assertThat(claims["htu"].asString()).isEqualTo("${issuer()}/oauth2/token")
        // No access token is PRESENTED on a token request, so there is nothing to bind `ath` to.
        assertThat(claims["ath"]).isNull()
    }

    @Test
    fun `a token_type of DPoP is carried into the stored session`() {
        server.enqueue(tokenResponse(tokenType = "DPoP"))

        val tokens = RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        // This is what flips the CLI over to `Authorization: DPoP …` on subsequent API calls.
        assertThat(tokens.tokenType).isEqualTo("DPoP")
    }

    @Test
    fun `a 400 use_dpop_nonce is retried once with the server nonce`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setHeader("Content-Type", "application/json")
                .setHeader("DPoP-Nonce", "n-1")
                .setBody("""{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce"}"""),
        )
        server.enqueue(tokenResponse())

        val tokens = RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(tokens.accessToken).isEqualTo("AT-new")
        assertThat(server.requestCount).isEqualTo(2)
        assertThat(claims(server.takeRequest().getHeader("DPoP")!!)["nonce"]).isNull()
        assertThat(claims(server.takeRequest().getHeader("DPoP")!!)["nonce"].asString()).isEqualTo("n-1")
    }

    @Test
    fun `a plain 400 is not retried`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"error":"invalid_grant"}"""),
        )

        org.assertj.core.api.Assertions
            .assertThatThrownBy { RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old") }
            .isInstanceOfSatisfying(RefreshTokenException::class.java) {
                assertThat(it.oauthError).isEqualTo("invalid_grant")
            }
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `the same key signs every request of the installation`() {
        server.enqueue(tokenResponse())
        server.enqueue(tokenResponse())

        val sender = Dpop.sender()
        RefreshTokenFlow(issuer = issuer(), sender = sender).refresh("RT-1")
        RefreshTokenFlow(issuer = issuer(), sender = sender).refresh("RT-2")

        val first = header(server.takeRequest().getHeader("DPoP")!!)["jwk"].toString()
        val second = header(server.takeRequest().getHeader("DPoP")!!)["jwk"].toString()
        assertThat(second).isEqualTo(first)
    }

    @Test
    fun `no DPoP key store means no proof and an unchanged request`() {
        Dpop.resetForTest()
        Dpop.storeProvider = { throw TokenStoreUnavailableException("no keychain on this box") }
        server.enqueue(tokenResponse())

        val tokens = RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(tokens.accessToken).isEqualTo("AT-new")
        assertThat(server.takeRequest().getHeader("DPoP")).isNull()
    }

    private fun header(proof: String) = segment(proof, 0)

    private fun claims(proof: String) = segment(proof, 1)

    private fun segment(proof: String, index: Int) = mapper.readTree(
        String(Base64.getUrlDecoder().decode(pad(proof.split(".")[index])), Charsets.UTF_8),
    )

    private fun pad(segment: String) = segment + "=".repeat((4 - segment.length % 4) % 4)

    private class InMemoryStore : DpopKeyStore {
        private var stored: StoredDpopKey? = null
        override fun read(): StoredDpopKey? = stored
        override fun write(key: StoredDpopKey) {
            stored = key
        }

        override fun delete() {
            stored = null
        }
    }
}
