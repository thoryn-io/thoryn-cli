package com.devnow.thoryn.cli.auth

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

/**
 * SSO-3221 — the CLI attaches a DPoP proof **only to a platform that advertises DPoP**.
 *
 * ## What went wrong
 *
 * `cli-v0.20.0` sent a proof on every token request. Spring Authorization Server binds whenever a
 * valid proof is present, without consulting the client's `dpop_required` flag, so the hub answered
 * `token_type: DPoP`; the CLI's `Authorization` scheme follows `token_type`, so it began presenting
 * `DPoP <token>` to resource servers that did not accept the scheme, and every customer-plane call
 * answered 401. Every scheduled thoryn-examples run went red from 2026-09-19 04:23 UTC — from a
 * client release, against an unchanged platform.
 *
 * The hub half of SSO-3221 stops binding unless the client opted in. This suite covers the client
 * half, which is deliberately redundant with it: a released binary outlives any single platform
 * version, so the CLI must not assume every deployment it ever meets carries the hub fix.
 *
 * The whole test is the presence or absence of the `DPoP` request header on the token request, and
 * with it the `Authorization` scheme the CLI ends up using.
 */
class DpopCapabilityGateTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
        Dpop.resetForTest()
        Dpop.storeProvider = { InMemoryStore() }
        DpopCapability.resetForTest()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        Dpop.resetForTest()
        DpopCapability.resetForTest()
    }

    private fun issuer(): String = server.url("/").toString().trimEnd('/')

    /**
     * Serves both the discovery document and the token endpoint, so the capability probe and the
     * token request can be interleaved the way they are in a real invocation. [dpopAlgorithms] null
     * means a platform that does not advertise DPoP — the pre-PR-3643 staging stack.
     */
    private fun serve(dpopAlgorithms: String?) {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when {
                request.path?.endsWith("/.well-known/openid-configuration") == true ->
                    MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody(discovery(dpopAlgorithms))

                else -> MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("""{"access_token":"AT-new","refresh_token":"RT-new","token_type":"Bearer","expires_in":900}""")
            }
        }
    }

    private fun discovery(dpopAlgorithms: String?): String {
        val dpop = dpopAlgorithms?.let { ""","${DpopCapability.DISCOVERY_FIELD}":$it""" } ?: ""
        return """{"issuer":"${issuer()}","token_endpoint":"${issuer()}/oauth2/token"$dpop}"""
    }

    /**
     * The `DPoP` header on the token request, skipping the discovery probe that may precede it.
     *
     * Fails outright when no token request was made: a "no proof was sent" assertion that passes
     * because nothing was sent at all would be worthless, and this is the file where that mistake
     * would be invisible.
     */
    private fun proofOnTokenRequest(): String? {
        val requests = (1..server.requestCount).map { server.takeRequest() }
        val tokenRequest = requests.firstOrNull { it.path?.contains("/oauth2/token") == true }
        assertThat(tokenRequest)
            .describedAs("no token request reached the server — paths seen: %s", requests.map { it.path })
            .isNotNull()
        return tokenRequest!!.getHeader("DPoP")
    }

    // ── the regression ──────────────────────────────────────────────────────────

    @Test
    fun `no proof is sent to a platform whose discovery does not advertise DPoP`() {
        serve(dpopAlgorithms = null)

        val tokens = RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(proofOnTokenRequest())
            .describedAs("a pre-DPoP platform must see the exact wire shape it saw before cli-v0.20.0")
            .isNull()
        assertThat(DpopSession.schemeFor(tokens))
            .describedAs("no proof means no cnf.jkt means token_type Bearer means Authorization: Bearer")
            .isEqualTo("Bearer")
    }

    @Test
    fun `an empty algorithm list is not an advertisement`() {
        serve(dpopAlgorithms = "[]")

        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(proofOnTokenRequest())
            .describedAs("RFC 9449 section 5.1 advertises the algorithms the AS accepts — none means none")
            .isNull()
    }

    @Test
    fun `an unreachable hub answers no rather than throwing`() {
        // A closed port, through the REAL probe: the discovery fetch has to swallow its own I/O
        // failure. A hub that cannot serve discovery is a hub the command was about to fail against
        // anyway, and the capability question must not be the thing that reports it.
        val closed = MockWebServer().also { it.start() }
        val base = closed.url("/").toString().trimEnd('/')
        closed.shutdown()

        assertThat(DpopCapability.advertisedBy(base)).isFalse()
    }

    @Test
    fun `a discovery document that cannot be fetched answers no`() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when {
                request.path?.endsWith("/.well-known/openid-configuration") == true ->
                    MockResponse().setResponseCode(503)

                else -> MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("""{"access_token":"AT-new","token_type":"Bearer","expires_in":900}""")
            }
        }

        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(proofOnTokenRequest())
            .describedAs("no advertisement, no proof — the shape that cannot break anything")
            .isNull()
    }

    // ── and the platform that does advertise ────────────────────────────────────

    @Test
    fun `a proof is sent to a platform that advertises DPoP`() {
        serve(dpopAlgorithms = """["ES256","RS256","PS256"]""")

        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(proofOnTokenRequest())
            .describedAs("the whole point of SSO-3199 still works where the platform understands it")
            .isNotNull()
    }

    @Test
    fun `the hub is probed at most once per process`() {
        serve(dpopAlgorithms = """["ES256"]""")

        repeat(3) { RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old") }

        val discoveryRequests = (1..server.requestCount)
            .map { server.takeRequest() }
            .count { it.path?.endsWith("/.well-known/openid-configuration") == true }
        assertThat(discoveryRequests)
            .describedAs("memoised per hub — one small GET, not one per token request")
            .isEqualTo(1)
    }

    // ── the pieces ──────────────────────────────────────────────────────────────

    @Test
    fun `hubBaseOf strips the token endpoint so a path-prefixed hub still resolves`() {
        assertThat(DpopCapability.hubBaseOf(URI.create("https://hub.example.org/oauth2/token")))
            .isEqualTo("https://hub.example.org")
        assertThat(DpopCapability.hubBaseOf(URI.create("https://example.org/hub/oauth2/token")))
            .describedAs("a hub under a path prefix serves its discovery document under the same prefix")
            .isEqualTo("https://example.org/hub")
        assertThat(DpopCapability.hubBaseOf(URI.create("https://hub.example.org/oauth2/device_authorization")))
            .isEqualTo("https://hub.example.org")
        assertThat(DpopCapability.hubBaseOf(URI.create("https://hub.example.org/something/else")))
            .describedAs("anything unrecognised falls back to the origin")
            .isEqualTo("https://hub.example.org")
    }

    @Test
    fun `advertisesDpop reads the RFC 9449 discovery field and nothing else`() {
        assertThat(DpopCapability.advertisesDpop("""{"${DpopCapability.DISCOVERY_FIELD}":["ES256"]}""")).isTrue()
        assertThat(DpopCapability.advertisesDpop("""{"${DpopCapability.DISCOVERY_FIELD}":[]}""")).isFalse()
        assertThat(DpopCapability.advertisesDpop("""{"issuer":"https://hub.example.org"}""")).isFalse()
        assertThat(DpopCapability.advertisesDpop("not json")).isFalse()
        assertThat(DpopCapability.advertisesDpop("")).isFalse()
        assertThat(DpopCapability.advertisesDpop(null)).isFalse()
    }

    @Test
    fun `a blank hub base is never advertised`() {
        assertThat(DpopCapability.advertisedBy(null)).isFalse()
        assertThat(DpopCapability.advertisedBy("   ")).isFalse()
    }

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
