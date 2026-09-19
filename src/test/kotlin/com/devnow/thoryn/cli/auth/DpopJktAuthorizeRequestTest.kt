package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.cmd.LoginCommand
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64

/**
 * SSO-3225 — the CLI names its DPoP key on the authorize request (`dpop_jkt`, RFC 9449 §10).
 *
 * ## The hole
 *
 * SSO-3199 got the ACCESS TOKEN sender-constrained to the installation key. The authorization CODE
 * was still bound to nothing — and this flow delivers the code to a **literal-loopback redirect**
 * (RFC 8252 §7.3): `http://127.0.0.1:<port>`, in the clear, on a workstation that may be running
 * other software. Anything that could read that redirect could redeem the code with its own key and
 * be handed a token sender-constrained to the attacker. Binding the token is no use when the
 * attacker gets to pick the key it is bound to.
 *
 * ## What is actually asserted
 *
 * The parameter is worth nothing unless it names **the key that will later sign the proof** — a
 * `dpop_jkt` naming some other key would make every sign-in fail, and a `dpop_jkt` naming a key
 * nobody checks would be decoration. So the central test does not compare the parameter to a
 * constant: it drives a real token request through [Dpop.sender], pulls the `jwk` out of the proof
 * that rode on it, thumbprints it, and compares. That closes the loop the hub will close from the
 * other side.
 *
 * The gate is [DpopCapability] — the same one that decides whether a proof is sent at all
 * (SSO-3221). A platform that does not advertise DPoP gets the pre-SSO-3199 authorize URL.
 */
class DpopJktAuthorizeRequestTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
        Dpop.resetForTest()
        Dpop.storeProvider = { InMemoryDpopKeyStore() }
        DpopCapability.resetForTest()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        Dpop.resetForTest()
        DpopCapability.resetForTest()
    }

    private fun issuer(): String = server.url("/").toString().trimEnd('/')

    /** Serves discovery (advertising DPoP or not) plus a token endpoint. */
    private fun serve(advertisesDpop: Boolean) {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when {
                request.path?.endsWith("/.well-known/openid-configuration") == true -> {
                    val dpop = if (advertisesDpop) {
                        ""","${DpopCapability.DISCOVERY_FIELD}":["ES256"]"""
                    } else {
                        ""
                    }
                    MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("""{"issuer":"${issuer()}","token_endpoint":"${issuer()}/oauth2/token"$dpop}""")
                }

                else -> MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("""{"access_token":"AT","token_type":"Bearer","expires_in":900}""")
            }
        }
    }

    /**
     * The authorize URL the loopback flow would open, built through the same function the flow
     * calls, with the same capability gate the flow applies.
     */
    private fun authorizeUrl(): String = LoginCommand.authorizeUrl(
        issuer = issuer(),
        clientId = "cli",
        redirectUri = "http://127.0.0.1:54321/callback",
        scope = "openid offline_access",
        codeChallenge = "a-challenge",
        state = "st",
        dpopJkt = if (DpopCapability.advertisedBy(issuer())) Dpop.session()?.thumbprint else null,
    )

    private fun dpopJktParameterOf(url: String): String? = url.substringAfter('?')
        .split('&')
        .map { it.split('=', limit = 2) }
        .firstOrNull { it[0] == "dpop_jkt" }
        ?.getOrNull(1)
        ?.let { URLDecoder.decode(it, Charsets.UTF_8) }

    /**
     * The RFC 7638 thumbprint of the key that signed the proof on the token request the CLI just
     * made — recovered from the proof's own `jwk` header, independently of [DpopKey].
     *
     * Fails outright when no token request reached the server: an assertion about a proof that
     * passes because nothing was ever sent would be worthless.
     */
    private fun thumbprintOfProofOnTokenRequest(): String {
        val requests = (1..server.requestCount).map { server.takeRequest() }
        val tokenRequest = requests.firstOrNull { it.path?.contains("/oauth2/token") == true }
        assertThat(tokenRequest)
            .describedAs("no token request reached the server — paths seen: %s", requests.map { it.path })
            .isNotNull()
        val proof = tokenRequest!!.getHeader("DPoP")
        assertThat(proof).describedAs("the token request carried no DPoP proof").isNotNull()

        val headerJson = String(
            Base64.getUrlDecoder().decode(proof!!.substringBefore('.')),
            Charsets.UTF_8,
        )
        val jwk = ObjectMapper().readTree(headerJson)["jwk"]
        assertThat(jwk).describedAs("proof header carried no jwk").isNotNull()
        // RFC 7638 §3.2 — the canonical form for an EC key is {"crv","kty","x","y"}, lexicographic,
        // no whitespace. Re-derived here rather than reused from DpopKey so the two cannot agree on
        // a shared mistake.
        val canonical = """{"crv":"${jwk["crv"].asString()}","kty":"${jwk["kty"].asString()}",""" +
            """"x":"${jwk["x"].asString()}","y":"${jwk["y"].asString()}"}"""
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)),
        )
    }

    // ── the binding ─────────────────────────────────────────────────────────────

    @Test
    fun `dpop_jkt on the authorize request names the very key that later signs the token-request proof`() {
        serve(advertisesDpop = true)

        val sentJkt = dpopJktParameterOf(authorizeUrl())
        // Now perform the token-endpoint leg the same way `thoryn login` does, and look at the key
        // that actually signed the proof.
        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        assertThat(sentJkt)
            .describedAs("the authorize request must name a key, or the code stays redeemable by any key")
            .isNotNull()
        assertThat(sentJkt)
            .describedAs("naming any key other than the one that signs the proof would fail every sign-in")
            .isEqualTo(thumbprintOfProofOnTokenRequest())
    }

    @Test
    fun `the named key is this installation's stable DPoP key`() {
        serve(advertisesDpop = true)

        assertThat(dpopJktParameterOf(authorizeUrl()))
            .describedAs("the keychain key, so a cnf.jkt minted at login is still provable at the next command")
            .isEqualTo(Dpop.session()!!.key.thumbprint)
    }

    // ── the gate (SSO-3221) ─────────────────────────────────────────────────────

    @Test
    fun `no dpop_jkt is sent to a platform that does not advertise DPoP`() {
        serve(advertisesDpop = false)

        val url = authorizeUrl()

        assertThat(url)
            .describedAs("a released binary meets platforms older than itself — send the pre-SSO-3199 authorize URL")
            .doesNotContain("dpop_jkt")
        assertThat(url).contains("code_challenge_method=S256") // …and is otherwise unchanged
    }

    @Test
    fun `asking a platform that does not advertise DPoP never touches the key store`() {
        // The capability question is asked FIRST, exactly as in Dpop.sender: probing the key store
        // would generate a key and print a "DPoP is disabled" warning for a feature that was never
        // going to be used.
        serve(advertisesDpop = false)
        var storeOpened = false
        Dpop.storeProvider = { storeOpened = true; InMemoryDpopKeyStore() }

        authorizeUrl()

        assertThat(storeOpened).isFalse()
    }

    @Test
    fun `no dpop_jkt is sent when no key store is available`() {
        // A machine with no usable secure store sends no proof either, so naming a key would bind
        // the code to something the CLI could not then prove — an unredeemable code.
        serve(advertisesDpop = true)
        Dpop.storeProvider = { error("no keychain on this machine") }

        assertThat(dpopJktParameterOf(authorizeUrl())).isNull()
    }

    @Test
    fun `a blank thumbprint is omitted rather than sent as an empty parameter`() {
        val url = LoginCommand.authorizeUrl(
            issuer = issuer(),
            clientId = "cli",
            redirectUri = "http://127.0.0.1:54321/callback",
            scope = "openid",
            codeChallenge = "a-challenge",
            state = "st",
            dpopJkt = "  ",
        )

        assertThat(url)
            .describedAs("'no key named' and 'a key named badly' are different requests to the hub")
            .doesNotContain("dpop_jkt")
    }

    /** In-memory [DpopKeyStore] — no OS keychain, no files. */
    private class InMemoryDpopKeyStore : DpopKeyStore {
        private var stored: StoredDpopKey? = null
        override fun read(): StoredDpopKey? = stored
        override fun write(key: StoredDpopKey) { stored = key }
        override fun delete() { stored = null }
    }
}
