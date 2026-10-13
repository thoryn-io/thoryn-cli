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
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLDecoder
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64

/**
 * SSO-3234 — `thoryn login` pushes its authorization request (RFC 9126) when the hub advertises the
 * endpoint, and the browser then carries only `client_id` + an opaque `request_uri`.
 *
 * ## What is actually being protected
 *
 * On the plain authorize URL every parameter of the request — scopes, `redirect_uri`, PKCE's
 * `code_challenge`, and since SSO-3225 `dpop_jkt` — passes through the browser: its address bar,
 * its history, its extensions, and anything on the path. A push moves all of that to a direct
 * back-channel POST. So the central assertions here are about **what is left on the URL** and
 * **what actually reached the PAR endpoint** — the same parameter set, moved, not dropped.
 *
 * ## And what must not happen
 *
 * A `4xx` is surfaced, never downgraded. If a rejected push silently retried front-channel, then
 * anything able to forge a single `400` — an on-path proxy, a captive portal — could strip PAR off
 * every sign-in and put the parameters back in the browser. That is the exposure PAR removes, so
 * the failure mode is deliberately loud. A `5xx` or a transport failure is a different thing (the
 * hub is unwell, the older wire shape still works) and does fall back.
 */
class PushedAuthorizationRequestTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
        ParCapability.resetForTest()
        Dpop.resetForTest()
        Dpop.storeProvider = { InMemoryDpopKeyStore() }
        DpopCapability.resetForTest()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
        ParCapability.resetForTest()
        Dpop.resetForTest()
        DpopCapability.resetForTest()
    }

    private fun issuer(): String = server.url("/").toString().trimEnd('/')

    private val parameters: List<Pair<String, String>>
        get() = LoginCommand.authorizeParameters(
            clientId = "cli",
            redirectUri = "http://127.0.0.1:54321/callback",
            scope = "openid offline_access",
            codeChallenge = "a-challenge",
            state = "st-1",
            dpopJkt = "a-thumbprint",
        )

    /**
     * Serves discovery (advertising the PAR endpoint or not) and answers the PAR endpoint with
     * [parStatus] + [parBody].
     */
    private fun serve(
        advertisesPar: Boolean,
        parStatus: Int = 201,
        parBody: String = """{"request_uri":"urn:ietf:params:oauth:request_uri:abc123","expires_in":90}""",
        advertisesDpop: Boolean = false,
    ) {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when {
                request.path?.endsWith("/.well-known/openid-configuration") == true -> {
                    val par = if (advertisesPar) {
                        ""","${ParCapability.DISCOVERY_FIELD}":"${issuer()}/oauth2/par""""
                    } else {
                        ""
                    }
                    val dpop = if (advertisesDpop) ""","${DpopCapability.DISCOVERY_FIELD}":["ES256"]""" else ""
                    MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("""{"issuer":"${issuer()}","token_endpoint":"${issuer()}/oauth2/token"$par$dpop}""")
                }

                request.path?.contains("/oauth2/par") == true ->
                    MockResponse().setResponseCode(parStatus)
                        .setHeader("Content-Type", "application/json")
                        .setBody(parBody)

                request.path?.contains("/oauth2/token") == true ->
                    MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("""{"access_token":"AT","token_type":"Bearer","expires_in":900}""")

                else -> MockResponse().setResponseCode(404)
            }
        }
    }

    private fun carry(err: PrintStream = PrintStream(ByteArrayOutputStream())) =
        LoginCommand.carryAuthorizeRequest(
            issuer = issuer(),
            clientId = "cli",
            parameters = parameters,
            err = err,
        )

    private fun queryOf(url: String): Map<String, String> = url.substringAfter('?')
        .split('&')
        .filter { it.isNotBlank() }
        .associate {
            val (k, v) = it.split('=', limit = 2).let { p -> p[0] to p.getOrElse(1) { "" } }
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }

    private fun parRequest(): RecordedRequest {
        val seen = (1..server.requestCount).map { server.takeRequest() }
        return seen.firstOrNull { it.path?.contains("/oauth2/par") == true }
            ?: error("no PAR request reached the server — paths seen: ${seen.map { it.path }}")
    }

    // ── PAR advertised ──────────────────────────────────────────────────────────

    @Test
    fun `the browser carries only client_id and request_uri when the hub advertises PAR`() {
        serve(advertisesPar = true)

        val carried = carry()!!

        assertThat(carried.pushed).isTrue()
        assertThat(queryOf(carried.authorizeUrl))
            .describedAs("RFC 9126 §4 — the front channel carries the reference, not the request")
            .containsOnlyKeys("client_id", "request_uri")
        assertThat(queryOf(carried.authorizeUrl)["request_uri"])
            .isEqualTo("urn:ietf:params:oauth:request_uri:abc123")
    }

    @Test
    fun `every authorize parameter reaches the PAR endpoint instead of the browser`() {
        serve(advertisesPar = true)

        val carried = carry()!!
        val pushed = parRequest()

        assertThat(pushed.method).isEqualTo("POST")
        assertThat(pushed.getHeader("Content-Type")).startsWith("application/x-www-form-urlencoded")
        val body = pushed.body.readUtf8()
            .split('&')
            .associate {
                val (k, v) = it.split('=', limit = 2).let { p -> p[0] to p.getOrElse(1) { "" } }
                URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
            }

        // The parameters MOVED — they are not on the URL, and they are all here.
        assertThat(body).containsAllEntriesOf(parameters.toMap())
        assertThat(body["code_challenge_method"]).isEqualTo("S256")
        // RFC 9449 §10.1 — the DPoP key is named with `dpop_jkt` in the POST body, so the binding is
        // the same whether or not PAR is in play.
        assertThat(body["dpop_jkt"]).isEqualTo("a-thumbprint")
        // RFC 9126 §2 — a public client's `client_id` IS its authentication; no secret, no header.
        assertThat(pushed.getHeader("Authorization")).isNull()
        // RFC 9126 §2.1 — `request_uri` MUST NOT be provided in a pushed request.
        assertThat(body).doesNotContainKey("request_uri")

        assertThat(queryOf(carried.authorizeUrl)).doesNotContainKeys("code_challenge", "scope", "dpop_jkt", "state")
    }

    @Test
    fun `the wait is clipped to the pushed request's expires_in`() {
        serve(
            advertisesPar = true,
            parBody = """{"request_uri":"urn:ietf:params:oauth:request_uri:short","expires_in":45}""",
        )

        assertThat(carry()!!.wait)
            .describedAs("RFC 9126 §2.2 — waiting past the request_uri's life only fails later and less clearly")
            .isEqualTo(Duration.ofSeconds(45))
    }

    @Test
    fun `a hub that omits expires_in leaves the ordinary loopback wait in place`() {
        serve(advertisesPar = true, parBody = """{"request_uri":"urn:ietf:params:oauth:request_uri:nott1"}""")

        assertThat(carry()!!.wait).isEqualTo(Duration.ofMinutes(5))
    }

    // ── PAR not advertised ──────────────────────────────────────────────────────

    @Test
    fun `a hub that does not advertise PAR gets the plain authorize URL`() {
        serve(advertisesPar = false)

        val carried = carry()!!

        assertThat(carried.pushed).isFalse()
        val query = queryOf(carried.authorizeUrl)
        assertThat(query["response_type"]).isEqualTo("code")
        assertThat(query["code_challenge"]).isEqualTo("a-challenge")
        assertThat(query["code_challenge_method"]).isEqualTo("S256")
        assertThat(query["dpop_jkt"]).isEqualTo("a-thumbprint")
        assertThat(query["state"]).isEqualTo("st-1")
        assertThat(query).doesNotContainKey("request_uri")
    }

    // ── failure handling ────────────────────────────────────────────────────────

    @Test
    fun `a 4xx from the PAR endpoint fails the sign-in rather than silently downgrading it`() {
        serve(advertisesPar = true, parStatus = 400, parBody = """{"error":"invalid_scope","error_description":"unknown scope"}""")
        val err = ByteArrayOutputStream()

        val carried = carry(PrintStream(err, true, Charsets.UTF_8))

        assertThat(carried)
            .describedAs(
                "a rejected push must not retry front-channel: one forged 400 would otherwise strip " +
                    "PAR off every sign-in and put the parameters back in the browser",
            )
            .isNull()
        assertThat(err.toString(Charsets.UTF_8))
            .contains("rejected the pushed authorization request")
            .contains("invalid_scope")
            .contains("unknown scope")
    }

    @Test
    fun `a 5xx from the PAR endpoint falls back to the plain authorize URL`() {
        serve(advertisesPar = true, parStatus = 503, parBody = "")
        val err = ByteArrayOutputStream()

        val carried = carry(PrintStream(err, true, Charsets.UTF_8))!!

        assertThat(carried.pushed).isFalse()
        assertThat(queryOf(carried.authorizeUrl)["code_challenge"]).isEqualTo("a-challenge")
        assertThat(err.toString(Charsets.UTF_8)).contains("could not push the authorization request")
    }

    @Test
    fun `an unreachable PAR endpoint falls back to the plain authorize URL`() {
        // Advertise a PAR endpoint on a port nothing is listening on.
        val dead = java.net.ServerSocket(0).use { "http://127.0.0.1:${it.localPort}/oauth2/par" }
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"issuer":"${issuer()}","${ParCapability.DISCOVERY_FIELD}":"$dead"}""")
        }
        val err = ByteArrayOutputStream()

        val carried = carry(PrintStream(err, true, Charsets.UTF_8))!!

        assertThat(carried.pushed).isFalse()
        assertThat(queryOf(carried.authorizeUrl)["code_challenge"]).isEqualTo("a-challenge")
    }

    @Test
    fun `a 201 without a request_uri is treated as unavailable, not as a push`() {
        serve(advertisesPar = true, parBody = """{"expires_in":60}""")

        val carried = carry()!!

        assertThat(carried.pushed).isFalse()
        assertThat(queryOf(carried.authorizeUrl)["code_challenge"]).isEqualTo("a-challenge")
    }

    // ── the capability read itself ──────────────────────────────────────────────

    @Test
    fun `the advertised endpoint is read from discovery and memoised per hub`() {
        serve(advertisesPar = true)

        assertThat(ParCapability.endpointFor(issuer())).isEqualTo("${issuer()}/oauth2/par")
        // Second ask must not re-probe: swap the dispatcher for one that would answer differently.
        serve(advertisesPar = false)
        assertThat(ParCapability.endpointFor(issuer())).isEqualTo("${issuer()}/oauth2/par")
    }

    @Test
    fun `an unreachable or unparseable discovery document answers no PAR`() {
        assertThat(ParCapability.endpointIn(null)).isNull()
        assertThat(ParCapability.endpointIn("not json")).isNull()
        assertThat(ParCapability.endpointIn("""{"issuer":"https://hub"}""")).isNull()
        assertThat(ParCapability.endpointIn("""{"${ParCapability.DISCOVERY_FIELD}":"  "}""")).isNull()
        assertThat(ParCapability.endpointIn("""{"${ParCapability.DISCOVERY_FIELD}":"https://hub/oauth2/par"}"""))
            .isEqualTo("https://hub/oauth2/par")
    }

    // ── composing with the SSO-3227 key ladder ──────────────────────────────────

    /**
     * SSO-3234 × SSO-3227 — the `dpop_jkt` that reaches the PAR body must name **the key that will
     * later sign the token-request proof**, exactly as SSO-3225 requires of the front-channel
     * parameter. Moving the parameter to a back channel changes the carrier, not the contract.
     *
     * This does not compare the parameter to a constant, which would only prove the CLI
     * self-consistent. It drives a real token request through [Dpop.sender], pulls the `jwk` out of
     * the proof that actually rode on it, re-derives the RFC 7638 thumbprint independently of
     * [DpopKey] so the two cannot share a mistake, and compares that with what was pushed.
     *
     * The failure this guards is specific and silent: a future refactor that reads the key again on
     * the PAR path — with the ladder's default `provision = false` — would push a *different* (or
     * absent) thumbprint from the one that signs, and every sign-in on a machine that upgrades its
     * key class would fail `invalid_grant` with nothing in the URL to explain it. The login path
     * therefore resolves the key ONCE and hands the same value to whichever carrier is used.
     */
    @Test
    fun `the dpop_jkt pushed in the PAR body names the key that signs the token-request proof`() {
        serve(advertisesPar = true, advertisesDpop = true)

        // Exactly what LoginCommand.dpopJkt() does on the login path, `provision = true` included.
        val jkt = if (DpopCapability.advertisedBy(issuer())) Dpop.session(provision = true)?.thumbprint else null
        assertThat(jkt).describedAs("the login path must resolve a key when the hub advertises DPoP").isNotNull()

        val parameters = LoginCommand.authorizeParameters(
            clientId = "cli",
            redirectUri = "http://127.0.0.1:54321/callback",
            scope = "openid",
            codeChallenge = "a-challenge",
            state = "st-1",
            dpopJkt = jkt,
        )
        val carried = LoginCommand.carryAuthorizeRequest(
            issuer = issuer(),
            clientId = "cli",
            parameters = parameters,
        )!!
        assertThat(carried.pushed).isTrue()

        // The token-endpoint leg the same way `thoryn login` performs it.
        RefreshTokenFlow(issuer = issuer(), sender = Dpop.sender()).refresh("RT-old")

        val requests = (1..server.requestCount).map { server.takeRequest() }
        val pushed = requests.firstOrNull { it.path?.contains("/oauth2/par") == true }
            ?: error("no PAR request reached the server — paths seen: ${requests.map { it.path }}")
        val pushedJkt = formOf(pushed.body.readUtf8())["dpop_jkt"]

        assertThat(pushedJkt)
            .describedAs("naming any key other than the one that signs the proof would fail every sign-in")
            .isEqualTo(thumbprintOfProofOn(requests, "/oauth2/token"))
        assertThat(pushedJkt).isEqualTo(jkt)
    }

    /**
     * RFC 9449 §10.1 offers two ways to name the key on a pushed request: `dpop_jkt` in the body, or
     * a `DPoP` proof header. The CLI uses the first. §10.1 requires the two to AGREE when both are
     * sent, so sending the header as well buys nothing — and it would spend a single-use `jti` on a
     * request that is not a grant.
     */
    @Test
    fun `the push carries dpop_jkt in the body and no DPoP proof header`() {
        serve(advertisesPar = true, advertisesDpop = true)
        val jkt = Dpop.session(provision = true)!!.thumbprint

        LoginCommand.carryAuthorizeRequest(
            issuer = issuer(),
            clientId = "cli",
            parameters = LoginCommand.authorizeParameters(
                clientId = "cli",
                redirectUri = "http://127.0.0.1:54321/callback",
                scope = "openid",
                codeChallenge = "a-challenge",
                state = "st-1",
                dpopJkt = jkt,
            ),
        )

        val pushed = parRequest()
        assertThat(formOf(pushed.body.readUtf8())["dpop_jkt"]).isEqualTo(jkt)
        assertThat(pushed.getHeader("DPoP"))
            .describedAs("RFC 9449 §10.1 — the body parameter is the mechanism in use; the header is the alternative, not an addition")
            .isNull()
    }

    private fun formOf(body: String): Map<String, String> = body
        .split('&')
        .filter { it.isNotBlank() }
        .associate {
            val (k, v) = it.split('=', limit = 2).let { p -> p[0] to p.getOrElse(1) { "" } }
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }

    /**
     * The RFC 7638 thumbprint of the key that signed the DPoP proof on the request to [path],
     * recovered from the proof's own `jwk` header — re-derived here rather than reused from
     * [DpopKey] so the two cannot agree on a shared mistake.
     */
    private fun thumbprintOfProofOn(requests: List<RecordedRequest>, path: String): String {
        val request = requests.firstOrNull { it.path?.contains(path) == true }
            ?: error("no request to $path reached the server — paths seen: ${requests.map { it.path }}")
        val proof = request.getHeader("DPoP") ?: error("the request to $path carried no DPoP proof")
        val headerJson = String(Base64.getUrlDecoder().decode(proof.substringBefore('.')), Charsets.UTF_8)
        val jwk = ObjectMapper().readTree(headerJson)["jwk"] ?: error("proof header carried no jwk")
        // RFC 7638 §3.2 — canonical EC form is {"crv","kty","x","y"}, lexicographic, no whitespace.
        val canonical = """{"crv":"${jwk["crv"].asString()}","kty":"${jwk["kty"].asString()}",""" +
            """"x":"${jwk["x"].asString()}","y":"${jwk["y"].asString()}"}"""
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)),
        )
    }

    /** In-memory [DpopKeyStore] — no OS keychain, no files. */
    private class InMemoryDpopKeyStore : DpopKeyStore {
        private var stored: StoredDpopKey? = null
        override fun read(): StoredDpopKey? = stored
        override fun write(key: StoredDpopKey) { stored = key }
        override fun delete() { stored = null }
    }
}
