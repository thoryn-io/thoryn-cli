package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.api.ProductApiClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.util.Base64

/**
 * SSO-3568 — **the CLI never sends the same `jti` twice** (RFC 9449 §4.3, §11.1).
 *
 * ## Why this test exists
 *
 * SSO-3568 reported this, and raised it as a hypothesis rather than a finding:
 *
 * > `DPoP proof has already been used` suggests the proof minted for the refresh attempt was reused
 * > for the subsequent resource call.
 *
 * It was not. The hub-side chain landed the same day settles it:
 *
 * - **oathy SSO-3572** — the api-gateway and product-api BOTH enforce single-use and both wrote the
 *   replay key `dpop:jti:<jkt>:<jti>` into ONE namespace. The gateway consumed the `jti`, forwarded
 *   the request with the proof intact, and product-api found the key already present, so *every
 *   proxied request* looked replayed. One proof, two enforcing tiers, a shared keyspace. The fix
 *   namespaces them (`dpop:jti:gw:` / `dpop:jti:papi:` / `dpop:jti:hub:`), and its own commit
 *   message records that the proof carried a FRESH `jti` and that "the only party reporting it was
 *   the CLI, and neither server recorded a thing."
 * - **oathy SSO-3570** — the companion `invalid_grant` on a refresh seconds after a successful login:
 *   the hub persisted the `cnf` MAP claim via `toString()`, so it read back as the literal
 *   `"{jkt=abc}"`, `as? Map<*, *>` yielded null, and every session looked unbound to the strict DPoP
 *   cutover. Also not the CLI.
 *
 * So there was nothing to fix on this side — but the hypothesis was a reasonable one and cost real
 * time, so the invariant it doubted is pinned here rather than left to be re-derived. [DpopProofTest]
 * covers `jti` freshness at the [DpopSession.proof] call; this covers it **on the wire**, across the
 * retry paths where a reused proof would actually be a defect: the `use_dpop_nonce` retry and the
 * refresh-and-retry after a `401`.
 */
class DpopProofUniquenessTest {

    private lateinit var server: MockWebServer
    private val mapper = ObjectMapper()
    private val session = DpopSession(DpopKey.generate())

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

    /** Every `jti` the server actually received, in order. */
    private fun receivedJtis(count: Int): List<String> = (1..count).map {
        val proof = server.takeRequest().getHeader("DPoP")
        assertThat(proof).isNotBlank()
        val claims = mapper.readTree(Base64.getUrlDecoder().decode(proof!!.split(".")[1]))
        claims["jti"].asString()
    }

    private fun client(tokens: Tokens, reauthenticate: (() -> Tokens?)? = null) = ProductApiClient(
        gateway = baseUrl(),
        tokens = tokens,
        reauthenticate = reauthenticate,
        dpop = session,
    )

    @Test
    fun `two consecutive requests on one session carry distinct jtis`() {
        // The ticket's pair, in the order it reported them: a call, then the next call.
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))
        val client = client(Tokens(accessToken = "AT-1", tokenType = "DPoP"))

        client.listApplications()
        client.listApplications()

        assertThat(receivedJtis(2).distinct()).hasSize(2)
    }

    @Test
    fun `the nonce retry re-signs rather than replaying the challenged proof`() {
        // RFC 9449 §8. The retry is the same request, so replaying its proof would be the easy bug —
        // and the one that would make a legitimate retry indistinguishable from an attack.
        server.enqueue(
            MockResponse().setResponseCode(401)
                .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                .setHeader("DPoP-Nonce", "nonce-1"),
        )
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        client(Tokens(accessToken = "AT-bound", tokenType = "DPoP")).listApplications()

        assertThat(server.requestCount).isEqualTo(2)
        assertThat(receivedJtis(2).distinct()).hasSize(2)
    }

    @Test
    fun `the refresh-and-retry after a 401 carries a new jti, not the refused one`() {
        // The path SSO-3568 worried about generalising to "every legitimate retry path".
        server.enqueue(json(401, """{"error":"invalid_token"}"""))
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        client(
            Tokens(accessToken = "AT-old", tokenType = "DPoP"),
            reauthenticate = { Tokens(accessToken = "AT-new", tokenType = "DPoP") },
        ).listApplications()

        assertThat(server.requestCount).isEqualTo(2)
        assertThat(receivedJtis(2).distinct()).hasSize(2)
    }

    @Test
    fun `a token-endpoint proof and the resource proof that follows it differ`() {
        // The exact sequence from the report: the hub token endpoint, then the gateway resource call.
        // These are separate `HttpRequest`s through the same process-wide session — the shape in which
        // a cached or memoised proof object would have shown up as a reused `jti`.
        server.enqueue(json(200, """{"access_token":"AT-new","token_type":"DPoP","expires_in":900}"""))
        server.enqueue(json(200, """{"data":[],"pagination":{}}"""))

        RefreshTokenFlow(
            issuer = baseUrl(),
            sender = HttpSender { request, handler ->
                session.send(request) { decorated -> java.net.http.HttpClient.newHttpClient().send(decorated, handler) }
            },
            clientId = "cli",
        ).refresh("RT-1")
        client(Tokens(accessToken = "AT-new", tokenType = "DPoP")).listApplications()

        assertThat(receivedJtis(2).distinct()).hasSize(2)
    }

    @Test
    fun `many proofs in one process are all distinct`() {
        // A process-wide `DpopSession` is memoised by `Dpop.session()`; the PROOF must not be. 200 is
        // enough to catch a per-session or per-origin cache, which is what the hypothesis described.
        val jtis = (1..200).map { session.proof("GET", java.net.URI.create("https://api.example.test/x")) }
            .map { mapper.readTree(Base64.getUrlDecoder().decode(it.split(".")[1]))["jti"].asString() }

        assertThat(jtis.distinct()).hasSize(200)
    }
}
