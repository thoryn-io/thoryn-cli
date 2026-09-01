package com.devnow.thoryn.cli.cmd.examples

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path

/**
 * SSO-2830 — the examples framework: the ephemeral relying party's routing, the
 * per-example state store round-trip, and the registry.
 */
class ExamplesFeatureTest {

    private val issuer = "https://acme.hub.stg.thoryn.org"
    private val clientId = "app-123"
    private var rp: ExampleRelyingParty? = null

    // Never follow redirects — we assert on the 302 Location headers directly.
    private val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @AfterEach
    fun stop() {
        rp?.stop()
    }

    private fun get(path: String): HttpResponse<String> {
        val party = rp!!
        val req = HttpRequest.newBuilder(URI("${party.baseUrl}$path")).GET().build()
        return http.send(req, HttpResponse.BodyHandlers.ofString())
    }

    @Test
    fun `landing page is public and offers sign-in`() {
        rp = ExampleRelyingParty(issuer, clientId).start()
        val resp = get("/")
        assertThat(resp.statusCode()).isEqualTo(200)
        assertThat(resp.body()).contains("Sign in")
    }

    @Test
    fun `protected page redirects to login when there is no session`() {
        rp = ExampleRelyingParty(issuer, clientId).start()
        val resp = get("/protected")
        assertThat(resp.statusCode()).isEqualTo(302)
        assertThat(resp.headers().firstValue("Location")).hasValue("/login")
    }

    @Test
    fun `login starts a PKCE authorization-code flow against the tenant issuer`() {
        rp = ExampleRelyingParty(issuer, clientId).start()
        val resp = get("/login")
        assertThat(resp.statusCode()).isEqualTo(302)
        val location = resp.headers().firstValue("Location").orElse("")
        assertThat(location).startsWith("$issuer/oauth2/authorize")
        assertThat(location)
            .contains("response_type=code")
            .contains("client_id=app-123")
            .contains("code_challenge_method=S256")
            .contains("code_challenge=")
            // the loopback redirect carries the ephemeral port the RP is bound to
            .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A${rp!!.port}%2Fcallback")
    }

    @Test
    fun `state store round-trips and clears`(@TempDir tmp: Path) {
        val store = ExampleStateStore(dir = tmp)
        assertThat(store.read("simple-signin")).isNull()

        store.write(ExampleState(example = "simple-signin", workspaceSlug = "ex-abc", clientId = "cid-1"))
        val read = store.read("simple-signin")
        assertThat(read).isNotNull
        assertThat(read!!.workspaceSlug).isEqualTo("ex-abc")
        assertThat(read.clientId).isEqualTo("cid-1")

        store.clear("simple-signin")
        assertThat(store.read("simple-signin")).isNull()
    }

    @Test
    fun `registry exposes the simple-signin example`() {
        assertThat(ExampleRegistry.byName("simple-signin")).isNotNull
        assertThat(ExampleRegistry.all().map { it.name }).contains("simple-signin")
        assertThat(ExampleRegistry.byName("nope")).isNull()
    }
}
