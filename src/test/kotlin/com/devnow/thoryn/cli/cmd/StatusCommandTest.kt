package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.time.Instant

/**
 * SSO-2862 — `thoryn status`: probe hub OIDC discovery + the gateway, report reachability, latency,
 * and (unrefreshed) token validity.
 *
 * The command fires the hub probe first, then the gateway probe, so both can target the shared
 * [MockWebServer] with responses enqueued in that order.
 */
class StatusCommandTest : CommandTestBase() {

    /** A URL on a port nothing is listening on — a connection there is refused (host unreachable). */
    private fun deadUrl(): String {
        val port = ServerSocket(0).use { it.localPort }
        return "http://127.0.0.1:$port"
    }

    @Test
    fun `reports ok when hub and gateway are reachable`() {
        server.enqueue(jsonResponse(200, """{"issuer":"https://hub"}""")) // hub discovery
        server.enqueue(jsonResponse(200, """{"items":[]}"""))             // gateway applications

        val (exit, out, _) = runCli("status", "--hub", baseUrl(), "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["ok"]).isEqualTo(true)
        assertThat(json["hubStatus"]).isEqualTo("HTTP 200")
        assertThat(json["gatewayStatus"]).isEqualTo("HTTP 200")
        assertThat(json["signedIn"]).isEqualTo(true)
        assertThat(json["authAccepted"]).isEqualTo(true)
    }

    @Test
    fun `a 401 from the gateway is reachable but auth not accepted`() {
        server.enqueue(jsonResponse(200, """{"issuer":"https://hub"}"""))
        server.enqueue(jsonResponse(401, """{"error":"invalid_token"}"""))

        val (exit, out, _) = runCli("status", "--hub", baseUrl(), "--gateway", baseUrl(), "--output", "json")

        // hub healthy + gateway reachable → overall ok, even though the token was rejected.
        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["ok"]).isEqualTo(true)
        assertThat(json["gatewayStatus"]).isEqualTo("HTTP 401")
        assertThat(json["authAccepted"]).isEqualTo(false)
    }

    @Test
    fun `exits 3 when the hub is unreachable`() {
        // Gateway probe still hits the live server; only the hub is dead.
        server.enqueue(jsonResponse(200, """{"items":[]}"""))

        val (exit, out, _) = runCli("status", "--hub", deadUrl(), "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_IO_ERROR)
        val json = parseJson(out)
        assertThat(json["ok"]).isEqualTo(false)
        assertThat(json["hubStatus"].toString()).contains("unreachable")
    }

    @Test
    fun `runs signed out and reports not signed in`() {
        clearTokens()
        server.enqueue(jsonResponse(200, """{"issuer":"https://hub"}"""))
        server.enqueue(jsonResponse(401, """{"error":"invalid_token"}""")) // no bearer → 401, still reachable

        val (exit, out, _) = runCli("status", "--hub", baseUrl(), "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["ok"]).isEqualTo(true)
        assertThat(json["signedIn"]).isEqualTo(false)
        assertThat(json["tokenStatus"]).isEqualTo("not signed in")
        assertThat(json).doesNotContainKey("authAccepted")
    }

    @Test
    fun `surfaces the active workspace when one is selected`() {
        SelectedWorkspaceStore().write(SelectedWorkspace(tenantId = "t-1", slug = "testq2", tenantHubIssuer = "https://testq2.hub.example.org"))
        server.enqueue(jsonResponse(200, """{"issuer":"https://hub"}"""))
        server.enqueue(jsonResponse(200, """{"items":[]}"""))

        val (exit, out, _) = runCli("status", "--hub", baseUrl(), "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["activeWorkspace"]).isEqualTo("testq2")
    }

    @Test
    fun `reports an EXPIRED token without refreshing it`() {
        seedTokens(Tokens(accessToken = "AT", refreshToken = "RT", expiresAtEpochSecond = Instant.now().epochSecond - 60))
        server.enqueue(jsonResponse(200, """{"issuer":"https://hub"}"""))
        server.enqueue(jsonResponse(200, """{"items":[]}"""))

        val (exit, out, _) = runCli("status", "--hub", baseUrl(), "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["tokenStatus"].toString()).contains("EXPIRED")
    }
}
