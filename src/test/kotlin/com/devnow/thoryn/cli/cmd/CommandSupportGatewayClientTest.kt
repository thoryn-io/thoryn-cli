package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2863 — `CommandSupport.gatewayClient` honours an active `workspace switch` by minting a
 * token FOR the selected tenant from the refreshable base session on demand, instead of relying on
 * a persisted (non-refreshable) exchanged token.
 *
 * The single [MockWebServer] stands in for both the hub `/oauth2/token` (token exchange) and the
 * gateway `/api/v1/applications` — the exchange fires first, then the gateway call.
 */
class CommandSupportGatewayClientTest : CommandTestBase() {

    @Test
    fun `with a selected workspace it exchanges the base token and calls the gateway with the switched bearer`() {
        // Base session in the store: has an issuer (so the exchange has a hub) and no expiry
        // (so ensureFresh returns it without a refresh round-trip).
        val base = Tokens(accessToken = "AT-base", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)

        val selectedStore = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selectedStore.write(
            SelectedWorkspace(tenantId = "t-1", slug = "acme", tenantHubIssuer = "https://acme.hub.example.org"),
        )

        // 1) token-exchange response, then 2) the gateway list response.
        server.enqueue(jsonResponse(200, """{"access_token":"switched-token","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"items":[],"total":0}"""))

        val client = CommandSupport.gatewayClient(baseUrl(), base, selectedStore)
        val result = client.listApplications()

        assertThat(result["total"].asInt()).isEqualTo(0)

        val exchange = server.takeRequest()
        val body = exchange.body.readUtf8()
        assertThat(body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
        assertThat(body).contains("resource=https%3A%2F%2Facme.hub.example.org")

        // The gateway call carried the SWITCHED bearer, not the base token.
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer switched-token")
    }

    @Test
    fun `SSO-2870 - a selected environment rides on the switched call as X-Thoryn-Environment`() {
        val base = Tokens(accessToken = "AT-base", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        val selectedStore = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selectedStore.write(
            SelectedWorkspace(
                tenantId = "t-1", slug = "acme",
                tenantHubIssuer = "https://acme.hub.example.org", environmentSlug = "sandbox-alpha",
            ),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"switched-token","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"items":[],"total":0}"""))

        CommandSupport.gatewayClient(baseUrl(), base, selectedStore).listApplications()

        server.takeRequest() // the token exchange
        val gatewayCall = server.takeRequest()
        assertThat(gatewayCall.getHeader("Authorization")).isEqualTo("Bearer switched-token")
        assertThat(gatewayCall.getHeader("X-Thoryn-Environment")).isEqualTo("sandbox-alpha")
    }

    @Test
    fun `SSO-2870 - applyEnvironment=false omits the environment header (env-management path)`() {
        val base = Tokens(accessToken = "AT-base", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        val selectedStore = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selectedStore.write(
            SelectedWorkspace(
                tenantId = "t-1", slug = "acme",
                tenantHubIssuer = "https://acme.hub.example.org", environmentSlug = "sandbox-alpha",
            ),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"switched-token","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"environments":[]}"""))

        CommandSupport.gatewayClient(baseUrl(), base, selectedStore, applyEnvironment = false).listEnvironments()

        server.takeRequest() // the token exchange
        assertThat(server.takeRequest().getHeader("X-Thoryn-Environment")).isNull()
    }

    @Test
    fun `with no selected workspace it uses the base token directly (no exchange)`() {
        val base = Tokens(accessToken = "AT-base", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        val emptyStore = SelectedWorkspaceStore(path = tempHome.resolve("absent.json")) // nothing written

        server.enqueue(jsonResponse(200, """{"items":[],"total":0}"""))

        CommandSupport.gatewayClient(baseUrl(), base, emptyStore).listApplications()

        // Exactly one request (the gateway call), carrying the base bearer — no token exchange.
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer AT-base")
    }
}
