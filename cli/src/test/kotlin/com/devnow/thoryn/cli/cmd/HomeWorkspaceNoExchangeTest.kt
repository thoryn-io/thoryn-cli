package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-3692 — a selection naming the workspace this session SIGNED IN AT (selection issuer == session
 * issuer) is served with the base token: no RFC 8693 exchange. Since SSO-3104 a
 * `thoryn login --workspace thoryn` session's issuer IS the `thoryn` workspace issuer, so
 * `thoryn workspace switch thoryn` used to run a SAME-tenant exchange with no scope — which the hub
 * answered with a scope-less token (`TOKEN_ISSUED … scopes:[]` on staging, 2026-10-14) and every
 * later command died `access_denied` on a `tenant:*` scope gate. A selection naming ANOTHER
 * workspace exchanges exactly as before (`CommandSupportGatewayClientTest`).
 */
class HomeWorkspaceNoExchangeTest : CommandTestBase() {

    @Test
    fun `gatewayClient serves a selection of the sign-in home workspace with the base token and no exchange`() {
        // The session was signed in AT the workspace: its issuer equals the selection's issuer (modulo a
        // trailing slash). The base token carries the login scopes and is the refreshable one.
        val base = Tokens(
            accessToken = "AT-home", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl(),
            scope = "openid tenant:environments.read", workspace = "thoryn", platformIssuer = "https://auth.stg.thoryn.org",
        )
        seedTokens(base)
        val selectedStore = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        selectedStore.write(
            SelectedWorkspace(tenantId = "t-home", slug = "thoryn", tenantHubIssuer = baseUrl() + "/", environmentSlug = "production"),
        )
        // Exactly one response is queued: the gateway call. An exchange would eat it and fail the call.
        server.enqueue(jsonResponse(200, """{"environments":[]}"""))

        CommandSupport.gatewayClient(baseUrl(), base, selectedStore).listEnvironments()

        assertThat(server.requestCount).isEqualTo(1)
        val gatewayCall = server.takeRequest()
        assertThat(gatewayCall.getHeader("Authorization")).isEqualTo("Bearer AT-home")
        // SSO-2870 — the selected environment still rides on the base-token call.
        assertThat(gatewayCall.getHeader("X-Thoryn-Environment")).isEqualTo("production")
    }

    @Test
    fun `workspace switch into the sign-in home workspace records the selection without a validation exchange`() {
        // Session signed in at `acme` on a local-dev platform whose base is the mock; the list goes to the
        // explicit --issuer (the mock), the composed target is `http://acme.localhost:<port>` == the
        // session issuer, so no exchange is attempted (and no DNS lookup of acme.localhost happens).
        val homeIssuer = baseUrl().replace("://", "://acme.")
        seedTokens(Tokens(accessToken = "AT-home", refreshToken = "RT", issuer = homeIssuer, gateway = baseUrl(), platformIssuer = baseUrl()))
        server.enqueue(
            jsonResponse(200, """[{"tenantId":"t-home","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]"""),
        )
        // Would be consumed by the exchange the old code ran — and fail the switch with exit 2.
        server.enqueue(jsonResponse(400, """{"error":"invalid_scope"}"""))

        val (exit, out, err) = runCli("workspace", "switch", "acme", "--issuer", baseUrl(), "--output", "json")

        assertThat(exit).withFailMessage(err).isEqualTo(0)
        assertThat(server.requestCount).isEqualTo(1) // the workspace list only
        assertThat(parseJson(out)["tenantHubIssuer"]).isEqualTo(homeIssuer)
        val selection = Files.readString(tempHome.resolve(".config/thoryn/workspace.json"))
        assertThat(selection).contains("\"slug\":\"acme\"").contains(homeIssuer)
    }

    @Test
    fun `workspace switch into another workspace still runs the validation exchange`() {
        seedTokens(Tokens(accessToken = "AT-home", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl(), platformIssuer = baseUrl()))
        server.enqueue(
            jsonResponse(200, """[{"tenantId":"t-2","slug":"globex","displayName":"Globex","archived":false,"loginUrl":"/x"}]"""),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"globex-token","token_type":"Bearer","expires_in":900}"""))

        val (exit, _, err) = runCli("workspace", "switch", "globex", "--issuer", baseUrl(), "--output", "json")

        assertThat(exit).withFailMessage(err).isEqualTo(0)
        assertThat(server.requestCount).isEqualTo(2)
        server.takeRequest() // list
        assertThat(server.takeRequest().body.readUtf8()).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
    }

    @Test
    fun `sameIssuer compares issuers structurally and never calls a sandbox issuer home`() {
        assertThat(CommandSupport.sameIssuer("https://thoryn.auth.stg.thoryn.org", "https://thoryn.auth.stg.thoryn.org/")).isTrue()
        assertThat(CommandSupport.sameIssuer("https://Thoryn.Auth.stg.thoryn.org", "https://thoryn.auth.stg.thoryn.org")).isTrue()
        assertThat(CommandSupport.sameIssuer("http://acme.localhost:54702", "http://acme.localhost:54702/")).isTrue()
        // A sandbox issuer is a different issuer (own key) — a session on it is not a session on the workspace.
        assertThat(CommandSupport.sameIssuer("https://thoryn.auth.stg.thoryn.org/sandbox-alpha", "https://thoryn.auth.stg.thoryn.org")).isFalse()
        // Another workspace, the platform apex, a different port, nothing.
        assertThat(CommandSupport.sameIssuer("https://thoryn.auth.stg.thoryn.org", "https://acme.auth.stg.thoryn.org")).isFalse()
        assertThat(CommandSupport.sameIssuer("https://auth.stg.thoryn.org", "https://thoryn.auth.stg.thoryn.org")).isFalse()
        assertThat(CommandSupport.sameIssuer("http://acme.localhost:54702", "http://acme.localhost:54703")).isFalse()
        assertThat(CommandSupport.sameIssuer(null, "https://thoryn.auth.stg.thoryn.org")).isFalse()
        assertThat(CommandSupport.sameIssuer("https://thoryn.auth.stg.thoryn.org", "")).isFalse()
    }
}
