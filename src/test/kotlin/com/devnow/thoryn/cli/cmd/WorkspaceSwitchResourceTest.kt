package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3379 — the RFC 8693 `resource` of a workspace switch is composed from the platform BASE issuer,
 * never by prefixing the slug onto the session issuer.
 *
 * Since SSO-3360 the hub resolves `resource` through the platform issuer rule: a workspace issuer is
 * exactly `https://{slug}.auth.<env>` (or `/{env}`, or an active custom domain) and anything else is
 * `invalid_target`. After an interactive sign-in the session issuer is already a WORKSPACE issuer
 * (`https://thoryn.auth.stg.thoryn.org`), so the old slug-prefix produced
 * `https://acme.thoryn.auth.stg.thoryn.org`.
 */
class WorkspaceSwitchResourceTest : CommandTestBase() {

    private val stagingBase = "https://auth.stg.thoryn.org"
    private val homeWorkspaceIssuer = "https://thoryn.auth.stg.thoryn.org"

    @Test
    fun `a workspace issuer composed from a workspace-issuer session names the target workspace, not a nested host`() {
        assertThat(WorkspaceTenantHost.tenantIssuer(homeWorkspaceIssuer, "acme"))
            .isEqualTo("https://acme.auth.stg.thoryn.org")
        // The pre-SSO-3297 `hub.` label composes the same way.
        assertThat(WorkspaceTenantHost.tenantIssuer("https://thoryn.hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.hub.stg.thoryn.org")
        // A sandbox session issuer (`…/{env}`) drops its path — the target is the workspace itself.
        assertThat(WorkspaceTenantHost.tenantIssuer("$homeWorkspaceIssuer/sandbox-alpha", "acme"))
            .isEqualTo("https://acme.auth.stg.thoryn.org")
        // The base itself composes as before.
        assertThat(WorkspaceTenantHost.tenantIssuer(stagingBase, "acme"))
            .isEqualTo("https://acme.auth.stg.thoryn.org")
    }

    @Test
    fun `the platform issuer is the one recorded at login`() {
        val session = Tokens(accessToken = "AT", issuer = homeWorkspaceIssuer, platformIssuer = stagingBase)
        assertThat(CommandSupport.resolvePlatformIssuer(ThorynConfig.DEFAULT_HUB, session)).isEqualTo(stagingBase)
    }

    @Test
    fun `a token file written before SSO-3379 falls back to the base of its workspace issuer`() {
        val legacy = Tokens(accessToken = "AT", issuer = homeWorkspaceIssuer)
        val base = CommandSupport.resolvePlatformIssuer(ThorynConfig.DEFAULT_HUB, legacy)
        assertThat(base).isEqualTo(stagingBase)
        assertThat(WorkspaceTenantHost.tenantIssuer(base, "acme")).isEqualTo("https://acme.auth.stg.thoryn.org")
    }

    @Test
    fun `an explicit issuer override is the platform base, and a workspace issuer passed there is normalised`() {
        val session = Tokens(accessToken = "AT", issuer = homeWorkspaceIssuer, platformIssuer = stagingBase)
        assertThat(CommandSupport.resolvePlatformIssuer("https://auth.example.org", session))
            .isEqualTo("https://auth.example.org")
        assertThat(CommandSupport.resolvePlatformIssuer("https://beta.auth.example.org/", session))
            .isEqualTo("https://auth.example.org")
    }

    @Test
    fun `workspace switch sends the target workspace issuer composed from the platform base as the resource`() {
        // The hub calls go to the MockWebServer (the session issuer); the platform base recorded at
        // login is staging-shaped, as after `thoryn login --workspace thoryn --issuer <staging>`.
        seedTokens(
            Tokens(
                accessToken = "AT-test",
                refreshToken = "RT",
                issuer = baseUrl(),
                gateway = baseUrl(),
                platformIssuer = stagingBase,
            ),
        )
        server.enqueue(
            jsonResponse(200, """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]"""),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"acme-tenant-token","token_type":"Bearer","expires_in":900}"""))

        val (exit, out, err) = runCli("workspace", "switch", "acme", "--output", "json")

        assertThat(exit).withFailMessage(err).isEqualTo(0)
        assertThat(parseJson(out)["tenantHubIssuer"]).isEqualTo("https://acme.auth.stg.thoryn.org")
        server.takeRequest() // workspace list
        val exchange = server.takeRequest().body.readUtf8()
        assertThat(exchange).contains("resource=https%3A%2F%2Facme.auth.stg.thoryn.org")
            .doesNotContain("thoryn.auth.stg.thoryn.org")
    }

    @Test
    fun `a nested selection stored by an older CLI is healed before the gateway exchange`() {
        val base = Tokens(accessToken = "AT-base", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl(), platformIssuer = stagingBase)
        seedTokens(base)
        val store = SelectedWorkspaceStore(path = tempHome.resolve("ws.json"))
        store.write(
            SelectedWorkspace(tenantId = "t-1", slug = "acme", tenantHubIssuer = "https://acme.thoryn.auth.stg.thoryn.org"),
        )
        server.enqueue(jsonResponse(200, """{"access_token":"switched-token","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"items":[],"total":0}"""))

        CommandSupport.gatewayClient(baseUrl(), base, store).listApplications()

        val exchange = server.takeRequest().body.readUtf8()
        assertThat(exchange).contains("resource=https%3A%2F%2Facme.auth.stg.thoryn.org")
            .doesNotContain("acme.thoryn.auth")
    }

    @Test
    fun `a clean stored selection is used verbatim`() {
        val clean = SelectedWorkspace(tenantId = "t-1", slug = "acme", tenantHubIssuer = "https://acme.auth.stg.thoryn.org")
        assertThat(WorkspaceTenantHost.healedSelection(clean, "https://auth.other.example")).isEqualTo(clean.tenantHubIssuer)
        val local = SelectedWorkspace(tenantId = "t-1", slug = "acme", tenantHubIssuer = "http://acme.localhost:54702")
        assertThat(WorkspaceTenantHost.healedSelection(local, "http://localhost:54702")).isEqualTo(local.tenantHubIssuer)
    }
}
