package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3104 — interactive sign-in (loopback / device-code) happens ON A WORKSPACE: `--workspace <slug>`
 * (or THORYN_WORKSPACE) is required and the issuer becomes the workspace's tenant hub. The shared
 * default tenant is not a sign-in target any more, and the CLI's own login client is `cli`, provisioned
 * in the `thoryn` workspace from this repo's `.thoryn/provision.yaml`.
 */
class LoginWorkspaceTest : CommandTestBase() {

    @Test
    fun `an interactive login without a workspace is refused before any network activity`() {
        val (exit, _, err) = runCli("login", "--issuer", "https://hub.stg.thoryn.org")
        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("no workspace selected").contains("--workspace <slug>").contains(ThorynConfig.WORKSPACE_ENV)
        assertThat(server.requestCount).isEqualTo(0)

        val (deviceExit, _, deviceErr) = runCli("login", "--device-code", "--issuer", "https://hub.stg.thoryn.org")
        assertThat(deviceExit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(deviceErr).contains("no workspace selected")
    }

    @Test
    fun `later token round-trips use the client the session signed in with, not the default`() {
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        fun jwt(claims: String) = enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString(claims.toByteArray()) + "."
        // 1) stored on the session (a login with this branch or `--client-id`)
        assertThat(CommandSupport.sessionClientId(com.devnow.thoryn.cli.auth.Tokens(accessToken = "opaque", clientId = "app-1"))).isEqualTo("app-1")
        // 2) a session written by an older CLI: the client_id / azp claim of the access token
        assertThat(CommandSupport.sessionClientId(com.devnow.thoryn.cli.auth.Tokens(accessToken = jwt("""{"client_id":"thoryn-cli"}""")))).isEqualTo("thoryn-cli")
        assertThat(CommandSupport.sessionClientId(com.devnow.thoryn.cli.auth.Tokens(accessToken = jwt("""{"azp":"thoryn-cli"}""")))).isEqualTo("thoryn-cli")
        // 3) nothing known → the CLI's default client
        assertThat(CommandSupport.sessionClientId(com.devnow.thoryn.cli.auth.Tokens(accessToken = "opaque"))).isEqualTo(ThorynConfig.DEFAULT_CLIENT_ID)
    }

    @Test
    fun `the default login client is cli and a workspace derives the tenant hub issuer plus the base gateway`() {
        assertThat(ThorynConfig.DEFAULT_CLIENT_ID).isEqualTo("cli")
        val base = "https://hub.stg.thoryn.org"
        assertThat(ThorynConfig.tenantIssuer(base, "thoryn")).isEqualTo("https://thoryn.hub.stg.thoryn.org")
        // The gateway is derived from the hub BASE, never from the tenant host (which has no `hub.` prefix).
        assertThat(ThorynConfig.gatewayForIssuer(base)).isEqualTo("https://api.stg.thoryn.org")
        assertThat(ThorynConfig.gatewayForIssuer(ThorynConfig.tenantIssuer(base, "thoryn"))).isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }
}
