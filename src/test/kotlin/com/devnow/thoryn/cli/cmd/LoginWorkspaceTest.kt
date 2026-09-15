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
    fun `the default login client is cli and a workspace derives the tenant hub issuer plus the base gateway`() {
        assertThat(ThorynConfig.DEFAULT_CLIENT_ID).isEqualTo("cli")
        val base = "https://hub.stg.thoryn.org"
        assertThat(ThorynConfig.tenantIssuer(base, "thoryn")).isEqualTo("https://thoryn.hub.stg.thoryn.org")
        // The gateway is derived from the hub BASE, never from the tenant host (which has no `hub.` prefix).
        assertThat(ThorynConfig.gatewayForIssuer(base)).isEqualTo("https://api.stg.thoryn.org")
        assertThat(ThorynConfig.gatewayForIssuer(ThorynConfig.tenantIssuer(base, "thoryn"))).isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }
}
