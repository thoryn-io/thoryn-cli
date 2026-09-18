package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

/**
 * SSO-3182 — a RELEASED CLI must not default to `http://localhost:54702`.
 *
 * `thoryn login --workspace thoryn` with no `--issuer` used to open
 * `http://localhost:54702/oauth2/authorize` (a localhost host has no `hub.` label, so
 * [ThorynConfig.tenantIssuer] could not even derive the workspace host). The hub base is now resolved
 * from `--issuer`, `THORYN_HUB`, the previous session, or the baked-in platform hub — and with none of
 * them the command fails fast with guidance instead of dialling localhost.
 */
class LoginIssuerResolutionTest : CommandTestBase() {

    @AfterEach
    fun clearHubProperty() {
        System.clearProperty(ThorynConfig.HUB_ENV)
    }

    // ---- resolution order (unit) -------------------------------------------

    @Test
    fun `the flag wins, then the env var, then the previous session, then the baked-in platform hub`() {
        val none: (String) -> String? = { null }
        val env: (String) -> String? = { if (it == ThorynConfig.HUB_ENV) "https://hub.env.example.org" else null }

        assertThat(
            ThorynConfig.resolveHubBase("https://hub.flag.example.org/", "https://a.hub.prev.org", env, "https://hub.baked.org"),
        ).isEqualTo(ThorynConfig.HubBase("https://hub.flag.example.org", ThorynConfig.HubSource.FLAG))

        assertThat(ThorynConfig.resolveHubBase(null, "https://a.hub.prev.org", env, "https://hub.baked.org"))
            .isEqualTo(ThorynConfig.HubBase("https://hub.env.example.org", ThorynConfig.HubSource.ENV))

        // The previous session stores the TENANT issuer; the base hub is derived from it.
        assertThat(ThorynConfig.resolveHubBase(null, "https://acme.hub.stg.thoryn.org", none, "https://hub.baked.org"))
            .isEqualTo(ThorynConfig.HubBase("https://hub.stg.thoryn.org", ThorynConfig.HubSource.PREVIOUS_SESSION))

        assertThat(ThorynConfig.resolveHubBase(null, null, none, "https://hub.baked.org"))
            .isEqualTo(ThorynConfig.HubBase("https://hub.baked.org", ThorynConfig.HubSource.PLATFORM))

        assertThat(ThorynConfig.resolveHubBase(null, null, none, null)).isNull()
    }

    @Test
    fun `there is no localhost platform default and the production hub is still an open product decision`() {
        // Set PLATFORM_HUB to the production hub once that domain is live (see the KDoc); until then a
        // released binary must ask rather than guess — and must never guess localhost.
        assertThat(ThorynConfig.PLATFORM_HUB).isNull()
        assertThat(ThorynConfig.NO_HUB_GUIDANCE).doesNotContain("$/") // sanity: no unresolved template
        assertThat(ThorynConfig.NO_HUB_GUIDANCE).contains(ThorynConfig.STAGING_ISSUER).contains(ThorynConfig.HUB_ENV)
    }

    @Test
    fun `base hub and workspace slug are derived from a tenant issuer`() {
        assertThat(ThorynConfig.baseHubOf("https://thoryn.hub.stg.thoryn.org")).isEqualTo("https://hub.stg.thoryn.org")
        assertThat(ThorynConfig.baseHubOf("https://hub.stg.thoryn.org/")).isEqualTo("https://hub.stg.thoryn.org")
        assertThat(ThorynConfig.baseHubOf("http://localhost:54702")).isEqualTo("http://localhost:54702")
        assertThat(ThorynConfig.workspaceOfIssuer("https://thoryn.hub.stg.thoryn.org")).isEqualTo("thoryn")
        assertThat(ThorynConfig.workspaceOfIssuer("https://hub.stg.thoryn.org")).isNull()
        assertThat(ThorynConfig.workspaceOfIssuer(null)).isNull()
    }

    // ---- end-to-end through the command ------------------------------------

    @Test
    fun `login with no issuer, no THORYN_HUB and no previous session fails fast with guidance`() {
        assumeTrue(System.getenv(ThorynConfig.HUB_ENV) == null, "THORYN_HUB is set in this environment")
        clearTokens()

        val (exit, _, err) = runCli("login", "--workspace", "thoryn")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("no Thoryn platform selected")
            .contains("--issuer ${ThorynConfig.STAGING_ISSUER}")
            .contains(ThorynConfig.HUB_ENV)
        // Nothing was dialled — in particular not localhost:54702.
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `login without an issuer reuses the hub of the previous session`() {
        // A previous sign-in recorded the (test) hub as the session issuer; `--workspace` alone must reach
        // that platform rather than localhost. Device-code keeps the assertion to one HTTP round-trip.
        seedTokens(Tokens(accessToken = "AT", issuer = baseUrl(), gateway = baseUrl()))
        server.enqueue(jsonResponse(400, """{"error":"invalid_client"}"""))

        val (_, _, err) = runCli("login", "--device-code", "--workspace", "acme")

        assertThat(err).contains("Using hub ${baseUrl()}").contains("previous sign-in")
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/device_authorization")
    }

    @Test
    fun `THORYN_HUB names the platform when no flag is given`() {
        clearTokens()
        System.setProperty(ThorynConfig.HUB_ENV, baseUrl())
        server.enqueue(jsonResponse(400, """{"error":"invalid_client"}"""))

        val (_, _, err) = runCli("login", "--device-code", "--workspace", "acme")

        assertThat(err).contains("Using hub ${baseUrl()}").contains(ThorynConfig.HUB_ENV)
        assertThat(server.takeRequest().path).isEqualTo("/oauth2/device_authorization")
    }

    @Test
    fun `an interactive login records the workspace it signed in on`() {
        clearTokens()
        server.enqueue(jsonResponse(200, """{"device_code":"DEV-1","user_code":"ABCD-1234","verification_uri":"${baseUrl()}/activate","expires_in":600,"interval":0}"""))
        server.enqueue(jsonResponse(200, """{"access_token":"AT-1","refresh_token":"RT-1","token_type":"Bearer","expires_in":900}"""))

        val (exit, _, err) = runCli("login", "--device-code", "--workspace", "acme", "--issuer", baseUrl())

        assertThat(exit).withFailMessage("stderr was:\n%s", err).isEqualTo(0)
        val stored = FileTokenStore().read()!!
        assertThat(stored.workspace).isEqualTo("acme")
        assertThat(LoginCommand.reLoginCommand(stored)).isEqualTo("thoryn login --workspace acme")
    }

    @Test
    fun `a sign-in that received no refresh token says the session cannot renew itself`() {
        val notice = LoginCommand.noRefreshTokenNotice(
            Tokens(accessToken = "AT", refreshToken = null, expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900),
            requestedScope = ThorynConfig.DEFAULT_SCOPE,
            deviceCode = false,
        )
        assertThat(notice).isNotNull()
        assertThat(notice!!).contains("no refresh token").contains("--device-code")
        // Nothing to say when a refresh token WAS issued, or when offline_access was not requested.
        assertThat(LoginCommand.noRefreshTokenNotice(Tokens(accessToken = "AT", refreshToken = "RT"), ThorynConfig.DEFAULT_SCOPE, false)).isNull()
        assertThat(LoginCommand.noRefreshTokenNotice(Tokens(accessToken = "AT"), "openid", false)).isNull()
    }
}
