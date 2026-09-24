package com.devnow.thoryn.cli.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2827 — [ThorynConfig.gatewayForIssuer] derives the customer-plane gateway
 * from a hub issuer by swapping the `hub.` host label for `api.`, so `thoryn login`
 * records the right gateway for the session without the user passing `--gateway`.
 */
class ThorynConfigGatewayTest {

    @Test
    fun `staging hub derives the staging gateway`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://hub.stg.thoryn.org"))
            .isEqualTo("https://api.stg.thoryn.org")
            .isEqualTo(ThorynConfig.STAGING_GATEWAY)
    }

    @Test
    fun `production hub derives the production gateway`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://hub.thoryn.org"))
            .isEqualTo("https://api.thoryn.org")
    }

    @Test
    fun `a trailing slash on the issuer is tolerated`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://hub.stg.thoryn.org/"))
            .isEqualTo("https://api.stg.thoryn.org")
    }

    @Test
    fun `localhost hub has no derivable gateway and falls back to the default`() {
        assertThat(ThorynConfig.gatewayForIssuer("http://localhost:54702"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }

    /**
     * SSO-3296 — `auth.` is a recognised platform label (epic SSO-3289), so an `auth.` base issuer
     * derives its gateway exactly as a `hub.` one does. The customer-plane host itself does NOT move
     * at the SSO-3297 cutover (ADR §1) — only the label it is derived FROM.
     */
    @Test
    fun `an auth base issuer derives the api gateway the same way a hub one does`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://auth.stg.thoryn.org"))
            .isEqualTo("https://api.stg.thoryn.org")
        assertThat(ThorynConfig.gatewayForIssuer("https://auth.thoryn.io"))
            .isEqualTo("https://api.thoryn.io")
    }

    @Test
    fun `a host with no recognised platform label falls back to the default gateway`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://idp.example.com"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
        // A WORKSPACE host is not a base host — the gateway is derived from the base only.
        assertThat(ThorynConfig.gatewayForIssuer("https://acme.auth.stg.thoryn.org"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }

    @Test
    fun `unparseable input falls back rather than throwing`() {
        assertThat(ThorynConfig.gatewayForIssuer("not a url"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }
}
