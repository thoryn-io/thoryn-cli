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

    @Test
    fun `a non-hub host falls back to the default gateway`() {
        assertThat(ThorynConfig.gatewayForIssuer("https://auth.example.com"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }

    @Test
    fun `unparseable input falls back rather than throwing`() {
        assertThat(ThorynConfig.gatewayForIssuer("not a url"))
            .isEqualTo(ThorynConfig.DEFAULT_GATEWAY)
    }
}
