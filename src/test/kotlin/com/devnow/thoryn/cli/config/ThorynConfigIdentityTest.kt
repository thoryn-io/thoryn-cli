package com.devnow.thoryn.cli.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2830 — [ThorynConfig.tenantIssuer] and [ThorynConfig.tenantIdentityHost]
 * derive the per-tenant hub issuer and the tenant sign-in host from the base hub
 * issuer. The identity host is load-bearing: identity-service resolves the tenant
 * from the request Host (SSO-1920), so a user provisioned for tenant X can only
 * sign in via `{X}.identity.<env>`.
 */
class ThorynConfigIdentityTest {

    @Test
    fun `staging tenant issuer prefixes the slug on the hub host`() {
        assertThat(ThorynConfig.tenantIssuer("https://hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.hub.stg.thoryn.org")
    }

    @Test
    fun `staging tenant identity host swaps hub for identity and prefixes the slug`() {
        assertThat(ThorynConfig.tenantIdentityHost("https://hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.identity.stg.thoryn.org")
    }

    @Test
    fun `production hosts derive correctly`() {
        assertThat(ThorynConfig.tenantIssuer("https://hub.thoryn.org", "acme"))
            .isEqualTo("https://acme.hub.thoryn.org")
        assertThat(ThorynConfig.tenantIdentityHost("https://hub.thoryn.org", "acme"))
            .isEqualTo("https://acme.identity.thoryn.org")
    }

    @Test
    fun `a non-hub host leaves the issuer unchanged and falls back to the default identity host`() {
        assertThat(ThorynConfig.tenantIssuer("http://localhost:54702", "acme"))
            .isEqualTo("http://localhost:54702")
        assertThat(ThorynConfig.tenantIdentityHost("http://localhost:54702", "acme"))
            .isEqualTo(ThorynConfig.DEFAULT_IDENTITY)
    }
}
