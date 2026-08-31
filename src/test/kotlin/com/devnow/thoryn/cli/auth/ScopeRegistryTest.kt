package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-959 — unit tests for [ScopeRegistry] wildcard expansion.
 */
class ScopeRegistryTest {

    @Test
    fun `all-supply-chain wildcard expands to the full supply-chain scope set`() {
        val expanded = ScopeRegistry.expand("all-supply-chain")
        val tokens = expanded.split(' ')
        assertThat(tokens).containsExactlyElementsOf(ScopeRegistry.SUPPLY_CHAIN_SCOPES)
    }

    @Test
    fun `all-tenant-config wildcard expands to the tenant-configuration scope set`() {
        // SSO-1552 — covers the clients / federation / audit command trees.
        val expanded = ScopeRegistry.expand("all-tenant-config")
        val tokens = expanded.split(' ')
        assertThat(tokens).containsExactlyElementsOf(ScopeRegistry.TENANT_CONFIG_SCOPES)
        assertThat(tokens)
            .contains("tenant:applications.write")
            .contains("tenant:federation.write")
            .contains("tenant:audit.read")
    }

    @Test
    fun `non-wildcard scope passes through unchanged`() {
        assertThat(ScopeRegistry.expand("openid offline_access"))
            .isEqualTo("openid offline_access")
    }

    @Test
    fun `comma-separated wildcards are accepted alongside space-separated`() {
        val expanded = ScopeRegistry.expand("openid,all-supply-chain")
        // The literal `openid` stays first, then the wildcard expands to the
        // full supply-chain set in encounter order (credential-types first per
        // SSO-1593, then trust-registry, …).
        assertThat(expanded).startsWith("openid tenant:supply-chain.credential-types.read")
        assertThat(expanded.split(' ')).contains("tenant:supply-chain.trust-registry.read")
    }

    @Test
    fun `wildcard mixed with literal scopes deduplicates`() {
        val expanded = ScopeRegistry.expand(
            "tenant:supply-chain.audit.read all-supply-chain",
        )
        val tokens = expanded.split(' ')
        // 'tenant:supply-chain.audit.read' must appear once, not twice.
        assertThat(tokens.count { it == "tenant:supply-chain.audit.read" }).isEqualTo(1)
        // The full literal set is still present (deduplication is by string identity).
        assertThat(tokens).contains("tenant:supply-chain.trust-registry.read")
        assertThat(tokens).contains("tenant:supply-chain.issuer-bridge.rotate-key")
    }

    @Test
    fun `blank input passes through unchanged`() {
        assertThat(ScopeRegistry.expand("")).isEqualTo("")
        assertThat(ScopeRegistry.expand("   ")).isEqualTo("   ")
    }

    @Test
    fun `unknown wildcard passes through so the hub surfaces invalid_scope`() {
        // The CLI should NOT silently rewrite "all-everything" — that would
        // mask a typo. The hub will return invalid_scope; the user sees it.
        val expanded = ScopeRegistry.expand("all-everything")
        assertThat(expanded).isEqualTo("all-everything")
    }

    @Test
    fun `loginHintForScope returns a copy-paste-ready command`() {
        assertThat(ScopeRegistry.loginHintForScope("tenant:supply-chain.audit.read"))
            .isEqualTo("oathy login --scope tenant:supply-chain.audit.read")
    }

    @Test
    fun `heartbeat-write scope is intentionally NOT in the wildcard set`() {
        // SSO-957: heartbeat-write is a bridge-only service-account scope.
        // A human running `oathy login --scope all-supply-chain` must not
        // accidentally grab the bridge's authority.
        assertThat(ScopeRegistry.SUPPLY_CHAIN_SCOPES)
            .doesNotContain("tenant:supply-chain.issuer-bridge.heartbeat-write")
    }

    @Test
    fun `credential-types read and write scopes are included in the wildcard set`() {
        // SSO-1593: `thoryn supply-chain credential-types ...` needs the
        // credential-types scope pair; including them in `all-supply-chain`
        // means one `oathy login --scope all-supply-chain` covers the new
        // commands.
        assertThat(ScopeRegistry.SUPPLY_CHAIN_SCOPES)
            .contains("tenant:supply-chain.credential-types.read")
            .contains("tenant:supply-chain.credential-types.write")
    }

    @Test
    fun `intermediary read and write scopes are included in the wildcard set`() {
        // SSO-970: the chain-of-custody CLI subcommands (`thoryn supply-chain
        // chain ...`) require the SSO-962 intermediary scopes. Including
        // them in `all-supply-chain` means a single `oathy login --scope
        // all-supply-chain` covers the new commands too.
        assertThat(ScopeRegistry.SUPPLY_CHAIN_SCOPES)
            .contains("tenant:supply-chain.issuer-bridge.intermediary.read")
            .contains("tenant:supply-chain.issuer-bridge.intermediary.write")
    }
}
