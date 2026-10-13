package com.devnow.thoryn.cli.cmd.connection

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2948 — the confinement primitive behind the ADR's "scope ceiling" layer:
 * `connection.scopes ⊆ the client's granted set`. SSO-2951's repo-level test will assert this against
 * the real machine client's granted scopes.
 */
class ScopesWithinGrantTest {

    @Test
    fun `a proper subset is within the grant`() {
        val granted = setOf("tenant:applications.read", "tenant:applications.write", "tenant:federation.read")
        val requested = setOf("tenant:applications.read", "tenant:applications.write")
        assertThat(Connection.scopesWithinGrant(requested, granted)).isTrue()
    }

    @Test
    fun `an equal set is within the grant`() {
        val s = setOf("tenant:applications.read", "tenant:users.read")
        assertThat(Connection.scopesWithinGrant(s, s)).isTrue()
    }

    @Test
    fun `the empty request is within any grant`() {
        assertThat(Connection.scopesWithinGrant(emptySet(), setOf("tenant:applications.read"))).isTrue()
    }

    @Test
    fun `a superset exceeds the grant and is rejected`() {
        val granted = setOf("tenant:applications.read")
        val requested = setOf("tenant:applications.read", "tenant:applications.write")
        assertThat(Connection.scopesWithinGrant(requested, granted)).isFalse()
    }

    @Test
    fun `a single scope absent from the grant is rejected`() {
        val granted = setOf("tenant:applications.read", "tenant:applications.write")
        val requested = setOf("tenant:federation.write")
        assertThat(Connection.scopesWithinGrant(requested, granted)).isFalse()
    }
}
