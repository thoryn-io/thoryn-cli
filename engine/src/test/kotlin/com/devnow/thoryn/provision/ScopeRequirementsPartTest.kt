package com.devnow.thoryn.provision

import com.devnow.thoryn.provision.ScopeRequirements.Phase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3962 (ADR 2026-10-25 §1 "Identity", §3) — the trust-scopes rule follows the PART. An application file's identity
 * is confined to `tenant:applications.read` + `tenant:access.read` (plan) and `tenant:applications.write` (apply) — and the
 * rule says exactly why a file asks for anything beyond that baseline ([ScopeRequirements.beyondBaseline]) and which held
 * scopes such a file never needs ([ScopeRequirements.unneeded]). A tenant file is the union of its kinds' scopes, as before.
 */
class ScopeRequirementsPartTest {

    private fun file(apiVersion: String, resources: String): ProvisionFile =
        ProvisionFile.parse(("apiVersion: $apiVersion\nresources:\n" + resources.trimIndent().prependIndent("  ")).toByteArray(), "p.yaml", yaml = true)

    private fun scopes(needs: List<ScopeRequirements.ScopeNeed>, phase: Phase) = needs.filter { it.phase == phase }.map { it.scope }.distinct()

    private val productionApp = """
        - kind: application
          name: web
          spec: { displayName: Web, clientType: public, redirectUris: ["https://web.example/cb"] }
    """

    @Test
    fun `a plain application file needs exactly the three scopes — applications read + access read to plan, applications write to apply`() {
        val f = file(ProvisionFile.API_VERSION_APPLICATION, productionApp)
        val needs = ScopeRequirements.of(f)
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:applications.read", "tenant:access.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:applications.write")
        assertThat(needs.map { it.scope }.toSet()).isEqualTo(ScopeRequirements.APPLICATION_FILE_SCOPES)
        assertThat(ScopeRequirements.beyondBaseline(f, needs)).isEmpty()
    }

    @Test
    fun `what an application's own mechanisms add is derived and named as beyond the baseline`() {
        val f = file(
            ProvisionFile.API_VERSION_APPLICATION,
            """
            - kind: application
              name: web
              environment: dev
              spec: { displayName: Web, redirectUris: ["https://web.example/cb"] }
              secretSink: { kind: workloadPull, trust: web-pod }
              grants:
                - { subject: "member:alice", relation: viewer }
            """,
        )
        val needs = ScopeRequirements.of(f)
        val beyond = ScopeRequirements.beyondBaseline(f, needs)
        assertThat(beyond.map { it.scope }.distinct()).containsExactlyInAnyOrder("tenant:environments.read", "tenant:workload-identity.read", "tenant:access.write")
        assertThat(beyond.single { it.scope == "tenant:environments.read" }.conditional).isTrue()
        assertThat(beyond.single { it.scope == "tenant:workload-identity.read" }.why).contains("secretSink.trust 'web-pod'")
        assertThat(beyond.filter { it.scope == "tenant:access.write" }.map { it.why }).anyMatch { it.contains("grants: block") }.anyMatch { it.contains("secretSink workloadPull") }
    }

    @Test
    fun `a tenant-defining scope can never be among an application file's needs — the kinds that need one are refused in it`() {
        ProvisionFile.TENANT_KINDS.forEach { kind ->
            val tenantScopes = setOf(ScopeRequirements.readScope(kind), ScopeRequirements.writeScope(kind))
            assertThat(tenantScopes intersect ScopeRequirements.APPLICATION_FILE_SCOPES).withFailMessage("%s's scopes overlap the application baseline", kind).isEmpty()
        }
    }

    @Test
    fun `unneeded names the held scopes an application file never asks for, and nothing for a tenant or mixed file`() {
        val app = file(ProvisionFile.API_VERSION_APPLICATION, productionApp)
        val held = setOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:users.read", "tenant:users.write", "tenant:environments.read")
        assertThat(ScopeRequirements.unneeded(app, ScopeRequirements.of(app), held)).containsExactly("tenant:environments.read", "tenant:users.read", "tenant:users.write")
        // The deprecated alias of a needed scope is not "unneeded".
        assertThat(ScopeRequirements.unneeded(app, ScopeRequirements.of(app), setOf("tenant:clients.read", "tenant:applications.write", "tenant:access.read"))).isEmpty()
        val tenant = file(ProvisionFile.API_VERSION_TENANT, "- kind: role\n  name: editor\n  spec: { permissions: [docs:write] }")
        assertThat(ScopeRequirements.unneeded(tenant, ScopeRequirements.of(tenant), held)).isEmpty()
        assertThat(ScopeRequirements.beyondBaseline(tenant, ScopeRequirements.of(tenant))).isEmpty()
        val mixed = file(ProvisionFile.API_VERSION, productionApp)
        assertThat(ScopeRequirements.unneeded(mixed, ScopeRequirements.of(mixed), held)).isEmpty()
    }
}
