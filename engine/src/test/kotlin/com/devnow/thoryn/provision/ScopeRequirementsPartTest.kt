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
        val held = setOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:users.read", "tenant:users.write", "tenant:idp.write")
        assertThat(ScopeRequirements.unneeded(app, ScopeRequirements.of(app), held)).containsExactly("tenant:idp.write", "tenant:users.read", "tenant:users.write")
        // The deprecated alias of a needed scope is not "unneeded".
        assertThat(ScopeRequirements.unneeded(app, ScopeRequirements.of(app), setOf("tenant:clients.read", "tenant:applications.write", "tenant:access.read"))).isEmpty()
        val tenant = file(ProvisionFile.API_VERSION_TENANT, "- kind: role\n  name: editor\n  spec: { permissions: [docs:write] }")
        assertThat(ScopeRequirements.unneeded(tenant, ScopeRequirements.of(tenant), held)).isEmpty()
        assertThat(ScopeRequirements.beyondBaseline(tenant, ScopeRequirements.of(tenant))).isEmpty()
        val mixed = file(ProvisionFile.API_VERSION, productionApp)
        assertThat(ScopeRequirements.unneeded(mixed, ScopeRequirements.of(mixed), held)).isEmpty()
    }

    /**
     * SSO-4086 (oauthy ADR 2026-10-30-ephemeral-sandbox-test-identities §2) — an application's identity holds two sandbox TOOL
     * scopes for its own tests that no declared resource asks for: `tenant:environments.read` (the test inbox) and
     * `tenant:test-identities.write` (minting a disposable test account). They are expected on an application trust, not the
     * identity being wider than its file; `tenant:users.*` next to them is still unneeded — the mint is what replaces it.
     */
    @Test
    fun `the sandbox tool scopes — environments read and test-identities write — are not unneeded on an application file, tenant users scopes still are`() {
        assertThat(ScopeRequirements.SANDBOX_TOOL_SCOPES).containsExactlyInAnyOrder("tenant:environments.read", "tenant:test-identities.write")
        val app = file(ProvisionFile.API_VERSION_APPLICATION, productionApp)
        val needs = ScopeRequirements.of(app)
        // A production-plane application: nothing in the file asks for environments.read — it is still not a finding.
        assertThat(needs.map { it.scope }).doesNotContain("tenant:environments.read", "tenant:test-identities.write")
        val starterTrust = ScopeRequirements.APPLICATION_FILE_SCOPES + ScopeRequirements.SANDBOX_TOOL_SCOPES
        assertThat(ScopeRequirements.unneeded(app, needs, starterTrust)).isEmpty()
        assertThat(ScopeRequirements.unneeded(app, needs, starterTrust + "tenant:users.read" + "tenant:users.write")).containsExactly("tenant:users.read", "tenant:users.write")
        // The read half of the family is not a tool scope: a trust that reads the list is reported, as any other tenant scope.
        assertThat(ScopeRequirements.unneeded(app, needs, starterTrust + "tenant:test-identities.read")).containsExactly("tenant:test-identities.read")
        // The allowance is for the application part only — nothing changes for a tenant file (never a finding there anyway).
        val tenant = file(ProvisionFile.API_VERSION_TENANT, "- kind: role\n  name: editor\n  spec: { permissions: [docs:write] }")
        assertThat(ScopeRequirements.unneeded(tenant, ScopeRequirements.of(tenant), starterTrust)).isEmpty()
    }
}
