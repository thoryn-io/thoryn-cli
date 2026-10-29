package com.devnow.thoryn.provision

import com.devnow.thoryn.provision.ScopeRequirements.Phase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3926 — the scopes a provisioning file needs, per phase, derived from what it declares: each kind's read scope to
 * plan and write scope to apply (product-api's controller gates), `tenant:access.*` for the ownership check, a `grants:`
 * block and a `workloadPull` sink's grant, `tenant:workload-identity.read` for a trust a binding or a sink names, a declared
 * trust's scope ceiling — and, for an apply, only the writes its plan actually makes.
 */
class ScopeRequirementsTest {

    private fun file(resources: String): ProvisionFile =
        ProvisionFile.parse(("apiVersion: thoryn.io/provision/v1\nresources:\n" + resources.trimIndent().prependIndent("  ")).toByteArray(), "p.yaml", yaml = true)

    private fun scopes(needs: List<ScopeRequirements.ScopeNeed>, phase: Phase) = needs.filter { it.phase == phase }.map { it.scope }.distinct()

    @Test
    fun `every kind the file format allows has a read and a write scope`() {
        ProvisionFile.KINDS.forEach { kind ->
            assertThat(ScopeRequirements.readScope(kind)).withFailMessage("no read scope for %s", kind).matches("tenant:[a-z-]+\\.read")
            assertThat(ScopeRequirements.writeScope(kind)).withFailMessage("no write scope for %s", kind).matches("tenant:[a-z-]+\\.write")
        }
    }

    @Test
    fun `a declared trust needs workload-identity read to plan and write to apply, plus the scopes it carries`() {
        val needs = ScopeRequirements.of(
            file(
                """
                - kind: workloadIdentityTrust
                  name: pod
                  spec: { provider: kubernetes, kubernetes: { issuer: "https://oidc.example/c", namespace: forge, serviceAccount: web }, scopes: [tenant:applications.write], confirmProduction: true }
                """,
            ),
        )
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:workload-identity.read", "tenant:access.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:workload-identity.write", "tenant:applications.write")
    }

    @Test
    fun `a workloadPull sink needs the trust's read to plan and access write for its manager grant`() {
        val needs = ScopeRequirements.of(
            file(
                """
                - kind: application
                  name: login
                  spec: { displayName: Login, redirectUris: ["https://x.example/cb"] }
                  secretSink: { kind: workloadPull, trust: pod }
                """,
            ),
        )
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:applications.read", "tenant:access.read", "tenant:workload-identity.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:applications.write", "tenant:access.write")
        assertThat(needs.single { it.scope == "tenant:access.write" }.why).contains("secretSink workloadPull")
    }

    @Test
    fun `a customer-managed secret — declared or the default — adds no scope — applications read and access read to plan, applications write to apply`() {
        // SSO-3954 — nothing is resolved by name and nothing is granted, so neither workload-identity read nor access write is needed.
        val needs = ScopeRequirements.of(
            file(
                """
                - kind: application
                  name: login
                  spec: { displayName: Login, redirectUris: ["https://x.example/cb"] }
                - kind: application
                  name: proxy
                  spec: { displayName: Proxy, redirectUris: ["https://x.example/oauth2/callback"] }
                  secretSink: { kind: customerManaged }
                """,
            ),
        )
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:applications.read", "tenant:access.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:applications.write")
        assertThat(needs.map { it.why }).noneMatch { it.contains("secretSink") }
    }

    @Test
    fun `grants need access read and write, a sandbox resource a conditional environments read, a read-only reference nothing to write`() {
        val needs = ScopeRequirements.of(
            file(
                """
                - kind: environment
                  name: ci
                  spec: { slug: ci }
                  grants: [ { subject: "client:wi_1", relation: manager } ]
                - kind: user
                  name: u
                  environment: ci
                  spec: { email: "u@example.com" }
                - kind: application
                  name: shared
                  readOnly: true
                  spec: { clientId: shared, displayName: Shared }
                """,
            ),
        )
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:environments.read", "tenant:access.read", "tenant:users.read", "tenant:applications.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:environments.write", "tenant:access.write", "tenant:users.write")
        assertThat(needs.filter { it.conditional }.map { it.resource to it.scope }).containsExactly("user/u" to "tenant:environments.read")
    }

    @Test
    fun `a declared role needs roles read to plan and roles write to apply, and no ownership check`() {
        val needs = ScopeRequirements.of(file("- { kind: role, name: forge-maintainer, spec: { permissions: [\"forge:maintain\"] } }"))
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:roles.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:roles.write")
        assertThat(needs.single { it.scope == "tenant:roles.read" }.resource).isEqualTo("role/forge-maintainer")
        val r = file("- { kind: role, name: r, spec: { permissions: [] } }").resources.single()
        val create = ProvisionPlan(listOf(PlannedChange(r.kind, r.name, ChangeAction.CREATE, "new", resource = r)))
        assertThat(ScopeRequirements.forChanges(create).map { it.scope }).containsExactly("tenant:roles.write")
    }

    @Test
    fun `a declared legal document needs legal-documents read to plan and legal-documents write to apply, and no ownership check`() {
        // SSO-4057 — product-api's TenantLegalDocumentsController gates on its own tenant:legal-documents.* pair alone (SSO-4069; no platform access object).
        val needs = ScopeRequirements.of(file("- { kind: legalDocument, name: terms, spec: { type: terms-of-use, version: v1, title: Terms, body: \"x\" } }"))
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:legal-documents.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:legal-documents.write")
        assertThat(needs.single { it.scope == "tenant:legal-documents.read" }.resource).isEqualTo("legalDocument/terms")
    }

    @Test
    fun `an application's tokenClaims is covered by the applications scopes it already needs`() {
        val needs = ScopeRequirements.of(file("- { kind: application, name: a, spec: { displayName: A, tokenClaims: { sources: [permissions] } } }"))
        assertThat(scopes(needs, Phase.PLAN)).containsExactly("tenant:applications.read", "tenant:access.read")
        assertThat(scopes(needs, Phase.APPLY)).containsExactly("tenant:applications.write")
    }

    @Test
    fun `the deprecated clients alias satisfies the applications scope`() {
        val needs = ScopeRequirements.of(file("- { kind: application, name: a, spec: { displayName: A } }"))
        assertThat(ScopeRequirements.missing(needs, setOf("tenant:clients.read", "tenant:clients.write", "tenant:access.read")).map { it.scope }).isEmpty()
        assertThat(ScopeRequirements.missing(needs, setOf("tenant:access.read")).map { it.scope }).containsExactly("tenant:applications.read", "tenant:applications.write")
    }

    @Test
    fun `an apply needs only the writes its plan makes`() {
        val r = file("- { kind: application, name: a, spec: { displayName: A } }").resources.single()
        val noop = ProvisionPlan(listOf(PlannedChange(r.kind, r.name, ChangeAction.NOOP, "matches", resource = r)))
        assertThat(ScopeRequirements.forChanges(noop)).isEmpty()
        val create = ProvisionPlan(listOf(PlannedChange(r.kind, r.name, ChangeAction.CREATE, "new", resource = r, grantAdds = listOf("client:x manager"))))
        assertThat(ScopeRequirements.forChanges(create).map { it.scope }).containsExactly("tenant:applications.write", "tenant:access.write")
    }

    @Test
    fun `only a scope-gate 403 is a missing scope — never a step-up, another 403 code or another status`() {
        fun ex(status: Int, code: String?, www: String? = null) = ProductApiException(status, code, "d", "", www)
        val ok = MissingScopeException.of(ex(403, "access_denied"), "tenant:x.read", Phase.PLAN, "a/b", "read live state")!!
        assertThat(ok.scope).isEqualTo("tenant:x.read")
        assertThat(ok.message).contains("a/b: could not read live state").contains("does not carry tenant:x.read")
        assertThat(MissingScopeException.of(ex(403, "insufficient_scope"), "tenant:x.read", Phase.PLAN, null, "x")).isNotNull()
        assertThat(MissingScopeException.of(ex(403, "scope_not_grantable"), "tenant:x.read", Phase.PLAN, null, "x")).isNull()
        assertThat(MissingScopeException.of(ex(403, null, "Bearer error=\"insufficient_user_authentication\""), "tenant:x.read", Phase.PLAN, null, "x")).isNull()
        assertThat(MissingScopeException.of(ex(404, "not_found"), "tenant:x.read", Phase.PLAN, null, "x")).isNull()
    }
}
