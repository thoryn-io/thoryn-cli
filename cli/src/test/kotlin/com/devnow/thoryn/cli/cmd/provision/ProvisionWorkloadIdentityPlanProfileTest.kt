package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionFileRef
import com.devnow.thoryn.provision.ProvisionReceipt
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3702 (SSO-3699 option B) — `kind: workloadIdentityTrust` with a `plan:` block. Sent on create; compared as an
 * immutable pin EXCEPT for the one additive case — a declared profile on a live trust WITHOUT one converges through
 * `POST …/{id}/plan-profile` (the `wi_` client stays) — while a live profile that differs is the red plan
 * `workload_identity_trust_immutable` ("re-create the trust"). The file refuses what product-api refuses, with its
 * codes; `import` renders a live profile. And the regression the story names: the OWNER identity, signed in with a
 * read-only (plan-profile) token, plans an owned resource GREEN, while a foreign `manager` still gets
 * `owned_elsewhere` in plan and apply.
 */
class ProvisionWorkloadIdentityPlanProfileTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine(callerScopes: Set<String>? = null, subject: String? = null) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject, callerScopes = callerScopes,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?, e: ProvisionEngine = engine()): ProvisionReceipt =
        e.apply(f, receipt, e.plan(f, receipt, false), "acme", "acme") {}

    private val pins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-cli", "ownerId" to 229451779L, "repositoryId" to 1361536515L, "environment" to "thoryn-provision-e2e", "ref" to "refs/heads/main", "githubHostedRunnersOnly" to true)
    private val sixScopes = listOf("tenant:environments.read", "tenant:environments.write", "tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:access.write")
    private val readScopes = listOf("tenant:environments.read", "tenant:applications.read", "tenant:access.read")

    private fun trustYaml(plan: String?) = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: workloadIdentityTrust
            name: thoryn-cli-ci
            spec:
              provider: github_actions
              github: { repository: thoryn-io/thoryn-cli, ownerId: 229451779, repositoryId: 1361536515, environment: thoryn-provision-e2e, ref: refs/heads/main, githubHostedRunnersOnly: true }
              scopes: [${sixScopes.joinToString(", ")}]
              confirmProduction: true${plan?.let { "\n              $it" } ?: ""}
    """

    private val withDerivedPlan = trustYaml("plan: { environment: thoryn-provision-e2e-plan }")
    private val withExplicitPlan = trustYaml("plan: { environment: thoryn-provision-e2e-plan, scopes: [tenant:environments.read, tenant:access.read] }")

    @Test
    fun `a declared plan profile rides on the create — scopes only when listed — and the receipt and connection document are the one-trust shape`() {
        val receipt = apply(file(withDerivedPlan), null)
        val post = api.writes.single { it.method == "POST" && it.path == "/api/v1/workload-identity/trusts" }
        @Suppress("UNCHECKED_CAST")
        assertThat(post.body["plan"] as Map<String, Any?>).containsEntry("environment", "thoryn-provision-e2e-plan").doesNotContainKey("scopes")
        // The fake derived the .read members, like the hub.
        @Suppress("UNCHECKED_CAST")
        assertThat(api.trusts.single()["plan"] as Map<String, Any?>).containsEntry("scopes", readScopes)
        assertThat(receipt.resources.single().attributes[ProvisionEngine.ATTR_CLIENT_ID]).startsWith("wi_")
        // ONE connection.json: the document names the apply environment and carries no plan member (the hub decides by claim).
        val out = console.toString()
        assertThat(out).contains("connection.json for the workload").contains("\"environment\" : \"thoryn-provision-e2e\"").doesNotContain("\"plan\"").doesNotContain("connection.plan.json")

        // A second plan / apply is a no-op; the plan row names the profile.
        api.reset(); console.reset()
        val again = engine().plan(file(withDerivedPlan), receipt, false)
        assertThat(again.changes.single().action).isEqualTo(ChangeAction.NOOP)
        @Suppress("UNCHECKED_CAST")
        assertThat(again.changes.single().trust?.get("plan") as Map<String, Any?>).containsEntry("environment", "thoryn-provision-e2e-plan")
        assertThat(again.changes.single().trust?.get("subjectPatterns") as List<*>).hasSize(2)
        apply(file(withDerivedPlan), receipt)
        assertThat(api.writes.filter { it.method != "GET" }).isEmpty()

        // Explicit plan scopes are sent as declared.
        api.trusts.clear(); api.reset()
        apply(file(withExplicitPlan), null)
        @Suppress("UNCHECKED_CAST")
        assertThat(api.writes.single { it.method == "POST" && it.path == "/api/v1/workload-identity/trusts" }.body["plan"] as Map<String, Any?>)
            .containsEntry("scopes", listOf("tenant:environments.read", "tenant:access.read"))
    }

    @Test
    fun `a declared plan profile on a live trust WITHOUT one is converged by the additive set-plan-profile call — the wi_ client stays, and the same receipt owns it`() {
        val id = api.seedTrust(null, "thoryn-cli-ci", pins = pins, scopes = sixScopes, clientId = "wi_10a7b379c79f7d1353f5798d")
        // Adopt first without a plan block: the trust is owned, unchanged.
        val adopted = apply(file(trustYaml(null)), null)
        assertThat(adopted.resources.single().adopted).isTrue()
        api.reset(); console.reset()

        val plan = engine().plan(file(withDerivedPlan), adopted, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.error).isNull()
        assertThat(change.diff).containsOnlyKeys("plan.environment")
        assertThat(change.reason).contains("adds the plan profile").contains("thoryn-provision-e2e-plan").contains("wi_10a7b379c79f7d1353f5798d stays")
        assertThat(plan.hasErrors).isFalse()

        val receipt = engine().apply(file(withDerivedPlan), adopted, plan, "acme", "acme") {}
        val writes = api.writes.filter { it.method != "GET" }
        assertThat(writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/workload-identity/trusts/$id/plan-profile")
        assertThat(writes.single().body).containsEntry("environment", "thoryn-provision-e2e-plan").doesNotContainKey("scopes")
        // The identity is untouched: same id, same wi_ client, still adopted (never deleted by destroy).
        val owned = receipt.resources.single()
        assertThat(owned.id).isEqualTo(id)
        assertThat(owned.attributes[ProvisionEngine.ATTR_CLIENT_ID]).isEqualTo("wi_10a7b379c79f7d1353f5798d")
        assertThat(owned.adopted).isTrue()
        assertThat(api.trusts.single()["clientId"]).isEqualTo("wi_10a7b379c79f7d1353f5798d")
        assertThat(console.toString()).contains("~ workloadIdentityTrust thoryn-cli-ci: plan profile added").contains("wi_ client wi_10a7b379c79f7d1353f5798d unchanged")

        // Converged: the next plan is a no-op and the next apply writes nothing.
        api.reset()
        assertThat(engine().plan(file(withDerivedPlan), receipt, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(file(withDerivedPlan), receipt)
        assertThat(api.writes.filter { it.method != "GET" }).isEmpty()

        // The same additive convergence on an adopt (no receipt yet): plan says update-while-adopting, apply adds the profile.
        api.trusts.clear(); api.reset(); console.reset()
        api.seedTrust(null, "thoryn-cli-ci", pins = pins, scopes = sixScopes, clientId = "wi_fresh")
        val adopting = engine().plan(file(withDerivedPlan), null, false).changes.single()
        assertThat(adopting.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(adopting.reason).startsWith("exists (adopting)")
        val fresh = apply(file(withDerivedPlan), null)
        assertThat(fresh.resources.single().adopted).isTrue()
        assertThat(api.writes.filter { it.method != "GET" }.map { it.path }).containsExactly("/api/v1/workload-identity/trusts/${api.trusts.single()["id"]}/plan-profile")
    }

    @Test
    fun `a live plan profile that differs from the declared one is workload_identity_trust_immutable naming the re-create, and apply refuses whole`() {
        api.seedTrust(null, "thoryn-cli-ci", pins = pins, scopes = sixScopes, plan = mapOf("environment" to "another-plan", "scopes" to readScopes))

        val plan = engine().plan(file(withDerivedPlan), null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_TRUST_IMMUTABLE)
        assertThat(change.diff).containsOnlyKeys("plan.environment")
        assertThat(change.diff["plan.environment"]).isEqualTo("another-plan → thoryn-provision-e2e-plan")
        assertThat(change.reason).contains("already carries a plan profile that differs").contains("re-create the trust")
        assertThatThrownBy { engine().apply(file(withDerivedPlan), null, plan, "acme", "acme") {} }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("nothing was written")
        assertThat(api.writes.filter { it.method != "GET" }).isEmpty()

        // Explicit plan scopes that differ from the live profile's are a difference too.
        api.trusts.clear()
        api.seedTrust(null, "thoryn-cli-ci", pins = pins, scopes = sixScopes, plan = mapOf("environment" to "thoryn-provision-e2e-plan", "scopes" to readScopes))
        val scopesDiffer = engine().plan(file(withExplicitPlan), null, false).changes.single()
        assertThat(scopesDiffer.action).isEqualTo(ChangeAction.ERROR)
        assertThat(scopesDiffer.diff).containsOnlyKeys("plan.scopes")
        // …while a derived declaration (no scopes listed) matches whatever the hub derived.
        assertThat(engine().plan(file(withDerivedPlan), null, false).changes.single().action).isEqualTo(ChangeAction.ADOPT)
        // And a file that declares no plan block does not compare the live one at all.
        assertThat(engine().plan(file(trustYaml(null)), null, false).changes.single().action).isEqualTo(ChangeAction.ADOPT)
    }

    @Test
    fun `the file refuses what product-api refuses, with its codes`() {
        fun violations(plan: String, provider: String = "github_actions", pinBlock: String = "github: { repository: thoryn-io/thoryn-cli, environment: thoryn-provision-e2e }") = runCatching {
            ProvisionFile.parse(
                """
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: workloadIdentityTrust
                    name: t
                    spec: { provider: $provider, $pinBlock, scopes: [tenant:applications.read, tenant:applications.write], confirmProduction: true, plan: $plan }
                """.trimIndent().toByteArray(),
                "provision.yaml",
            )
        }.exceptionOrNull()?.message ?: ""

        assertThat(violations("{ environment: thoryn-provision-e2e }")).contains(ProvisionFile.ERR_PLAN_ENVIRONMENT_EQUALS_APPLY)
        assertThat(violations("{ scopes: [tenant:applications.read] }")).contains(ProvisionFile.ERR_PLAN_PROFILE_REQUIRES_ENVIRONMENT)
        assertThat(violations("{ environment: \"\" }")).contains(ProvisionFile.ERR_INVALID_PLAN_ENVIRONMENT)
        assertThat(violations("{ environment: p, scopes: [tenant:applications.write] }")).contains(ProvisionFile.ERR_PLAN_SCOPE_NOT_READ_ONLY)
        assertThat(violations("{ environment: p, scopes: [tenant:users.read] }")).contains(ProvisionFile.ERR_PLAN_SCOPE_NOT_SUBSET)
        assertThat(violations("{ environment: p, scopes: [] }")).contains(ProvisionFile.ERR_PLAN_SCOPES_EMPTY)
        assertThat(violations("{ environment: p, other: 1 }")).contains("unknown property 'other'")
        assertThat(violations("{ environment: p }", provider = "kubernetes", pinBlock = "kubernetes: { issuer: \"https://oidc.example/c\", namespace: a, serviceAccount: b }")).contains(ProvisionFile.ERR_PLAN_PROFILE_UNSUPPORTED)
        assertThat(violations("{ environment: p, scopes: [tenant:applications.read] }")).isEmpty()

        // The hub's own refusal at apply names the fix (a scope the file passed but the API still refuses, e.g. a race on the trust's scopes).
        api.callerScopes = setOf("tenant:applications.write")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: t
                spec: { provider: github_actions, github: { repository: thoryn-io/thoryn-cli, environment: e }, scopes: [tenant:applications.write, tenant:applications.read], confirmProduction: true, plan: { environment: p } }
            """,
        )
        val e = engine()
        assertThatThrownBy { e.apply(f, null, e.plan(f, null, false), "acme", "acme") {} }.hasMessageContaining("scope_not_grantable")
    }

    @Test
    fun `import renders a live plan profile with its scopes made explicit, and the rendered entry round-trips as a no-op`() {
        api.seedTrust(null, "thoryn-cli-ci", pins = pins, scopes = sixScopes, plan = mapOf("environment" to "thoryn-provision-e2e-plan", "scopes" to readScopes))
        val result = engine().import(existing = null, receipt = null)
        val entry = result.resources.single { it.resource.kind == "workloadIdentityTrust" }
        assertThat(entry.resource.spec["plan"]).isEqualTo(mapOf("environment" to "thoryn-provision-e2e-plan", "scopes" to readScopes))
        val yaml = "apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: workloadIdentityTrust, name: thoryn-cli-ci, spec: ${tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(entry.resource.spec)} }\n"
        val receipt = ProvisionReceipt(file = ProvisionFileRef("provision.yaml", "sha256:x"), appliedAt = "now", resources = listOfNotNull(entry.owned))
        assertThat(engine().plan(file(yaml), receipt, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `the owner identity with a read-only plan-profile token plans an owned resource GREEN, while a foreign manager still gets owned_elsewhere in plan and apply`() {
        // The repository's ONE identity owns the login client (creator-becomes-owner / a founder's grant); a plan job
        // signs in as the SAME wi_ client, minted read-only scopes by the plan profile.
        api.callerIsAdmin = false
        api.seedApplication(null, "CLI", listOf("http://127.0.0.1/old"), clientId = "cli")
        api.seedGrant("client:wi_10a7b379c79f7d1353f5798d", "owner", "application:cli")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: cli
                spec: { clientId: cli, displayName: "CLI", redirectUris: ["http://127.0.0.1/callback"] }
            """,
        )

        api.caller = "client:wi_10a7b379c79f7d1353f5798d"
        val ownerPlan = engine(callerScopes = readScopes.toSet(), subject = "client:wi_10a7b379c79f7d1353f5798d").plan(f, null, false)
        assertThat(ownerPlan.hasErrors).isFalse()
        val mine = ownerPlan.changes.single()
        assertThat(mine.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(mine.error).isNull()
        assertThat(mine.owner).isEqualTo("client:wi_10a7b379c79f7d1353f5798d")
        assertThat(mine.access).isEqualTo("manager")
        // A plan only reads: no write reached the API (the token could not have written anyway).
        assertThat(api.writes).isEmpty()

        // A foreign repository's identity — a `manager` of the client, but not its owner — is still refused, in plan and in apply.
        api.caller = "client:wi_other"
        api.seedGrant("client:wi_other", "manager", "application:cli")
        val foreign = engine(subject = "client:wi_other")
        val foreignPlan = foreign.plan(f, null, false)
        val refused = foreignPlan.changes.single()
        assertThat(refused.action).isEqualTo(ChangeAction.ERROR)
        assertThat(refused.error).isEqualTo(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(refused.reason).doesNotContain("wi_10a7b379c79f7d1353f5798d")
        assertThatThrownBy { foreign.apply(f, null, foreignPlan, "acme", "acme") {} }.isInstanceOf(ProvisionException::class.java).hasMessageContaining(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(api.writes).isEmpty()
    }
}
