package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3925 — `provision plan / apply` converge a declared trust whose only difference from the live one is its SCOPES (and
 * its live plan profile's) IN PLACE (`PUT …/trusts/{id}/scopes`): the trust id, its `wi_` client and its owner stay, so no
 * `connection.json` or grant moves. A narrowing converges from CI; a WIDENING is a person's act (oauthy ADR 2026-10-21 §4b) —
 * from CI the plan is red `elevated_action_requires_person` naming the `set-scopes` line, for a person it is planned and the
 * platform's step-up refusal is rendered with the `thoryn login --acr-values … --max-age …` line. A pin change stays
 * `workload_identity_trust_immutable`. Runs as the CONFINED repository identity that OWNS the trust, the dogfood shape.
 */
class ProvisionTrustScopesInPlaceTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val repo = "client:wi_00000000000000000000beef"
    private val pins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-cicd", "environment" to "provision", "ref" to "refs/heads/main")
    private val live = listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read")

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = repo
    }

    private fun engine(subject: String? = repo, callerScopes: Set<String>? = null) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject, callerScopes = callerScopes,
    )

    private fun doc(scopes: List<String>, plan: String? = null, repository: String = "thoryn-io/thoryn-cicd") = ProvisionFile.parse(
        """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: workloadIdentityTrust
            name: cicd-forge
            spec:
              provider: github_actions
              github: { repository: $repository, environment: provision, ref: refs/heads/main }
              scopes: [${scopes.joinToString(", ")}]
              confirmProduction: true${plan?.let { "\n              plan: $it" } ?: ""}
        """.trimIndent().toByteArray(),
        "provision.yaml",
    )

    /** The trust; [owned] ⇒ the repository identity owns it (the CI shape), else nobody does (a founder's file applies it). */
    private fun seed(plan: Map<String, Any?>? = null, owned: Boolean = true): String =
        api.seedTrust(null, "cicd-forge", pins = pins, scopes = live, clientId = "wi_cicdforge", plan = plan)
            .also { if (owned) api.seedGrant(repo, "owner", "trust:$it") }

    private fun scopeWrites() = api.writes.filter { it.method != "GET" && it.path != "/api/v1/access/check" }

    @Test
    fun `a narrowing converges in place from CI - same trust, same wi_ client, then a no-op`() {
        val id = seed()
        val narrower = doc(listOf("tenant:applications.read", "tenant:access.read"))
        val e = engine()
        val plan = e.plan(narrower, false)
        val row = plan.changes.single()
        assertThat(row.action).describedAs(row.reason).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.error).isNull()
        assertThat(row.diff).containsOnlyKeys("scopes")
        assertThat(row.reason).contains("changes its scopes in place").contains("removes tenant:applications.write").contains("wi_cicdforge stays")
            .doesNotContain("passkey")

        val result = e.apply(narrower, plan, "thoryn", null)
        val write = scopeWrites().single()
        assertThat(write.method).isEqualTo("PUT")
        assertThat(write.path).isEqualTo("/api/v1/workload-identity/trusts/$id/scopes")
        assertThat(write.body).containsEntry("scopes", listOf("tenant:applications.read", "tenant:access.read")).doesNotContainKey("planScopes")
        assertThat(result.resources.single().id).isEqualTo(id)
        assertThat(result.resources.single().attributes[ProvisionEngine.ATTR_CLIENT_ID]).isEqualTo("wi_cicdforge")
        assertThat(api.trusts.single()["clientId"]).isEqualTo("wi_cicdforge")
        assertThat(console.toString()).contains("~ workloadIdentityTrust cicd-forge: scopes changed in place (-tenant:applications.write)").contains("wi_ client wi_cicdforge unchanged")

        api.reset()
        assertThat(engine().plan(narrower, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `a widening from CI is red elevated_action_requires_person naming the set-scopes line, and nothing is written`() {
        val id = seed()
        val wider = doc(live + "tenant:workload-identity.read")
        val e = engine()
        val plan = e.plan(wider, false)
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_ELEVATED_ACTION_REQUIRES_PERSON)
        assertThat(row.reason).contains("adds tenant:workload-identity.read").contains("a PERSON's act")
            .contains("thoryn workload-identity trusts set-scopes $id --scope \"${(live + "tenant:workload-identity.read").joinToString(" ")}\"")
        assertThat(row.fixNote).contains("may narrow a trust's scopes, never widen them")
        assertThatThrownBy { e.apply(wider, plan, "thoryn", null) }.isInstanceOf(ProvisionException::class.java)
        assertThat(scopeWrites()).isEmpty()
    }

    @Test
    fun `a widening by a person is planned with the passkey note and made in place`() {
        api.caller = "member:founder"
        api.callerIsAdmin = true
        val id = seed(owned = false)
        val wider = doc(live + "tenant:workload-identity.read")
        val e = engine(subject = "member:founder")
        val plan = e.plan(wider, false)
        val row = plan.changes.single()
        assertThat(row.action).describedAs(row.reason).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.reason).contains("adds tenant:workload-identity.read")
            .contains("passkey sign-in from the last 5 minutes").contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
        e.apply(wider, plan, "thoryn", null)
        assertThat(scopeWrites().single().path).isEqualTo("/api/v1/workload-identity/trusts/$id/scopes")
        assertThat(api.trusts.single()["scopes"]).isEqualTo(live + "tenant:workload-identity.read")
        assertThat(api.trusts.single()["clientId"]).isEqualTo("wi_cicdforge")
    }

    @Test
    fun `a person whose sign-in is not a fresh passkey gets the step-up line at apply, and the trust is unchanged`() {
        api.caller = "member:founder"
        api.callerIsAdmin = true
        seed(owned = false)
        api.trustWidening = "step_up"
        val wider = doc(live + "tenant:workload-identity.read")
        val e = engine(subject = "member:founder")
        assertThatThrownBy { e.apply(wider, e.plan(wider, false), "thoryn", null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("needs a passkey sign-in from the last 5 minutes")
            .hasMessageContaining("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
        assertThat(api.trusts.single()["scopes"]).isEqualTo(live)
    }

    @Test
    fun `declared plan scopes that differ from the live profile's change in place, and a narrowing keeps a derived profile inside the new scopes`() {
        val id = seed(plan = mapOf("environment" to "provision-plan", "scopes" to listOf("tenant:applications.read", "tenant:access.read")))

        // Explicit plan scopes, narrower: an in-place change of the plan profile only.
        val planNarrower = doc(live, plan = "{ environment: provision-plan, scopes: [tenant:access.read] }")
        val e = engine()
        val plan = e.plan(planNarrower, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        assertThat(plan.changes.single().diff).containsOnlyKeys("plan.scopes")
        e.apply(planNarrower, plan, "thoryn", null)
        assertThat(scopeWrites().single().body).containsEntry("planScopes", listOf("tenant:access.read")).doesNotContainKey("scopes")

        // A derived profile (no plan scopes declared) and narrower apply scopes: the profile keeps what is still inside them.
        api.trusts.clear(); api.reset()
        seed(plan = mapOf("environment" to "provision-plan", "scopes" to listOf("tenant:applications.read", "tenant:access.read")))
        val applyNarrower = doc(listOf("tenant:applications.read", "tenant:applications.write"), plan = "{ environment: provision-plan }")
        val e2 = engine()
        e2.apply(applyNarrower, e2.plan(applyNarrower, false), "thoryn", null)
        assertThat(scopeWrites().single().body)
            .containsEntry("scopes", listOf("tenant:applications.read", "tenant:applications.write"))
            .containsEntry("planScopes", listOf("tenant:applications.read"))

        // …and none left: the file must name the plan scopes.
        api.trusts.clear(); api.reset()
        seed(plan = mapOf("environment" to "provision-plan", "scopes" to listOf("tenant:access.read")))
        val orphaned = engine().plan(doc(listOf("tenant:applications.read", "tenant:applications.write"), plan = "{ environment: provision-plan }"), false).changes.single()
        assertThat(orphaned.action).isEqualTo(ChangeAction.ERROR)
        assertThat(orphaned.error).isEqualTo(ProvisionFile.ERR_PLAN_SCOPE_NOT_SUBSET)
        assertThat(orphaned.reason).contains("name spec.plan.scopes")
        assertThat(id).isNotBlank()
    }

    @Test
    fun `a scope the applying identity does not hold is scope_not_grantable in the plan`() {
        seed()
        val row = engine(callerScopes = setOf("tenant:applications.read", "tenant:access.read", "tenant:workload-identity.write"))
            .plan(doc(listOf("tenant:applications.read", "tenant:access.read", "tenant:applications.write")), false).changes.single()
        // Nothing changed for applications.write (it is live already) — but the trust's set is re-granted whole: the API checks every scope.
        assertThat(row.action).isEqualTo(ChangeAction.NOOP)
        val narrow = engine(callerScopes = setOf("tenant:access.read", "tenant:workload-identity.write"))
            .plan(doc(listOf("tenant:applications.read", "tenant:access.read")), false).changes.single()
        assertThat(narrow.action).isEqualTo(ChangeAction.ERROR)
        assertThat(narrow.error).isEqualTo(ProvisionEngine.ERROR_SCOPE_NOT_GRANTABLE)
        // SSO-4089 — the scope is named as one the trust already carries (product-api re-grants the whole set), not as an addition.
        assertThat(narrow.reason).contains("does not hold tenant:applications.read, which the trust already carries").doesNotContain("which this file adds")
    }

    @Test
    fun `a scope change together with a pin change is still workload_identity_trust_immutable`() {
        seed()
        val row = engine().plan(doc(listOf("tenant:applications.read"), repository = "thoryn-io/elsewhere"), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_TRUST_IMMUTABLE)
        assertThat(row.reason).contains("a trust's pins are immutable")
    }
}
