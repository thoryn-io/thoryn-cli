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
import java.io.File
import java.io.PrintStream
import java.util.Base64

/**
 * SSO-4089 — the scope ceiling in a plan that runs under a trust's PLAN PROFILE (thoryn-io/thoryn-tenant PR 5, run
 * 41036416524). The plan job is minted read-only scopes by design, so it never holds a `.write` scope; the identity that
 * APPLIES is the trust's apply profile, whose scopes this session cannot see. The engine therefore leaves the ceiling to
 * apply under the plan profile — a narrowing is a plain `update`, a create is planned with the ceiling noted on the row —
 * instead of refusing every trust that keeps a write scope with `scope_not_grantable`. A session whose scopes ARE the
 * applying identity's (a person, an API key, the apply profile) keeps the refusal, naming what this file adds apart from
 * what the trust already carries.
 */
class ProvisionTrustScopesPlanProfileTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    /** The config repository's own identity (thoryn-tenant), which owns the trust it declares. */
    private val repo = "client:wi_0000000000000000000tenant"
    private val pins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-cicd", "environment" to "forge", "ref" to "refs/heads/main")
    private val live = listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:roles.read", "tenant:roles.write")
    private val livePlan = listOf("tenant:applications.read", "tenant:access.read", "tenant:roles.read")
    private val narrowed = listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read")
    private val narrowedPlan = listOf("tenant:applications.read", "tenant:access.read")
    /** What the hub mints a plan job: the plan profile of thoryn-tenant's trust — read scopes only. */
    private val planProfileScopes = setOf("tenant:applications.read", "tenant:access.read", "tenant:roles.read", "tenant:workload-identity.read")

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = repo
    }

    private fun engine(callerScopes: Set<String>?, planProfile: Boolean, subject: String? = repo) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject, callerScopes = callerScopes, planProfile = planProfile,
    )

    /** The plan job's engine: the plan profile's read scopes, flagged as such. */
    private fun planJob() = engine(callerScopes = planProfileScopes, planProfile = true)

    private fun doc(scopes: List<String>, planScopes: List<String>, name: String = "thoryn-cicd-forge-v3", environment: String? = null) = ProvisionFile.parse(
        buildString {
            appendLine("apiVersion: thoryn.io/provision/v1")
            appendLine("resources:")
            appendLine("  - kind: workloadIdentityTrust")
            appendLine("    name: $name")
            environment?.let { appendLine("    environment: $it") }
            appendLine("    spec:")
            appendLine("      provider: github_actions")
            appendLine("      github: { repository: thoryn-io/thoryn-cicd, environment: forge, ref: refs/heads/main }")
            appendLine("      scopes: [${scopes.joinToString(", ")}]")
            appendLine("      plan: { environment: forge-plan, scopes: [${planScopes.joinToString(", ")}] }")
            appendLine("      confirmProduction: true")
        }.toByteArray(),
        "thoryn/tenant.yaml",
    )

    private fun seed(): String =
        api.seedTrust(null, "thoryn-cicd-forge-v3", pins = pins, scopes = live, clientId = "wi_cicdforge", plan = mapOf("environment" to "forge-plan", "scopes" to livePlan))
            .also { api.seedGrant(repo, "owner", "trust:$it") }

    private fun scopeWrites() = api.writes.filter { it.method != "GET" && it.path != "/api/v1/access/check" }

    @Test
    fun `a narrowing under the plan profile plans as an update with no grantability condition`() {
        seed()
        val plan = planJob().plan(doc(narrowed, narrowedPlan), false)
        val row = plan.changes.single()
        assertThat(row.action).describedAs(row.reason).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.error).isNull()
        assertThat(row.diff).containsOnlyKeys("scopes", "plan.scopes")
        assertThat(row.reason).contains("changes its scopes in place").contains("removes tenant:roles.read tenant:roles.write plan:tenant:roles.read")
            .doesNotContain("scope_not_grantable").doesNotContain("checked at apply").doesNotContain("adds")
        assertThat(plan.hasErrors).isFalse()
        assertThat(scopeWrites()).isEmpty()
    }

    @Test
    fun `the same narrowing by a person whose session lacks a write scope the trust keeps is still scope_not_grantable, naming it as kept`() {
        // product-api re-grants the whole new set on `PUT …/{id}/scopes` (D6: every requested scope, as at create), so a
        // session whose scopes ARE the applying identity's and lack a KEPT scope is refused — the apply would be.
        api.caller = "member:founder"
        api.callerIsAdmin = true
        seed()
        val row = engine(callerScopes = planProfileScopes, planProfile = false, subject = "member:founder").plan(doc(narrowed, narrowedPlan), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_SCOPE_NOT_GRANTABLE)
        assertThat(row.reason).contains("does not hold tenant:applications.write, which the trust already carries").doesNotContain("which this file adds")
    }

    @Test
    fun `a widening under the plan profile is not scope_not_grantable — it is the person's act the apply would be refused as, naming only the added scope`() {
        seed()
        val wider = doc(live + "tenant:workload-identity.read", livePlan)
        val plan = planJob().plan(wider, false)
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_ELEVATED_ACTION_REQUIRES_PERSON)
        // The set-scopes fix line lists the whole new set (that is the command); nothing is said to be "not held".
        assertThat(row.reason).contains("adds tenant:workload-identity.read").doesNotContain("scope_not_grantable").doesNotContain("does not hold")
        assertThat(scopeWrites()).isEmpty()
    }

    @Test
    fun `a widening in a person session lacking the added scope is refused naming only the added scope`() {
        api.caller = "member:founder"
        api.callerIsAdmin = true
        seed()
        val held = live.toSet() + "tenant:workload-identity.write"
        val wider = doc(live + "tenant:workload-identity.read", livePlan)
        val row = engine(callerScopes = held, planProfile = false, subject = "member:founder").plan(wider, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_SCOPE_NOT_GRANTABLE)
        assertThat(row.reason).contains("does not hold tenant:workload-identity.read, which this file adds")
            .doesNotContain("already carries").doesNotContain("tenant:applications.write").doesNotContain("tenant:roles.write")
    }

    @Test
    fun `a trust create under the plan profile is planned with the ceiling left to apply, and the API still refuses an apply identity that lacks a scope`() {
        val envId = api.seedEnvironment("forge-sbx")
        api.seedGrant(repo, "manager", "environment:$envId")
        val f = doc(narrowed, narrowedPlan, name = "forge-sbx-ci", environment = "forge-sbx")
        val plan = planJob().plan(f, false)
        val row = plan.changes.single()
        assertThat(row.action).describedAs(row.reason).isEqualTo(ChangeAction.CREATE)
        assertThat(row.error).isNull()
        assertThat(row.reason).contains("grantability of tenant:applications.read tenant:applications.write tenant:access.read is checked at apply against the apply identity")
            .contains("read-only plan profile")
        assertThat(plan.hasErrors).isFalse()

        // The apply job: its own token. product-api's ceiling (the fake's `callerScopes`) answers for an identity that lacks a scope.
        api.callerScopes = setOf("tenant:applications.read", "tenant:access.read", "tenant:workload-identity.write")
        val applyJob = engine(callerScopes = null, planProfile = false)
        assertThatThrownBy { applyJob.apply(f, plan, "thoryn", null) }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("scope_not_grantable")
        assertThat(api.trusts).isEmpty()

        // …and converges for one that holds them.
        api.callerScopes = narrowed.toSet() + "tenant:workload-identity.write"
        val receipt = engine(callerScopes = null, planProfile = false).apply(f, plan, "thoryn", null)
        assertThat(receipt.resources.single().action).isEqualTo(ChangeAction.CREATE)
        assertThat(api.trusts.single()["scopes"]).isEqualTo(narrowed)
    }

    @Test
    fun `a narrowing planned under the plan profile converges at apply under the apply profile, which holds the trust's new set`() {
        val id = seed()
        val plan = planJob().plan(doc(narrowed, narrowedPlan), false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        // The apply profile of thoryn-tenant's trust holds the writes it provisions (product-api checks the whole new set).
        api.callerScopes = narrowed.toSet() + setOf("tenant:workload-identity.write", "tenant:workload-identity.read")
        val receipt = engine(callerScopes = api.callerScopes, planProfile = false).apply(doc(narrowed, narrowedPlan), plan, "thoryn", null)
        val write = scopeWrites().single()
        assertThat(write.method).isEqualTo("PUT")
        assertThat(write.path).isEqualTo("/api/v1/workload-identity/trusts/$id/scopes")
        assertThat(write.body).containsEntry("scopes", narrowed).containsEntry("planScopes", narrowedPlan)
        assertThat(receipt.resources.single().id).isEqualTo(id)
        assertThat(api.trusts.single()["scopes"]).isEqualTo(narrowed)
        assertThat(api.trusts.single()["clientId"]).isEqualTo("wi_cicdforge")
    }

    // ── the CLI: the session's profile reaches the engine ──

    private fun jwt(scope: String, clientId: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString("""{"sub":"$clientId","client_id":"$clientId","scope":"$scope","tnt":"${api.tenantId}"}""".toByteArray())
        return "$header.$payload.sig"
    }

    @Test
    fun `thoryn provision plan under a plan-profile session plans the narrowing, and the same read-only scopes under the apply profile are the red ceiling`() {
        seed()
        val wi = repo.removePrefix("client:")
        val f = File(File(tempHome.toFile(), ".thoryn").apply { mkdirs() }, "tenant.yaml").apply {
            writeBytes(buildDoc())
        }
        fun session(profile: String) = Tokens(
            accessToken = jwt(planProfileScopes.joinToString(" "), wi), authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY,
            profile = profile, clientId = wi, jobEnvironment = if (profile == Tokens.PROFILE_PLAN) "tenant-plan" else "tenant",
        )

        seedTokens(session(Tokens.PROFILE_PLAN))
        val planned = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(planned.err).describedAs(planned.err).doesNotContain("scope_not_grantable")
        assertThat(planned.exit).isEqualTo(0)
        assertThat(planned.out).contains("workloadIdentityTrust  thoryn-cicd-forge-v3").contains("update").contains("removes tenant:roles.read tenant:roles.write plan:tenant:roles.read")
            .contains("1 to update")
        assertThat(scopeWrites()).isEmpty()

        // The APPLY profile's scopes are the applying identity's: the same read-only set cannot re-grant a kept write scope.
        api.reset()
        seedTokens(session(Tokens.PROFILE_APPLY))
        val red = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(red.exit).isNotEqualTo(0)
        assertThat(red.err).contains("scope_not_grantable").contains("does not hold tenant:applications.write, which the trust already carries")
    }

    private fun buildDoc(): ByteArray = buildString {
        appendLine("apiVersion: thoryn.io/provision/v1")
        appendLine("resources:")
        appendLine("  - kind: workloadIdentityTrust")
        appendLine("    name: thoryn-cicd-forge-v3")
        appendLine("    spec:")
        appendLine("      provider: github_actions")
        appendLine("      github: { repository: thoryn-io/thoryn-cicd, environment: forge, ref: refs/heads/main }")
        appendLine("      scopes: [${narrowed.joinToString(", ")}]")
        appendLine("      plan: { environment: forge-plan, scopes: [${narrowedPlan.joinToString(", ")}] }")
        appendLine("      confirmProduction: true")
    }.toByteArray()
}
