package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.Access
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.FixRequest
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
 * SSO-3774 (oauthy ADR 2026-10-16 repository-owned workload identity trusts §4; story S3) — the engine gates a
 * `workloadIdentityTrust` PER OBJECT (`trust:<id>`, an ownable platform object since S1 SSO-3772), the way it gates an
 * application: the relation on the trust unioned with the relation on its plane, `owner` from the response for
 * owned-elsewhere, and the right on the trust itself as the fix. A create keeps the plane rule plus the PERSON rule
 * (Q2: a production trust is created by a person, once — never from CI). Binding a login client to a trust needs
 * `manager` on the trust (I4, SSO-3773). Every test runs as a CONFINED repository identity: no reach on the workspace.
 */
class ProvisionTrustPerObjectGateTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val repo = "client:wi_00000000000000000000beef"
    private val other = "client:wi_00000000000000000000cafe"

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

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    /** The production-plane GitHub trust a founder created for the starters application (pins as the hub renders them). */
    private val prodPins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-starters", "environment" to "provision", "ref" to "refs/heads/main")

    private fun trustYaml(name: String, environment: String? = null, extra: String = "", readOnly: Boolean = false) = """
          - kind: workloadIdentityTrust
            name: $name
${environment?.let { "            environment: $it\n" } ?: ""}${if (readOnly) "            readOnly: true\n" else ""}            spec:
              provider: github_actions
              github: { repository: ${if (environment == null) "thoryn-io/thoryn-starters, environment: provision, ref: refs/heads/main" else "acme/shared"} }
              scopes: [tenant:applications.read]$extra
${if (environment == null) "              confirmProduction: true\n" else ""}"""

    private fun doc(vararg entries: String) = file("apiVersion: thoryn.io/provision/v1\nresources:\n" + entries.joinToString(""))

    @Test
    fun `a repository that OWNS a production trust plans noop on it and converges its plan profile — with no reach on the workspace`() {
        val id = api.seedTrust(null, "starters-ci", pins = prodPins)
        api.seedGrant(repo, "owner", "trust:$id")

        val noop = engine().plan(doc(trustYaml("starters-ci")), false).changes.single()
        assertThat(noop.action).isEqualTo(ChangeAction.NOOP)
        assertThat(noop.access).isEqualTo(Access.MANAGER.label)
        assertThat(noop.owner).isEqualTo(repo)
        assertThat(api.checksOn("trust:$id")).contains("manager")

        // The one additive update a trust has (SSO-3702): the owner converges it through set-plan-profile.
        val withPlan = doc(trustYaml("starters-ci", extra = "\n              plan: { environment: provision-plan }"))
        val e = engine()
        val plan = e.plan(withPlan, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        val result = e.apply(withPlan, plan, "thoryn", null)
        assertThat(api.writes.single().path).isEqualTo("/api/v1/workload-identity/trusts/$id/plan-profile")
        assertThat(result.resources.single().owner).isEqualTo(repo)
    }

    @Test
    fun `an application whose trust the repository owns resolves federatedTrust under confinement and rebinds to another owned trust`() {
        api.environmentClaimFilter = true
        val blue = api.seedTrust(null, "starters-blue", pins = prodPins)
        val green = api.seedTrust(null, "starters-green", pins = prodPins + ("environment" to "provision-green"))
        listOf(blue, green).forEach { api.seedGrant(repo, "owner", "trust:$it") }
        api.seedApplication(null, "Starters", listOf("https://starters.thoryn.io/cb"), clientId = "starters")
        api.applications.single()["clientAuthenticationMethods"] = listOf("federated_assertion")
        api.applications.single()["federatedTrust"] = blue
        api.seedGrant(repo, "owner", "application:starters")
        fun app(trust: String) = """
          - kind: application
            name: starters
            spec: { clientId: starters, displayName: Starters, redirectUris: ["https://starters.thoryn.io/cb"], clientAuthenticationMethods: [federated_assertion], federatedTrust: $trust }
"""
        val green2 = trustYaml("starters-green").replace("environment: provision,", "environment: provision-green,")

        val same = engine().plan(doc(trustYaml("starters-blue"), green2, app("starters-blue")), false)
        assertThat(same.hasErrors).isFalse()
        assertThat(same.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }

        val rebound = doc(trustYaml("starters-blue"), green2, app("starters-green"))
        val e = engine()
        val plan = e.plan(rebound, false)
        assertThat(plan.hasErrors).isFalse()
        assertThat(plan.changes.single { it.kind == "application" }.diff).containsOnlyKeys("federatedTrust")
        e.apply(rebound, plan, "thoryn", null)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("federatedTrust" to green))
    }

    @Test
    fun `a trust another repository owns is access_owned_elsewhere naming no subject — unless declared readOnly — and one it may only view is access_read_only with owner on the trust`() {
        val sbx = api.seedEnvironment("ci-sbx")
        api.seedGrant(repo, "manager", "environment:$sbx")
        val shared = api.seedTrust("ci-sbx", "shared", pins = mapOf("owner" to "acme", "repository" to "shared"))
        api.seedGrant(other, "owner", "trust:$shared")

        val elsewhere = engine().plan(doc(trustYaml("shared", "ci-sbx")), false).changes.single()
        assertThat(elsewhere.action).isEqualTo(ChangeAction.ERROR)
        assertThat(elsewhere.error).isEqualTo(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(elsewhere.reason).contains("trust:$shared is owned by another repository").doesNotContain(other)
        assertThat(elsewhere.fix!!.cli).isNull() // a dispute an admin decides, never a command for the repository
        assertThat(engine().plan(doc(trustYaml("shared", "ci-sbx", readOnly = true)), false).changes.single().action).isEqualTo(ChangeAction.NOOP)

        val elsewhereEnv = api.seedEnvironment("other")
        val viewed = api.seedTrust("other", "viewed", pins = mapOf("owner" to "acme", "repository" to "shared"))
        api.seedGrant(repo, "viewer", "trust:$viewed") // a right on the trust alone — nothing on its environment
        assertThat(api.holds("environment:$elsewhereEnv", "viewer")).isFalse()
        val readOnly = engine().plan(doc(trustYaml("viewed", "other")), false).changes.single()
        assertThat(readOnly.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(readOnly.fix!!.objectRef).isEqualTo("trust:$viewed")
        assertThat(readOnly.fix!!.cli).isEqualTo("thoryn access grant $repo owner trust:$viewed")
    }

    @Test
    fun `binding a client to a trust it does not manage is refused with owner on the trust — another repository's trust is the dispute — and an unchanged binding is never re-checked`() {
        api.environmentClaimFilter = true
        val viewed = api.seedTrust(null, "pods", "kubernetes", pins = mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "web", "serviceAccount" to "web"))
        api.seedGrant(repo, "viewer", "trust:$viewed")
        api.seedApplication(null, "Web", listOf("https://web.example/cb"), clientId = "web")
        api.seedGrant(repo, "owner", "application:web")
        val bind = doc(
            """
          - kind: application
            name: web
            spec: { clientId: web, displayName: Web, redirectUris: ["https://web.example/cb"], clientAuthenticationMethods: [federated_assertion], federatedTrust: pods }
""",
        )

        val refused = engine().plan(bind, false).changes.single()
        assertThat(refused.action).isEqualTo(ChangeAction.ERROR)
        assertThat(refused.error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(refused.reason).contains("requires `manager` on the trust").contains(ProvisionEngine.ERROR_FEDERATED_TRUST_NOT_FOUND)
        assertThat(refused.fix!!.cli).isEqualTo("thoryn access grant $repo owner trust:$viewed")
        assertThatThrownBy { engine().apply(bind, engine().plan(bind, false), "thoryn", null) }.isInstanceOf(ProvisionException::class.java)
        assertThat(api.writes).isEmpty()

        api.seedGrant(other, "owner", "trust:$viewed")
        val dispute = engine().plan(bind, false).changes.single()
        assertThat(dispute.error).isEqualTo(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(dispute.fix!!.cli).isNull()

        // Bound already (an admin did it): the platform re-checks a binding only when it is set or changed — so does the plan.
        api.applications.single()["clientAuthenticationMethods"] = listOf("federated_assertion")
        api.applications.single()["federatedTrust"] = viewed
        assertThat(engine().plan(bind, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `CI never creates a production trust — refused with the founder's command, while a person creates it and CI still creates a sandbox trust`() {
        api.callerIsAdmin = true // even a CI identity that reaches the whole workspace: absence is real here, and the rule is Q2's
        val f = doc(trustYaml("starters-ci"))
        val ci = engine()
        val plan = ci.plan(f, false)
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_TRUST_PRODUCTION_PERSON)
        assertThat(row.reason).contains("is a person's act").contains("thoryn provision apply --file")
            .contains("thoryn access grant $repo owner trust:${FixRequest.TRUST_ID_PLACEHOLDER}")
        val (items, notes) = FixRequest.fromPlan(plan)
        assertThat(items).isEmpty() // "no trust creation" is outside the consentable set: a note, never an item
        assertThat(notes.single()).contains("created by a PERSON")
        assertThatThrownBy { ci.apply(f, plan, "thoryn", null) }.isInstanceOf(ProvisionException::class.java)
        assertThat(api.trusts).isEmpty()

        // The founder (a person) creates it — the bootstrap the ADR keeps human.
        val founder = engine(subject = "member:founder")
        assertThat(founder.plan(f, false).changes.single().action).isEqualTo(ChangeAction.CREATE)
        // A sandbox is the repository's to fill: CI creates there, and becomes the trust's owner (creator-becomes-owner, S1).
        api.callerIsAdmin = false
        val sbx = api.seedEnvironment("ci-sbx")
        api.seedGrant(repo, "manager", "environment:$sbx")
        val sandbox = doc(trustYaml("pr-ci", "ci-sbx"))
        val created = ci.apply(sandbox, ci.plan(sandbox, false), "thoryn", null)
        assertThat(created.resources.single().owner).isEqualTo(repo)
    }

    @Test
    fun `a changed pin on an owned production trust is immutable and says a new pin set is a person's new trust — the engine never mutates a pin`() {
        val id = api.seedTrust(null, "starters-ci", pins = prodPins)
        api.seedGrant(repo, "owner", "trust:$id")
        val moved = doc(trustYaml("starters-ci").replace("thoryn-io/thoryn-starters", "attacker/fork"))
        val plan = engine().plan(moved, false)
        val row = plan.changes.single()
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_TRUST_IMMUTABLE)
        assertThat(row.reason).contains("a new production trust is created by a PERSON, never by this file from CI")
        assertThat(row.fixNote).contains("a new pin set is a new trust a person creates")
        assertThatThrownBy { engine().apply(moved, plan, "thoryn", null) }.isInstanceOf(ProvisionException::class.java)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a readOnly trust the identity cannot see is access_not_reachable with viewer on it by name`() {
        api.seedTrust(null, "platform-ci", pins = prodPins)
        val row = engine().plan(doc(trustYaml("platform-ci", readOnly = true)), false).changes.single()
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_NOT_REACHABLE)
        assertThat(row.fix!!.kind).isEqualTo(FixRequest.Kind.VIEWER)
        assertThat(row.fix!!.objectRef).isEqualTo("trust:platform-ci")
        assertThat(row.fix!!.cli).isEqualTo("thoryn access grant $repo viewer trust:${FixRequest.TRUST_ID_PLACEHOLDER}")
    }
}
