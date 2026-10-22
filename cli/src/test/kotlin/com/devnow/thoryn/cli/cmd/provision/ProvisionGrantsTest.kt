package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3113 (epic SSO-3108) — the `grants:` block of a provisioning file converges like any other
 * field, against the SSO-3112 `/api/v1/access` contract (stubbed by [FakeProductApi]): after a
 * resource resolves to a live id its object's grants are listed (`GET …/grants?object=<ref>`), missing
 * ones POSTed; SSO-3715 (ADR 2026-10-15 §2) — undeclared live grants are shown as "present, not declared"
 * and revoked only by `--prune`, on an object the caller may delete, never the `owner` tuple, a workspace
 * userset or the caller's own subject. The object ref derives from the live id; a session without
 * `tenant:access.write` fails closed AFTER the resource itself exists.
 */
class ProvisionGrantsTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        // SSO-3119 — the fake resolves a `client:` subject before it writes a tuple, as product-api does
        // (AccessGrantService.subjectBelongsToWorkspace). The fixtures below grant to `client:cli-ci`, so
        // that identity has to exist; the case where the SAME file declares it is its own test.
        api.seedApplication(env = null, displayName = "CI identity", clientId = "cli-ci")
    }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        // SSO-3715 — the caller's own subject (the fake's default founder): `--prune` never revokes its own grant.
        subject = "member:founder",
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, prune: Boolean = false): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, prune), "acme", null)
    }

    private fun writes() = api.writes.map { it.method + " " + it.path }

    private val declared = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
            grants:
              - { subject: "client:cli-ci", relation: manager }
          - kind: application
            name: rp
            environment: ci
            spec: { displayName: "RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
            grants:
              - { subject: "member:alice", relation: viewer }
          - kind: loginMethods
            environment: ci
            spec: { methods: [password] }
            grants:
              - { subject: "client:cli-ci", relation: manager }
    """

    @Test
    fun `grants on created resources are POSTed after each resource exists, keyed by its live id, and a second apply issues no writes`() {
        val f = file(declared)
        val plan = engine().plan(f, false)
        // Nothing exists yet ⇒ every declared grant is an add on a create.
        assertThat(plan.changes.map { it.action }).allMatch { it == ChangeAction.CREATE }
        assertThat(plan.changes.map { it.grantAdds }).containsExactly(listOf("client:cli-ci manager"), listOf("member:alice viewer"), listOf("client:cli-ci manager"))
        assertThat(plan.grantChanges).isEqualTo(3)
        assertThat(plan.toStructured()["summary"]).isEqualTo(mapOf("create" to 3, "update" to 0, "remove" to 0, "noop" to 0, "skip" to 0, "grants" to 3, "error" to 0, "publish" to 0, "deliver" to 0, "pull" to 0))

        val receipt = apply(f)
        val envId = receipt.resources[0].id
        val clientId = receipt.resources[1].id
        // SSO-3119 — every resource is created first, then every grant, in declaration order; the object
        // ref is the live id (the singleton by its env slug).
        assertThat(writes()).containsExactly(
            "POST /api/v1/environments", "POST /api/v1/applications", "PUT /api/v1/login-methods",
            "POST /api/v1/access/grants", "POST /api/v1/access/grants", "POST /api/v1/access/grants",
        )
        val grantPosts = api.writesTo("/api/v1/access/grants")
        assertThat(grantPosts.map { it.body }).containsExactly(
            mapOf("subject" to "client:cli-ci", "relation" to "manager", "object" to "environment:$envId"),
            mapOf("subject" to "member:alice", "relation" to "viewer", "object" to "application:$clientId"),
            mapOf("subject" to "client:cli-ci", "relation" to "manager", "object" to "login_methods:ci-sbx"),
        )
        // Grants are workspace-level: no X-Thoryn-Environment on the access calls.
        assertThat(grantPosts.map { it.env }).allMatch { it == null }
        assertThat(console.toString()).contains("+ grant environment ci: client:cli-ci manager on environment:$envId")

        // Converged ⇒ the next plan/apply reads the grants and writes nothing.
        api.reset()
        val again = engine().plan(f, false)
        assertThat(again.hasChanges).isFalse()
        assertThat(again.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    /**
     * SSO-3715 (ADR 2026-10-15 §2) — grants are additive by default: a live grant the block does not declare is
     * "present, not declared", shown and left alone. With `--prune` (on an object the caller may delete — here a
     * founder who manages the sandbox nobody owns) the undeclared ones are revoked, EXCEPT the workspace userset
     * and the caller's own subject (`member:founder`, the fake's default caller).
     */
    @Test
    fun `grants converge on an existing object — missing added, undeclared ones shown, revoked only by --prune and never the userset or the caller itself`() {
        val envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedGrant("workspace:t-1#admin", "manager", "environment:$envId")
        api.seedGrant("member:founder", "manager", "environment:$envId")  // creator-becomes-manager
        api.seedGrant("client:old-ci", "manager", "environment:$envId")   // an admin's own grant
        api.seedGrant("client:old-ci", "manager", "environment:env-other") // an object the file does not own
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
                grants:
                  - { subject: "client:cli-ci", relation: manager }
            """,
        )
        val plan = engine().plan(f, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.grantAdds).containsExactly("client:cli-ci manager")
        assertThat(change.grantRemoves).isEmpty()
        // Shown, never red: the three grants the block does not declare.
        assertThat(change.grantUndeclared).containsExactlyInAnyOrder("workspace:t-1#admin manager", "member:founder manager", "client:old-ci manager")
        assertThat(change.reason).contains("grants: +1 −0").contains("3 grant(s) present, not declared")
        assertThat(change.toStructured()["grantsUndeclared"]).isEqualTo(change.grantUndeclared)
        assertThat(plan.hasChanges).isTrue()

        apply(f)
        assertThat(writes()).containsExactly("POST /api/v1/access/grants")
        assertThat(api.grantsOn("environment:$envId"))
            .containsExactlyInAnyOrder("workspace:t-1#admin manager", "member:founder manager", "client:old-ci manager", "client:cli-ci manager")

        // Drop it from the file WITHOUT --prune ⇒ nothing is revoked: there is no ledger of "this file granted it".
        api.reset()
        val dropped = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
                grants: []
            """,
        )
        val shown = engine().plan(dropped, false).changes.single()
        assertThat(shown.grantRemoves).isEmpty()
        assertThat(shown.grantUndeclared).hasSize(4)
        apply(dropped)
        assertThat(api.writes).isEmpty()

        // With --prune ⇒ the undeclared grants are revoked, EXCEPT the workspace userset and the caller's own subject.
        val pruned = engine().plan(dropped, true).changes.single { it.kind == "environment" }
        assertThat(pruned.grantRemoves).containsExactlyInAnyOrder("client:old-ci manager", "client:cli-ci manager")
        assertThat(pruned.grantUndeclared).containsExactlyInAnyOrder("workspace:t-1#admin manager", "member:founder manager")
        apply(dropped, prune = true)
        assertThat(writes()).containsExactly("DELETE /api/v1/access/grants", "DELETE /api/v1/access/grants")
        assertThat(api.writes.map { it.body["subject"] }).containsExactlyInAnyOrder("client:old-ci", "client:cli-ci")
        assertThat(api.grantsOn("environment:$envId")).containsExactlyInAnyOrder("workspace:t-1#admin manager", "member:founder manager")
        // An object the file does not declare is never touched.
        assertThat(api.grantsOn("environment:env-other")).containsExactly("client:old-ci manager")
    }

    @Test
    fun `a no-op resource still converges its grants, an omitted grants block touches nothing, and an empty one revokes every revocable grant with --prune`() {
        val f = file(declared.substringBefore("  - kind: application"))
        val receipt = apply(f)
        val envId = receipt.resources.single().id
        api.reset()

        // Omitted `grants:` ⇒ unmanaged: the existing grant survives, nothing is written.
        val unmanaged = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: environment, name: ci, spec: { slug: ci-sbx, displayName: \"CI sandbox\" } }\n")
        assertThat(engine().plan(unmanaged, false).hasChanges).isFalse()
        apply(unmanaged)
        assertThat(api.writes).isEmpty()
        assertThat(api.grantsOn("environment:$envId")).containsExactly("client:cli-ci manager")

        // A no-op resource with a NEW grant in the file ⇒ exactly one POST, no resource write.
        val extra = file(declared.substringBefore("  - kind: application").replace("- { subject: \"client:cli-ci\", relation: manager }", "- { subject: \"client:cli-ci\", relation: manager }\n              - { subject: \"member:bob\", relation: viewer }"))
        val plan = engine().plan(extra, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.NOOP)
        assertThat(plan.changes.single().grantAdds).containsExactly("member:bob viewer")
        assertThat(plan.hasChanges).isTrue()
        apply(extra)
        assertThat(writes()).containsExactly("POST /api/v1/access/grants")
        assertThat(api.grantsOn("environment:$envId")).containsExactlyInAnyOrder("client:cli-ci manager", "member:bob viewer")

        // SSO-3715 — `grants: []` declares none: without --prune every live grant is shown and stays; with --prune every
        // revocable one goes (a grant an admin made by hand included — the declaration is the file, the authority is the
        // owner), the exclusions aside.
        api.reset()
        api.seedGrant("client:outsider", "viewer", "environment:$envId")
        val none = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: environment, name: ci, spec: { slug: ci-sbx, displayName: \"CI sandbox\" }, grants: [] }\n")
        apply(none)
        assertThat(api.writes).isEmpty()
        assertThat(api.grantsOn("environment:$envId")).hasSize(3)
        apply(none, prune = true)
        assertThat(writes()).containsExactly("DELETE /api/v1/access/grants", "DELETE /api/v1/access/grants", "DELETE /api/v1/access/grants")
        assertThat(api.grantsOn("environment:$envId")).isEmpty()
    }

    @Test
    fun `a session without tenant access write fails closed with the scope named — after the resource itself exists`() {
        api.denyGrantWrites = true
        val f = file(declared.substringBefore("  - kind: application"))
        val e = engine()
        assertThatThrownBy { e.apply(f, e.plan(f, false), "acme", null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("tenant:access.write")
            .hasMessageContaining("thoryn login --scope tenant:access.write")
            .hasMessageContaining("environment/ci")
        // The environment was created (it is live — the platform is the ledger) before the grant step failed.
        assertThat(api.environments).hasSize(1)
        assertThat(api.grants).isEmpty()

        // Reading grants at plan time without tenant:access.read fails closed too.
        api.denyGrantWrites = false
        api.denyGrantReads = true
        assertThatThrownBy { engine().plan(f, false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("tenant:access.read")
    }

    /**
     * SSO-3119 — the regression the founder apply of `.thoryn/provision.yaml` hit live on 2026-09-16.
     * [ProvisionEngine.orderForApply] converges environments BEFORE applications whatever order the file
     * uses, so converging a `grants:` block the moment its own object resolved asked product-api to grant
     * to `client:cli-ci` before this same file had created it — an opaque 404 (ADR 2026-09-15 §8), and a
     * deadlock, since a re-run reaches the same grant before the same missing client.
     */
    @Test
    fun `a grant may name a client the same file declares later — every resource is created before any grant`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
                grants:
                  - { subject: "client:own-ci", relation: manager }
              - kind: application
                name: identity
                spec: { clientId: own-ci, displayName: "Own CI", clientType: confidential, grantTypes: [client_credentials] }
            """,
        )
        val receipt = apply(f)
        val envId = receipt.resources.first { it.key == "environment/ci" }.id
        assertThat(receipt.resources.first { it.key == "application/identity" }.id).isEqualTo("own-ci")
        assertThat(writes()).containsExactly(
            "POST /api/v1/environments", "POST /api/v1/applications", "POST /api/v1/access/grants",
        )
        assertThat(api.grantsOn("environment:$envId")).containsExactly("client:own-ci manager")

        // Converged: the next pass reads the grants and writes nothing.
        api.reset()
        assertThat(engine().plan(f, false).hasChanges).isFalse()
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `the access object ref derives from the live id per kind, singletons by their environment slug`() {
        assertThat(ProvisionEngine.objectRef("environment", "env-1", null)).isEqualTo("environment:env-1")
        assertThat(ProvisionEngine.objectRef("application", "app-1", "sbx")).isEqualTo("application:app-1")
        assertThat(ProvisionEngine.objectRef("user", "u-1", "sbx")).isEqualTo("user:u-1")
        assertThat(ProvisionEngine.objectRef("federationMember", "fm-1", "sbx")).isEqualTo("federation_member:fm-1")
        assertThat(ProvisionEngine.objectRef("emailProvider", "smtp", "sbx")).isEqualTo("email_provider:sbx")
        assertThat(ProvisionEngine.objectRef("loginTheme", "login-theme", "sbx")).isEqualTo("login_theme:sbx")
        assertThat(ProvisionEngine.objectRef("loginFlow", "3", "sbx")).isEqualTo("login_flow:sbx")
        assertThat(ProvisionEngine.objectRef("loginMethods", "login-methods", null)).isEqualTo("login_methods:production")
    }
}
