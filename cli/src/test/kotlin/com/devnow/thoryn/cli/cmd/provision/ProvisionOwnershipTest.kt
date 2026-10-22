package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionEngine
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
 * SSO-3659 (ADR 2026-10-13 §1) — ownership is decided by the signed-in identity's platform reach, asked PER
 * OBJECT through `POST /api/v1/access/check` (SSO-3673; ADR 2026-10-13 platform-owner-relation-and-forward-check)
 * before any write. The fixture identity `client:repo` is NOT a workspace admin: it manages ONE sandbox
 * (`environment:env-1`, and by containment the client inside it), may only view `application:shared`, and holds
 * nothing on `application:foreign`.
 *
 * The verdict table under test: `manager` ⇒ converge; `viewer` ⇒ only a matching `readOnly: true`
 * reference (any diff is `access_read_only`, declared without `readOnly` is `access_read_only` naming the
 * fix); none ⇒ `access_not_owned`; a create ⇒ `manager` on the parent (checked on the parent object), no grant
 * step; a resource the PLATFORM says another identity owns (its `owner` relation) ⇒ `access_owned_elsewhere`,
 * naming no subject. A plan with an error is refused WHOLE by `apply`. SSO-3715 — the owner the platform
 * reports rides on each plan row and on `apply --output json`; there is no receipt.
 */
class ProvisionOwnershipTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = "client:repo"
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedApplication("ci-sbx", "RP", listOf("http://127.0.0.1/old"), clientId = "rp")
        api.seedApplication(null, "Shared", listOf("https://shared.example.com/cb"), clientId = "shared")
        api.seedApplication(null, "Foreign", listOf("https://foreign.example.com/cb"), clientId = "foreign")
        api.seedGrant("client:repo", "manager", "environment:$envId")
        api.seedGrant("client:repo", "viewer", "application:shared")
    }

    private fun engine(subject: String = "client:repo") = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
        subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    private fun writes() = api.writes.map { it.method + " " + it.path }

    /** The managed sandbox, as the first resource of a file; a test appends its own entries (two-space indented) after it. */
    private val managedEnv = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
    """.trimIndent()

    @Test
    fun `a manager resource with a diff converges — the sandbox grant reaches the client inside it by containment`() {
        val f = file(
            managedEnv + "\n" + """
              - kind: application
                name: rp
                environment: ci
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
            """.trimIndent().prependIndent("  "),
        )
        val plan = engine().plan(f, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(plan.hasErrors).isFalse()
        assertThat(byKey.getValue("environment/ci").action).isEqualTo(ChangeAction.NOOP)
        assertThat(byKey.getValue("environment/ci").access).isEqualTo("manager")
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").access).isEqualTo("manager")
        assertThat(byKey.getValue("application/rp").diff.keys).containsExactly("redirectUris")

        val result = apply(f)
        assertThat(writes()).containsExactly("PATCH /api/v1/applications/rp")
        assertThat(result.resources.map { it.key to it.action }).containsExactly("environment/ci" to ChangeAction.NOOP, "application/rp" to ChangeAction.UPDATE)
        // The reach was read from the platform graph, workspace-level (no environment header), nothing else was written.
        assertThat(api.writes.map { it.path }).noneMatch { it.startsWith("/api/v1/access") }
        // SSO-3673 — asked PER OBJECT (`manager` on each live object), not per type: no `/access/mine` listing at all.
        assertThat(api.checksOn("environment:$envId")).startsWith("manager")
        assertThat(api.checksOn("application:rp")).startsWith("manager")
        assertThat(api.mineReads).isEmpty()
    }

    @Test
    fun `a viewer resource declared readOnly with a diff is a red plan and apply refuses before any write`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: shared
                readOnly: true
                spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/other"] }
            """,
        )
        val plan = engine().plan(f, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.readOnly).isTrue()
        assertThat(change.reason).contains("access_read_only").contains("redirectUris")
        assertThat(plan.hasErrors).isTrue()
        assertThat(plan.toStructured()["summary"]).isEqualTo(mapOf("create" to 0, "update" to 0, "remove" to 0, "noop" to 0, "skip" to 0, "grants" to 0, "error" to 1, "publish" to 0, "deliver" to 0, "pull" to 0))
        assertThat(change.toStructured()).containsEntry("error", "access_read_only").containsEntry("access", "viewer").containsEntry("readOnly", true)

        val e = engine()
        assertThatThrownBy { e.apply(f, plan, "acme", null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("nothing was written")
            .hasMessageContaining("application shared")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a viewer resource declared WITHOUT readOnly is red and names the fix`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: shared
                spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/cb"] }
            """,
        )
        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.readOnly).isFalse()
        assertThat(change.reason).contains("may only VIEW application:shared").contains("`readOnly: true`")
    }

    @Test
    fun `a viewer resource declared readOnly that matches is a no-op reference — never owned, never in the apply output`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: shared
                readOnly: true
                spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/cb"] }
            """,
        )
        val plan = engine().plan(f, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.readOnly).isTrue()
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.reason).contains("read-only reference (viewer)")
        assertThat(plan.hasChanges).isFalse()
        assertThat(plan.hasErrors).isFalse()

        val result = apply(f)
        assertThat(api.writes).isEmpty()
        assertThat(result.resources).isEmpty()
        assertThat(api.applications.map { it["clientId"] }).contains("shared")
        // SSO-3715 — and `destroy` never reaches for it: a reference is not this file's to remove.
        val destroy = engine().planDestroy(f).changes.single()
        assertThat(destroy.action).isEqualTo(ChangeAction.SKIP)
        assertThat(destroy.reason).contains("read-only reference")
    }

    @Test
    fun `a resource the identity has no relation to is access_not_owned — readOnly does not make it visible`() {
        val owned = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: foreign
                spec: { clientId: foreign, displayName: "Foreign", redirectUris: ["https://foreign.example.com/cb"] }
            """,
        )
        val change = engine().plan(owned, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(change.access).isEqualTo("none")
        assertThat(change.reason).contains("no relation on application:foreign").contains("thoryn access grant")

        val reference = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: foreign
                readOnly: true
                spec: { clientId: foreign, displayName: "Foreign", redirectUris: ["https://foreign.example.com/cb"] }
            """,
        )
        val ref = engine().plan(reference, false).changes.single()
        assertThat(ref.action).isEqualTo(ChangeAction.ERROR)
        assertThat(ref.error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(ref.readOnly).isTrue()
    }

    @Test
    fun `a create under a parent the identity manages succeeds with no grant step — creator-becomes-manager is the platform's`() {
        val f = file(
            managedEnv + "\n" + """
              - kind: user
                name: tester
                environment: ci
                spec: { email: tester@example.com, emailVerified: true }
            """.trimIndent().prependIndent("  "),
        )
        val plan = engine().plan(f, false)
        val user = plan.changes.single { it.kind == "user" }
        assertThat(user.action).isEqualTo(ChangeAction.CREATE)
        assertThat(user.access).isEqualTo("manager")
        assertThat(plan.hasErrors).isFalse()

        val result = apply(f)
        assertThat(writes()).containsExactly("POST /api/v1/users")
        assertThat(api.writes.single().env).isEqualTo("ci-sbx")
        assertThat(result.resources.map { it.key to it.action }).containsExactly("environment/ci" to ChangeAction.NOOP, "user/tester" to ChangeAction.CREATE)
        // SSO-3673 — the create was gated by a forward check on the PARENT object, not by a per-type listing.
        assertThat(api.checksOn("environment:$envId")).contains("manager")
        assertThat(api.mineReads).isEmpty()
    }

    @Test
    fun `a create whose parent the identity does not manage is access_not_owned — the production plane and a foreign sandbox alike`() {
        val otherEnv = api.seedEnvironment("other-sbx", "Someone else's sandbox")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: web
                spec: { displayName: "Web", clientType: public, redirectUris: ["https://web.example.com/cb"] }
              - kind: user
                name: intruder
                environment: other-sbx
                spec: { email: intruder@example.com }
              - kind: environment
                name: fresh
                spec: { slug: fresh-sbx }
            """,
        )
        val plan = engine().plan(f, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/web").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(byKey.getValue("application/web").reason).contains("workspace:${api.tenantId}")
        assertThat(byKey.getValue("user/intruder").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(byKey.getValue("user/intruder").reason).contains("environment:$otherEnv")
        assertThat(byKey.getValue("environment/fresh").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(plan.errors).hasSize(3)
        assertThatThrownBy { engine().apply(f, plan, "acme", null) }.hasMessageContaining("3 resource(s) failed the ownership check")
        assertThat(api.writes).isEmpty()
        // SSO-3673 — the production-plane and environment creates asked the platform about THE workspace object.
        assertThat(api.checksOn("workspace:${api.tenantId}")).contains("manager")
        assertThat(api.checksOn("environment:$otherEnv")).contains("manager")

        // The same file, as a workspace admin: every create is allowed (the parent of all three is the workspace / its sandbox).
        api.callerIsAdmin = true
        assertThat(engine().plan(f, false).hasErrors).isFalse()
    }

    @Test
    fun `a sandbox this file creates in the same apply covers its children — no separate parent check, no grant step`() {
        api.seedGrant("workspace:${api.tenantId}", "admin", "environment:ignored") // noise: an unrelated tuple
        api.grants += mutableMapOf("subject" to "client:repo", "relation" to "admin", "object" to "workspace:${api.tenantId}", "createdAt" to "2026-10-01T00:00:00Z")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: fresh
                spec: { slug: fresh-sbx }
              - kind: application
                name: rp2
                environment: fresh
                spec: { displayName: "RP2", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
            """,
        )
        val plan = engine().plan(f, false)
        assertThat(plan.hasErrors).isFalse()
        assertThat(plan.changes.map { it.action to it.access }).containsExactly(ChangeAction.CREATE to "manager", ChangeAction.CREATE to "manager")
        apply(f)
        assertThat(writes()).containsExactly("POST /api/v1/environments", "POST /api/v1/applications")
    }

    @Test
    fun `a resource the platform says another identity owns is access_owned_elsewhere without naming that owner — unless declared readOnly, and the owner itself converges`() {
        // SSO-3673 — the marker is the platform's `owner` relation, rendered on the application and re-checked per object.
        api.seedGrant("client:wi_other", "owner", "application:rp")
        val f = file(
            managedEnv + "\n" + """
              - kind: application
                name: rp
                environment: ci
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
            """.trimIndent().prependIndent("  "),
        )
        val refused = engine().plan(f, false).changes.single { it.kind == "application" }
        assertThat(refused.action).isEqualTo(ChangeAction.ERROR)
        assertThat(refused.error).isEqualTo(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(refused.access).isEqualTo("manager")
        assertThat(refused.owner).isEqualTo("client:wi_other")
        assertThat(refused.reason).contains("owned by another repository").contains("`readOnly: true`").contains("thoryn access grant <subject> owner application:rp")
        // No oracle: the plan's wording never echoes the other subject.
        assertThat(refused.reason).doesNotContain("wi_other")
        assertThat(api.checksOn("application:rp")).contains("owner")
        assertThatThrownBy { apply(f) }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("access_owned_elsewhere")
        assertThat(api.writes).isEmpty()

        // Declared readOnly and matching what is live ⇒ a reference, allowed next to the owning repository.
        val reference = file(
            managedEnv + "\n" + """
              - kind: application
                name: rp
                environment: ci
                readOnly: true
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/old"] }
            """.trimIndent().prependIndent("  "),
        )
        val ref = engine().plan(reference, false).changes.single { it.kind == "application" }
        assertThat(ref.action).isEqualTo(ChangeAction.NOOP)
        assertThat(ref.readOnly).isTrue()

        // The owner itself (`owner` implies `manager` on the model — it holds nothing else, not even on the sandbox)
        // converges the client it owns, and the apply output carries the owner.
        api.caller = "client:wi_other"
        val owner = engine(subject = "client:wi_other")
        val ownersFile = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: rp
                environment: ci-sbx
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
            """,
        )
        val ownerPlan = owner.plan(ownersFile, false)
        assertThat(ownerPlan.hasErrors).isFalse()
        val app = ownerPlan.changes.single { it.kind == "application" }
        assertThat(app.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(app.owner).isEqualTo("client:wi_other")
        // `manager` first (allowed through `owner`), then — because the live object has an owner — "is it me?": yes.
        assertThat(api.checksOn("application:rp").takeLast(2)).containsExactly("manager", "owner")
        val result = owner.apply(ownersFile, ownerPlan, "acme", null)
        assertThat(writes()).containsExactly("PATCH /api/v1/applications/rp")
        assertThat(result.resources.single { it.kind == "application" }.owner).isEqualTo("client:wi_other")
    }

    @Test
    fun `an unowned resource converges and the apply output carries the owner the platform reports — null, then the owner an admin sets, then the creator on a create`() {
        val f = file(
            managedEnv + "\n" + """
              - kind: application
                name: rp
                environment: ci
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
              - kind: application
                name: fresh
                environment: ci
                spec: { displayName: "Fresh", clientType: public, redirectUris: ["http://127.0.0.1/fresh"] }
            """.trimIndent().prependIndent("  "),
        )
        val first = apply(f)
        val byKey = first.resources.associateBy { it.key }
        // Nobody owns `rp` (a person created it): recorded as such; no owner check was needed for it.
        assertThat(byKey.getValue("application/rp").owner).isNull()
        assertThat(api.checksOn("application:rp")).doesNotContain("owner")
        // Creator-becomes-owner on the platform: the `client:` creator is the owner the create response reports.
        val freshId = byKey.getValue("application/fresh").id
        assertThat(byKey.getValue("application/fresh").owner).isEqualTo("client:repo")
        assertThat(api.ownerOf("application:$freshId")).isEqualTo("client:repo")

        // A workspace admin makes this repository the owner of `rp`: the next (no-op) apply records what the platform reports.
        api.seedGrant("client:repo", "owner", "application:rp")
        api.reset()
        val second = apply(f)
        assertThat(api.writes).isEmpty()
        assertThat(second.resources.single { it.key == "application/rp" }.owner).isEqualTo("client:repo")
        assertThat(second.resources.single { it.key == "application/rp" }.action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `a grants entry with relation owner is refused by the loader and names the fix — a repository cannot claim ownership by writing YAML`() {
        assertThatThrownBy {
            file(
                managedEnv.replace("spec: { slug: ci-sbx, displayName: \"CI sandbox\" }", "spec: { slug: ci-sbx }\n    grants: [ { subject: \"client:repo\", relation: owner } ]"),
            )
        }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("resources[0] grants[0]")
            .hasMessageContaining("relation 'owner'")
            .hasMessageContaining("cannot claim ownership by writing YAML")
            .hasMessageContaining("thoryn access grant <subject> owner <object>")
        assertThat(ProvisionFile.GRANT_RELATIONS).containsExactlyInAnyOrder("manager", "viewer")
    }

    @Test
    fun `a session that cannot check its own access fails closed naming tenant access read — before any resource is probed for writes`() {
        api.denyGrantReads = true
        assertThatThrownBy { engine().plan(file(managedEnv), false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("POST /api/v1/access/check")
            .hasMessageContaining("tenant:access.read")
            .hasMessageContaining("thoryn login --scope tenant:access.read")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `platform ids come back percent-encoded and are matched on their decoded form`() {
        assertThat(ProvisionEngine.decodePlatformId("application:ci%40builder".substringAfter(':'))).isEqualTo("ci@builder")
        assertThat(ProvisionEngine.decodePlatformId("plain-id")).isEqualTo("plain-id")
        assertThat(ProvisionEngine.decodePlatformId("bad%2")).isEqualTo("bad%2")
        assertThat(ProvisionEngine.slugName("Thoryn CLI (prod) ")).isEqualTo("thoryn-cli-prod")
    }
}
