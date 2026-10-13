package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.OwnedResource
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFileRef
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionReceipt
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
 * SSO-3659 (ADR 2026-10-13 §1) — ownership is decided by the signed-in identity's platform reach, read from
 * `GET /api/v1/access/mine` (the platform graph's list-objects) before any write. The fixture identity
 * `client:repo` is NOT a workspace admin: it manages ONE sandbox (`environment:env-1`, and by containment the
 * client inside it), may only view `application:shared`, and holds nothing on `application:foreign`.
 *
 * The verdict table under test: `manager` ⇒ converge; `viewer` ⇒ only a matching `readOnly: true`
 * reference (any diff is `access_read_only`, declared without `readOnly` is `access_read_only` naming the
 * fix); none ⇒ `access_not_owned`; a create ⇒ `manager` on the parent, no grant step; a resource another
 * repository's receipt owns ⇒ `access_owned_elsewhere`. A plan with an error is refused WHOLE by `apply`.
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

    private fun engine(peers: List<ProvisionReceipt> = emptyList()) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
        subject = "client:repo",
        peers = peers,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?, peers: List<ProvisionReceipt> = emptyList(), persist: (ProvisionReceipt) -> Unit = {}): ProvisionReceipt {
        val e = engine(peers)
        return e.apply(f, receipt, e.plan(f, receipt, false), "acme", null, persist)
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
        val plan = engine().plan(f, null, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(plan.hasErrors).isFalse()
        assertThat(byKey.getValue("environment/ci").action).isEqualTo(ChangeAction.ADOPT)
        assertThat(byKey.getValue("environment/ci").access).isEqualTo("manager")
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").access).isEqualTo("manager")
        assertThat(byKey.getValue("application/rp").diff.keys).containsExactly("redirectUris")

        val receipt = apply(f, null)
        assertThat(writes()).containsExactly("PATCH /api/v1/applications/rp")
        assertThat(receipt.subject).isEqualTo("client:repo")
        assertThat(receipt.resources.map { it.key }).containsExactly("environment/ci", "application/rp")
        // The reach was read from the platform graph, workspace-level (no environment header), nothing else was written.
        assertThat(api.writes.map { it.path }).noneMatch { it.startsWith("/api/v1/access") }
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
        val plan = engine().plan(f, null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.readOnly).isTrue()
        assertThat(change.reason).contains("access_read_only").contains("redirectUris")
        assertThat(plan.hasErrors).isTrue()
        assertThat(plan.toStructured()["summary"]).isEqualTo(mapOf("create" to 0, "update" to 0, "adopt" to 0, "remove" to 0, "noop" to 0, "skip" to 0, "grants" to 0, "error" to 1))
        assertThat(change.toStructured()).containsEntry("error", "access_read_only").containsEntry("access", "viewer").containsEntry("readOnly", true)

        val persisted = mutableListOf<ProvisionReceipt>()
        val e = engine()
        assertThatThrownBy { e.apply(f, null, plan, "acme", null) { persisted += it } }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("nothing was written")
            .hasMessageContaining("application shared")
        assertThat(api.writes).isEmpty()
        assertThat(persisted).isEmpty()
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
        val change = engine().plan(f, null, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.readOnly).isFalse()
        assertThat(change.reason).contains("may only VIEW application:shared").contains("`readOnly: true`")
    }

    @Test
    fun `a viewer resource declared readOnly that matches is a no-op reference — never owned, and a stale receipt entry is dropped without a delete`() {
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
        val plan = engine().plan(f, null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.readOnly).isTrue()
        assertThat(change.access).isEqualTo("viewer")
        assertThat(change.adopted).isFalse()
        assertThat(change.reason).contains("read-only reference (viewer)")
        assertThat(plan.hasChanges).isFalse()
        assertThat(plan.hasErrors).isFalse()

        val receipt = apply(f, null)
        assertThat(api.writes).isEmpty()
        assertThat(receipt.resources).isEmpty()

        // A receipt from before the file said `readOnly` still owns it: the entry is disowned, the client stays.
        val stale = ProvisionReceipt(
            file = ProvisionFileRef("provision.yaml", "sha256:old"), appliedAt = "2026-10-01T00:00:00Z", subject = "client:repo",
            resources = listOf(OwnedResource("application", "shared", "shared", null)),
        )
        val after = apply(f, stale)
        assertThat(api.writes).isEmpty()
        assertThat(after.resources).isEmpty()
        assertThat(api.applications.map { it["clientId"] }).contains("shared")
        assertThat(console.toString()).contains("dropped from the receipt")
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
        val change = engine().plan(owned, null, false).changes.single()
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
        val ref = engine().plan(reference, null, false).changes.single()
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
        val plan = engine().plan(f, null, false)
        val user = plan.changes.single { it.kind == "user" }
        assertThat(user.action).isEqualTo(ChangeAction.CREATE)
        assertThat(user.access).isEqualTo("manager")
        assertThat(plan.hasErrors).isFalse()

        val receipt = apply(f, null)
        assertThat(writes()).containsExactly("POST /api/v1/users")
        assertThat(api.writes.single().env).isEqualTo("ci-sbx")
        assertThat(receipt.resources.map { it.key to it.adopted }).containsExactly("environment/ci" to true, "user/tester" to false)
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
        val plan = engine().plan(f, null, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/web").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(byKey.getValue("application/web").reason).contains("workspace:${api.tenantId}")
        assertThat(byKey.getValue("user/intruder").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(byKey.getValue("user/intruder").reason).contains("environment:$otherEnv")
        assertThat(byKey.getValue("environment/fresh").error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(plan.errors).hasSize(3)
        assertThatThrownBy { engine().apply(f, null, plan, "acme", null) {} }.hasMessageContaining("3 resource(s) failed the ownership check")
        assertThat(api.writes).isEmpty()

        // The same file, as a workspace admin: every create is allowed (the parent of all three is the workspace / its sandbox).
        api.callerIsAdmin = true
        assertThat(engine().plan(f, null, false).hasErrors).isFalse()
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
        val plan = engine().plan(f, null, false)
        assertThat(plan.hasErrors).isFalse()
        assertThat(plan.changes.map { it.action to it.access }).containsExactly(ChangeAction.CREATE to "manager", ChangeAction.CREATE to "manager")
        apply(f, null)
        assertThat(writes()).containsExactly("POST /api/v1/environments", "POST /api/v1/applications")
    }

    @Test
    fun `a resource another repository's receipt owns is refused unless declared readOnly — and the same identity's own receipt is not a peer`() {
        val other = ProvisionReceipt(
            file = ProvisionFileRef("thoryn-cicd/.thoryn/provision.yaml", "sha256:x"), appliedAt = "2026-10-09T00:00:00Z", subject = "client:wi_other",
            resources = listOf(OwnedResource("application", "login", "rp", "ci-sbx")),
        )
        val f = file(
            managedEnv + "\n" + """
              - kind: application
                name: rp
                environment: ci
                spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
            """.trimIndent().prependIndent("  "),
        )
        val refused = engine(peers = listOf(other)).plan(f, null, false).changes.single { it.kind == "application" }
        assertThat(refused.action).isEqualTo(ChangeAction.ERROR)
        assertThat(refused.error).isEqualTo(ProvisionEngine.ERROR_OWNED_ELSEWHERE)
        assertThat(refused.access).isEqualTo("manager")
        assertThat(refused.reason).contains("thoryn-cicd/.thoryn/provision.yaml (client:wi_other)").contains("`readOnly: true`")
        assertThatThrownBy { apply(f, null, peers = listOf(other)) }.isInstanceOf(ProvisionException::class.java)
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
        val ref = engine(peers = listOf(other)).plan(reference, null, false).changes.single { it.kind == "application" }
        assertThat(ref.action).isEqualTo(ChangeAction.NOOP)
        assertThat(ref.readOnly).isTrue()

        // A peer receipt applied by THIS identity is the same repository's earlier state, not another owner.
        val mine = other.copy(subject = "client:repo")
        assertThat(engine(peers = listOf(mine)).plan(f, null, false).hasErrors).isFalse()
        // Without any peer the guard has nothing to compare against — the documented limit of a receipt-based marker.
        assertThat(engine().plan(f, null, false).hasErrors).isFalse()
    }

    @Test
    fun `a session that cannot read its own reach fails closed naming tenant access read — before any resource is probed for writes`() {
        api.denyGrantReads = true
        assertThatThrownBy { engine().plan(file(managedEnv), null, false) }
            .isInstanceOf(ProvisionException::class.java)
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
