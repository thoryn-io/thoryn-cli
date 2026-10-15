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

/**
 * SSO-3715 (ADR 2026-10-15 platform-is-the-ledger-no-committed-provisioning-receipt) — the control tests of the
 * ADR's decomposition, story 1. Each was watched FAILING against the reverted engine (the PR carries the table):
 *
 *  - `retain: true` survives `destroy` (shown as retained; the same resource without it is removed);
 *  - a `client:` identity's manager-not-owner resource survives (manager alone never suffices for automation), the
 *    owned one is deleted; an environment goes only when owned, after its children;
 *  - a `member:` destroy skips an owned resource ("change its file") and removes what it manages and nobody owns;
 *  - non-ownable kinds go WITH their sandbox and never on the production plane (reported with the command);
 *  - two same-name applications are the red row `converge_key_ambiguous`, never a create;
 *  - an undeclared grant is shown, revoked only with `--prune` on an object the caller may delete, and never the
 *    `owner` tuple, a workspace userset or the caller itself;
 *  - `apply` / `plan --output json` carry `{kind, name, id, environment, action}`; nothing is written beside the file.
 */
class ProvisionPlatformIsLedgerTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = "client:repo"
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedGrant("client:repo", "manager", "environment:$envId") // a founder made the repository MANAGER of the sandbox — not owner
        api.seedApplication("ci-sbx", "RP", listOf("http://127.0.0.1/old"), clientId = "rp")
        api.seedGrant("client:repo", "owner", "application:rp")         // creator-becomes-owner: the repository OWNS the client it created
        api.seedApplication("ci-sbx", "Shared", clientId = "shared")   // a founder's client inside the sandbox: nobody owns it
        api.users += mutableMapOf("id" to "u-1", "email" to "tester@example.com", "emailVerified" to true, "status" to "active", "_env" to "ci-sbx")
    }

    private fun engine(subject: String? = "client:repo") = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
        subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun deletes() = api.writes.filter { it.method == "DELETE" }.map { it.path }

    private val sandboxFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
          - kind: application
            name: rp
            environment: ci
            spec: { clientId: rp, displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
          - kind: application
            name: shared
            environment: ci
            spec: { clientId: shared, displayName: "Shared", redirectUris: ["http://127.0.0.1/callback"] }
          - kind: user
            name: tester
            environment: ci
            spec: { email: tester@example.com, emailVerified: true }
    """

    @Test
    fun `a client identity removes only what it OWNS — manager alone never lets automation delete, the environment goes only when owned and after its children`() {
        val f = file(sandboxFile)
        val plan = engine().planDestroy(f)
        val byKey = plan.changes.associateBy { it.key }
        // Owned ⇒ removed.
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.REMOVE)
        // Nobody owns it and this identity is a manager by containment: refused, with the right and the person's command.
        val shared = byKey.getValue("application/shared")
        assertThat(shared.action).isEqualTo(ChangeAction.SKIP)
        assertThat(shared.reason).contains("not OWNED by this identity").contains("`manager` alone never lets automation delete").contains("thoryn access grant client:repo owner application:shared")
        assertThat(shared.byHand).isEqualTo("thoryn clients delete shared --environment ci-sbx")
        // The sandbox: manager by a founder's grant, owner null ⇒ stays (exactly `environment/ci` of thoryn-cli's own file).
        val env = byKey.getValue("environment/ci")
        assertThat(env.action).isEqualTo(ChangeAction.SKIP)
        assertThat(env.reason).contains("environment:$envId is not OWNED by this identity")
        assertThat(env.byHand).isEqualTo("thoryn env delete $envId --confirm ci-sbx")
        // A non-ownable kind is removed with its sandbox only — and the sandbox stays.
        val user = byKey.getValue("user/tester")
        assertThat(user.action).isEqualTo(ChangeAction.SKIP)
        assertThat(user.reason).contains("removed only with its sandbox 'ci-sbx', which stays")
        assertThat(user.byHand).contains("thoryn users suspend u-1 --environment ci-sbx")
        assertThat(plan.removes.map { it.key }).containsExactly("application/rp")

        val outcome = engine().destroy(plan, null) // a sandbox removal needs no workspace confirmation
        assertThat(outcome.failures).isEmpty()
        assertThat(deletes()).containsExactly("/api/v1/applications/rp")
        assertThat(api.writes.single().env).isEqualTo("ci-sbx")
        assertThat(api.environments).hasSize(1)
        assertThat(api.applications.map { it["clientId"] }).containsExactly("shared")

        // A workspace admin hands the sandbox to the repository (`owner`): now it is the repository's to remove — after its
        // children — and the user inside goes with it (the hard-delete cascades; no call of its own).
        api.seedGrant("client:repo", "owner", "environment:$envId")
        api.reset()
        val owned = engine().planDestroy(f)
        assertThat(owned.changes.map { it.key to it.action }).containsExactly(
            "user/tester" to ChangeAction.SKIP, "application/shared" to ChangeAction.SKIP, "application/rp" to ChangeAction.SKIP, "environment/ci" to ChangeAction.REMOVE,
        )
        assertThat(owned.changes.single { it.kind == "user" }.reason).isEqualTo("removed with its sandbox 'ci-sbx' (the environment hard-delete cascades; no call of its own)")
        assertThat(owned.changes.single { it.name == "rp" }.reason).contains("not found by its converge key")
        engine().destroy(owned, null)
        assertThat(deletes()).containsExactly("/api/v1/environments/$envId")
        assertThat(api.writes.single().confirm).isEqualTo("ci-sbx")
        assertThat(api.environments).isEmpty()
    }

    @Test
    fun `retain true keeps an owned resource through destroy and --prune — shown as retained, with the same resource removed without it`() {
        val retained = file(sandboxFile.replace("spec: { clientId: rp,", "retain: true\n            spec: { clientId: rp,"))
        assertThat(retained.resources.single { it.name == "rp" }.retain).isTrue()
        // Converged like any other owned resource …
        val plan = engine().plan(retained, false)
        val row = plan.changes.single { it.name == "rp" }
        assertThat(row.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.retain).isTrue()
        assertThat(row.toStructured()).containsEntry("retain", true)
        // … never removed by destroy: a skip row that says so, and no delete.
        val destroy = engine().planDestroy(retained)
        val kept = destroy.changes.single { it.name == "rp" }
        assertThat(kept.action).isEqualTo(ChangeAction.SKIP)
        assertThat(kept.reason).isEqualTo(ProvisionEngine.RETAINED)
        assertThat(kept.byHand).isNull()
        assertThat(destroy.removes).isEmpty()
        engine().destroy(destroy, null)
        assertThat(deletes()).isEmpty()
        assertThat(api.applications.map { it["clientId"] }).contains("rp")
        // The same file without `retain` removes it (the control).
        assertThat(engine().planDestroy(file(sandboxFile)).removes.map { it.key }).containsExactly("application/rp")
        // `retain` is refused on a read-only reference (never removed anyway), and must be a boolean.
        assertThatThrownBy { file(sandboxFile.replace("spec: { clientId: shared,", "readOnly: true\n            retain: true\n            spec: { clientId: shared,")) }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("read-only reference cannot carry 'retain'")
        assertThatThrownBy { file(sandboxFile.replace("spec: { clientId: rp,", "retain: keep\n            spec: { clientId: rp,")) }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("retain must be true or false")
    }

    @Test
    fun `a person's destroy removes what they manage and nobody owns, and leaves an owned resource to its repository`() {
        api.caller = "member:founder"
        api.seedGrant("member:founder", "manager", "environment:$envId")
        val plan = engine(subject = "member:founder").planDestroy(file(sandboxFile))
        val byKey = plan.changes.associateBy { it.key }
        // Owned by a repository ⇒ a person's destroy leaves it, naming the fix (the FILE of that repository).
        val owned = byKey.getValue("application/rp")
        assertThat(owned.action).isEqualTo(ChangeAction.SKIP)
        assertThat(owned.reason).contains("application:rp is owned by a repository").contains("change its file")
        assertThat(owned.byHand).isEqualTo("thoryn clients delete rp --environment ci-sbx")
        // Unowned and managed ⇒ removed; the sandbox too (manager, nobody owns it), after its children.
        assertThat(byKey.getValue("application/shared").action).isEqualTo(ChangeAction.REMOVE)
        assertThat(byKey.getValue("environment/ci").action).isEqualTo(ChangeAction.REMOVE)
        assertThat(byKey.getValue("user/tester").reason).contains("removed with its sandbox 'ci-sbx'")
        assertThat(plan.removes.map { it.key }).containsExactly("application/shared", "environment/ci")
        engine(subject = "member:founder").destroy(plan, null)
        assertThat(deletes()).containsExactly("/api/v1/applications/shared", "/api/v1/environments/$envId")
        assertThat(api.applications.map { it["clientId"] }).containsExactly("rp")
    }

    @Test
    fun `a production-plane singleton and user are never removed by destroy — reported with the explicit command`() {
        api.callerIsAdmin = true
        api.caller = "member:founder"
        api.loginMethods[null] = listOf("password")
        api.users += mutableMapOf("id" to "u-9", "email" to "ops@example.com", "status" to "active", "_env" to null)
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: loginMethods
                spec: { methods: [password] }
              - kind: user
                name: ops
                spec: { email: ops@example.com }
            """,
        )
        val plan = engine(subject = "member:founder").planDestroy(f)
        assertThat(plan.changes.map { it.action }).allMatch { it == ChangeAction.SKIP }
        val methods = plan.changes.single { it.kind == "loginMethods" }
        assertThat(methods.reason).contains("a loginMethods on the PRODUCTION plane is never removed by destroy / --prune")
        assertThat(methods.byHand).isEqualTo("thoryn login-methods reset")
        assertThat(plan.changes.single { it.kind == "user" }.byHand).contains("thoryn users suspend u-9 --confirm <workspace-slug>")
        engine(subject = "member:founder").destroy(plan, "acme")
        assertThat(api.writes).isEmpty()
        assertThat(api.loginMethods[null]).isEqualTo(listOf("password"))
    }

    @Test
    fun `two live applications matching one display name are the red row converge_key_ambiguous — never a third copy — and clientId resolves it`() {
        api.callerIsAdmin = true
        api.seedApplication(null, "Web", clientId = "web-1")
        api.seedApplication(null, "Web", clientId = "web-2")
        val ambiguous = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: web
                spec: { displayName: "Web", clientType: public, redirectUris: ["https://web.example.com/cb"] }
            """,
        )
        val plan = engine().plan(ambiguous, false)
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_CONVERGE_KEY_AMBIGUOUS)
        assertThat(row.reason).contains("converge_key_ambiguous").contains("2 live resources match displayName 'Web'").contains("declare `clientId`")
        assertThat(row.fixNote).isEqualTo(ProvisionEngine.FILE_FIX_NOTE_AMBIGUOUS)
        assertThat(plan.hasErrors).isTrue()
        assertThatThrownBy { engine().apply(ambiguous, plan, "acme", null) }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("converge_key_ambiguous")
        assertThat(api.writes).isEmpty()
        assertThat(api.applications.count { it["displayName"] == "Web" }).isEqualTo(2)

        // The fix is in the file: a declared `clientId` names exactly one.
        val pinned = file(ambiguous.resources.single().let { "apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: application, name: web, spec: { clientId: web-2, displayName: \"Web\", clientType: public, redirectUris: [\"https://web.example.com/cb\"] } }\n" })
        val resolved = engine().plan(pinned, false).changes.single()
        assertThat(resolved.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(resolved.liveId).isEqualTo("web-2")
    }

    @Test
    fun `an undeclared grant is shown, revoked only by --prune on an object the caller may delete, and never the owner tuple, a workspace userset or the caller itself`() {
        api.seedGrant("workspace:${api.tenantId}#admin", "manager", "application:rp")
        api.seedGrant("client:repo", "manager", "application:rp")      // the caller's own (redundant next to owner, but a person could have granted it)
        api.seedGrant("member:alice", "viewer", "application:rp")
        api.seedGrant("client:other", "manager", "application:rp")
        api.seedGrant("member:alice", "viewer", "environment:$envId")
        val f = file(
            sandboxFile.replace("spec: { slug: ci-sbx, displayName: \"CI sandbox\" }", "spec: { slug: ci-sbx, displayName: \"CI sandbox\" }\n            grants: []")
                .replace("spec: { clientId: rp, displayName: \"RP\", redirectUris: [\"http://127.0.0.1/callback\"] }", "spec: { clientId: rp, displayName: \"RP\", redirectUris: [\"http://127.0.0.1/callback\"] }\n            grants: []"),
        )
        // Without --prune: present, not declared — informational, never red, nothing revoked.
        val shown = engine().plan(f, false)
        assertThat(shown.hasErrors).isFalse()
        val rp = shown.changes.single { it.name == "rp" }
        assertThat(rp.grantRemoves).isEmpty()
        assertThat(rp.grantUndeclared).containsExactlyInAnyOrder("client:repo owner", "workspace:t-1#admin manager", "client:repo manager", "member:alice viewer", "client:other manager")
        assertThat(rp.reason).contains("5 grant(s) present, not declared")
        engine().apply(f, shown, "acme", null)
        assertThat(api.writes.map { it.method }).doesNotContain("DELETE")

        // With --prune: on the OWNED client the undeclared grants go — except the owner tuple, the workspace userset and the
        // caller's own subject; on the sandbox (manager, not owner) nothing goes, and the row says why.
        val prune = engine().plan(f, true)
        val pruned = prune.changes.single { it.name == "rp" }
        assertThat(pruned.grantRemoves).containsExactlyInAnyOrder("member:alice viewer", "client:other manager")
        assertThat(pruned.grantUndeclared).containsExactlyInAnyOrder("client:repo owner", "workspace:t-1#admin manager", "client:repo manager")
        val env = prune.changes.single { it.kind == "environment" }
        assertThat(env.grantRemoves).isEmpty()
        assertThat(env.grantUndeclared).contains("member:alice viewer")
        assertThat(env.reason).contains("kept: this identity may not delete the object")
        engine().apply(f, prune, "acme", null)
        assertThat(api.writes.filter { it.method == "DELETE" }.map { it.body }).containsExactlyInAnyOrder(
            mapOf("subject" to "member:alice", "relation" to "viewer", "object" to "application:rp"),
            mapOf("subject" to "client:other", "relation" to "manager", "object" to "application:rp"),
        )
        assertThat(api.grantsOn("application:rp")).containsExactlyInAnyOrder("client:repo owner", "workspace:t-1#admin manager", "client:repo manager")
        assertThat(api.grantsOn("environment:$envId")).contains("member:alice viewer")
    }

    @Test
    fun `apply and plan carry the resolved ids per declared resource — the output a workflow reads instead of a receipt`() {
        val f = file(sandboxFile)
        val e = engine()
        val plan = e.plan(f, false)
        @Suppress("UNCHECKED_CAST")
        val planned = plan.toStructured()["resources"] as List<Map<String, Any?>>
        assertThat(planned.map { it["kind"] to it["name"] }).containsExactly("environment" to "ci", "application" to "rp", "application" to "shared", "user" to "tester")
        assertThat(planned[0]).containsEntry("id", envId).containsEntry("environment", "ci-sbx").containsEntry("action", "noop")
        assertThat(planned[1]).containsEntry("id", "rp").containsEntry("environment", "ci-sbx").containsEntry("action", "update").containsEntry("owner", "client:repo")
        val result = e.apply(f, plan, "acme", null)
        @Suppress("UNCHECKED_CAST")
        val applied = result.toStructured()["resources"] as List<Map<String, Any?>>
        assertThat(applied.map { it.keys }).allMatch { it.containsAll(setOf("kind", "name", "id", "environment", "action")) }
        assertThat(applied.map { it["id"] }).containsExactly(envId, "rp", "shared", "u-1")
        assertThat(applied.map { it["action"] }).containsExactly("noop", "update", "noop", "noop")
        assertThat(result.toStructured()["summary"]).isEqualTo(mapOf("create" to 0, "update" to 1, "noop" to 3))
    }

    @Test
    fun `nothing is written beside the file — no receipt type, no receipt path, no file write in the engine or the provision command`() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "engine/src/main/kotlin").isDirectory }
        val engineSources = File(root, "engine/src/main/kotlin").walk().filter { it.extension == "kt" }.toList()
        val commandSources = File(root, "cli/src/main/kotlin/com/devnow/thoryn/cli/cmd/provision").walk().filter { it.extension == "kt" }.toList()
        val stateStore = File(root, "cli/src/main/kotlin/com/devnow/thoryn/cli/cmd/examples/ExampleStateStore.kt")
        assertThat(engineSources).isNotEmpty
        assertThat(engineSources.map { it.name }).doesNotContain("ProvisionReceipt.kt")
        (engineSources + commandSources + stateStore).forEach { source ->
            val text = source.readText()
            assertThat(text).`as`(source.path).doesNotContain("ProvisionReceipt").doesNotContain(".receipt.json").doesNotContain("provisionReceiptPath")
        }
        // The converge engine and the file model read files (the provisioning file) and never write one. (`FixRequest` writes
        // the SSO-3710 fix request a red plan asks for — a different file, by the caller's explicit `--fix-request`.)
        engineSources.filter { it.name in setOf("ProvisionEngine.kt", "ProvisionFile.kt", "ProvisionApi.kt", "AccessRefs.kt", "CustomDomain.kt") }.forEach { source ->
            assertThat(source.readText()).`as`(source.path).doesNotContain("Files.write").doesNotContain("writeText").doesNotContain("FileOutputStream").doesNotContain("StandardOpenOption")
        }
        // The native-image reflection config that served the receipt's Jackson round-trip is gone with it.
        assertThat(File(root, "engine/src/main/resources/META-INF/native-image/io.thoryn/thoryn-provision-engine/reflect-config.json")).doesNotExist()
    }
}
