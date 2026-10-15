package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.Access
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3659 (ADR 2026-10-13 §2) — `thoryn provision import` is the inverse of `plan`, bounded by the same
 * relations: what the identity manages is rendered as an entry the file converges, what it may only view as
 * `readOnly: true`, and what it has no relation to is not listed by the platform and so cannot be imported.
 * SSO-3715 — `import` writes the file only. Engine-level through [ProvisionEngine.import]; end to end through
 * the CLI with `--write`, whose output must round-trip: the appended file plans as all no-ops.
 */
class ProvisionImportTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = "client:repo"
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedApplication("ci-sbx", "Loopback RP", listOf("http://127.0.0.1/callback"), clientId = "rp")
        api.applications.last()["clientType"] = "public"
        api.applications.last()["scopes"] = listOf("openid", "profile")
        api.users += mutableMapOf("id" to "u-9", "email" to "tester@example.com", "emailVerified" to true, "status" to "active", "_env" to "ci-sbx")
        api.loginMethods["ci-sbx"] = listOf("password", "passkey")
        api.seedApplication(null, "Shared Login", listOf("https://shared.example.com/cb"), clientId = "shared")
        api.seedApplication(null, "Foreign", listOf("https://foreign.example.com/cb"), clientId = "foreign")
        api.seedGrant("client:repo", "manager", "environment:$envId")
        api.seedGrant("client:repo", "viewer", "application:shared")
    }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = "client:repo",
    )

    @Test
    fun `import renders managed objects as entries, viewed ones as readOnly, and omits what the identity has no relation to`() {
        val result = engine().import(existing = null)
        assertThat(api.writes).isEmpty()
        val byKey = result.resources.associateBy { it.resource.key }
        assertThat(byKey.keys).containsExactlyInAnyOrder("environment/ci-sbx", "application/loopback-rp", "application/shared-login", "user/tester", "loginMethods/loginMethods")
        // Nothing names `foreign`: the platform never listed it, so it cannot be imported.
        assertThat(result.resources.map { it.liveId }).doesNotContain("foreign")

        val env = byKey.getValue("environment/ci-sbx")
        assertThat(env.access).isEqualTo(Access.MANAGER)
        assertThat(env.resource.spec).isEqualTo(mapOf("slug" to "ci-sbx", "displayName" to "CI sandbox"))
        assertThat(env.liveId).isEqualTo(envId)
        assertThat(env.resource.readOnly).isFalse()

        val rp = byKey.getValue("application/loopback-rp")
        assertThat(rp.access).isEqualTo(Access.MANAGER) // by containment: manager on the sandbox
        assertThat(rp.resource.readOnly).isFalse()
        assertThat(rp.resource.environment).isEqualTo("ci-sbx") // the env resource this same import adds, by NAME
        assertThat(rp.resource.spec).containsEntry("clientId", "rp").containsEntry("displayName", "Loopback RP").containsEntry("clientType", "public")
            .containsEntry("redirectUris", listOf("http://127.0.0.1/callback")).containsEntry("scopes", listOf("openid", "profile"))
        assertThat(rp.liveId).isEqualTo("rp")
        assertThat(rp.note).isNull() // public: no secret to warn about

        val shared = byKey.getValue("application/shared-login")
        assertThat(shared.access).isEqualTo(Access.VIEWER)
        assertThat(shared.resource.readOnly).isTrue()
        assertThat(shared.resource.environment).isNull() // production plane
        assertThat(shared.toEntry()).containsEntry("readOnly", true)
        assertThat(shared.note).isNull() // a reference is never written, so its secret is nobody's concern here

        assertThat(byKey.getValue("user/tester").resource.spec).isEqualTo(mapOf("email" to "tester@example.com", "emailVerified" to true))
        assertThat(byKey.getValue("loginMethods/loginMethods").resource.spec).isEqualTo(mapOf("methods" to listOf("password", "passkey")))
        assertThat(byKey.getValue("loginMethods/loginMethods").liveId).isEqualTo("login-methods")
        assertThat(result.skipped).isEmpty()
        // SSO-3715 — nothing is recorded by an import: the entries are the whole result.
        assertThat(result.resources.map { it.toStructured().keys }).allMatch { it.containsAll(setOf("kind", "spec", "id", "access")) && "owned" !in it }
    }

    @Test
    fun `import leaves out what the file already declares and renders an object the platform says another repository owns readOnly`() {
        val existing = ProvisionFile.parse(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, spec: { slug: ci-sbx } }
              - { kind: application, name: shared, readOnly: true, spec: { clientId: shared, displayName: "Shared Login" } }
            """.trimIndent().toByteArray(),
            "provision.yaml",
        )
        // SSO-3673 — `other-rp` sits in the sandbox this identity manages (so it is listed as `manager`), but the
        // platform's `owner` relation names another repository: imported as a reference, naming no subject.
        api.seedApplication("ci-sbx", "Other RP", listOf("http://127.0.0.1/other"), clientId = "other-rp")
        api.seedGrant("client:wi_other", "owner", "application:other-rp")
        val result = engine().import(existing)
        val byKey = result.resources.associateBy { it.resource.key }
        assertThat(byKey.keys).containsExactlyInAnyOrder("application/loopback-rp", "application/other-rp", "user/tester", "loginMethods/loginMethods")
        // The child names the ALREADY DECLARED environment resource, not the slug.
        assertThat(byKey.getValue("application/loopback-rp").resource.environment).isEqualTo("ci")
        val other = byKey.getValue("application/other-rp")
        assertThat(other.access).isEqualTo(Access.MANAGER)
        assertThat(other.resource.readOnly).isTrue()
        assertThat(other.note).contains("owned by another repository").doesNotContain("wi_other")
        assertThat(api.checksOn("application:other-rp")).containsExactly("owner")
        // An object nobody owns that this identity manages is imported as an entry the file converges.
        val tester = byKey.getValue("user/tester")
        assertThat(tester.resource.readOnly).isFalse()
        assertThat(byKey.getValue("application/loopback-rp").resource.readOnly).isFalse()
    }

    @Test
    fun `thoryn provision import prints without writing, and --write appends entries that round-trip to an all-noop plan`() {
        val dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        val file = File(dir, "provision.yaml").apply {
            writeText(
                """
                # a hand-written header comment survives --write
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: environment
                    name: ci
                    spec: { slug: ci-sbx, displayName: "CI sandbox" }
                """.trimIndent() + "\n",
            )
        }
        val receipt = File(dir, "provision.receipt.json")

        val dry = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl())
        assertThat(dry.exit).isEqualTo(0)
        assertThat(dry.out).contains("- kind: application").contains("clientId: rp").contains("readOnly: true").contains("clientId: shared").doesNotContain("foreign")
        assertThat(dry.err).contains("nothing was written").contains("--write")
        assertThat(file.readText()).doesNotContain("rp")
        assertThat(receipt).doesNotExist()
        assertThat(api.writes).isEmpty()

        val written = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl(), "--write")
        assertThat(written.exit).isEqualTo(0)
        assertThat(written.out).contains("Imported 4 entry(ies)").contains("3 to converge").contains("1 read-only").contains("Nothing else was written")
        val text = file.readText()
        assertThat(text).startsWith("# a hand-written header comment").contains("name: loopback-rp").contains("environment: ci").contains("readOnly: true")
        // SSO-3715 — the file is the only thing written: no receipt beside it.
        assertThat(receipt).doesNotExist()
        assertThat(api.writes).isEmpty()

        // The appended file describes exactly what is live: every imported entry is a no-op (the hand-written sandbox the
        // import left alone included), and a second import adds nothing.
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.err).isEmpty()
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove, 5 unchanged.")
        val again = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl(), "--write")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("Nothing to import")
        assertThat(file.readText()).isEqualTo(text)
    }

    @Test
    fun `import --write creates the file when none exists and refuses a file whose resources list is not last`() {
        val fresh = File(tempHome.toFile(), "fresh/provision.yaml")
        val created = runCli("provision", "import", "--file", fresh.path, "--gateway", baseUrl(), "--write")
        assertThat(created.exit).isEqualTo(0)
        assertThat(fresh.readText()).startsWith("apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: environment")
        assertThat(ProvisionFile.load(fresh).resources.map { it.key }).containsExactlyInAnyOrder(
            "environment/ci-sbx", "application/loopback-rp", "application/shared-login", "user/tester", "loginMethods/loginMethods",
        )

        val odd = File(tempHome.toFile(), "odd/provision.yaml").apply { parentFile.mkdirs(); writeText("resources:\n  - { kind: environment, name: ci, spec: { slug: ci-sbx } }\napiVersion: thoryn.io/provision/v1\n") }
        val before = odd.readText()
        val refused = runCli("provision", "import", "--file", odd.path, "--gateway", baseUrl(), "--write")
        assertThat(refused.exit).isNotEqualTo(0)
        assertThat(refused.err).contains("not the last top-level key")
        assertThat(odd.readText()).isEqualTo(before)
    }
}
