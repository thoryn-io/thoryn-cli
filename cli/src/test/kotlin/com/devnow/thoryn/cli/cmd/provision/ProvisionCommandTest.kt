package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3088 (epic SSO-3087) — `thoryn provision plan | apply | destroy` end to end through the CLI
 * against a MockWebServer standing in for the api-gateway → product-api surface.
 *
 * The load-bearing invariants: `plan` is read-only; `apply` creates environments first and targets
 * dependants at the created sandbox via `X-Thoryn-Environment`; a SECOND `apply` issues NO writes;
 * `destroy` removes child-first, confirms a sandbox hard-delete with its own slug, and REFUSES a
 * production-plane removal without `--confirm <workspace-slug>`; SSO-3715 — nothing is written next to
 * the file (no receipt), `--output json` carries the ids.
 */
class ProvisionCommandTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun paths() = api.writes.map { it.method + " " + it.path }

    private fun writeFile(name: String, body: String): File =
        File(tempHome.toFile(), ".thoryn/$name").also { it.parentFile.mkdirs(); it.writeText(body) }

    private val sandboxFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
          - kind: application
            name: rp
            environment: ci
            spec: { displayName: "RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
          - kind: user
            name: tester
            environment: ci
            spec: { email: tester@example.com, emailVerified: true }
    """.trimIndent()

    @Test
    fun `plan is read-only, apply creates env-first then converges, a second apply is a no-op, destroy removes child-first`() {
        val file = writeFile("provision.yaml", sandboxFile)
        val receipt = File(file.parentFile, "provision.receipt.json")

        // plan: three creates, only GET traffic (live read-by-key).
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("environment").contains("create").contains("3 to create, 0 to update, 0 to remove, 0 unchanged")
        assertThat(api.writes).isEmpty()
        assertThat(receipt).doesNotExist()

        // apply: env, then app + user INTO the created sandbox.
        val apply = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).isEmpty()
        assertThat(apply.exit).isEqualTo(0)
        assertThat(apply.out).contains("Applied. 3 resource(s) converged (3 created, 0 updated)")
        assertThat(paths()).containsExactly("POST /api/v1/environments", "POST /api/v1/applications", "POST /api/v1/users")
        assertThat(api.writes[0].env).isNull()
        assertThat(api.writes[0].body).containsEntry("slug", "ci-sbx").containsEntry("name", "CI sandbox")
        assertThat(api.writes[1].env).isEqualTo("ci-sbx")
        assertThat(api.writes[1].body).containsEntry("displayName", "RP")
        assertThat(api.writes[2].env).isEqualTo("ci-sbx")

        // SSO-3715 — nothing beside the file: the platform is the ledger.
        assertThat(receipt).doesNotExist()
        assertThat(file.parentFile.listFiles()!!.map { it.name }).containsExactly("provision.yaml")
        val ids = listOf(api.environments.single()["id"].toString(), api.applications.single()["clientId"].toString(), api.users.single()["id"].toString())
        // `--output json` is where a workflow reads the ids from: one document, `resources[]` with kind / name / id / environment / action.
        api.reset()
        val json = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes", "--output", "json")
        assertThat(json.exit).isEqualTo(0)
        val doc = tools.jackson.databind.json.JsonMapper.builder().build().readTree(json.out)
        val resources = doc["resources"].toList()
        assertThat(resources.map { it["kind"].asString() + "/" + it["name"].asString() }).containsExactly("environment/ci", "application/rp", "user/tester")
        assertThat(resources.map { it["id"].asString() }).isEqualTo(ids)
        assertThat(doc["resources"][0]["environment"].asString()).isEqualTo("ci-sbx")
        assertThat(doc["resources"][1]["environment"].asString()).isEqualTo("ci-sbx")
        assertThat(resources.map { it["action"].asString() }).allMatch { it == "noop" }
        assertThat(doc["summary"]["noop"].asInt()).isEqualTo(3)
        assertThat(api.writes).isEmpty()

        // second apply: everything owned and matching → no writes at all.
        api.reset()
        val again = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("0 to create, 0 to update, 0 to remove, 3 unchanged").contains("No changes.")
        assertThat(api.writes).isEmpty()

        // destroy (SSO-3715): the founder manages the client and the sandbox and nobody owns them ⇒ the app first, then
        // the sandbox confirmed with its OWN slug; the user goes WITH its sandbox (a skip row says so — the cascade).
        val destroy = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(destroy.err).isEmpty()
        assertThat(destroy.exit).isEqualTo(0)
        assertThat(destroy.out).contains("skip    removed with its sandbox 'ci-sbx'").contains("2 to remove, 1 left in place")
        assertThat(paths()).containsExactly("DELETE /api/v1/applications/${ids[1]}", "DELETE /api/v1/environments/${ids[0]}")
        assertThat(api.writes[0].env).isEqualTo("ci-sbx")
        assertThat(api.writes[1].confirm).isEqualTo("ci-sbx")
        assertThat(receipt).doesNotExist()
        assertThat(destroy.out).contains("Destroyed 2 resource(s). 1 left in place")
    }

    @Test
    fun `a production-plane removal is refused without --confirm and confirmed with the workspace slug`() {
        val file = writeFile(
            "provision.yaml",
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: web
                spec: { displayName: "Web app", redirectUris: ["https://app.example.com/cb"] }
            """.trimIndent(),
        )
        // `web` has no clientType ⇒ confidential (product-api's default) ⇒ a one-time secret is minted; deliver it to a file.
        val secretFile = File(tempHome.toFile(), "web.secret")
        val applied = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes", "--secret-file", secretFile.path)
        assertThat(applied.exit).isEqualTo(0)
        assertThat(api.writes.single().env).isNull()
        val id = api.applications.single()["clientId"]
        assertThat(secretFile.readText().trim()).isEqualTo(api.mintedSecrets[id])
        assertThat(applied.out).doesNotContain(api.mintedSecrets[id])
        api.reset()

        val refused = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(refused.exit).isNotEqualTo(0)
        assertThat(refused.err).contains("PRODUCTION plane").contains("--confirm <workspace-slug>")
        assertThat(api.writes).isEmpty() // nothing was deleted

        val ok = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes", "--confirm", "acme")
        assertThat(ok.exit).isEqualTo(0)
        assertThat(paths()).containsExactly("DELETE /api/v1/applications/$id")
        assertThat(api.writes.single().confirm).isEqualTo("acme")
    }

    @Test
    fun `a resource this identity OWNS and drops from the file is left alone until --prune removes it — the platform is the ledger`() {
        // SSO-3715 — a `client:` identity (a repository's wi_) that may create here: creator-becomes-owner makes it the owner.
        // The CLI derives the subject from the token (`client_id` with no distinct `sub`), exactly as product-api does.
        api.caller = "client:repo"
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        seedTokens(com.devnow.thoryn.cli.auth.Tokens(accessToken = enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString("""{"sub":"repo","client_id":"repo","tnt":"${api.tenantId}"}""".toByteArray()) + ".sig"))
        val file = writeFile("provision.yaml", sandboxFile)
        assertThat(runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes").exit).isEqualTo(0)
        val clientId = api.applications.single()["clientId"].toString()
        assertThat(api.ownerOf("application:$clientId")).isEqualTo("client:repo")
        api.reset()

        // Drop the client from the desired state: without --prune it is nowhere in the plan (no ledger of "declared once").
        file.writeText(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
              - kind: user
                name: tester
                environment: ci
                spec: { email: tester@example.com, emailVerified: true }
            """.trimIndent(),
        )
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).doesNotContain(clientId).contains("0 to remove")
        // With --prune: what the platform says this identity OWNS and the file does not declare is a removal.
        val prunePlan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl(), "--prune")
        assertThat(prunePlan.out).contains(clientId).contains("remove").contains("owned by this identity").contains("1 to remove")
        assertThat(api.writes).isEmpty()

        val pruned = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes", "--prune")
        assertThat(pruned.err).isEmpty()
        assertThat(pruned.exit).isEqualTo(0)
        assertThat(paths()).containsExactly("DELETE /api/v1/applications/$clientId")
        assertThat(api.applications).isEmpty()
        assertThat(File(file.parentFile, "provision.receipt.json")).doesNotExist()
    }

    @Test
    fun `apply delivers a minted client secret through --secret-file and exits EXIT_NO_SECRET when it cannot`() {
        // SSO-3113 — a confidential client_credentials application (a least-privilege CI identity).
        val file = writeFile(
            "provision.yaml",
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx }
              - kind: application
                name: ci-worker
                environment: ci
                spec: { displayName: "CI worker", clientType: confidential, grantTypes: [client_credentials] }
            """.trimIndent(),
        )
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.out).contains("(a client secret will be minted and shown once)")

        // No --secret-file and a non-TTY stdout ⇒ SecretIo refuses; the client is still created + owned; exit 65.
        val refused = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(refused.exit).isEqualTo(com.devnow.thoryn.cli.cmd.SecretIo.EXIT_NO_SECRET)
        val clientId = api.applications.single()["clientId"].toString()
        val secret = api.mintedSecrets.getValue(clientId)
        assertThat(refused.out).doesNotContain(secret)
        assertThat(refused.err).doesNotContain(secret).contains("thoryn clients rotate-secret $clientId")
        assertThat(api.applications.map { it["displayName"] }).containsExactly("CI worker")
        assertThat(File(file.parentFile, "provision.receipt.json")).doesNotExist()

        // A second confidential client, this time with --secret-file: delivered to the owner-only file, never stdout.
        file.appendText(
            "\n" + """
            - kind: application
              name: reporter
              environment: ci
              spec: { displayName: "Reporter", grantTypes: [client_credentials] }
            """.trimIndent().prependIndent("  ") + "\n",
        )
        val secretFile = File(tempHome.toFile(), "reporter.secret")
        val delivered = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes", "--secret-file", secretFile.path)
        assertThat(delivered.exit).isEqualTo(0)
        val reporterId = api.applications.last()["clientId"].toString()
        assertThat(secretFile.readText().trim()).isEqualTo(api.mintedSecrets.getValue(reporterId))
        assertThat(delivered.out).doesNotContain(api.mintedSecrets.getValue(reporterId)).contains("Applied. 3 resource(s) converged (1 created, 0 updated)")
        assertThat(delivered.err).contains("written to").doesNotContain(api.mintedSecrets.getValue(reporterId))
    }

    @Test
    fun `apply converges a resource's grants and plan lists the grant changes`() {
        // SSO-3119 — the fake resolves a `client:` subject before writing the tuple, as product-api does;
        // this file declares no client, so the grant's subject has to exist already.
        api.seedApplication(env = null, displayName = "CI identity", clientId = "cli-ci")
        val file = writeFile(
            "provision.yaml",
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx }
                grants:
                  - { subject: "client:cli-ci", relation: manager }
            """.trimIndent(),
        )
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("environment ci: grant + client:cli-ci manager").contains("1 grant change(s).")

        val apply = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).isEmpty()
        assertThat(apply.exit).isEqualTo(0)
        val envId = api.environments.single()["id"]
        assertThat(paths()).containsExactly("POST /api/v1/environments", "POST /api/v1/access/grants")
        assertThat(api.writes[1].body).isEqualTo(mapOf("subject" to "client:cli-ci", "relation" to "manager", "object" to "environment:$envId"))
        assertThat(apply.out).contains("+ grant environment ci: client:cli-ci manager on environment:$envId")

        // Converged: a second apply reads the grants and writes nothing.
        api.reset()
        val again = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("No changes.")
        assertThat(api.writes).isEmpty()

        // Without tenant:access.write the apply fails closed with the scope named (the sandbox stays).
        // Drop the grant out-of-band so the declared one is an ADD again.
        api.grants.removeIf { it["object"] == "environment:$envId" }
        api.denyGrantWrites = true
        val denied = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(denied.exit).isNotEqualTo(0)
        assertThat(denied.err).contains("tenant:access.write").contains("thoryn login --scope tenant:access.write")
    }

    @Test
    fun `a resource the identity may only view is a red plan — plan exits non-zero and apply refuses before any write`() {
        // SSO-3659 — the identity is not a workspace admin: it may view `shared` and manages nothing else.
        api.callerIsAdmin = false
        api.caller = "client:repo"
        api.seedApplication(null, "Shared", listOf("https://shared.example.com/cb"), clientId = "shared")
        api.seedGrant("client:repo", "viewer", "application:shared")
        val file = writeFile(
            "provision.yaml",
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: shared
                spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/cb"] }
            """.trimIndent(),
        )
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(com.devnow.thoryn.cli.cmd.CommandSupport.EXIT_HTTP_ERROR)
        assertThat(plan.out).contains("error").contains("1 ownership error(s).")
        assertThat(plan.err).contains("failed the ownership check").contains("access_read_only").contains("`readOnly: true`")
        val structured = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl(), "--output", "json")
        assertThat(structured.exit).isEqualTo(com.devnow.thoryn.cli.cmd.CommandSupport.EXIT_HTTP_ERROR)
        assertThat(structured.out).contains("\"error\" : \"access_read_only\"").contains("\"access\" : \"viewer\"")

        val apply = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).isEqualTo(com.devnow.thoryn.cli.cmd.CommandSupport.EXIT_HTTP_ERROR)
        assertThat(apply.err).contains("access_read_only").contains("Nothing was changed.")
        assertThat(api.writes).isEmpty()
        assertThat(File(file.parentFile, "provision.receipt.json")).doesNotExist()

        // Declared as the dependency it is, the same file is green and owns nothing.
        file.writeText(file.readText().replace("    name: shared\n", "    name: shared\n    readOnly: true\n"))
        val green = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(green.err).isEmpty()
        assertThat(green.exit).isEqualTo(0)
        assertThat(green.out).contains("read-only reference (viewer)").contains("No changes.")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an invalid file fails fast with the violations and touches nothing`() {
        val file = writeFile("provision.yaml", "apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: db, name: x, spec: {} }\n")
        val r = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(r.exit).isNotEqualTo(0)
        assertThat(r.err).contains("invalid provisioning file").contains("allowlist")
        assertThat(api.writes).isEmpty()
        assertThat(server.requestCount).isZero()
    }
}
