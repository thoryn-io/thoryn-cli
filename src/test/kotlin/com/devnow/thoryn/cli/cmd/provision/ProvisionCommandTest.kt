package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3088 (epic SSO-3087) — `thoryn provision plan | apply | destroy` end to end through the CLI
 * against a MockWebServer standing in for the api-gateway → product-api surface.
 *
 * The load-bearing invariants: `plan` is read-only; `apply` creates environments first and targets
 * dependants at the created sandbox via `X-Thoryn-Environment`; a SECOND `apply` issues NO writes;
 * `destroy` removes child-first, confirms a sandbox hard-delete with its own slug, and REFUSES a
 * production-plane removal without `--confirm <workspace-slug>`; the receipt lives next to the file
 * and is removed once nothing is owned.
 */
class ProvisionCommandTest : CommandTestBase() {

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

        // plan: three creates, no HTTP traffic, no session needed.
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("environment").contains("create").contains("3 to create, 0 to remove, 0 unchanged")
        assertThat(server.requestCount).isZero()
        assertThat(receipt).doesNotExist()

        // apply: env, then app + user INTO the created sandbox.
        server.enqueue(jsonResponse(201, """{"id":"env-1","slug":"ci-sbx","kind":"sandbox"}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-1","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"u-1","email":"tester@example.com"}"""))
        val apply = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).isEmpty()
        assertThat(apply.exit).isEqualTo(0)
        assertThat(apply.out).contains("Applied. 3 resource(s) owned.")

        val envReq = server.takeRequest()
        assertThat(envReq.method).isEqualTo("POST")
        assertThat(envReq.path).isEqualTo("/api/v1/environments")
        assertThat(envReq.getHeader("X-Thoryn-Environment")).isNull()
        assertThat(envReq.body.readUtf8()).contains("\"slug\":\"ci-sbx\"").contains("\"name\":\"CI sandbox\"")
        val appReq = server.takeRequest()
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.getHeader("X-Thoryn-Environment")).isEqualTo("ci-sbx")
        assertThat(appReq.body.readUtf8()).contains("\"displayName\":\"RP\"")
        val userReq = server.takeRequest()
        assertThat(userReq.path).isEqualTo("/api/v1/users")
        assertThat(userReq.getHeader("X-Thoryn-Environment")).isEqualTo("ci-sbx")

        // The receipt sits next to the file, records ids + env slugs, and is the ownership ledger.
        assertThat(receipt).exists()
        val recorded = ProvisionReceiptStore().read(receipt)!!
        assertThat(recorded.file.digest).startsWith("sha256:")
        assertThat(recorded.resources.map { it.key to it.id }).containsExactly(
            "environment/ci" to "env-1", "application/rp" to "app-1", "user/tester" to "u-1",
        )
        assertThat(recorded.resources[0].attributes["slug"]).isEqualTo("ci-sbx")
        assertThat(recorded.resources[1].environment).isEqualTo("ci-sbx")

        // second apply: everything owned → no writes at all.
        val before = server.requestCount
        val again = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("0 to create, 0 to remove, 3 unchanged").contains("No changes.")
        assertThat(server.requestCount).isEqualTo(before)

        // destroy: user + app first (reverse), then the sandbox, confirmed with its OWN slug.
        server.enqueue(jsonResponse(200, "{}"))
        server.enqueue(jsonResponse(204, ""))
        server.enqueue(jsonResponse(204, ""))
        val destroy = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(destroy.err).isEmpty()
        assertThat(destroy.exit).isEqualTo(0)
        val d1 = server.takeRequest()
        assertThat(d1.method).isEqualTo("DELETE")
        assertThat(d1.path).isEqualTo("/api/v1/users/u-1")
        assertThat(d1.getHeader("X-Thoryn-Environment")).isEqualTo("ci-sbx")
        val d2 = server.takeRequest()
        assertThat(d2.path).isEqualTo("/api/v1/applications/app-1")
        val d3 = server.takeRequest()
        assertThat(d3.path).isEqualTo("/api/v1/environments/env-1")
        assertThat(d3.getHeader("X-Thoryn-Confirm")).isEqualTo("ci-sbx")
        assertThat(receipt).doesNotExist()
        assertThat(destroy.out).contains("Destroyed. Nothing is owned any more.")
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
        server.enqueue(jsonResponse(201, """{"clientId":"app-prod","status":"active"}"""))
        assertThat(runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes").exit).isEqualTo(0)
        assertThat(server.takeRequest().getHeader("X-Thoryn-Environment")).isNull()

        val refused = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(refused.exit).isNotEqualTo(0)
        assertThat(refused.err).contains("PRODUCTION plane").contains("--confirm <workspace-slug>")
        assertThat(server.requestCount).isEqualTo(1) // nothing was deleted

        server.enqueue(jsonResponse(204, ""))
        val ok = runCli("provision", "destroy", "--file", file.path, "--gateway", baseUrl(), "--yes", "--confirm", "acme")
        assertThat(ok.exit).isEqualTo(0)
        val del = server.takeRequest()
        assertThat(del.path).isEqualTo("/api/v1/applications/app-prod")
        assertThat(del.getHeader("X-Thoryn-Confirm")).isEqualTo("acme")
    }

    @Test
    fun `dropping a resource from the file is a skip until --prune removes it`() {
        val file = writeFile("provision.yaml", sandboxFile)
        server.enqueue(jsonResponse(201, """{"id":"env-1","slug":"ci-sbx"}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-1"}"""))
        server.enqueue(jsonResponse(201, """{"id":"u-1"}"""))
        assertThat(runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes").exit).isEqualTo(0)
        repeat(3) { server.takeRequest() }

        // Drop the user from the desired state.
        file.writeText(sandboxFile.lines().takeWhile { !it.contains("kind: user") }.joinToString("\n"))
        val plan = runCli("provision", "plan", "--file", file.path)
        assertThat(plan.out).contains("skip").contains("re-run with --prune")
        val prunePlan = runCli("provision", "plan", "--file", file.path, "--prune")
        assertThat(prunePlan.out).contains("remove").contains("1 to remove")

        server.enqueue(jsonResponse(200, "{}"))
        val pruned = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes", "--prune")
        assertThat(pruned.err).isEmpty()
        assertThat(pruned.exit).isEqualTo(0)
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/users/u-1")
        val recorded = ProvisionReceiptStore().read(File(file.parentFile, "provision.receipt.json"))!!
        assertThat(recorded.resources.map { it.key }).containsExactly("environment/ci", "application/rp")
    }

    @Test
    fun `an invalid file fails fast with the violations and touches nothing`() {
        val file = writeFile("provision.yaml", "apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: db, name: x, spec: {} }\n")
        val r = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(r.exit).isNotEqualTo(0)
        assertThat(r.err).contains("invalid provisioning file").contains("allowlist")
        assertThat(server.requestCount).isZero()
    }
}
