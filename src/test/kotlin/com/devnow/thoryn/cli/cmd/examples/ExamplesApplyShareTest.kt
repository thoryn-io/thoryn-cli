package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.recipe.Attestation
import com.devnow.thoryn.cli.cmd.examples.recipe.Receipt
import com.devnow.thoryn.cli.cmd.examples.recipe.ReceiptStore
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeRef
import com.devnow.thoryn.cli.cmd.examples.recipe.WorkspaceRef
import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-2876 — the guided `examples apply` (driven non-interactively here via --set + --yes) and
 * `examples share`.
 */
class ExamplesApplyShareTest : CommandTestBase() {

    @Test
    fun `apply provisions non-interactively with --set and --yes, and writes a receipt`() {
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        // The interpreter's setup drives: createWorkspace → registerTenant → applications.create →
        // identity.registerUser (SSO-2908) → verify → attest.
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","emailVerified":true,"status":"ACTIVE"}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"receipt-attestation-t-1-local-v1","signature":"h..s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val (exit, out, _) = runCli(
            "examples", "apply", "simple-signin",
            "--set", "workspaceSlug=ex-signin-abc12345",
            "--set", "displayName=Demo",
            "--yes",
            "--hub", baseUrl(), "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Plan — recipe simple-signin").contains("Applied")
        val receipt = ReceiptStore().read("simple-signin")
        assertThat(receipt).isNotNull
        assertThat(receipt!!.resources).anyMatch { it.id == "app-9" }
        // The create hit the workspace under the provisioning token.
        server.takeRequest() // createWorkspace
        server.takeRequest() // registerTenant
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer PT-1")
    }

    @Test
    fun `apply provisions the workspace-less ci-signin recipe with the callers own token`() {
        // SSO-2944 — a customer-plane API key is tenant-scoped and cannot create workspaces, so ci-signin
        // provisions an ephemeral app inside the STANDING workspace the key owns. `--environment` is set
        // so the guided apply skips the environment listing; `workspaceSlug` names the standing workspace.
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        // applications.create → verify applications.get → attest. NO createWorkspace / registerTenant.
        server.enqueue(jsonResponse(201, """{"clientId":"app-ci","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-ci","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val (exit, out, _) = runCli(
            "examples", "apply", "ci-signin",
            "--set", "workspaceSlug=ci-standing",
            "--environment", "production",
            "--yes",
            "--hub", baseUrl(), "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Plan — recipe ci-signin").contains("Applied")
        val receipt = ReceiptStore().read("ci-signin")
        assertThat(receipt).isNotNull
        assertThat(receipt!!.resources).anyMatch { it.id == "app-ci" }
        // The FIRST request is the app create, under the caller's OWN tenant-scoped bearer.
        val appReq = server.takeRequest()
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `apply takes a param from the env var of its name without --set, and never echoes a secret`() {
        // SSO-3102 — the recipe's params are overridable by the example that runs it: CI exports demoPassword
        // under that NAME; the guided apply skips its prompt (no console here anyway), feeds it to the
        // provisioning file's passwordEnv, and shows it only as "(secret)" in the plan.
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        val api = FakeProductApi()
        server.dispatcher = api
        val dir = tempHome.resolve(".config/thoryn/recipes-cache/v1.0.0-cache/recipes/env-demo")
        Files.createDirectories(dir)
        Files.writeString(
            dir.resolve("recipe.json"),
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "env-demo",
              "version": "1.0.0",
              "summary": "params from the environment",
              "provision": "./provision.yaml",
              "params": [
                { "name": "workspaceSlug", "prompt": "Standing workspace", "default": "acme" },
                { "name": "envSlug", "prompt": "Sandbox slug", "default": "demo-sbx" },
                { "name": "demoPassword", "prompt": "Demo user password", "default": "Default-{{generate.slug8}}-Pw1!", "secret": true }
              ]
            }
            """.trimIndent(),
        )
        Files.writeString(
            dir.resolve("provision.yaml"),
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: sandbox, spec: { slug: "{{env.envSlug}}" } }
              - { kind: user, name: demo, environment: sandbox, spec: { email: demo@example.com, passwordEnv: demoPassword, emailVerified: true } }
            """.trimIndent(),
        )
        val originalEnv = RecipeParamEnv.lookup
        RecipeParamEnv.lookup = { mapOf("demoPassword" to "From-Env-9!", "envSlug" to "env-sbx")[it] }
        try {
            val (exit, out, _) = runCli("examples", "apply", "env-demo", "--yes", "--hub", baseUrl(), "--gateway", baseUrl())
            assertThat(exit).isEqualTo(0)
            assertThat(out).contains("demoPassword = (secret)").contains("envSlug = env-sbx").doesNotContain("From-Env-9!")
            assertThat(api.provisioningWrites.first { it.path == "/api/v1/environments" }.body["slug"]).isEqualTo("env-sbx")
            assertThat(api.provisioningWrites.first { it.path == "/api/v1/users" }.body["password"]).isEqualTo("From-Env-9!")
        } finally {
            RecipeParamEnv.lookup = originalEnv
        }
    }

    @Test
    fun `apply provisions a recipe's provisioning file first, plans it, and teardown destroys it`() {
        // SSO-3100 — a catalog recipe (previously verified + cached) that carries only a `provision`
        // reference: the guided apply lists the provisioning file in its plan, says the sandbox is created
        // by that file (no environment prompt), converges it, and `teardown` destroys it child-first.
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        val api = FakeProductApi()
        server.dispatcher = api
        val dir = tempHome.resolve(".config/thoryn/recipes-cache/v1.0.0-cache/recipes/sandbox-demo")
        Files.createDirectories(dir)
        Files.writeString(
            dir.resolve("recipe.json"),
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "sandbox-demo",
              "version": "1.0.0",
              "summary": "provisioned sign-in demo",
              "provision": "./provision.yaml",
              "params": [ { "name": "workspaceSlug", "prompt": "Standing workspace", "default": "acme" } ],
              "verify": [ { "assert": "applications.get", "id": "{{provision.application.rp.clientId}}", "expect": { "status": "active" } } ]
            }
            """.trimIndent(),
        )
        Files.writeString(
            dir.resolve("provision.yaml"),
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: sandbox, spec: { slug: demo-sbx } }
              - { kind: application, name: rp, environment: sandbox, spec: { displayName: "Demo RP", redirectUris: ["http://127.0.0.1/callback"] } }
              - { kind: loginMethods, environment: sandbox, spec: { methods: [password, passkey] } }
            """.trimIndent(),
        )

        val (exit, out, _) = runCli("examples", "apply", "sandbox-demo", "--yes", "--hub", baseUrl(), "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("Plan — recipe sandbox-demo")
            .contains("environment: sandbox 'sandbox' (slug demo-sbx) — created by ./provision.yaml")
            .contains("provision (./provision.yaml, applied first — 3 resource(s))")
            .contains("- application rp (in sandbox)")
            .contains("steps: none — the provisioning file carries everything")
            .contains("[provision] ./provision.yaml")
            .contains("Applied")
        assertThat(api.provisioningWrites.map { it.method + " " + it.path })
            .containsExactly("POST /api/v1/environments", "POST /api/v1/applications", "PUT /api/v1/login-methods")
        val receipt = ReceiptStore().read("sandbox-demo")!!
        assertThat(receipt.resources.map { it.kind }).containsExactly("environment", "application", "loginMethods")
        assertThat(receipt.verify).allMatch { it.passed }
        assertThat(ExampleStateStore().provisionReceiptPath("sandbox-demo").toFile()).exists()

        // A second apply is refused while the setup exists (unchanged guard) …
        assertThat(runCli("examples", "apply", "sandbox-demo", "--yes", "--hub", baseUrl(), "--gateway", baseUrl()).err).contains("teardown")

        // … and teardown destroys what the provisioning file created, child-first (sandbox last).
        api.reset()
        val down = runCli("examples", "teardown", "sandbox-demo", "--hub", baseUrl(), "--gateway", baseUrl())
        assertThat(down.exit).isEqualTo(0)
        assertThat(api.provisioningWrites.map { it.method + " " + it.path }).containsExactly(
            "DELETE /api/v1/login-methods", "DELETE /api/v1/applications/${receipt.resources[1].id}", "DELETE /api/v1/environments/${receipt.resources[0].id}",
        )
        assertThat(api.environments).isEmpty()
        assertThat(ExampleStateStore().provisionReceiptPath("sandbox-demo").toFile()).doesNotExist()
        assertThat(ReceiptStore().read("sandbox-demo")).isNull()
    }

    @Test
    fun `share prints the secret-free receipt and notes it is unsigned`() {
        ReceiptStore().write(
            Receipt(
                recipe = RecipeRef("simple-signin", "1.0.0", "sha256:xyz"),
                appliedAt = "2026-09-05T10:00:00Z",
                workspace = WorkspaceRef("ex-x", "t-1"),
            ),
        )
        val (exit, out, err) = runCli("examples", "share", "simple-signin")
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("simple-signin").contains("sha256:xyz")
        assertThat(err).contains("NOT platform-signed")
    }

    @Test
    fun `share notes a platform-signed receipt`() {
        ReceiptStore().write(
            Receipt(
                recipe = RecipeRef("simple-signin", "1.0.0", "sha256:xyz"),
                appliedAt = "2026-09-05T10:00:00Z",
                workspace = WorkspaceRef("ex-x", "t-1"),
                attestation = Attestation("kid-1", "sig", "cp", "2026-09-05T10:00:01Z"),
            ),
        )
        val (exit, _, err) = runCli("examples", "share", "simple-signin")
        assertThat(exit).isEqualTo(0)
        assertThat(err).contains("platform-signed").contains("kid-1")
    }

    @Test
    fun `share without a receipt is a usage error`() {
        val (exit, _, err) = runCli("examples", "share", "simple-signin")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("No receipt")
    }
}
