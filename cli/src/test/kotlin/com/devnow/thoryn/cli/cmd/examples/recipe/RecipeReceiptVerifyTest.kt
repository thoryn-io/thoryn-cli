package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3148 — `thoryn examples verify` is a SEPARATE invocation that re-reads a receipt's resources. It
 * must target the environment the run provisioned into (recorded on the receipt), otherwise every
 * sandbox-plane application reads 404 on the production plane and conformance reports false drift.
 */
class RecipeReceiptVerifyTest : CommandTestBase() {

    private fun context(): ExampleContext {
        val base = Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        return ExampleContext(
            hub = baseUrl(),
            gateway = baseUrl(),
            tokens = base,
            state = ExampleStateStore(dir = tempHome.resolve("examples-state")),
        )
    }

    /** A workspace-less recipe (caller's own token, no token-exchange) — the conformance recipe shape. */
    private fun workspaceLessRecipe(): Recipe = Recipe(
        JsonMapper.builder().build().readTree(
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "verify-env-test",
              "version": "1.0.0",
              "summary": "verify re-reads on the receipt's environment",
              "steps": []
            }
            """.trimIndent(),
        ),
    )

    private fun receipt(environment: String?) = Receipt(
        recipe = RecipeRef("verify-env-test", "1.0.0", "sha256:x"),
        appliedAt = "2026-09-17T00:00:00Z",
        workspace = WorkspaceRef(slug = "examples", tenantId = null),
        environment = environment,
        resources = listOf(ResourceRef(kind = "application", id = "app-7")),
        verify = listOf(VerifyResult("applications.get", "app-7", mapOf("status" to "active"), passed = true)),
    )

    @Test
    fun `verify re-reads a sandbox-provisioned application on the receipt's environment`() {
        server.enqueue(jsonResponse(200, """{"clientId":"app-7","status":"active"}"""))

        val results = RecipeInterpreter(context(), workspaceLessRecipe()).verifyReceipt(receipt("conf-branded-sign-1"))

        assertThat(results).singleElement().matches { it.passed }
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.path).isEqualTo("/api/v1/applications/app-7")
        assertThat(req.getHeader("X-Thoryn-Environment")).isEqualTo("conf-branded-sign-1")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `verify of a production-plane receipt sends no environment header`() {
        server.enqueue(jsonResponse(200, """{"clientId":"app-7","status":"active"}"""))

        val results = RecipeInterpreter(context(), workspaceLessRecipe()).verifyReceipt(receipt(null))

        assertThat(results).singleElement().matches { it.passed }
        assertThat(server.takeRequest().getHeader("X-Thoryn-Environment")).isNull()
    }

    @Test
    fun `a 404 on the re-read is reported as a failed check`() {
        server.enqueue(jsonResponse(404, """{"status":404,"errorCode":"not_found","detail":"The request could not be completed."}"""))

        val results = RecipeInterpreter(context(), workspaceLessRecipe()).verifyReceipt(receipt("conf-branded-sign-1"))

        assertThat(results).singleElement().matches { !it.passed }
    }
}
