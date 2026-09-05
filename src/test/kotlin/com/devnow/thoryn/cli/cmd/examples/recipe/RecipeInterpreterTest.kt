package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleState
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2873 — the recipe interpreter applies `simple-signin` end-to-end against the REAL product-API
 * wire shape (a MockWebServer standing in for the hub + gateway), and tears it down. Proves the
 * declarative recipe drives the same calls the compiled example made: create workspace → register
 * tenant → create the app under the workspace (with the provisioning token) → verify it is active.
 */
class RecipeInterpreterTest : CommandTestBase() {

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

    @Test
    fun `applies simple-signin end to end via the real product APIs`() {
        val ctx = context()
        // 1) createWorkspace → returns a provisioning token (so no token-exchange on the tenant calls)
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        // 2) registerTenant (best-effort)
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        // 3) applications.create (under the workspace)
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
        // 4) verify applications.get
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))

        val state = RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup()

        assertThat(state.example).isEqualTo("simple-signin")
        assertThat(state.tenantId).isEqualTo("t-1")
        assertThat(state.clientId).isEqualTo("app-9")
        assertThat(state.workspaceSlug).startsWith("ex-signin-")

        assertThat(server.takeRequest().path).isEqualTo("/account/workspace")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/tenants")
        val appReq = server.takeRequest()
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.method).isEqualTo("POST")
        // The app is created UNDER the workspace, authenticated with the provisioning token.
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-9")
    }

    @Test
    fun `a failed verify assertion surfaces as a RecipeException`() {
        val ctx = context()
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"x","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9"}"""))
        // verify expects status=active, but the app comes back suspended.
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"suspended"}"""))

        val ex = runCatching { RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup() }
            .exceptionOrNull()
        assertThat(ex).isInstanceOf(RecipeException::class.java)
        assertThat(ex!!.message).contains("status").contains("active").contains("suspended")
    }

    @Test
    fun `teardown deletes the created application`() {
        val ctx = context()
        val state = ExampleState(
            example = "simple-signin",
            workspaceSlug = "ex-signin-abc12345",
            tenantId = "t-1",
            clientId = "app-9",
        )
        // teardown re-enters the workspace via token-exchange (no provisioning token persisted), then deletes.
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(noContent())

        RecipeInterpreter(ctx, Recipe.load("simple-signin")).teardown(state)

        server.takeRequest() // the token exchange
        val del = server.takeRequest()
        assertThat(del.method).isEqualTo("DELETE")
        assertThat(del.path).isEqualTo("/api/v1/applications/app-9")
    }
}
