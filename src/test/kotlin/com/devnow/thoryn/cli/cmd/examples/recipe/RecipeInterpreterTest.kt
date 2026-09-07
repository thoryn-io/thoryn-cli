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
        // 5) SSO-2878 — best-effort platform attestation of the receipt.
        server.enqueue(jsonResponse(200, """{"kid":"receipt-attestation-t-1-local-v1","signature":"h..s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup()
        val state = run.state

        assertThat(state.example).isEqualTo("simple-signin")
        assertThat(state.tenantId).isEqualTo("t-1")
        assertThat(state.clientId).isEqualTo("app-9")
        assertThat(state.workspaceSlug).startsWith("ex-signin-")

        // SSO-2875 — the run produced a receipt recording exactly what was provisioned.
        val receipt = run.receipt
        assertThat(receipt.recipe.id).isEqualTo("simple-signin")
        assertThat(receipt.recipe.digest).startsWith("sha256:")
        assertThat(receipt.workspace.tenantId).isEqualTo("t-1")
        assertThat(receipt.resources).anyMatch { it.kind == "application" && it.id == "app-9" }
        assertThat(receipt.verify).anyMatch { it.assert == "applications.get" && it.passed }
        // SSO-2878 — the platform-signed attestation was folded into the receipt.
        assertThat(receipt.attestation).isNotNull
        assertThat(receipt.attestation!!.kid).isEqualTo("receipt-attestation-t-1-local-v1")

        // SSO-2897 — the run recorded the post-logout redirect URI on the application resource.
        assertThat(receipt.resources)
            .anyMatch { it.kind == "application" && it.attributes["postLogoutRedirectUri"] == "http://127.0.0.1/" }

        assertThat(server.takeRequest().path).isEqualTo("/account/workspace")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/tenants")
        val appReq = server.takeRequest()
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.method).isEqualTo("POST")
        // The app is created UNDER the workspace, authenticated with the provisioning token.
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        // SSO-2897 — the recipe's postLogoutRedirectUris is forwarded verbatim to product-api's
        // create-application request (which persists it on the hub RegisteredClient for RP-Initiated Logout).
        assertThat(appReq.body.readUtf8())
            .contains("\"postLogoutRedirectUris\"")
            .contains("http://127.0.0.1/")
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
    fun `teardown deletes the app then hard-deletes the workspace`() {
        val ctx = context()
        val state = ExampleState(
            example = "simple-signin",
            workspaceSlug = "ex-signin-abc12345",
            tenantId = "t-1",
            clientId = "app-9",
        )
        // teardown re-enters the workspace via token-exchange (no provisioning token persisted), then
        // deletes the app, then hard-deletes the workspace (SSO-2901 — stop the ex-signin-* tenant sprawl).
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(noContent())
        server.enqueue(jsonResponse(202, """{"tenantId":"t-1","slug":"ex-signin-abc12345","archived":true}"""))

        RecipeInterpreter(ctx, Recipe.load("simple-signin")).teardown(state)

        server.takeRequest() // the token exchange
        // Child-first: the app is deleted BEFORE the workspace it lives in.
        val del = server.takeRequest()
        assertThat(del.method).isEqualTo("DELETE")
        assertThat(del.path).isEqualTo("/api/v1/applications/app-9")
        // Then the workspace hard-delete on the HUB surface, name-confirmation guarded by the slug.
        val hardDelete = server.takeRequest()
        assertThat(hardDelete.method).isEqualTo("POST")
        assertThat(hardDelete.path).isEqualTo("/account/workspace/t-1/hard-delete")
        assertThat(hardDelete.getHeader("X-Thoryn-Confirm")).isEqualTo("ex-signin-abc12345")
    }
}
