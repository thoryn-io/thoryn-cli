package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.recipe.Receipt
import com.devnow.thoryn.cli.cmd.examples.recipe.ReceiptStore
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeRef
import com.devnow.thoryn.cli.cmd.examples.recipe.ResourceRef
import com.devnow.thoryn.cli.cmd.examples.recipe.VerifyResult
import com.devnow.thoryn.cli.cmd.examples.recipe.WorkspaceRef
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2875 — `thoryn examples receipt` shows the recorded receipt (offline), and `thoryn examples
 * verify` re-checks the provisioned config against live state using the receipt's resource ids.
 */
class ExamplesReceiptTest : CommandTestBase() {

    private fun seedReceipt(verify: List<VerifyResult> = emptyList()) {
        ReceiptStore().write(
            Receipt(
                recipe = RecipeRef("simple-signin", "1.0.0", "sha256:abc"),
                appliedAt = "2026-09-05T10:00:00Z",
                workspace = WorkspaceRef("ex-signin-x", "t-1"),
                resources = listOf(ResourceRef("application", "app-9", mapOf("redirectUri" to "http://127.0.0.1/callback"))),
                verify = verify,
            ),
        )
    }

    @Test
    fun `receipt prints the stored receipt as json`() {
        seedReceipt()
        val (exit, out, _) = runCli("examples", "receipt", "simple-signin", "--output", "json")
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("simple-signin").contains("app-9").contains("sha256:abc")
    }

    @Test
    fun `receipt with no stored receipt is a usage error`() {
        val (exit, _, err) = runCli("examples", "receipt", "simple-signin")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("No receipt")
    }

    @Test
    fun `verify re-checks the receipt against live state and passes when the app is intact`() {
        seedReceipt(verify = listOf(VerifyResult("applications.get", "app-9", mapOf("status" to "active"), passed = true)))
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        // verify re-enters the workspace (token-exchange) then re-fetches the app.
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))

        val (exit, out, _) = runCli("examples", "verify", "simple-signin", "--hub", baseUrl(), "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("PASS").contains("passed")
    }

    @Test
    fun `verify fails when the provisioned app has drifted`() {
        seedReceipt(verify = listOf(VerifyResult("applications.get", "app-9", mapOf("status" to "active"), passed = true)))
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"suspended"}"""))

        val (exit, out, _) = runCli("examples", "verify", "simple-signin", "--hub", baseUrl(), "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out).contains("FAIL").contains("drifted")
    }
}
