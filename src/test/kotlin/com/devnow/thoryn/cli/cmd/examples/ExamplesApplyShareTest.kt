package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.recipe.Attestation
import com.devnow.thoryn.cli.cmd.examples.recipe.Receipt
import com.devnow.thoryn.cli.cmd.examples.recipe.ReceiptStore
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeRef
import com.devnow.thoryn.cli.cmd.examples.recipe.WorkspaceRef
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2876 — the guided `examples apply` (driven non-interactively here via --set + --yes) and
 * `examples share`.
 */
class ExamplesApplyShareTest : CommandTestBase() {

    @Test
    fun `apply provisions non-interactively with --set and --yes, and writes a receipt`() {
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl()))
        // The interpreter's setup drives: createWorkspace → registerTenant → applications.create → verify → attest.
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
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
