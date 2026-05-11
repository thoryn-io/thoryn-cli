package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain revoke`.
 *
 * Two paths under one command:
 *   * Default: POST to `/broker/internal/credentials/{id}/revoke` (SSO-965),
 *     flips the bit and propagates REVOKED_VIA_PARENT to descendants.
 *   * `--dry-run`: GET `/broker/internal/credentials/{id}/descendants` and
 *     print the blast radius **without** mutating state.
 */
class RevokeCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `revoke without --dry-run POSTs to the revoke endpoint with the reason in the body`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:roast-w18","revocationKind":"DIRECT",
                   "revokedAt":"2026-05-11T12:00:00Z","auditRowId":"row-99",
                   "descendantsFlipped":850}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:roast-w18",
            "--reason", "EUDR violation detected at upstream plot",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("urn:vc:roast-w18")
        assertThat(out).contains("DIRECT")
        assertThat(out).contains("850")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        // The URN's `:` separators get URL-encoded as `%3A` via the standard
        // ProductApiClient path-encoder (same behaviour as every other
        // supply-chain subcommand).
        assertThat(req.path).isEqualTo("/broker/internal/credentials/urn%3Avc%3Aroast-w18/revoke")
        val body = req.body.readUtf8()
        assertThat(body).contains("EUDR violation detected at upstream plot")
    }

    @Test
    fun `revoke without --reason and without --dry-run bails with EXIT_USAGE`() {
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:roast-w18",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("at least 10 characters")
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `revoke with a short reason and no --dry-run bails with EXIT_USAGE`() {
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:roast-w18",
            "--reason", "too short",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("at least 10 characters")
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `revoke --dry-run GETs the descendants endpoint and prints blast radius without committing`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"total":850,"byActionType":{"retail":600,"wholesale":250}}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:roast-w18",
            "--dry-run",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Dry-run")
        assertThat(out).contains("urn:vc:roast-w18")
        assertThat(out).contains("Descendants flipped")
        assertThat(out).contains("850")
        assertThat(out).contains("retail")
        assertThat(out).contains("wholesale")
        assertThat(out).contains("Nothing committed")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.path)
            .isEqualTo("/broker/internal/credentials/urn%3Avc%3Aroast-w18/descendants")
    }

    @Test
    fun `revoke --dry-run with --depth forwards the depth as a query param`() {
        gateway.enqueue(jsonResponse(200, """{"total":0}"""))

        val (exit, _, _) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:x",
            "--dry-run", "--depth", "3",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(0)
        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/broker/internal/credentials/urn%3Avc%3Ax/descendants?depth=3")
    }

    @Test
    fun `403 on revoke prints the issuer-bridge revoke scope hint`() {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))

        val (exit, _, err) = runCli(
            "supply-chain", "chain", "revoke", "urn:vc:roast-w18",
            "--reason", "EUDR violation detected at upstream plot",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains(
            "oathy login --scope tenant:supply-chain.issuer-bridge.revoke",
        )
    }
}
