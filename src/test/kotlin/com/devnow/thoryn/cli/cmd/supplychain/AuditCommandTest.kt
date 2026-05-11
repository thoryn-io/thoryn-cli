package com.devnow.thoryn.cli.cmd.supplychain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-959 — unit tests for `thoryn supply-chain audit ...`.
 *
 * Replay (the alias for `thoryn audit-replay`) is tested separately in
 * [AuditReplayParityTest] — it needs a JWKS server in addition to the
 * gateway stub.
 */
class AuditCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `search forwards filters as query params and renders the table`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"auditRowId":"row-1","timestamp":"2026-05-09T12:00:00Z","credentialClass":"FSISustainabilityCertification",
                   "outcome":"VALID","issuerKid":"k1","policyVersion":"walletless-v1-revocation-unchecked"},
                  {"auditRowId":"row-2","timestamp":"2026-05-09T13:00:00Z","credentialClass":"FSISustainabilityCertification",
                   "outcome":"VALID","issuerKid":"k1","policyVersion":"walletless-v1-revocation-unchecked"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "search",
            "--from", "2026-01-01",
            "--to", "2026-03-31",
            "--credential-class", "FSISustainabilityCertification",
            "--outcome", "VALID",
            "--limit", "100",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("row-1")
        assertThat(out).contains("row-2")

        val req = gateway.takeRequest()
        val path = req.path ?: ""
        assertThat(path).startsWith("/api/v1/audit-log?")
        assertThat(path).contains("from=2026-01-01")
        assertThat(path).contains("to=2026-03-31")
        assertThat(path).contains("credentialClass=FSISustainabilityCertification")
        assertThat(path).contains("outcome=VALID")
        assertThat(path).contains("limit=100")
    }

    @Test
    fun `get fetches a single row by ID`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"auditRowId":"row-42","tenantId":"tenant-acme","timestamp":"2026-05-09T12:00:00Z","outcome":"VALID"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "get", "row-42",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("row-42")
        assertThat(out).contains("tenant-acme")

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/audit-log/row-42")
    }

    @Test
    fun `receipt without --pdf returns JSON to stdout`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"rowId":"row-42","envelope":{"kid":"audit-log-signing:v1","signature":"vault:v1:sig","canonicalPayload":"{}"}}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "receipt", "row-42",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"rowId\"")
        assertThat(out).contains("row-42")

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/audit-log/row-42/receipt.json")
    }

    @Test
    fun `receipt --pdf writes binary to stdout`() {
        // Fake PDF/A-3 header — first four bytes are %PDF in real PDFs.
        val pdfBytes = byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37) +
            ByteArray(100) { (it % 256).toByte() }
        gateway.enqueue(pdfResponse(pdfBytes))

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "receipt", "row-42",
            "--pdf",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        // The binary bytes are emitted to stdout. The captured "out" is UTF-8
        // decoded; %PDF is ASCII so it should be intact at the start.
        assertThat(out.toByteArray(Charsets.UTF_8).take(4))
            .containsExactly(0x25, 0x50, 0x44, 0x46)

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/audit-log/row-42/receipt.pdf")
        assertThat(req.getHeader("Accept")).isEqualTo("application/pdf")
    }

    @Test
    fun `receipt --pdf with -o writes to file and a confirmation to stderr`(@org.junit.jupiter.api.io.TempDir tmp: java.nio.file.Path) {
        val pdfBytes = byteArrayOf(0x25, 0x50, 0x44, 0x46) + ByteArray(20)
        gateway.enqueue(pdfResponse(pdfBytes))

        val target = tmp.resolve("receipt.pdf").toFile()
        val (exit, _, err) = runCli(
            "supply-chain", "audit", "receipt", "row-42",
            "--pdf",
            "-o", target.absolutePath,
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(target).exists()
        assertThat(target.readBytes()).hasSize(pdfBytes.size)
        assertThat(err).contains("Wrote ${pdfBytes.size} bytes")
    }

    @Test
    fun `403 on search prints the audit-read scope hint`() {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))

        val (exit, _, err) = runCli(
            "supply-chain", "audit", "search",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("oathy login --scope tenant:supply-chain.audit.read")
    }
}
