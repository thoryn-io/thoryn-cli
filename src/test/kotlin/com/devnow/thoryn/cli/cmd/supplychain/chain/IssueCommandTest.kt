package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain issue` (combine path).
 *
 * Mirrors the SSO-962 combine flow: N parents → 1 outgoing credential.
 * The CLI sends a structured `outgoing` block; the server is responsible
 * for fan-out to `POST /broker/internal/credentials/bulk` under the hood.
 */
class IssueCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `issue with processed_combined POSTs the structured body and renders the record`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:roast-001","auditRowId":"row-1",
                   "issuedAt":"2026-05-11T12:00:00Z",
                   "jws":"eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.c2ln",
                   "action":"processed_combined"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "issue",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--parent", "urn:vc:02",
            "--action", "processed_combined",
            "--batch-id", "ROAST-2026-W18",
            "--quantity", "850kg",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("urn:vc:roast-001")
        assertThat(out).contains("row-1")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path)
            .isEqualTo("/api/v1/issuer-bridges/bridge-mill-1/intermediary/issue")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"action\":\"processed_combined\"")
        assertThat(body).contains("urn:vc:01")
        assertThat(body).contains("urn:vc:02")
        assertThat(body).contains("ROAST-2026-W18")
        // The unit gets split out as a structured pair, not a raw "850kg".
        assertThat(body).contains("\"amount\":850")
        assertThat(body).contains("\"unit\":\"kg\"")
    }

    @Test
    fun `issue --action split is rejected with EXIT_USAGE (split has its own subcommand)`() {
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "issue",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--action", "split",
            "--batch-id", "ROAST-1",
            "--quantity", "100kg",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("--action must be one of processed_combined | packaged_combined")
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `issue --quantity rejects an unparseable value before any HTTP call`() {
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "issue",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--action", "processed_combined",
            "--batch-id", "ROAST-1",
            "--quantity", "abc",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("--quantity must be <amount><unit>")
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `issue --output-jws writes the compact JWS to disk`(@TempDir tmp: Path) {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:roast-001","auditRowId":"row-1",
                   "jws":"eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.c2ln"}""".trimIndent(),
            ),
        )

        val target = tmp.resolve("receipt.jws")
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "issue",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--action", "processed_combined",
            "--batch-id", "ROAST-1",
            "--quantity", "1kg",
            "--output-jws", target.toString(),
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(target).exists()
        assertThat(target.toFile().readText())
            .isEqualTo("eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.c2ln")
        assertThat(err).contains("Wrote ")
    }

    @Test
    fun `403 on issue prints the intermediary write scope hint`() {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))

        val (exit, _, err) = runCli(
            "supply-chain", "chain", "issue",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--action", "processed_combined",
            "--batch-id", "ROAST-1",
            "--quantity", "1kg",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains(
            "oathy login --scope tenant:supply-chain.issuer-bridge.intermediary.write",
        )
    }

    @Test
    fun `parseQuantity recognises kg and stuks and bails on missing unit`() {
        assertThat(IssueCommand.parseQuantity("850kg"))
            .isNotNull()
            .satisfies({
                assertThat(it!!.first.toLong()).isEqualTo(850L)
                assertThat(it.second).isEqualTo("kg")
            })
        assertThat(IssueCommand.parseQuantity("12.5kg"))
            .isNotNull()
            .satisfies({
                assertThat(it!!.first.toDouble()).isEqualTo(12.5)
                assertThat(it.second).isEqualTo("kg")
            })
        assertThat(IssueCommand.parseQuantity("300stuks"))
            .isNotNull()
            .satisfies({
                assertThat(it!!.second).isEqualTo("stuks")
            })
        // Missing unit.
        assertThat(IssueCommand.parseQuantity("100"))
            .isNull()
        // Pure non-numeric prefix.
        assertThat(IssueCommand.parseQuantity("kg"))
            .isNull()
    }
}
