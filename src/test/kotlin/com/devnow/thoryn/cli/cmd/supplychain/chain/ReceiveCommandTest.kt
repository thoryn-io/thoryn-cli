package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain receive`.
 *
 * Wire-shape parity with the SSO-962 Receive screen: N parents go in, N
 * verdicts come out. The CLI POSTs to
 * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/receive` and renders
 * the resulting list in the requested format.
 */
class ReceiveCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `receive POSTs parents to the intermediary receive endpoint and renders the table`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"credentialId":"urn:vc:01","actor":"Farm A","batchId":"BATCH-1",
                   "quantity":{"amount":50,"unit":"kg"},"validUntil":"2026-12-31","verdict":"VALID"},
                  {"credentialId":"urn:vc:02","actor":"Farm B","batchId":"BATCH-2",
                   "quantity":{"amount":75,"unit":"kg"},"validUntil":"2026-12-31","verdict":"VALID"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "receive",
            "--bridge-id", "bridge-mill-1",
            "--parent-jws", "urn:vc:01",
            "--parent-jws", "urn:vc:02",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("urn:vc:01")
        assertThat(out).contains("urn:vc:02")
        assertThat(out).contains("Farm A")
        assertThat(out).contains("VALID")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path)
            .isEqualTo("/api/v1/issuer-bridges/bridge-mill-1/intermediary/receive")
        val body = req.body.readUtf8()
        assertThat(body).contains("urn:vc:01")
        assertThat(body).contains("urn:vc:02")
    }

    @Test
    fun `receive --output json emits structured JSON to stdout`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[{"credentialId":"urn:vc:01","verdict":"VALID"}]""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "receive",
            "--bridge-id", "bridge-mill-1",
            "--parent-jws", "urn:vc:01",
            "--gateway", gatewayUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"credentialId\"")
        assertThat(out).contains("urn:vc:01")
    }

    @Test
    fun `403 from gateway prints the intermediary read scope hint`() {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))

        val (exit, _, err) = runCli(
            "supply-chain", "chain", "receive",
            "--bridge-id", "bridge-mill-1",
            "--parent-jws", "urn:vc:01",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains(
            "oathy login --scope tenant:supply-chain.issuer-bridge.intermediary.read",
        )
    }
}
