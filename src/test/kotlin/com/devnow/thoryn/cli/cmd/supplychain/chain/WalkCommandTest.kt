package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain walk`.
 *
 * The walker endpoint is `POST /broker/verify/walletless?walkChain=true`
 * (SSO-964). The CLI sends the leaf URN/JWS in the body and renders the
 * DAG response. Table mode uses [ChainTreeRenderer] for the unicode-box
 * layout; JSON / YAML mode passes the response through.
 */
class WalkCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `walk renders the DAG with per-node verdicts and an aggregate header`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """
                {
                  "verdict": "VALID",
                  "auditRowId": "row-99",
                  "chain": {
                    "credentialId": "RETAIL-203",
                    "actionType": "received",
                    "verdict": "VALID",
                    "parents": [
                      {
                        "credentialId": "ROAST-W18",
                        "actionType": "processed_combined",
                        "verdict": "VALID",
                        "parents": [
                          {"credentialId":"PLOT-A","actionType":"origin","verdict":"VALID"},
                          {"credentialId":"PLOT-B","actionType":"origin","verdict":"VALID"}
                        ]
                      }
                    ]
                  }
                }
                """.trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "walk", "urn:vc:retail-203",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Aggregate verdict: VALID")
        assertThat(out).contains("Audit row:         row-99")
        assertThat(out).contains("RETAIL-203")
        assertThat(out).contains("ROAST-W18")
        assertThat(out).contains("PLOT-A")
        assertThat(out).contains("PLOT-B")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/broker/verify/walletless?walkChain=true")
        val body = req.body.readUtf8()
        assertThat(body).contains("urn:vc:retail-203")
    }

    @Test
    fun `walk --output json emits the raw walk-DAG response`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"verdict":"REVOKED","chain":{"credentialId":"X","verdict":"REVOKED"}}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "walk", "urn:vc:x",
            "--gateway", gatewayUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"verdict\"")
        assertThat(out).contains("REVOKED")
    }

    @Test
    fun `walk --depth forwards the depth cap in the body`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"verdict":"VALID","chain":{"credentialId":"X","verdict":"VALID"}}""",
            ),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "chain", "walk", "urn:vc:x",
            "--depth", "3",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = gateway.takeRequest()
        val body = req.body.readUtf8()
        assertThat(body).contains("\"depthCap\":3")
    }
}
