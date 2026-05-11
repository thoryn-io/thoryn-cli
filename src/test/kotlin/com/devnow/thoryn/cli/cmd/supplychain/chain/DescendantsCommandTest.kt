package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain descendants`.
 *
 * Two endpoints, one subcommand:
 *  - Default (operator view) — `GET /broker/internal/credentials/{id}/descendants` (SSO-965)
 *  - `--holder` (producer view) — `GET /api/v1/holder/credentials/{id}/descendants` (SSO-967)
 *
 * The privacy-toggle short-circuit on the holder endpoint returns
 * `{ descendants: null, reason: "tenant_privacy_policy" }`; the CLI must
 * render that explicitly so the user sees why they're not getting a tree.
 */
class DescendantsCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `descendants without --holder hits the broker operator endpoint`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:roast-w18","actionType":"processed_combined","verdict":"VALID",
                   "descendants":[
                     {"credentialId":"urn:vc:retail-1","actionType":"split","verdict":"VALID"}
                   ]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "descendants", "urn:vc:roast-w18",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("urn:vc:retail-1")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        // The URN's `:` separators get URL-encoded as `%3A` via the standard
        // ProductApiClient path-encoder.
        assertThat(req.path)
            .isEqualTo("/broker/internal/credentials/urn%3Avc%3Aroast-w18/descendants")
    }

    @Test
    fun `descendants --holder hits the holder portal endpoint`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:plot-a","verdict":"VALID","descendants":[]}""",
            ),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "chain", "descendants", "urn:vc:plot-a",
            "--holder",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/holder/credentials/urn%3Avc%3Aplot-a/descendants")
    }

    @Test
    fun `descendants --holder renders the privacy-toggle short-circuit explicitly`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"descendants":null,"reason":"tenant_privacy_policy"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "descendants", "urn:vc:plot-a",
            "--holder",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Path hidden by tenant policy")
        assertThat(out).contains("tenant_privacy_policy")
    }

    @Test
    fun `descendants --depth forwards the depth as a query param`() {
        gateway.enqueue(
            jsonResponse(200, """{"credentialId":"X","verdict":"VALID","descendants":[]}"""),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "chain", "descendants", "urn:vc:x",
            "--depth", "2",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(0)
        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/broker/internal/credentials/urn%3Avc%3Ax/descendants?depth=2")
    }

    @Test
    fun `descendants --output json emits raw response payload`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"urn:vc:x","verdict":"VALID","descendants":[]}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "chain", "descendants", "urn:vc:x",
            "--gateway", gatewayUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"credentialId\"")
        assertThat(out).contains("\"VALID\"")
    }
}
