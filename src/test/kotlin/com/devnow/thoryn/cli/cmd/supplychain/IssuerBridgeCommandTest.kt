package com.devnow.thoryn.cli.cmd.supplychain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-959 — unit tests for `thoryn supply-chain issuer-bridge ...`.
 */
class IssuerBridgeCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `list renders bridges with heartbeat and status`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"bridgeId":"bridge-mps-1","vendor":"mps","currentKid":"mps-v1",
                   "lastHeartbeatAt":"2026-05-09T12:00:00Z","credentialsLive":1234,"status":"healthy"},
                  {"bridgeId":"bridge-globalgap-1","vendor":"globalgap","currentKid":"ggap-v3",
                   "lastHeartbeatAt":"2026-05-09T11:55:00Z","credentialsLive":890,"status":"degraded"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "issuer-bridge", "list",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("bridge-mps-1")
        assertThat(out).contains("bridge-globalgap-1")
        assertThat(out).contains("degraded")

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/issuer-bridges")
    }

    @Test
    fun `show fetches single bridge by ID`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"bridgeId":"bridge-mps-1","vendor":"mps","currentKid":"mps-v1","status":"healthy",
                   "queued":12,"signed":345,"encoded":345,"failed":0}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "issuer-bridge", "show", "bridge-mps-1",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("bridge-mps-1")
        assertThat(out).contains("mps")
        assertThat(out).contains("queued")

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/issuer-bridges/bridge-mps-1")
    }

    @Test
    fun `credentials forwards filter params`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"credentialId":"cred-1","growerId":"grower-a","issuedAt":"2026-04-01","status":"active"},
                  {"credentialId":"cred-2","growerId":"grower-a","issuedAt":"2026-04-15","status":"active"}
                ]""".trimIndent(),
            ),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "issuer-bridge", "credentials",
            "--bridge-id", "bridge-mps-1",
            "--status", "active",
            "--limit", "100",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = gateway.takeRequest()
        val path = req.path ?: ""
        assertThat(path).startsWith("/api/v1/issuer-bridges/bridge-mps-1/credentials?")
        assertThat(path).contains("status=active")
        assertThat(path).contains("limit=100")
    }

    @Test
    fun `revoke rejects a reason shorter than 10 characters before any HTTP call`() {
        val (exit, _, err) = runCli(
            "supply-chain", "issuer-bridge", "revoke",
            "--bridge-id", "bridge-mps-1",
            "--credential-id", "cred-42",
            "--reason", "too short",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("at least 10 characters")
        // No HTTP request should have been made.
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `revoke POSTs to the revoke endpoint with the reason in the body`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialId":"cred-42","status":"revoked","revokedAt":"2026-05-11T00:00:00Z","auditRowId":"row-99"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "issuer-bridge", "revoke",
            "--bridge-id", "bridge-mps-1",
            "--credential-id", "cred-42",
            "--reason", "Cert pulled mid-cycle by certifier",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("cred-42")
        assertThat(out).contains("revoked")
        assertThat(out).contains("row-99")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path)
            .isEqualTo("/api/v1/issuer-bridges/bridge-mps-1/credentials/cred-42/revoke")
        val body = req.body.readUtf8()
        assertThat(body).contains("Cert pulled mid-cycle by certifier")
    }

    @Test
    fun `rotate-key generate step POSTs to keys endpoint`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"bridgeId":"bridge-mps-1","step":"generate","kid":"mps-v2","auditRowId":"row-100"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "issuer-bridge", "rotate-key",
            "--bridge-id", "bridge-mps-1",
            "--step", "generate",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("generate")
        assertThat(out).contains("mps-v2")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/issuer-bridges/bridge-mps-1/keys")
    }

    @Test
    fun `rotate-key publish step PATCHes the current key`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"bridgeId":"bridge-mps-1","step":"publish","kid":"mps-v2","previousKid":"mps-v1"}""",
            ),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "issuer-bridge", "rotate-key",
            "--bridge-id", "bridge-mps-1",
            "--step", "publish",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("PATCH")
        assertThat(req.path).isEqualTo("/api/v1/issuer-bridges/bridge-mps-1/keys/current")
    }

    @Test
    fun `rotate-key with unknown step rejects with EXIT_USAGE`() {
        val (exit, _, err) = runCli(
            "supply-chain", "issuer-bridge", "rotate-key",
            "--bridge-id", "bridge-mps-1",
            "--step", "explode",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("--step must be one of")
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `403 on revoke suggests issuer-bridge revoke scope`() {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))
        val (exit, _, err) = runCli(
            "supply-chain", "issuer-bridge", "revoke",
            "--bridge-id", "bridge-mps-1",
            "--credential-id", "cred-42",
            "--reason", "Cert pulled mid-cycle by certifier",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("oathy login --scope tenant:supply-chain.issuer-bridge.revoke")
    }
}
