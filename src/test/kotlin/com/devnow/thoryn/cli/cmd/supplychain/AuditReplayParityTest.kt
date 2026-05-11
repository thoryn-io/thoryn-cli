package com.devnow.thoryn.cli.cmd.supplychain

import com.sun.net.httpserver.HttpServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * SSO-959 acceptance criteria: `thoryn supply-chain audit replay <id>`
 * re-uses the existing `thoryn audit-replay` logic; behaviour parity tested.
 *
 * This test:
 *
 *  1. Spins up a fake JWKS server that publishes a P-256 public key under
 *     a known kid (same as `AuditReplayCommandTest`).
 *  2. Mints an audit receipt signed with the matching private key, returns
 *     it from the gateway when the CLI fetches it.
 *  3. Runs `thoryn supply-chain audit replay <id>` and asserts the same
 *     PASS / INVALID_SIGNATURE / UNVERIFIABLE outcomes as the standalone
 *     `thoryn audit-replay`.
 *
 * Parity assertion: identical receipt inputs produce identical exit codes
 * regardless of whether the user invoked the standalone command or the
 * supply-chain alias.
 */
class AuditReplayParityTest : SupplyChainCommandTestBase() {

    private lateinit var jwksServer: HttpServer
    private lateinit var jwksUrl: String
    private lateinit var keyPair: KeyPair
    private val kid = "audit-log-signing:v1"
    private val canonicalPayload = """{"id":"row-1","tenantId":"tenant-acme","requestId":"req-1"}"""

    @BeforeEach
    fun setUpJwks() {
        keyPair = generateEcdsaKeyPair()
        startJwksServer(keyPair, kid)
    }

    @AfterEach
    fun tearDownJwks() {
        jwksServer.stop(0)
    }

    @Test
    fun `valid receipt via supply-chain audit replay returns PASS (0)`() {
        val signature = sign(canonicalPayload, keyPair)
        gateway.enqueue(
            jsonResponse(
                200,
                receiptJson(sig = "vault:v1:$signature", kid = kid, payload = canonicalPayload),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "replay", "row-1",
            "--gateway", gatewayUrl(),
            "--jwks-url", jwksUrl,
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("PASS")
        assertThat(out).contains("rowId                    = row-1")
        // The gateway's receipt.json endpoint was hit.
        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/audit-log/row-1/receipt.json")
    }

    @Test
    fun `tampered receipt via supply-chain audit replay returns INVALID_SIGNATURE (1)`() {
        val signature = sign(canonicalPayload, keyPair)
        val tampered = canonicalPayload.replace("tenant-acme", "tenant-attacker")
        gateway.enqueue(
            jsonResponse(
                200,
                receiptJson(sig = "vault:v1:$signature", kid = kid, payload = tampered),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "replay", "row-1",
            "--gateway", gatewayUrl(),
            "--jwks-url", jwksUrl,
        )

        // Exit code 1 == INVALID_SIGNATURE per AuditReplayCommand.
        assertThat(exit).isEqualTo(1)
        assertThat(out).contains("INVALID_SIGNATURE")
    }

    @Test
    fun `unknown kid via supply-chain audit replay returns UNVERIFIABLE (2)`() {
        val signature = sign(canonicalPayload, keyPair)
        gateway.enqueue(
            jsonResponse(
                200,
                receiptJson(sig = "vault:v1:$signature", kid = "audit-log-signing:v999", payload = canonicalPayload),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "audit", "replay", "row-1",
            "--gateway", gatewayUrl(),
            "--jwks-url", jwksUrl,
        )

        // Exit code 2 == UNVERIFIABLE per AuditReplayCommand.
        assertThat(exit).isEqualTo(2)
        assertThat(out).contains("UNVERIFIABLE")
    }

    private fun receiptJson(sig: String, kid: String, payload: String): String =
        """
        {
            "rowId": "row-1",
            "tenantId": "tenant-acme",
            "requestId": "req-1",
            "createdAt": "2026-05-09T12:00:00Z",
            "envelope": {
                "kid": "$kid",
                "signature": "$sig",
                "canonicalPayload": ${jsonString(payload)}
            }
        }
        """.trimIndent()

    private fun jsonString(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun generateEcdsaKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun sign(payload: String, keyPair: KeyPair): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    private fun startJwksServer(keyPair: KeyPair, kid: String) {
        val publicKey = keyPair.public as java.security.interfaces.ECPublicKey
        val xBytes = padTo32(publicKey.w.affineX.toByteArray().let { stripSignByte(it) })
        val yBytes = padTo32(publicKey.w.affineY.toByteArray().let { stripSignByte(it) })
        val xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes)
        val yB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes)
        val jwksJson = """
            {"keys":[{"kty":"EC","crv":"P-256","kid":"$kid","alg":"ES256","x":"$xB64","y":"$yB64"}]}
        """.trimIndent()

        jwksServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        jwksServer.createContext("/.well-known/historical-jwks.json") { exchange ->
            val bytes = jwksJson.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        jwksServer.start()
        jwksUrl = "http://127.0.0.1:${jwksServer.address.port}/.well-known/historical-jwks.json"
    }

    private fun stripSignByte(bytes: ByteArray): ByteArray =
        if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, 33) else bytes

    private fun padTo32(bytes: ByteArray): ByteArray {
        if (bytes.size == 32) return bytes
        if (bytes.size > 32) return bytes.copyOfRange(bytes.size - 32, bytes.size)
        val out = ByteArray(32)
        System.arraycopy(bytes, 0, out, 32 - bytes.size, bytes.size)
        return out
    }
}
