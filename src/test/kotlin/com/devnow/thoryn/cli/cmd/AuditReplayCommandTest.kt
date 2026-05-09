package com.devnow.thoryn.cli.cmd

import com.sun.net.httpserver.HttpServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import picocli.CommandLine
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.net.InetSocketAddress
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * SSO-940b — unit tests for [AuditReplayCommand].
 *
 * Asserts the four exit-code outcomes:
 * - `0` PASS — receipt verifies.
 * - `1` INVALID_SIGNATURE — kid found, signature does not verify (tampered).
 * - `2` UNVERIFIABLE — kid not in JWKS / receipt unsigned at write time.
 * - `3` MALFORMED — receipt JSON is the wrong shape.
 *
 * Spins up a local in-process HTTP server that serves a JWKS for the
 * test, so the command can hit `--jwks-url <localhost:port>` without
 * Internet.
 */
class AuditReplayCommandTest {

    @TempDir
    lateinit var tempDir: Path

    private lateinit var server: HttpServer
    private lateinit var jwksUrl: String
    private lateinit var keyPair: KeyPair
    private val kid = "audit-log-signing:v1"
    private val canonicalPayload = """{"id":"row-1","tenantId":"tenant-acme","requestId":"req-1"}"""

    @BeforeEach
    fun setUp() {
        keyPair = generateEcdsaKeyPair()
        startJwksServer(keyPair, kid)
    }

    @AfterEach
    fun tearDown() {
        server.stop(0)
    }

    @Test
    fun `valid receipt verifies and exits PASS (0)`() {
        val signature = sign(canonicalPayload, keyPair)
        val receipt = receiptJson(
            sig = "vault:v1:$signature",
            kid = kid,
            payload = canonicalPayload,
        )
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("PASS")
        assertThat(out).contains("rowId       = row-1")
    }

    @Test
    fun `tampered payload returns INVALID_SIGNATURE (1)`() {
        // Sign one payload, then tamper canonical payload in the receipt.
        val signature = sign(canonicalPayload, keyPair)
        val tampered = canonicalPayload.replace("tenant-acme", "tenant-attacker")
        val receipt = receiptJson(
            sig = "vault:v1:$signature",
            kid = kid,
            payload = tampered,
        )
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(1)
        assertThat(out).contains("INVALID_SIGNATURE")
    }

    @Test
    fun `unknown kid returns UNVERIFIABLE (2)`() {
        val signature = sign(canonicalPayload, keyPair)
        val receipt = receiptJson(
            sig = "vault:v1:$signature",
            kid = "audit-log-signing:v999",  // unknown kid
            payload = canonicalPayload,
        )
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(2)
        assertThat(out).contains("UNVERIFIABLE")
        assertThat(out).contains("audit-log-signing:v999")
    }

    @Test
    fun `unsigned receipt (Vault was down at write time) returns UNVERIFIABLE (2)`() {
        // Note: canonicalPayload contains JSON-shaped content; we escape it
        // before embedding it as a JSON string inside the receipt envelope.
        val escapedPayload = jsonString(canonicalPayload)
        val receipt = """
            {
                "rowId": "row-unsigned",
                "tenantId": "tenant-acme",
                "requestId": "req-unsigned",
                "createdAt": "2026-05-09T12:00:00Z",
                "envelope": {
                    "kid": null,
                    "signature": null,
                    "canonicalPayload": $escapedPayload
                }
            }
        """.trimIndent()
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(2)
        assertThat(out).contains("UNVERIFIABLE")
        assertThat(out).contains("unsigned at write time")
    }

    @Test
    fun `malformed receipt JSON returns MALFORMED (3)`() {
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText("not json at all")

        val (exitCode, _, err) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(3)
        assertThat(err).contains("MALFORMED")
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

    /** Escapes [s] as a JSON string literal (with surrounding quotes). */
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
        val der = sig.sign()
        return Base64.getEncoder().encodeToString(der)
    }

    private fun startJwksServer(keyPair: KeyPair, kid: String) {
        val publicKey = keyPair.public as java.security.interfaces.ECPublicKey
        val xBytes = publicKey.w.affineX.toByteArray().let {
            // Strip leading zero byte if BigInteger added a sign bit.
            if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
        }.let { padTo32(it) }
        val yBytes = publicKey.w.affineY.toByteArray().let {
            if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
        }.let { padTo32(it) }
        val xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes)
        val yB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes)
        val jwksJson = """
            {"keys":[{"kty":"EC","crv":"P-256","kid":"$kid","alg":"ES256","x":"$xB64","y":"$yB64"}]}
        """.trimIndent()

        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/.well-known/historical-jwks.json") { exchange ->
            val bytes = jwksJson.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        jwksUrl = "http://127.0.0.1:${server.address.port}/.well-known/historical-jwks.json"
    }

    private fun padTo32(bytes: ByteArray): ByteArray {
        if (bytes.size == 32) return bytes
        if (bytes.size > 32) return bytes.copyOfRange(bytes.size - 32, bytes.size)
        val out = ByteArray(32)
        System.arraycopy(bytes, 0, out, 32 - bytes.size, bytes.size)
        return out
    }

    private fun run(vararg args: String): Triple<Int, String, String> {
        val outBuf = ByteArrayOutputStream()
        val errBuf = ByteArrayOutputStream()
        val origOut = System.out
        val origErr = System.err
        System.setOut(PrintStream(outBuf))
        System.setErr(PrintStream(errBuf))
        try {
            val exit = CommandLine(AuditReplayCommand()).execute(*args)
            return Triple(exit, outBuf.toString(Charsets.UTF_8), errBuf.toString(Charsets.UTF_8))
        } finally {
            System.setOut(origOut)
            System.setErr(origErr)
        }
    }
}
