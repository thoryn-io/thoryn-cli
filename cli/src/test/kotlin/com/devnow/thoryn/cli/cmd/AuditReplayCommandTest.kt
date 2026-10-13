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
        assertThat(out).contains("rowId                    = row-1")
    }

    @Test
    fun `queued-offline row with broker MATCH returns OFFLINE_VERIFIED_BROKER_AGREED (0)`() {
        // SSO-952: a row whose policyVersion = walletless-offline-v1 AND
        // brokerPostVerification = MATCH represents an offline-verified
        // credential that the broker subsequently confirmed on flush.
        // Distinct from PASS so a regulator can tell which audit rows
        // came from queued evidence.
        val signature = sign(canonicalPayload, keyPair)
        val receipt = """
            {
                "rowId": "row-1",
                "tenantId": "tenant-acme",
                "requestId": "req-1",
                "createdAt": "2026-05-09T12:00:00Z",
                "policyVersion": "walletless-offline-v1",
                "brokerPostVerification": "MATCH",
                "envelope": {
                    "kid": "$kid",
                    "signature": "vault:v1:$signature",
                    "canonicalPayload": ${jsonString(canonicalPayload)}
                }
            }
        """.trimIndent()
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("OFFLINE_VERIFIED_BROKER_AGREED")
        assertThat(out).doesNotContain("\nPASS\n")
        assertThat(out).contains("policyVersion            = walletless-offline-v1")
        assertThat(out).contains("brokerPostVerification   = MATCH")
    }

    @Test
    fun `queued-offline row with brokerPostVerification null returns plain PASS (0)`() {
        // SSO-952: walletless-offline-v1 but brokerPostVerification null
        // (broker couldn't run the live re-check at flush time). This is
        // still PASS — the device's signed evidence is intact — but the
        // tooling does NOT promise a cross-check happened. Reflects the
        // queued ack semantics: cross-check is "best effort", not required.
        val signature = sign(canonicalPayload, keyPair)
        val receipt = """
            {
                "rowId": "row-1",
                "tenantId": "tenant-acme",
                "requestId": "req-1",
                "createdAt": "2026-05-09T12:00:00Z",
                "policyVersion": "walletless-offline-v1",
                "brokerPostVerification": null,
                "envelope": {
                    "kid": "$kid",
                    "signature": "vault:v1:$signature",
                    "canonicalPayload": ${jsonString(canonicalPayload)}
                }
            }
        """.trimIndent()
        val receiptFile = tempDir.resolve("receipt.json").toFile()
        receiptFile.writeText(receipt)

        val (exitCode, out, _) = run(receiptFile.absolutePath, "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("PASS")
        assertThat(out).doesNotContain("OFFLINE_VERIFIED_BROKER_AGREED")
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

    // ── SSO-968 chain-replay tests ──────────────────────────────────────────

    @Test
    fun `chain replay PASSes when every link signature verifies`() {
        // Sign three canonical payloads with the same EC key and serve them
        // via the in-process JWKS server (already running).
        val link1Payload = """{"id":"RETAIL-203"}"""
        val link2Payload = """{"id":"ROAST-W18"}"""
        val link3Payload = """{"id":"PLOT-12"}"""
        val link1Sig = "vault:v1:${sign(link1Payload, keyPair)}"
        val link2Sig = "vault:v1:${sign(link2Payload, keyPair)}"
        val link3Sig = "vault:v1:${sign(link3Payload, keyPair)}"

        val pdf = synthesizeChainPdf(
            mapOf(
                link1Payload to (kid to link1Sig),
                link2Payload to (kid to link2Sig),
                link3Payload to (kid to link3Sig),
            ),
            aggregateVerdict = "VALID",
        )
        val pdfFile = tempDir.resolve("chain.pdf").toFile()
        pdfFile.writeBytes(pdf)

        val (exitCode, out, _) = run(pdfFile.absolutePath, "--chain", "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("Chain: 3 links")
        assertThat(out).contains("Signature: PASS")
        // Aggregate from broker is `VALID`; signature replay aggregate is PASS.
        assertThat(out).contains("Aggregate: VALID")
        assertThat(out).contains("Signature replay: PASS")
        assertThat(out).contains("JWKS source: $jwksUrl")
    }

    @Test
    fun `chain replay reports INVALID_SIGNATURE when one link's signature is tampered`() {
        val link1Payload = """{"id":"RETAIL-203"}"""
        val link2Payload = """{"id":"ROAST-W18"}"""
        // Sign link 1 properly, but use a stale signature for link 2.
        val link1Sig = "vault:v1:${sign(link1Payload, keyPair)}"
        val tamperedSig = "vault:v1:${sign("totally-different", keyPair)}"

        val pdf = synthesizeChainPdf(
            mapOf(
                link1Payload to (kid to link1Sig),
                link2Payload to (kid to tamperedSig),
            ),
            aggregateVerdict = "VALID",
        )
        val pdfFile = tempDir.resolve("chain.pdf").toFile()
        pdfFile.writeBytes(pdf)

        val (exitCode, out, _) = run(pdfFile.absolutePath, "--chain", "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(1)
        assertThat(out).contains("INVALID_SIGNATURE")
        assertThat(out).contains("Signature replay: FAIL")
    }

    @Test
    fun `chain replay --jwks file works fully offline`() {
        val link1Payload = """{"id":"RETAIL-203"}"""
        val link1Sig = "vault:v1:${sign(link1Payload, keyPair)}"

        val pdf = synthesizeChainPdf(
            mapOf(link1Payload to (kid to link1Sig)),
            aggregateVerdict = "VALID",
        )
        val pdfFile = tempDir.resolve("chain.pdf").toFile()
        pdfFile.writeBytes(pdf)

        // Dump the JWKS to a local file so the CLI can read it offline.
        val jwksFile = tempDir.resolve("cached.jwks").toFile()
        jwksFile.writeText(jwksJsonForKey(keyPair, kid))

        // Use a deliberately-broken jwks-url to prove the file path wins.
        val (exitCode, out, _) = run(
            pdfFile.absolutePath,
            "--chain",
            "--jwks-url", "http://127.0.0.1:1/should/not/be/hit",
            "--jwks", jwksFile.absolutePath,
        )

        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("Signature: PASS")
        assertThat(out).contains("Aggregate: VALID")
        // The JWKS source line surfaces the file path, not the URL.
        assertThat(out).contains("JWKS source: ${jwksFile.absolutePath}")
    }

    @Test
    fun `chain replay returns MALFORMED when PDF lacks a manifest`() {
        // A PDF that doesn't carry the `chainManifestB64=` sentinel — e.g.
        // a single-credential receipt or anything else.
        val pdfFile = tempDir.resolve("chain.pdf").toFile()
        pdfFile.writeText("%PDF-1.7\n%not a thoryn chain receipt\n")

        val (exitCode, _, err) = run(pdfFile.absolutePath, "--chain", "--jwks-url", jwksUrl)

        assertThat(exitCode).isEqualTo(3)
        assertThat(err).contains("MALFORMED")
        assertThat(err).contains("Thoryn chain manifest")
    }

    /**
     * Builds a minimal "PDF" that carries the Thoryn chain manifest in its
     * Keywords block. Not a syntactically rigorous PDF — the CLI's
     * manifest extractor scans for the sentinel string anywhere in the
     * file, so any container that embeds the base64 chunk works.
     *
     * The receipt-PDF builder (product-api) is the production path; this
     * synthesizer is a test affordance so the CLI test doesn't need to
     * import OpenPDF.
     */
    private fun synthesizeChainPdf(
        linksByPayload: Map<String, Pair<String, String>>,
        aggregateVerdict: String,
    ): ByteArray {
        val mapper = tools.jackson.databind.json.JsonMapper.builder()
            .addModule(tools.jackson.module.kotlin.kotlinModule())
            .build()
        val links = linksByPayload.entries.mapIndexed { idx, (payload, sigKid) ->
            mapOf(
                "position" to (idx + 1),
                "credentialId" to "link-${idx + 1}",
                "verdict" to "VALID",
                "actionType" to "test",
                "issuerKid" to sigKid.first,
                "issuedAt" to "2026-05-01T00:00:00Z",
                "policyVersion" to "walletless-v1",
                "splitEventId" to null,
                "siblingCount" to null,
                "canonicalPayload" to payload,
                "signature" to sigKid.second,
                "historicalJwksUrl" to jwksUrl,
                "parentsTruncated" to false,
                "remainingDepth" to null,
            )
        }
        val manifest = mapOf(
            "auditRowId" to "row-test",
            "verdict" to aggregateVerdict,
            "depth" to links.size,
            "totalCredentials" to links.size,
            "truncated" to false,
            "historicalJwksUrl" to jwksUrl,
            "links" to links,
        )
        val json = mapper.writeValueAsString(manifest)
        val b64 = Base64.getEncoder().encodeToString(json.toByteArray(Charsets.UTF_8))
        // Minimal PDF-shaped wrapper: starts with %PDF-, carries the sentinel
        // somewhere inside (the CLI's parser only needs the sentinel + b64 +
        // a terminator that's not in the base64 alphabet).
        return ("%PDF-1.7\n/Keywords (chainManifestB64=$b64)\n%EOF\n").toByteArray(Charsets.UTF_8)
    }

    /** Produces a JWKS JSON for [keyPair] under [kid]. */
    private fun jwksJsonForKey(keyPair: KeyPair, kid: String): String {
        val publicKey = keyPair.public as java.security.interfaces.ECPublicKey
        val xBytes = publicKey.w.affineX.toByteArray().let {
            if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
        }.let { padTo32(it) }
        val yBytes = publicKey.w.affineY.toByteArray().let {
            if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
        }.let { padTo32(it) }
        val xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes)
        val yB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes)
        return """{"keys":[{"kty":"EC","crv":"P-256","kid":"$kid","alg":"ES256","x":"$xB64","y":"$yB64"}]}"""
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
