package com.devnow.thoryn.cli.cmd

import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.SerializationFeature
import tools.jackson.module.kotlin.kotlinModule
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import java.util.Base64
import java.util.concurrent.Callable

/**
 * `thoryn audit-replay <receipt.json>` — verifies a stored audit-row
 * receipt offline against the broker's published historical JWKS.
 *
 * SSO-940b. Companion to SSO-940a's broker endpoints
 * (`GET /admin/audit-logs/{rowId}/receipt` and
 * `GET /.well-known/historical-jwks.json`).
 *
 * **Outcomes** (per the audit-chain ADR's *Why JWS over the row*):
 * - `PASS` — receipt's signature verifies against the looked-up
 *   public key over the canonical payload. The row is genuine, signed
 *   by the broker, untampered.
 * - `INVALID_SIGNATURE` — kid found in JWKS but signature does not
 *   verify. The row was tampered (column changed) or the receipt was
 *   modified after issuance.
 * - `UNVERIFIABLE` — kid not found in JWKS, or receipt envelope is
 *   missing signature/kid (the row was unsigned at write time, e.g.
 *   Vault-down failure-open path).
 * - `MALFORMED` — receipt JSON is not the expected shape.
 *
 * **Exit codes**: `0` on PASS; `1` on INVALID_SIGNATURE; `2` on
 * UNVERIFIABLE; `3` on MALFORMED. Distinct codes so CI / scripts can
 * branch.
 *
 * **No bearer token required.** The historical JWKS endpoint is
 * public (per the audit-chain ADR's *Broker key rotation* section);
 * the receipt was already retrieved via an authenticated call, but
 * the verification step itself is bearer-free. A regulator can run
 * `thoryn audit-replay` with no Lintel credentials.
 */
@Command(
    name = "audit-replay",
    description = ["Verify a stored audit-row receipt offline against the broker's historical JWKS."],
    mixinStandardHelpOptions = true,
)
class AuditReplayCommand : Callable<Int> {

    @Parameters(
        index = "0",
        description = ["Path to the receipt JSON file (as returned by GET /admin/audit-logs/{rowId}/receipt)."],
    )
    lateinit var receiptFile: File

    @Option(
        names = ["--jwks-url"],
        description = ["Broker historical JWKS URL (default: \${DEFAULT-VALUE})."],
        defaultValue = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json",
    )
    var jwksUrl: String = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json"

    private val mapper = JsonMapper.builder()
        .addModule(kotlinModule())
        .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
        .build()

    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    override fun call(): Int {
        val receipt = parseReceipt() ?: return 3
        val sig = receipt.envelope?.signature
        val kid = receipt.envelope?.kid
        val canonicalPayload = receipt.envelope?.canonicalPayload

        if (sig == null || kid == null || canonicalPayload == null) {
            println("UNVERIFIABLE: receipt envelope is missing signature, kid, or canonicalPayload (the row was unsigned at write time — Vault was likely unreachable).")
            return 2
        }

        val jwks = fetchJwks() ?: run {
            println("UNVERIFIABLE: failed to fetch historical JWKS from $jwksUrl")
            return 2
        }

        val publicKey = findKeyByKid(jwks, kid) ?: run {
            println("UNVERIFIABLE: kid '$kid' not found in historical JWKS at $jwksUrl. The key may have been retired beyond the retention horizon.")
            return 2
        }

        val derBytes = decodeVaultSignature(sig) ?: run {
            println("MALFORMED: signature is not in the expected vault:vN:<base64> format.")
            return 3
        }

        val verifier = java.security.Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        val ok = try {
            verifier.verify(derBytes)
        } catch (ex: Exception) {
            // SignatureException → DER-decoding failure usually means the
            // signature bytes are malformed. Treat as INVALID, not
            // UNVERIFIABLE, because the kid was found.
            println("INVALID_SIGNATURE: signature failed to decode/verify: ${ex.message}")
            return 1
        }

        return if (ok) {
            println("PASS")
            println("  rowId       = ${receipt.rowId}")
            println("  tenantId    = ${receipt.tenantId ?: "(none)"}")
            println("  requestId   = ${receipt.requestId}")
            println("  createdAt   = ${receipt.createdAt}")
            println("  signingKid  = $kid")
            0
        } else {
            println("INVALID_SIGNATURE: kid '$kid' resolves to a public key, but the signature does not verify over the canonical payload. The row may have been tampered with after signing.")
            1
        }
    }

    private fun parseReceipt(): AuditReceiptDto? {
        if (!receiptFile.exists() || !receiptFile.canRead()) {
            System.err.println("Cannot read receipt file: ${receiptFile.absolutePath}")
            return null
        }
        val parsed: AuditReceiptDto = try {
            mapper.readValue(receiptFile, AuditReceiptDto::class.java)
        } catch (ex: Exception) {
            System.err.println("MALFORMED: receipt is not valid JSON / does not match the expected shape: ${ex.message}")
            return null
        }
        // Cheapest possible "this is shaped like a receipt" gate — without a
        // rowId we have nothing useful to surface even on success. Treat as
        // MALFORMED rather than UNVERIFIABLE to keep the exit-code semantics
        // tight ("did the file parse" vs. "was the verification possible").
        if (parsed.rowId.isNullOrBlank() || parsed.envelope == null) {
            System.err.println("MALFORMED: receipt is missing rowId or envelope.")
            return null
        }
        return parsed
    }

    private fun fetchJwks(): JsonNode? {
        return try {
            val response = http.send(
                HttpRequest.newBuilder(URI.create(jwksUrl))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString(),
            )
            if (response.statusCode() != 200) {
                System.err.println("JWKS fetch failed: HTTP ${response.statusCode()} from $jwksUrl")
                return null
            }
            mapper.readTree(response.body())
        } catch (ex: Exception) {
            System.err.println("JWKS fetch failed: ${ex.message}")
            null
        }
    }

    private fun findKeyByKid(jwks: JsonNode, kid: String): java.security.PublicKey? {
        val keys = jwks["keys"] ?: return null
        if (!keys.isArray()) return null
        for (key in keys) {
            if (key["kid"]?.asText() == kid) {
                return jwkToEcPublicKey(key)
            }
        }
        return null
    }

    /**
     * Reconstruct a P-256 [java.security.interfaces.ECPublicKey] from the
     * JWK fields `x` and `y`. Mirrors the inverse of the broker's
     * `BrokerAuditJwksService.parsePemToEcdsaJwk` (which encoded a
     * `ECPublicKey` as a JWK). We don't depend on Nimbus here — the CLI
     * is GraalVM-native-image-bound and Nimbus's reflection footprint is
     * heavy; a hand-rolled reconstruction stays small.
     */
    private fun jwkToEcPublicKey(key: JsonNode): java.security.PublicKey? {
        val xB64 = key["x"]?.asText() ?: return null
        val yB64 = key["y"]?.asText() ?: return null
        val crv = key["crv"]?.asText() ?: return null
        if (crv != "P-256") return null
        val xBytes = Base64.getUrlDecoder().decode(xB64)
        val yBytes = Base64.getUrlDecoder().decode(yB64)
        val params = java.security.AlgorithmParameters.getInstance("EC")
        params.init(java.security.spec.ECGenParameterSpec("secp256r1"))
        val ecParams = params.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        val point = java.security.spec.ECPoint(
            java.math.BigInteger(1, xBytes),
            java.math.BigInteger(1, yBytes),
        )
        val keySpec = java.security.spec.ECPublicKeySpec(point, ecParams)
        return KeyFactory.getInstance("EC").generatePublic(keySpec)
    }

    private fun decodeVaultSignature(sig: String): ByteArray? {
        val regex = Regex("^vault:v\\d+:")
        val base64 = if (regex.containsMatchIn(sig)) sig.replaceFirst(regex, "") else return null
        return try {
            Base64.getDecoder().decode(base64)
        } catch (_: Exception) {
            null
        }
    }
}

/**
 * Wire shape that mirrors the broker's `AuditReceipt`. Inlined here so
 * the CLI doesn't have a compile-time dependency on the broker module.
 */
data class AuditReceiptDto(
    val rowId: String? = null,
    val tenantId: String? = null,
    val requestId: String? = null,
    val createdAt: String? = null,
    val credentialHashes: String? = null,
    val issuerKeyKids: String? = null,
    val policyVersion: String? = null,
    val retentionHorizon: String? = null,
    val envelope: AuditReceiptEnvelopeDto? = null,
)

data class AuditReceiptEnvelopeDto(
    val kid: String? = null,
    val signature: String? = null,
    val canonicalPayload: String? = null,
)
