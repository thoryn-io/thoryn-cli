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
import kotlin.system.measureTimeMillis

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
 * - `OFFLINE_VERIFIED_BROKER_AGREED` (SSO-952) — same crypto as `PASS`,
 *   but the row's `policyVersion = walletless-offline-v1` AND
 *   `brokerPostVerification = MATCH`. This is the queued-offline path:
 *   apps/scan verified the credential locally while disconnected, then
 *   on reconnect the broker's live re-check agreed with the device's
 *   outcome. Distinguishable from `PASS` so a regulator can tell which
 *   audit rows came from queued evidence and which came from the live
 *   online path.
 * - `INVALID_SIGNATURE` — kid found in JWKS but signature does not
 *   verify. The row was tampered (column changed) or the receipt was
 *   modified after issuance.
 * - `UNVERIFIABLE` — kid not found in JWKS, or receipt envelope is
 *   missing signature/kid (the row was unsigned at write time, e.g.
 *   Vault-down failure-open path).
 * - `MALFORMED` — receipt JSON is not the expected shape.
 *
 * **Exit codes**: `0` on PASS / OFFLINE_VERIFIED_BROKER_AGREED;
 * `1` on INVALID_SIGNATURE; `2` on UNVERIFIABLE; `3` on MALFORMED.
 * Distinct codes so CI / scripts can branch.
 *
 * **No bearer token required.** The historical JWKS endpoint is
 * public (per the audit-chain ADR's *Broker key rotation* section);
 * the receipt was already retrieved via an authenticated call, but
 * the verification step itself is bearer-free. A regulator can run
 * `thoryn audit-replay` with no Thoryn credentials.
 *
 * **Note on queued-offline rows.** Rows produced by the apps/scan
 * offline path are signed with the device's per-deploy ECDSA key (kid
 * `device:<deviceKid>`), NOT with the broker's audit-log signing key.
 * The replay tool's signature-verify step works the same regardless —
 * the historical JWKS endpoint is expected to surface device public
 * keys alongside the broker's, indexed by kid. (If a queued row's kid
 * resolves to UNVERIFIABLE, the device key has been retired beyond the
 * retention horizon — same reasoning as broker-key rotation.)
 */
@Command(
    name = "audit-replay",
    description = ["Verify a stored audit-row receipt offline against the broker's historical JWKS."],
    mixinStandardHelpOptions = true,
)
class AuditReplayCommand : Callable<Int> {

    @Parameters(
        index = "0",
        description = [
            "Path to the receipt JSON file (single-credential mode), or to a chain receipt PDF " +
                "(use with --chain).",
        ],
    )
    lateinit var receiptFile: File

    @Option(
        names = ["--jwks-url"],
        description = ["Broker historical JWKS URL (default: \${DEFAULT-VALUE})."],
        defaultValue = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json",
    )
    var jwksUrl: String = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json"

    @Option(
        names = ["--chain"],
        description = [
            "SSO-968: walk the chain-of-custody embedded in a receipt PDF instead of " +
                "verifying a single receipt JSON. The argument becomes a PDF path. " +
                "Streams PASS/FAIL per link and prints an aggregate verdict.",
        ],
    )
    var chainMode: Boolean = false

    @Option(
        names = ["--jwks"],
        description = [
            "SSO-968: fully-offline JWKS source. Reads the JWKS JSON from this file " +
                "instead of fetching it over the network. Combine with --chain for an " +
                "air-gapped chain replay.",
        ],
    )
    var jwksFile: File? = null

    private val mapper = JsonMapper.builder()
        .addModule(kotlinModule())
        .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
        .build()

    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    override fun call(): Int {
        if (chainMode) {
            return chainReplay()
        }
        val receipt = parseReceipt() ?: return 3
        val sig = receipt.envelope?.signature
        val kid = receipt.envelope?.kid
        val canonicalPayload = receipt.envelope?.canonicalPayload

        if (sig == null || kid == null || canonicalPayload == null) {
            println("UNVERIFIABLE: receipt envelope is missing signature, kid, or canonicalPayload (the row was unsigned at write time — Vault was likely unreachable).")
            return 2
        }

        val jwks = loadJwks() ?: run {
            println("UNVERIFIABLE: failed to load historical JWKS (source: ${jwksSource()})")
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
            // SSO-952: distinguish queued-offline rows from the live online
            // path. A row whose policyVersion is walletless-offline-v1 AND
            // whose brokerPostVerification is MATCH represents the device's
            // offline outcome cross-checked against the broker's live
            // re-check on flush — different evidentiary class than PASS.
            val isQueuedOffline = receipt.policyVersion == "walletless-offline-v1" &&
                receipt.brokerPostVerification == "MATCH"
            val outcome = if (isQueuedOffline) "OFFLINE_VERIFIED_BROKER_AGREED" else "PASS"
            println(outcome)
            println("  rowId                    = ${receipt.rowId}")
            println("  tenantId                 = ${receipt.tenantId ?: "(none)"}")
            println("  requestId                = ${receipt.requestId}")
            println("  createdAt                = ${receipt.createdAt}")
            println("  signingKid               = $kid")
            if (receipt.policyVersion != null) {
                println("  policyVersion            = ${receipt.policyVersion}")
            }
            if (receipt.brokerPostVerification != null) {
                println("  brokerPostVerification   = ${receipt.brokerPostVerification}")
            }
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

    /**
     * SSO-968: when `--jwks <file>` is supplied, the JWKS comes from disk
     * (fully-offline replay). Otherwise we fetch from `--jwks-url`. The
     * chain-replay path uses the same source to verify every link, so an
     * air-gapped operator passes one cached JWKS for the whole walk.
     */
    private fun loadJwks(): JsonNode? {
        val file = jwksFile
        if (file != null) {
            if (!file.exists() || !file.canRead()) {
                System.err.println("JWKS file not readable: ${file.absolutePath}")
                return null
            }
            return try {
                mapper.readTree(file)
            } catch (ex: Exception) {
                System.err.println("JWKS file parse failed: ${ex.message}")
                null
            }
        }
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

    private fun jwksSource(): String = jwksFile?.absolutePath ?: jwksUrl

    /**
     * SSO-968 — chain-replay mode. Parses the PDF's `chainManifestB64=` block
     * from the Keywords metadata field (the receipt-PDF builder embeds it
     * there for every chain receipt), iterates each link, and verifies its
     * signature against the JWKS source. Streams PASS/FAIL per link and prints
     * an aggregate verdict at the end.
     *
     * Exit codes mirror the single-link path:
     *  0 — aggregate PASS
     *  1 — at least one INVALID_SIGNATURE
     *  2 — at least one UNVERIFIABLE (and no INVALID_SIGNATURE)
     *  3 — manifest MALFORMED
     */
    private fun chainReplay(): Int {
        val pdfBytes = readPdfBytes() ?: return 3
        val manifest = extractChainManifest(pdfBytes) ?: run {
            System.err.println(
                "MALFORMED: could not find Thoryn chain manifest inside the PDF. " +
                    "Ensure the file was produced by `GET /api/v1/audit-log/{id}/receipt.pdf?includeChain=true`.",
            )
            return 3
        }
        val jwks = loadJwks() ?: run {
            println("UNVERIFIABLE: failed to load JWKS (source: ${jwksSource()})")
            return 2
        }

        val totalLinks = manifest["links"]?.takeIf { it.isArray() }?.let { it.size() } ?: 0
        val depth = manifest["depth"]?.asInt() ?: 0
        val aggregate = manifest["verdict"]?.asString() ?: "UNKNOWN"
        val auditRowId = manifest["auditRowId"]?.asString() ?: "(unknown)"
        val truncated = manifest["truncated"]?.asBoolean() ?: false

        println("Chain: $totalLinks links, depth=$depth, auditRowId=$auditRowId")
        if (truncated) {
            println("  (truncated — broker walk hit depth/fan cap; verification covers visible portion only)")
        }

        var anyInvalid = false
        var anyUnverifiable = false
        val replayMs = measureTimeMillis {
            for (entry in manifest["links"] ?: mapper.createArrayNode()) {
                val pos = entry["position"]?.asInt() ?: -1
                val credentialId = entry["credentialId"]?.asString() ?: "(unknown)"
                val verdict = entry["verdict"]?.asString() ?: "(none)"
                val actionType = entry["actionType"]?.asString() ?: "—"
                val kid = entry["issuerKid"]?.asString()
                val signature = entry["signature"]?.asString()
                val canonicalPayload = entry["canonicalPayload"]?.asString()
                val outcome = verifyLink(jwks, kid, signature, canonicalPayload)
                println("  [%02d] %s — verdict=%s action=%s · Signature: %s".format(pos, credentialId, verdict, actionType, outcome))
                when (outcome) {
                    "INVALID_SIGNATURE" -> anyInvalid = true
                    "UNVERIFIABLE", "MALFORMED" -> anyUnverifiable = true
                }
            }
        }

        // Aggregate verdict from the manifest (broker-side computed) +
        // per-link signature outcomes (CLI-side recomputed). Any link signature
        // failure dominates the print-side aggregate; we still surface the
        // broker's aggregate verdict so the operator sees both.
        val signatureAggregate = when {
            anyInvalid -> "FAIL (INVALID_SIGNATURE)"
            anyUnverifiable -> "INCOMPLETE (UNVERIFIABLE links)"
            else -> "PASS"
        }
        println()
        println("Aggregate: $aggregate (broker verdict)")
        println("Signature replay: $signatureAggregate")
        println("Replay time: ${"%.1f".format(replayMs / 1000.0)}s")
        println("JWKS source: ${jwksSource()}")

        return when {
            anyInvalid -> 1
            anyUnverifiable -> 2
            else -> 0
        }
    }

    private fun readPdfBytes(): ByteArray? {
        if (!receiptFile.exists() || !receiptFile.canRead()) {
            System.err.println("Cannot read receipt PDF: ${receiptFile.absolutePath}")
            return null
        }
        return try {
            receiptFile.readBytes()
        } catch (ex: Exception) {
            System.err.println("Cannot read receipt PDF: ${ex.message}")
            null
        }
    }

    /**
     * Parses the Thoryn chain manifest from a PDF. The receipt-PDF builder
     * embeds a JSON manifest as base64 in the PDF's `Keywords` metadata field
     * behind the `chainManifestB64=` sentinel. The CLI scans the PDF bytes
     * for that sentinel and decodes the base64 chunk — no PDF library
     * required, keeps the GraalVM native-image footprint small.
     */
    private fun extractChainManifest(pdfBytes: ByteArray): JsonNode? {
        val asLatin1 = pdfBytes.toString(Charsets.ISO_8859_1)
        val idx = asLatin1.indexOf(CHAIN_MANIFEST_SENTINEL)
        if (idx < 0) return null
        val start = idx + CHAIN_MANIFEST_SENTINEL.length
        // Base64 alphabet is `[A-Za-z0-9+/=]` — stop at the first byte that's
        // not part of it. The receipt-PDF builder writes the manifest at the
        // end of the Keywords field so the terminator is a `)` or whitespace.
        val end = (start until asLatin1.length).firstOrNull { i ->
            val c = asLatin1[i]
            !(c.isLetterOrDigit() || c == '+' || c == '/' || c == '=')
        } ?: asLatin1.length
        val b64 = asLatin1.substring(start, end)
        if (b64.isEmpty()) return null
        return try {
            val json = String(Base64.getDecoder().decode(b64), Charsets.UTF_8)
            mapper.readTree(json)
        } catch (ex: Exception) {
            System.err.println("MALFORMED: chain manifest base64/JSON parse failed: ${ex.message}")
            null
        }
    }

    private fun verifyLink(
        jwks: JsonNode,
        kid: String?,
        signature: String?,
        canonicalPayload: String?,
    ): String {
        if (kid == null || signature == null || canonicalPayload == null) {
            return "UNVERIFIABLE (kid/signature/canonical missing)"
        }
        val key = findKeyByKid(jwks, kid) ?: return "UNVERIFIABLE (kid not in JWKS)"
        val der = decodeVaultSignature(signature) ?: return "MALFORMED (signature format)"
        val verifier = java.security.Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key)
        verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        return try {
            if (verifier.verify(der)) "PASS" else "INVALID_SIGNATURE"
        } catch (_: Exception) {
            "INVALID_SIGNATURE"
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

    companion object {
        /**
         * Sentinel for the chain manifest embedded in the PDF's Keywords field.
         * Must stay in sync with
         * `com.devnow.productapi.supplychain.audit.ReceiptPdfBuilder.chainManifestSentinel`.
         */
        internal const val CHAIN_MANIFEST_SENTINEL: String = "chainManifestB64="
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
    /**
     * SSO-952: post-flush re-check outcome for queued offline-mode
     * verifications. Null on rows produced by the live online path.
     * `MATCH` / `DISAGREE` for rows from `POST /broker/verify/walletless/queued`.
     */
    val brokerPostVerification: String? = null,
    val envelope: AuditReceiptEnvelopeDto? = null,
)

data class AuditReceiptEnvelopeDto(
    val kid: String? = null,
    val signature: String? = null,
    val canonicalPayload: String? = null,
)
