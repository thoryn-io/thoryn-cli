package com.devnow.thoryn.cli.cmd.examples.recipe

import tools.jackson.databind.JsonNode
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/**
 * SSO-2878 — verifies an ES256 **detached JWS** attestation offline against a JWKS, using only the JDK
 * (`SHA256withECDSA`) — no Nimbus, so the CLI's GraalVM native image is unaffected. Mirrors the
 * ES256/JWK reconstruction the `audit-replay` command already uses; adds the JOSE-`R||S`→DER conversion
 * a compact JWS signature needs (Vault-format audit signatures were already DER).
 */
internal object Es256JwsVerifier {

    enum class Status { PASS, INVALID, UNVERIFIABLE }

    /**
     * Verify [signature] (a detached JWS `header..sig`) over the payload whose base64url is
     * [canonicalPayloadB64], against the key [kid] in [jwks].
     */
    fun verify(jwks: JsonNode, kid: String, signature: String, canonicalPayloadB64: String): Status {
        val key = findKey(jwks, kid) ?: return Status.UNVERIFIABLE
        val parts = signature.split(".")
        if (parts.size != 3 || parts[0].isEmpty()) return Status.UNVERIFIABLE
        val signingInput = "${parts[0]}.$canonicalPayloadB64".toByteArray(Charsets.US_ASCII)
        val der = joseToDer(runCatching { Base64.getUrlDecoder().decode(parts[2]) }.getOrNull() ?: return Status.INVALID)
            ?: return Status.INVALID
        return try {
            val v = Signature.getInstance("SHA256withECDSA")
            v.initVerify(key)
            v.update(signingInput)
            if (v.verify(der)) Status.PASS else Status.INVALID
        } catch (_: Exception) {
            Status.INVALID
        }
    }

    private fun findKey(jwks: JsonNode, kid: String): PublicKey? {
        val keys = jwks["keys"]?.takeIf { it.isArray } ?: return null
        val jwk = keys.firstOrNull { it["kid"]?.asString() == kid } ?: return null
        return jwkToEcPublicKey(jwk)
    }

    private fun jwkToEcPublicKey(jwk: JsonNode): PublicKey? {
        if (jwk["crv"]?.asString() != "P-256") return null
        val x = jwk["x"]?.asString() ?: return null
        val y = jwk["y"]?.asString() ?: return null
        return try {
            val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            val ecParams = params.getParameterSpec(ECParameterSpec::class.java)
            val point = ECPoint(BigInteger(1, Base64.getUrlDecoder().decode(x)), BigInteger(1, Base64.getUrlDecoder().decode(y)))
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, ecParams))
        } catch (_: Exception) {
            null
        }
    }

    /** Convert a JOSE P-256 signature (`R||S`, 64 bytes) to the DER encoding JDK's verifier expects. */
    private fun joseToDer(raw: ByteArray): ByteArray? {
        if (raw.size != 64) return null
        val r = toDerInteger(raw.copyOfRange(0, 32))
        val s = toDerInteger(raw.copyOfRange(32, 64))
        val body = r + s
        return byteArrayOf(0x30) + derLength(body.size) + body
    }

    /** Encode a big-endian unsigned magnitude as a DER INTEGER (strip leading zeros; add one if MSB set). */
    private fun toDerInteger(mag: ByteArray): ByteArray {
        var i = 0
        while (i < mag.size - 1 && mag[i].toInt() == 0) i++
        var trimmed = mag.copyOfRange(i, mag.size)
        if (trimmed[0].toInt() and 0x80 != 0) trimmed = byteArrayOf(0) + trimmed
        return byteArrayOf(0x02) + derLength(trimmed.size) + trimmed
    }

    private fun derLength(len: Int): ByteArray =
        if (len < 0x80) byteArrayOf(len.toByte()) else byteArrayOf(0x81.toByte(), len.toByte())
}
