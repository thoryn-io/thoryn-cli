package com.devnow.thoryn.cli.auth

import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * SSO-2879 — signs an RFC 7523 §2.2 `private_key_jwt` CLIENT ASSERTION with an EC P-256 (ES256)
 * private key, using ONLY the JDK (`SHA256withECDSA`) — no Nimbus, so the CLI's GraalVM native
 * image is unaffected (mirrors [com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier], which
 * does the inverse JOSE-`R||S`<->DER conversion for verification).
 *
 * The assertion is the credential the conformance-CI exchange client presents to the hub's token
 * endpoint. The hub validates it (RFC 7523 §3) against the client's INLINE public JWKS
 * (`client.jwks`, seeded by hub migration V143): signature (ES256), `iss == sub == client_id`,
 * `aud` = the hub's DEFAULT-issuer token endpoint, `exp` present + timestamp window.
 *
 * The private key is supplied as an unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`), the
 * shape `openssl pkcs8` / most keygen tooling emits for an EC key. It is read from an env var /
 * file by the caller (never argv) and used only to sign — never logged or persisted.
 */
class EcPrivateKeyJwtSigner(
    /** Unencrypted PKCS#8 PEM of the EC P-256 signing key. */
    privateKeyPem: String,
    /** The `kid` stamped into the JWS header so the hub selects the matching public JWK. */
    private val keyId: String,
    private val clock: () -> Instant = { Instant.now() },
    private val jtiSource: () -> String = { UUID.randomUUID().toString() },
) {

    private val privateKey = parsePkcs8EcPrivateKey(privateKeyPem)

    /**
     * Build and sign the client assertion for [clientId] bound to [audience] (the hub token
     * endpoint). `iss == sub == client_id` per RFC 7523 §3; `exp = now + [ttlSeconds]`.
     */
    fun sign(clientId: String, audience: String, ttlSeconds: Long = 60L): String {
        val now = clock().epochSecond
        val header = """{"alg":"ES256","typ":"JWT","kid":${jsonString(keyId)}}"""
        val claims = buildString {
            append('{')
            append("\"iss\":").append(jsonString(clientId)).append(',')
            append("\"sub\":").append(jsonString(clientId)).append(',')
            append("\"aud\":").append(jsonString(audience)).append(',')
            append("\"jti\":").append(jsonString(jtiSource())).append(',')
            append("\"iat\":").append(now).append(',')
            append("\"exp\":").append(now + ttlSeconds)
            append('}')
        }
        val signingInput = "${b64u(header.toByteArray(Charsets.UTF_8))}.${b64u(claims.toByteArray(Charsets.UTF_8))}"
        val signature = ecdsaEs256(signingInput.toByteArray(Charsets.US_ASCII))
        return "$signingInput.${b64u(signature)}"
    }

    /** Sign [data] with SHA256withECDSA and convert the DER output to the JOSE `R||S` (64-byte) form. */
    private fun ecdsaEs256(data: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(data)
        return derToJose(signer.sign())
    }

    companion object {
        private fun b64u(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        /** Minimal JSON string escaping — key ids / client ids are simple, but be correct anyway. */
        private fun jsonString(s: String): String {
            val sb = StringBuilder("\"")
            for (c in s) {
                when (c) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
                }
            }
            return sb.append('"').toString()
        }

        private fun parsePkcs8EcPrivateKey(pem: String): java.security.PrivateKey {
            val body = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace(Regex("\\s"), "")
            require(body.isNotBlank()) { "private key PEM is empty or not PKCS#8 (expected -----BEGIN PRIVATE KEY-----)" }
            val der = try {
                Base64.getDecoder().decode(body)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("private key PEM body is not valid base64: ${e.message}", e)
            }
            return try {
                KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (e: Exception) {
                throw IllegalArgumentException("could not parse EC P-256 PKCS#8 private key: ${e.message}", e)
            }
        }

        /**
         * Convert a DER-encoded ECDSA signature (SEQUENCE{INTEGER r, INTEGER s}) to the JOSE
         * fixed-width `R||S` (64-byte, P-256) form a compact JWS carries. Inverse of
         * [com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier.joseToDer].
         */
        internal fun derToJose(der: ByteArray): ByteArray {
            var offset = 0
            require(der.size >= 8 && der[offset].toInt() and 0xff == 0x30) { "not a DER SEQUENCE" }
            offset++
            // SEQUENCE length (short or one-byte long form — an ECDSA P-256 sig is well under 128 body bytes,
            // but 0x81 long-form can appear when r/s each need a leading zero pad).
            if (der[offset].toInt() and 0xff == 0x81) offset++
            offset++ // skip the length byte itself
            val r = readDerInteger(der, offset).also { offset = it.second }.first
            val s = readDerInteger(der, offset).first
            val out = ByteArray(64)
            copyFixed(r, out, 0)
            copyFixed(s, out, 32)
            return out
        }

        private fun readDerInteger(der: ByteArray, start: Int): Pair<ByteArray, Int> {
            var offset = start
            require(der[offset].toInt() and 0xff == 0x02) { "expected DER INTEGER" }
            offset++
            val len = der[offset].toInt() and 0xff
            offset++
            val value = der.copyOfRange(offset, offset + len)
            return value to (offset + len)
        }

        /** Right-align a big-endian magnitude (which may carry a DER leading-zero sign byte) into [out] at [pos]. */
        private fun copyFixed(magnitude: ByteArray, out: ByteArray, pos: Int) {
            val unsigned = BigInteger(1, magnitude).toByteArray().let {
                if (it.size > 1 && it[0].toInt() == 0) it.copyOfRange(1, it.size) else it
            }
            require(unsigned.size <= 32) { "ECDSA integer wider than 32 bytes — not a P-256 signature" }
            System.arraycopy(unsigned, 0, out, pos + (32 - unsigned.size), unsigned.size)
        }
    }
}
