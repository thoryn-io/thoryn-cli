package com.devnow.thoryn.cli.auth

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64

/**
 * SSO-3199 — the CLI's **per-installation DPoP key pair** (RFC 9449), an EC P-256 / ES256 key used to
 * sign DPoP proof JWTs.
 *
 * Crypto is JDK-only (`EC` + `SHA256withECDSA`), like [EcPrivateKeyJwtSigner] and
 * [com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier] — no Nimbus, so the GraalVM native
 * image is unaffected and the CLI gains no new dependency.
 *
 * The key is generated once on first use and persisted through [DpopKeyStore] (the OS keychain; the
 * chmod-0600 file store only under the CI opt-in). **The private key never leaves this process**: it
 * is never printed, never written to a receipt, and never sent anywhere — only the PUBLIC JWK travels,
 * inside the proof's `jwk` header.
 *
 * [thumbprint] is the RFC 7638 JWK thumbprint (base64url SHA-256 over the canonical
 * `{"crv","kty","x","y"}` JSON), i.e. exactly the value the hub mints into the access token's
 * `cnf.jkt` claim (`DpopAccessTokenCustomizer`, oathy) and the value `thoryn whoami` prints.
 */
class DpopKey internal constructor(
    /**
     * SSO-3227 — where the private key lives. [SoftwareDpopSigner] holds a JDK `PrivateKey`; a
     * secure-element signer holds only an opaque OS handle and signs behind a user-presence check.
     */
    internal val signer: DpopSigner,
    private val publicKey: ECPublicKey,
    /** When this installation's key was generated — surfaced by `thoryn whoami`, never a secret. */
    val createdAt: Instant,
    /** SSO-3227 — the protection class this key actually has. Reported by `whoami` / `status`. */
    val keyClass: DpopKeyClass = DpopKeyClass.SOFTWARE_KEYCHAIN,
) {

    /** The public JWK, in RFC 7638 canonical member order, as it rides in the proof's `jwk` header. */
    val publicJwkJson: String = canonicalJwk(publicKey)

    /** RFC 7638 JWK thumbprint (`jkt`) — what the hub binds into `cnf.jkt`. */
    val thumbprint: String =
        b64u(MessageDigest.getInstance("SHA-256").digest(publicJwkJson.toByteArray(Charsets.UTF_8)))

    /**
     * Serialise for [DpopKeyStore]. Contains the PRIVATE key — only ever handed to the secure store.
     *
     * Only a software key can be serialised: a secure-element key is non-exportable by construction,
     * which is the entire point of [DpopKeyClass.SECURE_ELEMENT]. Calling this on one is a programming
     * error, not a runtime condition — the hardware provider persists nothing through [DpopKeyStore].
     */
    internal fun toStored(): StoredDpopKey {
        val software = signer as? SoftwareDpopSigner
            ?: error("a ${keyClass.wireValue} DPoP key is non-exportable and cannot be written to the key store")
        return StoredDpopKey(
            privateKeyPkcs8 = Base64.getEncoder().encodeToString(software.privateKey.encoded),
            publicKeyX509 = Base64.getEncoder().encodeToString(publicKey.encoded),
            createdAtEpochSecond = createdAt.epochSecond,
        )
    }

    /**
     * Sign a compact JWS over [headerJson] / [claimsJson] with ES256, returning
     * `base64url(header).base64url(claims).base64url(R||S)`.
     */
    internal fun signCompact(headerJson: String, claimsJson: String): String {
        val signingInput = "${b64u(headerJson.toByteArray(Charsets.UTF_8))}.${b64u(claimsJson.toByteArray(Charsets.UTF_8))}"
        // Reuse the DER → JOSE (R||S) conversion the RFC 7523 client-assertion signer already carries.
        // Both the JDK provider and SecKeyCreateSignature emit ASN.1 DER, so one conversion serves both.
        val jose = EcPrivateKeyJwtSigner.derToJose(signer.signDer(signingInput.toByteArray(Charsets.US_ASCII)))
        return "$signingInput.${b64u(jose)}"
    }

    companion object {

        /** Generate a fresh P-256 key pair for this installation. */
        fun generate(now: Instant = Instant.now()): DpopKey {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val pair = generator.generateKeyPair()
            return DpopKey(SoftwareDpopSigner(pair.private), pair.public as ECPublicKey, now)
        }

        /**
         * SSO-3227 — wrap a key whose private half lives in a secure element: this process holds only
         * the public point and a [signer] that asks the OS (and the user) for each signature.
         */
        internal fun hardware(
            signer: DpopSigner,
            publicKey: ECPublicKey,
            createdAt: Instant,
            keyClass: DpopKeyClass = DpopKeyClass.SECURE_ELEMENT,
        ): DpopKey = DpopKey(signer, publicKey, createdAt, keyClass)

        /** Rehydrate a key persisted by [toStored]. Throws [IllegalArgumentException] on a corrupt record. */
        internal fun fromStored(stored: StoredDpopKey): DpopKey = try {
            val factory = KeyFactory.getInstance("EC")
            val private = factory.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(stored.privateKeyPkcs8)))
            val public = factory.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(stored.publicKeyX509)))
            DpopKey(
                SoftwareDpopSigner(private),
                public as ECPublicKey,
                Instant.ofEpochSecond(stored.createdAtEpochSecond),
                DpopKeyClass.SOFTWARE_KEYCHAIN,
            )
        } catch (e: Exception) {
            throw IllegalArgumentException("stored DPoP key could not be parsed: ${e.message}", e)
        }

        /**
         * SSO-3227 — rebuild a P-256 public key from the ANSI X9.63 uncompressed point
         * (`0x04 || X || Y`, 65 bytes) that `SecKeyCopyExternalRepresentation` hands back for a Secure
         * Enclave key. The JDK has no decoder for that bare form, so wrap it in a SubjectPublicKeyInfo
         * whose AlgorithmIdentifier is the fixed `id-ecPublicKey` + `prime256v1` prefix below and let
         * [KeyFactory] parse it — 26 constant bytes instead of a third-party ASN.1 dependency.
         */
        internal fun publicKeyFromX963(point: ByteArray): ECPublicKey {
            require(point.size == 65 && point[0].toInt() == 0x04) {
                "expected a 65-byte uncompressed P-256 point (0x04 || X || Y), got ${point.size} bytes"
            }
            return KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(P256_SPKI_PREFIX + point)) as ECPublicKey
        }

        /**
         * `SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 }, BIT STRING (66 bytes) }` — the
         * constant SubjectPublicKeyInfo header that precedes an uncompressed P-256 point.
         */
        private val P256_SPKI_PREFIX: ByteArray = byteArrayOf(
            0x30, 0x59, //                                              SEQUENCE, 89 bytes
            0x30, 0x13, //                                              SEQUENCE, 19 bytes
            0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
            0x03, 0x42, 0x00, //                                        BIT STRING, 66 bytes, 0 unused
        )

        internal fun b64u(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        /**
         * The RFC 7638 canonical JWK for an EC public key: exactly the required members
         * (`crv`, `kty`, `x`, `y`), lexicographically ordered, no whitespace. Used verbatim both as
         * the proof's `jwk` header value and as the thumbprint input — so the `jkt` the CLI prints is
         * provably the one the hub computes from the proof it received.
         */
        private fun canonicalJwk(publicKey: ECPublicKey): String {
            val fieldSize = 32 // P-256
            val x = b64u(unsignedFixed(publicKey.w.affineX.toByteArray(), fieldSize))
            val y = b64u(unsignedFixed(publicKey.w.affineY.toByteArray(), fieldSize))
            return """{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}"""
        }

        /** Left-pad / strip the BigInteger sign byte so a coordinate is exactly [size] bytes. */
        private fun unsignedFixed(magnitude: ByteArray, size: Int): ByteArray {
            val trimmed = if (magnitude.size > size && magnitude[0].toInt() == 0) {
                magnitude.copyOfRange(magnitude.size - size, magnitude.size)
            } else {
                magnitude
            }
            require(trimmed.size <= size) { "EC coordinate wider than $size bytes — not a P-256 key" }
            if (trimmed.size == size) return trimmed
            val out = ByteArray(size)
            System.arraycopy(trimmed, 0, out, size - trimmed.size, trimmed.size)
            return out
        }
    }
}
