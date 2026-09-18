package com.devnow.thoryn.cli.auth

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
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
    private val privateKey: PrivateKey,
    private val publicKey: ECPublicKey,
    /** When this installation's key was generated — surfaced by `thoryn whoami`, never a secret. */
    val createdAt: Instant,
) {

    /** The public JWK, in RFC 7638 canonical member order, as it rides in the proof's `jwk` header. */
    val publicJwkJson: String = canonicalJwk(publicKey)

    /** RFC 7638 JWK thumbprint (`jkt`) — what the hub binds into `cnf.jkt`. */
    val thumbprint: String =
        b64u(MessageDigest.getInstance("SHA-256").digest(publicJwkJson.toByteArray(Charsets.UTF_8)))

    /** Serialise for [DpopKeyStore]. Contains the PRIVATE key — only ever handed to the secure store. */
    internal fun toStored(): StoredDpopKey = StoredDpopKey(
        privateKeyPkcs8 = Base64.getEncoder().encodeToString(privateKey.encoded),
        publicKeyX509 = Base64.getEncoder().encodeToString(publicKey.encoded),
        createdAtEpochSecond = createdAt.epochSecond,
    )

    /**
     * Sign a compact JWS over [headerJson] / [claimsJson] with ES256, returning
     * `base64url(header).base64url(claims).base64url(R||S)`.
     */
    internal fun signCompact(headerJson: String, claimsJson: String): String {
        val signingInput = "${b64u(headerJson.toByteArray(Charsets.UTF_8))}.${b64u(claimsJson.toByteArray(Charsets.UTF_8))}"
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(signingInput.toByteArray(Charsets.US_ASCII))
        // Reuse the DER → JOSE (R||S) conversion the RFC 7523 client-assertion signer already carries.
        val jose = EcPrivateKeyJwtSigner.derToJose(signer.sign())
        return "$signingInput.${b64u(jose)}"
    }

    companion object {

        /** Generate a fresh P-256 key pair for this installation. */
        fun generate(now: Instant = Instant.now()): DpopKey {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val pair = generator.generateKeyPair()
            return DpopKey(pair.private, pair.public as ECPublicKey, now)
        }

        /** Rehydrate a key persisted by [toStored]. Throws [IllegalArgumentException] on a corrupt record. */
        internal fun fromStored(stored: StoredDpopKey): DpopKey = try {
            val factory = KeyFactory.getInstance("EC")
            val private = factory.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(stored.privateKeyPkcs8)))
            val public = factory.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(stored.publicKeyX509)))
            DpopKey(private, public as ECPublicKey, Instant.ofEpochSecond(stored.createdAtEpochSecond))
        } catch (e: Exception) {
            throw IllegalArgumentException("stored DPoP key could not be parsed: ${e.message}", e)
        }

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
