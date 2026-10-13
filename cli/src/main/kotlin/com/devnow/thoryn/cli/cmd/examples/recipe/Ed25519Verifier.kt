package com.devnow.thoryn.cli.cmd.examples.recipe

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * SSO-2874 — verifies an Ed25519 detached signature over the recipe-catalog bundle against the CLI's
 * pinned release-signing PUBLIC key. JDK-only (`Signature.getInstance("Ed25519")`, JDK 15+), so the
 * GraalVM native image is unaffected. The signed bytes are the raw bundle; the signature is the raw
 * 64-byte Ed25519 signature the release workflow produces (`openssl pkeyutl -sign -rawin`).
 */
internal object Ed25519Verifier {

    /** True iff [signature] is a valid Ed25519 signature over [message] under the SPKI key [publicKeySpkiB64]. */
    fun verify(publicKeySpkiB64: String, message: ByteArray, signature: ByteArray): Boolean = try {
        val spki = Base64.getDecoder().decode(publicKeySpkiB64)
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(key)
        verifier.update(message)
        verifier.verify(signature)
    } catch (_: Exception) {
        false
    }
}
