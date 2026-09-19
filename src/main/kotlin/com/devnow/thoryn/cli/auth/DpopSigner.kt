package com.devnow.thoryn.cli.auth

import java.security.PrivateKey
import java.security.Signature

/**
 * SSO-3227 — **the one operation a DPoP key has to perform**, and the seam that lets the private key
 * live somewhere this process cannot read.
 *
 * [DpopKey] used to hold a [PrivateKey] and call [Signature] directly. That is still true for the
 * software key ([SoftwareDpopSigner]) — but a Secure Enclave / TPM key has no [PrivateKey] object at
 * all: there is only an opaque handle the OS will sign with, and only after the user proves presence.
 * Narrowing the dependency to "give me an ECDSA signature over these bytes" is what makes both shapes
 * fit behind one [DpopKey].
 *
 * Implementations return the **ASN.1 DER** ECDSA signature (the shape both the JDK and
 * `SecKeyCreateSignature` produce); [DpopKey.signCompact] converts it to the JOSE `R||S` form.
 */
internal interface DpopSigner {

    /** ASN.1 DER ECDSA-with-SHA256 signature over [signingInput]. */
    fun signDer(signingInput: ByteArray): ByteArray
}

/**
 * The software signer: an in-process [PrivateKey] signed with via the JDK provider. This is the
 * SSO-3199 behaviour, unchanged, and the only signer whose key can be serialised to a
 * [StoredDpopKey] — a hardware key is non-exportable by construction.
 */
internal class SoftwareDpopSigner(internal val privateKey: PrivateKey) : DpopSigner {

    override fun signDer(signingInput: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(signingInput)
        return signer.sign()
    }
}
