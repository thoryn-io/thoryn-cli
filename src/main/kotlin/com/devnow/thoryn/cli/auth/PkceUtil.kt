package com.devnow.thoryn.cli.auth

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * PKCE helpers per RFC 7636.
 *
 * `code_verifier`  — 32-byte cryptographically random string, base64url-encoded.
 * `code_challenge` — SHA-256(code_verifier), base64url-encoded.
 *
 * Used by [LoopbackOAuthFlow] when starting an Authorization Code flow.
 */
object PkceUtil {

    private val random = SecureRandom()

    /**
     * Generate a fresh `code_verifier` — 32 random bytes, base64url-no-pad.
     */
    fun newCodeVerifier(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return base64UrlEncode(bytes)
    }

    /**
     * Compute the `code_challenge` for a given `code_verifier`.
     * `S256` method only — `plain` is not supported.
     */
    fun codeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return base64UrlEncode(digest)
    }

    /**
     * Generate a random URL-safe `state` value to bind the authorization
     * request to its callback (mitigates CSRF per RFC 6749 §10.12).
     */
    fun newState(): String = base64UrlEncode(ByteArray(16).also { random.nextBytes(it) })

    private fun base64UrlEncode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
