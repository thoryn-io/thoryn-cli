package com.devnow.thoryn.cli.auth

import java.net.URI

/**
 * SSO-1145 — Validates the `--issuer` URL before a device-code (or loopback)
 * flow begins.
 *
 * Security rationale: accepting `http://` for arbitrary hosts allows a
 * developer to accidentally (or an attacker to deliberately) point the CLI at
 * a plaintext server and have the access token transmitted in the clear.
 * `http://` is only safe for local-only development where TLS is not available
 * (loopback addresses: 127.0.0.1, localhost, [::1]).
 *
 * Rules:
 *  - `https://` → always allowed.
 *  - `http://` + loopback host (127.0.0.1, localhost, [::1]) → allowed.
 *  - `http://` + non-loopback host + devMode=true → allowed with a WARN log
 *    so the operator knows they bypassed the guard.
 *  - `http://` + non-loopback host + devMode=false → rejected.
 *  - Any other scheme → rejected (e.g. `ftp://`).
 */
object IssuerUrlValidator {

    private val LOOPBACK_HOSTS = setOf("127.0.0.1", "localhost", "[::1]", "::1")

    /**
     * Validates [issuer] and throws [IssuerUrlValidationException] on rejection.
     *
     * @param issuer  the raw issuer URL string (from `--issuer`).
     * @param devMode when `true`, `http://` non-loopback hosts are allowed
     *                but a WARN is printed to stderr.
     */
    fun validate(issuer: String, devMode: Boolean) {
        val uri = try {
            URI.create(issuer.trimEnd('/'))
        } catch (_: IllegalArgumentException) {
            throw IssuerUrlValidationException("Invalid issuer URL: '$issuer'")
        }

        val scheme = uri.scheme?.lowercase()
            ?: throw IssuerUrlValidationException("Issuer URL has no scheme: '$issuer'")

        when (scheme) {
            "https" -> return  // Always allowed.
            "http" -> validateHttp(uri, issuer, devMode)
            else -> throw IssuerUrlValidationException(
                "Unsupported scheme '$scheme' in issuer URL '$issuer'. Only https:// (and http:// for loopback) are supported.",
            )
        }
    }

    private fun validateHttp(uri: URI, raw: String, devMode: Boolean) {
        val host = uri.host?.lowercase()?.trim('[', ']') ?: ""
        val isLoopback = host in setOf("127.0.0.1", "localhost", "::1")

        if (isLoopback) {
            return  // http:// loopback is always fine.
        }

        if (devMode) {
            System.err.println("WARN: --dev flag active, http:// issuers are allowed.")
            return
        }

        throw IssuerUrlValidationException(
            "http:// issuers are only allowed for loopback addresses (127.0.0.1, localhost, [::1]).\n" +
                "Use --dev to bypass for local development, or switch to https://.",
        )
    }
}

class IssuerUrlValidationException(message: String) : RuntimeException(message)
