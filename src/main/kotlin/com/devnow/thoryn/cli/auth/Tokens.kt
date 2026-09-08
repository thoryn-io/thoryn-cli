package com.devnow.thoryn.cli.auth

/**
 * Tokens kept on disk between CLI invocations.
 *
 * Field names are camelCase here and in the on-disk file. When the actual
 * loopback OAuth flow ships, the snake_case token-response from the hub is
 * mapped into this shape at deserialization time (a small step in the code
 * exchange handler) — the storage format stays camelCase.
 */
data class Tokens(
    val accessToken: String,
    val refreshToken: String? = null,
    val idToken: String? = null,
    val tokenType: String = "Bearer",
    val expiresAtEpochSecond: Long? = null,
    val scope: String? = null,
    // SSO-2827 — the hub issuer and gateway base URL this session authenticated
    // against, recorded at login so subsequent commands (`workspace`, `clients`,
    // `federation`, `audit`) default to them instead of silently re-defaulting to
    // localhost. Nullable + defaulted for backward-compatibility with token files
    // written before SSO-2827 (an older file simply has no session hosts, and the
    // commands fall back to the built-in defaults). Neither is a secret.
    val issuer: String? = null,
    val gateway: String? = null,
    // SSO-2941 — how this session was obtained. For an API-key / client-credentials
    // (RFC 6749 §4.4) session this is [AUTH_MODE_CLIENT_CREDENTIALS], which has NO
    // refresh token: on expiry the CLI re-mints from the stored [clientId] + the
    // env-supplied secret (THORYN_API_KEY / THORYN_CLIENT_SECRET) rather than a
    // refresh_token redemption. Null for interactive logins (they refresh normally).
    // Neither field is a secret — [clientId] is a public identifier and the client
    // secret is NEVER persisted (it lives only in the CI environment).
    val authMode: String? = null,
    val clientId: String? = null,
) {
    companion object {
        /** SSO-2941 — [authMode] value marking a non-interactive API-key / client-credentials session. */
        const val AUTH_MODE_CLIENT_CREDENTIALS: String = "client_credentials"
    }
}
