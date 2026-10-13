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
    // SSO-3182 — the workspace slug an interactive login signed in on (`thoryn login --workspace <slug>`),
    // so a session that can no longer be renewed can print the exact re-login line. Not a secret.
    val workspace: String? = null,
    // SSO-3228 — the DEVICE this installation's DPoP key is registered as, recorded when a bound
    // login registers it. `deviceId` is what `thoryn devices revoke` names; `deviceName` is what
    // `thoryn whoami` prints. Both null for an unbound session, for a CLI that has not registered
    // yet, or when registration was refused — the session works either way. Neither is a secret:
    // the id is an opaque identifier and the name is the one the user chose.
    val deviceId: String? = null,
    val deviceName: String? = null,
    // SSO-3379 — the platform BASE issuer this session's login resolved (`https://auth.<env>`), as
    // opposed to [issuer], which after an interactive sign-in is the WORKSPACE issuer
    // (`https://<slug>.auth.<env>`). Every other workspace's issuer is composed from THIS base
    // (`https://<other>.auth.<env>`), never by prefixing a slug onto [issuer] — that produced the nested
    // `https://<other>.<slug>.auth.<env>` the hub rejects `invalid_target` since SSO-3360. Nullable for
    // token files written before SSO-3379: readers fall back to the base of [issuer]
    // ([com.devnow.thoryn.cli.config.ThorynConfig.baseHubOf]). Not a secret.
    val platformIssuer: String? = null,
    // SSO-3308 — the token endpoint a WORKLOAD IDENTITY session exchanges its GitHub Actions job token at
    // (`{audience}/oauth2/token` unless the sign-in named another on the same origin). The session's
    // [issuer] is the trust's audience. Kept so a renewal can run the same exchange again with a FRESH job
    // token (a job token works once). Null for every other session. Not a secret.
    val tokenEndpoint: String? = null,
) {
    companion object {
        /** SSO-2941 — [authMode] value marking a non-interactive API-key / client-credentials session. */
        const val AUTH_MODE_CLIENT_CREDENTIALS: String = "client_credentials"

        /**
         * SSO-3308 — [authMode] value marking a secret-less WORKLOAD IDENTITY session: a GitHub Actions job
         * token exchanged for a short-lived (≤ 15 min) workspace token under a workload identity trust. No
         * refresh token; on expiry the CLI runs the exchange again with a fresh job token from the runner.
         */
        const val AUTH_MODE_WORKLOAD_IDENTITY: String = "workload_identity"
    }
}
