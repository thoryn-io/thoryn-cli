package com.devnow.oathy.cli.auth

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
)
