package com.devnow.thoryn.cli.auth

import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.node.ObjectNode
import java.util.Base64

/**
 * Decodes the claims of a compact JWS (a JWT access / id token) for **display only**.
 *
 * SSO-2860 (CLI maturity — `whoami`): this reads the base64url-encoded payload segment and parses
 * it as JSON. It performs **no signature verification** and MUST NOT be used for any authorization
 * decision — the CLI trusts the token because it obtained it from its own token store, and only
 * surfaces its claims (sub, tnt, scope, exp, …) so the user can see who / where they are.
 *
 * A token that is absent, not a well-formed three-part JWT, or whose payload is not JSON yields an
 * empty object, so callers can null-safely read individual claims without try/catch.
 */
object JwtClaims {

    private val mapper = ObjectMapper()

    /** The (unverified) payload claims of [token], or an empty object when it cannot be decoded. */
    fun of(token: String?): JsonNode {
        val payload = token?.split(".")?.getOrNull(1) ?: return mapper.createObjectNode()
        return try {
            val json = String(Base64.getUrlDecoder().decode(pad(payload)), Charsets.UTF_8)
            mapper.readTree(json).takeIf { it is ObjectNode } ?: mapper.createObjectNode()
        } catch (_: Exception) {
            mapper.createObjectNode()
        }
    }

    /** Right-pad a base64url segment to a multiple of 4 so [Base64.getUrlDecoder] accepts it. */
    private fun pad(segment: String): String = segment + "=".repeat((4 - segment.length % 4) % 4)
}
