package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Unit tests for [PkceUtil] — the PKCE primitives the CLI uses for
 * Authorization Code flows.
 */
class PkceUtilTest {

    @Test
    fun `code verifier is at least 43 characters as required by RFC 7636 section 4 dot 1`() {
        // 32 random bytes base64url-no-pad encode to 43 characters.
        val verifier = PkceUtil.newCodeVerifier()
        assertThat(verifier.length).isGreaterThanOrEqualTo(43)
        assertThat(verifier.length).isLessThanOrEqualTo(128)
    }

    @Test
    fun `code verifier characters are URL-safe`() {
        val verifier = PkceUtil.newCodeVerifier()
        // RFC 7636 §4.1 alphabet: ALPHA / DIGIT / "-" / "." / "_" / "~"
        // Base64url-no-pad uses ALPHA / DIGIT / "-" / "_" — subset, so always valid.
        assertThat(verifier).matches(Regex("[A-Za-z0-9_-]+").toPattern())
    }

    @Test
    fun `each verifier is unique`() {
        val first = PkceUtil.newCodeVerifier()
        val second = PkceUtil.newCodeVerifier()
        assertThat(first).isNotEqualTo(second)
    }

    @Test
    fun `code challenge is base64url-encoded SHA-256 of the verifier`() {
        val verifier = "abc"
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()),
        )

        val actual = PkceUtil.codeChallenge(verifier)

        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `state values are unique and URL-safe`() {
        val s1 = PkceUtil.newState()
        val s2 = PkceUtil.newState()
        assertThat(s1).isNotEqualTo(s2)
        assertThat(s1).matches(Regex("[A-Za-z0-9_-]+").toPattern())
    }
}
