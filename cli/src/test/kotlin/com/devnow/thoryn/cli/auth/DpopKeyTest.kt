package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * SSO-3199 — the per-installation DPoP key (RFC 9449 / RFC 7638).
 *
 * Pins the three properties the rest of the feature rests on: the public JWK is the RFC 7638
 * canonical form, `jkt` is its SHA-256 thumbprint (the value the hub mints into `cnf.jkt`), and a key
 * survives the store round-trip with the SAME thumbprint — without which a token bound at login would
 * be unprovable on the next invocation.
 */
class DpopKeyTest {

    private val mapper = ObjectMapper()

    @Test
    fun `public jwk is the RFC 7638 canonical EC form with no private members`() {
        val jwk = mapper.readTree(DpopKey.generate().publicJwkJson)

        assertThat(jwk["kty"].asString()).isEqualTo("EC")
        assertThat(jwk["crv"].asString()).isEqualTo("P-256")
        // Canonical member order + exactly the required members (RFC 7638 §3.2), so the thumbprint
        // the CLI prints is the one the hub computes from the same bytes.
        val json = DpopKey.generate().publicJwkJson
        assertThat(json).matches("""\{"crv":"P-256","kty":"EC","x":"[\w-]+","y":"[\w-]+"}""")
        // A private key MUST NOT appear in the proof's `jwk` header (RFC 9449 §4.2).
        assertThat(json).doesNotContain("\"d\"")
    }

    @Test
    fun `x and y are 32-byte base64url coordinates`() {
        val jwk = mapper.readTree(DpopKey.generate().publicJwkJson)
        val decoder = Base64.getUrlDecoder()

        assertThat(decoder.decode(jwk["x"].asString())).hasSize(32)
        assertThat(decoder.decode(jwk["y"].asString())).hasSize(32)
    }

    @Test
    fun `thumbprint is the base64url SHA-256 of the canonical jwk`() {
        val key = DpopKey.generate()

        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(key.publicJwkJson.toByteArray(Charsets.UTF_8)),
        )

        assertThat(key.thumbprint).isEqualTo(expected)
        assertThat(key.thumbprint).hasSize(43) // 256 bits, base64url, unpadded
    }

    @Test
    fun `a key survives the store round-trip with the same thumbprint`() {
        val original = DpopKey.generate(Instant.ofEpochSecond(1_700_000_000))

        val restored = DpopKey.fromStored(original.toStored())

        assertThat(restored.thumbprint).isEqualTo(original.thumbprint)
        assertThat(restored.publicJwkJson).isEqualTo(original.publicJwkJson)
        assertThat(restored.createdAt).isEqualTo(original.createdAt)
    }

    @Test
    fun `two generated keys are distinct`() {
        assertThat(DpopKey.generate().thumbprint).isNotEqualTo(DpopKey.generate().thumbprint)
    }
}
