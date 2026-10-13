package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import java.net.URI
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * SSO-3199 — the structure and signature of a DPoP proof JWT (RFC 9449 §4).
 *
 * The proof is what the hub verifies, so every claim it checks is pinned here: `typ`/`alg`/`jwk` in the
 * header, `htm`/`htu`/`iat`/`jti` in the payload, `ath` only when a bound access token is presented,
 * and a signature that verifies against the EMBEDDED public key (the hub has no other copy of it).
 */
class DpopProofTest {

    private val mapper = ObjectMapper()
    private val key = DpopKey.generate()
    private val session = DpopSession(
        key = key,
        clock = { Instant.ofEpochSecond(1_700_000_000) },
        jtiSource = { "jti-fixed-0001" },
    )

    @Test
    fun `header carries typ dpop+jwt, ES256 and the public jwk`() {
        val header = header(session.proof("POST", URI.create("https://hub.example.test/oauth2/token")))

        assertThat(header["typ"].asString()).isEqualTo("dpop+jwt")
        assertThat(header["alg"].asString()).isEqualTo("ES256")
        assertThat(header["jwk"].toString()).isEqualTo(key.publicJwkJson)
        assertThat(header["jwk"]["d"]).isNull() // never the private key
    }

    @Test
    fun `payload carries htm htu iat and jti`() {
        val claims = claims(session.proof("post", URI.create("https://hub.example.test/oauth2/token")))

        assertThat(claims["htm"].asString()).isEqualTo("POST") // uppercased per RFC 9110 method casing
        assertThat(claims["htu"].asString()).isEqualTo("https://hub.example.test/oauth2/token")
        assertThat(claims["iat"].asLong()).isEqualTo(1_700_000_000L)
        assertThat(claims["jti"].asString()).isEqualTo("jti-fixed-0001")
        assertThat(claims["ath"]).isNull() // no access token presented on a token request
        assertThat(claims["nonce"]).isNull()
    }

    @Test
    fun `htu drops the query and the fragment`() {
        val uri = URI.create("https://api.example.test/api/v1/users?email=a%40b.test&limit=5#frag")

        val claims = claims(session.proof("GET", uri))

        assertThat(claims["htu"].asString()).isEqualTo("https://api.example.test/api/v1/users")
    }

    @Test
    fun `ath is the base64url SHA-256 of the access token`() {
        val accessToken = "AT-abc.def.ghi"

        val claims = claims(session.proof("GET", URI.create("https://api.example.test/api/v1/applications"), accessToken))

        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.US_ASCII)),
        )
        assertThat(claims["ath"].asString()).isEqualTo(expected)
    }

    @Test
    fun `the signature verifies against the embedded public jwk`() {
        val proof = session.proof("POST", URI.create("https://hub.example.test/oauth2/token"))
        val parts = proof.split(".")

        // Feed the proof's OWN embedded key back as the verification JWKS — exactly what the hub does.
        val jwks = mapper.readTree("""{"keys":[${withKid(key.publicJwkJson, "proof")}]}""")
        assertThat(Es256JwsVerifier.verify(jwks, "proof", proof, parts[1]))
            .isEqualTo(Es256JwsVerifier.Status.PASS)
    }

    @Test
    fun `a tampered payload fails verification`() {
        val proof = session.proof("POST", URI.create("https://hub.example.test/oauth2/token"))
        val tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(
            """{"htm":"POST","htu":"https://evil.example.test/oauth2/token","iat":1700000000,"jti":"x"}"""
                .toByteArray(Charsets.UTF_8),
        )

        val jwks = mapper.readTree("""{"keys":[${withKid(key.publicJwkJson, "proof")}]}""")
        assertThat(Es256JwsVerifier.verify(jwks, "proof", proof, tampered))
            .isEqualTo(Es256JwsVerifier.Status.INVALID)
    }

    @Test
    fun `each proof carries a fresh jti`() {
        val live = DpopSession(key)

        val first = claims(live.proof("GET", URI.create("https://api.example.test/x")))["jti"].asString()
        val second = claims(live.proof("GET", URI.create("https://api.example.test/x")))["jti"].asString()

        assertThat(first).isNotEqualTo(second)
        // RFC 9449 §4.2: at least 96 bits of entropy — a UUID string satisfies it.
        assertThat(first).hasSizeGreaterThanOrEqualTo(36)
    }

    private fun header(proof: String): JsonNode = segment(proof, 0)

    private fun claims(proof: String): JsonNode = segment(proof, 1)

    private fun segment(proof: String, index: Int): JsonNode {
        val raw = proof.split(".")[index]
        val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
        return mapper.readTree(String(Base64.getUrlDecoder().decode(padded), Charsets.UTF_8))
    }

    /** [Es256JwsVerifier] selects a key by `kid`; the proof's JWK has none, so add one for the test. */
    private fun withKid(jwkJson: String, kid: String): String =
        jwkJson.dropLast(1) + ""","kid":"$kid"}"""
}
