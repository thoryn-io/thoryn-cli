package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64

/**
 * SSO-2879 — unit tests for [EcPrivateKeyJwtSigner], the ES256 `private_key_jwt` client-assertion
 * signer. The load-bearing assertion: an assertion it signs VERIFIES against the matching public JWK
 * using the platform's own detached-JWS verifier ([Es256JwsVerifier]) — proving the JOSE `R||S`
 * signature encoding and the signing-input construction are interoperable with the hub's decoder.
 */
class EcPrivateKeyJwtSignerTest {

    private val mapper = JsonMapper.builder().build()

    @Test
    fun `signs a client assertion that verifies against the matching public JWK`() {
        val kp = ecKeyPair()
        val kid = "ci-conformance-wif-v1"
        val jwks = jwksJson(kp.public as ECPublicKey, kid)
        val signer = EcPrivateKeyJwtSigner(privateKeyPem = pkcs8Pem(kp.private.encoded), keyId = kid)

        val assertion = signer.sign(
            clientId = "conformance-ci-github-wif",
            audience = "https://hub.stg.thoryn.org/oauth2/token",
        )

        val parts = assertion.split(".")
        assertThat(parts).hasSize(3)
        // Es256JwsVerifier consumes a DETACHED JWS (`header..sig`) + the base64url payload separately.
        val detached = "${parts[0]}..${parts[2]}"
        val status = Es256JwsVerifier.verify(mapper.readTree(jwks), kid, detached, parts[1])
        assertThat(status).isEqualTo(Es256JwsVerifier.Status.PASS)
    }

    @Test
    fun `assertion header and claims carry iss=sub=client_id, the aud, an exp and a jti`() {
        val kp = ecKeyPair()
        val signer = EcPrivateKeyJwtSigner(
            privateKeyPem = pkcs8Pem(kp.private.encoded),
            keyId = "kid-1",
            clock = { Instant.ofEpochSecond(1_000_000) },
            jtiSource = { "fixed-jti" },
        )

        val assertion = signer.sign(clientId = "cli-x", audience = "https://hub/oauth2/token", ttlSeconds = 90)
        val parts = assertion.split(".")

        val header = String(Base64.getUrlDecoder().decode(parts[0]))
        assertThat(header).contains("\"alg\":\"ES256\"").contains("\"kid\":\"kid-1\"")

        val claims = mapper.readTree(String(Base64.getUrlDecoder().decode(parts[1])))
        assertThat(claims["iss"].asString()).isEqualTo("cli-x")
        assertThat(claims["sub"].asString()).isEqualTo("cli-x")
        assertThat(claims["aud"].asString()).isEqualTo("https://hub/oauth2/token")
        assertThat(claims["jti"].asString()).isEqualTo("fixed-jti")
        assertThat(claims["iat"].asLong()).isEqualTo(1_000_000)
        assertThat(claims["exp"].asLong()).isEqualTo(1_000_090)
    }

    @Test
    fun `a signature from a DIFFERENT key does NOT verify`() {
        val signingKp = ecKeyPair()
        val otherKp = ecKeyPair()
        val kid = "kid-1"
        val jwksOfOther = jwksJson(otherKp.public as ECPublicKey, kid)
        val signer = EcPrivateKeyJwtSigner(privateKeyPem = pkcs8Pem(signingKp.private.encoded), keyId = kid)

        val assertion = signer.sign(clientId = "cli-x", audience = "https://hub/oauth2/token")
        val parts = assertion.split(".")

        val status = Es256JwsVerifier.verify(mapper.readTree(jwksOfOther), kid, "${parts[0]}..${parts[2]}", parts[1])
        assertThat(status).isEqualTo(Es256JwsVerifier.Status.INVALID)
    }

    @Test
    fun `a non-PKCS8 PEM is rejected with a clear error`() {
        assertThatThrownBy { EcPrivateKeyJwtSigner(privateKeyPem = "not a pem", keyId = "k") }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    // ── helpers ────────────────────────────────────────────────────────────────────────────────

    private fun ecKeyPair() = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun pkcs8Pem(der: ByteArray): String {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n"
    }

    private fun jwksJson(pub: ECPublicKey, kid: String): String {
        val x = b64u(pub.w.affineX.toByteArray())
        val y = b64u(pub.w.affineY.toByteArray())
        return """{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"$kid","x":"$x","y":"$y"}]}"""
    }

    /** Left-pad/strip a BigInteger's two's-complement bytes to a fixed 32-byte P-256 coordinate, base64url. */
    private fun b64u(raw: ByteArray): String {
        val trimmed = if (raw.size > 32 && raw[0].toInt() == 0) raw.copyOfRange(raw.size - 32, raw.size) else raw
        val fixed = ByteArray(32)
        System.arraycopy(trimmed, 0, fixed, 32 - trimmed.size, trimmed.size)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed)
    }
}
