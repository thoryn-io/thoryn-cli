package com.devnow.thoryn.cli.cmd.examples.recipe

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * SSO-2878 — a JDK-only round-trip proving [Es256JwsVerifier] (which the CLI uses to verify a receipt's
 * platform attestation offline, no Nimbus) accepts a genuine detached JWS and rejects a tampered one or
 * an unknown key. The `R||S`→DER conversion is the load-bearing bit; a bug there would silently pass or
 * fail every signature, so this exercises the real crypto.
 */
class Es256JwsVerifierTest {

    private val mapper = JsonMapper.builder().build()
    private val urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()

    @Test
    fun `accepts a valid detached JWS, rejects tampering and an unknown kid`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val kid = "receipt-attestation-t-1-local-v1"
        val jwks = jwks(kp.public as ECPublicKey, kid)

        val payloadB64 = urlEnc.encodeToString("""{"recipe":{"id":"simple-signin"}}""".toByteArray())
        val headerB64 = urlEnc.encodeToString("""{"alg":"ES256","kid":"$kid"}""".toByteArray())
        val signingInput = "$headerB64.$payloadB64".toByteArray(Charsets.US_ASCII)

        val der = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(signingInput); sign() }
        val jws = "$headerB64..${urlEnc.encodeToString(derToJose(der))}"

        assertThat(Es256JwsVerifier.verify(jwks, kid, jws, payloadB64)).isEqualTo(Es256JwsVerifier.Status.PASS)
        // Tampered payload → the signature no longer matches.
        assertThat(Es256JwsVerifier.verify(jwks, kid, jws, urlEnc.encodeToString("tampered".toByteArray())))
            .isEqualTo(Es256JwsVerifier.Status.INVALID)
        // kid not in the JWKS → cannot be checked.
        assertThat(Es256JwsVerifier.verify(jwks, "other", jws, payloadB64)).isEqualTo(Es256JwsVerifier.Status.UNVERIFIABLE)
    }

    private fun jwks(key: ECPublicKey, kid: String): JsonNode {
        fun coord(b: BigInteger): String {
            var bytes = b.toByteArray()
            if (bytes.size > 32) bytes = bytes.copyOfRange(bytes.size - 32, bytes.size)
            if (bytes.size < 32) bytes = ByteArray(32 - bytes.size) + bytes
            return urlEnc.encodeToString(bytes)
        }
        val x = coord(key.w.affineX)
        val y = coord(key.w.affineY)
        return mapper.readTree("""{"keys":[{"kty":"EC","crv":"P-256","kid":"$kid","x":"$x","y":"$y"}]}""")
    }

    /** DER SEQUENCE{INTEGER r, INTEGER s} → fixed 64-byte `R||S`. */
    private fun derToJose(der: ByteArray): ByteArray {
        var i = 2 // skip SEQ tag + len (short form for P-256)
        require(der[i].toInt() == 0x02); i++
        val rLen = der[i].toInt(); i++
        val r = der.copyOfRange(i, i + rLen); i += rLen
        require(der[i].toInt() == 0x02); i++
        val sLen = der[i].toInt(); i++
        val s = der.copyOfRange(i, i + sLen)
        return left32(r) + left32(s)
    }

    private fun left32(mag: ByteArray): ByteArray {
        var b = mag
        if (b.size > 32) b = b.copyOfRange(b.size - 32, b.size)
        if (b.size < 32) b = ByteArray(32 - b.size) + b
        return b
    }
}
