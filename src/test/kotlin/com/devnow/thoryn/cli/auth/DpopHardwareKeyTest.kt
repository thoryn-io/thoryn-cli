package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URI
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64

/**
 * SSO-3227 — **the hardware-key path, everything except the enclave itself.**
 *
 * A Secure Enclave key differs from a software one in exactly two observable ways: the public half
 * arrives as a bare ANSI X9.63 point instead of a SubjectPublicKeyInfo, and signing goes through an
 * opaque OS handle instead of a JDK `PrivateKey`. Both are reproduced faithfully here with a JDK key
 * standing in for the enclave, which exercises every line of the path that runs on a real Mac apart
 * from the `SecKeyCreateSignature` call itself — including the ASN.1 prefix that turns the enclave's
 * point back into a usable public key, where an off-by-one would produce a `jkt` the hub cannot match.
 */
class DpopHardwareKeyTest {

    private val mapper = ObjectMapper()

    @BeforeEach
    @AfterEach
    fun reset() {
        Dpop.resetForTest()
        Tty.resetForTest()
        UserPresence.resetForTest()
    }

    /**
     * Stands in for [SecureEnclaveSigner]: signs with a JDK private key the test holds, exactly as the
     * enclave signs with one it will not surrender — same DER output, same interface.
     */
    private class FakeEnclaveSigner(private val privateKey: PrivateKey) : DpopSigner {
        var signatures = 0
        override fun signDer(signingInput: ByteArray): ByteArray {
            signatures++
            return Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(signingInput)
                sign()
            }
        }
    }

    private fun p256() = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    /** The enclave's `SecKeyCopyExternalRepresentation` form: `0x04 || X || Y`, 65 bytes. */
    private fun x963(publicKey: ECPublicKey): ByteArray {
        fun coordinate(value: java.math.BigInteger): ByteArray {
            val raw = value.toByteArray()
            val trimmed = if (raw.size > 32 && raw[0].toInt() == 0) raw.copyOfRange(raw.size - 32, raw.size) else raw
            return ByteArray(32).also { System.arraycopy(trimmed, 0, it, 32 - trimmed.size, trimmed.size) }
        }
        return byteArrayOf(0x04) + coordinate(publicKey.w.affineX) + coordinate(publicKey.w.affineY)
    }

    // ── the X9.63 → public key conversion ────────────────────────────────────

    @Test
    fun `an X9_63 uncompressed point round-trips to the same public key`() {
        val pair = p256()
        val original = pair.public as ECPublicKey

        val rebuilt = DpopKey.publicKeyFromX963(x963(original))

        assertThat(rebuilt.w).isEqualTo(original.w)
        assertThat(rebuilt.encoded).isEqualTo(original.encoded)
    }

    @Test
    fun `a hardware key derives the SAME jkt as the software key with the same public half`() {
        // The hub computes `cnf.jkt` from the `jwk` header alone, so a hardware key whose point came
        // back through the enclave must produce a thumbprint identical to the software key's — or a
        // migrated installation would silently stop matching its own tokens.
        val pair = p256()
        val software = DpopKey(SoftwareDpopSigner(pair.private), pair.public as ECPublicKey, Instant.EPOCH)
        val hardware = DpopKey.hardware(
            FakeEnclaveSigner(pair.private),
            DpopKey.publicKeyFromX963(x963(pair.public as ECPublicKey)),
            Instant.EPOCH,
        )

        assertThat(hardware.thumbprint).isEqualTo(software.thumbprint)
        assertThat(hardware.publicJwkJson).isEqualTo(software.publicJwkJson)
    }

    @Test
    fun `a point that is not a 65-byte uncompressed P-256 point is rejected`() {
        assertThatThrownBy { DpopKey.publicKeyFromX963(ByteArray(64)) }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("65-byte uncompressed P-256 point")

        // A compressed point (0x02/0x03 prefix) is the wrong shape too, not merely the wrong length.
        assertThatThrownBy { DpopKey.publicKeyFromX963(ByteArray(65).also { it[0] = 0x02 }) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    // ── a proof signed by the "hardware" key ─────────────────────────────────

    @Test
    fun `a proof signed through the hardware signer verifies against the embedded public jwk`() {
        val pair = p256()
        val signer = FakeEnclaveSigner(pair.private)
        val key = DpopKey.hardware(signer, DpopKey.publicKeyFromX963(x963(pair.public as ECPublicKey)), Instant.EPOCH)
        val session = DpopSession(key, clock = { Instant.ofEpochSecond(1_700_000_000) }, jtiSource = { "jti-1" })

        val proof = session.proof("POST", URI.create("https://hub.example.test/oauth2/token"))

        assertThat(signer.signatures).isEqualTo(1)
        // Verified against the key carried IN the proof — the only copy the hub ever sees. Es256JwsVerifier
        // selects by `kid`, which a DPoP proof's `jwk` has none of, so one is added for the lookup.
        val jwks = mapper.readTree("""{"keys":[${key.publicJwkJson.dropLast(1)},"kid":"proof"}]}""")
        assertThat(Es256JwsVerifier.verify(jwks, "proof", proof, proof.split(".")[1]))
            .isEqualTo(Es256JwsVerifier.Status.PASS)
    }

    @Test
    fun `the proof header carries the key class as a telemetry hint`() {
        // Verified against Spring Authorization Server's real proof parser
        // (DPoPProofJwtDecoderFactory, spring-security-oauth2-jose 7.1.1 — the artefact oathy's hub
        // resolves): an unknown header member decodes fine, because Nimbus routes unrecognised members
        // to custom params and neither the `typ` verifier nor the `jwk` key selector consults them.
        val pair = p256()
        val hardware = DpopKey.hardware(
            FakeEnclaveSigner(pair.private),
            DpopKey.publicKeyFromX963(x963(pair.public as ECPublicKey)),
            Instant.EPOCH,
        )

        val hardwareHeader = header(DpopSession(hardware).proof("GET", URI.create("https://api.example.test/x")))
        val softwareHeader = header(DpopSession(DpopKey.generate()).proof("GET", URI.create("https://api.example.test/x")))

        assertThat(hardwareHeader["key_class"].asString()).isEqualTo("secure_element")
        assertThat(softwareHeader["key_class"].asString()).isEqualTo("software_keychain")
        // The required members are untouched — the hint is additive, never a substitute.
        assertThat(hardwareHeader["typ"].asString()).isEqualTo("dpop+jwt")
        assertThat(hardwareHeader["alg"].asString()).isEqualTo("ES256")
        assertThat(hardwareHeader["jwk"]["d"]).isNull()
    }

    // ── non-exportability ────────────────────────────────────────────────────

    @Test
    fun `a hardware key refuses to be serialised into the key store`() {
        // Non-exportability is the entire security claim; writing one to the keychain would mean it was
        // never in hardware at all. Fail loudly rather than persist something that cannot exist.
        val pair = p256()
        val hardware = DpopKey.hardware(
            FakeEnclaveSigner(pair.private),
            DpopKey.publicKeyFromX963(x963(pair.public as ECPublicKey)),
            Instant.EPOCH,
        )

        assertThatThrownBy { hardware.toStored() }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("non-exportable")
    }

    // ── cadence, through the real signer wrapper ─────────────────────────────

    @Test
    fun `every proof in one command goes through one key, announcing presence at most once`() {
        // "Not per request" is the rule. A command that mints a token proof plus three API proofs must
        // explain itself once, not four times.
        val err = ByteArrayOutputStream()
        val pair = p256()
        val inner = FakeEnclaveSigner(pair.private)
        val key = DpopKey.hardware(
            object : DpopSigner {
                override fun signDer(signingInput: ByteArray): ByteArray {
                    UserPresence.announceIfDue(PrintStream(err))
                    return inner.signDer(signingInput)
                }
            },
            DpopKey.publicKeyFromX963(x963(pair.public as ECPublicKey)),
            Instant.EPOCH,
        )
        val session = DpopSession(key)

        repeat(4) { session.proof("GET", URI.create("https://api.example.test/v$it")) }

        assertThat(inner.signatures).isEqualTo(4)
        assertThat(err.toString().lines().filter { it.isNotBlank() }).hasSize(1)
    }

    private fun header(proof: String) =
        mapper.readTree(String(Base64.getUrlDecoder().decode(proof.substringBefore('.'))))
}
