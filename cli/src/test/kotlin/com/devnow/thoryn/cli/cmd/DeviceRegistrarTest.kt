package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.Base64

/**
 * SSO-3228 — registering this installation's DPoP key as a named device at login.
 *
 * The three things worth pinning: registration happens only when the minted token is actually
 * **bound to this installation's key** (the same gate the hub applies, so the two cannot disagree),
 * the device id and name come back on the stored session, and a refusal **never fails the sign-in**
 * — a device record is a revocation convenience, not a credential.
 */
class DeviceRegistrarTest : CommandTestBase() {

    private val err = ByteArrayOutputStream()

    @BeforeEach
    fun clearRegistrarSeams() {
        DeviceRegistrar.resetForTest()
        DeviceRegistrar.hostname = { "alices-mbp" }
    }

    @AfterEach
    fun restoreRegistrarSeams() {
        DeviceRegistrar.resetForTest()
    }

    /** An access token whose (display-only) claims carry `cnf.jkt` = this installation's key. */
    private fun boundToken(thumbprint: String?): Tokens {
        val claims = if (thumbprint == null) """{"sub":"alice"}""" else """{"sub":"alice","cnf":{"jkt":"$thumbprint"}}"""
        val b64 = { s: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray()) }
        return Tokens(
            accessToken = "${b64("""{"alg":"none"}""")}.${b64(claims)}.sig",
            issuer = baseUrl(),
        )
    }

    private fun localThumbprint(): String = Dpop.session(PrintStream(err))!!.thumbprint

    @Test
    fun `a bound login registers this machine and records the device on the session`() {
        server.enqueue(jsonResponse(201, """{"id":"d-1","jkt":"x","name":"alices-mbp","registered":true}"""))

        val result = DeviceRegistrar.register(boundToken(localThumbprint()), err = PrintStream(err))

        assertThat(result.deviceId).isEqualTo("d-1")
        assertThat(result.deviceName).isEqualTo("alices-mbp")
        val request = server.takeRequest()
        assertThat(request.path).isEqualTo("/account/devices")
        assertThat(request.method).isEqualTo("POST")
        val body = request.body.readUtf8()
        assertThat(body)
            // The JWK rides as a JSON STRING (the hub re-parses it to compute the thumbprint), so it
            // appears escaped on the wire.
            .describedAs("only the PUBLIC key travels — the private half never leaves the keychain")
            .contains("kty")
            .contains("P-256")
            .doesNotContain("\\\"d\\\"")
        assertThat(body).contains("alices-mbp")
    }

    @Test
    fun `--device-name overrides the hostname`() {
        server.enqueue(jsonResponse(201, """{"id":"d-2","name":"alice work laptop"}"""))

        val result = DeviceRegistrar.register(
            boundToken(localThumbprint()),
            explicitName = "alice work laptop",
            err = PrintStream(err),
        )

        assertThat(result.deviceName).isEqualTo("alice work laptop")
        assertThat(server.takeRequest().body.readUtf8()).contains("alice work laptop")
    }

    @Test
    fun `an unbound (bearer) session registers nothing`() {
        val tokens = boundToken(thumbprint = null)

        val result = DeviceRegistrar.register(tokens, err = PrintStream(err))

        assertThat(result).isSameAs(tokens)
        assertThat(server.requestCount)
            .describedAs("there is no key to register, and the hub would refuse — so no call is made")
            .isZero()
    }

    @Test
    fun `a token bound to some OTHER installation's key registers nothing`() {
        val tokens = boundToken("a-thumbprint-from-another-machine")

        val result = DeviceRegistrar.register(tokens, err = PrintStream(err))

        assertThat(result).isSameAs(tokens)
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a hub that refuses does not cost the user their sign-in`() {
        server.enqueue(jsonResponse(404, """{"type":"about:blank","status":404,"title":"Not Found"}"""))
        val tokens = boundToken(localThumbprint())

        val result = DeviceRegistrar.register(tokens, err = PrintStream(err))

        assertThat(result)
            .describedAs("a device record is a convenience; the session is valid without one")
            .isSameAs(tokens)
        assertThat(err.toString()).contains("could not be registered")
    }
}
