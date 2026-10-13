package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.FileDpopKeyStore
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * SSO-3199 — `thoryn logout` clears the session and offers DPoP key rotation.
 *
 * The key is kept by default (it authorises nothing on its own, and keeping it means the next login
 * re-binds to the same `jkt`); `--rotate-key` discards it so the next login generates a new one.
 */
class LogoutCommandTest : CommandTestBase() {

    @BeforeEach
    fun resetDpop() {
        Dpop.resetForTest()
    }

    @AfterEach
    fun clearDpop() {
        Dpop.resetForTest()
    }

    @Test
    fun `logout clears the tokens and keeps the DPoP key, printing only its thumbprint`() {
        val jkt = Dpop.session()!!.thumbprint

        val (exit, out, _) = runCli("logout")

        assertThat(exit).isEqualTo(0)
        assertThat(FileTokenStore().read()).isNull()
        assertThat(out).contains("Signed out")
        // SSO-3227 — the line now names the key's protection class alongside the thumbprint, so the
        // last thing shown before a machine is handed on says WHAT was kept, not merely that
        // something was. On a test JVM that is always the software keychain (Tty is pinned
        // non-interactive, so the hardware rung never engages).
        assertThat(out).contains("DPoP key kept (jkt $jkt, software_keychain)")
        assertThat(FileDpopKeyStore().read()).isNotNull()
        // The stored private key must never reach the terminal.
        assertThat(out).doesNotContain(FileDpopKeyStore().read()!!.privateKeyPkcs8)
    }

    @Test
    fun `logout --rotate-key discards the key so the next login generates a new one`() {
        val before = Dpop.session()!!.thumbprint

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("DPoP key discarded")
        assertThat(FileDpopKeyStore().read()).isNull()
        assertThat(Dpop.session()!!.thumbprint).isNotEqualTo(before)
    }

    @Test
    fun `logout --rotate-key on a machine with no key says so`() {
        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("No DPoP key was stored")
    }

    // ── retiring the device with the key (SSO-3270) ───────────────────────────

    /**
     * A session as a login leaves it: bound to this installation's key and carrying the device id
     * the hub answered with at registration. `--hub` is not a `logout` option — the revoke goes to
     * the hub recorded at login, which is why the issuer points at the MockWebServer here.
     */
    private fun seedRegisteredSession(issuer: String = baseUrl(), deviceId: String? = "d-1") {
        seedTokens(
            Tokens(
                accessToken = "AT-test",
                // Deliberately NO refresh token: a 401 must surface as a 401 rather than sending the
                // client off to redeem one against this same mock queue.
                refreshToken = null,
                tokenType = "DPoP",
                issuer = issuer,
                deviceId = deviceId,
                deviceName = "alice-mbp",
            ),
        )
    }

    /** The decoded JWS header of a request's DPoP proof — i.e. WHICH key signed it. */
    private fun proofHeaderOf(request: RecordedRequest): String {
        val proof = request.getHeader("DPoP")
        assertThat(proof).describedAs("the hub takes the revoke's authority from a proof").isNotNull()
        return String(Base64.getUrlDecoder().decode(proof!!.substringBefore('.')), Charsets.UTF_8)
    }

    @Test
    fun `logout --rotate-key revokes the device, signed by the key being retired`() {
        // The ordering this test exists for: the revoke must be signed by the key it is about, so it
        // has to go out BEFORE that key is discarded. Proving it from the proof — rather than from a
        // call counter — is the assertion that would actually fail if the two ever swapped.
        val retiredKey = Dpop.session()!!.key.publicJwkJson
        val retiredThumbprint = Dpop.session()!!.thumbprint
        seedRegisteredSession()
        server.enqueue(
            jsonResponse(
                200,
                """{"id":"d-1","jkt":"$retiredThumbprint","name":"alice-mbp",
                    "revokedAt":"2026-09-20T09:34:44Z","revokedSessions":2}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).isEqualTo(0)
        val revoke = server.takeRequest()
        assertThat(revoke.path).isEqualTo("/account/devices/d-1/revoke")
        assertThat(revoke.method).isEqualTo("POST")
        assertThat(revoke.body.readUtf8())
            .describedAs("the audit row should say this was a rotation, not a theft")
            .contains("key_rotated")
        assertThat(proofHeaderOf(revoke))
            .describedAs("signed by the key being retired — i.e. sent before the rotation")
            .contains(retiredKey)
        assertThat(out).contains("Device 'alice-mbp' revoked at the hub (2 sessions ended).")
        assertThat(out).contains("DPoP key discarded")
        assertThat(Dpop.session()!!.thumbprint).isNotEqualTo(retiredThumbprint)
    }

    @Test
    fun `logout keeps the device when it keeps the key`() {
        seedRegisteredSession()

        val (exit, out, _) = runCli("logout")

        assertThat(exit).isEqualTo(0)
        assertThat(server.requestCount)
            .describedAs("the next login re-binds to the same jkt, so the same device row is still true")
            .isZero()
        assertThat(out).contains("DPoP key kept")
    }

    @Test
    fun `logout --rotate-key asks the hub nothing when no device was ever registered`() {
        // A session that predates device registration, or one whose registration the hub declined:
        // there is no row to strand, so there is nothing to do and nobody to say it to.
        seedRegisteredSession(deviceId = null)

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).isEqualTo(0)
        assertThat(server.requestCount).isZero()
        assertThat(out).doesNotContain("revoked at the hub")
    }

    @Test
    fun `logout --rotate-key tolerates a device the hub no longer knows`() {
        seedRegisteredSession()
        server.enqueue(jsonResponse(404, """{"errorCode":"device_not_found","detail":"No such device."}"""))

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).describedAs("signing out is a local act that must always succeed").isEqualTo(0)
        assertThat(out).contains("the hub has no device 'd-1' to revoke")
        assertThat(out).contains("DPoP key discarded")
        assertThat(FileDpopKeyStore().read()).isNull()
    }

    @Test
    fun `logout --rotate-key tolerates a session the hub has already ended`() {
        seedRegisteredSession()
        server.enqueue(jsonResponse(401, """{"error":"invalid_token"}"""))

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("could not be revoked at the hub")
        assertThat(out)
            .describedAs("a note that leaves someone stuck is not a note — name the way to finish the job")
            .contains("thoryn devices revoke d-1")
        assertThat(out).contains("DPoP key discarded")
    }

    @Test
    fun `logout --rotate-key completes when the hub cannot be reached at all`() {
        // Port 1 on loopback refuses immediately: the aeroplane case, without the wait.
        seedRegisteredSession(issuer = "http://127.0.0.1:1")

        val (exit, out, _) = runCli("logout", "--rotate-key")

        assertThat(exit)
            .describedAs("a user handing this machine on must not be left holding a live key")
            .isEqualTo(0)
        assertThat(out).contains("could not be revoked at the hub")
        assertThat(out).contains("DPoP key discarded")
        assertThat(FileDpopKeyStore().read()).isNull()
        assertThat(FileTokenStore().read()).isNull()
    }
}
