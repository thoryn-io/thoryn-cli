package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.FileDpopKeyStore
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.Base64

/**
 * SSO-3199 — `thoryn whoami` surfaces the DPoP key thumbprint (`jkt`) and whether the stored token is
 * sender-constrained to it, and **never** surfaces the private key.
 */
class WhoamiDpopTest : CommandTestBase() {

    @BeforeEach
    fun resetDpop() {
        // Drop any key cached by an earlier test class so the key lands in THIS test's sandboxed home.
        Dpop.resetForTest()
    }

    @AfterEach
    fun clearDpop() {
        Dpop.resetForTest()
    }

    private fun jwt(claims: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return "${enc.encodeToString("""{"alg":"none"}""".toByteArray())}.${enc.encodeToString(claims.toByteArray())}."
    }

    @Test
    fun `whoami prints the installation's key thumbprint and reports an unbound bearer token`() {
        seedTokens(
            Tokens(
                accessToken = jwt("""{"sub":"u","tnt":"acme"}"""),
                expiresAtEpochSecond = Instant.now().epochSecond + 3600,
            ),
        )

        val (exit, out, _) = runCli("whoami", "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["dpopKeyThumbprint"].toString()).hasSize(43)
        assertThat(json["dpopBound"].toString()).startsWith("no (bearer token")
    }

    @Test
    fun `whoami reports a token bound to this installation's key`() {
        // Generate the key first so the token can carry its thumbprint as `cnf.jkt`, exactly as the hub
        // mints it (DpopAccessTokenCustomizer).
        val jkt = Dpop.session()!!.thumbprint
        seedTokens(
            Tokens(
                accessToken = jwt("""{"sub":"u","tnt":"acme","cnf":{"jkt":"$jkt"}}"""),
                tokenType = "DPoP",
                expiresAtEpochSecond = Instant.now().epochSecond + 3600,
            ),
        )

        val (_, out, _) = runCli("whoami", "--output", "json")

        assertThat(parseJson(out)["dpopBound"].toString()).isEqualTo("yes (cnf.jkt matches this installation's key)")
    }

    @Test
    fun `whoami flags a token bound to a DIFFERENT key`() {
        seedTokens(
            Tokens(
                accessToken = jwt("""{"sub":"u","tnt":"acme","cnf":{"jkt":"someone-elses-thumbprint"}}"""),
                tokenType = "DPoP",
                expiresAtEpochSecond = Instant.now().epochSecond + 3600,
            ),
        )

        val (_, out, _) = runCli("whoami", "--output", "json")

        assertThat(parseJson(out)["dpopBound"].toString()).startsWith("MISMATCH")
    }

    @Test
    fun `whoami reports the key's protection class and why the secure element was passed over`() {
        // SSO-3227 — the security property a session actually has is the key CLASS, not merely that a
        // key exists. Reporting only "here is a jkt" would let an installation believe it has the
        // hardware guarantee when it silently fell back. The skip reason is the actionable half.
        seedTokens(Tokens(accessToken = jwt("""{"sub":"u"}"""), expiresAtEpochSecond = Instant.now().epochSecond + 3600))

        val (exit, out, _) = runCli("whoami", "--output", "json")

        assertThat(exit).isEqualTo(0)
        val keyClass = parseJson(out)["dpopKeyClass"].toString()
        // The test JVM is pinned non-interactive (see Dpop.resetForTest), so the ladder must land on
        // the software rung and say that user presence could not be proven here.
        assertThat(keyClass).startsWith("software_keychain — ")
        assertThat(keyClass).contains("secure_element unavailable")
    }

    @Test
    fun `whoami never prints the private key`() {
        seedTokens(Tokens(accessToken = jwt("""{"sub":"u"}"""), expiresAtEpochSecond = Instant.now().epochSecond + 3600))

        val (_, out, err) = runCli("whoami", "--output", "json")

        val stored = FileDpopKeyStore().read()
        assertThat(stored).isNotNull()
        assertThat(out + err).doesNotContain(stored!!.privateKeyPkcs8)
        assertThat(out + err).doesNotContain("privateKey")
    }
}
