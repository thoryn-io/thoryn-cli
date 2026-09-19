package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.FileDpopKeyStore
import com.devnow.thoryn.cli.auth.FileTokenStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

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
}
