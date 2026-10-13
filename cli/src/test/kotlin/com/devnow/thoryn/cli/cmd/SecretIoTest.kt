package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-1552 — focused unit tests for [SecretIo], the secret-safety helper.
 *
 * These exercise the input/output contract directly with injected streams and a
 * fake console seam, so the secret-handling rules are pinned independently of
 * any command or HTTP plumbing.
 */
class SecretIoTest {

    @TempDir
    lateinit var tmp: Path

    private fun out() = ByteArrayOutputStream()

    // ── input ────────────────────────────────────────────────────────────────

    @Test
    fun `readSecretInput reads from a secret file and strips a trailing newline`() {
        val file = tmp.resolve("s.txt").toFile()
        file.writeText("my-secret\n")

        val secret = SecretIo.readSecretInput(secretFile = file, prompt = "x", console = null, err = PrintStream(out()))

        assertThat(secret).isEqualTo("my-secret")
    }

    @Test
    fun `readSecretInput uses the no-echo console when no file is given`() {
        val fakeConsole = SecretIo.ConsoleLike { "typed-secret".toCharArray() }

        val secret = SecretIo.readSecretInput(secretFile = null, prompt = "Secret: ", console = fakeConsole)

        assertThat(secret).isEqualTo("typed-secret")
    }

    @Test
    fun `readSecretInput returns null with guidance when there is no file and no console`() {
        val err = out()
        val secret = SecretIo.readSecretInput(secretFile = null, prompt = "x", console = null, err = PrintStream(err))

        assertThat(secret).isNull()
        assertThat(err.toString()).contains("no interactive terminal").contains("--secret-file")
    }

    @Test
    fun `readSecretInput returns null on a missing secret file`() {
        val err = out()
        val missing = tmp.resolve("nope.txt").toFile()
        val secret = SecretIo.readSecretInput(secretFile = missing, prompt = "x", console = null, err = PrintStream(err))

        assertThat(secret).isNull()
        assertThat(err.toString()).contains("could not read --secret-file")
    }

    // ── output ─────────────────────────────────────────────────────────────

    @Test
    fun `emitSecret writes to a file with owner-only permissions and nothing to stdout`() {
        val out = out()
        val err = out()
        val file = tmp.resolve("emitted.txt").toFile()

        val emitted = SecretIo.emitSecret(
            label = "Client secret",
            secret = "minted",
            secretFile = file,
            forceStdout = false,
            // value irrelevant when secretFile is set
            stdoutIsTty = false,
            out = PrintStream(out),
            err = PrintStream(err),
        )

        assertThat(emitted).isTrue()
        assertThat(Files.readString(file.toPath()).trim()).isEqualTo("minted")
        assertThat(out.toString()).doesNotContain("minted")
        assertThat(err.toString()).contains("written to")

        if (file.toPath().fileSystem.supportedFileAttributeViews().contains("posix")) {
            val perms = Files.getPosixFilePermissions(file.toPath())
            assertThat(perms).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
            )
        }
    }

    @Test
    fun `emitSecret refuses a non-TTY stdout without forceStdout`() {
        val out = out()
        val err = out()

        val emitted = SecretIo.emitSecret(
            label = "Client secret",
            secret = "leaky",
            secretFile = null,
            forceStdout = false,
            stdoutIsTty = false,
            out = PrintStream(out),
            err = PrintStream(err),
        )

        assertThat(emitted).isFalse()
        assertThat(out.toString()).doesNotContain("leaky")
        assertThat(err.toString()).contains("Refusing to print")
    }

    @Test
    fun `emitSecret prints to a non-TTY stdout when forceStdout is set, with a warning`() {
        val out = out()
        val err = out()

        val emitted = SecretIo.emitSecret(
            label = "Client secret",
            secret = "forced",
            secretFile = null,
            forceStdout = true,
            stdoutIsTty = false,
            out = PrintStream(out),
            err = PrintStream(err),
        )

        assertThat(emitted).isTrue()
        assertThat(out.toString()).contains("forced")
        assertThat(err.toString()).contains("WARNING").contains("shown ONCE")
    }

    @Test
    fun `emitSecret prints to an interactive TTY with a warning`() {
        val out = out()
        val err = out()

        val emitted = SecretIo.emitSecret(
            label = "New client secret",
            secret = "tty-secret",
            secretFile = null,
            forceStdout = false,
            stdoutIsTty = true,
            out = PrintStream(out),
            err = PrintStream(err),
        )

        assertThat(emitted).isTrue()
        assertThat(out.toString()).contains("tty-secret")
        assertThat(err.toString()).contains("WARNING")
    }
}
