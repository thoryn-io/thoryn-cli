package com.devnow.thoryn.cli

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import picocli.CommandLine
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * Sanity tests for the picocli wiring — `--version` and `--help` work, and
 * unknown commands error cleanly.
 */
class ThorynMainTest {

    @Test
    fun `version flag prints the version and exits zero`() {
        val (exitCode, out, _) = run("--version")
        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("thoryn")
        assertThat(out).contains("0.0.1-SNAPSHOT")
    }

    @Test
    fun `help flag prints usage and exits zero`() {
        val (exitCode, out, _) = run("--help")
        assertThat(exitCode).isEqualTo(0)
        assertThat(out).contains("Thoryn customer-plane CLI")
        assertThat(out).contains("login")
        assertThat(out).contains("logout")
        assertThat(out).contains("clients")
    }

    @Test
    fun `clients with no subcommand prints usage to stderr and exits 64`() {
        val (exitCode, _, err) = run("clients")
        assertThat(exitCode).isEqualTo(64)
        assertThat(err).contains("Usage: thoryn clients")
    }

    @Test
    fun `unknown command exits non-zero`() {
        val (exitCode, _, _) = run("nonexistent-command")
        assertThat(exitCode).isNotEqualTo(0)
    }

    private fun run(vararg args: String): Triple<Int, String, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val originalOut = System.out
        val originalErr = System.err
        try {
            System.setOut(PrintStream(out))
            System.setErr(PrintStream(err))
            val exit = CommandLine(ThorynMain()).execute(*args)
            return Triple(exit, out.toString(), err.toString())
        } finally {
            System.setOut(originalOut)
            System.setErr(originalErr)
        }
    }
}
