package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.ConnectException
import java.net.UnknownHostException

/**
 * SSO-2827 — the CLI must default the hub/gateway to the ones recorded at login.
 * SSO-2828 — a transport failure must name the target host and a real cause, never
 * print the bare `Request failed: null`.
 */
class CommandSupportSessionAndErrorsTest {

    private fun session(issuer: String? = null, gateway: String? = null) =
        Tokens(accessToken = "a", issuer = issuer, gateway = gateway)

    // ---- SSO-2827: host resolution -----------------------------------------

    @Test
    fun `resolveHub prefers an explicit non-default hub over the session`() {
        assertThat(
            CommandSupport.resolveHub("https://hub.stg.thoryn.org", session(issuer = "https://hub.other.org")),
        ).isEqualTo("https://hub.stg.thoryn.org")
    }

    @Test
    fun `resolveHub falls back to the session issuer when the flag is the local default`() {
        assertThat(
            CommandSupport.resolveHub(ThorynConfig.DEFAULT_HUB, session(issuer = "https://hub.stg.thoryn.org")),
        ).isEqualTo("https://hub.stg.thoryn.org")
    }

    @Test
    fun `resolveHub falls back to the local default with no session`() {
        assertThat(CommandSupport.resolveHub(ThorynConfig.DEFAULT_HUB, null)).isEqualTo(ThorynConfig.DEFAULT_HUB)
        assertThat(CommandSupport.resolveHub(ThorynConfig.DEFAULT_HUB, session(issuer = null)))
            .isEqualTo(ThorynConfig.DEFAULT_HUB)
    }

    @Test
    fun `resolveGateway mirrors resolveHub for the gateway`() {
        assertThat(
            CommandSupport.resolveGateway(ThorynConfig.DEFAULT_GATEWAY, session(gateway = "https://api.stg.thoryn.org")),
        ).isEqualTo("https://api.stg.thoryn.org")
        assertThat(
            CommandSupport.resolveGateway("https://api.custom.org", session(gateway = "https://api.stg.thoryn.org")),
        ).isEqualTo("https://api.custom.org")
    }

    // ---- SSO-2828: failure rendering ---------------------------------------

    @Test
    fun `describeThrowable never returns null when the exception message is null`() {
        assertThat(CommandSupport.describeThrowable(ConnectException())).isEqualTo("connection refused")
    }

    @Test
    fun `describeThrowable classifies unknown host and appends the message`() {
        assertThat(CommandSupport.describeThrowable(UnknownHostException("hub.stg.thoryn.org")))
            .isEqualTo("unknown host (hub.stg.thoryn.org)")
    }

    @Test
    fun `describeThrowable walks the cause chain to classify the root`() {
        val wrapped = RuntimeException(null as String?, ConnectException("host down"))
        assertThat(CommandSupport.describeThrowable(wrapped)).isEqualTo("connection refused (host down)")
    }

    @Test
    fun `renderRequestFailure prints the target host and cause, and never the word null`() {
        val buf = ByteArrayOutputStream()
        val code = CommandSupport.renderRequestFailure(ConnectException(), "https://api.stg.thoryn.org", PrintStream(buf))
        assertThat(code).isEqualTo(CommandSupport.EXIT_IO_ERROR)
        assertThat(buf.toString())
            .contains("https://api.stg.thoryn.org")
            .contains("connection refused")
            .doesNotContain("null")
    }
}
