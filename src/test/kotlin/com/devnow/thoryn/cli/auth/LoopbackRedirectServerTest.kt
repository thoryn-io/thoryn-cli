package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.HttpURLConnection
import java.net.URI
import java.time.Duration

/**
 * Unit tests for [LoopbackRedirectServer] — the temporary HTTP listener
 * the CLI uses to catch the OAuth `?code=…` redirect during a
 * loopback-redirect Authorization Code flow.
 *
 * The big behavioural assertions here are the SSO-805 / RFC 8252 §7.3
 * contracts: the server binds to a literal-IP loopback address (no DNS
 * resolution of `localhost`) and the `redirect_uri` it advertises is
 * built from that literal IP.
 */
class LoopbackRedirectServerTest {

    private val server = LoopbackRedirectServer()

    @AfterEach
    fun tearDown() {
        server.close()
    }

    @Test
    fun `bound address is a loopback IP literal — never the hostname (RFC 8252 section 7 dot 3)`() {
        server.start()

        // The bound address must report as a loopback per java.net.InetAddress.
        // This is the SSO-805 contract — the kernel sees the literal IP, not
        // a hostname that DNS / /etc/hosts could re-point.
        assertThat(server.boundAddress.isLoopbackAddress)
            .withFailMessage("Bound address %s is not a loopback address", server.boundAddress)
            .isTrue()

        // getHostAddress() returns the textual literal — `127.0.0.1` on
        // IPv4-preferring systems, `::1` on IPv6-preferring systems. It must
        // never be the string "localhost", which is the bug RFC 8252 §7.3
        // and SSO-805 close.
        val literal = server.boundAddress.hostAddress
        assertThat(literal).isIn("127.0.0.1", "0:0:0:0:0:0:0:1", "::1")
        assertThat(literal).doesNotContain("localhost")
    }

    @Test
    fun `redirect URI uses the literal loopback IP, not the hostname`() {
        server.start()

        val uri = server.redirectUri
        // Must contain the literal IP form …
        assertThat(uri).matches(Regex("""http://(127\.0\.0\.1|\[::1]|\[0:0:0:0:0:0:0:1]):\d+/callback""").toPattern())
        // … and must not advertise `localhost` to the hub.
        assertThat(uri).doesNotContain("localhost")
        // The port is the kernel-assigned ephemeral port, captured on start.
        assertThat(server.port).isPositive()
        assertThat(uri).contains(":${server.port}/callback")
    }

    @Test
    fun `awaitCallback returns the parsed query parameters when the browser redirects in`() {
        server.start()

        // Drive a synthetic browser redirect on a separate thread so the main
        // thread can wait on awaitCallback (the public, blocking entry point).
        val driver = Thread {
            val url = URI("${server.redirectUri}?code=abc123&state=xyz%2F").toURL()
            (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 2_000
                readTimeout = 2_000
                inputStream.use { it.readAllBytes() } // drain the success page
                disconnect()
            }
        }
        driver.start()

        val params = server.awaitCallback(Duration.ofSeconds(5))
        driver.join(2_000)

        assertThat(params).containsEntry("code", "abc123")
        // RFC 3986 percent-decoding: `%2F` → `/`.
        assertThat(params).containsEntry("state", "xyz/")
    }

    @Test
    fun `awaitCallback throws LoopbackTimeoutException when no redirect arrives in time`() {
        server.start()

        // No browser thread spun up — this must time out fast and not hang
        // the test runner.
        assertThrows<LoopbackTimeoutException> {
            server.awaitCallback(Duration.ofMillis(50))
        }
    }

    @Test
    fun `parseQueryString handles empty values, missing equals signs, and percent-encoding`() {
        // White-box test against the helper directly — covers edge cases we
        // can't easily produce via a real HTTP request from another test.
        val result = LoopbackRedirectServer.parseQueryString("code=abc&state=&debug&pkce=A%20B")
        assertThat(result).containsEntry("code", "abc")
        assertThat(result).containsEntry("state", "")
        assertThat(result).containsEntry("debug", "")
        assertThat(result).containsEntry("pkce", "A B")
    }

    @Test
    fun `start cannot be called twice without close in between`() {
        server.start()

        assertThrows<IllegalStateException> {
            server.start()
        }
    }

    @Test
    fun `redirectUri throws before start so callers cannot accidentally advertise an unbound port`() {
        // The port field defaults to 0 until start() runs. Building a redirect
        // URI from that would produce `http://127.0.0.1:0/callback`, which
        // looks legitimate but cannot receive callbacks. Fail loudly instead.
        assertThrows<IllegalStateException> {
            server.redirectUri
        }
    }
}
