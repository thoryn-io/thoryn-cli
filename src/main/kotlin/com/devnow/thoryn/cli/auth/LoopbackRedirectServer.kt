package com.devnow.thoryn.cli.auth

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Tiny single-shot HTTP listener that receives the OAuth `?code=…&state=…`
 * redirect during a `thoryn login` Authorization Code + PKCE flow.
 *
 * ## Why a literal-IP bind, not `localhost` (RFC 8252 §7.3 — SSO-805)
 *
 * RFC 8252 §7.3 requires native clients to use the **IP literal** loopback
 * addresses (`127.0.0.1` and `[::1]`) for the loopback redirect URI rather
 * than the hostname `localhost`. The hostname goes through the host's DNS /
 * `/etc/hosts` resolver — a hostile or misconfigured entry that points
 * `localhost` somewhere else turns the loopback redirect into a DNS-rebinding
 * capture vector for the authorization code.
 *
 * `InetAddress.getLoopbackAddress()` returns the JVM's literal loopback
 * (`127.0.0.1` on IPv4-preferring systems, `::1` on IPv6-preferring
 * systems) — a literal address, never resolved via DNS. Binding the
 * `HttpServer` to that address (and building `redirect_uri` from
 * `getHostAddress()`) closes the rebinding vector at the CLI side.
 *
 * The hub's `RegisteredClient` for the CLI must allow both `127.0.0.1`
 * and `[::1]` redirect URIs in its allow-list to match — see the
 * Flyway migration that lands alongside this class.
 *
 * ## Lifecycle
 *
 *  1. `start()` binds an ephemeral port (port 0) on the loopback address and
 *     registers a single handler at [callbackPath] (default `/callback`).
 *     All other paths return 404.
 *  2. The browser redirects back from the hub. The handler captures the raw
 *     query string, writes a small HTML "you can close this tab" page, and
 *     hands the query off to a queue.
 *  3. `awaitCallback(timeout)` blocks on that queue and returns the captured
 *     query parameters as a [Map].
 *  4. `close()` stops the server with no grace period.
 *
 * The server is intentionally not a [java.io.Closeable] subclass with
 * `use { … }` semantics — the callback path interleaves with browser-driven
 * I/O, so the caller orchestrates `start` / `awaitCallback` / `close`
 * explicitly. That's standard for OAuth loopback listeners.
 */
class LoopbackRedirectServer(
    private val callbackPath: String = "/callback",
) {

    private val callbackQueue = LinkedBlockingQueue<Map<String, String>>(1)
    private var server: HttpServer? = null

    /**
     * The literal loopback address the server is (or will be) bound to.
     *
     * Resolved via [InetAddress.getLoopbackAddress] which returns a literal
     * IP — `127.0.0.1` on IPv4-preferring systems, `::1` on IPv6 — without
     * consulting DNS. Exposed for tests so they can assert
     * `isLoopbackAddress() == true` without touching the network.
     */
    val boundAddress: InetAddress = InetAddress.getLoopbackAddress()

    /**
     * The bound port. Only valid after [start] returns.
     *
     * Uses an ephemeral port (`new InetSocketAddress(loopback, 0)` asks
     * the kernel to pick a free port). Captured here so the caller can
     * build `redirect_uri = http://<ip>:<port>/callback` and put it on the
     * authorize URL.
     */
    var port: Int = 0
        private set

    /**
     * Start listening on the loopback interface. After this returns:
     *  - [port] is the kernel-assigned ephemeral port
     *  - [redirectUri] is the literal-IP URL to advertise to the hub
     *  - [awaitCallback] will return the first request to [callbackPath]
     *
     * Idempotent: calling `start` twice without [close] in between is a
     * usage error and throws.
     */
    fun start() {
        check(server == null) { "LoopbackRedirectServer already started" }
        // Binding via InetAddress (not the String overload) skips the DNS
        // resolver entirely — the literal IP from getLoopbackAddress() is
        // passed directly to the kernel. This is the SSO-805 / RFC 8252
        // §7.3 rebinding fix at the bind site.
        val httpServer = HttpServer.create(InetSocketAddress(boundAddress, 0), /* backlog = */ 0)
        httpServer.createContext(callbackPath) { exchange -> handleCallback(exchange) }
        httpServer.executor = null // default per-request executor; one shot is enough
        httpServer.start()
        server = httpServer
        port = httpServer.address.port
    }

    /**
     * The full `redirect_uri` to advertise to the hub.
     *
     * Built from the literal IP returned by
     * [InetAddress.getHostAddress] — `127.0.0.1` for IPv4 loopback, `::1`
     * for IPv6 — wrapped in `[…]` brackets when IPv6 per RFC 3986 §3.2.2.
     * Never contains the hostname `localhost`; that's the whole point of
     * SSO-805.
     */
    val redirectUri: String
        get() {
            check(server != null) { "LoopbackRedirectServer not started yet — call start() first" }
            val host = boundAddress.hostAddress
            // RFC 3986 §3.2.2: IPv6 literals must appear as `[address]:port`.
            val hostPart = if (host.contains(':')) "[$host]" else host
            return "http://$hostPart:$port$callbackPath"
        }

    /**
     * Block (up to [timeout]) for the OAuth authorization-server redirect to
     * arrive on [callbackPath]. Returns the parsed query parameters as a
     * map; throws [LoopbackTimeoutException] if no callback arrives in time.
     */
    fun awaitCallback(timeout: java.time.Duration): Map<String, String> {
        check(server != null) { "LoopbackRedirectServer not started yet — call start() first" }
        return callbackQueue.poll(timeout.toMillis(), TimeUnit.MILLISECONDS)
            ?: throw LoopbackTimeoutException(
                "No callback received on $redirectUri within ${timeout.toSeconds()}s",
            )
    }

    /** Stop the listener. Safe to call multiple times. */
    fun close() {
        server?.stop(0)
        server = null
    }

    private fun handleCallback(exchange: HttpExchange) {
        try {
            val raw = exchange.requestURI.rawQuery.orEmpty()
            val params = parseQueryString(raw)
            // Best-effort enqueue; the bounded queue holds 1 — duplicate
            // browser refreshes after the first callback are dropped here
            // and answered with the same friendly page.
            callbackQueue.offer(params)
            val body = if (params.containsKey("error")) errorPage(params) else successPage()
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders["Content-Type"] = listOf("text/html; charset=utf-8")
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        } finally {
            exchange.close()
        }
    }

    private fun successPage(): String =
        """<!doctype html>
        |<html lang="en"><head><meta charset="utf-8"><title>Signed in — Thoryn CLI</title></head>
        |<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">
        |  <h1>Signed in.</h1>
        |  <p>You can close this tab and return to the terminal.</p>
        |</body></html>
        |""".trimMargin()

    private fun errorPage(params: Map<String, String>): String {
        val err = params["error"].orEmpty()
        val desc = params["error_description"].orEmpty()
        return """<!doctype html>
            |<html lang="en"><head><meta charset="utf-8"><title>Sign-in failed — Thoryn CLI</title></head>
            |<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">
            |  <h1>Sign-in failed.</h1>
            |  <p><strong>${escapeHtml(err)}</strong></p>
            |  <p>${escapeHtml(desc)}</p>
            |  <p>Return to the terminal — the CLI will print the same error.</p>
            |</body></html>
            |""".trimMargin()
    }

    companion object {

        /**
         * Parse `key=value&key=value` form-encoded query strings into a map.
         * Repeated keys keep the first value (sufficient for OAuth
         * `code` / `state` / `error` parameters which never repeat).
         */
        internal fun parseQueryString(raw: String): Map<String, String> {
            if (raw.isBlank()) return emptyMap()
            val result = LinkedHashMap<String, String>()
            for (pair in raw.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val (k, v) = if (eq < 0) pair to "" else pair.substring(0, eq) to pair.substring(eq + 1)
                if (k.isEmpty()) continue
                val key = urlDecode(k)
                val value = urlDecode(v)
                result.putIfAbsent(key, value)
            }
            return result
        }

        private fun urlDecode(s: String): String =
            java.net.URLDecoder.decode(s, StandardCharsets.UTF_8)

        private fun escapeHtml(s: String): String =
            s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;")
    }
}

/** Thrown by [LoopbackRedirectServer.awaitCallback] when no redirect arrives in the allowed window. */
class LoopbackTimeoutException(message: String) : RuntimeException(message)
