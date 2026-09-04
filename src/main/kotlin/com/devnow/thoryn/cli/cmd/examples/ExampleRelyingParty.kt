package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.auth.PkceUtil
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import tools.jackson.databind.JsonNode
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * SSO-2830 — an EPHEMERAL local relying party for the sign-in example.
 *
 * A tiny localhost web app with a public landing page and a protected page,
 * standing in for "some protected page a user signs into". It runs a standard
 * OIDC Authorization-Code + PKCE flow against the tenant hub issuer — nothing is
 * added to oathy's deployed services (oathy stays Hub-product-only, SSO-1829):
 * this RP lives only for the duration of `thoryn examples <name> run`.
 *
 * Routes:
 *   GET /           public landing — a "Sign in" link.
 *   GET /login      start OIDC: fresh PKCE + state, 302 to {issuer}/oauth2/authorize.
 *   GET /callback   exchange the code at {issuer}/oauth2/token (public + PKCE), set a
 *                   session cookie, 302 to /protected.
 *   GET /protected  the protected page — shows the signed-in user's ID-token claims;
 *                   302 to /login when there is no session.
 *   GET /logout     clear the session, 302 to /.
 *
 * The redirect URI registered with the client is `http://127.0.0.1/callback`; the
 * hub ignores the loopback port at authorize time (RFC 8252 / SSO-2801), so the
 * app can bind any ephemeral port and send `http://127.0.0.1:{port}/callback`.
 */
internal class ExampleRelyingParty(
    private val tenantIssuer: String,
    private val clientId: String,
    private val scopes: String = "openid profile email",
    /** Invoked once, when the user first lands on /protected — carries the ID-token claims. */
    private val onSignedIn: (Map<String, Any?>) -> Unit = {},
) {
    private val mapper = jacksonObjectMapper()
    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    private lateinit var server: HttpServer
    var port: Int = 0
        private set

    /** state -> PKCE verifier for in-flight authorizations. */
    private val pending = ConcurrentHashMap<String, String>()

    /** Single-user local demo: the current session's ID-token claims (null = signed out). */
    @Volatile
    private var sessionClaims: Map<String, Any?>? = null

    @Volatile
    private var signalled = false

    val baseUrl: String get() = "http://127.0.0.1:$port"
    val redirectUri: String get() = "$baseUrl/callback"

    fun start(): ExampleRelyingParty {
        server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        port = server.address.port
        server.createContext("/") { ex -> route(ex) }
        server.executor = null
        server.start()
        return this
    }

    fun stop() {
        // SSO-2868 — give in-flight exchanges up to 2s to finish so a just-served /protected page is
        // never truncated by the shutdown.
        if (this::server.isInitialized) server.stop(2)
    }

    private fun route(ex: HttpExchange) {
        try {
            when (ex.requestURI.path) {
                "/" -> landing(ex)
                "/login" -> login(ex)
                "/callback" -> callback(ex)
                "/protected" -> protected(ex)
                "/logout" -> { sessionClaims = null; redirect(ex, "/") }
                else -> respond(ex, 404, "text/plain", "Not found")
            }
        } catch (t: Throwable) {
            respond(ex, 500, "text/html", page("Something went wrong", "<p class='err'>${escape(t.message ?: t.javaClass.simpleName)}</p><p><a href='/'>Back</a></p>"))
        } finally {
            ex.close()
        }
    }

    private fun landing(ex: HttpExchange) {
        val body = """
            <p>This is a demo relying party running locally on <code>$baseUrl</code>.</p>
            <p>Its <a href="/protected">protected page</a> requires a signed-in user.</p>
            <p><a class="btn" href="/login">Sign in with Thoryn →</a></p>
        """.trimIndent()
        respond(ex, 200, "text/html", page("Example app", body))
    }

    private fun login(ex: HttpExchange) {
        val verifier = PkceUtil.newCodeVerifier()
        val state = PkceUtil.newState()
        pending[state] = verifier
        val authorize = buildString {
            append(tenantIssuer.trimEnd('/')).append("/oauth2/authorize")
            append("?response_type=code")
            append("&client_id=").append(enc(clientId))
            append("&redirect_uri=").append(enc(redirectUri))
            append("&scope=").append(enc(scopes))
            append("&state=").append(enc(state))
            append("&code_challenge=").append(enc(PkceUtil.codeChallenge(verifier)))
            append("&code_challenge_method=S256")
        }
        redirect(ex, authorize)
    }

    private fun callback(ex: HttpExchange) {
        val params = queryParams(ex.requestURI.rawQuery)
        val error = params["error"]
        if (error != null) {
            respond(ex, 400, "text/html", page("Sign-in failed", "<p class='err'>${escape(error)}${params["error_description"]?.let { ": " + escape(it) } ?: ""}</p><p><a href='/'>Back</a></p>"))
            return
        }
        val code = params["code"]
        val state = params["state"]
        val verifier = state?.let { pending.remove(it) }
        if (code == null || verifier == null) {
            respond(ex, 400, "text/html", page("Sign-in failed", "<p class='err'>Missing or unrecognized authorization response (state mismatch).</p><p><a href='/'>Back</a></p>"))
            return
        }
        val tokenResponse = exchangeCode(code, verifier)
        val claims = tokenResponse?.get("id_token")?.asString()?.let { decodeJwtClaims(it) }
        if (claims == null) {
            respond(ex, 502, "text/html", page("Sign-in failed", "<p class='err'>Token exchange did not return a usable ID token.</p><p><a href='/'>Back</a></p>"))
            return
        }
        sessionClaims = claims
        redirect(ex, "/protected")
    }

    private fun protected(ex: HttpExchange) {
        val claims = sessionClaims
        if (claims == null) {
            redirect(ex, "/login")
            return
        }
        val subject = (claims["email"] ?: claims["preferred_username"] ?: claims["sub"])?.toString() ?: "you"
        val rows = claims.entries
            .filter { it.key !in setOf("nonce", "at_hash", "c_hash") }
            .sortedBy { it.key }
            .joinToString("") { (k, v) -> "<tr><td>${escape(k)}</td><td>${escape(v.toString())}</td></tr>" }
        val body = """
            <p class="ok">✓ You are signed in as <strong>${escape(subject)}</strong>.</p>
            <p>This page is protected — it renders only because the OIDC flow completed and a valid ID token was issued by your tenant.</p>
            <h3>Your ID-token claims</h3>
            <table>$rows</table>
            <p style="margin-top:1.5rem"><a href="/logout">Sign out</a></p>
        """.trimIndent()
        respond(ex, 200, "text/html", page("Protected page", body))

        // SSO-2868 — signal ONLY AFTER the protected page has been fully written to the browser.
        // Previously onSignedIn fired first, `run` woke on the latch and called `stop()`, and the
        // server shut down mid-response → the browser got ERR_CONNECTION_REFUSED on /protected even
        // though the CLI reported success. `respond()` fully flushes the body before this runs.
        if (!signalled) {
            signalled = true
            runCatching { onSignedIn(claims) }
        }
    }

    private fun exchangeCode(code: String, verifier: String): JsonNode? {
        val form = mapOf(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to redirectUri,
            "client_id" to clientId,
            "code_verifier" to verifier,
        ).entries.joinToString("&") { (k, v) -> "${enc(k)}=${enc(v)}" }
        val req = HttpRequest.newBuilder(URI(tenantIssuer.trimEnd('/') + "/oauth2/token"))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build()
        val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (resp.statusCode() !in 200..299) return null
        return runCatching { mapper.readTree(resp.body()) }.getOrNull()
    }

    private fun decodeJwtClaims(jwt: String): Map<String, Any?>? {
        val parts = jwt.split(".")
        if (parts.size < 2) return null
        return try {
            val payload = String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
            @Suppress("UNCHECKED_CAST")
            mapper.readValue(payload, Map::class.java) as Map<String, Any?>
        } catch (_: Exception) {
            null
        }
    }

    // --- tiny HTTP helpers -------------------------------------------------

    private fun respond(ex: HttpExchange, status: Int, contentType: String, body: String) {
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.add("Content-Type", "$contentType; charset=utf-8")
        ex.sendResponseHeaders(status, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    private fun redirect(ex: HttpExchange, location: String) {
        ex.responseHeaders.add("Location", location)
        ex.sendResponseHeaders(302, -1)
    }

    private fun queryParams(rawQuery: String?): Map<String, String> =
        rawQuery.orEmpty().split("&").filter { it.isNotBlank() }.associate {
            val i = it.indexOf('=')
            if (i < 0) it to "" else dec(it.substring(0, i)) to dec(it.substring(i + 1))
        }

    private fun enc(v: String) = URLEncoder.encode(v, StandardCharsets.UTF_8)
    private fun dec(v: String) = java.net.URLDecoder.decode(v, StandardCharsets.UTF_8)

    private fun escape(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun page(title: String, body: String): String = """
        <!doctype html><html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$title — Thoryn example</title>
        <style>
          body{font:16px/1.5 system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1.25rem;color:#1a1a2e}
          h1{font-size:1.4rem;margin:0 0 1rem} h3{margin-top:2rem}
          a.btn{display:inline-block;background:#3d5afe;color:#fff;padding:.6rem 1rem;border-radius:8px;text-decoration:none;font-weight:600}
          code{background:#eef;padding:.1rem .35rem;border-radius:4px}
          table{border-collapse:collapse;width:100%;font-size:.9rem} td{border-bottom:1px solid #e6e6ef;padding:.4rem .5rem;vertical-align:top}
          td:first-child{font-weight:600;white-space:nowrap;color:#555}
          .ok{color:#0a7d33;font-size:1.1rem} .err{color:#b00020}
        </style></head><body>
        <h1>$title</h1>
        $body
        </body></html>
    """.trimIndent()
}
