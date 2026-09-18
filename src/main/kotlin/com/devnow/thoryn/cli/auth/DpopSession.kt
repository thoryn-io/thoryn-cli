package com.devnow.thoryn.cli.auth

import java.io.PrintStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * SSO-3199 — **DPoP (RFC 9449) for the `thoryn` CLI**: mints a proof JWT for every outbound request
 * and handles the `DPoP-Nonce` challenge.
 *
 * ## What rides on the wire
 *
 * Every request the CLI sends to the hub token endpoint (authorization-code redemption, `refresh_token`,
 * the RFC 8693 workspace-switch exchange, device-code polling, client-credentials) and every hub /
 * gateway API call carries a `DPoP:` header holding a freshly-signed proof:
 *
 * ```
 * header  { "typ":"dpop+jwt", "alg":"ES256", "jwk": <public JWK of the installation key> }
 * claims  { "htm":"POST", "htu":"https://api.example/…", "iat":…, "jti":…, ["ath":…], ["nonce":…] }
 * ```
 *
 * - `htu` is the target URI **without query or fragment** (§4.2). It is derived by string truncation of
 *   the actual request URI, so the percent-encoding the server sees is the percent-encoding that was
 *   hashed — re-parsing through [URI] would normalise it and produce spurious mismatches.
 * - `ath` — base64url(SHA-256(ASCII(access token))) — is added **only** when the request presents a
 *   DPoP-bound access token, i.e. when its `Authorization` header uses the `DPoP` scheme (§7.1).
 * - `nonce` is added when the server has handed one out for that origin (see below).
 *
 * ## Backwards compatibility — why this is safe before the hub requires DPoP
 *
 * The hub accepts a proof **optionally** today (`token_settings_dpop_required` is false for the `cli`
 * client until the oathy-side flip): a proof present ⇒ the access token gains `cnf.jkt`; absent ⇒ a plain
 * bearer token. So sending a proof changes nothing until the flip. The presentation scheme is driven by
 * the server, not by the CLI: [authorizationScheme] returns `DPoP` **only** when the token response said
 * `token_type: DPoP`, and `Bearer` otherwise — so against today's hub and today's resource servers (which
 * have no DPoP support yet) the CLI keeps sending `Authorization: Bearer …` exactly as before.
 *
 * ## Nonce handling (§8)
 *
 * A server may demand a nonce: the authorization server answers `400` with `error=use_dpop_nonce`, a
 * resource server answers `401` with `WWW-Authenticate: DPoP …error="use_dpop_nonce"`; both supply the
 * value in the `DPoP-Nonce` response header. [send] caches that nonce **per origin** and retries the
 * request **exactly once** with a proof carrying it. The cache lives for the process — a CLI invocation
 * is short-lived, and a stale nonce simply produces one more challenge-and-retry.
 */
class DpopSession(
    val key: DpopKey,
    private val clock: () -> Instant = { Instant.now() },
    private val jtiSource: () -> String = { UUID.randomUUID().toString() },
) {

    /** `origin -> most recent server nonce`. Per-process; see the class doc. */
    private val nonces = ConcurrentHashMap<String, String>()

    /** The RFC 7638 thumbprint of this installation's key — the `cnf.jkt` the hub binds into tokens. */
    val thumbprint: String get() = key.thumbprint

    /**
     * Build a proof for [method] + [uri]. [accessToken] non-null adds the `ath` binding (§4.2); the
     * cached nonce for the URI's origin is included when present.
     */
    fun proof(method: String, uri: URI, accessToken: String? = null): String {
        val header = """{"typ":"dpop+jwt","alg":"ES256","jwk":${key.publicJwkJson}}"""
        val claims = buildString {
            append("""{"htm":"""").append(method.uppercase()).append('"')
            append(""","htu":"""").append(jsonEscape(htu(uri))).append('"')
            append(""","iat":""").append(clock().epochSecond)
            append(""","jti":"""").append(jsonEscape(jtiSource())).append('"')
            accessToken?.let { append(""","ath":"""").append(ath(it)).append('"') }
            nonces[origin(uri)]?.let { append(""","nonce":"""").append(jsonEscape(it)).append('"') }
            append('}')
        }
        return key.signCompact(header, claims)
    }

    /**
     * Return [request] with a `DPoP` proof header attached (replacing any previous one, so a retry
     * re-signs rather than sending two proofs).
     */
    fun decorate(request: HttpRequest): HttpRequest {
        val accessToken = request.headers().firstValue("Authorization").orElse(null)
            ?.takeIf { it.startsWith("$SCHEME ", ignoreCase = true) }
            ?.substring(SCHEME.length + 1)
            ?.trim()
        val proof = proof(request.method(), request.uri(), accessToken)
        return HttpRequest.newBuilder(request, { _, _ -> true }).setHeader(HEADER, proof).build()
    }

    /**
     * Send [request] with a proof attached, retrying **once** when the server answers a
     * `use_dpop_nonce` challenge (§8). [transport] performs the actual I/O.
     */
    fun <T> send(request: HttpRequest, transport: (HttpRequest) -> HttpResponse<T>): HttpResponse<T> {
        val first = transport(decorate(request))
        val nonce = nonceChallenge(first) ?: return first
        nonces[origin(request.uri())] = nonce
        return transport(decorate(request))
    }

    /** Instance shorthand for [DpopSession.schemeFor]. */
    fun authorizationScheme(tokens: Tokens): String = schemeFor(tokens)

    /**
     * The nonce a server is asking us to use, or null when the response is not a nonce challenge.
     * `400 use_dpop_nonce` from the authorization server, `401` + `WWW-Authenticate: DPoP` from a
     * resource server; in both cases the value arrives in the `DPoP-Nonce` header, and without that
     * header there is nothing to retry with.
     */
    private fun nonceChallenge(response: HttpResponse<*>): String? {
        val nonce = response.headers().firstValue(NONCE_HEADER).orElse(null)?.takeIf { it.isNotBlank() } ?: return null
        return when (response.statusCode()) {
            400 -> nonce.takeIf { (response.body() as? String)?.contains(USE_DPOP_NONCE) == true }
            401 -> nonce.takeIf {
                response.headers().allValues("WWW-Authenticate").any { header ->
                    header.contains(USE_DPOP_NONCE, ignoreCase = true) ||
                        header.trimStart().startsWith(SCHEME, ignoreCase = true)
                }
            }
            else -> null
        }
    }

    companion object {
        /** The request header carrying the proof JWT. */
        const val HEADER: String = "DPoP"

        /** The response header carrying a server-supplied nonce (§8). */
        const val NONCE_HEADER: String = "DPoP-Nonce"

        /** The `Authorization` scheme (and `token_type`) for a sender-constrained token (§7.1). */
        const val SCHEME: String = "DPoP"

        /** The error code both the AS (400) and the RS (401) use to demand a nonce (§8). */
        const val USE_DPOP_NONCE: String = "use_dpop_nonce"

        /**
         * The `Authorization` scheme to present [tokens] with: `DPoP` when the token endpoint answered
         * `token_type: DPoP` (RFC 9449 §5, §7.1), `Bearer` otherwise.
         *
         * Deliberately a property of the TOKEN, not of whether this installation can currently sign a
         * proof: a bound token is a DPoP token however the CLI is feeling, and presenting it as a bearer
         * would be a silent downgrade rather than an honest failure.
         */
        fun schemeFor(tokens: Tokens): String =
            if (tokens.tokenType.equals(SCHEME, ignoreCase = true)) SCHEME else "Bearer"

        /** `ath` — base64url(SHA-256(ASCII(access token))) (§4.2). */
        internal fun ath(accessToken: String): String =
            DpopKey.b64u(MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.US_ASCII)))

        /** `htu` — the target URI with query and fragment removed, by truncation (see class doc). */
        internal fun htu(uri: URI): String =
            uri.toString().substringBefore('?').substringBefore('#')

        /** Nonce cache key: scheme + authority. */
        internal fun origin(uri: URI): String = "${uri.scheme}://${uri.authority}"

        private fun jsonEscape(value: String): String = buildString {
            for (c in value) {
                when (c) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
                }
            }
        }
    }
}

/**
 * SSO-3199 — process-wide access to the installation's [DpopSession].
 *
 * The key is loaded from [DpopKeyStore] on first use and generated + persisted when absent, so it is
 * stable across invocations (a fresh key on every command would defeat the whole point: a `cnf.jkt`
 * minted at login has to still be provable at the next `thoryn clients list`).
 *
 * **Degrades to no-DPoP rather than failing.** When no secure store is available the session is null and
 * every call site simply omits the proof — exactly the pre-SSO-3199 wire shape. This keeps the release
 * safe on machines the hub has not yet flipped to `dpop_required`; after the flip such a machine gets a
 * clear `invalid_dpop_proof` from the hub, which is the honest failure.
 */
object Dpop {

    /** Test seam — substitute the store (and hence the key) without touching a real keychain. */
    internal var storeProvider: () -> DpopKeyStore = { DpopKeyStoreFactory.default() }

    /** Test seam — deterministic clock / jti for proof-structure assertions. */
    internal var clock: () -> Instant = { Instant.now() }
    internal var jtiSource: () -> String = { UUID.randomUUID().toString() }

    @Volatile
    private var cached: DpopSession? = null

    @Volatile
    private var unavailable: Boolean = false

    @Volatile
    private var warned: Boolean = false

    /**
     * The installation's DPoP session, or null when no secure store is available (see the object doc).
     * A one-line warning is printed at most once per process in that case.
     */
    @Synchronized
    fun session(err: PrintStream = System.err): DpopSession? {
        cached?.let { return it }
        if (unavailable) return null
        return try {
            val store = storeProvider()
            val stored = store.read()
            val key = if (stored != null) {
                runCatching { DpopKey.fromStored(stored) }.getOrNull() ?: generateAndStore(store)
            } else {
                generateAndStore(store)
            }
            DpopSession(key, clock, jtiSource).also { cached = it }
        } catch (e: Exception) {
            unavailable = true
            if (!warned) {
                warned = true
                err.println(
                    "Note: sender-constrained tokens (DPoP) are disabled for this invocation — " +
                        "${e.message ?: e.javaClass.simpleName}. Requests are sent without a DPoP proof.",
                )
            }
            null
        }
    }

    private fun generateAndStore(store: DpopKeyStore): DpopKey =
        DpopKey.generate(clock()).also { store.write(it.toStored()) }

    /**
     * Delete the stored key so the next command generates a fresh one — `thoryn logout --rotate-key`.
     * Returns true when a key was present. The hub side needs no cleanup: a `cnf.jkt` only ever binds a
     * token, and the tokens are being discarded in the same breath.
     */
    @Synchronized
    fun rotate(): Boolean {
        val store = runCatching { storeProvider() }.getOrNull() ?: return false
        val had = runCatching { store.read() }.getOrNull() != null
        runCatching { store.delete() }
        cached = null
        unavailable = false
        return had
    }

    /** Test seam — drop the cached session / warning latch between tests. */
    internal fun resetForTest() {
        cached = null
        unavailable = false
        warned = false
        clock = { Instant.now() }
        jtiSource = { UUID.randomUUID().toString() }
        storeProvider = { DpopKeyStoreFactory.default() }
    }

    /**
     * A real [HttpSender] (the seam the token flows take) that attaches a DPoP proof to every request
     * and performs the single `use_dpop_nonce` retry. Falls back to a plain sender when no session is
     * available, so the flows behave exactly as they did before SSO-3199.
     */
    fun sender(timeout: Duration = Duration.ofSeconds(15)): HttpSender {
        val client = HttpClient.newBuilder().connectTimeout(timeout).build()
        return HttpSender { request, handler ->
            val session = session()
            if (session == null) client.send(request, handler)
            else session.send(request) { decorated -> client.send(decorated, handler) }
        }
    }
}
