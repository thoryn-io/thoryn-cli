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
 * ## Backwards compatibility — SSO-3221 corrects what SSO-3199 assumed here
 *
 * SSO-3199 shipped this ahead of the platform on the argument that *the presentation scheme is
 * server-driven*: [schemeFor] returns `DPoP` only when the token response said `token_type: DPoP`,
 * so the CLI would keep sending `Authorization: Bearer` until the hub flipped the `cli` client.
 *
 * **That was true of the CLI and wrong about the hub.** Spring Authorization Server binds the token
 * to the proof's key and answers `token_type: DPoP` whenever a valid proof is present — it never
 * consults `token_settings_dpop_required`. So the CLI's own proof flipped the answer, the CLI
 * faithfully followed its own flip, and it began presenting `DPoP <token>` to resource servers that
 * did not accept the scheme. Every scheduled thoryn-examples run went red from 2026-09-19 04:23 UTC.
 *
 * The correction is [DpopCapability]: a proof rides on a token request **only when the hub
 * advertises DPoP support** in its discovery document. Everything else here is unchanged — the
 * scheme is still server-driven, and a machine with no usable key store still degrades to sending
 * no proof.
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
        // SSO-3227 — `key_class` is a TELEMETRY HINT AND NOTHING ELSE. It is self-asserted by the
        // client, sits outside the signature's semantics, and any server that made an authorization
        // decision on it would be trusting an attacker-chosen string. It is here because the platform
        // wants to see how much of the fleet is on hardware-backed keys, and because verifying that
        // the hub tolerates it was cheap: run against Spring Authorization Server's real proof parser
        // (`DPoPProofJwtDecoderFactory`, spring-security-oauth2-jose 7.1.1 — the same artefact oathy's
        // hub resolves), a proof carrying this header decodes exactly as one without it, because
        // Nimbus routes unrecognised header members to custom params and the `typ`/`jwk` validators
        // never look at them. See the SSO-3227 PR for the transcript.
        val header =
            """{"typ":"dpop+jwt","alg":"ES256","jwk":${key.publicJwkJson},"key_class":"${key.keyClass.wireValue}"}"""
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

    /**
     * SSO-3227 — the provider ladder, strongest first. A test that overrides [storeProvider] is
     * overriding the *software* rung, which is why the ladder is rebuilt from it rather than captured.
     */
    internal var ladder: () -> List<DpopKeyProvider> = {
        listOf(
            SecureElementDpopKeyProvider(clock = clock),
            SoftwareKeychainDpopKeyProvider(storeProvider = storeProvider, clock = clock),
            EphemeralDpopKeyProvider(clock = clock),
        )
    }

    @Volatile
    private var cached: DpopSession? = null

    @Volatile
    private var cachedResolution: DpopKeyProviders.Resolution? = null

    @Volatile
    private var provisioned: Boolean = false

    @Volatile
    private var unavailable: Boolean = false

    @Volatile
    private var warned: Boolean = false

    /**
     * SSO-3227 — the key that will actually sign, its protection class, and the reason each stronger
     * class was passed over. Memoised for the process; drives `thoryn whoami` / `thoryn status` and is
     * safe to call when signed out.
     *
     * Deliberately resolved by *loading*, not by asking: see [DpopKeyProviders.resolve]. A class is
     * only reported once a key of that class is in hand, so the line `whoami` prints is the protection
     * a session actually has rather than the protection the machine might in principle offer.
     */
    @Synchronized
    internal fun resolution(provision: Boolean = false): DpopKeyProviders.Resolution =
        cachedResolution ?: DpopKeyProviders.resolve(ladder(), provision).also { cachedResolution = it }

    /**
     * SSO-3227 — the protection class of the key this installation signs with, or null when no proof
     * can be minted at all (the non-persistent degrade). Display-only.
     */
    fun keyClass(): DpopKeyClass? = runCatching { resolution().keyClass.takeIf { it.persistent } }.getOrNull()

    /**
     * The installation's DPoP session, or null when no *persistent* key can be had (see the object
     * doc). A one-line warning is printed at most once per process in that case.
     *
     * @param provision SSO-3227 — allow a provider to CREATE a key it does not have yet. Only the
     *   `thoryn login` path passes true, so a routine command can never provision a hardware key
     *   mid-session and silently re-bind: an existing session keeps the key its token is bound to,
     *   and the upgrade lands on the next login, exactly as the story requires.
     */
    @Synchronized
    @JvmOverloads
    fun session(err: PrintStream = System.err, provision: Boolean = false): DpopSession? {
        // A provisioning pass may legitimately supersede a weaker key chosen earlier in this process
        // (whoami-then-login inside one `examples apply`, say) — so re-select once when asked.
        if (provision && !provisioned) {
            provisioned = true
            cached = null
            cachedResolution = null
            unavailable = false
        }
        cached?.let { return it }
        if (unavailable) return null
        return try {
            val resolved = resolution(provision)
            // No persistent key anywhere on the ladder. An in-memory key cannot honour a `cnf.jkt`
            // minted at login on the NEXT command, so binding a token to one would be worse than not
            // binding at all: degrade to no proof — the pre-SSO-3199 wire shape — and say why.
            val key = resolved.key ?: throw TokenStoreUnavailableException(
                resolved.skipped.lastOrNull { it.first.persistent }?.second
                    ?: resolved.keyClass.description,
            )
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

    /**
     * Delete the stored key so the next command generates a fresh one — `thoryn logout --rotate-key`.
     * Returns true when a key was present. The hub side needs no cleanup: a `cnf.jkt` only ever binds a
     * token, and the tokens are being discarded in the same breath.
     *
     * SSO-3227 — this asks **every** rung of the ladder to delete, not just the one currently
     * selected. A machine can hold both a Secure Enclave key and an older software key (that is
     * exactly the state a migration leaves behind, and the state a `--rotate-key` after losing a
     * laptop has to clean up), so "rotate" has to mean *no key of any class survives*. The recorded
     * presence timestamp goes with them.
     */
    @Synchronized
    fun rotate(): Boolean {
        val had = ladder().map { provider -> runCatching { provider.delete() }.getOrDefault(false) }.any { it }
        runCatching { UserPresence.clear() }
        cached = null
        cachedResolution = null
        provisioned = false
        unavailable = false
        return had
    }

    /** Test seam — drop the cached session / warning latch between tests. */
    internal fun resetForTest() {
        cached = null
        cachedResolution = null
        provisioned = false
        unavailable = false
        warned = false
        clock = { Instant.now() }
        jtiSource = { UUID.randomUUID().toString() }
        storeProvider = { DpopKeyStoreFactory.default() }
        DpopKeyProviders.resetForTest()
        UserPresence.resetForTest()
        // SSO-3227 — a test JVM is never a place to raise a biometric prompt. Surefire forks with
        // pipes, so `Tty.interactive()` would answer false anyway; pinning it makes that a guarantee
        // rather than an accident of how the suite happens to be launched.
        Tty.override = false
    }

    /**
     * A real [HttpSender] (the seam the token flows take) that attaches a DPoP proof to every request
     * and performs the single `use_dpop_nonce` retry. Falls back to a plain sender when no session is
     * available, so the flows behave exactly as they did before SSO-3199.
     *
     * ## SSO-3221 — and only to a platform that advertises DPoP
     *
     * The proof is withheld unless the hub this request is aimed at publishes
     * [DpopCapability.DISCOVERY_FIELD] (RFC 9449 §5.1). Sending one to a platform that does not
     * understand DPoP is what broke the fleet on 2026-09-19: the hub bound the token purely because
     * a proof arrived, answered `token_type: DPoP`, the CLI's scheme followed, and every resource
     * server that did not accept the scheme returned 401. See [DpopCapability].
     *
     * **The gate is here and not on API calls, deliberately.** The token endpoint is where a proof
     * causes something — it is what makes the hub bind and retype the response. On a gateway call
     * the proof is an extra header next to an `Authorization` whose scheme is already decided by
     * the token the hub issued; a server that does not know DPoP ignores it, and a server that does
     * needs it the moment the token is bound. Gating there would buy nothing and would cost a hub
     * round-trip on every command that runs on a still-fresh token.
     */
    fun sender(timeout: Duration = Duration.ofSeconds(15)): HttpSender {
        val client = HttpClient.newBuilder().connectTimeout(timeout).build()
        return HttpSender { request, handler ->
            // Capability first: on a platform that does not advertise DPoP this must not touch the
            // key store at all — no key generated on first use, and no "DPoP is disabled" warning
            // about a feature that would not have been used anyway.
            val session = if (DpopCapability.advertisedBy(DpopCapability.hubBaseOf(request.uri()))) session() else null
            if (session == null) client.send(request, handler)
            else session.send(request) { decorated -> client.send(decorated, handler) }
        }
    }
}
