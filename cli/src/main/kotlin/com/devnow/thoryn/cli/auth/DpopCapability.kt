package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * SSO-3221 — **does this platform actually support DPoP?** Answered from the hub's own OIDC
 * discovery document, and memoised per hub for the life of the process.
 *
 * ## Why the CLI has to ask before it sends a proof
 *
 * `cli-v0.20.0` (SSO-3199) attached a DPoP proof to every token-endpoint request. The compatibility
 * argument for shipping that ahead of the platform was: *the presentation scheme is server-driven,
 * so the CLI keeps sending `Authorization: Bearer` until the hub says `token_type: DPoP`.* True of
 * the CLI — and it missed that the hub says `token_type: DPoP` **as soon as a proof is sent**.
 * Spring Authorization Server binds whenever a valid proof is present, without consulting the
 * client. So the CLI's own proof flipped the answer, the CLI followed its own flip, and it began
 * presenting `DPoP <token>` to resource servers that did not accept the scheme. Every scheduled
 * thoryn-examples run went red from 2026-09-19 04:23 UTC.
 *
 * The hub half of SSO-3221 stops binding unless the client opted in. This is the client half, and
 * the two are deliberately redundant: a released binary outlives any single platform version, so
 * the CLI should not depend on every deployment it ever meets carrying the hub fix. **Send a proof
 * only to a platform that says it understands proofs.**
 *
 * ## The signal
 *
 * `dpop_signing_alg_values_supported` in `{hub}/.well-known/openid-configuration`. RFC 9449 §5.1
 * defines it as the JWS algorithms the authorization server accepts in a DPoP proof, and states
 * that its presence is how a client learns the server supports DPoP. A non-empty array is the
 * whole test.
 *
 * **There is no second, gateway-side signal to check.** The customer-plane gateway and product-api
 * advertise no capability document today — DPoP resource-server support arrived there as security
 * configuration, not as metadata — so discovery is the only advertisement that exists. That is
 * acceptable because the two tiers deploy together from one chart, and because the hub half of
 * SSO-3221 is the load-bearing fix; this gate is the belt to its braces. If a gateway capability
 * endpoint is ever added, [advertisedBy] is the one place that has to learn about it.
 *
 * ## Cost, and where the gate is applied
 *
 * One small unauthenticated `GET`, at most once per hub per process, and **only on a command that
 * reaches the token endpoint** — a sign-in, a refresh, a workspace exchange, a device poll. A
 * command that runs on a still-fresh token and only calls the gateway never probes at all. See
 * [Dpop.sender] for why the gate lives at the token endpoint and not on API calls.
 *
 * Any failure — unreachable, non-200, unparseable, field absent or empty — answers **no**, which is
 * the pre-SSO-3199 wire shape and cannot break anything. A hub that cannot serve its own discovery
 * document is a hub the command was about to fail against anyway.
 */
object DpopCapability {

    private val memo = ConcurrentHashMap<String, Boolean>()

    /** Test seam — replaces the network probe. Keyed by the hub base URL. */
    internal var probe: (String) -> Boolean = { fetch(it) }

    /** RFC 9449 §5.1 — the discovery field whose presence advertises DPoP support. */
    const val DISCOVERY_FIELD: String = "dpop_signing_alg_values_supported"

    /**
     * True when the hub at [hubBaseUrl] advertises DPoP support. Memoised per hub; a blank or
     * unparseable base answers false.
     */
    fun advertisedBy(hubBaseUrl: String?): Boolean {
        val base = hubBaseUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() } ?: return false
        return memo.computeIfAbsent(base) { probe(it) }
    }

    /**
     * The hub base a token-endpoint request was aimed at.
     *
     * Derived from the request URI by stripping the endpoint path, so a hub deployed under a path
     * prefix still resolves to the right discovery document; anything unrecognised falls back to
     * the origin, which is correct for every deployment shape the CLI supports today.
     */
    internal fun hubBaseOf(uri: URI): String {
        val url = uri.toString().substringBefore('?').substringBefore('#')
        TOKEN_ENDPOINT_PATHS.firstOrNull { url.endsWith(it) }?.let { return url.removeSuffix(it) }
        return "${uri.scheme}://${uri.authority}"
    }

    /** Test seam — drop the memo between tests. */
    internal fun resetForTest() {
        memo.clear()
        probe = { fetch(it) }
    }

    /** Force an answer for [hubBaseUrl] without a network call — tests, and nothing else. */
    internal fun seedForTest(hubBaseUrl: String, advertised: Boolean) {
        memo[hubBaseUrl.trim().trimEnd('/')] = advertised
    }

    private fun fetch(hubBaseUrl: String): Boolean = try {
        val client = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()
        val request = HttpRequest.newBuilder(URI.create("$hubBaseUrl/.well-known/openid-configuration"))
            .timeout(READ_TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        response.statusCode() == 200 && advertisesDpop(response.body())
    } catch (_: Exception) {
        // Unreachable, interrupted, TLS failure — answer "no proof", the shape that cannot break.
        false
    }

    /** True when [body] is a discovery document carrying a non-empty [DISCOVERY_FIELD] array. */
    internal fun advertisesDpop(body: String?): Boolean {
        if (body.isNullOrBlank()) return false
        val algorithms = runCatching { MAPPER.readTree(body)[DISCOVERY_FIELD] }.getOrNull() ?: return false
        return algorithms.isArray && algorithms.any { !it.asString().isNullOrBlank() }
    }

    private val MAPPER = ObjectMapper()
    private val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(3)
    private val READ_TIMEOUT: Duration = Duration.ofSeconds(5)

    /** Endpoint paths a token-endpoint request can carry; stripped to recover the hub base. */
    private val TOKEN_ENDPOINT_PATHS = listOf("/oauth2/token", "/oauth2/device_authorization")
}
