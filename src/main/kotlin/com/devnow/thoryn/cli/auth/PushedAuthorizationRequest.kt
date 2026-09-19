package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * SSO-3234 — **does this platform take pushed authorization requests, and where?** Answered from
 * the hub's own OIDC discovery document (RFC 9126 §5,
 * [`pushed_authorization_request_endpoint`](https://www.rfc-editor.org/rfc/rfc9126#section-5)), and
 * memoised per hub for the life of the process.
 *
 * Deliberately shaped like [DpopCapability], including the memo, the test seams and the
 * everything-fails-to-"no" rule — same question, same answer surface, one thing to learn. It
 * returns the **endpoint** rather than a boolean because the client needs the URL, and because
 * RFC 9126 §5 advertises support by publishing that URL and in no other way.
 */
object ParCapability {

    /** RFC 9126 §5 — the discovery field that both advertises PAR support and locates the endpoint. */
    const val DISCOVERY_FIELD: String = "pushed_authorization_request_endpoint"

    private val memo = ConcurrentHashMap<String, String>()
    private val NONE = ""

    /** Test seam — replaces the network probe. Keyed by the hub base URL. */
    internal var probe: (String) -> String? = { fetch(it) }

    /**
     * The PAR endpoint the hub at [hubBaseUrl] advertises, or null when it advertises none.
     *
     * A hub that does not publish the field does not (as far as any client can tell) support PAR,
     * and the caller uses the plain authorize URL. Unreachable, non-200 and unparseable all answer
     * null for the same reason [DpopCapability] does: that is the older wire shape, and it cannot
     * break anything a fresh hub was going to accept.
     */
    fun endpointFor(hubBaseUrl: String?): String? {
        val base = hubBaseUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() } ?: return null
        return memo.computeIfAbsent(base) { probe(it) ?: NONE }.takeIf { it.isNotEmpty() }
    }

    /** The advertised endpoint in a discovery document [body], or null. Pure — no I/O. */
    internal fun endpointIn(body: String?): String? {
        if (body.isNullOrBlank()) return null
        val node = runCatching { MAPPER.readTree(body)[DISCOVERY_FIELD] }.getOrNull() ?: return null
        return node.asString()?.trim()?.takeIf { it.isNotEmpty() }
    }

    /** Test seam — drop the memo between tests. */
    internal fun resetForTest() {
        memo.clear()
        probe = { fetch(it) }
    }

    /** Force an answer for [hubBaseUrl] without a network call — tests, and nothing else. */
    internal fun seedForTest(hubBaseUrl: String, endpoint: String?) {
        memo[hubBaseUrl.trim().trimEnd('/')] = endpoint ?: NONE
    }

    private fun fetch(hubBaseUrl: String): String? = try {
        val client = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()
        val request = HttpRequest.newBuilder(URI.create("$hubBaseUrl/.well-known/openid-configuration"))
            .timeout(READ_TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() == 200) endpointIn(response.body()) else null
    } catch (_: Exception) {
        null
    }

    private val MAPPER = ObjectMapper()
    private val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(3)
    private val READ_TIMEOUT: Duration = Duration.ofSeconds(5)
}

/** The outcome of a push. */
sealed interface ParPushResult {

    /**
     * RFC 9126 §2.2 — the hub took the request. [requestUri] is single-use (§4) and [expiresIn] is
     * its lifetime in seconds, or null when the hub did not say.
     */
    data class Pushed(val requestUri: String, val expiresIn: Long?) : ParPushResult

    /**
     * The hub **understood and refused** the request (4xx). This is never downgraded to the plain
     * authorize URL: see [PushedAuthorizationRequestFlow] for why.
     */
    data class Refused(val status: Int, val errorCode: String?, val description: String?) : ParPushResult

    /** The push could not be delivered or the hub failed on it (5xx, transport, unparseable 201). */
    data class Unavailable(val reason: String) : ParPushResult
}

/**
 * SSO-3234 — pushes an authorization request to the hub's RFC 9126 endpoint and returns the opaque
 * `request_uri` the browser will carry instead of the parameters themselves.
 *
 * ## Why the CLI bothers
 *
 * On the plain authorize URL every parameter of the request — the scopes, the `redirect_uri`,
 * PKCE's `code_challenge`, and since SSO-3225 `dpop_jkt` — travels through the **browser**: its
 * address bar, its history, its extensions, and whatever sits between it and the hub. A pushed
 * request sends the same parameters back-channel, straight from this process to the hub over TLS,
 * and the browser then carries only `client_id` and an opaque single-use reference. It is the
 * FAPI 2.0 baseline, and it is the precondition for ever marking this client
 * `require_pushed_authorization_requests`.
 *
 * ## Client authentication
 *
 * The `thoryn` CLI is a public client (`token_endpoint_auth_method=none`, SSO-2822), so per
 * RFC 9126 §2 — which applies the token endpoint's rules to this endpoint and names
 * `token_endpoint_auth_method` as what decides them — the `client_id` in the body is the whole of
 * its authentication. When a client secret IS configured the push authenticates with HTTP Basic,
 * mirroring [AuthorizationCodeFlow].
 *
 * ## No DPoP proof on the push — and why the client is built here
 *
 * RFC 9449 §10.1 offers two ways to name the DPoP key on a pushed request: `dpop_jkt` in the body,
 * or a `DPoP` proof header (from which the server derives the same binding). The CLI uses the
 * **first**, and passes exactly the `dpop_jkt` the front-channel request would have carried, so the
 * binding is identical whether or not PAR is in play and there is one code path to reason about.
 * The header variant would additionally spend a single-use `jti` on a request that is not a grant,
 * and §10.1 requires the two to agree when both are sent — so sending both buys nothing. Nothing in
 * discovery says a server *requires* the header form, and §10.1 requires servers to support both,
 * so there is no signal that could make the CLI prefer it. The hub's own support for the header
 * form is unverified, and SSO-3225 already recorded the shape of that risk: a parameter a server
 * validates strictly can fail a sign-in outright.
 *
 * So the flow builds its **own plain [HttpClient]** rather than accepting the login command's
 * DPoP-decorating [HttpSender]. That is not tidiness: [Dpop.sender] attaches a proof to any request
 * whose host advertises DPoP, and the PAR endpoint is on that host — so simply passing the login
 * command's sender in silently sent BOTH mechanisms, which is what an early revision of this class
 * did and what `PushedAuthorizationRequestTest` now catches. Owning the client makes "the push
 * carries no proof" a property of the type instead of a habit of its callers.
 *
 * ## The 4xx rule
 *
 * A `5xx` or a transport failure is [ParPushResult.Unavailable] and the caller falls back to the
 * plain authorize URL — the hub is having a bad day and the older wire shape still works. A **4xx
 * is surfaced as an error, never downgraded**: it means the hub understood the push and rejected
 * it, and silently retrying front-channel would both hide a real misconfiguration and hand an
 * on-path attacker a way to strip PAR off every sign-in by forging one 400.
 */
class PushedAuthorizationRequestFlow(
    private val parEndpoint: String,
    private val mapper: ObjectMapper = ObjectMapper(),
) {

    /** Plain by construction — see the class doc. Never [Dpop.sender]. */
    private val client: HttpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()

    /**
     * Push [parameters] (the authorize parameters, minus `request_uri`, which RFC 9126 §2.1
     * forbids in a pushed request).
     */
    fun push(parameters: List<Pair<String, String>>, clientSecret: String? = null): ParPushResult {
        val builder = HttpRequest.newBuilder()
            .uri(URI.create(parEndpoint))
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(formEncode(parameters)))
        if (clientSecret != null) {
            val clientId = parameters.firstOrNull { it.first == "client_id" }?.second.orEmpty()
            builder.header("Authorization", basicAuth(clientId, clientSecret))
        }

        val response = try {
            client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            return ParPushResult.Unavailable(e.message ?: e::class.simpleName ?: "transport failure")
        }

        val status = response.statusCode()
        if (status in 400..499) {
            val (code, description) = parseError(response.body())
            return ParPushResult.Refused(status, code, description)
        }
        if (status != 201 && status != 200) {
            return ParPushResult.Unavailable("the hub answered HTTP $status")
        }

        val body = runCatching { mapper.readTree(response.body()) }.getOrNull()
            ?: return ParPushResult.Unavailable("the hub's response was not JSON")
        val requestUri = body[REQUEST_URI]?.asString()?.takeIf { it.isNotBlank() }
            ?: return ParPushResult.Unavailable("the hub's response carried no $REQUEST_URI")
        val expiresIn = body["expires_in"]?.takeIf { it.isNumber }?.asLong()
        return ParPushResult.Pushed(requestUri, expiresIn)
    }

    private fun parseError(body: String?): Pair<String?, String?> = try {
        val node = mapper.readTree(body.orEmpty())
        node["error"]?.asString() to node["error_description"]?.asString()
    } catch (_: Exception) {
        null to null
    }

    private fun formEncode(pairs: List<Pair<String, String>>): String =
        pairs.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}"
        }

    private fun basicAuth(id: String, secret: String): String =
        "Basic ${java.util.Base64.getEncoder().encodeToString("$id:$secret".toByteArray(Charsets.UTF_8))}"

    private companion object {
        const val REQUEST_URI = "request_uri"
        val REQUEST_TIMEOUT: Duration = Duration.ofSeconds(15)
        val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(5)
    }
}
