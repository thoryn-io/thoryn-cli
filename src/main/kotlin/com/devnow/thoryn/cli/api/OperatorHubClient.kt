package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.DpopSession
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.Tokens
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-3356 — the operator-plane client: calls the hub's `/admin/…` operator surface DIRECTLY.
 *
 * Not the gateway, and not a public hub host. The hub refuses `/admin` on every public address —
 * at the edge (the chart's deny Ingress) and in the hub itself (`AdminSurfaceExposureFilter`,
 * SSO-3177 / SSO-3365) — so an operator reaches it through
 * `kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080`, which is what [hubUrl] points at by
 * default. The request's `Host` is then `localhost:18080`: not a configured public host, so the
 * exposure filter passes it, and the hub's tenant resolution treats `localhost` as its own
 * in-process host. [com.devnow.thoryn.cli.cmd.operator.OperatorHubTarget] refuses any URL that is not
 * such a private address before this class is ever constructed.
 *
 * ## Credentials
 *
 * The operator session's token (`thoryn operator login`), presented under the scheme the hub issued
 * it with: `Bearer` for an ordinary token, `DPoP` for a sender-constrained one (RFC 9449 §7.1). A
 * DPoP proof is attached ONLY for a bound token, and its `htu` is the exact URL this client sends to
 * — the port-forward URL — which is also the hub's own view of the request (it reconstructs the URL
 * from the `Host` it receives; the hub's resource-server DPoP check is strict, SSO-3272). Today the
 * operator client `thoryn-operator` is neither DPoP-required nor DPoP-allowed (hub V174 and the
 * cutover list), so its tokens are plain bearers and no proof is sent.
 *
 * Errors are RFC 9457 problem details (`errorCode` + `detail`) from the operator gate and the custom-
 * domain controller; a scope refusal is a bare `403` with `WWW-Authenticate: Bearer
 * error="insufficient_scope"` (Spring Security's own), which [OperatorHubException] also captures.
 */
class OperatorHubClient(
    private val hubUrl: String,
    private val tokens: Tokens,
    private val dpop: DpopSession? = null,
    private val sender: HttpSender = defaultSender(),
    private val mapper: ObjectMapper = defaultMapper(),
) {

    /** `PUT /admin/tenants/{slug}/custom-domain/entitlement` — body `{"entitled": <entitled>}`. */
    fun setCustomDomainEntitlement(slug: String, entitled: Boolean): JsonNode =
        send("PUT", "/admin/tenants/${encode(slug)}/custom-domain/entitlement", mapOf("entitled" to entitled))

    /** `GET /admin/tenants/{slug}/custom-domain` — the workspace's custom domain, or `404 custom_domain_not_found`. */
    fun getCustomDomain(slug: String): JsonNode =
        send("GET", "/admin/tenants/${encode(slug)}/custom-domain", body = null)

    private fun send(method: String, path: String, body: Any?): JsonNode {
        val uri = URI.create("${hubUrl.trimEnd('/')}$path")
        val scheme = DpopSession.schemeFor(tokens)
        val builder = HttpRequest.newBuilder()
            .uri(uri)
            .timeout(Duration.ofSeconds(30))
            .header("Accept", "application/json, application/problem+json")
            .header("Authorization", "$scheme ${tokens.accessToken}")
        val publisher = if (body == null) {
            HttpRequest.BodyPublishers.noBody()
        } else {
            builder.header("Content-Type", "application/json")
            HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))
        }
        val request = builder.method(method, publisher).build()
        // A proof only for a BOUND token: a bearer token needs none, and the scheme is a property of
        // the token the hub issued, never of whether this machine happens to hold a key.
        val bound = scheme.equals(DpopSession.SCHEME, ignoreCase = true)
        val response = if (bound && dpop != null) {
            dpop.send(request) { decorated -> sender.send(decorated, HttpResponse.BodyHandlers.ofString()) }
        } else {
            sender.send(request, HttpResponse.BodyHandlers.ofString())
        }
        val status = response.statusCode()
        val text = response.body().orEmpty()
        if (status in 200..299) {
            return if (text.isBlank()) mapper.createObjectNode() else mapper.readTree(text)
        }
        throw OperatorHubException.from(
            status = status,
            body = text,
            wwwAuthenticate = response.headers().firstValue("WWW-Authenticate").orElse(null),
            mapper = mapper,
        )
    }

    private fun encode(s: String): String = URLEncoder.encode(s, Charsets.UTF_8).replace("+", "%20")

    companion object {
        fun defaultSender(): HttpSender {
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
            return HttpSender { request, handler -> client.send(request, handler) }
        }

        fun defaultMapper(): ObjectMapper = JsonMapper.builder().addModule(kotlinModule()).build()
    }
}

/**
 * A non-2xx answer from the hub's operator surface.
 *
 * [errorCode] is the RFC 9457 `errorCode` extension (`not_found`, `operator_passkey_required`,
 * `custom_domain_not_found`, …), the RFC 6750 `error` from a `WWW-Authenticate` challenge
 * (`insufficient_scope`, `invalid_token`) when the body carried none, or the legacy `error` member of
 * the hub's tenant-resolution refusal (`unknown_tenant`). [detail] is the human sentence.
 */
class OperatorHubException(
    val httpStatus: Int,
    val errorCode: String?,
    val detail: String?,
    val rawBody: String,
) : RuntimeException("HTTP $httpStatus: ${errorCode ?: "no_error_code"}${detail?.let { " — $it" } ?: ""}") {

    companion object {
        private val CHALLENGE_ERROR = Regex("""error\s*=\s*"([^"]+)"""")

        fun from(status: Int, body: String, wwwAuthenticate: String?, mapper: ObjectMapper): OperatorHubException {
            val node: JsonNode? = runCatching { mapper.readTree(body) }.getOrNull()?.takeIf { it.isObject }
            fun text(field: String): String? = node?.get(field)?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            val fromChallenge = wwwAuthenticate?.let { CHALLENGE_ERROR.find(it)?.groupValues?.get(1) }
            val code = text("errorCode") ?: text("error") ?: fromChallenge
            val detail = text("detail") ?: text("error_description")
            return OperatorHubException(status, code, detail, body)
        }
    }
}
