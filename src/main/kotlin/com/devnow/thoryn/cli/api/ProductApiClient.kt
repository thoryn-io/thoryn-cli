package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.Tokens
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import tools.jackson.module.kotlin.readValue
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Typed wrapper around `java.net.http.HttpClient` for the product-api
 * endpoints the supply-chain CLI hits. The CLI is GraalVM-native-image bound,
 * so we use the JDK HTTP client (already on the classpath via
 * `ClientsCommand` / `AuditReplayCommand`) rather than Spring's reactive
 * WebClient — there's nothing to `.block()` on, no Reactor dependency, and
 * one less reflection-heavy library to feed to native-image.
 *
 * Authentication: every method takes a [Tokens] (read from the local store
 * by the caller) and adds `Authorization: Bearer <access>` automatically.
 * A 401 from the gateway surfaces as a [ProductApiException]
 * (HTTP 401) — the existing `LogoutCommand` clears local tokens; an explicit
 * "refresh + retry" loop is a follow-up.
 *
 * Errors: any non-2xx response throws [ProductApiException] carrying the
 * status code and the OAuth2 `error` code parsed from the body, when
 * present. Subcommands map `error_description.contains("scope")` /
 * `error == "insufficient_scope"` into a "Run `oathy login --scope …`"
 * hint per the SSO-959 acceptance criteria.
 *
 * **No `.block()`** — the JDK HTTP client is synchronous; the
 * SSO-771 reactive-bridge rule doesn't apply. Per-request timeout is 30 s,
 * matching the existing `ClientsCommand.ListSubcommand` behaviour.
 */
class ProductApiClient(
    private val gateway: String,
    private val tokens: Tokens,
    private val http: HttpClient = defaultClient(),
    private val mapper: ObjectMapper = defaultMapper(),
) {

    // ── Trust Registry (SSO-954) ────────────────────────────────────────────

    fun listTrustRegistryCredentialClasses(): JsonNode =
        get("/api/v1/trust-registry/credential-classes")

    fun listTrustRegistryIssuers(credentialClass: String): JsonNode =
        get("/api/v1/trust-registry/credential-classes/${encode(credentialClass)}/issuers")

    fun addTrustRegistryIssuer(credentialClass: String, body: Map<String, Any?>): JsonNode =
        post("/api/v1/trust-registry/credential-classes/${encode(credentialClass)}/issuers", body)

    fun removeTrustRegistryIssuer(credentialClass: String, issuerId: String): JsonNode =
        delete("/api/v1/trust-registry/credential-classes/${encode(credentialClass)}/issuers/${encode(issuerId)}")

    fun previewTrustRegistryIssuer(body: Map<String, Any?>): JsonNode =
        post("/api/v1/trust-registry/issuers/preview", body)

    // ── Verification policy (SSO-955) ───────────────────────────────────────

    fun listVerificationPolicies(): JsonNode =
        get("/api/v1/verification-policies")

    fun getVerificationPolicy(credentialClass: String): JsonNode =
        get("/api/v1/verification-policies/${encode(credentialClass)}")

    fun setVerificationPolicy(credentialClass: String, body: Map<String, Any?>): JsonNode =
        put("/api/v1/verification-policies/${encode(credentialClass)}", body)

    // ── Audit log (SSO-956) ─────────────────────────────────────────────────

    fun searchAuditLog(query: Map<String, String?>): JsonNode {
        val qs = query.entries
            .mapNotNull { (k, v) -> if (v.isNullOrBlank()) null else "${encode(k)}=${encode(v)}" }
            .joinToString("&")
        val path = if (qs.isEmpty()) "/api/v1/audit-log" else "/api/v1/audit-log?$qs"
        return get(path)
    }

    fun getAuditLogRow(auditRowId: String): JsonNode =
        get("/api/v1/audit-log/${encode(auditRowId)}")

    /**
     * Fetch the JSON receipt for an audit row — same shape as
     * `GET /admin/audit-logs/{rowId}/receipt` on the broker.
     */
    fun getAuditLogReceiptJson(auditRowId: String): JsonNode =
        get("/api/v1/audit-log/${encode(auditRowId)}/receipt.json")

    /**
     * Fetch the binary PDF receipt for an audit row. Returns the raw bytes
     * so the caller can write to a file (or pipe to stdout for `> file.pdf`).
     */
    fun getAuditLogReceiptPdf(auditRowId: String): ByteArray {
        val request = baseRequest("/api/v1/audit-log/${encode(auditRowId)}/receipt.pdf")
            .header("Accept", "application/pdf")
            .GET()
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        if (response.statusCode() !in 200..299) {
            // For PDF endpoint a non-2xx body might still be JSON error.
            val body = response.body()?.let { String(it, Charsets.UTF_8) } ?: ""
            throw ProductApiException.fromResponse(response.statusCode(), body, mapper)
        }
        return response.body() ?: ByteArray(0)
    }

    // ── Issuer-bridges (SSO-957) ────────────────────────────────────────────

    fun listIssuerBridges(): JsonNode =
        get("/api/v1/issuer-bridges")

    fun getIssuerBridge(bridgeId: String): JsonNode =
        get("/api/v1/issuer-bridges/${encode(bridgeId)}")

    fun listIssuerBridgeCredentials(bridgeId: String, query: Map<String, String?>): JsonNode {
        val qs = query.entries
            .mapNotNull { (k, v) -> if (v.isNullOrBlank()) null else "${encode(k)}=${encode(v)}" }
            .joinToString("&")
        val path = "/api/v1/issuer-bridges/${encode(bridgeId)}/credentials" +
            if (qs.isEmpty()) "" else "?$qs"
        return get(path)
    }

    fun revokeIssuerBridgeCredential(bridgeId: String, credentialId: String, reason: String): JsonNode =
        post(
            "/api/v1/issuer-bridges/${encode(bridgeId)}/credentials/${encode(credentialId)}/revoke",
            mapOf("reason" to reason),
        )

    /**
     * Drive a step of the five-step key-rotation wizard (SSO-957). The body
     * is forwarded verbatim — `step` is the wizard step name
     * (`generate`, `publish`, `cut-over`, `monitor`, `retire`).
     */
    fun rotateIssuerBridgeKey(bridgeId: String, step: String): JsonNode =
        when (step) {
            "generate" -> post("/api/v1/issuer-bridges/${encode(bridgeId)}/keys", mapOf("step" to step))
            else -> patchKey(bridgeId, step)
        }

    private fun patchKey(bridgeId: String, step: String): JsonNode {
        // PATCH on the current kid for the bridge — the server resolves
        // "current kid" from the bridge record so the CLI doesn't have to
        // chain a GET.
        val body = mapOf("step" to step)
        val request = baseRequest("/api/v1/issuer-bridges/${encode(bridgeId)}/keys/current")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .method("PATCH", HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
        return execute(request)
    }

    // ── Generic verbs ───────────────────────────────────────────────────────

    private fun get(path: String): JsonNode {
        val request = baseRequest(path)
            .header("Accept", "application/json")
            .GET()
            .build()
        return execute(request)
    }

    private fun post(path: String, body: Any): JsonNode {
        val request = baseRequest(path)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
        return execute(request)
    }

    private fun put(path: String, body: Any): JsonNode {
        val request = baseRequest(path)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
        return execute(request)
    }

    private fun delete(path: String): JsonNode {
        val request = baseRequest(path)
            .header("Accept", "application/json")
            .DELETE()
            .build()
        return execute(request)
    }

    private fun execute(request: HttpRequest): JsonNode {
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        val body = response.body() ?: ""
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), body, mapper)
        }
        if (body.isBlank()) return mapper.nullNode()
        return mapper.readTree(body)
    }

    private fun baseRequest(path: String): HttpRequest.Builder {
        val uri = URI.create("${gateway.trimEnd('/')}$path")
        return HttpRequest.newBuilder()
            .uri(uri)
            .timeout(Duration.ofSeconds(30))
            .header("Authorization", "Bearer ${tokens.accessToken}")
    }

    private fun encode(s: String): String = URLEncoder.encode(s, Charsets.UTF_8)

    companion object {
        fun defaultClient(): HttpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()

        fun defaultMapper(): ObjectMapper = JsonMapper.builder()
            .addModule(kotlinModule())
            .build()
    }
}

/**
 * Thrown when the product-api returns a non-2xx response.
 *
 * The OAuth2 / problem+json bodies the gateway returns carry an `error`
 * code (`insufficient_scope`, `invalid_token`, `invalid_tenant`, …) and an
 * optional `error_description`. The CLI surfaces both — the error code so
 * we can route to a "run `oathy login --scope …`" hint, the description so
 * the user sees the human-readable reason.
 */
class ProductApiException(
    val httpStatus: Int,
    /** OAuth2 error code, or null if the body wasn't OAuth2-shaped. */
    val errorCode: String?,
    val errorDescription: String?,
    /** Raw body for `--output json` structured-error reporting. */
    val rawBody: String,
) : RuntimeException("HTTP $httpStatus: ${errorCode ?: "no_error_code"}${errorDescription?.let { " — $it" } ?: ""}") {

    /** True if this is a "you don't have the right scope" failure. */
    val isInsufficientScope: Boolean
        get() = httpStatus == 403 || errorCode == "insufficient_scope"

    companion object {
        fun fromResponse(status: Int, body: String, mapper: ObjectMapper): ProductApiException {
            val (code, description) = parseOAuthError(body, mapper)
            return ProductApiException(status, code, description, body)
        }

        private fun parseOAuthError(body: String, mapper: ObjectMapper): Pair<String?, String?> {
            if (body.isBlank()) return null to null
            return try {
                val parsed: Map<String, Any?> = mapper.readValue(body)
                val code = parsed["error"] as? String
                val description = (parsed["error_description"] as? String)
                    ?: (parsed["message"] as? String)
                    ?: (parsed["detail"] as? String)
                code to description
            } catch (_: Exception) {
                null to null
            }
        }
    }
}
