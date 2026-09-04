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

    // ── OAuth applications / clients (SSO-1552; product-api SSO-1027/SSO-1028) ─
    //
    // The CLI targets the `/api/v1/applications` surface (NOT the thinner
    // `/clients`) for ALL client ops so the CLI and console share one contract:
    // `/api/v1/applications` is the console's surface and the only one that
    // carries secret rotation. Maintaining two divergent client surfaces would
    // fork the audit trail and the validation rules.

    fun listApplications(): JsonNode =
        get("/api/v1/applications")

    fun getApplication(clientId: String): JsonNode =
        get("/api/v1/applications/${encode(clientId)}")

    fun createApplication(body: Map<String, Any?>): JsonNode =
        post("/api/v1/applications", body)

    fun updateApplication(clientId: String, body: Map<String, Any?>): JsonNode =
        patch("/api/v1/applications/${encode(clientId)}", body)

    /**
     * DELETE returns 204 No Content on success; surfaces non-2xx as [ProductApiException].
     *
     * [confirmSlug] (SSO-2413) — when non-blank, sent as the [CONFIRM_HEADER]
     * (`X-Thoryn-Confirm`) so a delete targeting the caller's **production**
     * workspace clears product-api's `ProductionConfirmationInterceptor`
     * (`428 production_confirmation_required` otherwise, `422` on mismatch).
     * Sandbox / non-production deletes are ungated and need no value.
     */
    fun deleteApplication(clientId: String, confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/applications/${encode(clientId)}", confirmSlug)

    /**
     * `POST /api/v1/applications/{id}/secret/rotate` — returns the new plaintext
     * secret ONCE (`newSecret`) plus the previous-secret overlap expiry. 409 when
     * a rotation is already in flight; 404 cross-tenant / unknown id.
     *
     * [confirmSlug] (SSO-2413) — see [deleteApplication]; a production-plane
     * rotation is gated the same way.
     */
    fun rotateApplicationSecret(clientId: String, confirmSlug: String? = null): JsonNode =
        post("/api/v1/applications/${encode(clientId)}/secret/rotate", emptyMap<String, Any?>(), confirmSlug)

    // ── Federation members (SSO-1552; product-api SSO-1034 / SSO-1548 oidc) ────
    //
    // product-api mounts the controller at the UNVERSIONED `/federation-members`,
    // and the api-gateway also exposes the canonical `/api/v1/federation-members/[**]`
    // (StripPrefix=2 → product-api). SSO-2068 repoints the CLI onto the canonical
    // `/api/v1` path; the unversioned alias stays live through the deprecation window.

    fun listFederationMembers(): JsonNode =
        get("/api/v1/federation-members")

    fun createFederationMember(body: Map<String, Any?>): JsonNode =
        post("/api/v1/federation-members", body)

    /**
     * DELETE returns 204 No Content on success; surfaces non-2xx as [ProductApiException].
     *
     * [confirmSlug] (SSO-2413) — see [deleteApplication]; a production-plane
     * federation-member delete is gated the same way.
     */
    fun deleteFederationMember(memberId: String, confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/federation-members/${encode(memberId)}", confirmSlug)

    // ── Workspace (SSO-1552; hub /account/[*] — NOT behind the gateway) ────────
    //
    // The hub's workspace surface is gated by `SCOPE_openid` only (any signed-in
    // user) and is NOT routed through the api-gateway, so these methods are
    // called against a client whose base URL is the HUB issuer, not the gateway.

    fun listWorkspaces(): JsonNode =
        get("/account/workspaces")

    fun createWorkspace(body: Map<String, Any?>): JsonNode =
        post("/account/workspace", body)

    /**
     * SSO-2831 — `POST /account/workspace/{tenantId}/archive` — archives (soft-suspends)
     * a workspace. Guarded by a name-confirmation: [confirmSlug] is sent as the
     * [CONFIRM_HEADER] (`X-Thoryn-Confirm`) and must equal the workspace slug, or the hub
     * answers `428 workspace_confirmation_required` (missing) / `422 workspace_confirmation_mismatch`.
     * Reversible via [reactivateWorkspace]. Hub-routed (not the gateway).
     */
    fun archiveWorkspace(tenantId: String, confirmSlug: String? = null): JsonNode =
        post("/account/workspace/${encode(tenantId)}/archive", emptyMap<String, Any?>(), confirmSlug)

    /** SSO-2831 — `POST /account/workspace/{tenantId}/reactivate` — clears the archive flag. */
    fun reactivateWorkspace(tenantId: String): JsonNode =
        post("/account/workspace/${encode(tenantId)}/reactivate", emptyMap<String, Any?>())

    /**
     * SSO-2859 — `POST /account/workspace/{tenantId}/hard-delete` — IRREVERSIBLY deletes a
     * workspace (SSO-2831 distributed teardown): suspends the tenant immediately and enqueues the
     * purge of every tenant-scoped row across hub / product-api / identity + the per-tenant Vault
     * keys. Returns **202 Accepted** (the async poller completes the purge). Name-confirmation
     * guarded: [confirmSlug] rides as [CONFIRM_HEADER] (`X-Thoryn-Confirm`) and must equal the
     * workspace slug, or the hub replies 428 (required) / 422 (mismatch).
     */
    fun hardDeleteWorkspace(tenantId: String, confirmSlug: String? = null): JsonNode =
        post("/account/workspace/${encode(tenantId)}/hard-delete", emptyMap<String, Any?>(), confirmSlug)

    /**
     * `POST /api/v1/tenants` on product-api (gateway-routed) — registers a
     * freshly-created hub workspace in product-api's `tenant_registry`. The only
     * product-api endpoint exempt from the `tnt`-claim filter. Called against a
     * GATEWAY-based client right after [createWorkspace].
     */
    fun registerTenant(body: Map<String, Any?>): JsonNode =
        post("/api/v1/tenants", body)

    // ── Audit events (SSO-1552; product-api tenant:audit.read surface) ─────────
    //
    // The gateway-routed, `tenant:audit.read`-gated customer audit-events query
    // path is `/api/v1/audit/events`. The backend query implementation lands under epic
    // SSO-725 (today it answers 501); the CLI is a thin marshaller that surfaces
    // whatever the server returns, so it works the moment the backend ships.

    fun queryAuditEvents(query: Map<String, String?>): JsonNode {
        val qs = query.entries
            .mapNotNull { (k, v) -> if (v.isNullOrBlank()) null else "${encode(k)}=${encode(v)}" }
            .joinToString("&")
        val path = if (qs.isEmpty()) "/api/v1/audit/events" else "/api/v1/audit/events?$qs"
        return get(path)
    }

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

    // ── Credential types (SSO-1593) ─────────────────────────────────────────
    //
    // Tenant-facing credential-type catalog. `enable` / `disable` address a
    // catalog entry by its URL-safe SLUG (`crew-authorization`), never the VCT
    // URL. Read endpoints need `tenant:supply-chain.credential-types.read`;
    // mutations need `tenant:supply-chain.credential-types.write`.

    fun listCredentialTypeCatalog(): JsonNode =
        get("/api/v1/credential-types/catalog")

    fun listCredentialTypeBindings(): JsonNode =
        get("/api/v1/credential-types")

    /**
     * `PUT /api/v1/credential-types/{catalogId}` — enable/adopt a catalog type,
     * with an optional display override in [body]. Idempotent; returns the
     * resulting binding. Pass an empty map to adopt with the catalog default
     * display.
     */
    fun enableCredentialType(catalogId: String, body: Map<String, Any?>): JsonNode =
        put("/api/v1/credential-types/${encode(catalogId)}", body)

    /**
     * `DELETE /api/v1/credential-types/{catalogId}` — soft-disable. Returns 204
     * (no body); surfaces non-2xx as [ProductApiException]. 404 `not_found` when
     * the tenant never enabled the type (privacy-symmetric).
     */
    fun disableCredentialType(catalogId: String): Unit =
        deleteNoContent("/api/v1/credential-types/${encode(catalogId)}")

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
     *
     * SSO-968 — `includeChain=true` requests a chain-of-custody PDF: cover
     * page + per-link pages + final "how to verify offline" page. If the
     * server-side PDF exceeds the 20 MB cap, the response is a ZIP-of-PDFs
     * (content-type `application/zip`); the CLI passes the raw bytes
     * through and lets the caller inspect the magic header / file extension.
     */
    fun getAuditLogReceiptPdf(auditRowId: String, includeChain: Boolean = false): ByteArray {
        val basePath = "/api/v1/audit-log/${encode(auditRowId)}/receipt.pdf"
        val path = if (includeChain) "$basePath?includeChain=true" else basePath
        val request = baseRequest(path)
            // Accept both PDF and ZIP — server picks the format based on size.
            .header("Accept", "application/pdf, application/zip")
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

    // ── Chain-of-custody (SSO-970 / SSO-962, SSO-964, SSO-965, SSO-967) ─────

    /**
     * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/receive` — server-side
     * verify N parents without state change. Mirrors the console's Receive
     * screen (SSO-962). Scope: `tenant:supply-chain.issuer-bridge.intermediary.read`.
     *
     * The body carries the list of parents as either compact JWS payloads or
     * credential URNs; the product-api forwards each to
     * `POST /broker/verify/walletless` and returns a normalised verdict per
     * parent for the operator to acknowledge before the action screen.
     */
    fun intermediaryReceive(bridgeId: String, body: Map<String, Any?>): JsonNode =
        post("/api/v1/issuer-bridges/${encode(bridgeId)}/intermediary/receive", body)

    /**
     * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/issue` — orchestrates
     * combine and split paths through the broker's bulk-issue endpoint
     * (SSO-962 + SSO-963). Scope: `tenant:supply-chain.issuer-bridge.intermediary.write`.
     *
     * The body's `action` field discriminates:
     *  - `processed_combined` / `packaged_combined` — produces 1 child from N parents.
     *  - `split` — produces N children from 1 parent, returned as a list with
     *    embedded JWS + (optional) per-child QR-PDF bytes.
     */
    fun intermediaryIssue(bridgeId: String, body: Map<String, Any?>): JsonNode =
        post("/api/v1/issuer-bridges/${encode(bridgeId)}/intermediary/issue", body)

    /**
     * `POST /broker/verify/walletless?walkChain=true` — chain walker (SSO-964).
     *
     * The body carries the leaf credential as compact JWS or URN; the broker
     * walks `parentCredentialIds` upward and returns a tree with per-node
     * verdict plus the lowest-common-denominator aggregate at the root. The
     * default `walkChain=false` path is unchanged from SSO-949.
     */
    fun verifyWalletlessWithChain(body: Map<String, Any?>): JsonNode =
        post("/broker/verify/walletless?walkChain=true", body)

    /**
     * `POST /broker/internal/credentials/{credentialId}/revoke` — direct revoke
     * with automatic descendant propagation (SSO-965). Scope:
     * `tenant:supply-chain.issuer-bridge.revoke`.
     *
     * Returns the source revoke audit row plus a summary of descendants
     * flipped to `REVOKED_VIA_PARENT`.
     */
    fun revokeCredentialWithPropagation(credentialId: String, reason: String): JsonNode =
        post(
            "/broker/internal/credentials/${encode(credentialId)}/revoke",
            mapOf("reason" to reason),
        )

    /**
     * `GET /broker/internal/credentials/{credentialId}/descendants` — operator
     * view of the downward DAG (SSO-965 blast-radius preview). Depth-capped
     * server-side (depth 5 per SSO-964 conventions). Scope:
     * `tenant:supply-chain.issuer-bridge.revoke` (this is the operator's
     * pre-revoke "what would I break?" call).
     */
    fun getCredentialDescendants(credentialId: String, depth: Int? = null): JsonNode {
        val path = "/broker/internal/credentials/${encode(credentialId)}/descendants" +
            if (depth != null) "?depth=$depth" else ""
        return get(path)
    }

    /**
     * `GET /api/v1/holder/credentials/{credentialId}/descendants` — holder-portal
     * downward view, subject to the tenant's `hideDownstreamFromProducers`
     * privacy toggle (SSO-967). Returns either the full tree or a
     * `{ descendants: null, reason: "tenant_privacy_policy" }` payload when
     * the tenant has the toggle on.
     *
     * Scope: same as the holder portal's read filter; the CLI re-uses the
     * standard tenant scope set.
     */
    fun getHolderCredentialDescendants(credentialId: String, depth: Int? = null): JsonNode {
        val path = "/api/v1/holder/credentials/${encode(credentialId)}/descendants" +
            if (depth != null) "?depth=$depth" else ""
        return get(path)
    }

    // ── Generic verbs ───────────────────────────────────────────────────────

    private fun get(path: String): JsonNode {
        val request = baseRequest(path)
            .header("Accept", "application/json")
            .GET()
            .build()
        return execute(request)
    }

    private fun post(path: String, body: Any, confirmSlug: String? = null): JsonNode {
        val request = baseRequest(path)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .withConfirmation(confirmSlug)
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

    private fun patch(path: String, body: Any): JsonNode {
        val request = baseRequest(path)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .method("PATCH", HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
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

    /**
     * DELETE that expects `204 No Content`. Throws [ProductApiException] on any
     * non-2xx; ignores the (empty) body on success. Used by the application /
     * federation delete paths where the server returns no JSON.
     */
    private fun deleteNoContent(path: String, confirmSlug: String? = null) {
        val request = baseRequest(path)
            .header("Accept", "application/json")
            .withConfirmation(confirmSlug)
            .DELETE()
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), response.body() ?: "", mapper)
        }
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

    /**
     * SSO-2413 — attach the production destructive-action confirmation header
     * (`X-Thoryn-Confirm: <workspace-slug>`) when the caller supplied a
     * non-blank `--confirm` value. product-api's `ProductionConfirmationInterceptor`
     * requires it only for destructive actions targeting a **production** plane
     * workspace; a blank value is treated as "not supplied" so sandbox / default-
     * tenant flows send no header and stay ungated.
     */
    private fun HttpRequest.Builder.withConfirmation(confirmSlug: String?): HttpRequest.Builder =
        if (confirmSlug.isNullOrBlank()) this else header(CONFIRM_HEADER, confirmSlug)

    companion object {
        /**
         * SSO-2413 — the typed-name confirmation header product-api's
         * `ProductionConfirmationInterceptor` reads on gated destructive endpoints.
         * A header (not a body field) so it works uniformly for the body-less DELETE
         * verbs. Value is the caller's own workspace slug.
         */
        const val CONFIRM_HEADER: String = "X-Thoryn-Confirm"

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
 * Two error wire shapes are surfaced, both reduced to (`errorCode`,
 * `errorDescription`):
 *  - RFC 6749 §5.2 OAuth bodies (`error` + `error_description`) from the hub's
 *    token / device endpoints.
 *  - RFC 9457 problem-details (`errorCode` + `detail`, plus `title`) that
 *    product-api's `ProblemDetailsWriter` emits across the customer plane
 *    (SSO-1122) — `/api/v1/applications`, `/federation-members`, `/audit/[*]`.
 *
 * The CLI surfaces both — the code so we can route to a "run `oathy login
 * --scope …`" hint, the description so the user sees the human-readable reason.
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

    /**
     * SSO-2413 — the destructive action targets a **production** workspace and no
     * (valid) `X-Thoryn-Confirm` header was sent (product-api's
     * `ProductionConfirmationInterceptor` → `428 production_confirmation_required`).
     * Keyed off the RFC 9457 `errorCode`; the `428` status is a fallback for when
     * the body could not be parsed.
     */
    val isProductionConfirmationRequired: Boolean
        get() = errorCode == ERROR_CODE_CONFIRMATION_REQUIRED || (errorCode == null && httpStatus == 428)

    /**
     * SSO-2413 — an `X-Thoryn-Confirm` header was sent but did not equal the
     * caller's workspace slug (`422 production_confirmation_mismatch`). Keyed off
     * the RFC 9457 `errorCode`; the `422` status is a fallback for an unparsed body.
     */
    val isProductionConfirmationMismatch: Boolean
        get() = errorCode == ERROR_CODE_CONFIRMATION_MISMATCH || (errorCode == null && httpStatus == 422)

    companion object {
        /** RFC 9457 `errorCode` emitted with 428 when a production destructive action lacks the confirm header. */
        const val ERROR_CODE_CONFIRMATION_REQUIRED: String = "production_confirmation_required"

        /** RFC 9457 `errorCode` emitted with 422 when the confirm header does not match the workspace slug. */
        const val ERROR_CODE_CONFIRMATION_MISMATCH: String = "production_confirmation_mismatch"

        fun fromResponse(status: Int, body: String, mapper: ObjectMapper): ProductApiException {
            val (code, description) = parseOAuthError(body, mapper)
            return ProductApiException(status, code, description, body)
        }

        private fun parseOAuthError(body: String, mapper: ObjectMapper): Pair<String?, String?> {
            if (body.isBlank()) return null to null
            return try {
                val parsed: Map<String, Any?> = mapper.readValue(body)
                // Machine code, in precedence order:
                //  - `error`     — RFC 6749 §5.2 (hub token / device endpoints).
                //  - `errorCode` — RFC 9457 extension product-api's ProblemDetailsWriter
                //                  emits across the whole customer plane (SSO-1122). This
                //                  is what `/api/v1/applications`, `/federation-members`,
                //                  `/audit/[*]` return; without it a 404/409 problem body
                //                  loses its stable code and renders as bare "HTTP 404".
                val code = (parsed["error"] as? String)
                    ?: (parsed["errorCode"] as? String)
                val description = (parsed["error_description"] as? String)
                    ?: (parsed["detail"] as? String) // RFC 9457 human-readable detail
                    ?: (parsed["message"] as? String)
                    ?: (parsed["title"] as? String) // RFC 9457 title fallback
                code to description
            } catch (_: Exception) {
                null to null
            }
        }
    }
}
