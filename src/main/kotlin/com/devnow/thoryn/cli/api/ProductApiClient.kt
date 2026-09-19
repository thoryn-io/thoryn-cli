package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.DpopSession
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
 *
 * **Reactive refresh-on-401 (SSO-2861).** [CommandSupport.ensureFresh] refreshes
 * *proactively* before a call when the access token is near expiry (SSO-2834);
 * this is its reactive complement. When a request returns `401` and a
 * [reauthenticate] callback is present, the client invokes it once to obtain a
 * fresh [Tokens] (a forced refresh-token redemption), swaps the bearer, and
 * retries the request **exactly once**. If no callback is wired, the refresh
 * yields no new token, or the retry still `401`s, the `401` surfaces as a
 * [ProductApiException] unchanged — so callers without a reauthenticator behave
 * exactly as before.
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
    tokens: Tokens,
    private val http: HttpClient = defaultClient(),
    private val mapper: ObjectMapper = defaultMapper(),
    /**
     * SSO-2861 — invoked once when a request returns `401`, to obtain a fresh
     * [Tokens] for a single retry. Returns null (or the same access token) to
     * decline the retry and let the `401` surface. Null means "no reactive
     * refresh" — the pre-SSO-2861 behaviour.
     */
    private val reauthenticate: (() -> Tokens?)? = null,
    /**
     * SSO-2870 — the selected environment slug (a sandbox, or `production`). When non-blank it rides on
     * EVERY request as the `X-Thoryn-Environment` header, so the whole customer-plane surface (clients,
     * users, federation, …) targets the caller-selected environment rather than the token's default
     * (production) plane. `null`/blank ⇒ no header, i.e. the pre-SSO-2870 behaviour. product-api honors
     * the header only for a tenant-admin token and only for an environment the caller's own `tnt` owns.
     */
    private val environmentSlug: String? = null,
    /**
     * SSO-3199 — the installation's DPoP session (RFC 9449). When present every request carries a
     * `DPoP:` proof header (with the `ath` access-token binding once the token is presented under the
     * `DPoP` scheme), and a `use_dpop_nonce` challenge is retried once. Null ⇒ no proof, i.e. the
     * pre-SSO-3199 wire shape — which is what every test fixture and every already-minted-token caller
     * keeps. **The presentation scheme is server-driven**: `DPoP` only when the token response said
     * `token_type: DPoP`, `Bearer` otherwise, so nothing changes until the hub flips the `cli` client.
     */
    private val dpop: DpopSession? = null,
) {

    /** Current bearer material; swapped in place by the reactive refresh-on-401 retry. */
    private var tokens: Tokens = tokens

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
        post("/api/v1/applications/${encode(clientId)}/secret/rotate", emptyBody(), confirmSlug)

    // ── Tenant users (SSO-2907; product-api SSO-1884 `/api/v1/users`) ──────────
    //
    // The tenant user-management facade, gated by `tenant:users.write`. In the
    // default set-password mode a `password` in the body provisions a sign-in-able
    // credential and `emailVerified:true` marks the account verified without an
    // email round-trip — the pieces a full sign-up→login example recipe needs.
    // Returns the created `UserResponse` ({id, email, emailVerified, status, …}).

    fun createUser(body: Map<String, Any?>): JsonNode =
        post("/api/v1/users", body)

    // ── User lifecycle (SSO-3081; product-api `/api/v1/users`) ─────────────────
    //
    // Suspend / reactivate a directory user in the caller's tenant. `suspend` is a
    // production-destructive action gated by the SSO-2413 confirmation contract
    // (X-Thoryn-Confirm = workspace slug); `reactivate` is not gated. Scopes:
    // read → tenant:users.read, write → tenant:users.write.

    /**
     * `GET /api/v1/users` — the caller tenant's directory users, newest first, as the
     * `{ items: [...], pageInfo }` list envelope. [email] / [status] narrow the page
     * (server-side filters); [limit] bounds it (clamped 1..server-max). Used by the
     * suspend / reactivate commands to resolve an `--email` to its user id.
     */
    fun listUsers(email: String? = null, status: String? = null, limit: Int? = null): JsonNode {
        val query = buildList {
            email?.takeIf { it.isNotBlank() }?.let { add("email=${encode(it)}") }
            status?.takeIf { it.isNotBlank() }?.let { add("status=${encode(it)}") }
            limit?.let { add("limit=$it") }
        }.joinToString("&").let { if (it.isEmpty()) "" else "?$it" }
        return get("/api/v1/users$query")
    }

    fun getUser(userId: String): JsonNode =
        get("/api/v1/users/${encode(userId)}")

    /**
     * `PATCH /api/v1/users/{userId}` (SSO-3089; product-api `usersUpdate`, `tenant:users.write`) —
     * update a directory user's mutable profile fields (`emailVerified`, `firstName`, `lastName`,
     * `locale`, …). Used by `thoryn provision apply` to converge a declared `user` resource.
     */
    fun updateUser(userId: String, body: Map<String, Any?>): JsonNode =
        patch("/api/v1/users/${encode(userId)}", body)

    /**
     * `POST /api/v1/users/{id}/suspend` — disable a user so their next sign-in is refused
     * (identity marks the account non-ACTIVE → the hosted login shows the suspended notice).
     * `204 No Content`. [confirmSlug] rides as `X-Thoryn-Confirm`, clearing the SSO-2413
     * production-confirmation gate (`428` absent / `422` mismatch on the production plane; a
     * sandbox plane is ungated).
     */
    fun suspendUser(userId: String, confirmSlug: String? = null): Unit =
        postNoContent("/api/v1/users/${encode(userId)}/suspend", confirmSlug)

    /** `POST /api/v1/users/{id}/reactivate` — clear a suspension (`204`; not confirmation-gated). */
    fun reactivateUser(userId: String): Unit =
        postNoContent("/api/v1/users/${encode(userId)}/reactivate")

    /**
     * `DELETE /api/v1/users/{userId}` (SSO-3088; product-api `usersDelete`, `tenant:users.write`) —
     * remove a directory user. product-api already exposed this; the CLI gained it for
     * `thoryn provision destroy` (a `user` resource is a scenario FIXTURE, pruned with its file).
     * [confirmSlug] rides as the SSO-2413 confirmation header for a production-plane delete.
     */
    fun deleteUser(userId: String, confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/users/${encode(userId)}", confirmSlug)

    // ── Environments (SSO-2870; product-api SSO-2410 `/api/v1/environments`) ────
    //
    // A workspace (tenant) holds N durable sandbox environments + one platform-
    // managed production environment. These reads/writes are NOT environment-scoped
    // themselves — they manage the environment registry — so they carry no
    // X-Thoryn-Environment header dependency (a client built with or without a
    // selected environment lists the same set). Scopes: read → tenant:environments.read,
    // write → tenant:environments.write (already granted to thoryn-cli, hub V119).

    fun listEnvironments(): JsonNode =
        get("/api/v1/environments")

    /**
     * `GET /api/v1/environments/{id}` (SSO-2964) — a single environment record by its UUID `id`.
     * A cross-tenant / unknown id is `404 not_found` (privacy-symmetric); a token without
     * `tenant:environments.read` is `403`. Both surface as [ProductApiException].
     */
    fun getEnvironment(id: String): JsonNode =
        get("/api/v1/environments/${encode(id)}")

    fun createEnvironment(body: Map<String, Any?>): JsonNode =
        post("/api/v1/environments", body)

    fun renameEnvironment(id: String, body: Map<String, Any?>): JsonNode =
        patch("/api/v1/environments/${encode(id)}", body)

    /** POST /api/v1/environments/{id}/suspend — [confirmSlug] clears the production-confirmation gate. */
    fun suspendEnvironment(id: String, confirmSlug: String? = null): JsonNode =
        post("/api/v1/environments/${encode(id)}/suspend", emptyBody(), confirmSlug)

    fun reactivateEnvironment(id: String): JsonNode =
        post("/api/v1/environments/${encode(id)}/reactivate", emptyBody())

    /**
     * `DELETE /api/v1/environments/{id}` (SSO-2960) — IRREVERSIBLY hard-deletes a **sandbox**
     * environment and purges every environment-scoped row within it. Success is `200`/`204` (no body).
     *
     * Confirmation-guarded via the SSO-2413 wire contract: [confirmSlug] rides as the [CONFIRM_HEADER]
     * (`X-Thoryn-Confirm`) and MUST equal the target environment's OWN slug — product-api answers
     * `428 production_confirmation_required` when it is absent and `422 production_confirmation_mismatch`
     * when it does not match. The endpoint refuses the platform-managed production plane with
     * `409 cannot_delete_production_environment`; a cross-tenant / unknown id is `404 not_found`
     * (privacy-symmetric); a token without `tenant:environments.write` is `403`.
     *
     * Every non-2xx surfaces as [ProductApiException] carrying the stable RFC 9457 `errorCode` and
     * `detail`, so callers see a clear, code-mapped message (`isProductionConfirmationRequired` /
     * `isProductionConfirmationMismatch` classify the 428/422 confirm-gate outcomes).
     */
    fun deleteEnvironment(id: String, confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/environments/${encode(id)}", confirmSlug)

    // ── Sandbox test inbox (SSO-3026; product-api /api/v1/environments/{id}/test-emails) ──────────
    //
    // A sandbox environment SUPPRESSES every real transactional email (TestModeEmailGate) and CAPTURES
    // it here instead, so a developer can complete a sandbox email flow (verification, …) without a
    // real mailbox. Read-only, environment-scoped in the PATH; scope tenant:environments.read (already
    // granted to thoryn-cli, hub V119). A production environment captured nothing, so the list is empty.

    /**
     * `GET /api/v1/environments/{envId}/test-emails` — the sandbox's captured emails, newest first.
     * [limit] (1..200, clamped server-side) bounds the page. Returns the list envelope
     * `{ "emails": [ { id, channel, to, subject, actionLink, bodyHtml, createdAt } ] }`.
     */
    fun listTestEmails(envId: String, limit: Int? = null): JsonNode {
        val query = limit?.let { "?limit=$it" } ?: ""
        return get("/api/v1/environments/${encode(envId)}/test-emails$query")
    }

    /**
     * `GET /api/v1/environments/{envId}/test-emails/{id}` — one captured email (incl. its `actionLink`,
     * e.g. the verify URL). A cross-scope / unknown id is `404 not_found` (privacy-symmetric).
     */
    fun getTestEmail(envId: String, emailId: String): JsonNode =
        get("/api/v1/environments/${encode(envId)}/test-emails/${encode(emailId)}")

    // ── Email provider (SSO-2917; product-api /api/v1/email-provider) ──────────
    //
    // The tenant's bring-your-own SMTP transport config (the activation, per tenant,
    // of the SSO-76 / SSO-2049 BYO-SMTP send path). read → tenant:email.read,
    // write → tenant:email.write (granted to thoryn-cli by hub V149). The SMTP
    // password is WRITE-ONLY: it rides the PUT body once (identity encrypts it at
    // rest) and is NEVER present on the response — the read view carries only
    // `hasPassword`. PUT is a normalising merge-upsert (a null field keeps the
    // stored value). DELETE resets the tenant to the platform sender (204).

    fun getEmailProvider(): JsonNode =
        get("/api/v1/email-provider")

    fun putEmailProvider(body: Map<String, Any?>): JsonNode =
        put("/api/v1/email-provider", body)

    /**
     * `POST /api/v1/email-provider/verify` (SSO-2923) — dial the tenant's configured BYO-SMTP
     * transport and return `{success, reason?, outcome}`. [to] (optional) sends a real test
     * message to that address through the tenant's own SMTP server; omitted ⇒ a connect-only
     * probe. A reachable-but-failed check is a `200` with `success=false` (the caller inspects
     * the body); only transport/validation errors surface as [ProductApiException].
     */
    fun verifyEmailProvider(to: String? = null): JsonNode =
        post("/api/v1/email-provider/verify", buildMap { to?.let { put("to", it) } })

    /**
     * `DELETE /api/v1/email-provider` — reset to the platform sender (204 No Content);
     * surfaces non-2xx as [ProductApiException]. [confirmSlug] (SSO-2413) — a
     * production-plane reset is gated by product-api's `ProductionConfirmationInterceptor`
     * (`@ProductionConfirmationRequired`); pass the workspace slug to clear it.
     */
    fun deleteEmailProvider(confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/email-provider", confirmSlug)

    // ── Hosted-login branding (SSO-3037; product-api /api/v1/login-experience/branding) ─
    //
    // The per-(tenant, environment) branding of the hosted sign-in / register screens:
    // logoUrl + primaryColor + backgroundColor + borderRadiusPx + theme, rendered by
    // identity-service as CSS custom properties (`--brand-*`) in the login templates. read →
    // tenant:idp.read; write → tenant:idp.write (both granted to thoryn-cli by hub V83). PUT
    // is a merge-upsert of the supplied fields; the response carries `stored` (raw, null = unset)
    // + `effective` (post-fallback values the page uses) + `updatedAt`. Environment-scoped via
    // the `X-Thoryn-Environment` header this client already sends for the selected env.

    fun getLoginBranding(): JsonNode =
        get("/api/v1/login-experience/branding")

    fun putLoginBranding(body: Map<String, Any?>): JsonNode =
        put("/api/v1/login-experience/branding", body)

    // ── Login flows (SSO-3065; product-api /api/v1/login-flows, per environment) ──
    // Author + activate the multi-step login journey (which authenticator stages a sign-in walks) for
    // the selected environment. Enables e.g. a `password + REQUIRED passkey` second-factor flow — the
    // one thing a passkey MFA example needs that no other CLI surface exposed. Scopes: read →
    // tenant:idp.read, write (draft/activate/apply-template) → tenant:idp.write.
    fun getActiveLoginFlow(): JsonNode =
        get("/api/v1/login-flows/active")

    fun putLoginFlowDraft(body: Map<String, Any?>): JsonNode =
        put("/api/v1/login-flows/draft", body)

    fun activateLoginFlow(version: Int): JsonNode =
        post("/api/v1/login-flows/activate", mapOf("version" to version))

    fun applyLoginFlowTemplate(templateId: String): JsonNode =
        post("/api/v1/login-flows/templates/${encode(templateId)}/apply", emptyMap<String, Any?>())

    // ── Login methods (SSO-3075; product-api /api/v1/login-methods, per environment) ──
    // The allow-list of sign-in methods the hosted login offers for the selected environment. Enables
    // e.g. adding `magic_code` (opt-in, not default-on) — the one thing a magic-code example needs that
    // no other CLI surface exposed. GET → tenant:idp.read; PUT/DELETE → tenant:idp.write.
    fun getLoginMethods(): JsonNode =
        get("/api/v1/login-methods")

    fun putLoginMethods(methods: List<String>): JsonNode =
        put("/api/v1/login-methods", mapOf("methods" to methods))

    fun resetLoginMethods(): JsonNode =
        delete("/api/v1/login-methods")

    // ── Access grants (SSO-3113; product-api /api/v1/access — the SSO-3112 contract) ──────────
    //
    // Least-privilege relationships between a SUBJECT (`member:<sub>` / `client:<clientId>`) and an
    // OBJECT (`workspace:<tenantId>`, `environment:<id>`, `application:<clientId>`, `user:<id>`,
    // `federation_member:<id>`, `email_provider:<envSlug>`, `login_theme:<envSlug>`,
    // `login_flow:<envSlug>`, `login_methods:<envSlug>`) via a RELATION (`manager` / `viewer`).
    // Workspace-level (objects carry their environment id), so no X-Thoryn-Environment dependency.
    // Scopes: read → tenant:access.read, write → tenant:access.write.

    /**
     * `GET /api/v1/access/grants?object=<type>:<id>` / `?subject=<type>:<id>` — the grants on an object
     * or held by a subject, as the product-api ListEnvelope `{ "data": [ {subject, relation, object,
     * createdAt} ], "pagination": {…} }` (the array is under `data`, NOT `items`).
     */
    fun listGrants(objectRef: String? = null, subjectRef: String? = null): JsonNode {
        val query = buildList {
            objectRef?.takeIf { it.isNotBlank() }?.let { add("object=${encode(it)}") }
            subjectRef?.takeIf { it.isNotBlank() }?.let { add("subject=${encode(it)}") }
        }.joinToString("&").let { if (it.isEmpty()) "" else "?$it" }
        return get("/api/v1/access/grants$query")
    }

    /** `POST /api/v1/access/grants` `{subject, relation, object}` — 201 created, 200 when it already exists (idempotent). */
    fun createGrant(subjectRef: String, relation: String, objectRef: String): JsonNode =
        post("/api/v1/access/grants", grantBody(subjectRef, relation, objectRef))

    /** `DELETE /api/v1/access/grants` with the JSON body `{subject, relation, object}` — 204 No Content. */
    fun deleteGrant(subjectRef: String, relation: String, objectRef: String): Unit =
        deleteWithBodyNoContent("/api/v1/access/grants", grantBody(subjectRef, relation, objectRef))

    /** `GET /api/v1/access/mine?type=<objectType>&relation=<relation>` — `{ "data": [ "<type>:<id>", … ] }` for the caller. */
    fun listMyAccess(type: String? = null, relation: String? = null): JsonNode {
        val query = buildList {
            type?.takeIf { it.isNotBlank() }?.let { add("type=${encode(it)}") }
            relation?.takeIf { it.isNotBlank() }?.let { add("relation=${encode(it)}") }
        }.joinToString("&").let { if (it.isEmpty()) "" else "?$it" }
        return get("/api/v1/access/mine$query")
    }

    private fun grantBody(subjectRef: String, relation: String, objectRef: String): Map<String, Any?> =
        linkedMapOf("subject" to subjectRef, "relation" to relation, "object" to objectRef)

    // ── Attestations (SSO-2878; product-api verify-then-sign) ──────────────────
    //
    // POST a receipt to have the platform re-verify its resources against live tenant
    // state and, only if all verify, return a per-tenant ES256 detached-JWS attestation
    // ({kid, signature, canonicalPayload, attestedAt}). GET the JWKS for offline verify.

    fun attestReceipt(receipt: Any): JsonNode =
        post("/api/v1/attestations", receipt)

    fun attestationJwks(): JsonNode =
        get("/api/v1/attestations/jwks")

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

    /** `GET /api/v1/federation-members/{memberId}` (SSO-3089) — one member; 404 cross-tenant / unknown. */
    fun getFederationMember(memberId: String): JsonNode =
        get("/api/v1/federation-members/${encode(memberId)}")

    /**
     * `PATCH /api/v1/federation-members/{memberId}` (SSO-3089; product-api `federationMembersUpdate`,
     * `tenant:federation.write`) — update a member's `displayName` / `discoveryUrl` / `clientId` /
     * `clientSecret` / `claimMapping` / `providerConfig`. Used by `thoryn provision apply` to converge.
     */
    fun updateFederationMember(memberId: String, body: Map<String, Any?>): JsonNode =
        patch("/api/v1/federation-members/${encode(memberId)}", body)

    /**
     * DELETE returns 204 No Content on success; surfaces non-2xx as [ProductApiException].
     *
     * [confirmSlug] (SSO-2413) — see [deleteApplication]; a production-plane
     * federation-member delete is gated the same way.
     */
    fun deleteFederationMember(memberId: String, confirmSlug: String? = null): Unit =
        deleteNoContent("/api/v1/federation-members/${encode(memberId)}", confirmSlug)

    // ── Devices (SSO-3228; hub /account/devices — NOT behind the gateway) ─────
    //
    // A registered DPoP key is a named DEVICE the owner can see and revoke. Like the workspace
    // surface these live on the HUB behind `SCOPE_openid`, so they are called against a client whose
    // base URL is the hub issuer. Registration additionally needs the request to be DPoP-presented —
    // which it is whenever the session token is bound, because the scheme follows the token.

    /**
     * `POST /account/devices` — register (or re-describe) the key THIS session's token is bound to.
     * Idempotent per key: a re-login updates the name rather than creating a second device.
     */
    fun registerDevice(body: Map<String, Any?>): JsonNode =
        post("/account/devices", body)

    /** `GET /account/devices` — the caller's own devices, each with its key's recent activity. */
    fun listDevices(): JsonNode =
        get("/account/devices")

    /** `POST /account/devices/{id}/revoke` — end one device and the sessions its key holds. */
    fun revokeDevice(deviceId: String, reason: String?): JsonNode =
        post("/account/devices/${encode(deviceId)}/revoke", mapOf("reason" to reason))

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
        post("/account/workspace/${encode(tenantId)}/archive", emptyBody(), confirmSlug)

    /** SSO-2831 — `POST /account/workspace/{tenantId}/reactivate` — clears the archive flag. */
    fun reactivateWorkspace(tenantId: String): JsonNode =
        post("/account/workspace/${encode(tenantId)}/reactivate", emptyBody())

    /**
     * SSO-2859 — `POST /account/workspace/{tenantId}/hard-delete` — IRREVERSIBLY deletes a
     * workspace (SSO-2831 distributed teardown): suspends the tenant immediately and enqueues the
     * purge of every tenant-scoped row across hub / product-api / identity + the per-tenant Vault
     * keys. Returns **202 Accepted** (the async poller completes the purge). Name-confirmation
     * guarded: [confirmSlug] rides as [CONFIRM_HEADER] (`X-Thoryn-Confirm`) and must equal the
     * workspace slug, or the hub replies 428 (required) / 422 (mismatch).
     */
    fun hardDeleteWorkspace(tenantId: String, confirmSlug: String? = null): JsonNode =
        post("/account/workspace/${encode(tenantId)}/hard-delete", emptyBody(), confirmSlug)

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
        val response = sendAuthed(HttpResponse.BodyHandlers.ofByteArray()) { at ->
            baseRequest(path).authed(at)
                // Accept both PDF and ZIP — server picks the format based on size.
                .header("Accept", "application/pdf, application/zip")
                .GET()
                .build()
        }
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
        return executeJson { at ->
            baseRequest("/api/v1/issuer-bridges/${encode(bridgeId)}/keys/current").authed(at)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build()
        }
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

    /**
     * SSO-2958 — a native-image-safe empty request body.
     *
     * A raw kotlin `emptyMap()` / `mapOf()` is the `kotlin.collections.EmptyMap`
     * singleton. When jackson-module-kotlin serialises it, its
     * `KotlinNamesAnnotationIntrospector.findPreferredCreator` reflects on
     * `EmptyMap`'s constructor via kotlin-reflect — and `EmptyMap` carries no
     * native-image reflection metadata, so the native binary throws
     * `KotlinReflectionInternalError: Unresolved class: class kotlin.collections.EmptyMap`
     * (the fat jar works because it has full runtime reflection). A Jackson
     * [tools.jackson.databind.node.ObjectNode] serialises to `{}` with zero
     * kotlin-reflection, so it is safe on the native hot path. Every body-less
     * POST below routes through this rather than passing `emptyMap()`.
     */
    private fun emptyBody(): JsonNode = mapper.createObjectNode()

    private fun get(path: String): JsonNode = executeJson { at ->
        baseRequest(path).authed(at)
            .header("Accept", "application/json")
            .GET()
            .build()
    }

    private fun post(path: String, body: Any, confirmSlug: String? = null): JsonNode = executeJson { at ->
        baseRequest(path).authed(at)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .withConfirmation(confirmSlug)
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
    }

    private fun put(path: String, body: Any): JsonNode = executeJson { at ->
        baseRequest(path).authed(at)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
    }

    private fun patch(path: String, body: Any): JsonNode = executeJson { at ->
        baseRequest(path).authed(at)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .method("PATCH", HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
            .build()
    }

    private fun delete(path: String): JsonNode = executeJson { at ->
        baseRequest(path).authed(at)
            .header("Accept", "application/json")
            .DELETE()
            .build()
    }

    /**
     * DELETE that expects `204 No Content`. Throws [ProductApiException] on any
     * non-2xx; ignores the (empty) body on success. Used by the application /
     * federation delete paths where the server returns no JSON.
     */
    private fun deleteNoContent(path: String, confirmSlug: String? = null) {
        val response = sendAuthed(HttpResponse.BodyHandlers.ofString()) { at ->
            baseRequest(path).authed(at)
                .header("Accept", "application/json")
                .withConfirmation(confirmSlug)
                .DELETE()
                .build()
        }
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), response.body() ?: "", mapper)
        }
    }

    /**
     * DELETE carrying a JSON body that expects `204 No Content` (SSO-3113 — `DELETE /api/v1/access/grants`
     * identifies the grant by `{subject, relation, object}` in the body, not the path). Throws
     * [ProductApiException] on any non-2xx; ignores the (empty) body on success.
     */
    private fun deleteWithBodyNoContent(path: String, body: Any) {
        val response = sendAuthed(HttpResponse.BodyHandlers.ofString()) { at ->
            baseRequest(path).authed(at)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .method("DELETE", HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build()
        }
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), response.body() ?: "", mapper)
        }
    }

    /**
     * POST that expects `204 No Content` (a body-less side-effect — user suspend / reactivate).
     * Throws [ProductApiException] on any non-2xx; ignores the (empty) body on success. [confirmSlug]
     * rides as the SSO-2413 `X-Thoryn-Confirm` header when non-blank (mirrors [deleteNoContent]).
     */
    private fun postNoContent(path: String, confirmSlug: String? = null) {
        val response = sendAuthed(HttpResponse.BodyHandlers.ofString()) { at ->
            baseRequest(path).authed(at)
                .header("Accept", "application/json")
                .withConfirmation(confirmSlug)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build()
        }
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), response.body() ?: "", mapper)
        }
    }

    private fun executeJson(build: (accessToken: String) -> HttpRequest): JsonNode {
        val response = sendAuthed(HttpResponse.BodyHandlers.ofString(), build)
        val body = response.body() ?: ""
        if (response.statusCode() !in 200..299) {
            throw ProductApiException.fromResponse(response.statusCode(), body, mapper)
        }
        if (body.isBlank()) return mapper.nullNode()
        return mapper.readTree(body)
    }

    /**
     * SSO-2861 — send [build]'s request with the current bearer, and on a `401`
     * perform a single reactive refresh-and-retry when [reauthenticate] is wired.
     * The request is rebuilt with the fresh access token (an [HttpRequest] is
     * immutable) so exactly one extra attempt is made; a null / unchanged refresh
     * result, or a still-`401` retry, returns the response for the caller to raise.
     */
    private fun <T> sendAuthed(
        handler: HttpResponse.BodyHandler<T>,
        build: (accessToken: String) -> HttpRequest,
    ): HttpResponse<T> {
        val first = sendProofed(build(tokens.accessToken), handler)
        if (first.statusCode() != 401) return first
        val reauth = reauthenticate ?: return first
        val refreshed = runCatching { reauth() }.getOrNull() ?: return first
        if (refreshed.accessToken == tokens.accessToken) return first
        tokens = refreshed
        return sendProofed(build(tokens.accessToken), handler)
    }

    /**
     * SSO-3199 — send through the DPoP session when one is wired (proof header + a single
     * `use_dpop_nonce` retry, RFC 9449 §8); otherwise send the request untouched. A nonce challenge is
     * therefore resolved BEFORE [sendAuthed]'s `401` refresh path sees the response, so the two
     * retry mechanisms never compound.
     */
    private fun <T> sendProofed(request: HttpRequest, handler: HttpResponse.BodyHandler<T>): HttpResponse<T> =
        dpop?.send(request) { decorated -> http.send(decorated, handler) } ?: http.send(request, handler)

    private fun baseRequest(path: String): HttpRequest.Builder {
        val uri = URI.create("${gateway.trimEnd('/')}$path")
        val builder = HttpRequest.newBuilder()
            .uri(uri)
            .timeout(Duration.ofSeconds(30))
        // SSO-2870 — select the caller's environment for the whole customer-plane surface in one place.
        environmentSlug?.takeIf { it.isNotBlank() }?.let { builder.header(ENVIRONMENT_HEADER, it) }
        return builder
    }

    /**
     * Attach the credential for [accessToken] — applied per-send so a refreshed token is used on retry.
     *
     * SSO-3199 — the scheme follows the token the hub issued: `DPoP` when the token response carried
     * `token_type: DPoP` (RFC 9449 §7.1), `Bearer` otherwise. The CLI never *chooses* `DPoP` on its own,
     * which is what keeps it working against a hub (and resource servers) that do not yet bind tokens.
     */
    private fun HttpRequest.Builder.authed(accessToken: String): HttpRequest.Builder =
        header("Authorization", "${DpopSession.schemeFor(tokens)} $accessToken")

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

        /**
         * SSO-2870 — the admin environment-selector header product-api's `EnvironmentClaimFilter`
         * resolves (within the caller's own tenant) to the request's `environment.id`. Value is an
         * environment slug (a sandbox, or `production`). Mirrors product-api's
         * `EnvironmentContext.ENVIRONMENT_HEADER`.
         */
        const val ENVIRONMENT_HEADER: String = "X-Thoryn-Environment"

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
