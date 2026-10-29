package com.devnow.thoryn.cli.cmd.provision

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule

/**
 * SSO-3089 — an in-memory stand-in for the product-api surfaces `thoryn provision` converges against,
 * mounted as the MockWebServer [Dispatcher]. It keeps live state per environment (the
 * `X-Thoryn-Environment` header; absent ⇒ production), answers the read-by-key lookups, applies
 * writes, and RECORDS every write so a test can assert "a second apply issued no writes" or "exactly
 * one PATCH carrying only the changed field" without scripting response order.
 */
internal class FakeProductApi : Dispatcher() {

    data class Write(val method: String, val path: String, val env: String?, val confirm: String?, val body: Map<String, Any?>)

    /** SSO-3673 — one `POST /api/v1/access/check` the engine asked: the object and the relation (a READ, never in [writes]). */
    data class Check(val objectRef: String, val relation: String)

    val writes = mutableListOf<Write>()
    /** SSO-3673 — every forward check asked, in order; `checksOn(ref)` narrows to one object. */
    val checks = mutableListOf<Check>()
    /** SSO-3673 — every `GET /api/v1/access/mine` listing asked (`type relation`), so a test can show `plan` no longer lists. */
    val mineReads = mutableListOf<String>()
    val environments = mutableListOf<MutableMap<String, Any?>>()
    val applications = mutableListOf<MutableMap<String, Any?>>()
    val users = mutableListOf<MutableMap<String, Any?>>()
    val federationMembers = mutableListOf<MutableMap<String, Any?>>()
    val emailProviders = mutableMapOf<String?, MutableMap<String, Any?>>()
    val branding = mutableMapOf<String?, MutableMap<String, Any?>>()
    /**
     * SSO-4042 — the PRODUCTION plane's email template overrides by `<type>:<locale>` (`*` = the base cell). SSO-4054 (oauthy
     * SSO-4043) — templates are per environment: no `X-Thoryn-Environment` header (or `production`) addresses this map, a sandbox
     * slug addresses its own in [sandboxEmailTemplates] ([emailTemplatesOf]).
     */
    val emailTemplates = mutableMapOf<String, MutableMap<String, Any?>>()
    /** SSO-4054 — each sandbox's OWN email template overrides (sandbox slug → `<type>:<locale>` → record); empty ⇒ it inherits production's on the send path. */
    val sandboxEmailTemplates = mutableMapOf<String, MutableMap<String, MutableMap<String, Any?>>>()

    /** SSO-4054 — the store an `X-Thoryn-Environment` value addresses, as identity's `envOf`: absent, blank or `production` ⇒ production. */
    fun emailTemplatesOf(env: String?): MutableMap<String, MutableMap<String, Any?>> {
        val slug = env?.trim()?.takeIf { it.isNotEmpty() && it != "production" } ?: return emailTemplates
        return sandboxEmailTemplates.getOrPut(slug) { mutableMapOf() }
    }
    /** SSO-4054 — off (the #4289 contract): a sandbox GET is exact. On: a sandbox GET without its own row answers production's (labelled `environmentSlug: production`). */
    var emailTemplateGetResolves = false
    /**
     * SSO-4057 — tenant-level legal documents per environment (`null` ⇒ production, as [envKey] normalises the header): every
     * version of every type, oldest first, in identity's shape (`id`, `type` — the path segment —, `version`, `title`, `format`,
     * `body`, `active`, `acceptanceCount`). A test seeds acceptances on a version to see `409 document_accepted`.
     */
    val legalDocuments = mutableMapOf<String?, MutableList<MutableMap<String, Any?>>>()

    /** SSO-4057 — the versions of [type] in [env] (the header value; absent, blank or `production` ⇒ production). */
    fun legalDocumentsOf(env: String?, type: String): List<MutableMap<String, Any?>> = legalDocuments[envKey(env)].orEmpty().filter { it["type"] == type }

    /** SSO-4057 — seed one version (inactive unless [active]; an active one deactivates the other active version of its type). */
    fun seedLegalDocument(env: String?, type: String, version: String, body: String, title: String = "Terms", format: String = "markdown", active: Boolean = true, acceptances: Long = 0): String {
        val id = "ld-${++seq}"
        val docs = legalDocuments.getOrPut(envKey(env)) { mutableListOf() }
        if (active) docs.filter { it["type"] == type }.forEach { it["active"] = false }
        docs += mutableMapOf("id" to id, "type" to type, "version" to version, "title" to title, "format" to format, "body" to body, "active" to active, "acceptanceCount" to acceptances)
        return id
    }

    private fun envKey(env: String?): String? = env?.trim()?.takeIf { it.isNotEmpty() && it != "production" }

    /** SSO-4042 — identity's `maxBodyBytes` (64 KiB); a test lowers it to see the `413` surface through the engine. */
    var emailTemplateMaxBodyBytes = 64 * 1024
    val activeFlow = mutableMapOf<String?, Int>()
    /** SSO-3100 — the stored sign-in method allow-list per environment (absent ⇒ the default policy). */
    val loginMethods = mutableMapOf<String?, List<String>>()
    /** SSO-3113 — access grants (`/api/v1/access/grants`, the SSO-3112 contract): `{subject, relation, object, createdAt}`. */
    val grants = mutableListOf<MutableMap<String, Any?>>()
    /**
     * SSO-3659 — the caller's platform subject, the identity `/api/v1/access/mine` and `/api/v1/access/check`
     * (SSO-3673) answer FOR (product-api derives it from the token; the fake has no token, so a test states it).
     * Reach is COMPUTED from [grants] the way the platform model does — `manager = this ∪ owner ∪ parent.manager`,
     * `viewer = this ∪ manager ∪ parent.viewer`, `owner = this` (direct only, never inherited), an application's
     * parent being its environment (or the workspace on the production plane), an environment's and the custom
     * domain's the workspace — so a test seeds grants, not answers. The DEFAULT is a PERSON (a founder), so
     * creator-becomes-OWNER (a `client:` creator only, SSO-3667) does not fire unless a test makes the caller a client.
     */
    var caller = "member:founder"

    /**
     * SSO-3722 — model product-api's `EnvironmentClaimFilter` (SSO-3118, the 404-not-403 rule): with this on, every
     * plane-scoped read or write (applications, users, federation members, the singletons) is answered `404
     * unknown_environment` unless the caller holds at least `viewer` on that plane — the production plane included. A
     * brand-new repository identity with no relation on anything therefore gets 404 on its very first read, exactly as
     * thoryn-cicd run 38751887466 did. Off by default: the older tests model reach per object only.
     */
    var environmentClaimFilter = false
    /** SSO-3659 — a workspace admin manages everything. The DEFAULT, so a test about something else sees a founder's reach. */
    var callerIsAdmin = true
    /** The workspace id (`tnt`) — the object `workspace:<tenantId>` and the custom domain's id. */
    var tenantId = "t-1"
    /** SSO-3715 — route prefixes whose DELETE answers `503 unavailable` (a removal that fails at the platform; the engine keeps going child-first). */
    val failingDeletes = mutableSetOf<String>()
    /** SSO-3113 — simulate a token WITHOUT `tenant:access.write` / `tenant:access.read` (403 insufficient_scope). */
    var denyGrantWrites = false
    var denyGrantReads = false
    // ── SSO-3941 — RBAC (product-api /api/v1/roles, /api/v1/permissions, /api/v1/users/{sub}/roles) and claims in the token ──
    /** Roles: `id`, `name`, `description`, `_env` (null ⇒ production), `permissions` (permission ids). */
    val roles = mutableListOf<MutableMap<String, Any?>>()
    /** Workspace-wide permissions: `id`, `name`. */
    val permissions = mutableListOf<MutableMap<String, Any?>>()
    /** Assignments: `userId` (the sub), `roleId`. */
    val userRoles = mutableListOf<MutableMap<String, Any?>>()
    /** Claims in the token per clientId: the enabled sources (absent ⇒ never enabled). */
    val tokenClaims = mutableMapOf<String, List<String>>()
    /**
     * SSO-3945 (oauthy SSO-3943) — the stored role mapping per clientId (absent ⇒ none). Like product-api, a PUT REPLACES it:
     * a body without `roleMapping` (or with `null`) stores none. A DELETE keeps it, as product-api keeps the disabled row.
     */
    val roleMappings = mutableMapOf<String, Map<String, String>>()
    /** The page size of the roles / permissions lists (cursor = the offset), so a test can exercise paging. */
    var rbacPageSize = 500
    /** The claim sources product-api accepts today (a test widens it to model a server that gained one). */
    var supportedClaimSources = setOf("permissions", "org", "org_roles", "roles", "pim", "entitlements", "guest")

    fun seedRole(env: String?, name: String, permissionNames: List<String> = emptyList(), description: String? = null): String {
        val id = "role-${++seq}"
        roles += mutableMapOf("id" to id, "name" to name, "description" to description, "_env" to env, "permissions" to permissionNames.map { permissionId(it) }.toMutableList())
        return id
    }

    fun permissionId(name: String): String =
        permissions.firstOrNull { it["name"] == name }?.get("id")?.toString() ?: "perm-${++seq}".also { permissions += mutableMapOf("id" to it, "name" to name) }

    fun rolePermissionNames(roleId: String): List<String> =
        (roles.single { it["id"] == roleId }["permissions"] as List<*>).map { pid -> permissions.single { it["id"] == pid }["name"].toString() }

    private fun page(items: List<Map<String, Any?>>, path: String): MockResponse {
        val q = query(path)
        val offset = q["cursor"]?.toIntOrNull() ?: 0
        val size = q["limit"]?.toIntOrNull() ?: rbacPageSize
        val next = (offset + size).takeIf { it < items.size }?.toString()
        return json(200, mapOf("data" to items.drop(offset).take(size), "pagination" to mapOf("cursor" to next, "hasMore" to (next != null))))
    }

    private fun roleView(r: Map<String, Any?>) = mapOf("id" to r["id"], "name" to r["name"], "description" to r["description"], "createdAt" to "2026-10-24T00:00:00Z")

    /** product-api's `RolesController` + `PermissionsController` + `UserRolesController` in miniature. */
    private fun rbac(method: String, seg: List<String>, env: String?, confirm: String?, b: Map<String, Any?>, path: String): MockResponse {
        val inPlane = roles.filter { it["_env"] == env }
        return when {
            seg[0] == "permissions" && seg.size == 1 && method == "GET" -> page(permissions.map { it + ("createdAt" to "2026-10-24T00:00:00Z") }, path)
            seg[0] == "permissions" && seg.size == 1 && method == "POST" -> {
                val name = (b["name"] as? String)?.trim()?.takeIf { it.isNotEmpty() } ?: return problem(400, "invalid_name")
                if (Regex("^(tenant|admin|holder):.*", RegexOption.IGNORE_CASE).matches(name)) return problem(400, "permission_name_reserved")
                if (permissions.any { it["name"] == name }) return problem(409, "permission_exists")
                val id = permissionId(name); json(201, permissions.first { it["id"] == id })
            }
            seg[0] == "roles" && seg.size == 1 && method == "GET" -> page(inPlane.map { roleView(it) }, path)
            seg[0] == "roles" && seg.size == 1 && method == "POST" -> {
                val name = (b["name"] as? String)?.trim()?.takeIf { it.isNotEmpty() } ?: return problem(400, "invalid_name")
                if (inPlane.any { it["name"] == name }) return problem(409, "role_exists")
                val id = seedRole(env, name, description = b["description"] as? String)
                json(201, roleView(roles.first { it["id"] == id }))
            }
            seg[0] == "roles" -> {
                val r = inPlane.firstOrNull { it["id"] == seg[1] } ?: return problem(404, "not_found")
                when {
                    seg.size == 2 && method == "GET" -> json(200, roleView(r))
                    seg.size == 2 && method == "PATCH" -> { r["description"] = b["description"]; json(200, roleView(r)) }
                    seg.size == 2 && method == "DELETE" -> {
                        if (env == null && confirm.isNullOrBlank()) return problem(428, "production_confirmation_required")
                        roles.remove(r); userRoles.removeIf { it["roleId"] == r["id"] }; MockResponse().setResponseCode(204)
                    }
                    seg.size == 3 && seg[2] == "permissions" && method == "GET" ->
                        page((r["permissions"] as List<*>).map { pid -> permissions.single { it["id"] == pid } }, path)
                    seg.size == 3 && seg[2] == "permissions" && method == "PUT" -> {
                        val ids = (b["permissionIds"] as? List<*>).orEmpty().map { it.toString() }
                        if (ids.any { id -> permissions.none { it["id"] == id } }) return problem(404, "permission_not_found")
                        r["permissions"] = ids.distinct().toMutableList()
                        json(200, mapOf("data" to ids.distinct().map { id -> permissions.single { it["id"] == id } }))
                    }
                    else -> problem(405, "method")
                }
            }
            // /users/{sub}/roles[/{roleId}]
            seg.size == 3 && method == "GET" -> page(userRoles.filter { it["userId"] == seg[1] && inPlane.any { r -> r["id"] == it["roleId"] } }
                .map { it + mapOf("id" to "ur-${it["roleId"]}", "orgId" to null, "assignedBy" to caller, "assignedAt" to "2026-10-24T00:00:00Z") }, path)
            seg.size == 3 && method == "POST" -> {
                val roleId = b["roleId"]?.toString() ?: return problem(400, "invalid_request")
                if (inPlane.none { it["id"] == roleId }) return problem(404, "role_not_found")
                if (userRoles.any { it["userId"] == seg[1] && it["roleId"] == roleId }) return problem(409, "assignment_exists")
                userRoles += mutableMapOf("userId" to seg[1], "roleId" to roleId)
                json(201, mapOf("id" to "ur-$roleId", "userId" to seg[1], "roleId" to roleId, "orgId" to null, "assignedBy" to caller, "assignedAt" to "2026-10-24T00:00:00Z"))
            }
            seg.size == 4 && method == "DELETE" -> { userRoles.removeIf { it["userId"] == seg[1] && it["roleId"] == seg[3] }; MockResponse().setResponseCode(204) }
            else -> problem(405, "method")
        }
    }

    /** product-api's `TokenClaimsController` in miniature. */
    private fun tokenClaimsRoute(method: String, clientId: String, env: String?, b: Map<String, Any?>): MockResponse {
        if (applications.none { it["clientId"] == clientId && visible(it, env) }) return problem(404, "not_found")
        fun view() = tokenClaims[clientId].let { s ->
            mapOf(
                "clientId" to clientId, "enabled" to (s != null), "sources" to (s ?: emptyList()),
                "claimKeys" to (s ?: emptyList()).filter { it == "permissions" || it == "roles" },
                "roleMapping" to roleMappings[clientId], "webhookRegistered" to (s != null),
            )
        }
        return when (method) {
            "GET" -> json(200, view())
            "PUT" -> {
                val sources = ((b["sources"] as? List<*>)?.map { it.toString() } ?: listOf("permissions")).distinct()
                val unsupported = sources.filterNot { it in supportedClaimSources || it.startsWith("metadata:") }
                if (sources.isEmpty() || unsupported.isNotEmpty()) return problem(400, "unsupported_claim_source")
                @Suppress("UNCHECKED_CAST")
                val mapping = (b["roleMapping"] as? Map<String, Any?>)?.mapValues { it.value.toString() }
                if (mapping != null) roleMappingProblem(mapping, sources)?.let { return problem(400, "invalid_role_mapping", mapOf("detail" to it)) }
                tokenClaims[clientId] = sources
                if (mapping == null) roleMappings.remove(clientId) else roleMappings[clientId] = mapping
                json(200, view())
            }
            "DELETE" -> if (tokenClaims.remove(clientId) != null) MockResponse().setResponseCode(204) else problem(404, "not_found")
            else -> problem(405, "method")
        }
    }

    /** product-api's `RoleMappingRules.validate` (+ the `roles`-source precondition) in miniature, with its wording. */
    private fun roleMappingProblem(mapping: Map<String, String>, sources: List<String>): String? {
        if ("roles" !in sources) return "Field 'roleMapping' requires the 'roles' claim source."
        if (mapping.size > 100) return "Field 'roleMapping' holds ${mapping.size} entries; at most 100 are allowed."
        for ((role, value) in mapping) {
            if (role.isBlank() || role.length > 200 || Regex("\\p{Cntrl}").containsMatchIn(role)) {
                return "Every 'roleMapping' key must be a role name of 1 to 200 characters without control characters."
            }
            if (!Regex("^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$").matches(value)) {
                return "Every 'roleMapping' value must be 1 to 128 characters, start with a letter or digit, and contain only letters, digits and . _ - : @ /."
            }
            if (Regex("^(tenant|admin|holder):.*", RegexOption.IGNORE_CASE).matches(value)) {
                return "A 'roleMapping' value may not start with a reserved platform scope prefix (tenant:, admin:, holder:)."
            }
        }
        return null
    }

    /** SSO-3113 — the one-shot client secrets the fake minted for confidential applications, by clientId (test-side ledger only). */
    val mintedSecrets = mutableMapOf<String, String>()
    // ── SSO-3689 — workload-identity trusts (product-api /api/v1/workload-identity/trusts) ──
    /** The trusts, with `_env` (null ⇒ production). Rendered as `WorkloadIdentityTrustResponse` — never key material. */
    val trusts = mutableListOf<MutableMap<String, Any?>>()
    /**
     * The scopes the CALLER's token carries — the hub's scope ceiling (D6): a trust may carry only scopes among them
     * (`403 scope_not_grantable` otherwise). Null ⇒ the caller holds everything (a founder's session).
     */
    var callerScopes: Set<String>? = null

    /**
     * SSO-3926 — model product-api's `@PreAuthorize` scope gates: with this on (and [callerScopes] set), a call whose
     * endpoint is gated on a scope the caller does not hold is answered `403 access_denied` "The token does not grant the
     * scope required for this operation" — the exact refusal thoryn-cicd run 39917407017 met. [requests] records every call
     * the fake answered, so a test can assert that a refused-up-front plan sent none. Off by default.
     */
    var enforceScopeGates = false
    /** SSO-3926 — every `METHOD /route` the fake was asked, in order (reads included; [writes] keeps the non-GETs). */
    val requests = mutableListOf<String>()
    /** Race fixture: the first trust POST finds its name taken meanwhile — the fake seeds the trust from the body and answers 409. */
    var trustNameTakenOnce = false
    /** The page size the trusts list uses (cursor = the offset), so a test can exercise the engine's paging. */
    var trustPageSize = 50
    /**
     * SSO-3774 — model product-api AFTER oauthy S1 (SSO-3772, ADR 2026-10-16 §1): a trust is the platform object
     * `trust:<id>` — ownable (creator-becomes-owner for a `client:` creator; `owner` rendered on the response), contained in
     * its plane (`manager = this ∪ owner ∪ parent.manager`) — its reads / delete / plan-profile gated on the trust OR its
     * plane, the list FILTERED to the trusts the caller reaches (404 only when it reaches nothing in the plane), and a
     * binding needing `manager` on the trust (I4, SSO-3773). Off ⇒ the platform before S1: `trust` is an unknown type
     * (`400 invalid_type` on `/access/check` and `/access/mine`) and a trust is reached through its plane only.
     */
    var trustObjects = true
    /**
     * SSO-3925 — how product-api answers a WIDENING `PUT …/trusts/{id}/scopes` (a scope added to either set): null ⇒ made
     * (a person with a fresh passkey sign-in), `"step_up"` ⇒ the RFC 9470 `403` + `WWW-Authenticate`, `"machine"` ⇒
     * `403 elevated_action_requires_person`. A narrowing is always made.
     */
    var trustWidening: String? = null
    // ── SSO-3766 / SSO-3767 / SSO-3770 — the application settings product-api validates (oauthy SSO-3758 / 3759 / 3762) ──
    /** The workspace is the platform HOME (`thoryn`): only then may an application list `thoryn_access_grant`. */
    var homeWorkspace = false
    /** The authorization server's supported RFC 9396 types (discovery), plus the hub's own `thoryn_access_grant`. */
    var supportedAuthorizationDetailTypes = setOf("openid_credential", "thoryn_access_grant")
    /** Per environment (null ⇒ production): the authentication policy's `refreshClipSeconds` — the cap on a sliding session. */
    val refreshClipSeconds = mutableMapOf<String?, Long>()
    /** The NEXT application create / update is refused with this `(status, errorCode, extensions)` — a code the file cannot reach. */
    var nextApplicationWriteProblem: Triple<Int, String, Map<String, Any?>>? = null
    // ── SSO-3413 / SSO-3414 — the workspace's ONE custom domain (product-api /api/v1/custom-domain) ──
    /** Custom domains enabled for the workspace (the operator entitlement). */
    var domainEntitled = true
    /** False ⇒ the caller has no reach: every custom-domain call is the opaque 404 (no grant). */
    var domainReachable = true
    var domainHost: String? = null
    var domainState = "NONE"
    /** Whether the DNS records are published: a verify then passes (→ VERIFIED). */
    var dnsPublished = false
    /** The failing proof a verify reports while [dnsPublished] is false. */
    var dnsFailureReason = "txt_record_missing"
    /** The workspace has production users (a claim then needs acceptReSignIn). */
    var productionUsers = false
    /** SUSPENDED only — when the domain is released. */
    var domainReleaseAt: String? = null
    /** The `ttl` product-api sends on each record; null models a product-api from before SSO-3414. */
    var domainTtl: Int? = 300
    /** VERIFIED → ACTIVE after this many further status reads (models the certificate stage); null ⇒ never. */
    var activeAfterReads: Int? = null
    private var readsSinceVerified = 0
    private var lastCheckReason: String? = null

    // ── SSO-3792 — application creation slots (product-api SSO-3789, oauthy ADR 2026-10-17 §2 / §3) ──
    /**
     * The slots: `clientId`, `subject` (the holder), `_env` (the plane; null ⇒ production), `createdAt`, `expired`. A slot
     * lets its holder create exactly that client id on exactly that plane, once ([applicationCreateGate]); any create of
     * the name sweeps it.
     */
    val slots = mutableListOf<MutableMap<String, Any?>>()
    /** False ⇒ product-api before SSO-3789: every `/api/v1/access/application-slots` call is the router's `404`. */
    var slotsSupported = true
    /** Every `GET /api/v1/access/application-slots` (a READ the engine makes at most once per plan). */
    var slotReads = 0
    /**
     * A listing that carries EVERY holder's slots to a non-admin too (product-api filters to the caller's own; this models a
     * listing that does not), so a test can show the engine never takes another identity's slot as its own.
     */
    var slotListingUnfiltered = false
    /** Race fixture: an admin releases every slot between the plan and the apply's create (the create then misses the gate). */
    var releaseSlotsBeforeCreate = false

    fun seedSlot(clientId: String, subject: String, env: String? = null, expired: Boolean = false) {
        slots += mutableMapOf("clientId" to clientId, "subject" to subject, "_env" to env, "createdAt" to if (expired) "2026-08-01T00:00:00Z" else "2026-10-17T00:00:00Z", "expired" to expired)
    }

    private fun slotView(slot: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "object" to "application:${slot["clientId"]}",
        "subject" to slot["subject"],
        "environment" to (slot["_env"] ?: "production"),
        "createdAt" to slot["createdAt"],
        "expiresAt" to if (slot["expired"] == true) "2026-08-31T00:00:00Z" else "2026-11-16T00:00:00Z",
        "expired" to slot["expired"],
    )

    /** product-api's `ApplicationSlotController` + `ApplicationSlotService` in miniature. */
    private fun applicationSlots(method: String, route: String, b: Map<String, Any?>): MockResponse {
        if (!slotsSupported) return problem(404, "no_route:$method $route")
        val admin = callerIsAdmin || direct("workspace:$tenantId", "admin")
        val seg = route.removePrefix("/api/v1/access/application-slots").trim('/')
        return when {
            seg.isEmpty() && method == "GET" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                slotReads++
                json(200, mapOf("data" to slots.filter { admin || slotListingUnfiltered || it["subject"] == caller }.map { slotView(it) }, "pagination" to mapOf("total" to slots.size, "nextCursor" to null)))
            }
            seg.isEmpty() && method == "POST" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                val subject = (b["subject"] as? String)?.takeIf { it.startsWith("client:") } ?: return problem(400, "invalid_subject")
                val clientId = (b["object"] as? String)?.takeIf { it.startsWith("application:") }?.removePrefix("application:") ?: return problem(400, "invalid_object")
                val envSlug = (b["environment"] as? String)?.takeIf { it.isNotBlank() } ?: return problem(400, "invalid_environment")
                if (!admin) return problem(404, "not_found")
                if (envSlug != "production" && environments.none { it["slug"] == envSlug }) return problem(404, "not_found")
                if (trusts.none { "client:${it["clientId"]}" == subject }) return problem(404, "not_found")
                if (clientId in setOf("thoryn-cli", "self-service-bff")) return problem(409, "reserved_client_id")
                if (applications.any { it["clientId"] == clientId }) return problem(409, "application_exists")
                val plane = envSlug.takeIf { it != "production" }
                val held = slots.firstOrNull { it["clientId"] == clientId }
                if (held != null && held["expired"] != true) {
                    if (held["subject"] == subject && held["_env"] == plane) return json(200, slotView(held))
                    if (held["subject"] != subject) return problem(409, "application_slot_held")
                }
                held?.let { slots.remove(it) }
                seedSlot(clientId, subject, plane)
                json(201, slotView(slots.last()))
            }
            method == "DELETE" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                val slot = slots.firstOrNull { it["clientId"] == seg } ?: return problem(404, "not_found")
                if (slot["subject"] != caller && !admin) return problem(404, "not_found")
                slots.remove(slot); MockResponse().setResponseCode(204)
            }
            else -> problem(405, "method")
        }
    }

    /**
     * SSO-3792 — `ApplicationsService.create`'s gate (`whenCreatorOrSlot`): `manager` on the plane, OR an unexpired slot the
     * caller holds for exactly this client id on exactly this plane — claimed (removed) before the create. Answers the
     * refusing response, or null to proceed. A slot never includes turning token exchange or token introspection on
     * (`403`, slot kept).
     */
    private fun applicationCreateGate(id: String, explicit: Boolean, env: String?, b: Map<String, Any?>): MockResponse? {
        if (releaseSlotsBeforeCreate) slots.clear()
        if (holds(planeRef(env), "manager")) return null
        val slot = slots.firstOrNull { explicit && it["clientId"] == id && it["subject"] == caller && it["_env"] == env && it["expired"] != true }
            ?: return problem(404, "not_found")
        if (b["allowTokenExchange"] == true) return problem(403, "token_exchange_not_grantable")
        // SSO-3810 — nor turning token introspection on (product-api's `introspectionGate` at a slot create, ADR §3).
        if (b["allowTokenIntrospection"] == true) return problem(403, "token_introspection_not_grantable")
        slots.remove(slot)
        return null
    }

    fun customDomainStatus(): Map<String, Any?> {
        val host = domainHost
        val records = if (host == null) emptyList() else listOf(
            linkedMapOf<String, Any?>("type" to "TXT", "name" to "_thoryn-verify.$host", "value" to "thoryn-verify=tok-$host"),
            linkedMapOf<String, Any?>("type" to "CNAME", "name" to host, "value" to "acme.auth.thoryn.io"),
        ).onEach { r -> domainTtl?.let { r["ttl"] = it } }
        val active = domainState == "ACTIVE"
        return linkedMapOf(
            "domain" to host,
            "state" to domainState,
            "entitled" to domainEntitled,
            "cnameTarget" to "acme.auth.thoryn.io",
            "dnsRecords" to records,
            "issuer" to if (active && host != null) "https://$host" else "https://acme.auth.thoryn.io",
            "customIssuer" to host?.let { "https://$it" },
            "certificateState" to when (domainState) { "VERIFIED" -> "PENDING"; "ACTIVE" -> "ACTIVE"; else -> "NONE" },
            "lastVerification" to lastCheckReason?.let { mapOf("checkedAt" to "2026-09-28T12:00:00Z", "result" to "failed", "reason" to it) },
            "suspension" to if (domainState == "SUSPENDED") mapOf("suspendedAt" to "2026-09-27T03:00:00Z", "reason" to (lastCheckReason ?: "cname_mismatch"), "releaseAt" to domainReleaseAt) else null,
            "reSignInAccepted" to false,
        )
    }

    private fun customDomain(method: String, route: String, b: Map<String, Any?>): MockResponse {
        if (!domainReachable) return problem(404, "custom_domain_not_found")
        return when {
            route == "/api/v1/custom-domain" && method == "GET" -> {
                if (domainState == "VERIFIED" && activeAfterReads != null && ++readsSinceVerified > activeAfterReads!!) domainState = "ACTIVE"
                json(200, customDomainStatus())
            }
            route == "/api/v1/custom-domain" && method == "PUT" -> {
                val host = b["domain"].toString()
                when {
                    !domainEntitled -> problem(403, "entitlement_required")
                    domainHost != null && domainHost != host -> problem(409, "custom_domain_exists")
                    productionUsers && b["acceptReSignIn"] != true -> problem(409, "production_users_present")
                    else -> {
                        if (domainHost == null) { domainHost = host; domainState = "PENDING" }
                        json(200, customDomainStatus())
                    }
                }
            }
            route == "/api/v1/custom-domain/verify" && method == "POST" -> when {
                domainHost == null -> problem(404, "custom_domain_not_found")
                !domainEntitled -> problem(403, "entitlement_required")
                dnsPublished -> {
                    if (domainState == "PENDING" || domainState == "SUSPENDED") { domainState = "VERIFIED"; readsSinceVerified = 0 }
                    lastCheckReason = null
                    json(200, customDomainStatus())
                }
                else -> {
                    lastCheckReason = dnsFailureReason
                    json(422, mapOf("type" to "about:blank", "status" to 422, "errorCode" to "verification_failed", "detail" to "DNS does not prove it", "reason" to dnsFailureReason))
                }
            }
            route == "/api/v1/custom-domain" && method == "DELETE" -> {
                domainHost = null; domainState = "NONE"; lastCheckReason = null
                MockResponse().setResponseCode(204)
            }
            else -> problem(404, "no_route:$method $route")
        }
    }

    private val supportedLoginMethods = listOf("password", "magic_link", "magic_code", "passkey", "totp", "sms")
    private var seq = 0
    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    // ── SSO-4042 — email templates, in identity's shape (`EmailTemplateType` + `EmailTemplateService`, behind product-api's facade) ──

    /** identity's `EmailTemplateType.allowedVariables`, written out from oauthy (read 2026-10-28). */
    private val EMAIL_TEMPLATE_VARIABLES = mapOf(
        "magic_link" to setOf("magicLinkUrl", "displayName", "expiryMinutes"),
        "invitation" to setOf("acceptUrl", "inviterName", "orgName", "role", "expiryDays"),
        "password_reset" to setOf("resetUrl", "displayName", "expiryMinutes"),
        "security_alert" to setOf("displayName", "clientId", "ipAddress", "userAgent", "timestamp", "action", "secureAccountUrl"),
        "account_unlock" to setOf("unlockUrl", "displayName", "expiryMinutes"),
        "email_verification" to setOf("verificationUrl", "displayName", "expiryHours"),
        "organization_invitation" to setOf("acceptUrl", "inviterName", "orgName", "expiryDays"),
        "co_admin_invitation" to setOf("acceptUrl", "inviterName", "expiryDays"),
    )
    private val TEMPLATE_PLACEHOLDER = Regex("\\{\\{\\s*([A-Za-z][A-Za-z0-9]*)\\s*}}")
    private val TEMPLATE_LOCALE = Regex("^[a-z]{2,3}$")

    /**
     * SSO-4054 — `GET /api/v1/login-experience/email-templates` (oauthy SSO-4053): every (type, locale) cell the HEADER's
     * environment stores, no body, sorted by (type, locale), in the `{data, pagination}` envelope (always one page). Exact per
     * environment, as identity's `EmailTemplateService.list`: a sandbox that stores nothing lists nothing.
     */
    private fun emailTemplateList(env: String?): MockResponse {
        val envSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: "production"
        val rows = emailTemplatesOf(env).entries.sortedWith(compareBy({ it.key.substringBefore(':') }, { it.key.substringAfter(':') })).map { (key, rec) ->
            mapOf("templateType" to key.substringBefore(':'), "locale" to key.substringAfter(':'), "environmentSlug" to envSlug, "subject" to rec["subject"], "updatedAt" to "2026-10-29T00:00:00")
        }
        return json(200, mapOf("data" to rows, "pagination" to mapOf("cursor" to null, "hasMore" to false)))
    }

    /**
     * SSO-4042 — one cell; SSO-4054 — of the HEADER's environment ([emailTemplatesOf]). The GET is EXACT, as oauthy #4289 pins it
     * (identity's `InternalTenantEmailTemplateEnvironmentE2ETest`: "a sandbox GET is exact — 404 template_not_customized even when
     * production has an override"): the production fallback is the send path's, never the admin read's. [emailTemplateGetResolves]
     * makes the GET answer production's row for a sandbox that has none, so a test can show the engine never mistakes an
     * inherited copy for the sandbox's own.
     */
    private fun emailTemplate(method: String, type: String, rawLocale: String?, b: Map<String, Any?>, env: String?): MockResponse {
        val emailTemplates = emailTemplatesOf(env)
        val envSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: "production"
        val allowed = EMAIL_TEMPLATE_VARIABLES[type] ?: return problem(400, "unknown_template_type", mapOf("allowedTypes" to EMAIL_TEMPLATE_VARIABLES.keys.toList()))
        val trimmed = rawLocale?.trim()
        val locale = if (trimmed.isNullOrEmpty() || trimmed == "*") "*" else trimmed.lowercase().also { if (!TEMPLATE_LOCALE.matches(it)) return problem(400, "invalid_template_locale") }
        val key = "$type:$locale"
        fun view(rec: Map<String, Any?>, from: String = envSlug) = mapOf("templateType" to type, "locale" to locale, "environmentSlug" to from, "subject" to rec["subject"], "bodyHtml" to rec["bodyHtml"], "allowedVariables" to allowed.sorted(), "updatedAt" to "2026-10-28T00:00:00")
        return when (method) {
            "GET" -> emailTemplates[key]?.let { json(200, view(it)) }
                ?: this.emailTemplates[key]?.takeIf { emailTemplateGetResolves && envSlug != "production" }?.let { json(200, view(it, from = "production")) }
                ?: problem(404, "template_not_customized", mapOf("allowedVariables" to allowed.sorted()))
            "PUT" -> {
                val subject = b["subject"]?.toString() ?: ""
                val body = b["bodyHtml"]?.toString() ?: ""
                if (subject.isBlank()) return problem(400, "template_subject_blank")
                if (body.isBlank()) return problem(400, "template_body_blank")
                if (subject.length > 998) return problem(413, "template_subject_too_large")
                if (body.toByteArray(Charsets.UTF_8).size > emailTemplateMaxBodyBytes) return problem(413, "template_body_too_large")
                val referenced = (TEMPLATE_PLACEHOLDER.findAll(subject) + TEMPLATE_PLACEHOLDER.findAll(body)).map { it.groupValues[1] }.toSet()
                val unknown = referenced - allowed
                if (unknown.isNotEmpty()) {
                    return json(400, mapOf("type" to "about:blank", "status" to 400, "title" to "unknown_template_variable", "errorCode" to "unknown_template_variable",
                        "detail" to "The template references ${unknown.size} variable(s) that are not allowed for the '$type' template type. Allowed variables are: ${allowed.sorted().joinToString(", ")}.",
                        "allowedVariables" to allowed.sorted(), "unknownVariables" to unknown.sorted()))
                }
                emailTemplates[key] = mutableMapOf("subject" to subject, "bodyHtml" to body)
                json(200, view(emailTemplates.getValue(key)))
            }
            "DELETE" -> {
                val reset = emailTemplates.remove(key)
                val remaining = emailTemplates.keys.filter { it.startsWith("$type:") }.map { it.substringAfter(':') }.sorted()
                json(200, mapOf("templateType" to type, "allLocales" to false, "resetLocales" to listOfNotNull(locale.takeIf { reset != null }), "remainingLocales" to remaining))
            }
            else -> problem(405, "method")
        }
    }

    // ── SSO-4057 — tenant-level legal documents, in identity's shape (`TenantLegalDocumentService` + `TenantLegalDocumentRules`,
    // behind product-api's `TenantLegalDocumentsController`; oauthy #4290, read 2026-10-29) ──

    private val LEGAL_HTML = Regex("<[A-Za-z/!?]")

    /** identity's `TenantLegalDocumentRules.validate`, the first broken rule as a `400`; null when valid. */
    private fun legalDocumentRuleProblem(b: Map<String, Any?>): MockResponse? {
        fun plain(v: Any?, max: Int) = v?.toString()?.trim()?.takeIf { it.isNotEmpty() && it.length <= max && it.none { c -> c == '<' || c == '>' || c.isISOControl() } }
        plain(b["version"], 64) ?: return problem(400, "invalid_version", mapOf("field" to "version"))
        plain(b["title"], 200) ?: return problem(400, "invalid_title", mapOf("field" to "title"))
        val format = b["format"]?.toString()?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "markdown"
        if (format != "markdown" && format != "text") return problem(400, "invalid_body_format", mapOf("field" to "format"))
        val body = b["body"]?.toString()?.takeIf { it.isNotBlank() } ?: return problem(400, "invalid_body", mapOf("field" to "body"))
        if (body.toByteArray(Charsets.UTF_8).size > 131_072) return problem(400, "body_too_large", mapOf("field" to "body"))
        if (body.any { it.isISOControl() && it != '\n' && it != '\r' && it != '\t' }) return problem(400, "invalid_body", mapOf("field" to "body"))
        if (LEGAL_HTML.containsMatchIn(body)) return problem(400, "html_not_allowed", mapOf("field" to "body"))
        return null
    }

    private fun legalDocumentView(d: Map<String, Any?>, env: String?): Map<String, Any?> = mapOf(
        "id" to d["id"], "docType" to (if (d["type"] == "privacy-policy") "privacy" else "terms"), "environment" to (envKey(env) ?: "production"),
        "version" to d["version"], "title" to d["title"], "format" to d["format"], "body" to d["body"], "active" to d["active"],
        "createdAt" to "2026-10-29T00:00:00", "acceptanceCount" to d["acceptanceCount"],
    )

    /** `/api/v1/login-experience/legal-documents/{type}[/{id}[/activate]]` — [seg] from `login-experience`. */
    private fun legalDocumentRoute(method: String, seg: List<String>, b: Map<String, Any?>, env: String?): MockResponse {
        val type = seg[2]
        if (type != "terms-of-use" && type != "privacy-policy") return problem(404, "no_route:$method ${seg.joinToString("/")}")
        val docs = legalDocuments.getOrPut(envKey(env)) { mutableListOf() }
        val ofType = docs.filter { it["type"] == type }
        if (seg.size == 3) return when (method) {
            // Newest first, every version (a soft-deleted one is just inactive), in product-api's ListEnvelope.
            "GET" -> json(200, mapOf("data" to ofType.reversed().map { legalDocumentView(it, env) }))
            "POST" -> {
                legalDocumentRuleProblem(b)?.let { return it }
                val version = b["version"].toString().trim()
                if (ofType.any { it["version"] == version }) return problem(409, "version_exists")
                ofType.forEach { it["active"] = false }
                val id = "ld-${++seq}"
                docs += mutableMapOf("id" to id, "type" to type, "version" to version, "title" to b["title"].toString().trim(),
                    "format" to (b["format"]?.toString()?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "markdown"), "body" to b["body"].toString(), "active" to true, "acceptanceCount" to 0L)
                json(201, legalDocumentView(docs.last(), env))
            }
            else -> problem(405, "method")
        }
        val doc = ofType.firstOrNull { it["id"] == seg[3] } ?: return problem(404, "not_found")
        return when {
            seg.size == 4 && method == "GET" -> json(200, legalDocumentView(doc, env))
            seg.size == 4 && method == "DELETE" -> {
                if ((doc["acceptanceCount"] as Number).toLong() > 0) return problem(409, "document_accepted")
                doc["active"] = false
                MockResponse().setResponseCode(204)
            }
            seg.size == 5 && seg[4] == "activate" && method == "POST" -> {
                ofType.forEach { it["active"] = false }
                doc["active"] = true
                MockResponse().setResponseCode(204)
            }
            else -> problem(405, "method")
        }
    }

    // ── SSO-4041 — hosted-login branding, in identity's shape (`LoginBrandingAdminService` + `BrandingCssVariables`) ──

    // SSO-4048 — the record grew six fields with oauthy SSO-4044: name, page title, favicon, footer links (no defaults: absent = not rendered).
    private val BRANDING_LINK_FIELDS = mapOf("faviconUrl" to listOf("https://"), "supportUrl" to listOf("https://", "mailto:"), "termsUrl" to listOf("https://"), "privacyUrl" to listOf("https://"))
    private val BRANDING_TEXT_FIELDS = mapOf("displayName" to 80, "pageTitle" to 120)
    private val BRANDING_FIELDS = listOf("logoUrl", "primaryColor", "backgroundColor", "borderRadiusPx", "theme", "cssVariables") + BRANDING_TEXT_FIELDS.keys + BRANDING_LINK_FIELDS.keys
    private val BRANDING_DEFAULTS = mapOf("logoUrl" to null, "primaryColor" to "#2563eb", "backgroundColor" to "#ffffff", "borderRadiusPx" to 4, "theme" to "auto") +
        (BRANDING_TEXT_FIELDS.keys + BRANDING_LINK_FIELDS.keys).associateWith { null }
    private val HEX_COLOR = Regex("^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
    private val CSS_VARIABLES = mapOf("--thoryn-accent" to "color", "--thoryn-text" to "color", "--thoryn-muted" to "color", "--thoryn-font-family" to "font")
    private val FONT_STACK = Regex("^[A-Za-z0-9 ,_'\"-]{1,120}$")

    /** product-api's `BrandingResponse`: `stored` with EVERY field (null when unset, `cssVariables` `{}`) + `effective` (defaults filled). */
    private fun brandingView(env: String?): Map<String, Any?> {
        val record = branding[env].orEmpty()
        val stored = BRANDING_FIELDS.associateWith { f -> record[f] ?: if (f == "cssVariables") emptyMap<String, String>() else null }
        val effective = BRANDING_DEFAULTS + record.filterKeys { it != "cssVariables" } + ("cssVariables" to (record["cssVariables"] ?: emptyMap<String, String>()))
        return mapOf("stored" to stored, "effective" to effective, "updatedAt" to if (record.isEmpty()) null else "2026-10-28T00:00:00Z")
    }

    /** identity's strict write validation (`400 invalid_branding_field`, extension `field`); the contrast floor is not modelled. */
    private fun brandingProblem(b: Map<String, Any?>): MockResponse? {
        fun bad(field: String) = problem(400, "invalid_branding_field", mapOf("field" to field))
        listOf("primaryColor", "backgroundColor").forEach { f -> (b[f] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { if (!HEX_COLOR.matches(it)) return bad(f) } }
        (b["borderRadiusPx"] as? Number)?.toInt()?.let { if (it !in 0..64) return bad("borderRadiusPx") }
        (b["theme"] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { if (it.lowercase() !in setOf("light", "dark", "auto")) return bad("theme") }
        (b["logoUrl"] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { if (!it.startsWith("https://") || it.length > 2000) return bad("logoUrl") }
        (b["cssVariables"] as? Map<*, *>)?.forEach { (k, v) ->
            val kind = CSS_VARIABLES[k] ?: return bad("cssVariables")
            val value = v?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return@forEach
            if (kind == "color" && !HEX_COLOR.matches(value)) return bad("cssVariables")
            if (kind == "font" && !FONT_STACK.matches(value)) return bad("cssVariables")
        }
        // SSO-4048 — identity's `sanitisePlainText` / `sanitiseHttpsUrl` / `sanitiseSupportUrl` (trimmed; blank clears).
        BRANDING_TEXT_FIELDS.forEach { (f, max) ->
            (b[f] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { t -> if (t.length > max || t.any { it == '<' || it == '>' || it.isISOControl() }) return bad(f) }
        }
        BRANDING_LINK_FIELDS.forEach { (f, schemes) ->
            (b[f] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { u ->
                val ok = u.length <= 2000 && u.none { it.isWhitespace() || it.isISOControl() } && schemes.any { u.startsWith(it, ignoreCase = true) && u.length > it.length }
                if (!ok) return bad(f)
            }
        }
        return null
    }

    fun writesTo(pathPrefix: String) = writes.filter { it.path.startsWith(pathPrefix) }

    /** SSO-3100 — the PROVISIONING writes only: the recipe interpreter's best-effort receipt attestation POST is not one. */
    val provisioningWrites: List<Write> get() = writes.filter { !it.path.startsWith("/api/v1/attestations") }
    fun reset() { writes.clear() }

    fun seedEnvironment(slug: String, name: String = slug): String =
        "env-${++seq}".also { environments += mutableMapOf("id" to it, "slug" to slug, "name" to name, "kind" to "sandbox", "suspended" to false) }

    /** [clientId] pins the id (a file may declare a fixed one); otherwise the fake allocates `app-<n>`. */
    fun seedApplication(
        env: String?,
        displayName: String,
        redirectUris: List<String> = listOf("http://127.0.0.1/callback"),
        clientId: String? = null,
    ): String =
        (clientId ?: "app-${++seq}").also { applications += mutableMapOf("clientId" to it, "displayName" to displayName, "redirectUris" to redirectUris, "status" to "active", "_env" to env) }

    /**
     * SSO-3689 — a live trust as product-api renders it: the `wi_` workload client, the environment issuer as audience,
     * the provider's pin block (GitHub: owner / repository / ids / environment / ref / runner rule; Kubernetes: issuer /
     * namespace / serviceAccount and `inlineKeyIds` or a discovered `jwksUri` — never the keys themselves).
     */
    fun seedTrust(
        env: String?,
        name: String,
        provider: String = "github_actions",
        scopes: List<String> = listOf("tenant:applications.read"),
        pins: Map<String, Any?> = mapOf("owner" to "acme", "repository" to "billing"),
        clientId: String? = null,
        /** SSO-3702 — the trust's plan profile `{environment, scopes}` (scopes already derived), or null: rendered as `plan: null`. */
        plan: Map<String, Any?>? = null,
    ): String {
        val id = "trust-${++seq}"
        val audience = "https://acme.auth.thoryn.io" + (env?.let { "/$it" } ?: "")
        val repo = "${pins["owner"]}/${pins["repository"]}"
        val rec = mutableMapOf<String, Any?>(
            "id" to id, "name" to name, "provider" to provider, "scopes" to scopes, "enabled" to true,
            "clientId" to (clientId ?: "wi_${"%024x".format(seq)}"), "audience" to audience, "tokenEndpoint" to "$audience/oauth2/token",
            "environment" to (env ?: "production"), "createdAt" to "2026-10-14T00:00:00Z", "_env" to env,
            "issuer" to when (provider) { "forgejo" -> "${pins["instanceUrl"]}/api/actions"; "kubernetes" -> pins["issuer"]; else -> "https://token.actions.githubusercontent.com" },
            // SSO-3702 — product-api SSO-3701's shape: `plan` (null without a profile) and one anchored `sub` pattern per profile.
            "plan" to plan,
            "subjectPatterns" to if (provider == "github_actions") listOfNotNull(
                "^repo:\\Q$repo\\E:${pins["environment"]?.let { "environment:\\Q$it\\E" } ?: ".*"}$",
                plan?.let { "^repo:\\Q$repo\\E:environment:\\Q${it["environment"]}\\E$" },
            ) else emptyList(),
        )
        val block = pins.filterKeys { it != "jwks" }.toMutableMap()
        when (provider) {
            "github_actions" -> { block.putIfAbsent("githubHostedRunnersOnly", false); listOf("ownerId", "repositoryId", "environment", "ref").forEach { block.putIfAbsent(it, null) } }
            "kubernetes" -> {
                val kids = ((pins["jwks"] as? Map<*, *>)?.get("keys") as? List<*>).orEmpty().mapNotNull { (it as? Map<*, *>)?.get("kid")?.toString() }
                block["inlineKeyIds"] = kids
                block["jwksUri"] = if (kids.isEmpty()) "${pins["issuer"]}/openid/v1/jwks" else null
                listOf("namespace", "serviceAccount").forEach { block.putIfAbsent(it, null) }
            }
        }
        rec[when (provider) { "forgejo" -> "forgejo"; "kubernetes" -> "kubernetes"; else -> "github" }] = block
        trusts += rec
        return id
    }

    /** The plane's parent object in the model: the environment by slug, or the workspace for production. */
    private fun planeRef(env: String?): String =
        env?.let { s -> environments.firstOrNull { it["slug"] == s }?.let { "environment:${it["id"]}" } } ?: "workspace:$tenantId"

    private fun workloadIdentity(method: String, route: String, env: String?, confirm: String?, b: Map<String, Any?>, path: String): MockResponse {
        val seg = route.removePrefix("/api/v1/workload-identity/trusts").trim('/')
        // Environment managers write, viewers read; anyone else (and an unknown plane) is answered 404.
        if (env != null && environments.none { it["slug"] == env }) return problem(404, "environment_not_found")
        val plane = planeRef(env)
        val inPlane = trusts.filter { it["_env"] == env }
        // SSO-3774 (S1) — reach on the TRUST unions with reach on its plane; a caller that reaches nothing in the plane is 404.
        fun may(t: Map<String, Any?>, relation: String) = holds(plane, relation) || (trustObjects && holds("trust:${t["id"]}", relation))
        val visible = inPlane.filter { may(it, "viewer") }
        val creating = seg.isEmpty() && method == "POST"
        if (creating && !holds(plane, "manager")) return problem(404, "environment_not_found")
        if (!creating && !holds(plane, "viewer") && visible.isEmpty()) return problem(404, "environment_not_found")
        return when {
            seg.isEmpty() && method == "GET" -> {
                val q = query(path)
                val offset = q["cursor"]?.toIntOrNull() ?: 0
                val size = q["limit"]?.toIntOrNull() ?: trustPageSize
                val page = visible.drop(offset).take(size)
                val next = (offset + size).takeIf { it < visible.size }?.toString()
                json(200, mapOf("data" to page.map { trustView(it) }, "pagination" to mapOf("cursor" to next, "hasMore" to (next != null), "total" to visible.size)))
            }
            seg.isEmpty() && method == "POST" -> createTrust(env, b)
            // SSO-3702 (product-api SSO-3701) — the ONE additive mutation: `POST …/{id}/plan-profile`.
            seg.endsWith("/plan-profile") && method == "POST" -> {
                val t = visible.firstOrNull { it["id"] == seg.removeSuffix("/plan-profile") && may(it, "manager") } ?: return problem(404, "workload_identity_trust_not_found")
                if (t["plan"] != null) return problem(409, "plan_profile_already_set")
                @Suppress("UNCHECKED_CAST")
                val github = t["github"] as? Map<String, Any?>
                val plan = planProfileOf(t["provider"] as String, github?.get("environment") as? String, (t["scopes"] as List<*>).map { it.toString() }, b)
                if (plan is MockResponse) return plan
                @Suppress("UNCHECKED_CAST")
                t["plan"] = plan as Map<String, Any?>
                t["subjectPatterns"] = listOfNotNull((t["subjectPatterns"] as? List<*>)?.firstOrNull()?.toString(), "^repo:\\Q${github?.get("owner")}/${github?.get("repository")}\\E:environment:\\Q${plan["environment"]}\\E$")
                json(200, trustView(t))
            }
            // SSO-3925 (oauthy product-api) — the in-place scope change: `PUT …/{id}/scopes` `{ scopes?, planScopes? }`.
            seg.endsWith("/scopes") && method == "PUT" -> changeTrustScopes(visible.firstOrNull { it["id"] == seg.removeSuffix("/scopes") && may(it, "manager") }, b)
            method == "GET" -> visible.firstOrNull { it["id"] == seg }?.let { json(200, trustView(it)) } ?: problem(404, "workload_identity_trust_not_found")
            method == "DELETE" -> {
                val t = visible.firstOrNull { it["id"] == seg && may(it, "manager") } ?: return problem(404, "workload_identity_trust_not_found")
                // The production plane's destructive-action guard (SSO-2413): the workspace slug in X-Thoryn-Confirm.
                if (env == null && confirm.isNullOrBlank()) return problem(428, "production_confirmation_required")
                // SSO-3689 — delete is refused while a login client is bound (hub `409 federated_trust_in_use`).
                if (applications.any { it["federatedTrust"] == t["id"] }) return problem(409, "federated_trust_in_use")
                trusts.remove(t); grants.removeIf { it["object"] == "trust:${t["id"]}" }; MockResponse().setResponseCode(204)
            }
            else -> problem(405, "method")
        }
    }

    /** SSO-3925 — product-api's `WorkloadIdentityTrustService.updateScopes` (+ the hub's rules) in miniature. */
    private fun changeTrustScopes(t: MutableMap<String, Any?>?, b: Map<String, Any?>): MockResponse {
        if (t == null) return problem(404, "workload_identity_trust_not_found")
        val liveScopes = (t["scopes"] as List<*>).map { it.toString() }
        @Suppress("UNCHECKED_CAST")
        val plan = (t["plan"] as? Map<String, Any?>)?.toMutableMap()
        val livePlan = (plan?.get("scopes") as? List<*>)?.map { it.toString() }.orEmpty()
        val scopes = (b["scopes"] as? List<*>)?.map { it.toString() }
        val planScopes = (b["planScopes"] as? List<*>)?.map { it.toString() }
        if (scopes == null && planScopes == null) return problem(400, "invalid_request")
        if (scopes != null && (scopes.isEmpty() || scopes.any { !it.startsWith("tenant:") })) return problem(400, "invalid_scope")
        if (planScopes != null && plan == null) return problem(400, "plan_profile_not_set")
        callerScopes?.let { held -> if ((scopes.orEmpty() + planScopes.orEmpty()).any { it !in held }) return problem(403, "scope_not_grantable") }
        val apply = scopes ?: liveScopes
        val planAfter = planScopes ?: livePlan
        if (planAfter.any { it !in apply }) return problem(400, "plan_scope_not_subset")
        val widened = apply.any { it !in liveScopes } || planAfter.any { it !in livePlan }
        if (widened) {
            when (trustWidening) {
                "step_up" -> return problem(403, "insufficient_user_authentication").setHeader(
                    "WWW-Authenticate",
                    "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:thoryn:acr:phishing_resistant\", max_age=\"300\"",
                )
                "machine" -> return problem(403, "elevated_action_requires_person")
            }
        }
        t["scopes"] = apply
        if (plan != null) t["plan"] = plan.also { it["scopes"] = planAfter }
        return json(200, trustView(t))
    }

    /** product-api's `WorkloadIdentityTrustService.create` in miniature: name, scope ceiling, production rules, the provider's pin block. */
    private fun createTrust(env: String?, b: Map<String, Any?>): MockResponse {
        val name = (b["name"] as? String)?.takeIf { it.isNotBlank() } ?: return problem(400, "invalid_request")
        val provider = b["provider"] as? String ?: "github_actions"
        if (provider !in setOf("github_actions", "forgejo", "kubernetes")) return problem(400, "unsupported_provider")
        val scopes = (b["scopes"] as? List<*>).orEmpty().map { it.toString() }
        if (scopes.isEmpty() || scopes.any { !it.startsWith("tenant:") }) return problem(400, "invalid_scope")
        callerScopes?.let { held -> if (scopes.any { it !in held }) return problem(403, "scope_not_grantable") }
        if (trusts.any { it["_env"] == env && it["name"] == name }) return problem(409, "workload_identity_trust_name_taken")
        if (env == null && b["confirmProduction"] != true) return problem(400, "production_confirmation_required")
        @Suppress("UNCHECKED_CAST")
        val pins = (b[when (provider) { "forgejo" -> "forgejo"; "kubernetes" -> "kubernetes"; else -> "github" }] as? Map<String, Any?>) ?: return problem(400, "invalid_$provider")
        when (provider) {
            "github_actions" -> {
                if ((pins["owner"] as? String).isNullOrBlank() || (pins["repository"] as? String).isNullOrBlank()) return problem(400, "invalid_github")
                if ((pins["ownerId"] == null) != (pins["repositoryId"] == null)) return problem(400, "invalid_github_ids")
                if (env == null && (pins["environment"] as? String).isNullOrBlank()) return problem(400, "production_requires_environment")
            }
            "forgejo" -> {
                if ((pins["instanceUrl"] as? String)?.startsWith("https://") != true) return problem(400, "invalid_forgejo_instance")
                if (pins["ownerId"] == null || pins["repositoryId"] == null) return problem(400, "invalid_forgejo_ids")
                if (env == null && (pins["ref"] as? String).isNullOrBlank()) return problem(400, "production_requires_ref")
            }
            "kubernetes" -> {
                if ((pins["issuer"] as? String)?.startsWith("https://") != true) return problem(400, "invalid_kubernetes_issuer")
                if (env == null && ((pins["namespace"] as? String).isNullOrBlank() || (pins["serviceAccount"] as? String).isNullOrBlank())) return problem(400, "production_requires_service_account")
            }
        }
        // SSO-3702 — the plan profile declared at create (product-api SSO-3701 validates it exactly as the mutation does).
        var plan: Map<String, Any?>? = null
        @Suppress("UNCHECKED_CAST")
        (b["plan"] as? Map<String, Any?>)?.let { declared ->
            val outcome = planProfileOf(provider, pins["environment"] as? String, scopes, declared)
            if (outcome is MockResponse) return outcome
            @Suppress("UNCHECKED_CAST")
            plan = outcome as Map<String, Any?>
        }
        // The race fixture creates the trust WITHOUT the profile the engine declared (another writer's shape), then refuses.
        val id = seedTrust(env, name, provider, scopes, pins, plan = if (trustNameTakenOnce) null else plan)
        if (trustNameTakenOnce) {
            // The race: another writer took the name between the engine's lookup and its POST — the trust now exists, the POST is refused.
            trustNameTakenOnce = false
            return problem(409, "workload_identity_trust_name_taken")
        }
        // SSO-3774 (S1) — creator-becomes-owner for a `client:` creator, rendered on the create response.
        if (trustObjects) creatorBecomesOwner("trust:$id")
        return json(201, trustView(trusts.first { it["id"] == id }))
    }

    /**
     * SSO-3702 — product-api's plan-profile validation in miniature (the same for create and the mutation): github_actions
     * only (`plan_profile_unsupported`); a non-empty environment (`plan_profile_requires_environment` /
     * `invalid_plan_environment`) that differs from the apply one (`plan_environment_equals_apply`); scopes each
     * `tenant:<area>.read` (`plan_scope_not_read_only`) and among the trust's (`plan_scope_not_subset`), held by the caller
     * (`scope_not_grantable`); omitted scopes DERIVED as the `.read` members of the trust's — none ⇒ `plan_scopes_empty`.
     * Answers the stored profile, or the refusing [MockResponse].
     */
    private fun planProfileOf(provider: String, applyEnvironment: String?, trustScopes: List<String>, declared: Map<String, Any?>): Any {
        if (provider != "github_actions") return problem(400, "plan_profile_unsupported")
        val environment = declared["environment"] ?: return problem(400, "plan_profile_requires_environment")
        if (environment !is String || environment.isBlank()) return problem(400, "invalid_plan_environment")
        if (environment == applyEnvironment) return problem(400, "plan_environment_equals_apply")
        val explicit = (declared["scopes"] as? List<*>)?.map { it.toString() }
        val scopes = when {
            explicit == null -> trustScopes.filter { it.endsWith(".read") }
            explicit.isEmpty() -> return problem(400, "plan_scopes_empty")
            explicit.any { !it.endsWith(".read") } -> return problem(400, "plan_scope_not_read_only")
            explicit.any { it !in trustScopes } -> return problem(400, "plan_scope_not_subset")
            else -> explicit
        }
        if (scopes.isEmpty()) return problem(400, "plan_scopes_empty")
        callerScopes?.let { held -> if (scopes.any { it !in held }) return problem(403, "scope_not_grantable") }
        return linkedMapOf<String, Any?>("environment" to environment, "scopes" to scopes)
    }

    fun seedGrant(subject: String, relation: String, objectRef: String) {
        grants += mutableMapOf("subject" to subject, "relation" to relation, "object" to objectRef, "createdAt" to "2026-09-15T00:00:00Z")
    }

    fun grantsOn(objectRef: String): List<String> = grants.filter { it["object"] == objectRef }.map { "${it["subject"]} ${it["relation"]}" }

    /** SSO-3673 — the forward checks asked about one object, as `relation`s in order. */
    fun checksOn(objectRef: String): List<String> = checks.filter { it.objectRef == objectRef }.map { it.relation }

    // ── SSO-3667 / SSO-3673 — the platform `owner` relation (one subject per application / environment) ──

    private val ownableTypes: Set<String> get() = if (trustObjects) setOf("application", "environment", "trust") else setOf("application", "environment")

    /** The one `owner` subject of [objectRef], or null. */
    fun ownerOf(objectRef: String): String? = grants.firstOrNull { it["object"] == objectRef && it["relation"] == "owner" }?.get("subject") as String?

    /** SSO-3774 — a trust as product-api renders it: `owner: { subject } | null` after S1, no `owner` field before it. */
    private fun trustView(rec: Map<String, Any?>): Map<String, Any?> = if (trustObjects) withOwner(rec, "trust:${rec["id"]}") else public(rec)

    /** Render a resource the way product-api does since SSO-3667: `owner: { subject } | null` (applications; environments ahead of product-api's EnvironmentResponse). */
    private fun withOwner(rec: Map<String, Any?>, objectRef: String): Map<String, Any?> =
        public(rec) + mapOf("owner" to ownerOf(objectRef)?.let { mapOf("subject" to it) })

    /** Creator-becomes-owner (SSO-3667): a `client:` creator owns the ownable resource it creates; a person's create has no owner. */
    private fun creatorBecomesOwner(objectRef: String) {
        if (caller.startsWith("client:") && ownerOf(objectRef) == null) seedGrant(caller, "owner", objectRef)
    }

    // ── SSO-3659 — the caller's reach, computed from the grants through the platform model's containment ──

    /** Every platform object of [type] that exists in the fake, as `<type>:<id>` (production-plane singletons by `production`). */
    private fun objectsOf(type: String): List<String> = when (type) {
        "workspace" -> listOf("workspace:$tenantId")
        "environment" -> environments.map { "environment:${it["id"]}" }
        "application" -> applications.map { "application:${it["clientId"]}" }
        "user" -> users.map { "user:${it["id"]}" }
        "federation_member" -> federationMembers.map { "federation_member:${it["id"]}" }
        "email_provider" -> emailProviders.keys.map { "email_provider:${it ?: "production"}" }
        "login_theme" -> branding.keys.map { "login_theme:${it ?: "production"}" }
        "login_methods" -> loginMethods.keys.map { "login_methods:${it ?: "production"}" }
        "login_flow" -> activeFlow.keys.map { "login_flow:${it ?: "production"}" }
        "custom_domain" -> if (domainHost != null) listOf("custom_domain:$tenantId") else emptyList()
        "trust" -> if (trustObjects) trusts.map { "trust:${it["id"]}" } else emptyList()
        else -> emptyList()
    }

    /** The object's `parent` edge: an environment by slug (or the workspace for the production plane / env-less kinds). */
    private fun parentOf(ref: String): String? {
        val type = ref.substringBefore(':'); val id = ref.substringAfter(':')
        fun envRef(slug: String?): String = slug?.let { s -> environments.firstOrNull { it["slug"] == s }?.let { "environment:${it["id"]}" } } ?: "workspace:$tenantId"
        return when (type) {
            "workspace" -> null
            "environment", "custom_domain" -> "workspace:$tenantId"
            "application" -> envRef(applications.firstOrNull { it["clientId"] == id }?.get("_env") as String?)
            "user" -> envRef(users.firstOrNull { it["id"] == id }?.get("_env") as String?)
            "federation_member" -> envRef(federationMembers.firstOrNull { it["id"] == id }?.get("_env") as String?)
            "trust" -> envRef(trusts.firstOrNull { it["id"] == id }?.get("_env") as String?)
            else -> envRef(id.takeIf { it != "production" })
        }
    }

    private fun direct(ref: String, relation: String): Boolean = grants.any { it["object"] == ref && it["relation"] == relation && it["subject"] == caller }

    /**
     * `owner = this` (direct only — never inherited, never implied by admin standing); `manager = this ∪ owner ∪
     * parent.manager`; `viewer = this ∪ manager ∪ parent.viewer`; a workspace admin holds manager and viewer everywhere.
     */
    fun holds(ref: String, relation: String): Boolean {
        if (relation == "owner") return direct(ref, "owner")
        if (callerIsAdmin || direct("workspace:$tenantId", "admin")) return true
        if (direct(ref, relation)) return true
        if (direct(ref, "owner")) return true
        if (relation == "viewer" && direct(ref, "manager")) return true
        val parent = parentOf(ref) ?: return false
        return holds(parent, relation)
    }

    /** SSO-3673 — `POST /api/v1/access/check`'s `resolvedVia`: direct, owner, or inherited (product-api's precedence). */
    private fun resolvedVia(ref: String, relation: String): String = when {
        direct(ref, relation) -> "direct"
        relation != "owner" && ref.substringBefore(':') in ownableTypes && direct(ref, "owner") -> "owner"
        else -> "inherited"
    }

    /** What `/api/v1/access/mine?type=&relation=` answers: every object of the type the caller holds the relation on. */
    fun reach(type: String, relation: String): List<String> = objectsOf(type).filter { holds(it, relation) }

    private fun query(path: String): Map<String, String> =
        path.substringAfter('?', "").split('&').filter { it.contains('=') }.associate { kv ->
            kv.substringBefore('=') to java.net.URLDecoder.decode(kv.substringAfter('='), "UTF-8")
        }

    private fun body(req: RecordedRequest): Map<String, Any?> {
        val raw = req.body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        @Suppress("UNCHECKED_CAST")
        return mapper.readValue(raw, Map::class.java) as Map<String, Any?>
    }

    private fun json(status: Int, value: Any?): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(mapper.writeValueAsString(value))

    private fun problem(status: Int, code: String, extensions: Map<String, Any?> = emptyMap()): MockResponse =
        json(status, mapOf("type" to "about:blank", "status" to status, "title" to code, "errorCode" to code, "detail" to code) + extensions)

    private fun visible(rec: Map<String, Any?>, env: String?) = rec["_env"] == env

    /** SSO-3689 — like product-api's `ApplicationResponse`, the fake does NOT render `jwks` / `jwksUri` (the key location is write-only today). */
    private fun public(rec: Map<String, Any?>) = rec.filterKeys { !it.startsWith("_") && it !in KEY_LOCATION_FIELDS }

    private val KEY_LOCATION_FIELDS = setOf("jwks", "jwksUri")

    /** SSO-3689 — `FederatedAssertionBindingValidator` in miniature: a `federatedTrust` must be the id of a trust of THIS plane (`400 federated_trust_not_found`); the method needs the binding and refuses a key. */
    private fun federatedBindingProblem(b: Map<String, Any?>, env: String?, previous: Any? = null): MockResponse? {
        val methods = (b["clientAuthenticationMethods"] as? List<*>)?.map { it.toString() }
        val federated = methods?.contains("federated_assertion") == true
        val trust = b["federatedTrust"] as? String
        if (!federated) return if (trust != null && methods != null) problem(400, "federated_trust_without_method") else null
        if (methods!!.size != 1) return problem(400, "federated_assertion_only_method")
        if (b["jwks"] != null || b["jwksUri"] != null) return problem(400, "federated_assertion_no_secret_or_key")
        if (trust == null) return problem(400, "federated_trust_required")
        if (trusts.none { it["id"] == trust && it["_env"] == env }) return problem(400, "federated_trust_not_found")
        // SSO-3773 (I4) — setting or CHANGING a binding needs `manager` on the trust (its plane's before S1); the same opaque 400.
        if (trust != previous && !holds(if (trustObjects) "trust:$trust" else planeRef(env), "manager")) return problem(400, "federated_trust_not_found")
        return null
    }

    /**
     * SSO-3766 / SSO-3767 / SSO-3770 — `ApplicationsService` + `AdvancedClientSettingsValidator` in miniature, checked against
     * the state the application WILL have ([previous] + the body): the absolute session bounds, the sliding-window coherence,
     * the workspace cap; the supported / permitted authorization-detail types; token exchange needs an authenticating client
     * and the grant, and turning it ON on an existing application needs `manager` on its plane (`403`).
     */
    private fun applicationSettingsProblem(b: Map<String, Any?>, env: String?, previous: Map<String, Any?>? = null): MockResponse? {
        nextApplicationWriteProblem?.let { (status, code, extensions) -> nextApplicationWriteProblem = null; return problem(status, code, extensions) }
        val merged = (previous.orEmpty() + b)
        fun long(v: Any?): Long? = (v as? Number)?.toLong()
        long(b["refreshTokenAbsoluteMaxTtlSeconds"])?.let { if (it !in 3_600L..7_776_000L) return problem(400, "token_ttl_out_of_range", mapOf("field" to "refreshTokenAbsoluteMaxTtlSeconds", "min" to 3_600, "max" to 7_776_000)) }
        val sliding = merged["refreshTokenSlidingWindow"] == true
        val absolute = long(merged["refreshTokenAbsoluteMaxTtlSeconds"]) ?: 7_776_000L
        if (b["refreshTokenAbsoluteMaxTtlSeconds"] != null && !sliding) return problem(400, "session_lifetime_requires_sliding_window")
        if (sliding && absolute < (long(merged["refreshTokenTtlSeconds"]) ?: 3_600L)) return problem(400, "session_lifetime_below_refresh_ttl")
        val clip = refreshClipSeconds[env]
        if (sliding && clip != null && absolute > clip && (b["refreshTokenSlidingWindow"] != null || b["refreshTokenAbsoluteMaxTtlSeconds"] != null)) {
            return problem(400, "session_exceeds_tenant_policy", mapOf("max" to clip))
        }
        (b["allowedAuthorizationDetailTypes"] as? List<*>)?.map { it.toString() }?.let { types ->
            if (types.any { it !in supportedAuthorizationDetailTypes }) return problem(400, "unsupported_authorization_details_type")
            if ("thoryn_access_grant" in types && !homeWorkspace) return problem(403, "authorization_details_type_not_permitted")
        }
        if (merged["allowTokenExchange"] == true) {
            val methods = (merged["clientAuthenticationMethods"] as? List<*>)?.map { it.toString() }
            if (merged["clientType"] == "public" || methods?.contains("none") == true) return problem(400, "token_exchange_requires_confidential_client")
            if ((merged["grantTypes"] as? List<*>)?.contains("urn:ietf:params:oauth:grant-type:token-exchange") != true) return problem(400, "token_exchange_grant_required")
            if (previous != null && previous["allowTokenExchange"] != true && b["allowTokenExchange"] == true && !holds(planeRef(env), "manager")) {
                return problem(403, "token_exchange_not_grantable")
            }
        }
        // SSO-3807 / SSO-3810 — the access-token format values, and introspection only for an authenticating client; turning
        // introspection ON on an existing application needs `manager` on its plane (`403`), like token exchange.
        b["accessTokenFormat"]?.let { if (it !in setOf("self-contained", "reference")) return problem(400, "invalid_access_token_format") }
        if (merged["allowTokenIntrospection"] == true) {
            val methods = (merged["clientAuthenticationMethods"] as? List<*>)?.map { it.toString() }
            if (merged["clientType"] == "public" || methods?.contains("none") == true) return problem(400, "token_introspection_requires_confidential_client")
            if (previous != null && previous["allowTokenIntrospection"] != true && b["allowTokenIntrospection"] == true && !holds(planeRef(env), "manager")) {
                return problem(403, "token_introspection_not_grantable")
            }
        }
        return null
    }

    /** SSO-3766 / SSO-3767 / SSO-3770 — product-api renders every setting on every application response, defaults included. */
    private fun applicationView(a: Map<String, Any?>): Map<String, Any?> =
        mapOf<String, Any?>(
            "allowTokenExchange" to false, "allowedAuthorizationDetailTypes" to emptyList<String>(),
            "refreshTokenSlidingWindow" to false, "refreshTokenAbsoluteMaxTtlSeconds" to 7_776_000L,
            "allowTokenIntrospection" to false, "accessTokenFormat" to "self-contained",
            "dpopAllowed" to false, "dpopRequired" to false,
        ) + withOwner(a, "application:${a["clientId"]}")

    /**
     * SSO-3722 — "reach into a plane" as product-api's filter sees it: any relation on the plane itself (held or
     * inherited), or a direct grant on an object INSIDE it — an owner of one application in the plane reaches the plane.
     */
    private fun reaches(env: String?): Boolean {
        val plane = planeRef(env)
        if (holds(plane, "viewer")) return true
        // SSO-3792 — a slot is CONTAINED in its plane (`viewer = owner ∪ parent.viewer`): its holder may select the plane.
        if (slots.any { it["subject"] == caller && it["_env"] == env }) return true
        return grants.any { it["subject"] == caller && parentOf(it["object"].toString()) == plane }
    }

    /** The first path segment of every route product-api's EnvironmentClaimFilter guards (the plane-scoped surface). */
    /**
     * SSO-3926 — the scope product-api's controller gates [seg] on, written out from the oauthy controllers (not derived
     * from the engine's own table, so a drift between the two shows up as a failing test): `EnvironmentController`,
     * `ApplicationsController`, `UsersController`, `FederationMembersController`, `EmailProviderController`,
     * `LoginExperienceController`, `LoginFlowController`, `LoginMethodPolicyController`, `CustomDomainController`,
     * `WorkloadIdentityTrustController`, `AccessController`, `ApplicationSlotController`.
     */
    private fun scopeGate(method: String, seg: List<String>): String? {
        val verb = if (method == "GET" || (seg[0] == "access" && seg.getOrNull(1) == "check")) "read" else "write"
        val area = when (seg[0]) {
            "environments" -> "environments"
            "applications" -> "applications"
            "users" -> if (seg.getOrNull(2) == "roles") "roles" else "users"
            "federation-members" -> "federation"
            "email-provider" -> "email"
            // SSO-4057 — TenantLegalDocumentsController: its own `tenant:legal-documents.*` pair (oauthy SSO-4069), not the
            // login experience's `idp` area.
            "login-experience" -> if (seg.getOrNull(1) == "legal-documents") "legal-documents" else "idp"
            "login-flows", "login-methods" -> "idp"
            "custom-domain" -> "domains"
            "workload-identity" -> "workload-identity"
            "access" -> "access"
            // SSO-3941 — RolesController / PermissionsController / UserRolesController (/users/{sub}/roles).
            "roles", "permissions" -> "roles"
            else -> return null
        }
        return "tenant:$area.$verb"
    }

    /** SSO-3926 — product-api's `hasAnyAuthority` aliases: the deprecated `tenant:clients.*` still opens `/applications`. */
    private val SCOPE_ALIASES = mapOf("tenant:applications.read" to "tenant:clients.read", "tenant:applications.write" to "tenant:clients.write")

    private val PLANE_SCOPED_ROUTES = setOf("applications", "users", "roles", "federation-members", "email-provider", "login-experience", "login-methods", "login-flows")

    private fun mintsSecret(b: Map<String, Any?>): Boolean {
        val methods = (b["clientAuthenticationMethods"] as? List<*>)?.map { it.toString() } ?: return true
        return "client_secret_basic" in methods || "client_secret_post" in methods
    }

    override fun dispatch(req: RecordedRequest): MockResponse {
        val method = req.method ?: "GET"
        val path = req.path ?: "/"
        val route = path.substringBefore('?')
        val env = req.getHeader("X-Thoryn-Environment")
        val confirm = req.getHeader("X-Thoryn-Confirm")
        // SSO-3113 — a DELETE may carry a JSON body (`DELETE /api/v1/access/grants`); `body` tolerates an empty one.
        val b = if (method == "GET") emptyMap() else body(req)
        // SSO-3673 — the forward check is a POST but a READ: it is recorded on `checks`, never as a write.
        if (method != "GET" && route != "/api/v1/access/check") writes += Write(method, route, env, confirm, b)
        if (method == "DELETE" && failingDeletes.any { route.startsWith(it) }) return problem(503, "unavailable")
        val seg = route.removePrefix("/api/v1/").split('/')
        requests += "$method $route"
        if (enforceScopeGates) scopeGate(method, seg)?.let { required ->
            val held = callerScopes.orEmpty()
            val alias = SCOPE_ALIASES[required]
            if (required !in held && (alias == null || alias !in held)) {
                return json(403, mapOf("type" to "https://thoryn.io/problems/access_denied", "status" to 403, "title" to "Forbidden", "errorCode" to "access_denied", "detail" to "The token does not grant the scope required for this operation."))
            }
        }
        if (environmentClaimFilter && seg[0] in PLANE_SCOPED_ROUTES && !reaches(env)) return problem(404, "unknown_environment")
        return when {
            // ── environments ──
            route == "/api/v1/environments" && method == "GET" -> json(200, mapOf("environments" to environments.map { withOwner(it, "environment:${it["id"]}") }))
            route == "/api/v1/environments" && method == "POST" -> {
                val id = seedEnvironment(b["slug"].toString(), b["name"]?.toString() ?: b["slug"].toString())
                creatorBecomesOwner("environment:$id")
                json(201, withOwner(environments.first { it["id"] == id }, "environment:$id"))
            }
            seg[0] == "environments" && seg.size == 2 && method == "PATCH" -> {
                val e = environments.firstOrNull { it["id"] == seg[1] } ?: return problem(404, "not_found")
                b["name"]?.let { e["name"] = it }; json(200, e)
            }
            seg[0] == "environments" && seg.size == 2 && method == "DELETE" -> {
                val e = environments.firstOrNull { it["id"] == seg[1] } ?: return problem(404, "not_found")
                if (confirm != e["slug"]) return problem(if (confirm == null) 428 else 422, "production_confirmation_required")
                environments.remove(e); MockResponse().setResponseCode(204)
            }
            // ── applications ──
            route == "/api/v1/applications" && method == "GET" -> json(200, mapOf("data" to applications.filter { visible(it, env) }.map { applicationView(it) }))
            route == "/api/v1/applications" && method == "POST" -> {
                // SSO-3104 / SSO-3119 — product-api honours a REQUESTED `clientId` (that is how the
                // committed file pins `cli` / `cli-ci`); only an absent one is allocated. The fake used
                // to overwrite it unconditionally, which hid both the fixed-id create and the grant that
                // names it as a subject.
                val explicit = (b["clientId"] as? String)?.takeIf { it.isNotBlank() }
                val id = explicit ?: "app-${++seq}"
                applicationCreateGate(id, explicit != null, env, b)?.let { return it }
                if (applications.any { it["clientId"] == id }) return problem(409, "client_id_taken")
                federatedBindingProblem(b, env)?.let { return it }
                applicationSettingsProblem(b, env)?.let { return it }
                applications += (b + mapOf("clientId" to id, "status" to "active", "_env" to env)).toMutableMap()
                // SSO-3792 — any creation of the name sweeps its slot (a slot never outlives the creation of its name).
                slots.removeIf { it["clientId"] == id }
                // SSO-3667 — a `client:` creator becomes the application's owner (rendered on the create response).
                creatorBecomesOwner("application:$id")
                // SSO-3113 — a CONFIDENTIAL client's one-shot secret rides ONLY on the create response (never on a later
                // GET). product-api's `clientType` defaults to confidential, so only an explicit `public` is secret-less.
                val response = applicationView(applications.last()).toMutableMap()
                // SSO-3689 — a secret is minted only for a secret-bearing method (product-api defaults to client_secret_basic).
                if (b["clientType"] != "public" && mintsSecret(b)) {
                    val secret = "minted-secret-$id"
                    mintedSecrets[id] = secret
                    response["clientSecret"] = secret
                }
                json(201, response)
            }
            seg[0] == "applications" && seg.size == 2 -> {
                val a = applications.firstOrNull { it["clientId"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, applicationView(a))
                    "PATCH" -> {
                        federatedBindingProblem(b, env, a["federatedTrust"])?.let { return it }
                        applicationSettingsProblem(b, env, a)?.let { return it }
                        a.putAll(b); json(200, applicationView(a))
                    }
                    "DELETE" -> { applications.remove(a); MockResponse().setResponseCode(204) }
                    else -> problem(405, "method")
                }
            }
            // ── SSO-3941 — RBAC + claims in the token ──
            seg[0] == "roles" || seg[0] == "permissions" || (seg[0] == "users" && seg.getOrNull(2) == "roles") -> rbac(method, seg, env, confirm, b, path)
            seg[0] == "applications" && seg.size == 3 && seg[2] == "token-claims" -> tokenClaimsRoute(method, seg[1], env, b)
            // ── users ──
            route == "/api/v1/users" && method == "GET" -> {
                val email = path.substringAfter("email=", "").substringBefore('&').let { java.net.URLDecoder.decode(it, "UTF-8") }
                json(200, mapOf("items" to users.filter { visible(it, env) && (email.isBlank() || it["email"] == email) }.map { public(it) }))
            }
            route == "/api/v1/users" && method == "POST" -> {
                val id = "u-${++seq}"
                users += (b.filterKeys { it != "password" } + mapOf("id" to id, "status" to "active", "_env" to env)).toMutableMap()
                json(201, public(users.last()))
            }
            seg[0] == "users" && seg.size == 2 -> {
                val u = users.firstOrNull { it["id"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, public(u))
                    "PATCH" -> { u.putAll(b); json(200, public(u)) }
                    "DELETE" -> { users.remove(u); json(200, emptyMap<String, Any>()) }
                    else -> problem(405, "method")
                }
            }
            // ── federation members ──
            route == "/api/v1/federation-members" && method == "GET" -> json(200, mapOf("data" to federationMembers.filter { visible(it, env) }.map { public(it) }))
            route == "/api/v1/federation-members" && method == "POST" -> {
                val id = "fm-${++seq}"
                federationMembers += (b.filterKeys { it != "clientSecret" } + mapOf("id" to id, "_env" to env)).toMutableMap()
                json(201, public(federationMembers.last()))
            }
            seg[0] == "federation-members" && seg.size == 2 -> {
                val m = federationMembers.firstOrNull { it["id"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, public(m))
                    "PATCH" -> { m.putAll(b.filterKeys { it != "clientSecret" }); json(200, public(m)) }
                    "DELETE" -> { federationMembers.remove(m); MockResponse().setResponseCode(204) }
                    else -> problem(405, "method")
                }
            }
            // ── email provider (singleton per env) ──
            route == "/api/v1/email-provider" && method == "GET" -> {
                val p = emailProviders[env]
                json(200, p?.plus(mapOf("configured" to true)) ?: mapOf("configured" to false, "providerType" to "platform", "enabled" to false))
            }
            route == "/api/v1/email-provider" && method == "PUT" -> {
                val p = emailProviders.getOrPut(env) { mutableMapOf("providerType" to "smtp", "configVersion" to 0) }
                p.putAll(b.filterKeys { it != "smtpPassword" }); p["hasPassword"] = b.containsKey("smtpPassword") || p["hasPassword"] == true
                p["configVersion"] = (p["configVersion"] as Int) + 1
                json(200, p)
            }
            route == "/api/v1/email-provider" && method == "DELETE" -> { emailProviders.remove(env); MockResponse().setResponseCode(204) }
            // ── SSO-4042 / SSO-4054 — email templates, per environment (the header picks the plane, as product-api forwards it) ──
            seg[0] == "login-experience" && seg.getOrNull(1) == "email-templates" && seg.size == 2 && method == "GET" -> emailTemplateList(env)
            seg[0] == "login-experience" && seg.getOrNull(1) == "email-templates" && seg.size == 3 -> emailTemplate(method, seg[2], query(path)["locale"], b, env)
            // ── SSO-4057 — tenant-level legal documents, per environment (the header picks the plane) ──
            seg[0] == "login-experience" && seg.getOrNull(1) == "legal-documents" && seg.size in 3..5 -> legalDocumentRoute(method, seg, b, env)
            // ── branding (singleton per env) ──
            // SSO-4041 — as identity's `LoginBrandingAdminService.upsert` behaves behind product-api's facade: the PUT REPLACES
            // the record (an omitted / null field clears the stored value, `cssVariables` as one map), an unknown key is DROPPED by
            // the lenient JSON binding (never a 400 — the typo class this fake used to hide), a malformed value is
            // `400 invalid_branding_field`, and `stored` renders EVERY field (null when unset; `cssVariables` `{}`).
            route == "/api/v1/login-experience/branding" && method == "GET" -> json(200, brandingView(env))
            route == "/api/v1/login-experience/branding" && method == "PUT" -> {
                brandingProblem(b)?.let { return it }
                val record = b.filterKeys { it in BRANDING_FIELDS }.filterValues { it != null && !(it is String && it.isBlank()) && !(it is Map<*, *> && it.isEmpty()) }
                if (record.isEmpty()) branding.remove(env) else branding[env] = record.toMutableMap()
                json(200, brandingView(env))
            }
            // ── login methods (singleton per env; SSO-3100 — product-api /api/v1/login-methods) ──
            route == "/api/v1/login-methods" && method == "GET" -> {
                val stored = loginMethods[env]
                json(200, mapOf("stored" to stored, "effective" to (stored ?: supportedLoginMethods), "supported" to supportedLoginMethods))
            }
            route == "/api/v1/login-methods" && method == "PUT" -> {
                val methods = (b["methods"] as? List<*>).orEmpty().map { it.toString() }
                if (methods.isEmpty() || methods.any { it !in supportedLoginMethods }) return problem(400, "invalid_login_method")
                loginMethods[env] = methods
                json(200, mapOf("stored" to methods, "effective" to methods, "supported" to supportedLoginMethods))
            }
            route == "/api/v1/login-methods" && method == "DELETE" -> { loginMethods.remove(env); MockResponse().setResponseCode(204) }
            // ── login flows ──
            route == "/api/v1/login-flows/active" && method == "GET" ->
                activeFlow[env]?.let { json(200, mapOf("version" to it, "status" to "active", "stages" to emptyList<Any>())) } ?: problem(404, "not_found")
            seg[0] == "login-flows" && seg.size == 4 && seg[1] == "templates" && seg[3] == "apply" ->
                json(200, mapOf("version" to (++seq), "status" to "draft", "stages" to emptyList<Any>()))
            route == "/api/v1/login-flows/activate" && method == "POST" -> {
                val v = (b["version"] as Number).toInt(); activeFlow[env] = v
                json(200, mapOf("version" to v, "status" to "active", "stages" to emptyList<Any>()))
            }
            // ── access grants (SSO-3113; the SSO-3112 /api/v1/access contract) ──
            route == "/api/v1/access/grants" && method == "GET" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                val q = query(path)
                val matching = grants.filter { g -> (q["object"] == null || g["object"] == q["object"]) && (q["subject"] == null || g["subject"] == q["subject"]) }
                json(200, mapOf("data" to matching, "pagination" to mapOf("total" to matching.size, "nextCursor" to null)))
            }
            route == "/api/v1/access/grants" && method == "POST" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                if (listOf("subject", "relation", "object").any { (b[it] as? String).isNullOrBlank() }) return problem(400, "invalid_grant_shape")
                // SSO-3119 — product-api resolves the SUBJECT in the workspace before it writes the tuple
                // (AccessGrantService.subjectBelongsToWorkspace) and answers the opaque 404 of ADR
                // 2026-09-15 §8 when it cannot. Modelling that is what makes the ordering regression
                // visible here: a grant naming a client the same file has not created yet MUST fail.
                // Only `client:` refs are checked — the fake carries no membership registry, so a
                // `member:` subject is taken on trust.
                val subjectRef = b["subject"].toString()
                val objectRef = b["object"].toString()
                if (objectRef.startsWith("trust:")) {
                    // oauthy PR #4151 — before S1 a grant naming `trust:` is the opaque 404 not_found (only mine / check say invalid_type).
                    if (!trustObjects) return problem(404, "not_found")
                    val trust = trusts.firstOrNull { "trust:${it["id"]}" == objectRef } ?: return problem(404, "not_found")
                    // I6 — no identity owns or manages the trust it signs in with.
                    if (b["relation"] in setOf("owner", "manager") && subjectRef == "client:${trust["clientId"]}") return problem(400, "trust_self_management")
                }
                if (subjectRef.startsWith("client:") && trusts.none { "client:${it["clientId"]}" == subjectRef } && applications.none { it["clientId"] == subjectRef.removePrefix("client:") }) {
                    return problem(404, "not_found")
                }
                val existing = grants.firstOrNull { it["subject"] == b["subject"] && it["relation"] == b["relation"] && it["object"] == b["object"] }
                if (existing != null) return json(200, existing)
                // SSO-3667 — one owner per ownable object: a DIFFERENT owner is 409 owner_already_set, never a silent replace.
                if (b["relation"] == "owner") {
                    if (b["object"].toString().substringBefore(':') !in ownableTypes) return problem(400, "invalid_relation")
                    if (ownerOf(b["object"].toString()) != null) return problem(409, "owner_already_set")
                }
                seedGrant(b["subject"].toString(), b["relation"].toString(), b["object"].toString())
                json(201, grants.last())
            }
            route == "/api/v1/access/grants" && method == "DELETE" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                grants.removeIf { it["subject"] == b["subject"] && it["relation"] == b["relation"] && it["object"] == b["object"] }
                MockResponse().setResponseCode(204)
            }
            route == "/api/v1/access/mine" && method == "GET" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                val q = query(path)
                // SSO-3659 — the caller's OWN reach, computed from the grants (relation defaults to manager, as product-api's does).
                val type = q["type"] ?: return problem(400, "invalid_type")
                if (type == "trust" && !trustObjects) return problem(400, "invalid_type")
                mineReads += "$type ${q["relation"] ?: "manager"}"
                json(200, mapOf("data" to reach(type, q["relation"] ?: "manager")))
            }
            // SSO-3673 — the forward check for the caller's OWN subject (product-api AccessController.check): grammar is
            // 400 (`owner` only on an ownable type), a foreign / unknown object is `allowed: false`, never an error.
            route == "/api/v1/access/check" && method == "POST" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                val ref = (b["object"] as? String)?.takeIf { it.contains(':') } ?: return problem(400, "invalid_object")
                val relation = (b["relation"] as? String) ?: return problem(400, "invalid_relation")
                if (relation !in setOf("manager", "viewer", "owner")) return problem(400, "invalid_relation")
                if (ref.substringBefore(':') == "trust" && !trustObjects) return problem(400, "invalid_type")
                if (relation == "owner" && ref.substringBefore(':') !in ownableTypes) return problem(400, "invalid_relation")
                checks += Check(ref, relation)
                val allowed = objectsOf(ref.substringBefore(':')).contains(ref) && holds(ref, relation)
                json(200, mapOf("allowed" to allowed, "resolvedVia" to if (allowed) resolvedVia(ref, relation) else null))
            }
            // ── application creation slots (SSO-3792; product-api SSO-3789) ──
            route.startsWith("/api/v1/access/application-slots") -> applicationSlots(method, route, b)
            // ── custom domain (SSO-3413 / SSO-3414) ──
            route.startsWith("/api/v1/custom-domain") -> customDomain(method, route, b)
            // ── workload-identity trusts (SSO-3689) ──
            route.startsWith("/api/v1/workload-identity/trusts") -> workloadIdentity(method, route, env, confirm, b, path)
            // ── receipt attestation (SSO-2878; the recipe interpreter's best-effort signed layer) ──
            route == "/api/v1/attestations" && method == "POST" ->
                json(200, mapOf("kid" to "receipt-attestation-fake-v1", "signature" to "sig", "canonicalPayload" to "e30", "attestedAt" to "2026-01-01T00:00:00Z"))
            else -> problem(404, "no_route:$method $route")
        }
    }
}
