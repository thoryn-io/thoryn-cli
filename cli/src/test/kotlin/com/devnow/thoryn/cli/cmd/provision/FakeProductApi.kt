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
     * refusing response, or null to proceed. A slot never includes turning token exchange on (`403`, slot kept).
     */
    private fun applicationCreateGate(id: String, explicit: Boolean, env: String?, b: Map<String, Any?>): MockResponse? {
        if (releaseSlotsBeforeCreate) slots.clear()
        if (holds(planeRef(env), "manager")) return null
        val slot = slots.firstOrNull { explicit && it["clientId"] == id && it["subject"] == caller && it["_env"] == env && it["expired"] != true }
            ?: return problem(404, "not_found")
        if (b["allowTokenExchange"] == true) return problem(403, "token_exchange_not_grantable")
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
        return null
    }

    /** SSO-3766 / SSO-3767 / SSO-3770 — product-api renders every setting on every application response, defaults included. */
    private fun applicationView(a: Map<String, Any?>): Map<String, Any?> =
        mapOf<String, Any?>(
            "allowTokenExchange" to false, "allowedAuthorizationDetailTypes" to emptyList<String>(),
            "refreshTokenSlidingWindow" to false, "refreshTokenAbsoluteMaxTtlSeconds" to 7_776_000L,
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
    private val PLANE_SCOPED_ROUTES = setOf("applications", "users", "federation-members", "email-provider", "login-experience", "login-methods", "login-flows")

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
            // ── branding (singleton per env) ──
            route == "/api/v1/login-experience/branding" && method == "GET" -> {
                val stored = branding[env] ?: emptyMap()
                json(200, mapOf("stored" to stored, "effective" to (mapOf("theme" to "light", "primaryColor" to "#000000") + stored)))
            }
            route == "/api/v1/login-experience/branding" && method == "PUT" -> {
                val stored = branding.getOrPut(env) { mutableMapOf() }; stored.putAll(b)
                json(200, mapOf("stored" to stored, "effective" to (mapOf("theme" to "light", "primaryColor" to "#000000") + stored)))
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
