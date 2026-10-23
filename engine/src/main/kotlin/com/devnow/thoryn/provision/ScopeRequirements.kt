package com.devnow.thoryn.provision

/**
 * SSO-3926 — the `tenant:` scopes a provisioning file needs, derived from what it declares, BEFORE any call is made.
 *
 * Until this existed the only way to learn that a file declaring a `workloadIdentityTrust` needs
 * `tenant:workload-identity.read` to be PLANNED was a `403 access_denied` in the middle of the plan (thoryn-cicd run
 * 39917407017): the repository trust's plan profile lacked it. [of] states every scope up front, with the resource that
 * needs it and why, split into the two profiles a repository identity has:
 *
 *  - [Phase.PLAN] — what `provision plan` reads: the live state of every declared resource, the ownership check, the grants
 *    of a resource with a `grants:` block, the trusts a binding or a `workloadPull` sink names. A trust's PLAN profile
 *    (the read-only scopes a job in its plan GitHub environment is minted) must carry all of them.
 *  - [Phase.APPLY] — what `provision apply` writes on top of the plan: each kind's write scope, `tenant:access.write` for a
 *    `grants:` block and for a `workloadPull` sink's `manager` grant, and the hub's scope ceiling for a declared trust (an
 *    identity grants a trust only scopes it holds itself). The trust's APPLY profile — its scopes, which `connection.json`
 *    `auth.scopes` lists — must carry these AND the plan scopes, because `apply` plans first.
 *
 * **The authority is product-api, not a guess.** Each scope below is the `@PreAuthorize` gate of the endpoint the engine
 * calls through [ProvisionApi] (oauthy `servers/product-api`, read 2026-10-23):
 *
 * | kind | read (`GET`) | write (`POST` / `PUT` / `PATCH` / `DELETE`) | controller |
 * |---|---|---|---|
 * | `environment` | `tenant:environments.read` | `tenant:environments.write` | `EnvironmentController` |
 * | `application` | `tenant:applications.read` | `tenant:applications.write` (either also as the deprecated `tenant:clients.*` alias) | `ApplicationsController` |
 * | `user` | `tenant:users.read` | `tenant:users.write` | `UsersController` |
 * | `federationMember` | `tenant:federation.read` | `tenant:federation.write` | `FederationMembersController` |
 * | `emailProvider` | `tenant:email.read` | `tenant:email.write` | `EmailProviderController` |
 * | `loginTheme` | `tenant:idp.read` | `tenant:idp.write` | `LoginExperienceController` (`/branding`) |
 * | `loginFlow` | `tenant:idp.read` | `tenant:idp.write` | `LoginFlowController` |
 * | `loginMethods` | `tenant:idp.read` | `tenant:idp.write` | `LoginMethodPolicyController` |
 * | `customDomain` | `tenant:domains.read` | `tenant:domains.write` | `CustomDomainController` |
 * | `workloadIdentityTrust` | `tenant:workload-identity.read` | `tenant:workload-identity.write` (create, delete, plan profile) | `WorkloadIdentityTrustController` |
 * | access (`/access/check`, `/mine`, `/grants` GET, `/application-slots` GET) | `tenant:access.read` | `tenant:access.write` (`/grants` POST / DELETE) | `AccessController`, `ApplicationSlotController` |
 *
 * A [ScopeNeed] marked [ScopeNeed.conditional] is asked for only on some plans (resolving a sandbox's id is needed for a
 * create in it, or when the identity's reach on an existing object is indirect): a static check ([of], `provision
 * workflow check`) holds a file to it — the file must be plannable whatever is live — while the run-time preflight before a
 * plan does not block on it (the API's own `403`, mapped by [MissingScopeException], still names it if it is hit).
 */
object ScopeRequirements {

    /** Which of a repository identity's two profiles needs the scope. */
    enum class Phase(val label: String) {
        /** `provision plan` — reads only; a trust's plan profile must carry it. */
        PLAN("plan"),

        /** `provision apply` — writes; the trust's scopes (its apply profile) and `connection.json` `auth.scopes` must carry it. */
        APPLY("apply"),
    }

    /** One scope one declared resource needs: [resource] is its `kind/name` key (null for the file as a whole), [why] the operation. */
    data class ScopeNeed(
        val scope: String,
        val phase: Phase,
        val resource: String?,
        val why: String,
        val conditional: Boolean = false,
    ) {
        /** `kind/name (why)` — the display form. */
        val label: String get() = (resource?.let { "$it ($why)" } ?: why)
    }

    const val SCOPE_ENVIRONMENTS_READ = "tenant:environments.read"
    const val SCOPE_WORKLOAD_IDENTITY_READ = "tenant:workload-identity.read"
    const val SCOPE_WORKLOAD_IDENTITY_WRITE = "tenant:workload-identity.write"

    /** The scope area each kind's endpoint is gated on (`tenant:<area>.read` / `.write`) — the table above. */
    val AREAS: Map<String, String> = mapOf(
        ProvisionFile.KIND_ENVIRONMENT to "environments",
        ProvisionFile.KIND_APPLICATION to "applications",
        ProvisionFile.KIND_USER to "users",
        ProvisionFile.KIND_FEDERATION_MEMBER to "federation",
        ProvisionFile.KIND_EMAIL_PROVIDER to "email",
        ProvisionFile.KIND_LOGIN_THEME to "idp",
        ProvisionFile.KIND_LOGIN_FLOW to "idp",
        ProvisionFile.KIND_LOGIN_METHODS to "idp",
        ProvisionFile.KIND_CUSTOM_DOMAIN to "domains",
        ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST to "workload-identity",
    )

    /**
     * Deprecated alias AREAS product-api still accepts in place of the named one (`ApplicationsController`:
     * `hasAnyAuthority('SCOPE_tenant:applications.read','SCOPE_tenant:clients.read')`, and the same for write). A token
     * holding the alias is NOT missing the scope. Kept as areas, not scope literals: the CLI never REQUESTS an alias
     * (the cli client's registered scopes are exactly the scopes its sources name — `CiProvisionFileConformanceTest`).
     */
    val AREA_ALIASES: Map<String, String> = mapOf("applications" to "clients")

    /** The deprecated alias product-api accepts for [scope] (`tenant:<alias-area>.<verb>`), or null. */
    fun aliasOf(scope: String): String? {
        val area = scope.removePrefix("tenant:").substringBefore('.', "")
        val verb = scope.substringAfter('.', "")
        return AREA_ALIASES[area]?.takeIf { scope.startsWith("tenant:") && verb.isNotEmpty() }?.let { "tenant:$it.$verb" }
    }

    /** The scope product-api requires to READ a [kind] (null for a kind this table does not know). */
    fun readScope(kind: String): String? = AREAS[kind]?.let { "tenant:$it.read" }

    /** The scope product-api requires to WRITE a [kind] (create, update, remove). */
    fun writeScope(kind: String): String? = AREAS[kind]?.let { "tenant:$it.write" }

    /** Whether [held] satisfies [scope] — the scope itself, or the deprecated alias product-api accepts for it. */
    fun holds(held: Set<String>, scope: String): Boolean = scope in held || aliasOf(scope)?.let { it in held } == true

    /** The needs among [needs] that [held] does not satisfy, in their order. */
    fun missing(needs: List<ScopeNeed>, held: Set<String>): List<ScopeNeed> = needs.filterNot { holds(held, it.scope) }

    /** [needs] grouped by scope, scopes in first-seen order — one line per scope in a report. */
    fun byScope(needs: List<ScopeNeed>): Map<String, List<ScopeNeed>> = needs.groupBy { it.scope }

    /**
     * Every scope [file] needs, per [Phase], derived from its resource kinds, `grants:` blocks, bindings and secret sinks.
     * [prune] adds what `--prune` reads (the identity's owned objects). The plan needs are repeated in the apply set's
     * coverage by the callers (an apply plans first); this list states each need once, under the phase that introduces it.
     */
    fun of(file: ProvisionFile, prune: Boolean = false): List<ScopeNeed> {
        val needs = mutableListOf<ScopeNeed>()
        fun add(scope: String?, phase: Phase, r: ProvisionResource?, why: String, conditional: Boolean = false) {
            scope ?: return
            needs += ScopeNeed(scope, phase, r?.key, why, conditional)
        }
        file.resources.forEach { r ->
            add(readScope(r.kind), Phase.PLAN, r, "read its live state")
            add(AccessRefs.SCOPE_READ, Phase.PLAN, r, "the ownership check, POST /api/v1/access/check")
            if (r.kind != ProvisionFile.KIND_ENVIRONMENT && r.kind !in ProvisionFile.WORKSPACE_KINDS && !ProvisionFile.isProductionPlane(r.environment)) {
                add(SCOPE_ENVIRONMENTS_READ, Phase.PLAN, r, "resolve environment '${r.environment}' to its id for the ownership check", conditional = true)
            }
            if (r.grants != null) add(AccessRefs.SCOPE_READ, Phase.PLAN, r, "list the grants its grants: block converges")
            val federatedTrust = r.spec[ProvisionFile.SPEC_FEDERATED_TRUST]?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            if (r.kind == ProvisionFile.KIND_APPLICATION && federatedTrust != null) {
                add(SCOPE_WORKLOAD_IDENTITY_READ, Phase.PLAN, r, "resolve spec.federatedTrust '$federatedTrust' by name")
            }
            val pull = r.secretSink?.takeIf { it.runtimePull }
            if (pull != null) {
                add(SCOPE_WORKLOAD_IDENTITY_READ, Phase.PLAN, r, "resolve secretSink.trust '${pull.trust}' by name")
                add(AccessRefs.SCOPE_READ, Phase.PLAN, r, "list the grants the workloadPull sink converges")
            }
            if (r.readOnly) return@forEach
            add(writeScope(r.kind), Phase.APPLY, r, "create, update or remove it")
            if (r.grants != null) add(AccessRefs.SCOPE_WRITE, Phase.APPLY, r, "converge its grants: block")
            if (pull != null) add(AccessRefs.SCOPE_WRITE, Phase.APPLY, r, "grant the workload client of trust '${pull.trust}' manager on it (secretSink workloadPull)")
            if (r.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST) {
                trustScopes(r).forEach { s ->
                    add(s, Phase.APPLY, r, "the hub's scope ceiling: only an identity holding $s may create a trust carrying it (scope_not_grantable)")
                }
            }
        }
        if (prune) add(AccessRefs.SCOPE_READ, Phase.PLAN, null, "--prune lists what this identity owns, GET /api/v1/access/mine")
        return needs
    }

    /**
     * The APPLY needs of a computed [plan]: only the writes it will actually make — a `NOOP` row writes nothing — so the
     * run-time preflight before `apply` never blocks a converged file on a write scope it does not use. (A trust's scope
     * ceiling stays the engine's own plan verdict, `scope_not_grantable`.)
     */
    fun forChanges(plan: ProvisionPlan): List<ScopeNeed> {
        val needs = mutableListOf<ScopeNeed>()
        plan.changes.forEach { c ->
            if (c.readOnly) return@forEach
            val write = when (c.action) {
                ChangeAction.CREATE -> "create it"
                ChangeAction.UPDATE -> "update it"
                ChangeAction.REMOVE -> "remove it"
                else -> null
            }
            if (write != null) writeScope(c.kind)?.let { needs += ScopeNeed(it, Phase.APPLY, c.key, write) }
            if (c.hasGrantChanges) needs += ScopeNeed(AccessRefs.SCOPE_WRITE, Phase.APPLY, c.key, "converge ${c.grantAdds.size + c.grantRemoves.size} grant change(s)")
        }
        return needs
    }

    /** The `tenant:` scopes a declared trust carries (`spec.scopes`) — what the applying identity must itself hold to create it. */
    private fun trustScopes(r: ProvisionResource): List<String> =
        (r.spec[ProvisionFile.TRUST_SCOPES] as? List<*>).orEmpty().map { it.toString().trim() }.filter { it.startsWith("tenant:") }.distinct()
}

/**
 * SSO-3926 — product-api refused a call the engine made with `403` because the token does not carry the [scope] the
 * endpoint is gated on (`access_denied` "The token does not grant the scope required for this operation", or
 * `insufficient_scope`). Thrown instead of the generic "could not read live state (HTTP 403 …)" so a host can say WHICH
 * scope and — knowing its own session — WHICH profile to add it to (the CLI: the trust's plan profile, its scopes and
 * `connection.json`, or `thoryn login --scope`). [resource] is the `kind/name` the call was for (null for the ownership
 * reads, which are per identity); [phase] whether a plan or only an apply needs it.
 */
class MissingScopeException(
    val scope: String,
    val phase: ScopeRequirements.Phase,
    val resource: String?,
    val operation: String,
    val apiMessage: String?,
) : ProvisionException(
    "${resource?.let { "$it: " } ?: ""}could not $operation — the token does not carry $scope, the scope product-api requires for it" +
        (apiMessage?.let { " ($it)" } ?: "") + ". Nothing more was ${if (phase == ScopeRequirements.Phase.PLAN) "read or " else ""}written. " +
        "Sign in with it (`thoryn login --scope $scope`, or grant the CI identity that scope" +
        (if (phase == ScopeRequirements.Phase.PLAN) " — for a workload identity trust, in its plan profile too" else "") + ") and re-run.",
) {
    companion object {
        /**
         * The codes of a scope-gate refusal: Spring Security's `@PreAuthorize` denial as product-api's problem handler renders
         * it (`access_denied`, "The token does not grant the scope required for this operation") and RFC 6750 §3.1's
         * `insufficient_scope`. A 403 with any other code is a refusal of its own (`scope_not_grantable`,
         * `token_exchange_not_grantable`, …) and keeps its own rendering.
         */
        val SCOPE_ERROR_CODES: Set<String> = setOf("access_denied", "insufficient_scope")

        /** The refusal [ex] as a missing [scope] when it is a scope `403` (never a step-up challenge); null otherwise. */
        fun of(ex: ProductApiException, scope: String?, phase: ScopeRequirements.Phase, resource: String?, operation: String): MissingScopeException? =
            if (scope != null && ex.httpStatus == 403 && !ex.isStepUpRequired && (ex.errorCode == null || ex.errorCode in SCOPE_ERROR_CODES)) {
                MissingScopeException(scope, phase, resource, operation, ex.message)
            } else {
                null
            }
    }
}
