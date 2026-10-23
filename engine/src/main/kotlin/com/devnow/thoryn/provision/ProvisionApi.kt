package com.devnow.thoryn.provision

import tools.jackson.databind.JsonNode

/**
 * SSO-3662 — the port through which [ProvisionEngine] reaches product-api: exactly the customer-plane
 * calls the converge loop makes, nothing about HOW they are sent. The CLI's `ProductApiClient` (JDK
 * HttpClient, the signed-in session, DPoP) implements it directly; any other host of the engine adapts
 * its own HTTP client, presenting the identity that is to be the FGA subject. The engine obtains one
 * instance per environment plane through `ProvisionEngine(clients = { slug -> … })`: `null` ⇒ the
 * production plane, a slug ⇒ that sandbox (the CLI sends it as the `X-Thoryn-Environment` header).
 *
 * **Contract.** Every method answers the product-api body as a [JsonNode] (the engine reads fields by
 * name, so a newer product-api with extra fields is fine) and throws [ProductApiException] on a non-2xx
 * answer, carrying `httpStatus` and the RFC 9457 `errorCode` the engine branches on (404 ⇒ re-create /
 * no access; `insufficient_scope`; the custom-domain refusals). A `confirmSlug` is the `X-Thoryn-Confirm`
 * value product-api requires for a destructive action on the PRODUCTION plane (SSO-2413).
 * **Ownership reads (SSO-3659 / SSO-3673, scope `tenant:access.read`).** [checkAccess] is the gate's
 * per-OBJECT question — `POST /api/v1/access/check {object, relation}` for the CALLER's own subject
 * (product-api derives it from the token; nothing about the subject is sent), answered over the platform
 * store with the model's containment rules; a foreign or nonexistent object is `allowed: false`, never
 * an error. [listMyAccess] (`GET /api/v1/access/mine`, the per-TYPE reverse index) stays for `import`,
 * which LISTS what the identity may reach. The application read ([getApplication], [listApplications],
 * [createApplication]) renders the platform's `owner` relation as `owner: { subject } | null`
 * (SSO-3667); [ownerOf] reads it.
 *
 * The signatures are the CLI's `ProductApiClient` signatures at extraction time — adding a method here
 * is a breaking change for every implementation, so it is done deliberately.
 */
interface ProvisionApi {
    // ── Applications (`/api/v1/applications`) ──
    fun listApplications(): JsonNode
    fun getApplication(clientId: String): JsonNode
    fun createApplication(body: Map<String, Any?>): JsonNode
    fun updateApplication(clientId: String, body: Map<String, Any?>): JsonNode
    fun deleteApplication(clientId: String, confirmSlug: String? = null): Unit

    // ── Users (`/api/v1/users`) ──
    fun createUser(body: Map<String, Any?>): JsonNode
    fun listUsers(email: String? = null, status: String? = null, limit: Int? = null): JsonNode
    fun getUser(userId: String): JsonNode
    fun updateUser(userId: String, body: Map<String, Any?>): JsonNode
    fun deleteUser(userId: String, confirmSlug: String? = null): Unit

    // ── Environments (`/api/v1/environments`, production plane) ──
    fun listEnvironments(): JsonNode
    fun createEnvironment(body: Map<String, Any?>): JsonNode
    fun renameEnvironment(id: String, body: Map<String, Any?>): JsonNode
    fun deleteEnvironment(id: String, confirmSlug: String? = null): Unit

    // ── Email provider singleton (`/api/v1/email-provider`) ──
    fun getEmailProvider(): JsonNode
    fun putEmailProvider(body: Map<String, Any?>): JsonNode
    fun deleteEmailProvider(confirmSlug: String? = null): Unit

    // ── Custom domain singleton (`/api/v1/custom-domain`, production plane; SSO-3413) ──
    fun getCustomDomain(): JsonNode
    fun putCustomDomain(domain: String, acceptReSignIn: Boolean): JsonNode
    fun verifyCustomDomain(): JsonNode
    fun deleteCustomDomain(): Unit

    // ── Login theme / flow / methods singletons ──
    fun getLoginBranding(): JsonNode
    fun putLoginBranding(body: Map<String, Any?>): JsonNode
    fun getActiveLoginFlow(): JsonNode
    fun applyLoginFlowTemplate(templateId: String): JsonNode
    fun activateLoginFlow(version: Int): JsonNode
    fun getLoginMethods(): JsonNode
    fun putLoginMethods(methods: List<String>): JsonNode
    fun resetLoginMethods(): JsonNode

    // ── Federation members (`/api/v1/federation-members`) ──
    fun listFederationMembers(): JsonNode
    fun getFederationMember(memberId: String): JsonNode
    fun createFederationMember(body: Map<String, Any?>): JsonNode
    fun updateFederationMember(memberId: String, body: Map<String, Any?>): JsonNode
    fun deleteFederationMember(memberId: String, confirmSlug: String? = null): Unit

    // ── Workload identity trusts (`/api/v1/workload-identity/trusts`, environment-scoped; SSO-3689) ──
    // Scopes `tenant:workload-identity.read` (list / get) and `tenant:workload-identity.write` (create / delete /
    // set plan profile / set scopes); environment managers write, viewers read, anyone else is answered 404. There is NO
    // general update: the pins are immutable on the hub, so the engine never asks for one — the mutations are the additive
    // [setWorkloadIdentityTrustPlanProfile] (SSO-3702 / SSO-3701; SSO-3699 option B) and the in-place scope change
    // [setWorkloadIdentityTrustScopes] (SSO-3925). [createWorkloadIdentityTrust]
    // answers 201 with the trust's `clientId` (`wi_…`), `audience` and `tokenEndpoint`; a name already in use is `409
    // workload_identity_trust_name_taken`; a scope the caller does not hold is `403 scope_not_grantable`.
    fun listWorkloadIdentityTrusts(limit: Int? = null, cursor: String? = null): JsonNode
    fun getWorkloadIdentityTrust(id: String): JsonNode
    fun createWorkloadIdentityTrust(body: Map<String, Any?>): JsonNode
    fun deleteWorkloadIdentityTrust(id: String, confirmSlug: String? = null): Unit

    /**
     * SSO-3702 (product-api SSO-3701) — `POST /api/v1/workload-identity/trusts/{id}/plan-profile`
     * `{ environment, scopes? }`: give an existing `github_actions` trust its PLAN profile — the one additive
     * mutation that keeps the `wi_` client (no re-create, no `owner` move). Answers 200 with the trust; `409
     * plan_profile_already_set` when it has one (re-create the trust to change it); `400` with
     * `plan_environment_equals_apply`, `plan_scope_not_read_only`, `plan_scope_not_subset`,
     * `plan_profile_requires_environment`, `plan_scopes_empty`, `plan_profile_unsupported`,
     * `invalid_plan_environment`; `403 scope_not_grantable` for a plan scope the caller does not hold.
     */
    fun setWorkloadIdentityTrustPlanProfile(id: String, body: Map<String, Any?>): JsonNode

    /**
     * SSO-3925 (oauthy product-api) — `PUT /api/v1/workload-identity/trusts/{id}/scopes` `{ scopes?, planScopes? }`:
     * change a trust's apply scopes and/or its plan profile's scopes IN PLACE — the trust keeps its id, its `wi_`
     * client and every pin (no `connection.json` or owner moves). An omitted member keeps its set. Answers 200 with the
     * trust. NARROWING needs only `tenant:workload-identity.write` and `manager`; WIDENING (either set gains a scope) is
     * a person's elevated act: a machine identity is `403 elevated_action_requires_person`, a person without a passkey
     * sign-in from the last five minutes the RFC 9470 step-up `403` (`WWW-Authenticate` … `insufficient_user_authentication`).
     * `403 scope_not_grantable` for a scope the caller does not hold; `400 plan_profile_not_set`, `plan_scope_not_subset`,
     * `plan_scope_not_read_only`, `plan_scopes_empty`, `invalid_scope`.
     *
     * Defaulted so a host that predates in-place scope changes keeps compiling: the default answers what a product-api
     * from before SSO-3925 answers for the route — `404` with no trust error code.
     */
    fun setWorkloadIdentityTrustScopes(id: String, body: Map<String, Any?>): JsonNode =
        throw ProductApiException(404, "not_found", "this host does not change a trust's scopes in place", "")

    // ── Access grants, reach and the forward check (`/api/v1/access/grants`, `/mine`, `/check`; SSO-3112 / SSO-3659 / SSO-3673; workspace-level) ──
    fun listGrants(objectRef: String? = null, subjectRef: String? = null): JsonNode
    fun createGrant(subjectRef: String, relation: String, objectRef: String): JsonNode
    fun deleteGrant(subjectRef: String, relation: String, objectRef: String): Unit
    fun listMyAccess(type: String? = null, relation: String? = null): JsonNode

    /**
     * SSO-3673 — `POST /api/v1/access/check` `{ object, relation }`: does the CALLER hold [relation] on
     * [objectRef]? Answers [AccessCheck]; a non-2xx (a `400` on grammar, `403 insufficient_scope`) is a
     * [ProductApiException] the engine fails closed on.
     */
    fun checkAccess(objectRef: String, relation: String): AccessCheck

    /**
     * SSO-3792 (oauthy ADR 2026-10-17 §2, product-api SSO-3789) — `GET /api/v1/access/application-slots` (scope
     * `tenant:access.read`, which a plan profile holds): the application CREATION SLOTS the caller may see — a workspace
     * admin every slot, anyone else the slots it holds — as the ListEnvelope `{ data: [ {object, subject, environment,
     * createdAt, expiresAt, expired} ] }`. The engine reads it once per plan, only for a create it would otherwise refuse.
     *
     * Defaulted (unlike every other method) so a host that predates slots keeps compiling: the default answers what a
     * product-api from before SSO-3789 answers — `404` — which the engine reads as "no slots".
     */
    fun listApplicationSlots(): JsonNode =
        throw ProductApiException(404, "not_found", "this host does not read application creation slots", "")

    companion object {
        /**
         * SSO-3667 / SSO-3673 — the platform `owner` of a resource as its response renders it
         * (`owner: { subject: "client:<id>" }`), or null when the response carries none (nobody owns it,
         * or the kind does not render an owner yet). The subject reference is returned verbatim.
         */
        fun ownerOf(node: JsonNode?): String? =
            node?.get("owner")?.takeIf { it.isObject }?.get("subject")?.takeIf { it.isTextual }?.asString()?.takeIf { it.isNotBlank() }
    }
}

/**
 * SSO-3673 — the verdict of a platform forward check for the caller's own subject
 * (`POST /api/v1/access/check`): [allowed], and when allowed how it was satisfied ([resolvedVia] —
 * `direct`, `owner` or `inherited`; null when denied). Fail-closed by contract: an indeterminate check
 * is `allowed = false`.
 */
data class AccessCheck(val allowed: Boolean, val resolvedVia: String? = null)
