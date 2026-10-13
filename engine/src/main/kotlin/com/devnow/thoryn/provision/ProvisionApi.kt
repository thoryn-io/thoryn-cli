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
