package com.devnow.thoryn.provision

/**
 * SSO-3112 / SSO-3113 — the access-grant reference grammar product-api's `/api/v1/access` surface
 * accepts: `<type>:<id>` subjects and objects, the relations, the scopes a session needs, and the
 * workspace admin userset the engine never revokes. Shared by the CLI's `thoryn access` command and the
 * engine's `grants:` converge (SSO-3662: moved here so the library owns the grammar it validates with).
 *
 * SSO-3667 / SSO-3673 — [RELATION_OWNER] is what the ACCESS API grants (a workspace admin, on an
 * `application` / `environment`, at most one subject per object, implied into `manager`). It is
 * deliberately NOT in `ProvisionFile.GRANT_RELATIONS`: a provisioning file cannot claim ownership by
 * writing YAML (ADR 2026-10-13 platform-owner-relation-and-forward-check, open question 3 → decided).
 */
object AccessRefs {
    const val SCOPE_READ: String = "tenant:access.read"
    const val SCOPE_WRITE: String = "tenant:access.write"

    val SUBJECT_TYPES: Set<String> = setOf("member", "client")

    val OBJECT_TYPES: Set<String> = setOf(
        "workspace", "environment", "application", "user", "federation_member",
        "email_provider", "login_theme", "login_flow", "login_methods",
        // SSO-3434 — the workspace's custom-domain singleton (SSO-3413), `custom_domain:<tenantId>`.
        "custom_domain",
    )

    const val RELATION_MANAGER: String = "manager"
    const val RELATION_VIEWER: String = "viewer"
    /** SSO-3667 — one owning subject per ownable object; grantable by a workspace admin only. */
    const val RELATION_OWNER: String = "owner"

    /** The relations `thoryn access grant | revoke | mine` and `POST /api/v1/access/check` accept. */
    val RELATIONS: Set<String> = setOf(RELATION_MANAGER, RELATION_VIEWER, RELATION_OWNER)

    /** SSO-3667 — the object types the platform model defines `owner` on (`PlatformObjectTypes.OWNABLE`). */
    val OWNABLE_TYPES: Set<String> = setOf("application", "environment")

    val REF_PATTERN: Regex = Regex("^([a-z_]+):(\\S+)$")

    val ADMIN_USERSET_PATTERN: Regex = Regex("^workspace:\\S+#admin$")

    fun validateSubject(raw: String): String? {
        val m = REF_PATTERN.matchEntire(raw) ?: return "subject '$raw' must be <type>:<id> with type one of ${SUBJECT_TYPES.joinToString(", ")}"
        return if (m.groupValues[1] !in SUBJECT_TYPES) "subject type '${m.groupValues[1]}' must be one of ${SUBJECT_TYPES.joinToString(", ")}" else null
    }

    fun validateObject(raw: String): String? {
        val m = REF_PATTERN.matchEntire(raw) ?: return "object '$raw' must be <type>:<id> with type one of ${OBJECT_TYPES.joinToString(", ")}"
        return if (m.groupValues[1] !in OBJECT_TYPES) "object type '${m.groupValues[1]}' must be one of ${OBJECT_TYPES.joinToString(", ")}" else null
    }

    fun validateRelation(raw: String): String? =
        if (raw !in RELATIONS) "relation '$raw' must be one of ${RELATIONS.joinToString(", ")}" else null

    fun validate(subject: String, relation: String, objectRef: String): String? =
        validateSubject(subject) ?: validateRelation(relation) ?: validateObject(objectRef)
}
