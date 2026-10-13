package com.devnow.thoryn.provision

/**
 * SSO-3112 / SSO-3113 — the access-grant reference grammar product-api's `/api/v1/access` surface
 * accepts: `<type>:<id>` subjects and objects, the two relations, the scopes a session needs, and the
 * workspace admin userset the engine never revokes. Shared by the CLI's `thoryn access` command and the
 * engine's `grants:` converge (SSO-3662: moved here so the library owns the grammar it validates with).
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

    val RELATIONS: Set<String> = setOf("manager", "viewer")

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
