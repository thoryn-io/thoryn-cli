package com.devnow.thoryn.provision

import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.node.ObjectNode

/**
 * SSO-3414 — one DNS record a custom domain needs, in the MACHINE-READABLE shape a pipeline feeds to
 * its DNS tooling. The field names — `type`, `name`, `value`, `ttl` — are a stable contract, pinned by
 * tests: `thoryn domain status --json` (under `dnsRecords`) and `thoryn provision plan --output json`
 * (under `changes[].customDomain.records`) both emit exactly this shape.
 *
 * `ttl` is product-api's recommendation (oathy SSO-3414, `300`); an older product-api that does not
 * send it gets the same [DEFAULT_TTL_SECONDS]. Thoryn verifies the record's VALUE, never its TTL.
 */
data class DnsRecord(val type: String, val name: String, val value: String, val ttl: Int) {
    fun toStructured(): Map<String, Any> = linkedMapOf("type" to type, "name" to name, "value" to value, "ttl" to ttl)

    companion object {
        /** Mirrors product-api's `RECOMMENDED_DNS_TTL_SECONDS` for a server that predates the field. */
        const val DEFAULT_TTL_SECONDS: Int = 300

        fun of(node: JsonNode): DnsRecord? {
            val type = node.text("type") ?: return null
            val name = node.text("name") ?: return null
            val value = node.text("value") ?: return null
            val ttl = node["ttl"]?.takeIf { it.isNumber }?.asInt()?.takeIf { it > 0 } ?: DEFAULT_TTL_SECONDS
            return DnsRecord(type, name, value, ttl)
        }
    }
}

/**
 * SSO-3413 / SSO-3414 — the fields of product-api's `GET /api/v1/custom-domain` answer the CLI acts on,
 * parsed once. [issuer] is the issuer the workspace mints on RIGHT NOW (the platform issuer until the
 * domain is ACTIVE, then `https://<domain>`) — the value a pipeline exports for its applications'
 * configuration (a sandbox appends `/<environment>`).
 */
data class CustomDomainView(
    val domain: String?,
    val state: String,
    val entitled: Boolean,
    val issuer: String?,
    val customIssuer: String?,
    val cnameTarget: String?,
    val certificateState: String?,
    val records: List<DnsRecord>,
    val lastCheckResult: String?,
    val lastCheckReason: String?,
    val releaseAt: String?,
) {
    /** The structured view `provision plan --output json` carries under `changes[].customDomain`. */
    fun toStructured(): Map<String, Any?> = buildMap {
        put("host", domain)
        put("state", state)
        put("entitled", entitled)
        put("issuer", issuer)
        customIssuer?.let { put("customIssuer", it) }
        cnameTarget?.let { put("cnameTarget", it) }
        put("records", records.map { it.toStructured() })
        lastCheckReason?.let { put("lastCheckReason", it) }
        releaseAt?.let { put("releaseAt", it) }
    }

    companion object {
        const val NONE = "NONE"
        const val PENDING = "PENDING"
        const val VERIFIED = "VERIFIED"
        const val ACTIVE = "ACTIVE"
        const val SUSPENDED = "SUSPENDED"

        /** States a `POST /verify` can move forward. */
        val VERIFIABLE: Set<String> = setOf(PENDING, SUSPENDED)

        fun of(body: JsonNode): CustomDomainView {
            val last = body["lastVerification"]?.takeUnless { it.isNull }
            val suspension = body["suspension"]?.takeUnless { it.isNull }
            return CustomDomainView(
                domain = body.text("domain"),
                state = body.text("state") ?: NONE,
                entitled = body["entitled"]?.asBoolean() == true,
                issuer = body.text("issuer"),
                customIssuer = body.text("customIssuer"),
                cnameTarget = body.text("cnameTarget"),
                certificateState = body.text("certificateState"),
                records = body["dnsRecords"]?.takeIf { it.isArray }?.toList().orEmpty().mapNotNull { DnsRecord.of(it) },
                lastCheckResult = last?.text("result"),
                lastCheckReason = last?.text("reason") ?: suspension?.text("reason"),
                releaseAt = suspension?.text("releaseAt"),
            )
        }

        /**
         * [body] with every `dnsRecords` entry carrying the stable `{type, name, value, ttl}` shape — what
         * `thoryn domain … --json` prints, so a pipeline gets a `ttl` even from a product-api that predates it.
         */
        fun normalized(body: JsonNode): JsonNode {
            val copy = body.deepCopy()
            if (copy is ObjectNode && copy["dnsRecords"]?.isArray == true) {
                val records = MAPPER.createArrayNode()
                copy["dnsRecords"].toList().mapNotNull { DnsRecord.of(it) }.forEach { r ->
                    records.add(MAPPER.createObjectNode().put("type", r.type).put("name", r.name).put("value", r.value).put("ttl", r.ttl))
                }
                copy.set("dnsRecords", records)
            }
            return copy
        }

        private val MAPPER = ObjectMapper()
    }
}

/**
 * SSO-3413 / SSO-3414 — the custom-domain wording the engine prints or throws, shared with the CLI's
 * `thoryn domain` command so a pipeline reads the same sentence from `provision apply` and from
 * `domain verify` (SSO-3662: moved here with the engine).
 */
object CustomDomainMessages {
    /** The ONE operator step a workspace needs before any domain can be claimed (never a customer action). */
    const val NOT_ENTITLED: String =
        "custom domains are not enabled for this workspace. Enabling them is a Thoryn OPERATOR step, not something " +
            "this identity can do: a Thoryn operator (or, self-managed, your operator) signs in with a passkey " +
            "(`thoryn operator login`) and runs `thoryn operator custom-domain entitle <workspace>`. Re-run once " +
            "`thoryn domain status` shows `entitled: true`."

    /** The custom-domain surface answers 404 to an identity with no reach (never 403). */
    const val NO_ACCESS: String =
        "this identity cannot reach the workspace's custom domain. A workspace admin must grant it explicitly: " +
            "`thoryn access grant client:<client-id> manager custom_domain:<workspace-id>` (`thoryn whoami --output json` prints the workspace id as " +
            "`tenant`). The `tenant:domains.*` scopes alone are not enough."

    /** The `reason` extension of a `422 verification_failed` problem, when present. */
    fun problemReason(ex: ProductApiException): String? = try {
        ObjectMapper().readTree(ex.rawBody)?.text("reason")
    } catch (_: Exception) {
        null
    }

    fun reasonText(reason: String?): String = when (reason) {
        "txt_record_missing" -> "the TXT ownership record is missing or carries another value."
        "cname_missing" -> "the domain has no CNAME record."
        "cname_mismatch" -> "the CNAME points somewhere other than the workspace's platform host."
        null -> "no reason reported."
        else -> "$reason."
    }
}

private fun JsonNode.text(field: String): String? =
    this[field]?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
