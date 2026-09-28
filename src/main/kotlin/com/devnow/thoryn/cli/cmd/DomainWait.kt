package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.node.ObjectNode
import java.io.PrintStream
import java.time.Duration
import java.time.Instant

/**
 * SSO-3414 — one DNS record a custom domain needs, in the MACHINE-READABLE shape a pipeline feeds to
 * its DNS tooling. The field names — `type`, `name`, `value`, `ttl` — are a stable contract, pinned by
 * tests: `thoryn domain status --json` (under `dnsRecords`) and `thoryn provision plan --output json`
 * (under `changes[].customDomain.records`) both emit exactly this shape.
 *
 * `ttl` is product-api's recommendation (oathy SSO-3414, `300`); an older product-api that does not
 * send it gets the same [DEFAULT_TTL_SECONDS]. Thoryn verifies the record's VALUE, never its TTL.
 */
internal data class DnsRecord(val type: String, val name: String, val value: String, val ttl: Int) {
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
internal data class CustomDomainView(
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
 * SSO-3414 — the bounded **wait** a pipeline blocks on after publishing the DNS records: poll the custom
 * domain until it reaches [until] (`VERIFIED` also accepts `ACTIVE`), with a hard [timeout].
 *
 * With [drive] (`thoryn domain verify --wait`, `thoryn provision apply --wait`) a `PENDING` / `SUSPENDED`
 * domain is VERIFIED on every round (`POST /verify`, needs `tenant:domains.write`) instead of waiting for
 * the platform's 15-minute scheduled re-check; without it (`thoryn domain status --wait`) the loop only
 * reads. A failing DNS proof is not an error while there is time left — DNS takes a while to propagate —
 * but the last reason the status API reported is what a timeout fails with.
 *
 * A wait that can never succeed stops at once: no domain claimed (`NONE`), the claim expired, custom
 * domains not enabled for the workspace, or no access. Every `sleep` goes through [sleeper] and every
 * clock read through [clock], so tests run instantly.
 */
internal class DomainWaiter(
    private val client: ProductApiClient,
    private val until: String,
    private val timeout: Duration,
    private val interval: Duration,
    private val drive: Boolean,
    private val progress: PrintStream? = System.err,
    private val clock: () -> Instant = { Instant.now() },
    private val sleeper: (Duration) -> Unit = { Thread.sleep(it.toMillis()) },
) {
    sealed interface Outcome {
        val body: JsonNode?

        /** The domain reached the target state. */
        data class Reached(override val body: JsonNode) : Outcome

        /** The deadline passed; [reason] is the status API's last-check reason (null when it gave none). */
        data class TimedOut(override val body: JsonNode?, val state: String?, val reason: String?) : Outcome

        /** The wait can never succeed — [message] says why and what to do. */
        data class Stopped(override val body: JsonNode?, val message: String, val errorCode: String? = null) : Outcome
    }

    fun await(): Outcome {
        val deadline = clock().plus(timeout)
        var body: JsonNode? = null
        var reason: String? = null
        while (true) {
            body = try {
                client.getCustomDomain()
            } catch (ex: ProductApiException) {
                return stopFor(ex, body)
            }
            var view = CustomDomainView.of(body)
            if (reached(view.state)) return Outcome.Reached(body)
            if (view.state == CustomDomainView.NONE) {
                return Outcome.Stopped(body, "the workspace has no custom domain to wait for — claim one first (thoryn domain add <host>).")
            }
            reason = view.lastCheckReason ?: reason
            if (drive && view.state in CustomDomainView.VERIFIABLE) {
                try {
                    body = client.verifyCustomDomain()
                    view = CustomDomainView.of(body)
                    if (reached(view.state)) return Outcome.Reached(body)
                    reason = view.lastCheckReason ?: reason
                } catch (ex: ProductApiException) {
                    when (ex.errorCode) {
                        "verification_failed" -> reason = problemReason(ex) ?: reason
                        "dns_unavailable" -> Unit // inconclusive; nothing changed — try again next round
                        else -> return stopFor(ex, body)
                    }
                }
            }
            if (clock().plus(interval).isAfter(deadline)) {
                // Another round would cross the deadline: stop with the last reason the platform gave.
                return Outcome.TimedOut(body, view.state, reason)
            }
            progress?.println(
                "Waiting for ${view.domain ?: "the custom domain"} to be $until — now ${view.state}" +
                    (reason?.let { " (${DomainCommand.reasonText(it).removeSuffix(".")})" } ?: "") +
                    "; next check in ${human(interval)}.",
            )
            sleeper(interval)
        }
    }

    private fun reached(state: String): Boolean = when (until) {
        CustomDomainView.VERIFIED -> state == CustomDomainView.VERIFIED || state == CustomDomainView.ACTIVE
        else -> state == CustomDomainView.ACTIVE
    }

    private fun stopFor(ex: ProductApiException, body: JsonNode?): Outcome.Stopped = Outcome.Stopped(
        body,
        when (ex.errorCode) {
            "entitlement_required" -> NOT_ENTITLED
            "claim_expired" -> "the claim expired before it was verified — claim the domain again and publish the new TXT value."
            "custom_domain_not_found" -> NO_ACCESS
            else -> "the custom-domain API refused the request (${ex.message})."
        },
        ex.errorCode,
    )

    companion object {
        /** `--until` values. */
        val TARGETS: Set<String> = setOf(CustomDomainView.VERIFIED, CustomDomainView.ACTIVE)

        val DEFAULT_TIMEOUT: Duration = Duration.ofMinutes(15)
        val DEFAULT_INTERVAL: Duration = Duration.ofSeconds(20)

        /** The ONE operator step a workspace needs before any domain can be claimed (never a customer action). */
        const val NOT_ENTITLED: String =
            "custom domains are not enabled for this workspace. Enabling them is a Thoryn OPERATOR step, not something " +
                "this identity can do: a Thoryn operator (or, self-managed, your operator) signs in with a passkey " +
                "(`thoryn operator login`) and runs `thoryn operator custom-domain entitle <workspace>`. Re-run once " +
                "`thoryn domain status` shows `entitled: true`."

        /** The custom-domain surface answers 404 to an identity with no reach (never 403). */
        const val NO_ACCESS: String =
            "this identity cannot reach the workspace's custom domain. A workspace admin must grant it explicitly: " +
                "`thoryn access grant client:<client-id> manager custom_domain:<workspace-id>` (the workspace id is the " +
                "`tnt` claim `thoryn whoami` prints). The `tenant:domains.*` scopes alone are not enough."

        /** The `reason` extension of a `422 verification_failed` problem, when present. */
        fun problemReason(ex: ProductApiException): String? = try {
            ObjectMapper().readTree(ex.rawBody)?.text("reason")
        } catch (_: Exception) {
            null
        }

        /** `90s`, `15m`, `1h`, `1h30m` or plain seconds; null when unparseable or not positive. */
        fun parseDuration(raw: String?): Duration? {
            val s = raw?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
            s.toLongOrNull()?.let { return Duration.ofSeconds(it).takeIf { d -> !d.isZero && !d.isNegative } }
            val m = Regex("^(?:(\\d+)h)?(?:(\\d+)m)?(?:(\\d+)s)?$").matchEntire(s) ?: return null
            if (m.groupValues.drop(1).all { it.isEmpty() }) return null
            val (h, min, sec) = m.groupValues.drop(1).map { it.toLongOrNull() ?: 0L }
            return Duration.ofHours(h).plusMinutes(min).plusSeconds(sec).takeIf { !it.isZero }
        }

        fun human(d: Duration): String = when {
            d.toHours() >= 1 && d.toMinutesPart() == 0 && d.toSecondsPart() == 0 -> "${d.toHours()}h"
            d.toMinutes() >= 1 && d.toSecondsPart() == 0 -> "${d.toMinutes()}m"
            else -> "${d.seconds}s"
        }
    }
}

private fun JsonNode.text(field: String): String? =
    this[field]?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
