package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.provision.CustomDomainMessages
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.time.Duration
import java.time.Instant

/**
 * SSO-3662 — the custom-domain view types moved into the provisioning-engine library (the engine plans
 * and prints them); the CLI keeps their names through these aliases.
 */
internal typealias DnsRecord = com.devnow.thoryn.provision.DnsRecord
internal typealias CustomDomainView = com.devnow.thoryn.provision.CustomDomainView

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
        const val NOT_ENTITLED: String = CustomDomainMessages.NOT_ENTITLED

        /** The custom-domain surface answers 404 to an identity with no reach (never 403). */
        const val NO_ACCESS: String = CustomDomainMessages.NO_ACCESS

        /** The `reason` extension of a `422 verification_failed` problem, when present. */
        fun problemReason(ex: ProductApiException): String? = CustomDomainMessages.problemReason(ex)

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
