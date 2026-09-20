package com.devnow.thoryn.cli.output

import tools.jackson.databind.JsonNode
import java.math.BigDecimal
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException

/**
 * SSO-3275 — how the CLI prints a moment in time in a table column.
 *
 * `thoryn devices list` shipped (SSO-3271) printing `LAST SEEN 1789848418`: the hub declares
 * `DeviceView.lastSeenAt` as an `Instant`, and whatever a given hub's Jackson does with that — an
 * ISO-8601 string, epoch seconds, epoch millis, or seconds-with-nanos as a decimal — the CLI was
 * calling `asString()` on the node and printing whatever came back. An epoch is not an answer to
 * "when was this machine last seen": nobody reads it, and the column it sits in is the one a
 * person scans to decide whether a device is theirs.
 *
 * So the wire shape is decided HERE rather than assumed, and all four shapes are accepted. The
 * rendering is the instant **plus its age** — `2026-09-19T09:41:00Z (3m ago)` — because the
 * absolute time is what you compare against an audit log and the age is what you actually read.
 *
 * Two deliberate properties:
 *
 *  - **Unparseable input is passed through verbatim, never dropped and never guessed at.** A hub
 *    that sends something this does not recognise still shows the user its own value; inventing
 *    "never" or blanking the cell would hide a real answer.
 *  - **Only the TABLE rendering changes.** `--output json|yaml` still prints the hub's body as it
 *    arrived, so a script keeps parsing exactly what the hub sent (the SSO-3082 rule: the CLI does
 *    not reshape a backend payload behind a script's back).
 */
object Timestamps {

    /**
     * Epoch values at or above this are milliseconds, below it seconds.
     *
     * 1e11 seconds is the year 5138; 1e11 millis is 1973. Any timestamp a running system produces
     * falls on the unambiguous side of that line.
     */
    private const val MILLIS_THRESHOLD: Long = 100_000_000_000L

    /**
     * The table cell for a time-valued field: `2026-09-19T09:41:00Z (3m ago)`.
     *
     * Returns null when the field is absent, JSON `null` or empty — `node["x"]` answers a `NullNode`
     * for an explicit `null`, which is NOT Kotlin's null (the SSO-3228 lesson). Callers render that
     * as `-`, or as whatever "we were not told" means in their column.
     */
    fun render(node: JsonNode?, now: Instant = Instant.now()): String? {
        val present = node?.takeIf { !it.isNull } ?: return null
        val parsed = instantOf(present)
            ?: return present.asString().takeIf { it.isNotBlank() } // unrecognised: show it verbatim
        return "${parsed.truncatedToSeconds()} (${age(parsed, now)})"
    }

    /** The same field as an [Instant], or null when it is absent or not a time the CLI recognises. */
    fun instantOf(node: JsonNode?): Instant? {
        val present = node?.takeIf { !it.isNull } ?: return null
        return when {
            present.isNumber -> fromEpoch(present.decimalValue())
            present.isTextual -> fromText(present.asString())
            else -> null
        }
    }

    /**
     * How long ago [at] was, as a person would say it: `3m ago`, `2h 15m ago`, `9d ago`.
     *
     * A time in the future reads `in 3m` rather than a negative age — clock skew between a laptop
     * and the hub is ordinary, and "-3m ago" would look like a bug in the CLI instead.
     */
    fun age(at: Instant, now: Instant = Instant.now()): String {
        val seconds = now.epochSecond - at.epochSecond
        val magnitude = magnitude(Math.abs(seconds))
        return if (seconds < 0) "in $magnitude" else "$magnitude ago"
    }

    private fun magnitude(seconds: Long): String {
        val days = seconds / 86_400
        val hours = (seconds % 86_400) / 3_600
        val minutes = (seconds % 3_600) / 60
        return when {
            days > 0 -> "${days}d"
            hours > 0 -> "${hours}h ${minutes}m"
            minutes > 0 -> "${minutes}m"
            else -> "${seconds}s"
        }
    }

    /**
     * An epoch number: seconds, seconds-with-nanos (`1789848418.123456789`, what Jackson writes
     * with `WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS`), or milliseconds.
     */
    private fun fromEpoch(value: BigDecimal): Instant? = try {
        val whole = value.toBigInteger().toLong()
        if (Math.abs(whole) >= MILLIS_THRESHOLD) {
            Instant.ofEpochMilli(whole)
        } else {
            val nanos = value.subtract(BigDecimal(value.toBigInteger()))
                .movePointRight(9)
                .toLong()
            Instant.ofEpochSecond(whole, nanos)
        }
    } catch (_: ArithmeticException) {
        null
    } catch (_: java.time.DateTimeException) {
        null
    }

    /** An ISO-8601 instant, an offset date-time, or an epoch that arrived quoted as a string. */
    private fun fromText(raw: String): Instant? {
        val text = raw.trim()
        if (text.isEmpty()) return null
        return try {
            Instant.parse(text)
        } catch (_: DateTimeParseException) {
            try {
                OffsetDateTime.parse(text).toInstant()
            } catch (_: DateTimeParseException) {
                text.toBigDecimalOrNull()?.let { fromEpoch(it) }
            }
        }
    }

    /** `2026-09-19T09:41:00Z` — seconds precision, so a nanosecond tail does not widen the column. */
    private fun Instant.truncatedToSeconds(): String =
        truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()
}
