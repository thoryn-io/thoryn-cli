package com.devnow.thoryn.cli.auth

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * SSO-3928 — what a person is told when the hub refuses to renew their sign-in session with
 * `invalid_grant`: that the session has ENDED, why, and when.
 *
 * ## The report
 *
 * A `thoryn login --workspace thoryn` session from 18:00 UTC failed the next morning on every command
 * with "Could not renew your sign-in session (Hub returned 400: invalid_grant)". Nothing was broken:
 * the `cli` client's session ends after 8 hours without use (and 7 days after sign-in at the latest),
 * and the person had not run a command overnight. But the line said neither that the session had
 * ended nor why, so it read like a fault — and it took the hub's logs to tell an idle expiry apart
 * from a replay revocation or a revoked device.
 *
 * ## What the line now carries
 *
 *  - **Why**, from the hub's machine-readable `error_description` (SSO-3928, hub half):
 *    [REFRESH_TOKEN_EXPIRED] (unused past the idle window) or [SESSION_LIFETIME_EXCEEDED] (the
 *    session's maximum lifetime, or the workspace's cap). Matched EXACTLY, like
 *    [RevokedDevice.ERROR_DESCRIPTION] — these are wire contracts, not prose. Anything else, including
 *    a hub that predates them, is reported as a plain refusal.
 *  - **When**, from the session's own tokens, never from a policy hard-coded here: the sign-in time
 *    (`auth_time` of the ID token, else of the access token) and the last renewal (`iat` of the
 *    stored access token, which every renewal replaces). The limits themselves are the hub's to set
 *    and the README's to document — a CLI that printed "8 hours" would be wrong the day they change.
 *
 * The claims are read for display only ([JwtClaims] does no verification), and a claim that is
 * missing or unreadable is simply left out of the sentence.
 */
internal object SessionEnd {

    /** The hub's `error_description` for a refresh token past its own expiry — the idle window. */
    const val REFRESH_TOKEN_EXPIRED: String = "refresh_token_expired"

    /** The hub's `error_description` for a session past its absolute lifetime or the workspace cap. */
    const val SESSION_LIFETIME_EXCEEDED: String = "session_lifetime_exceeded"

    /** Test seam — "now", for the "N h ago" part of the line. */
    internal var clock: Clock = Clock.systemUTC()

    private val timestamp: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC)

    /**
     * The one line printed when a renewal is refused with `invalid_grant` for a reason other than a
     * revoked device or a retired issuer (those have their own guidance).
     *
     * @param errorDescription the hub's `error_description`, or null when it sent none
     * @param session the stored session whose renewal was refused
     * @param reLoginCommand the exact command that signs this session in again
     */
    fun guidance(errorDescription: String?, session: Tokens, reLoginCommand: String): String {
        val now = clock.instant()
        val signedIn = signedInAt(session)
        val renewed = lastRenewedAt(session)
        val why = when (errorDescription?.trim()) {
            REFRESH_TOKEN_EXPIRED ->
                "it was not used within the hub's idle window" + facts(listOf("last renewed" to renewed), now)
            SESSION_LIFETIME_EXCEEDED ->
                "it reached its maximum lifetime" + facts(listOf("signed in" to signedIn), now)
            else ->
                "the hub refused to renew it (invalid_grant)" +
                    facts(listOf("signed in" to signedIn, "last renewed" to renewed), now)
        }
        return "Your sign-in session has ended: $why. Run `$reLoginCommand` to sign in again."
    }

    /** When this session signed in: `auth_time` of the ID token, else of the access token. */
    internal fun signedInAt(session: Tokens): Instant? =
        epochClaim(session.idToken, "auth_time") ?: epochClaim(session.accessToken, "auth_time")

    /** When this session was last renewed: `iat` of the stored access token (each renewal replaces it). */
    internal fun lastRenewedAt(session: Tokens): Instant? = epochClaim(session.accessToken, "iat")

    /** " (signed in 2026-10-22 18:00 UTC, 13 h 19 min ago; last renewed …)", or "" when nothing is known. */
    private fun facts(items: List<Pair<String, Instant?>>, now: Instant): String {
        val known = items.mapNotNull { (label, at) -> at?.let { "$label ${timestamp.format(it)}, ${ago(it, now)}" } }
        return if (known.isEmpty()) "" else known.joinToString("; ", prefix = " (", postfix = ")")
    }

    /** "12 h 48 min ago", "3 d 2 h ago", "25 min ago", "less than a minute ago". */
    internal fun ago(at: Instant, now: Instant): String {
        val elapsed = Duration.between(at, now).let { if (it.isNegative) Duration.ZERO else it }
        val days = elapsed.toDays()
        val hours = elapsed.toHours()
        val minutes = elapsed.toMinutesPart()
        return when {
            elapsed < Duration.ofMinutes(1) -> "less than a minute ago"
            hours < 1 -> "$minutes min ago"
            hours < 48 -> "$hours h $minutes min ago"
            else -> "$days d ${elapsed.toHoursPart()} h ago"
        }
    }

    private fun epochClaim(token: String?, claim: String): Instant? =
        JwtClaims.of(token)[claim]
            ?.takeIf { it.isNumber }
            ?.asLong()
            ?.takeIf { it > 0 }
            ?.let { Instant.ofEpochSecond(it) }
}
