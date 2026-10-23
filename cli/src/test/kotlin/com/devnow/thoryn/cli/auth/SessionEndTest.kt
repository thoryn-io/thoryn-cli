package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * SSO-3928 — the line printed when the hub ends a sign-in session names WHY (from the hub's
 * machine-readable `error_description`) and WHEN (from the session's own tokens).
 *
 * The reported session: signed in 2026-10-22 18:00 UTC, last renewed 18:31, refused at 07:19 the next
 * morning — the `cli` client's 8 h idle window had passed overnight.
 */
class SessionEndTest {

    private val now = Instant.parse("2026-10-23T07:19:00Z")
    private val signedIn = Instant.parse("2026-10-22T18:00:00Z")
    private val renewed = Instant.parse("2026-10-22T18:31:00Z")
    private val originalClock = SessionEnd.clock

    @BeforeEach
    fun fixClock() {
        SessionEnd.clock = Clock.fixed(now, ZoneOffset.UTC)
    }

    @AfterEach
    fun restoreClock() {
        SessionEnd.clock = originalClock
    }

    private val reLogin = "thoryn login --workspace thoryn"

    private fun session() = Tokens(
        accessToken = jwt("""{"iat":${renewed.epochSecond},"auth_time":${signedIn.epochSecond},"exp":${renewed.epochSecond + 900}}"""),
        idToken = jwt("""{"auth_time":${signedIn.epochSecond}}"""),
        refreshToken = "RT",
        workspace = "thoryn",
    )

    @Test
    fun `an idle expiry says the session went unused and when it was last renewed`() {
        val line = SessionEnd.guidance("refresh_token_expired", session(), reLogin)

        assertThat(line).isEqualTo(
            "Your sign-in session has ended: it was not used within the hub's idle window " +
                "(last renewed 2026-10-22 18:31 UTC, 12 h 48 min ago). " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
    }

    @Test
    fun `a lifetime end says the session reached its maximum lifetime and when it signed in`() {
        val line = SessionEnd.guidance("session_lifetime_exceeded", session(), reLogin)

        assertThat(line).isEqualTo(
            "Your sign-in session has ended: it reached its maximum lifetime " +
                "(signed in 2026-10-22 18:00 UTC, 13 h 19 min ago). " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
    }

    @Test
    fun `a refusal without a known reason states the refusal and both times`() {
        // A hub that predates SSO-3928 sends a bare invalid_grant: the CLI cannot say why, but it can
        // still say when — which, next to the documented lifetimes, is usually enough.
        val line = SessionEnd.guidance(null, session(), reLogin)

        assertThat(line).isEqualTo(
            "Your sign-in session has ended: the hub refused to renew it (invalid_grant) " +
                "(signed in 2026-10-22 18:00 UTC, 13 h 19 min ago; last renewed 2026-10-22 18:31 UTC, 12 h 48 min ago). " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
    }

    @Test
    fun `an unrecognised description is not mistaken for a known reason`() {
        // Exact match only — a description that merely contains the token is not that reason.
        val line = SessionEnd.guidance("not_refresh_token_expired", session(), reLogin)

        assertThat(line).contains("the hub refused to renew it (invalid_grant)").doesNotContain("idle window")
    }

    @Test
    fun `tokens that are not readable JWTs leave the times out rather than inventing them`() {
        val opaque = Tokens(accessToken = "opaque-reference-token", refreshToken = "RT")

        assertThat(SessionEnd.guidance("refresh_token_expired", opaque, reLogin)).isEqualTo(
            "Your sign-in session has ended: it was not used within the hub's idle window. " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
        assertThat(SessionEnd.guidance(null, opaque, reLogin)).isEqualTo(
            "Your sign-in session has ended: the hub refused to renew it (invalid_grant). " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
    }

    @Test
    fun `the sign-in time falls back to the access token when there is no ID token`() {
        val noIdToken = session().copy(idToken = null)

        assertThat(SessionEnd.signedInAt(noIdToken)).isEqualTo(signedIn)
        assertThat(SessionEnd.lastRenewedAt(noIdToken)).isEqualTo(renewed)
    }

    @Test
    fun `elapsed time reads in the unit a person would use`() {
        assertThat(SessionEnd.ago(now.minusSeconds(20), now)).isEqualTo("less than a minute ago")
        assertThat(SessionEnd.ago(now.minusSeconds(25 * 60), now)).isEqualTo("25 min ago")
        assertThat(SessionEnd.ago(now.minusSeconds(47 * 3600 + 5 * 60), now)).isEqualTo("47 h 5 min ago")
        assertThat(SessionEnd.ago(now.minusSeconds(3 * 86400 + 2 * 3600), now)).isEqualTo("3 d 2 h ago")
        // A clock that runs behind the hub's must not print a negative age.
        assertThat(SessionEnd.ago(now.plusSeconds(90), now)).isEqualTo("less than a minute ago")
    }

    private fun jwt(payload: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
            enc.encodeToString(payload.toByteArray()) + ".sig"
    }
}
