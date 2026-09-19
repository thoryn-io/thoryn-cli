package com.devnow.thoryn.cli.output

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.ObjectMapper
import java.time.Instant

/**
 * SSO-3275 — the time-column renderer.
 *
 * `thoryn devices list` printed `LAST SEEN 1789848418` because it called `asString()` on whatever
 * the hub sent for an `Instant`. The renderer's job is to be indifferent to which of the four
 * shapes an `Instant` serialises to, and to say the same readable thing for all of them.
 */
class TimestampsTest {

    private val mapper = ObjectMapper()
    private val now: Instant = Instant.parse("2026-09-19T10:00:00Z")

    private fun node(json: String) = mapper.readTree("""{"at":$json}""")["at"]

    // ── the four wire shapes an Instant arrives in ────────────────────────────

    @Test
    fun `epoch seconds — the shape seen live on cli-v0_23_0 — reads as a timestamp and an age`() {
        // 1789848418 is the exact value from the SSO-3275 report.
        val rendered = Timestamps.render(node("1789848418"), now = Instant.parse("2026-09-19T20:20:00Z"))

        assertThat(rendered)
            .describedAs("an epoch is not an answer to 'when was this machine last seen'")
            .isEqualTo("2026-09-19T20:06:58Z (13m ago)")
    }

    @Test
    fun `epoch milliseconds are told apart from seconds by magnitude`() {
        val rendered = Timestamps.render(node("1789848418000"), now = Instant.parse("2026-09-19T20:20:00Z"))

        assertThat(rendered).isEqualTo("2026-09-19T20:06:58Z (13m ago)")
    }

    @Test
    fun `seconds-with-nanos, what Jackson writes with WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS, is read as one instant`() {
        val rendered = Timestamps.render(node("1789848418.123456789"), now = Instant.parse("2026-09-19T20:20:00Z"))

        assertThat(rendered)
            .describedAs("the nanosecond tail must not widen the column")
            .isEqualTo("2026-09-19T20:06:58Z (13m ago)")
    }

    @Test
    fun `an ISO-8601 string renders identically to the epoch that means the same moment`() {
        assertThat(Timestamps.render(node(""""2026-09-19T09:41:00Z""""), now))
            .isEqualTo("2026-09-19T09:41:00Z (19m ago)")
    }

    @Test
    fun `an offset date-time is normalised to UTC`() {
        assertThat(Timestamps.render(node(""""2026-09-19T11:41:00+02:00""""), now))
            .isEqualTo("2026-09-19T09:41:00Z (19m ago)")
    }

    @Test
    fun `an epoch that arrived quoted as a string is still an epoch`() {
        assertThat(Timestamps.render(node(""""1789848418""""), now = Instant.parse("2026-09-19T20:20:00Z")))
            .isEqualTo("2026-09-19T20:06:58Z (13m ago)")
    }

    // ── absent / unreadable ──────────────────────────────────────────────────

    @Test
    fun `absent, JSON null and empty all read as no answer`() {
        // `node["x"]` answers a NullNode for an explicit null — not Kotlin's null (SSO-3228).
        assertThat(Timestamps.render(null, now)).isNull()
        assertThat(Timestamps.render(node("null"), now)).isNull()
        assertThat(Timestamps.render(node("\"\""), now)).isNull()
    }

    @Test
    fun `a value the CLI does not recognise is shown verbatim rather than dropped or guessed at`() {
        assertThat(Timestamps.render(node("\"last tuesday\""), now))
            .describedAs("hiding a hub's own answer is worse than printing something odd")
            .isEqualTo("last tuesday")
    }

    // ── the age wording ──────────────────────────────────────────────────────

    @Test
    fun `the age reads in the unit a person would use`() {
        fun agoOf(secondsAgo: Long) = Timestamps.age(now.minusSeconds(secondsAgo), now)

        assertThat(agoOf(5)).isEqualTo("5s ago")
        assertThat(agoOf(180)).isEqualTo("3m ago")
        assertThat(agoOf(8_100)).isEqualTo("2h 15m ago")
        assertThat(agoOf(9 * 86_400)).isEqualTo("9d ago")
    }

    @Test
    fun `a timestamp in the future reads as in, not as a negative age`() {
        // Clock skew between a laptop and the hub is ordinary; "-3m ago" would look like a CLI bug.
        assertThat(Timestamps.age(now.plusSeconds(180), now)).isEqualTo("in 3m")
    }
}
