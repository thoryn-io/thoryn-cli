package com.devnow.thoryn.provision

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * SSO-3738 — the run a consent is for, `<owner>/<repository>/<run_id>`: GitHub's grammar, strictly, because the three
 * names end up in a URL a browser opens. A name that could move that URL elsewhere is refused, never escaped.
 */
class ConsentRunTest {

    @Test
    fun `a by-run reference parses into its three names and rebuilds the same ref and path`() {
        val run = (ConsentRun.parseRef("thoryn-io/thoryn-cicd/38751887466") as ConsentRun.Result.Ok).run
        assertThat(run).isEqualTo(ConsentRun("thoryn-io", "thoryn-cicd", 38751887466))
        assertThat(run.ref).isEqualTo("thoryn-io/thoryn-cicd/38751887466")
        assertThat(run.path).isEqualTo("/github/consent/run/thoryn-io/thoryn-cicd/38751887466")
        assertThat(run.urlUnder("https://starters.stg.thoryn.org/"))
            .isEqualTo("https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/38751887466")
        // GitHub names that look unusual but are valid: a dotfile repository, underscores, a one-letter owner.
        assertThat(ConsentRun.parseRef("a/.github/1")).isInstanceOf(ConsentRun.Result.Ok::class.java)
        assertThat(ConsentRun.parseRef("Acme-Corp/my_repo.v2/9223372036854775807")).isInstanceOf(ConsentRun.Result.Ok::class.java)
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(
        strings = [
            "thoryn-io/thoryn-cicd", // two parts
            "thoryn-io/thoryn-cicd/1/2", // four parts
            "/thoryn-cicd/1", // empty owner
            "thoryn-io//1", // empty repository
            "thoryn-io/thoryn-cicd/", // empty run id
            "-x/thoryn-cicd/1", // leading '-' — never an option to an opener
            "evil.com/thoryn-cicd/1", // a host as the owner
            "thoryn-io/../1", // a dot segment
            "thoryn-io/./1",
            "thoryn-io/thoryn-cicd/0", // not a run id
            "thoryn-io/thoryn-cicd/-1",
            "thoryn-io/thoryn-cicd/012",
            "thoryn-io/thoryn-cicd/1e3",
            "thoryn-io/thoryn-cicd/99999999999999999999", // overflows a Long
            "thoryn-io/thoryn-cicd/1?next=https://evil.example", // a query
            "thoryn-io/thoryn-cicd/1#x", // a fragment
            "thoryn-io/thoryn%2Fcicd/1", // percent-encoding
            "thoryn-io/thoryn cicd/1", // whitespace
            "thoryn-io/thoryn-cicd/1\nhttps://evil.example", // a smuggled line
            "thoryn@io/thoryn-cicd/1", // user-info shape
            "thoryn-io\\x/thoryn-cicd/1", // a backslash
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/r/1", // owner longer than 39
        ],
    )
    fun `a reference that is not exactly owner, repository and run id is refused`(raw: String) {
        val result = ConsentRun.parseRef(raw)
        assertThat(result).isInstanceOf(ConsentRun.Result.Refused::class.java)
        // The refusal echoes the value without control characters (no terminal escape smuggling).
        assertThat((result as ConsentRun.Result.Refused).reason).doesNotContain("\n")
    }

    @Test
    fun `the run is read back from a consent link the CLI built, and nothing else is mistaken for one`() {
        assertThat(ConsentRun.ofConsentLink("https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/38547022158"))
            .isEqualTo(ConsentRun("thoryn-io", "thoryn-cli", 38547022158))
        assertThat(ConsentRun.ofConsentLink("https://app.thoryn.io/prefix/github/consent/run/o/r/7/")).isEqualTo(ConsentRun("o", "r", 7))
        assertThat(ConsentRun.ofConsentLink(null)).isNull()
        assertThat(ConsentRun.ofConsentLink("https://app.thoryn.io/github/consent/abc")).isNull()
        assertThat(ConsentRun.ofConsentLink("https://app.thoryn.io/github/consent/run/o/r/7/extra")).isNull()
        assertThat(ConsentRun.ofConsentLink("https://app.thoryn.io/github/consent/run/o/r/7?x=1")).isNull()
    }

    @Test
    fun `the consent link builder refuses names outside GitHub's grammar instead of printing a link elsewhere`() {
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "thoryn-io", "thoryn-cli", 1))
            .isEqualTo("https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/1")
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "thoryn-io", "../../evil", 1)).isNull()
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "evil.example?", "thoryn-cli", 1)).isNull()
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "thoryn-io", "thoryn-cli", 0)).isNull()
    }
}
