package com.devnow.thoryn.cli

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2953 — the CLI version is build-stamped, not a hardcoded literal. These
 * tests fail on the old behaviour (a fixed `thoryn 0.0.1-SNAPSHOT` literal) by
 * asserting the injected version flows through and that a release version never
 * carries `SNAPSHOT`.
 */
class VersionProviderTest {

    @Test
    fun `render stamps the injected version and a release version has no SNAPSHOT`() {
        assertThat(VersionProvider.render("0.3.1")).isEqualTo("thoryn 0.3.1")
        assertThat(VersionProvider.render("0.3.1")).doesNotContain("SNAPSHOT")
    }

    @Test
    fun `version is read from the build-filtered resource, not an unresolved placeholder`() {
        val version = VersionProvider.readVersion()
        // Maven resource filtering must have substituted ${project.version}; an
        // unfiltered resource would leak the literal placeholder into --version.
        assertThat(version).doesNotContain("\${")
        assertThat(version).isNotBlank()
        assertThat(version).isNotEqualTo("unknown")
    }

    @Test
    fun `provider emits a single thoryn-prefixed line matching the stamped version`() {
        val lines = VersionProvider().version
        assertThat(lines).hasSize(1)
        assertThat(lines[0]).startsWith("thoryn ")
        assertThat(lines[0]).isEqualTo(VersionProvider.render(VersionProvider.readVersion()))
    }
}
