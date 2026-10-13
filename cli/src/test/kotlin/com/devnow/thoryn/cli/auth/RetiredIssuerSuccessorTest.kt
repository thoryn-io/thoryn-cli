package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/**
 * SSO-3415 — the successor a workspace's retired platform host names (`"issuer"` in its `410
 * issuer_retired`, oathy ADR 2026-09-25-custom-domains.md amendment 2026-09-28): what the CLI accepts,
 * and that [RetiredIssuer.resolve] follows it exactly once.
 */
class RetiredIssuerSuccessorTest {

    @AfterEach
    fun reset() {
        RetiredIssuer.resetForTest()
    }

    private val platform = "https://acme.auth.stg.thoryn.org"

    private fun retiredBody(successor: String?): String =
        """{"type":"https://thoryn.io/problems/issuer_retired","title":"Gone","status":410,"errorCode":"issuer_retired",""" +
            """"detail":"This host has been retired. This workspace now signs in at the issuer named in the 'issuer' member; use that issuer's discovery document.",""" +
            """"instance":"/.well-known/openid-configuration"""" +
            (successor?.let { ""","issuer":"$it"""" } ?: "") + "}"

    @Test
    fun `a retired platform host that names an issuer carries it as the successor`() {
        val status = RetiredIssuer.classify(platform, 410, retiredBody("https://auth.acme.com"))

        assertThat(status).isInstanceOf(RetiredIssuer.Status.Retired::class.java)
        assertThat((status as RetiredIssuer.Status.Retired).successor).isEqualTo("https://auth.acme.com")
    }

    @Test
    fun `the SSO-3377 fleet-wide answer names no successor`() {
        val status = RetiredIssuer.classify("https://hub.stg.thoryn.org", 410, retiredBody(null)) as RetiredIssuer.Status.Retired

        assertThat(status.successor).isNull()
    }

    @Test
    fun `a sandbox successor keeps the environment path, and the host is normalised`() {
        assertThat(RetiredIssuer.successorOf("$platform/staging-sbx", "https://Auth.Acme.com/staging-sbx/"))
            .isEqualTo("https://auth.acme.com/staging-sbx")
        assertThat(RetiredIssuer.successorOf(platform, "https://auth.acme.com:443")).isEqualTo("https://auth.acme.com")
    }

    @Test
    fun `a successor that is not https, not a sane host, or not the same environment is refused`() {
        val refused = listOf(
            "http://auth.acme.com", // a remote platform can never send the CLI to plain HTTP
            "ftp://auth.acme.com",
            "https://10.0.0.7", // IP literal
            "https://localhost",
            "https://intranet", // single label
            "https://auth.acme.com:8443",
            "https://user@auth.acme.com",
            "https://auth.acme.com?next=x",
            "https://auth.acme.com#frag",
            "https://auth.acme.com/other-env", // a workspace issuer cannot become a sandbox one
            "https://auth.acme.com/a/b",
            "https://auth acme.com",
            "//auth.acme.com",
            platform, // itself
            "",
            null,
        )
        for (raw in refused) {
            assertThat(RetiredIssuer.successorOf(platform, raw)).describedAs("$raw").isNull()
        }
        assertThat(RetiredIssuer.successorOf("$platform/staging-sbx", "https://auth.acme.com")).isNull()
        assertThat(RetiredIssuer.successorOf("$platform/staging-sbx", "https://auth.acme.com/prod-sbx")).isNull()
        // The one http exception: a LOCAL stack (loopback retired issuer) naming another loopback issuer.
        assertThat(RetiredIssuer.successorOf("http://localhost:8080", "http://127.0.0.1:8080")).isEqualTo("http://127.0.0.1:8080")
        assertThat(RetiredIssuer.successorOf("http://localhost:8080", "http://auth.acme.com")).isNull()
        assertThat(RetiredIssuer.successorOf(platform, "http://127.0.0.1:8080")).isNull()
    }

    @Test
    fun `resolve follows a live successor exactly once`() {
        val asked = mutableListOf<String>()
        RetiredIssuer.fetcher = { url ->
            asked += url
            if (url.startsWith(platform)) RetiredIssuer.Answer(410, retiredBody("https://auth.acme.com")) else RetiredIssuer.Answer(200, "{}")
        }

        assertThat(RetiredIssuer.resolve(platform)).isEqualTo(RetiredIssuer.Resolution.Moved(platform, "https://auth.acme.com"))
        assertThat(asked).containsExactly(
            "$platform/.well-known/openid-configuration",
            "https://auth.acme.com/.well-known/openid-configuration",
        )
    }

    @Test
    fun `a successor that is retired too is a chain - refused, never followed further`() {
        val asked = mutableListOf<String>()
        RetiredIssuer.fetcher = { url ->
            asked += url
            when {
                url.startsWith(platform) -> RetiredIssuer.Answer(410, retiredBody("https://auth.acme.com"))
                url.startsWith("https://auth.acme.com") -> RetiredIssuer.Answer(410, retiredBody("https://login.acme.com"))
                else -> RetiredIssuer.Answer(200, "{}")
            }
        }

        val resolution = RetiredIssuer.resolve(platform)

        assertThat(resolution).isInstanceOf(RetiredIssuer.Resolution.ChainRefused::class.java)
        assertThat(asked).hasSize(2).noneMatch { it.contains("login.acme.com") }
        assertThat(RetiredIssuer.chainGuidance(resolution as RetiredIssuer.Resolution.ChainRefused))
            .contains("follows one move only")
    }

    @Test
    fun `no successor, a refused successor or a gone host stop - and a live issuer is used as it is`() {
        RetiredIssuer.fetcher = { RetiredIssuer.Answer(410, retiredBody(null)) }
        assertThat(RetiredIssuer.resolve(platform)).isInstanceOf(RetiredIssuer.Resolution.Stop::class.java)

        RetiredIssuer.fetcher = { RetiredIssuer.Answer(410, retiredBody("http://auth.acme.com")) }
        val refused = RetiredIssuer.resolve(platform) as RetiredIssuer.Resolution.Stop
        assertThat((refused.status as RetiredIssuer.Status.Retired).successor).isNull()

        RetiredIssuer.fetcher = { RetiredIssuer.Answer(410, """{"errorCode":"tenant_deleted"}""") }
        assertThat(RetiredIssuer.resolve(platform)).isInstanceOf(RetiredIssuer.Resolution.Stop::class.java)

        RetiredIssuer.fetcher = { null }
        assertThat(RetiredIssuer.resolve("$platform/")).isEqualTo(RetiredIssuer.Resolution.Current(platform))
    }
}
