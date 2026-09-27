package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/** SSO-3377 — the retired-issuer probe's classification and the successor it suggests. */
class RetiredIssuerTest {

    @AfterEach
    fun reset() {
        RetiredIssuer.resetForTest()
    }

    private val retiredBody =
        """{"detail":"This host has been retired. Use the issuer advertised in the current discovery document.",""" +
            """"instance":"/.well-known/openid-configuration","status":410,"title":"Gone",""" +
            """"type":"https://thoryn.io/problems/issuer_retired","errorCode":"issuer_retired"}"""

    @Test
    fun `a 410 carrying errorCode issuer_retired is a retired issuer, with the hub's detail`() {
        val status = RetiredIssuer.classify("https://hub.stg.thoryn.org", 410, retiredBody)

        assertThat(status).isEqualTo(
            RetiredIssuer.Status.Retired(
                "https://hub.stg.thoryn.org",
                "This host has been retired. Use the issuer advertised in the current discovery document.",
            ),
        )
    }

    @Test
    fun `the problem type alone also identifies a retired issuer`() {
        val body = """{"type":"https://thoryn.io/problems/issuer_retired","status":410}"""

        assertThat(RetiredIssuer.classify("https://x", 410, body)).isInstanceOf(RetiredIssuer.Status.Retired::class.java)
    }

    @Test
    fun `a 410 with another or no errorCode is gone, not retired`() {
        assertThat(RetiredIssuer.classify("https://x", 410, """{"errorCode":"tenant_deleted","detail":"d"}"""))
            .isEqualTo(RetiredIssuer.Status.Gone("https://x", "d"))
        assertThat(RetiredIssuer.classify("https://x", 410, "not json")).isEqualTo(RetiredIssuer.Status.Gone("https://x", null))
        assertThat(RetiredIssuer.classify("https://x", 410, null)).isEqualTo(RetiredIssuer.Status.Gone("https://x", null))
    }

    @Test
    fun `every answer other than 410 is live, and so is no answer at all`() {
        listOf(200, 301, 404, 500, 503).forEach {
            assertThat(RetiredIssuer.classify("https://x", it, retiredBody)).isEqualTo(RetiredIssuer.Status.Live)
        }
        RetiredIssuer.fetcher = { null }
        assertThat(RetiredIssuer.check("https://hub.stg.thoryn.org")).isEqualTo(RetiredIssuer.Status.Live)
        RetiredIssuer.fetcher = { throw IllegalStateException("boom") }
        assertThat(RetiredIssuer.check("https://hub.stg.thoryn.org")).isEqualTo(RetiredIssuer.Status.Live)
    }

    @Test
    fun `the probe asks the issuer's own discovery document`() {
        val asked = mutableListOf<String>()
        RetiredIssuer.fetcher = { asked += it; RetiredIssuer.Answer(410, retiredBody) }

        RetiredIssuer.check("https://thoryn.hub.stg.thoryn.org/")

        assertThat(asked).containsExactly("https://thoryn.hub.stg.thoryn.org/.well-known/openid-configuration")
    }

    @Test
    fun `a retired hub base host suggests the auth host on the same platform`() {
        assertThat(RetiredIssuer.suggestionFor("https://hub.stg.thoryn.org"))
            .isEqualTo(RetiredIssuer.Suggestion("https://auth.stg.thoryn.org", null))
        assertThat(RetiredIssuer.suggestionFor("https://hub.stg.thoryn.org/", "acme"))
            .isEqualTo(RetiredIssuer.Suggestion("https://auth.stg.thoryn.org", "acme"))
    }

    @Test
    fun `a retired workspace host suggests the auth host and the workspace flag`() {
        val suggestion = RetiredIssuer.suggestionFor("https://thoryn.hub.stg.thoryn.org")

        assertThat(suggestion).isEqualTo(RetiredIssuer.Suggestion("https://auth.stg.thoryn.org", "thoryn"))
        assertThat(suggestion!!.loginCommand()).isEqualTo("thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn")
        assertThat(suggestion.loginCommand("thoryn login --client-credentials", includeWorkspace = false))
            .isEqualTo("thoryn login --client-credentials --issuer https://auth.stg.thoryn.org")
    }

    @Test
    fun `nothing is suggested where the platform cannot be inferred`() {
        listOf(
            "https://auth.stg.thoryn.org", // already the successor label
            "https://acme.auth.stg.thoryn.org",
            "https://login.acme.com", // a custom domain
            "http://localhost:54702",
            "not a url",
            "",
        ).forEach { assertThat(RetiredIssuer.suggestionFor(it)).withFailMessage(it).isNull() }
        assertThat(RetiredIssuer.suggestionFor(null)).isNull()
    }

    @Test
    fun `the login guidance names the retired issuer, says a saved issuer is not changed, and gives the line`() {
        val text = RetiredIssuer.loginGuidance(
            retired = RetiredIssuer.Status.Retired("https://thoryn.hub.stg.thoryn.org", "This host has been retired."),
            base = "https://hub.stg.thoryn.org",
            workspace = "thoryn",
            remembered = true,
        )

        assertThat(text).isEqualTo(
            """
            Error: the issuer https://thoryn.hub.stg.thoryn.org has been retired (HTTP 410 issuer_retired) — This host has been retired.
            https://hub.stg.thoryn.org was remembered from your previous sign-in on this machine; the CLI does not change a saved issuer for you.
            Sign in with the platform's current issuer:
                thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn
            """.trimIndent(),
        )
    }
}
