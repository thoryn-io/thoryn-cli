package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.Base64

/**
 * SSO-2860 — `thoryn whoami` (offline): decodes the stored access token's claims and surfaces the
 * signed-in identity + token expiry. No network — the base-class MockWebServer is unused here.
 */
class WhoamiCommandTest : CommandTestBase() {

    private fun jwt(claims: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString(claims.toByteArray())
        return "$header.$payload." // signature omitted — whoami never verifies (display only)
    }

    @Test
    fun `whoami surfaces subject, tenant, scopes and a valid token status`() {
        val exp = Instant.now().epochSecond + 3600
        val token = jwt("""{"sub":"user-123","tnt":"acme","client_id":"thoryn-cli","scope":"openid tenant:clients.read"}""")
        seedTokens(
            Tokens(
                accessToken = token,
                refreshToken = "RT",
                expiresAtEpochSecond = exp,
                scope = "openid tenant:clients.read",
                issuer = "https://hub.stg.thoryn.org",
                gateway = "https://api.stg.thoryn.org",
            ),
        )

        val (exit, out, _) = runCli("whoami", "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["subject"]).isEqualTo("user-123")
        assertThat(json["tenant"]).isEqualTo("acme")
        assertThat(json["clientId"]).isEqualTo("thoryn-cli")
        assertThat(json["issuer"]).isEqualTo("https://hub.stg.thoryn.org")
        assertThat(json["scopes"]).isEqualTo("openid tenant:clients.read")
        assertThat(json["tokenStatus"].toString()).contains("valid")
    }

    @Test
    fun `whoami reports EXPIRED for a past expiry`() {
        val token = jwt("""{"sub":"user-123","tnt":"acme"}""")
        seedTokens(Tokens(accessToken = token, expiresAtEpochSecond = Instant.now().epochSecond - 60))

        val (exit, out, _) = runCli("whoami", "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["tokenStatus"].toString()).contains("EXPIRED")
    }

    @Test
    fun `whoami with no token returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, err) = runCli("whoami")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }

    @Test
    fun `whoami surfaces the active workspace when one is selected`() {
        seedTokens(Tokens(accessToken = jwt("""{"sub":"u","tnt":"default"}"""), expiresAtEpochSecond = Instant.now().epochSecond + 3600))
        SelectedWorkspaceStore().write(SelectedWorkspace(tenantId = "t-1", slug = "testq2", tenantHubIssuer = "https://testq2.hub.example.org"))

        val (exit, out, _) = runCli("whoami", "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["tenant"]).isEqualTo("default")
        assertThat(json["activeWorkspace"]).isEqualTo("testq2")
    }

    @Test
    fun `whoami omits activeWorkspace when no workspace is selected`() {
        seedTokens(Tokens(accessToken = jwt("""{"sub":"u","tnt":"default"}""")))
        val (_, out, _) = runCli("whoami", "--output", "json")
        assertThat(parseJson(out)).doesNotContainKey("activeWorkspace")
    }
}
