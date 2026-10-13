package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3396 — `thoryn login --acr-values … --max-age …` asks the hub for a step-up sign-in (OIDC Core
 * §3.1.2.1, RFC 9470): the parameters ride the same authorize request list both carriers are built from
 * (the URL and the PAR body), and are absent unless asked for.
 */
class LoginStepUpParametersTest : CommandTestBase() {

    private fun parameters(acr: String?, maxAge: Long?) = LoginCommand.authorizeParameters(
        clientId = "cli",
        redirectUri = "http://127.0.0.1:54321/callback",
        scope = "openid",
        codeChallenge = "a-challenge",
        state = "st-1",
        dpopJkt = null,
        acrValues = acr,
        maxAge = maxAge,
    )

    @Test
    fun `acr_values and max_age are sent when asked for`() {
        assertThat(parameters("urn:thoryn:acr:phishing_resistant", 300))
            .contains("acr_values" to "urn:thoryn:acr:phishing_resistant", "max_age" to "300")
    }

    @Test
    fun `neither is sent by a plain login`() {
        assertThat(parameters(null, null).map { it.first }).doesNotContain("acr_values", "max_age")
    }

    @Test
    fun `a step-up is refused with the non-interactive flows`() {
        val (exit, _, err) = runCli("login", "--device-code", "--acr-values", "urn:thoryn:acr:phishing_resistant", "--issuer", "https://auth.example.test")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("--acr-values and --max-age apply to the interactive sign-in only")
    }
}
