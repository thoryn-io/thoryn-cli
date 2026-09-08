package com.devnow.thoryn.cli.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/**
 * SSO-2941 — [ThorynConfig.resolveApiKey] / [ThorynConfig.resolveApiKeySecret], the single-knob
 * `THORYN_API_KEY=<client-id>:<client-secret>` parsing for non-interactive `login --client-credentials`.
 *
 * The credential is supplied to these tests via the `THORYN_API_KEY` / `THORYN_CLIENT_SECRET`
 * **system properties** — the no-argv knobs the resolver reads before the environment — so the
 * secret never rides on a command line.
 */
class ThorynConfigApiKeyTest {

    @AfterEach
    fun clearProps() {
        System.clearProperty(ThorynConfig.API_KEY_ENV)
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    @Test
    fun `resolveApiKey splits client-id and secret on the first colon`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:s3cret")

        val key = ThorynConfig.resolveApiKey()

        assertThat(key).isNotNull
        assertThat(key!!.clientId).isEqualTo("ci-bot")
        assertThat(key.clientSecret).isEqualTo("s3cret")
    }

    @Test
    fun `resolveApiKey keeps colons that belong to the secret`() {
        // Only the FIRST colon separates id from secret; the rest is part of the secret.
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:aa:bb:cc")

        val key = ThorynConfig.resolveApiKey()!!

        assertThat(key.clientId).isEqualTo("ci-bot")
        assertThat(key.clientSecret).isEqualTo("aa:bb:cc")
    }

    @Test
    fun `resolveApiKey is null when unset`() {
        assertThat(ThorynConfig.resolveApiKey()).isNull()
    }

    @Test
    fun `resolveApiKey is null for a malformed value with no colon`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "no-colon-here")
        assertThat(ThorynConfig.resolveApiKey()).isNull()
    }

    @Test
    fun `resolveApiKey is null when either half is empty`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, ":secret-only")
        assertThat(ThorynConfig.resolveApiKey()).isNull()
        System.setProperty(ThorynConfig.API_KEY_ENV, "id-only:")
        assertThat(ThorynConfig.resolveApiKey()).isNull()
    }

    @Test
    fun `resolveApiKeySecret prefers the API key secret over THORYN_CLIENT_SECRET`() {
        System.setProperty(ThorynConfig.API_KEY_ENV, "ci-bot:from-api-key")
        System.setProperty("THORYN_CLIENT_SECRET", "from-client-secret")

        assertThat(ThorynConfig.resolveApiKeySecret()).isEqualTo("from-api-key")
    }

    @Test
    fun `resolveApiKeySecret falls back to THORYN_CLIENT_SECRET when no API key`() {
        System.setProperty("THORYN_CLIENT_SECRET", "from-client-secret")

        assertThat(ThorynConfig.resolveApiKeySecret()).isEqualTo("from-client-secret")
    }

    @Test
    fun `resolveApiKeySecret is null when nothing is set`() {
        assertThat(ThorynConfig.resolveApiKeySecret()).isNull()
    }
}
