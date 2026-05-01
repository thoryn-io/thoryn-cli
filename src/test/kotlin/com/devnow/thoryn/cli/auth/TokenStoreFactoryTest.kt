package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import com.github.javakeyring.PasswordAccessException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-794 — `TokenStoreFactory` selection rules.
 *
 * Verifies the decision tree documented on [TokenStoreFactory.default]:
 *
 *  1. `THORYN_CI_PLAINTEXT_TOKENS=1` overrides everything → [FileTokenStore].
 *  2. Keychain available → [KeychainTokenStore].
 *  3. Keychain unavailable + `THORYN_TOKEN_FILE` set → [FileTokenStore].
 *  4. Keychain unavailable + nothing set → [TokenStoreUnavailableException].
 *
 * Real env vars cannot be set from inside the JVM portably, so the test stubs
 * `TokenStoreFactory.environment` and `TokenStoreFactory.keychainProvider` for
 * the duration of each case and resets them after — the same pattern the
 * existing `ThorynCliE2ETest` uses for `user.home`.
 */
class TokenStoreFactoryTest {

    private val originalEnv = TokenStoreFactory.environment
    private val originalProvider = TokenStoreFactory.keychainProvider

    @BeforeEach
    fun resetSeams() {
        // Each test sets its own seam values; this just clears any leak from a
        // crashed previous test in the same JVM.
        TokenStoreFactory.environment = originalEnv
        TokenStoreFactory.keychainProvider = originalProvider
    }

    @AfterEach
    fun restoreSeams() {
        TokenStoreFactory.environment = originalEnv
        TokenStoreFactory.keychainProvider = originalProvider
    }

    @Test
    fun `THORYN_CI_PLAINTEXT_TOKENS=1 forces FileTokenStore`() {
        TokenStoreFactory.environment = envOf(TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR to "1")
        TokenStoreFactory.keychainProvider = { error("must not be called when opt-in is set") }

        val store = TokenStoreFactory.default()

        assertThat(store).isInstanceOf(FileTokenStore::class.java)
    }

    @Test
    fun `keychain available returns KeychainTokenStore`() {
        TokenStoreFactory.environment = envOf()
        TokenStoreFactory.keychainProvider = { NoopKeychain }

        val store = TokenStoreFactory.default()

        assertThat(store).isInstanceOf(KeychainTokenStore::class.java)
    }

    @Test
    fun `keychain unavailable + THORYN_TOKEN_FILE set falls back to FileTokenStore`() {
        TokenStoreFactory.environment = envOf(
            TokenStoreFactory.FILE_PATH_ENV_VAR to "/tmp/thoryn-test-tokens.json",
        )
        TokenStoreFactory.keychainProvider = {
            throw BackendNotSupportedException("no Secret Service daemon")
        }

        val store = TokenStoreFactory.default()

        assertThat(store).isInstanceOf(FileTokenStore::class.java)
    }

    @Test
    fun `keychain unavailable + no escape hatch throws clear error`() {
        TokenStoreFactory.environment = envOf()
        TokenStoreFactory.keychainProvider = {
            throw BackendNotSupportedException("no Secret Service daemon")
        }

        assertThatThrownBy { TokenStoreFactory.default() }
            .isInstanceOf(TokenStoreUnavailableException::class.java)
            .hasMessageContaining("OS keychain backend is not available")
            .hasMessageContaining(TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR)
            .hasMessageContaining(TokenStoreFactory.FILE_PATH_ENV_VAR)
    }

    @Test
    fun `THORYN_CI_PLAINTEXT_TOKENS wins even when keychain backend is reachable`() {
        // Documents the precedence rule: explicit opt-in beats backend probe.
        // This matters in CI runners that happen to have a Secret Service
        // daemon — the test harness pinned an env var, and we honour it.
        TokenStoreFactory.environment = envOf(TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR to "1")
        var keychainCreated = false
        TokenStoreFactory.keychainProvider = {
            keychainCreated = true
            NoopKeychain
        }

        val store = TokenStoreFactory.default()

        assertThat(store).isInstanceOf(FileTokenStore::class.java)
        assertThat(keychainCreated).isFalse()
    }

    @Test
    fun `blank THORYN_CI_PLAINTEXT_TOKENS does not trigger fallback`() {
        // A user who shell-quotes an empty string shouldn't accidentally
        // disable the keychain. Treat blank like "unset".
        TokenStoreFactory.environment = envOf(TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR to "")
        TokenStoreFactory.keychainProvider = { NoopKeychain }

        val store = TokenStoreFactory.default()

        assertThat(store).isInstanceOf(KeychainTokenStore::class.java)
    }

    @Test
    fun `blank THORYN_TOKEN_FILE is not treated as an escape hatch`() {
        TokenStoreFactory.environment = envOf(TokenStoreFactory.FILE_PATH_ENV_VAR to "")
        TokenStoreFactory.keychainProvider = {
            throw BackendNotSupportedException("no backend")
        }

        assertThatThrownBy { TokenStoreFactory.default() }
            .isInstanceOf(TokenStoreUnavailableException::class.java)
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun envOf(vararg pairs: Pair<String, String>): (String) -> String? {
        val map = pairs.toMap()
        return { key -> map[key] }
    }

    /**
     * Stand-in for a real keychain backend in tests that only need to verify
     * which [TokenStore] subclass the factory returns — i.e. they never call
     * `read`/`write`/`delete`. All operations throw
     * [PasswordAccessException] which the store would handle as "not signed
     * in", so even if the test accidentally invoked one of them the failure
     * mode would be obvious instead of silent.
     */
    private object NoopKeychain : KeychainAccess {
        override fun getPassword(service: String, account: String): String =
            throw PasswordAccessException("noop")

        override fun setPassword(service: String, account: String, password: String): Unit =
            throw PasswordAccessException("noop")

        override fun deletePassword(service: String, account: String): Unit =
            throw PasswordAccessException("noop")
    }
}
