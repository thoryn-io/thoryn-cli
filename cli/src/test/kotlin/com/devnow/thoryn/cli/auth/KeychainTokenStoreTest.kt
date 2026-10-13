package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import com.github.javakeyring.Keyring
import com.github.javakeyring.PasswordAccessException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty

/**
 * SSO-794 — `KeychainTokenStore` round-trip and error-path coverage.
 *
 * Most tests use [InMemoryKeychain] so they run on any CI runner without a
 * Secret Service / Keychain Access daemon. A separate `live keychain
 * round-trip` test exercises the real OS backend; that one is gated behind
 * `-Dthoryn.cli.test.live-keychain=true` because:
 *
 *  - macOS GitHub runners can technically reach Security.framework but the
 *    test would mutate the runner's login keychain and prompt for unlock.
 *  - Linux runners typically have no `gnome-keyring-daemon` running.
 *  - Windows runners need an active user session for DPAPI.
 *
 * Local developers can run the full suite (including the live test) with:
 *
 *     ./mvnw -pl tools/cli test -Dthoryn.cli.test.live-keychain=true
 */
class KeychainTokenStoreTest {

    @Test
    fun `read returns null when no entry has been written`() {
        val store = KeychainTokenStore(InMemoryKeychain())
        assertThat(store.read()).isNull()
    }

    @Test
    fun `write then read round-trips the tokens`() {
        val store = KeychainTokenStore(InMemoryKeychain())
        val tokens = Tokens(
            accessToken = "AT-1",
            refreshToken = "RT-1",
            idToken = "IT-1",
            tokenType = "Bearer",
            expiresAtEpochSecond = 1_700_000_000L,
            scope = "openid offline_access tenant:clients.read",
        )

        store.write(tokens)

        assertThat(store.read()).isEqualTo(tokens)
    }

    @Test
    fun `write twice replaces the previous entry`() {
        val store = KeychainTokenStore(InMemoryKeychain())

        store.write(Tokens(accessToken = "first"))
        store.write(Tokens(accessToken = "second"))

        assertThat(store.read()?.accessToken).isEqualTo("second")
    }

    @Test
    fun `delete removes the entry`() {
        val store = KeychainTokenStore(InMemoryKeychain())
        store.write(Tokens(accessToken = "AT-1"))

        store.delete()

        assertThat(store.read()).isNull()
    }

    @Test
    fun `delete is a no-op when no entry exists`() {
        val store = KeychainTokenStore(InMemoryKeychain())
        // Must not throw. Mirrors FileTokenStore.delete() semantics so the
        // CLI's `thoryn logout` is idempotent.
        store.delete()
    }

    @Test
    fun `read returns null when stored payload is corrupt JSON`() {
        val keychain = InMemoryKeychain().apply {
            // Bypass the store and inject garbage directly.
            setPassword(KeychainTokenStore.SERVICE, KeychainTokenStore.ACCOUNT, "{not-json")
        }
        val store = KeychainTokenStore(keychain)

        // The store treats a corrupt entry the same as "not signed in" so the
        // user's next `thoryn login` overwrites it with a valid bundle.
        assertThat(store.read()).isNull()
    }

    @Test
    fun `read returns null when underlying backend raises PasswordAccessException`() {
        val keychain = object : KeychainAccess {
            override fun getPassword(service: String, account: String): String =
                throw PasswordAccessException("keychain locked")

            override fun setPassword(service: String, account: String, password: String) =
                throw PasswordAccessException("keychain locked")

            override fun deletePassword(service: String, account: String) =
                throw PasswordAccessException("keychain locked")
        }
        val store = KeychainTokenStore(keychain)

        assertThat(store.read()).isNull()
    }

    /**
     * Live integration test — only enabled when `-Dthoryn.cli.test.live-keychain=true`
     * is on the command line *and* the runtime can actually open a real backend.
     * Skipped silently otherwise so CI stays green on headless runners.
     *
     * Locally on macOS this writes a real entry under "thoryn"/"tokens-test-<n>"
     * in Keychain Access, reads it back, and deletes it. We use a different
     * account name from production so a parallel `oathy login` session isn't
     * disturbed.
     */
    @Test
    @EnabledIfSystemProperty(named = "thoryn.cli.test.live-keychain", matches = "true")
    fun `live keychain round-trip`() {
        val keyring = try {
            Keyring.create()
        } catch (e: BackendNotSupportedException) {
            // System property forced the test on but the platform refused.
            // Fail visibly rather than silently — that's the contract of the
            // opt-in flag.
            throw AssertionError(
                "live-keychain test enabled but no backend is available: ${e.message}",
                e,
            )
        }
        val store = KeychainTokenStore(
            keychain = JavaKeyringAccess(keyring),
            account = "tokens-test-${System.nanoTime()}",
        )
        val tokens = Tokens(accessToken = "live-AT", refreshToken = "live-RT")

        try {
            store.write(tokens)
            assertThat(store.read()).isEqualTo(tokens)
        } finally {
            store.delete()
        }

        assertThat(store.read()).isNull()
    }

    /**
     * In-memory replacement for [KeychainAccess] used by the unit tests. Models
     * the same get/set/delete contract as the real Keyring — including throwing
     * [PasswordAccessException] when no entry exists, which is what the real
     * java-keyring backends do.
     */
    private class InMemoryKeychain : KeychainAccess {
        private val store: MutableMap<String, String> = mutableMapOf()

        override fun getPassword(service: String, account: String): String =
            store[key(service, account)]
                ?: throw PasswordAccessException("no entry for $service/$account")

        override fun setPassword(service: String, account: String, password: String) {
            store[key(service, account)] = password
        }

        override fun deletePassword(service: String, account: String) {
            val removed = store.remove(key(service, account))
            if (removed == null) {
                throw PasswordAccessException("no entry for $service/$account")
            }
        }

        private fun key(service: String, account: String): String = "$service/$account"
    }
}
