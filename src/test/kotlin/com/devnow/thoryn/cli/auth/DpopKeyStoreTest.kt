package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import com.github.javakeyring.PasswordAccessException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-3199 — persistence of the DPoP key, and the [Dpop] session that owns it.
 *
 * The load-bearing behaviour is **reuse**: a `cnf.jkt` the hub binds at login has to still be provable
 * on the next `thoryn` invocation, so the key must come back from the store rather than be regenerated.
 * The store selection follows [TokenStoreFactory]'s decision tree exactly — the private key must never
 * land somewhere weaker than the tokens it proves possession for.
 */
class DpopKeyStoreTest {

    private val originalEnv = TokenStoreFactory.environment
    private val originalProvider = TokenStoreFactory.keychainProvider

    @BeforeEach
    fun reset() {
        Dpop.resetForTest()
        DpopKeyStoreFactory.override = null
        TokenStoreFactory.environment = originalEnv
        TokenStoreFactory.keychainProvider = originalProvider
    }

    @AfterEach
    fun restore() {
        Dpop.resetForTest()
        DpopKeyStoreFactory.override = null
        TokenStoreFactory.environment = originalEnv
        TokenStoreFactory.keychainProvider = originalProvider
    }

    // ── the session: generate once, reuse forever ────────────────────────────

    @Test
    fun `the key is generated on first use and reused across invocations`() {
        val store = InMemoryDpopKeyStore()
        Dpop.storeProvider = { store }

        val first = Dpop.session()!!.thumbprint
        assertThat(store.stored).isNotNull()

        // A later invocation is a fresh process: drop the in-process cache, keep the store.
        Dpop.resetForTest()
        Dpop.storeProvider = { store }
        val second = Dpop.session()!!.thumbprint

        assertThat(second).isEqualTo(first)
    }

    @Test
    fun `a corrupt stored key is replaced rather than failing the command`() {
        val store = InMemoryDpopKeyStore().apply {
            stored = StoredDpopKey(privateKeyPkcs8 = "not-a-key", publicKeyX509 = "nope", createdAtEpochSecond = 1)
        }
        Dpop.storeProvider = { store }

        val session = Dpop.session()

        assertThat(session).isNotNull()
        assertThat(store.stored!!.privateKeyPkcs8).isNotEqualTo("not-a-key")
    }

    @Test
    fun `rotate discards the key so the next use generates a new one`() {
        val store = InMemoryDpopKeyStore()
        Dpop.storeProvider = { store }
        val before = Dpop.session()!!.thumbprint

        assertThat(Dpop.rotate()).isTrue()
        assertThat(store.stored).isNull()

        assertThat(Dpop.session()!!.thumbprint).isNotEqualTo(before)
    }

    @Test
    fun `rotate on a machine with no key reports nothing to discard`() {
        Dpop.storeProvider = { InMemoryDpopKeyStore() }

        assertThat(Dpop.rotate()).isFalse()
    }

    @Test
    fun `no usable store degrades to no DPoP instead of failing the command`() {
        val err = java.io.ByteArrayOutputStream()
        Dpop.storeProvider = { throw TokenStoreUnavailableException("no keychain here") }

        val session = Dpop.session(java.io.PrintStream(err))

        assertThat(session).isNull()
        assertThat(err.toString()).contains("DPoP").contains("without a DPoP proof")
    }

    @Test
    fun `the unavailable warning is printed at most once per process`() {
        val err = java.io.ByteArrayOutputStream()
        Dpop.storeProvider = { throw TokenStoreUnavailableException("no keychain here") }

        repeat(3) { Dpop.session(java.io.PrintStream(err)) }

        assertThat(err.toString().split("Note:").size - 1).isEqualTo(1)
    }

    // ── store selection — mirrors TokenStoreFactory ──────────────────────────

    @Test
    fun `THORYN_CI_PLAINTEXT_TOKENS=1 selects the file store`() {
        TokenStoreFactory.environment = envOf(TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR to "1")
        TokenStoreFactory.keychainProvider = { error("must not be consulted under the CI opt-in") }

        assertThat(DpopKeyStoreFactory.default()).isInstanceOf(FileDpopKeyStore::class.java)
    }

    @Test
    fun `a keychain backend selects the keychain store`() {
        TokenStoreFactory.environment = envOf()
        TokenStoreFactory.keychainProvider = { NoopKeychainAccess }

        assertThat(DpopKeyStoreFactory.default()).isInstanceOf(KeychainDpopKeyStore::class.java)
    }

    @Test
    fun `no keychain and no explicit file path refuses to write the private key in plaintext`() {
        TokenStoreFactory.environment = envOf()
        TokenStoreFactory.keychainProvider = { throw BackendNotSupportedException("no Secret Service daemon") }

        assertThatThrownBy { DpopKeyStoreFactory.default() }
            .isInstanceOf(TokenStoreUnavailableException::class.java)
            .hasMessageContaining("DPoP private key")
    }

    @Test
    fun `no keychain plus THORYN_TOKEN_FILE falls back to the file store`() {
        TokenStoreFactory.environment = envOf(TokenStoreFactory.FILE_PATH_ENV_VAR to "/tmp/thoryn-test-tokens.json")
        TokenStoreFactory.keychainProvider = { throw BackendNotSupportedException("headless") }

        assertThat(DpopKeyStoreFactory.default()).isInstanceOf(FileDpopKeyStore::class.java)
    }

    // ── the file store itself ────────────────────────────────────────────────

    @Test
    fun `the file store round-trips a key and is owner-only`(@TempDir dir: Path) {
        val path = dir.resolve("dpop-key.json")
        val store = FileDpopKeyStore(path)
        val key = DpopKey.generate()

        store.write(key.toStored())

        assertThat(DpopKey.fromStored(store.read()!!).thumbprint).isEqualTo(key.thumbprint)
        if (path.fileSystem.supportedFileAttributeViews().contains("posix")) {
            assertThat(Files.getPosixFilePermissions(path))
                .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        }

        store.delete()
        assertThat(store.read()).isNull()
    }

    @Test
    fun `the keychain store keeps the key under its own account, beside the tokens`() {
        val keychain = InMemoryKeychain()
        val store = KeychainDpopKeyStore(keychain)
        val key = DpopKey.generate()

        store.write(key.toStored())

        assertThat(keychain.entries.keys).containsExactly(
            KeychainTokenStore.SERVICE to KeychainDpopKeyStore.ACCOUNT,
        )
        assertThat(DpopKey.fromStored(store.read()!!).thumbprint).isEqualTo(key.thumbprint)
    }

    private fun envOf(vararg pairs: Pair<String, String>): (String) -> String? {
        val map = pairs.toMap()
        return { map[it] }
    }

    /** In-memory [DpopKeyStore] standing in for the keychain. */
    private class InMemoryDpopKeyStore : DpopKeyStore {
        var stored: StoredDpopKey? = null
        override fun read(): StoredDpopKey? = stored
        override fun write(key: StoredDpopKey) {
            stored = key
        }

        override fun delete() {
            stored = null
        }
    }

    private class InMemoryKeychain : KeychainAccess {
        val entries = mutableMapOf<Pair<String, String>, String>()
        override fun getPassword(service: String, account: String): String? =
            entries[service to account] ?: throw PasswordAccessException("no entry")

        override fun setPassword(service: String, account: String, password: String) {
            entries[service to account] = password
        }

        override fun deletePassword(service: String, account: String) {
            entries.remove(service to account) ?: throw PasswordAccessException("no entry")
        }
    }

    private object NoopKeychainAccess : KeychainAccess {
        override fun getPassword(service: String, account: String): String? = null
        override fun setPassword(service: String, account: String, password: String) = Unit
        override fun deletePassword(service: String, account: String) = Unit
    }
}
