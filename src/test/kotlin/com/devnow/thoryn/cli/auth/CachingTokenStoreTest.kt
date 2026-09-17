package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3147 — [CachingTokenStore] collapses the several token reads a single CLI command performs
 * into one delegate access (one macOS keychain prompt), while staying coherent across a mid-command
 * refresh (write-through) and a logout (clear).
 */
class CachingTokenStoreTest {

    /** A delegate that counts every read/write/delete so the caching contract is observable. */
    private class CountingStore(var stored: Tokens?) : TokenStore {
        var reads = 0
        var writes = 0
        var deletes = 0

        override fun read(): Tokens? {
            reads++
            return stored
        }

        override fun write(tokens: Tokens) {
            writes++
            stored = tokens
        }

        override fun delete() {
            deletes++
            stored = null
        }
    }

    private fun tokens(at: String) = Tokens(accessToken = at, refreshToken = "RT")

    @Test
    fun `repeated reads hit the delegate only once`() {
        val delegate = CountingStore(tokens("AT-1"))
        val store = CachingTokenStore(delegate)

        val first = store.read()
        val second = store.read()
        val third = store.read()

        assertThat(first?.accessToken).isEqualTo("AT-1")
        assertThat(second).isSameAs(first)
        assertThat(third).isSameAs(first)
        assertThat(delegate.reads).isEqualTo(1)
    }

    @Test
    fun `a null (not-signed-in) result is cached too`() {
        val delegate = CountingStore(null)
        val store = CachingTokenStore(delegate)

        assertThat(store.read()).isNull()
        assertThat(store.read()).isNull()

        assertThat(delegate.reads).isEqualTo(1)
    }

    @Test
    fun `write is write-through and updates the cache so later reads see the refresh`() {
        val delegate = CountingStore(tokens("AT-old"))
        val store = CachingTokenStore(delegate)

        assertThat(store.read()?.accessToken).isEqualTo("AT-old") // read 1, cached
        store.write(tokens("AT-new")) // e.g. a mid-command refresh

        assertThat(delegate.writes).isEqualTo(1)
        assertThat(delegate.stored?.accessToken).isEqualTo("AT-new") // persisted
        // Later reads see the refreshed token WITHOUT another delegate read.
        assertThat(store.read()?.accessToken).isEqualTo("AT-new")
        assertThat(delegate.reads).isEqualTo(1)
    }

    @Test
    fun `delete clears the cache and the delegate`() {
        val delegate = CountingStore(tokens("AT-1"))
        val store = CachingTokenStore(delegate)

        assertThat(store.read()?.accessToken).isEqualTo("AT-1")
        store.delete()

        assertThat(delegate.deletes).isEqualTo(1)
        assertThat(store.read()).isNull() // cache reflects the deletion
        assertThat(delegate.reads).isEqualTo(1) // still no re-read of the delegate
    }
}
