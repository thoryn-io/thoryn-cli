package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import com.github.javakeyring.Keyring
import com.github.javakeyring.PasswordAccessException
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper

/**
 * OS-keychain-backed [TokenStore] (SSO-794, ADR 2026-04-25 §4).
 *
 * Tokens are persisted via [java-keyring](https://github.com/javakeyring/java-keyring),
 * which is a thin wrapper that delegates to the platform-native credential vault:
 *
 *  - **macOS** — Security.framework / Keychain Access. Entries appear under the
 *    service name "thoryn" with account "tokens".
 *  - **Linux** — Secret Service (`gnome-keyring`, KDE KWallet) over D-Bus.
 *  - **Windows** — Credential Manager (DPAPI-encrypted, per-user).
 *
 * The whole [Tokens] bundle is serialised to JSON and stored as a single
 * keychain entry. This matches the on-disk shape of [FileTokenStore] so the
 * two are interchangeable behind the [TokenStore] interface — and so the
 * stored payload survives [Tokens] gaining new fields (refresh_token, id_token,
 * scope) without requiring schema migrations on the keychain side.
 *
 * **Why a single entry, not one per field?** macOS Keychain Access shows each
 * service+account pair as a row; storing five rows per CLI session would
 * pollute the user's keychain UI for no security gain (everything's encrypted
 * at the same level either way). One row, JSON inside, is the de-facto
 * convention used by `gh`, `aws-vault`, `glab`, etc.
 *
 * Construction may throw [BackendNotSupportedException] when the runtime
 * platform has no usable backend (headless Linux without a Secret Service
 * daemon, exotic OSes). Call sites should catch this and fall back through
 * [TokenStoreFactory] rather than hard-failing.
 *
 * The keychain is wrapped behind [KeychainAccess] so unit tests can swap in an
 * in-memory implementation — [Keyring] itself has a private constructor and
 * cannot be subclassed.
 */
class KeychainTokenStore(
    private val keychain: KeychainAccess,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
    private val service: String = SERVICE,
    private val account: String = ACCOUNT,
) : TokenStore {

    /** Convenience constructor that wraps a real [Keyring]. */
    constructor(keyring: Keyring) : this(JavaKeyringAccess(keyring))

    override fun read(): Tokens? =
        try {
            val json = keychain.getPassword(service, account)
            if (json.isNullOrBlank()) null
            else mapper.readValue(json, Tokens::class.java)
        } catch (_: PasswordAccessException) {
            // No entry yet, or the OS denied read. Treat both as "not signed in"
            // — the CLI will prompt for a fresh login and overwrite on success.
            null
        } catch (_: Exception) {
            // Stored payload is corrupt (manual keychain edit, schema drift on a
            // major Tokens-shape change). Same recovery path: signal "not signed
            // in" so the CLI re-runs the OAuth flow and replaces the entry.
            null
        }

    override fun write(tokens: Tokens) {
        val json = mapper.writeValueAsString(tokens)
        keychain.setPassword(service, account, json)
    }

    override fun delete() {
        try {
            keychain.deletePassword(service, account)
        } catch (_: PasswordAccessException) {
            // Best effort: deleting an entry that never existed (or was already
            // removed) must not fail the `thoryn logout` command. Mirrors
            // FileTokenStore.delete() which also swallows IOException.
        }
    }

    companion object {
        /** Keychain "service" identifier — what shows up in Keychain Access. */
        const val SERVICE: String = "thoryn"

        /** Keychain "account" identifier — single entry holds the JSON bundle. */
        const val ACCOUNT: String = "tokens"

        /**
         * Open the OS-default keychain backend. Throws
         * [BackendNotSupportedException] if no backend is available on this
         * platform (e.g. a Linux container without a Secret Service daemon).
         */
        fun openDefault(): Keyring = Keyring.create()
    }
}

/**
 * Minimal abstraction over the three [Keyring] operations we use. Exists so
 * that unit tests can supply an in-memory replacement; [Keyring] has a private
 * constructor and is not subclassable.
 *
 * The contract follows java-keyring's exception model: implementations must
 * throw [PasswordAccessException] when no entry exists for `(service, account)`
 * or the underlying vault refuses the operation.
 */
interface KeychainAccess {
    fun getPassword(service: String, account: String): String?
    fun setPassword(service: String, account: String, password: String)
    fun deletePassword(service: String, account: String)
}

/** Adapter from a real java-keyring [Keyring] to [KeychainAccess]. */
internal class JavaKeyringAccess(private val keyring: Keyring) : KeychainAccess {
    override fun getPassword(service: String, account: String): String? =
        keyring.getPassword(service, account)

    override fun setPassword(service: String, account: String, password: String) {
        keyring.setPassword(service, account, password)
    }

    override fun deletePassword(service: String, account: String) {
        keyring.deletePassword(service, account)
    }
}
