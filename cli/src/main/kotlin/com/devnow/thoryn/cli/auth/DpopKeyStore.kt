package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import com.github.javakeyring.PasswordAccessException
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.logging.Logger
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * SSO-3199 — the persisted form of the CLI's per-installation DPoP key (RFC 9449).
 *
 * `privateKeyPkcs8` is the PKCS#8 encoding of the EC P-256 private key, base64 (standard alphabet);
 * `publicKeyX509` is the matching SubjectPublicKeyInfo. **This record carries private key material**
 * and therefore only ever travels between [DpopKey] and a [DpopKeyStore] — it is never printed, never
 * logged, never put in a receipt, and never sent over the network.
 */
data class StoredDpopKey(
    val privateKeyPkcs8: String,
    val publicKeyX509: String,
    val createdAtEpochSecond: Long,
)

/**
 * Where the CLI keeps its DPoP key between invocations — the *same* secure backend the session tokens
 * use ([TokenStore]): the OS keychain by default, the chmod-0600 plaintext file only under the
 * explicit CI opt-in (`THORYN_CI_PLAINTEXT_TOKENS=1`).
 *
 * It is a SEPARATE entry from the token bundle on purpose: the key is an installation identity that
 * must survive `thoryn login` / `thoryn logout` cycles (a proof key is useless to an attacker without
 * a matching token), while the token bundle is the session. `thoryn logout --rotate-key` deletes it.
 */
interface DpopKeyStore {
    fun read(): StoredDpopKey?
    fun write(key: StoredDpopKey)
    fun delete()
}

/**
 * OS-keychain-backed [DpopKeyStore] — the production default. Stored as a single JSON entry under the
 * same keychain *service* as the tokens ([KeychainTokenStore.SERVICE]) with its own *account*
 * ([ACCOUNT]), so it shows up as one extra row and can be deleted independently.
 */
class KeychainDpopKeyStore(
    private val keychain: KeychainAccess,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
    private val service: String = KeychainTokenStore.SERVICE,
    private val account: String = ACCOUNT,
) : DpopKeyStore {

    override fun read(): StoredDpopKey? =
        try {
            val json = keychain.getPassword(service, account)
            if (json.isNullOrBlank()) null else mapper.readValue(json, StoredDpopKey::class.java)
        } catch (_: PasswordAccessException) {
            null // no entry yet, or the OS denied the read — treat as "no key", one is generated.
        } catch (_: Exception) {
            null // corrupt payload (manual keychain edit, schema drift) — regenerate rather than fail.
        }

    override fun write(key: StoredDpopKey) {
        keychain.setPassword(service, account, mapper.writeValueAsString(key))
    }

    override fun delete() {
        try {
            keychain.deletePassword(service, account)
        } catch (_: PasswordAccessException) {
            // Best effort — deleting an entry that never existed must not fail `thoryn logout`.
        }
    }

    companion object {
        /** Keychain "account" for the DPoP key row (the tokens live under `tokens`). */
        const val ACCOUNT: String = "dpop-key"
    }
}

/**
 * Plaintext file [DpopKeyStore], POSIX 0600 — the CI-only counterpart of [FileTokenStore], selected by
 * exactly the same opt-in ([DpopKeyStoreFactory]). Defaults to `dpop-key.json` **beside** the token
 * file, so a runner that redirects `THORYN_TOKEN_FILE` to a scratch dir keeps both artefacts together;
 * `THORYN_DPOP_KEY_FILE` overrides the path directly.
 */
class FileDpopKeyStore(
    private val path: Path = defaultPath(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) : DpopKeyStore {

    override fun read(): StoredDpopKey? {
        if (!path.exists()) return null
        return try {
            mapper.readValue(path.toFile(), StoredDpopKey::class.java)
        } catch (_: Exception) {
            null
        }
    }

    override fun write(key: StoredDpopKey) {
        path.parent?.let { Files.createDirectories(it) }
        Files.writeString(
            path,
            mapper.writeValueAsString(key),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
        applyOwnerOnlyPermissions(path)
    }

    override fun delete() {
        try {
            Files.deleteIfExists(path)
        } catch (_: IOException) {
            // Best effort, as in FileTokenStore.delete().
        }
    }

    private fun applyOwnerOnlyPermissions(path: Path) {
        if (!path.fileSystem.supportedFileAttributeViews().contains("posix")) return
        Files.setPosixFilePermissions(
            path,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        )
    }

    companion object {
        /** Explicit path override for the plaintext key file (CI / tests). */
        const val OVERRIDE_ENV_VAR: String = "THORYN_DPOP_KEY_FILE"

        fun defaultPath(): Path {
            TokenStoreFactory.environment(OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
            // Sibling of the token file so an overridden THORYN_TOKEN_FILE carries the key with it.
            val tokens = FileTokenStore.defaultPath()
            return tokens.resolveSibling("dpop-key.json")
        }
    }
}

/**
 * Picks the [DpopKeyStore] for the current environment, using **the same decision tree** as
 * [TokenStoreFactory] so the DPoP key never lands in a weaker place than the tokens it proves
 * possession for:
 *
 *  1. `THORYN_CI_PLAINTEXT_TOKENS=1` → [FileDpopKeyStore] (with the same WARNING).
 *  2. Keychain backend available → [KeychainDpopKeyStore].
 *  3. No keychain **and** `THORYN_TOKEN_FILE` / `THORYN_DPOP_KEY_FILE` set → [FileDpopKeyStore].
 *  4. Otherwise → [TokenStoreUnavailableException]. [Dpop] catches it and simply sends **no** proof,
 *     which is the pre-SSO-3199 behaviour — the CLI must not start failing commands on a box whose
 *     keychain is missing, and such a box cannot hold a session at all (the token store throws first).
 */
object DpopKeyStoreFactory {

    private val log: Logger = Logger.getLogger(DpopKeyStoreFactory::class.java.name)

    /** Test seam — substitute an in-memory store without touching the real keychain. */
    internal var override: (() -> DpopKeyStore)? = null

    fun default(): DpopKeyStore {
        override?.let { return it() }

        if (TokenStoreFactory.isPlaintextOptIn()) {
            log.warning(
                "Using the plaintext file store for the DPoP key. This violates ADR 2026-04-25 §4. " +
                    "Only safe in CI; set THORYN_CI_PLAINTEXT_TOKENS=1 to acknowledge.",
            )
            return FileDpopKeyStore()
        }

        return try {
            KeychainDpopKeyStore(TokenStoreFactory.keychainProvider())
        } catch (e: BackendNotSupportedException) {
            val escape = TokenStoreFactory.environment(FileDpopKeyStore.OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }
                ?: TokenStoreFactory.environment(TokenStoreFactory.FILE_PATH_ENV_VAR)?.takeIf { it.isNotBlank() }
            if (escape != null) {
                log.warning(
                    "OS keychain backend unavailable (${e.message ?: e.javaClass.simpleName}); storing the " +
                        "DPoP key in a plaintext file because an explicit file path is set. " +
                        "Dev/test escape hatch only.",
                )
                return FileDpopKeyStore()
            }
            throw TokenStoreUnavailableException(
                "OS keychain backend is not available on this platform " +
                    "(${e.message ?: e.javaClass.simpleName}); the CLI refuses to write its DPoP private " +
                    "key to a plaintext file without an explicit opt-in " +
                    "(${TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR}=1, CI use only).",
                e,
            )
        }
    }
}
