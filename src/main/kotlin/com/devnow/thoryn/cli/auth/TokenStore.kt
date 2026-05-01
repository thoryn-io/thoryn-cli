package com.devnow.thoryn.cli.auth

import com.github.javakeyring.BackendNotSupportedException
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.logging.Logger
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * Where the CLI keeps the user's tokens between invocations.
 *
 * The default implementation is [KeychainTokenStore] — tokens live in the OS
 * credential vault (macOS Keychain, Linux Secret Service, Windows Credential
 * Manager) per ADR 2026-04-25 §4. [FileTokenStore] (chmod-0600 JSON file) is
 * still available but only as an explicit CI-only opt-in via
 * `THORYN_CI_PLAINTEXT_TOKENS=1` — see [TokenStoreFactory].
 *
 * Override the file location with `THORYN_TOKEN_FILE=/path/to/tokens.json` —
 * useful in CI runners and tests; ignored unless the plaintext store is
 * actually selected.
 */
interface TokenStore {
    fun read(): Tokens?
    fun write(tokens: Tokens)
    fun delete()
}

/**
 * Plaintext file [TokenStore]. Writes JSON to `~/.config/thoryn/tokens.json`
 * (Linux/macOS) or `%APPDATA%/thoryn/tokens.json` (Windows), POSIX 0600.
 *
 * **This is an opt-in fallback**: it violates ADR 2026-04-25 §4 "tokens are
 * stored in the OS keychain — never in plaintext config files". Use
 * [KeychainTokenStore] in production. [TokenStoreFactory] only returns a
 * [FileTokenStore] when `THORYN_CI_PLAINTEXT_TOKENS=1` is set, or when the
 * keychain backend genuinely isn't available *and* the operator has set
 * `THORYN_TOKEN_FILE` to acknowledge the fallback explicitly.
 */
class FileTokenStore(
    private val path: Path = defaultPath(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) : TokenStore {

    override fun read(): Tokens? {
        if (!path.exists()) return null
        return try {
            mapper.readValue(path.toFile(), Tokens::class.java)
        } catch (_: Exception) {
            null
        }
    }

    override fun write(tokens: Tokens) {
        Files.createDirectories(path.parent)
        Files.writeString(
            path,
            mapper.writeValueAsString(tokens),
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
            // Best effort — if the file can't be removed (locked on Windows,
            // permission issue), leave it. The next `thoryn login` overwrites it.
        }
    }

    /**
     * On POSIX systems set the file to `0600` so the tokens are only readable
     * by the current user. No-op on Windows (uses ACLs, not POSIX bits).
     */
    private fun applyOwnerOnlyPermissions(path: Path) {
        val supportsPosix = path.fileSystem.supportedFileAttributeViews().contains("posix")
        if (!supportsPosix) return
        val perms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        Files.setPosixFilePermissions(path, perms)
        @Suppress("UNUSED_VARIABLE")
        val unused = PosixFilePermissions.toString(perms)
    }

    companion object {
        const val OVERRIDE_ENV_VAR: String = "THORYN_TOKEN_FILE"

        fun defaultPath(): Path {
            System.getenv(OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
            val home = System.getProperty("user.home") ?: error("user.home is not set")
            val isWindows = System.getProperty("os.name", "").startsWith("Windows", ignoreCase = true)
            return if (isWindows) {
                val appData = System.getenv("APPDATA") ?: "$home/AppData/Roaming"
                Path("$appData/thoryn/tokens.json")
            } else {
                Path("$home/.config/thoryn/tokens.json")
            }
        }
    }
}

/**
 * Picks the right [TokenStore] implementation for the current environment.
 *
 * Decision tree, in order:
 *
 *  1. **`THORYN_CI_PLAINTEXT_TOKENS=1`** — explicit CI/automation opt-in.
 *     Returns [FileTokenStore]. Logs a `WARNING` so a misconfigured prod box
 *     can be diagnosed from logs.
 *  2. **Keychain backend available** — returns [KeychainTokenStore]. This is
 *     the production default for `oathy` end-users (ADR 2026-04-25 §4).
 *  3. **No keychain backend** *and* `THORYN_TOKEN_FILE` is set — explicit
 *     dev/test escape hatch. Returns [FileTokenStore] with a `WARNING`.
 *  4. **No keychain backend** and no escape hatch — throws
 *     [TokenStoreUnavailableException]. Refusing to silently downgrade to
 *     plaintext is the whole point of SSO-794: a missing keychain on prod
 *     should fail loudly, not write secrets to disk.
 */
object TokenStoreFactory {

    /** Set to "1" (or any non-empty value) to force the plaintext file store. */
    const val PLAINTEXT_OPT_IN_ENV_VAR: String = "THORYN_CI_PLAINTEXT_TOKENS"

    /** Path override for the plaintext file store; only consulted on fallback. */
    const val FILE_PATH_ENV_VAR: String = FileTokenStore.OVERRIDE_ENV_VAR

    private val log: Logger = Logger.getLogger(TokenStoreFactory::class.java.name)

    /**
     * Test seam: returns the [KeychainAccess] used to back a
     * [KeychainTokenStore], or throws [BackendNotSupportedException] when no
     * platform backend is available. Production wraps the real
     * `Keyring.create()`; tests substitute an in-memory stub or simulate the
     * unsupported-backend case without needing a real OS keychain at all.
     */
    internal var keychainProvider: () -> KeychainAccess =
        { JavaKeyringAccess(KeychainTokenStore.openDefault()) }

    /**
     * Test seam: env-var lookup is overridden in tests rather than touching
     * `System.getenv` (no portable in-process way to set env vars on JVM).
     * Production reads from the real environment.
     */
    internal var environment: (String) -> String? = { System.getenv(it) }

    fun default(): TokenStore {
        if (isPlaintextOptIn()) {
            log.warning(
                "Using plaintext file token store. This violates ADR 2026-04-25 §4. " +
                    "Only safe in CI; set THORYN_CI_PLAINTEXT_TOKENS=1 to acknowledge.",
            )
            return FileTokenStore()
        }

        return try {
            KeychainTokenStore(keychainProvider())
        } catch (e: BackendNotSupportedException) {
            handleBackendUnavailable(e)
        }
    }

    private fun handleBackendUnavailable(cause: BackendNotSupportedException): TokenStore {
        val tokenFileEscape = environment(FILE_PATH_ENV_VAR)?.takeIf { it.isNotBlank() }
        if (tokenFileEscape != null) {
            log.warning(
                "OS keychain backend unavailable (${cause.message ?: cause.javaClass.simpleName}); " +
                    "falling back to plaintext file token store at $tokenFileEscape because " +
                    "$FILE_PATH_ENV_VAR is set. This violates ADR 2026-04-25 §4 and is only " +
                    "intended as a dev/test escape hatch.",
            )
            return FileTokenStore()
        }
        throw TokenStoreUnavailableException(
            "OS keychain backend is not available on this platform " +
                "(${cause.message ?: cause.javaClass.simpleName}). The CLI refuses to silently " +
                "downgrade to a plaintext file (ADR 2026-04-25 §4). To opt in explicitly, set " +
                "$PLAINTEXT_OPT_IN_ENV_VAR=1 (CI use only) or set $FILE_PATH_ENV_VAR to a path " +
                "you control (dev/test escape hatch).",
            cause,
        )
    }

    private fun isPlaintextOptIn(): Boolean =
        environment(PLAINTEXT_OPT_IN_ENV_VAR)?.isNotBlank() == true
}

/**
 * Thrown when the CLI cannot find a usable [TokenStore] and the operator has
 * not opted in to a plaintext fallback. Surfaces a clear, actionable error
 * instead of silently writing tokens to disk.
 */
class TokenStoreUnavailableException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)
