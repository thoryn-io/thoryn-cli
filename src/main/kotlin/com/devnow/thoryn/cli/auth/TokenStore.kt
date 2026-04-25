package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * Where the CLI keeps the user's tokens between invocations.
 *
 * The scaffold uses a chmod-600 file under `~/.config/thoryn/tokens.json`
 * (Linux/macOS) or `%APPDATA%/thoryn/tokens.json` (Windows). This is *not*
 * the OS keychain — that lands as a follow-up using `java-keyring` or a
 * platform-specific shim. The interface here is what the keychain
 * implementation will satisfy when it does.
 *
 * Override the location with `THORYN_TOKEN_FILE=/path/to/tokens.json` —
 * useful in CI runners where neither the home directory nor a keychain is
 * available, and for tests that don't want to scribble in the user's home.
 */
interface TokenStore {
    fun read(): Tokens?
    fun write(tokens: Tokens)
    fun delete()
}

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
        const val OVERRIDE_ENV_VAR = "THORYN_TOKEN_FILE"

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
