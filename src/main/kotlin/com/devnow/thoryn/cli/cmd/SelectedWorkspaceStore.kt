package com.devnow.thoryn.cli.cmd

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * SSO-1552 — records which workspace the CLI is "switched into".
 *
 * `thoryn workspace switch <slug>` (a) validates the workspace exists and that
 * we are an active member (via a throwaway token exchange), then (b) persists the
 * selected workspace here. It does NOT touch the token store.
 *
 * SSO-2863 — this record is load-bearing: `CommandSupport.gatewayClient` reads it
 * and, when a workspace is selected, mints a token FOR that tenant by exchanging
 * the *refreshable base session* token on demand (per command, re-exchanging on a
 * 401). That keeps the switched session alive as long as the base login (8h/7d)
 * instead of dying at the ~15-minute, non-refreshable exchanged token that the old
 * clobber-the-session-token approach produced.
 *
 * This file carries NO secret — only the chosen `tenantId` / `slug` / derived
 * tenant-hub issuer. The token store remains the source of truth for the
 * refreshable base bearer; this names which tenant to exchange into.
 *
 * Stored next to the plaintext token file (`~/.config/thoryn/workspace.json` on
 * Linux/macOS, `%APPDATA%/thoryn/workspace.json` on Windows). Override with
 * `THORYN_WORKSPACE_FILE` (used by tests).
 */
internal class SelectedWorkspaceStore(
    private val path: Path = defaultPath(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    fun read(): SelectedWorkspace? {
        if (!path.exists()) return null
        return try {
            mapper.readValue<SelectedWorkspace>(path.toFile())
        } catch (_: Exception) {
            null
        }
    }

    fun write(selected: SelectedWorkspace) {
        path.parent?.let { Files.createDirectories(it) }
        Files.writeString(
            path,
            mapper.writeValueAsString(selected),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
    }

    /**
     * SSO-2863 — drop any active workspace selection. Called on `thoryn login` (a fresh login resets
     * the base tenant, so a stale selection must not silently re-exchange into an old workspace).
     * Best-effort: a missing file or unreadable path is a no-op.
     */
    fun clear() {
        runCatching { Files.deleteIfExists(path) }
    }

    companion object {
        const val OVERRIDE_ENV_VAR: String = "THORYN_WORKSPACE_FILE"

        fun defaultPath(): Path {
            System.getenv(OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
            val home = System.getProperty("user.home") ?: error("user.home is not set")
            val isWindows = System.getProperty("os.name", "").startsWith("Windows", ignoreCase = true)
            return if (isWindows) {
                val appData = System.getenv("APPDATA") ?: "$home/AppData/Roaming"
                Path("$appData/thoryn/workspace.json")
            } else {
                Path("$home/.config/thoryn/workspace.json")
            }
        }
    }
}

/** The CLI's currently-selected workspace. Carries no secret. */
data class SelectedWorkspace(
    val tenantId: String,
    val slug: String,
    /** Tenant hub issuer derived as `{slug}.{hubHost}` — the `--issuer` for re-auth. */
    val tenantHubIssuer: String,
)
