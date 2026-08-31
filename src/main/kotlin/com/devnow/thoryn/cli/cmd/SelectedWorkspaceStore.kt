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
 * Unlike the web console, the CLI has no browser session: a workspace switch is
 * fundamentally a re-authentication against the tenant's hub subdomain (the
 * `loginUrl` the hub returns is a console-relative OIDC path the CLI cannot
 * drive). `thoryn workspace switch <slug>` therefore (a) validates the
 * workspace exists, (b) persists the selected workspace here, and (c) prints the
 * exact `thoryn login --issuer <tenant-hub>` line to mint a token carrying the
 * new `tnt`.
 *
 * This file carries NO secret — only the chosen `tenantId` / `slug` / derived
 * tenant-hub issuer. It is informational state (so a later command can show
 * "you last switched to …"), not an auth artefact; the token store remains the
 * source of truth for the active bearer.
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
