package com.devnow.thoryn.cli.cmd.examples

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * SSO-2830 — what an example provisioned, so `run` and `teardown` can find it
 * across CLI invocations. Carries NO secret — only ids (workspace slug/tenant,
 * the RP client id, the tenant hub + identity hosts) — the same shape and trust
 * model as [com.devnow.thoryn.cli.cmd.SelectedWorkspaceStore].
 */
internal data class ExampleState(
    val example: String,
    val workspaceSlug: String? = null,
    val tenantId: String? = null,
    val clientId: String? = null,
    val redirectUri: String? = null,
    val tenantIssuer: String? = null,
    val identityHost: String? = null,
    /**
     * SSO-2961 — the ephemeral sandbox environment an `env.create` step provisioned (its UUID `id` and
     * its own `slug`), so a later `teardown` invocation can hard-delete it via `env.delete`
     * (`DELETE /api/v1/environments/{id}` with `X-Thoryn-Confirm: <slug>`). Null when the recipe
     * created no environment. Ids only — the same secret-free trust model as the rest of this state.
     */
    val environmentId: String? = null,
    val environmentSlug: String? = null,
)

/**
 * Per-example JSON state, stored next to the token/workspace files under
 * `~/.config/thoryn/examples/<name>.json` (Linux/macOS) or
 * `%APPDATA%/thoryn/examples/<name>.json` (Windows). Override the directory with
 * `THORYN_EXAMPLES_DIR` (used by tests).
 */
internal class ExampleStateStore(
    private val dir: Path = defaultDir(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    fun read(exampleName: String): ExampleState? {
        val path = pathFor(exampleName)
        if (!path.exists()) return null
        return try {
            mapper.readValue<ExampleState>(path.toFile())
        } catch (_: Exception) {
            null
        }
    }

    fun write(state: ExampleState) {
        Files.createDirectories(dir)
        val path = pathFor(state.example)
        Files.writeString(
            path,
            mapper.writeValueAsString(state),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
    }

    fun clear(exampleName: String) {
        try {
            Files.deleteIfExists(pathFor(exampleName))
        } catch (_: Exception) {
            // best effort — the next setup overwrites it
        }
    }

    private fun pathFor(exampleName: String): Path = dir.resolve("$exampleName.json")

    companion object {
        const val OVERRIDE_ENV_VAR: String = "THORYN_EXAMPLES_DIR"

        fun defaultDir(): Path {
            System.getenv(OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
            val home = System.getProperty("user.home") ?: error("user.home is not set")
            val isWindows = System.getProperty("os.name", "").startsWith("Windows", ignoreCase = true)
            return if (isWindows) {
                val appData = System.getenv("APPDATA") ?: "$home/AppData/Roaming"
                Path("$appData/thoryn/examples")
            } else {
                Path("$home/.config/thoryn/examples")
            }
        }
    }
}
