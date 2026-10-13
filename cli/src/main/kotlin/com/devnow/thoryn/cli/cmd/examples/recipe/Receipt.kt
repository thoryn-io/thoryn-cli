package com.devnow.thoryn.cli.cmd.examples.recipe

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * SSO-2871 Phase 3 (SSO-2875) — a **receipt**: a portable, verifiable record of exactly what a recipe
 * run provisioned in the caller's account. Local always (this file); a platform-signed
 * [attestation] is layered on when the platform is reachable (Phase 3b, the attestation endpoint).
 *
 * Carries NO secret: server-minted secrets are written to files by the CLI and referenced here only
 * as [SecretRef] paths — never their values.
 */
internal data class Receipt(
    val schemaVersion: String = SCHEMA_VERSION,
    val recipe: RecipeRef,
    val appliedAt: String,
    val cliVersion: String? = null,
    /** The founder's token `sub` at apply time (display/audit only). */
    val subject: String? = null,
    val workspace: WorkspaceRef,
    /** The environment the run targeted (Phase 4); `null` ⇒ the production plane. */
    val environment: String? = null,
    val resources: List<ResourceRef> = emptyList(),
    val secretRefs: List<SecretRef> = emptyList(),
    val verify: List<VerifyResult> = emptyList(),
    /** SSO-2875 (Phase 3b) — the platform's signed attestation over this receipt; `null` until signed. */
    val attestation: Attestation? = null,
) {
    companion object {
        const val SCHEMA_VERSION: String = "thoryn.io/examples/receipt/v1"
    }
}

internal data class RecipeRef(val id: String, val version: String, val digest: String)
internal data class WorkspaceRef(val slug: String?, val tenantId: String?)
internal data class ResourceRef(val kind: String, val id: String, val attributes: Map<String, String> = emptyMap())
internal data class SecretRef(val kind: String, val path: String)
internal data class VerifyResult(val assert: String, val id: String?, val expect: Map<String, String> = emptyMap(), val passed: Boolean)

/** SSO-2875 Phase 3b — the platform's detached-JWS attestation over the receipt's canonical payload. */
internal data class Attestation(
    val kid: String,
    val signature: String,
    val canonicalPayload: String,
    val attestedAt: String,
)

/**
 * Stores one receipt per recipe id under `~/.config/thoryn/receipts/<id>.json` (next to the token
 * file). Override the directory with `THORYN_RECEIPTS_DIR` (used by tests).
 */
internal class ReceiptStore(
    private val dir: Path = defaultDir(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {
    fun read(recipeId: String): Receipt? {
        val path = pathFor(recipeId)
        if (!path.exists()) return null
        return try {
            mapper.readValue<Receipt>(path.toFile())
        } catch (_: Exception) {
            null
        }
    }

    fun write(receipt: Receipt) {
        Files.createDirectories(dir)
        Files.writeString(
            pathFor(receipt.recipe.id),
            mapper.writeValueAsString(receipt),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
    }

    fun clear(recipeId: String) {
        runCatching { Files.deleteIfExists(pathFor(recipeId)) }
    }

    private fun pathFor(recipeId: String): Path = dir.resolve("$recipeId.json")

    companion object {
        const val OVERRIDE_ENV_VAR: String = "THORYN_RECEIPTS_DIR"

        fun defaultDir(): Path {
            System.getenv(OVERRIDE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
            val home = System.getProperty("user.home") ?: error("user.home is not set")
            val isWindows = System.getProperty("os.name", "").startsWith("Windows", ignoreCase = true)
            return if (isWindows) {
                Path("${System.getenv("APPDATA") ?: "$home/AppData/Roaming"}/thoryn/receipts")
            } else {
                Path("$home/.config/thoryn/receipts")
            }
        }
    }
}
