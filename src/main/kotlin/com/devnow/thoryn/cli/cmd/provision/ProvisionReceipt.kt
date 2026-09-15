package com.devnow.thoryn.cli.cmd.provision

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption

/**
 * SSO-3088 (epic SSO-3087) — the **provisioning receipt**: the secret-free record of what a
 * provisioning file OWNS in the caller's account. `thoryn provision destroy` and `apply --prune` act
 * ONLY on ids recorded here, so the CLI never deletes a resource it did not create through the file.
 * Same model as the recipe [com.devnow.thoryn.cli.cmd.examples.recipe.Receipt] (SSO-2875): ids and
 * non-secret attributes only — never a password, client secret, or token.
 */
internal data class ProvisionReceipt(
    val schemaVersion: String = SCHEMA_VERSION,
    val file: ProvisionFileRef,
    val appliedAt: String,
    val cliVersion: String? = null,
    /** The workspace slug the session was bound to at apply time (display/audit only). */
    val workspace: String? = null,
    val resources: List<OwnedResource> = emptyList(),
) {
    companion object {
        const val SCHEMA_VERSION: String = "thoryn.io/provision/receipt/v1"
    }
}

internal data class ProvisionFileRef(val path: String, val digest: String)

/**
 * One resource the file owns: its `kind` + `name` (the converge key), the server id, the environment
 * SLUG it lives in (`null` ⇒ production plane; an `environment` resource records its own slug under
 * `attributes.slug`), and non-secret attributes.
 */
internal data class OwnedResource(
    val kind: String,
    val name: String,
    val id: String,
    val environment: String? = null,
    val attributes: Map<String, String> = emptyMap(),
) {
    val key: String get() = "$kind/$name"
}

/**
 * The receipt lives NEXT TO the file it records — `provision.yaml` → `provision.receipt.json` — so a
 * CI job's destroy step (and a customer's next `apply`) finds it without any per-user state, and it
 * stays portable with the repository. Override the path with `--receipt`.
 */
internal class ProvisionReceiptStore(private val mapper: ObjectMapper = jacksonObjectMapper()) {

    fun defaultPathFor(file: File): File {
        val base = file.name.substringBeforeLast('.', file.name)
        return File(file.absoluteFile.parentFile, "$base.receipt.json")
    }

    fun read(path: File): ProvisionReceipt? {
        if (!path.isFile) return null
        return try {
            mapper.readValue<ProvisionReceipt>(path)
        } catch (e: Exception) {
            throw ProvisionException("could not read provisioning receipt '${path.path}': ${e.message}")
        }
    }

    fun write(path: File, receipt: ProvisionReceipt) {
        path.absoluteFile.parentFile?.let { Files.createDirectories(it.toPath()) }
        Files.writeString(
            path.toPath(),
            mapper.writerWithDefaultPrettyPrinter().writeValueAsString(receipt) + "\n",
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
    }

    fun delete(path: File) {
        runCatching { Files.deleteIfExists(path.toPath()) }
    }
}
