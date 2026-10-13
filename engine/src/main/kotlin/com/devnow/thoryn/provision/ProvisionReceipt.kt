package com.devnow.thoryn.provision

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
 * Same model as the CLI's recipe `Receipt` (SSO-2875): ids and
 * non-secret attributes only — never a password, client secret, or token.
 */
data class ProvisionReceipt(
    val schemaVersion: String = SCHEMA_VERSION,
    val file: ProvisionFileRef,
    val appliedAt: String,
    val cliVersion: String? = null,
    /** The workspace slug the session was bound to at apply time (display/audit only). */
    val workspace: String? = null,
    /**
     * SSO-3659 (ADR 2026-10-13 §1, "one owning repository per resource") — the platform subject that applied
     * this receipt (`client:<clientId>` for a machine identity such as a repository's workload-identity
     * client, `member:<sub>` for a person), derived from the token exactly as product-api derives the
     * caller. This is the OWNERSHIP MARKER another repository's `plan` compares against when it is handed
     * this receipt as a peer (`--peer-receipt`): a resource recorded here as owned is `access_owned_elsewhere`
     * for every other subject. Absent on a pre-SSO-3659 receipt (the resources it records still count as
     * owned by that receipt). Not a secret.
     */
    val subject: String? = null,
    val resources: List<OwnedResource> = emptyList(),
) {
    companion object {
        const val SCHEMA_VERSION: String = "thoryn.io/provision/receipt/v1"
    }
}

data class ProvisionFileRef(val path: String, val digest: String)

/**
 * One resource the file owns: its `kind` + `name` (the converge key), the server id, the environment
 * SLUG it lives in (`null` ⇒ production plane; an `environment` resource records its own slug under
 * `attributes.slug`), and non-secret attributes.
 */
data class OwnedResource(
    val kind: String,
    val name: String,
    val id: String,
    val environment: String? = null,
    val attributes: Map<String, String> = emptyMap(),
    /**
     * SSO-3119 — the access grants (`<subject> <relation>`) THIS FILE created on this object, so a later
     * apply revokes only what it granted itself. The same "only removes what it created" rule [adopted]
     * states for resources: a grant the file merely found live (the creator's own `member:<sub> manager`
     * from SSO-3110's creator-becomes-manager, a grant an admin placed by hand) is never revoked, even
     * when the file's `grants:` block does not mention it. Absent on a pre-SSO-3119 receipt ⇒ the file
     * owns no grant yet ⇒ it revokes nothing, which is the safe direction.
     */
    val grants: List<String> = emptyList(),
    /**
     * SSO-3089 — true when the resource already existed (matched live by its converge key) and was
     * ADOPTED under management rather than created by this file. `apply` converges it, but `destroy`
     * / `--prune` NEVER delete it: the CLI only removes what it created.
     */
    val adopted: Boolean = false,
    /**
     * SSO-3668 — the outputs the last `apply` PUBLISHED for this resource (where its id landed), so a reader
     * of the receipt — a reviewer, `plan`, the human running the fallback — sees which repository /
     * environment / variable carries the id. Only targets that were actually reached are listed; a target
     * that could not be reached is the apply error `publish_target_unreachable` and is not recorded. Never a
     * secret: a published value is a client id, public by construction. Absent on a pre-SSO-3668 receipt.
     */
    val published: List<PublishedOutput> = emptyList(),
) {
    val key: String get() = "$kind/$name"
}

/** SSO-3668 — one output a resource's id was published to (the receipt's record of a [PublishTarget]). */
data class PublishedOutput(val kind: String, val repository: String, val environment: String, val name: String) {
    companion object {
        fun of(target: PublishTarget): PublishedOutput = PublishedOutput(target.kind, target.repository, target.environment, target.name)
    }
}

/**
 * The receipt lives NEXT TO the file it records — `provision.yaml` → `provision.receipt.json` — so a
 * CI job's destroy step (and a customer's next `apply`) finds it without any per-user state, and it
 * stays portable with the repository. Override the path with `--receipt`.
 */
class ProvisionReceiptStore(private val mapper: ObjectMapper = jacksonObjectMapper()) {

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
