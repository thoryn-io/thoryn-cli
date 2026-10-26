package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/**
 * SSO-3991 (workflow contract v2 §3; thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13.4) — the
 * `import-summary.json` the reusable workflow's `import` job uploads in the [ProvisioningWorkflowContract.IMPORT_ARTIFACT]
 * artifact beside the imported files, and the shape check of that artifact before it is uploaded.
 *
 * The job, for the i-th entry of `.thoryn/workflow.yaml`'s `files` (in order), copies the committed file to
 * `<artifact>/<file>`, runs `provision import --for-workflow <file> --file <artifact>/<file> --write --output json` into
 * `<work>/<i>.import.json`, and `provision plan --file <artifact>/<file> --output json` into `<work>/<i>.plan.json` (its exit
 * code into `<work>/<i>.plan.exit`). [build] turns that into the summary.
 *
 * WHAT THE SUMMARY CARRIES — a FIXED field list, never a value of the configuration: per file its path, connection,
 * `apiVersion`, size and SHA-256; each imported entry as `{kind, name, environment, readOnly, note}` (the `spec` stays in the
 * file, which the CLI renders from a fixed field list per kind and where a person reviews it in the diff); the *not imported*
 * lines the CLI printed (its own wording: kind, name, reason); and the plan preview's counts with each row that is not `noop`
 * as `{kind, name, environment, action, fields}` — the changed field NAMES, never their old or new values. No secret can
 * reach it: the API returns none, and nothing here copies a value out of a `spec` or a plan diff.
 *
 * WHAT IS REFUSED (exit [com.devnow.thoryn.cli.cmd.CommandSupport.EXIT_CHECK_FAILED], nothing uploaded): an artifact
 * directory holding anything but the configured files (a stray file, a symbolic link), a configured file missing from it or
 * not loading, a file over [MAX_FILE_BYTES], a summary over [MAX_SUMMARY_BYTES], an artifact over [MAX_ARTIFACT_BYTES], a
 * plan preview that did not run, a `head_sha` that is not a commit. The App validates the same shape on download (§13.4);
 * refusing here first means a run never hands it something it would refuse.
 */
object ImportSummary {

    /** The summary's own format version (contract v2 §3: `version: 1`). */
    const val VERSION: Int = 1

    /** One imported provisioning file. A tenant file is a few KiB; a megabyte is far past any real one. */
    const val MAX_FILE_BYTES: Long = 1L shl 20

    /** `import-summary.json` itself. */
    const val MAX_SUMMARY_BYTES: Long = 1L shl 20

    /** The whole artifact: every file plus the summary. */
    const val MAX_ARTIFACT_BYTES: Long = 8L shl 20

    private val COMMIT = Regex("^([0-9a-f]{40}|[0-9a-f]{64})$")
    private val json = JsonMapper.builder().build()

    class ImportSummaryException(message: String) : RuntimeException(message)

    /** The i-th configured file's work outputs. */
    fun importJson(work: File, index: Int) = File(work, "$index.import.json")
    fun planJson(work: File, index: Int) = File(work, "$index.plan.json")
    fun planExit(work: File, index: Int) = File(work, "$index.plan.exit")

    /**
     * The summary for [config]'s files, read from [artifact] (the copies) and [work] (the import and plan JSON). Every
     * problem is an [ImportSummaryException] naming the file and what is wrong.
     */
    fun build(headSha: String, config: WorkflowConfig, artifact: File, work: File): Map<String, Any?> {
        if (!COMMIT.matches(headSha)) throw ImportSummaryException("head_sha '$headSha' is not a commit SHA")
        val paths = config.files.map { it.file }
        paths.groupBy { normalize(it) }.filterValues { it.size > 1 }.keys.firstOrNull()?.let {
            throw ImportSummaryException("$it is configured more than once in ${config.source ?: WorkflowConfig.DEFAULT_PATH}; the import gives each file one home")
        }
        checkArtifactShape(artifact, paths.map { normalize(it) }.toSet())
        val files = config.files.mapIndexed { i, entry -> fileSummary(entry, i, artifact, work) }
        return linkedMapOf(
            "version" to VERSION,
            "contractVersion" to ProvisioningWorkflowContract.CONTRACT_VERSION,
            "headSha" to headSha,
            "files" to files,
        )
    }

    /** Write [summary] as `<artifact>/import-summary.json`, refusing it over [MAX_SUMMARY_BYTES] or a whole artifact over [MAX_ARTIFACT_BYTES]. */
    fun write(summary: Map<String, Any?>, artifact: File): File {
        val bytes = json.writerWithDefaultPrettyPrinter().writeValueAsBytes(summary) + '\n'.code.toByte()
        if (bytes.size > MAX_SUMMARY_BYTES) throw ImportSummaryException("${ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE} would be ${bytes.size} bytes, over the $MAX_SUMMARY_BYTES-byte bound")
        val filesBytes = artifact.walkTopDown().filter { it.isFile }.sumOf { it.length() }
        if (filesBytes + bytes.size > MAX_ARTIFACT_BYTES) throw ImportSummaryException("the $IMPORT artifact would be ${filesBytes + bytes.size} bytes, over the $MAX_ARTIFACT_BYTES-byte bound")
        return File(artifact, ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE).also { it.writeBytes(bytes) }
    }

    /** A short human account of [summary], for the job's step summary. */
    fun render(summary: Map<String, Any?>): String = buildString {
        appendLine("## Thoryn configuration import")
        appendLine()
        appendLine("Imported at `${summary["headSha"]}` as this repository's own read-only plan identity. Nothing was written to the repository; the files and `${ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE}` are the `$IMPORT` artifact.")
        @Suppress("UNCHECKED_CAST")
        (summary["files"] as List<Map<String, Any?>>).forEach { f ->
            @Suppress("UNCHECKED_CAST") val imported = f["imported"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST") val notImported = f["notImported"] as List<String>
            @Suppress("UNCHECKED_CAST") val plan = f["plan"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST") val notNoop = plan["notNoop"] as List<Map<String, Any?>>
            appendLine()
            appendLine("### ${f["path"]}")
            appendLine()
            appendLine("- imported: ${imported.size} entry(ies), ${imported.count { it["readOnly"] == true }} read-only")
            imported.forEach { e -> appendLine("  - ${e["kind"]} ${e["name"]}${e["environment"]?.let { " ($it)" } ?: ""}${if (e["readOnly"] == true) " — read-only" else ""}${e["note"]?.let { ": $it" } ?: ""}") }
            appendLine("- not imported: ${notImported.size}")
            notImported.forEach { appendLine("  - $it") }
            appendLine("- plan preview: " + if (plan["allNoop"] == true) "every row unchanged" else "${notNoop.size} row(s) not unchanged — the import could not reproduce them exactly")
            notNoop.forEach { r -> appendLine("  - ${r["action"]} ${r["kind"]} ${r["name"]}${r["environment"]?.let { " ($it)" } ?: ""}") }
        }
    }

    private const val IMPORT = ProvisioningWorkflowContract.IMPORT_ARTIFACT

    /** Exactly the configured files, as regular files — nothing else, no link, no leftover summary. */
    private fun checkArtifactShape(artifact: File, configured: Set<String>) {
        if (!artifact.isDirectory) throw ImportSummaryException("the artifact directory ${artifact.path} does not exist")
        val root = artifact.toPath()
        Files.walk(root).use { stream ->
            stream.filter { it != root }.forEach { p ->
                val rel = root.relativize(p).toString().replace(File.separatorChar, '/')
                if (Files.isSymbolicLink(p)) throw ImportSummaryException("$rel in the artifact directory is a symbolic link; the artifact holds only the imported files")
                if (Files.isRegularFile(p) && rel !in configured) throw ImportSummaryException("$rel in the artifact directory is not a configured provisioning file; the artifact holds only those and ${ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE}")
            }
        }
        configured.forEach { if (!File(artifact, it).isFile) throw ImportSummaryException("$it is configured but was not imported into the artifact directory") }
    }

    private fun fileSummary(entry: WorkflowConfig.FileEntry, index: Int, artifact: File, work: File): Map<String, Any?> {
        val path = normalize(entry.file)
        val copy = File(artifact, path)
        val bytes = copy.readBytes()
        if (bytes.size > MAX_FILE_BYTES) throw ImportSummaryException("$path is ${bytes.size} bytes after the import, over the $MAX_FILE_BYTES-byte bound")
        val loaded = try {
            ProvisionFile.parse(bytes, path, yaml = !path.endsWith(".json", ignoreCase = true))
        } catch (ex: ProvisionException) {
            throw ImportSummaryException("$path does not load after the import: ${ex.message?.lineSequence()?.first()}")
        }
        val imported = readJson(importJson(work, index), "the import of $path")
        val plan = readJson(planJson(work, index), "the plan preview of $path")
        if (plan["summary"]?.isObject != true) throw ImportSummaryException("the plan preview of $path did not run (exit ${planExitOf(work, index) ?: "unknown"}); its output is not a plan — see the job log")
        return linkedMapOf(
            "path" to path,
            "connection" to entry.connection,
            "apiVersion" to loaded.part.apiVersion,
            "bytes" to bytes.size,
            "sha256" to sha256(bytes),
            "imported" to (imported["resources"]?.takeIf { it.isArray }?.toList()?.map { r -> entryOf(r) } ?: emptyList<Map<String, Any?>>()),
            "notImported" to (imported["skipped"]?.takeIf { it.isArray }?.toList()?.mapNotNull { it.takeIf { n -> n.isString }?.asString() } ?: emptyList()),
            "plan" to planPreview(plan, planExitOf(work, index)),
        )
    }

    /** One imported entry, the allow-listed fields only. A singleton is rendered without `name`; its name is its kind. */
    private fun entryOf(r: JsonNode): Map<String, Any?> {
        val kind = r["kind"].strOrNull() ?: throw ImportSummaryException("an imported entry carries no kind")
        return linkedMapOf(
            "kind" to kind,
            "name" to (r["name"].strOrNull() ?: kind),
            "environment" to r["environment"].strOrNull(),
            "readOnly" to (r[ProvisionFile.READ_ONLY]?.asBoolean() ?: false),
            "note" to r["note"].strOrNull(),
        )
    }

    /** The plan's counts, and each row that is not `noop` with the NAMES of the fields that differ — never their values. */
    private fun planPreview(plan: JsonNode, exit: Int?): Map<String, Any?> {
        val counts = linkedMapOf<String, Any?>()
        plan["summary"].properties().forEach { (k, v) -> if (v.isIntegralNumber) counts[k] = v.asInt() }
        val notNoop = plan["changes"]?.takeIf { it.isArray }?.toList()?.filter { it["action"].strOrNull() != "noop" }?.map { c ->
            linkedMapOf(
                "kind" to c["kind"].strOrNull(),
                "name" to c["name"].strOrNull(),
                "environment" to c["environment"].strOrNull(),
                "action" to c["action"].strOrNull(),
                "fields" to (c["diff"]?.takeIf { it.isObject }?.propertyNames()?.toList() ?: emptyList()),
            )
        } ?: emptyList()
        val quiet = listOf("create", "update", "remove", "grants", "error", "publish").all { (counts[it] as? Int ?: 0) == 0 }
        return linkedMapOf("exit" to exit, "counts" to counts, "allNoop" to (notNoop.isEmpty() && quiet), "notNoop" to notNoop)
    }

    private fun readJson(file: File, what: String): JsonNode {
        if (!file.isFile) throw ImportSummaryException("$what produced no output (${file.path} is missing) — see the job log")
        val node = try { json.readTree(file) } catch (ex: Exception) { null }
        return node?.takeIf { it.isObject } ?: throw ImportSummaryException("$what did not print a JSON document — see the job log")
    }

    private fun planExitOf(work: File, index: Int): Int? = planExit(work, index).takeIf { it.isFile }?.readText()?.trim()?.toIntOrNull()

    private fun JsonNode?.strOrNull(): String? = this?.takeIf { it.isString }?.asString()

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun normalize(path: String): String = File(path).normalize().path.replace(File.separatorChar, '/').removePrefix("./")
}
