package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.ImportSummary.ImportSummaryException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import tools.jackson.databind.json.JsonMapper
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * SSO-3991 — `import-summary.json` (contract v2 §3): built from the import and plan JSON the job wrote, it carries a FIXED
 * field list — so a value that reaches the CLI's JSON output (a `spec`, a plan diff) never reaches the summary — and the
 * artifact directory is refused unless it holds exactly the configured files, each loading and within the size bound.
 */
class ImportSummaryTest {

    @TempDir lateinit var tmp: Path

    private val sha = "0123456789abcdef0123456789abcdef01234567"
    private val prodFile = ".thoryn/environments/production/provision.yaml"
    private val sbxFile = ".thoryn/environments/sbx/provision.yaml"
    private val config = WorkflowConfig.parse(
        "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - { file: $prodFile, connection: .thoryn/environments/production/connection.json }\n" +
            "  - { file: $sbxFile, connection: .thoryn/environments/sbx/connection.json }\n",
        ".thoryn/workflow.yaml",
    )
    private val tenantYaml = "apiVersion: thoryn.io/tenant/v1\nresources:\n  - { kind: role, name: editor, spec: { permissions: [docs:write] } }\n"
    private val secret = "SECRET-VALUE-must-never-appear"

    private fun artifact() = tmp.resolve("artifact").toFile()
    private fun work() = tmp.resolve("work").toFile().also { it.mkdirs() }

    /** A job's outputs for both files: the copies, the import JSON (with secret-shaped extras), the plan JSON. */
    private fun jobOutputs(planChanges: String = """[{"kind":"role","name":"editor","action":"noop","environment":null}]""", planSummary: String = """{"create":0,"update":0,"remove":0,"noop":1,"skip":0,"grants":0,"error":0,"publish":0}""") {
        listOf(prodFile, sbxFile).forEachIndexed { i, path ->
            File(artifact(), path).also { it.parentFile.mkdirs(); it.writeText(tenantYaml) }
            ImportSummary.importJson(work(), i).writeText(
                """{"file":"/tmp/x","part":"tenant","written":true,"resources":[
                  {"kind":"role","name":"editor","spec":{"permissions":["docs:write"],"clientSecret":"$secret"},"id":"r-1","access":"manager"},
                  {"kind":"emailProvider","environment":"sbx","readOnly":true,"spec":{"smtpHost":"smtp.example.com","smtpPassword":"$secret"},"id":"e-1","access":"manager","note":"holds a write-only secret"}
                ],"skipped":["user — 3 production-plane user(s) not imported"]}""",
            )
            ImportSummary.planJson(work(), i).writeText("""{"changes":$planChanges,"resources":[],"summary":$planSummary}""")
            ImportSummary.planExit(work(), i).writeText("0\n")
        }
    }

    private fun build() = ImportSummary.build(sha, config, artifact(), work())

    @Test
    fun `the summary carries the fixed field list per file — never a spec, an id or a secret`() {
        jobOutputs()
        val summary = build()
        val written = ImportSummary.write(summary, artifact())
        val text = written.readText()
        assertThat(written.name).isEqualTo("import-summary.json")
        assertThat(text).doesNotContain(secret).doesNotContain("smtpHost").doesNotContain("\"spec\"").doesNotContain("r-1").doesNotContain("\"access\"")

        val doc = JsonMapper.builder().build().readValue(text, Map::class.java)
        assertThat(doc["version"]).isEqualTo(1)
        assertThat(doc["contractVersion"]).isEqualTo(2)
        assertThat(doc["headSha"]).isEqualTo(sha)
        @Suppress("UNCHECKED_CAST") val files = doc["files"] as List<Map<String, Any?>>
        assertThat(files.map { it["path"] }).containsExactly(prodFile, sbxFile)
        val f = files.first()
        assertThat(f.keys).containsExactly("path", "connection", "apiVersion", "bytes", "sha256", "imported", "notImported", "plan")
        assertThat(f["apiVersion"]).isEqualTo("thoryn.io/tenant/v1")
        val expectedSha = MessageDigest.getInstance("SHA-256").digest(tenantYaml.toByteArray()).joinToString("") { "%02x".format(it) }
        assertThat(f["sha256"]).isEqualTo(expectedSha)
        @Suppress("UNCHECKED_CAST") val imported = f["imported"] as List<Map<String, Any?>>
        assertThat(imported).containsExactly(
            mapOf("kind" to "role", "name" to "editor", "environment" to null, "readOnly" to false, "note" to null),
            // A singleton has no `name` in the file: its name is its kind.
            mapOf("kind" to "emailProvider", "name" to "emailProvider", "environment" to "sbx", "readOnly" to true, "note" to "holds a write-only secret"),
        )
        assertThat(f["notImported"]).isEqualTo(listOf("user — 3 production-plane user(s) not imported"))
        @Suppress("UNCHECKED_CAST") val plan = f["plan"] as Map<String, Any?>
        assertThat(plan["allNoop"]).isEqualTo(true)
        assertThat(plan["exit"]).isEqualTo(0)
        assertThat(ImportSummary.render(summary)).contains("### $prodFile").contains("every row unchanged").doesNotContain(secret)
    }

    @Test
    fun `a plan row that is not noop is named with the fields that differ — never their values`() {
        jobOutputs(
            planChanges = """[{"kind":"emailProvider","name":"emailProvider","action":"update","environment":"sbx","diff":{"smtpHost":"old.example.com → $secret"}}]""",
            planSummary = """{"create":0,"update":1,"remove":0,"noop":0,"skip":0,"grants":0,"error":0,"publish":0}""",
        )
        val summary = build()
        val text = String(ImportSummary.write(summary, artifact()).readBytes())
        assertThat(text).doesNotContain(secret).doesNotContain("old.example.com")
        @Suppress("UNCHECKED_CAST") val plan = (summary["files"] as List<Map<String, Any?>>).first()["plan"] as Map<String, Any?>
        assertThat(plan["allNoop"]).isEqualTo(false)
        assertThat(plan["notNoop"]).isEqualTo(listOf(mapOf("kind" to "emailProvider", "name" to "emailProvider", "environment" to "sbx", "action" to "update", "fields" to listOf("smtpHost"))))
        assertThat(ImportSummary.render(summary)).contains("1 row(s) not unchanged").contains("update emailProvider emailProvider (sbx)")
    }

    @Test
    fun `the artifact holds exactly the configured files — a stray file, a link or a missing file is refused`() {
        jobOutputs()
        File(artifact(), ".thoryn/environments/production/connection.json").writeText("{}")
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("connection.json").hasMessageContaining("not a configured provisioning file")
        File(artifact(), ".thoryn/environments/production/connection.json").delete()

        Files.createSymbolicLink(artifact().toPath().resolve("link"), artifact().toPath().resolve(prodFile))
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("symbolic link")
        Files.delete(artifact().toPath().resolve("link"))

        File(artifact(), sbxFile).delete()
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("$sbxFile is configured but was not imported")
    }

    @Test
    fun `a file over the size bound, a file that does not load, a plan that did not run or a bad head sha is refused`() {
        jobOutputs()
        File(artifact(), prodFile).writeText(tenantYaml + "#".repeat(ImportSummary.MAX_FILE_BYTES.toInt()))
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("over the ${ImportSummary.MAX_FILE_BYTES}-byte bound")

        File(artifact(), prodFile).writeText("apiVersion: thoryn.io/tenant/v1\nresources: [ { kind: nope } ]\n")
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("does not load after the import")
        File(artifact(), prodFile).writeText(tenantYaml)

        ImportSummary.planJson(work(), 1).writeText("")
        ImportSummary.planExit(work(), 1).writeText("2\n")
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("the plan preview of $sbxFile did not print a JSON document")
        ImportSummary.planJson(work(), 1).writeText("""{"error":"x"}""")
        assertThatThrownBy { build() }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("did not run (exit 2)")

        assertThatThrownBy { ImportSummary.build("main", config, artifact(), work()) }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("not a commit SHA")
    }

    @Test
    fun `a whole artifact over its bound is refused before the summary is written`() {
        jobOutputs()
        val summary = build()
        // Many padded copies: each under the per-file bound, together over the artifact bound.
        repeat(9) { File(artifact(), "pad$it").writeText("#".repeat(ImportSummary.MAX_FILE_BYTES.toInt() - 1)) }
        assertThatThrownBy { ImportSummary.write(summary, artifact()) }.isInstanceOf(ImportSummaryException::class.java).hasMessageContaining("over the ${ImportSummary.MAX_ARTIFACT_BYTES}-byte bound")
        assertThat(File(artifact(), ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE)).doesNotExist()
    }
}
