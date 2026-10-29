package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.CONNECTION
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-4056 — `thoryn provision workflow check` loads each configured file with the directory it was read from, as
 * `ProvisionFile.load` does, so an `emailTemplate`'s `spec.bodyFile` resolves next to the file. Before the fix the check
 * parsed the bytes with no directory and every file naming a body file failed `config.valid` with "this provisioning
 * document was not read from a file" — and the reusable workflow runs this check before plan, apply and import, so a
 * config project with body files (including those `import` writes) failed every job.
 *
 * Every assertion was watched failing against the reverted call site (the control table in the PR).
 */
class ProvisionWorkflowCheckBodyFileTest : CommandTestBase() {

    private fun write(root: File, path: String, text: String): File = File(root, path).also { it.parentFile.mkdirs(); it.writeText(text) }

    /** The fixture connection, plus the two scopes an emailTemplate needs (`tenant:idp.*`), so config.trust-scopes passes too. */
    private val connection = CONNECTION.replace("\"tenant:access.write\"]", "\"tenant:access.write\", \"tenant:idp.read\", \"tenant:idp.write\"]")

    /** A config project as `thoryn project init` lays it out, whose one file declares an emailTemplate with `bodyFile: [bodyFile]`. */
    private fun project(bodyFile: String, bodies: Map<String, String> = emptyMap()): File {
        val root = tempHome.resolve("repo").toFile()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: .thoryn/provision.yaml\n    connection: .thoryn/connection.json\n")
        write(
            root, ".thoryn/provision.yaml",
            "apiVersion: thoryn.io/tenant/v1\nresources:\n" +
                "  - { kind: emailTemplate, name: reset, spec: { type: password_reset, subject: \"Reset your password\", bodyFile: $bodyFile } }\n",
        )
        write(root, ".thoryn/connection.json", connection)
        bodies.forEach { (path, content) -> write(root, path, content) }
        return root
    }

    @Suppress("UNCHECKED_CAST")
    private fun rules(root: File): Map<String, Map<String, Any?>> {
        val r = runCli("provision", "workflow", "check", "--root", root.path, "--output", "json")
        return (parseJson(r.out)["rules"] as List<Map<String, Any?>>).associateBy { it["id"] as String }
    }

    @Test
    fun `an emailTemplate whose body file is next to the provisioning file passes config valid and the whole check`() {
        val root = project("emails/password_reset.html", mapOf(".thoryn/emails/password_reset.html" to "<p><a href=\"{{resetUrl}}\">Reset</a></p>\n"))
        val valid = rules(root).getValue("config.valid")
        assertThat(valid["status"]).withFailMessage("%s", valid).isEqualTo("PASS")
        assertThat(valid["detail"] as String).contains("every configured file loads")

        val table = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(table.exit).withFailMessage("%s", table.out).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(table.out).contains("PASS  config.valid").contains("PASS  config.trust-scopes").contains("OK — 16 rule(s) pass.")
    }

    @Test
    fun `an emailTemplate whose body file is missing fails config valid with the not-found reason, not the not-read-from-a-file one`() {
        val root = project("emails/missing.html")
        val valid = rules(root).getValue("config.valid")
        assertThat(valid["status"]).isEqualTo("FAIL")
        assertThat(valid["detail"] as String)
            .contains(".thoryn/provision.yaml does not load")
            .contains("spec.bodyFile 'emails/missing.html' not found (")
            .contains(File(File(root, ".thoryn"), "emails/missing.html").absoluteFile.normalize().path)
            .doesNotContain("not read from a file")
    }

    @Test
    fun `an emailTemplate whose body file escapes the provisioning file's directory is refused as the loader refuses it, even when the file exists`() {
        val root = project("../outside.html", mapOf("outside.html" to "<p>not yours</p>\n"))
        val valid = rules(root).getValue("config.valid")
        assertThat(valid["status"]).isEqualTo("FAIL")
        assertThat(valid["detail"] as String)
            .contains(".thoryn/provision.yaml does not load")
            .contains("spec.bodyFile '../outside.html' must stay inside the provisioning file's directory (no '..')")
            .doesNotContain("not read from a file")
    }
}
