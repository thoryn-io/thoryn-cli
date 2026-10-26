package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.CONNECTION
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.TENANT_FILE
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3970 — `thoryn provision workflow check` must not report green when a file `.thoryn/workflow.yaml` lists does not
 * load. Found scaffolding thoryn-io/thoryn-tenant with 0.49.0: a tenant file with a `kind: application` appended printed
 * "OK — 13 rule(s) pass", because `config.valid` only checked that the file existed and the two rules that read it
 * (`config.secret-delivery`, `config.trust-scopes`) returned no verdict when nothing loaded. Each way a configured file can
 * fail to load now fails `config.valid` with the loader's reason, and the rules that read the file fail as not checked.
 */
class ProvisionWorkflowCheckUnloadedFileTest : CommandTestBase() {

    private val configRules = listOf("config.valid", "config.secret-delivery", "config.trust-scopes")

    private fun write(root: File, path: String, text: String): File = File(root, path).also { it.parentFile.mkdirs(); it.writeText(text) }

    /** A config project as `thoryn project init` lays it out, with [provision] as its one configured file (null: not committed). */
    private fun project(provision: String?, connection: String = CONNECTION): File {
        val root = tempHome.resolve("repo").toFile()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: .thoryn/provision.yaml\n    connection: .thoryn/connection.json\n")
        if (provision != null) write(root, ".thoryn/provision.yaml", provision)
        write(root, ".thoryn/connection.json", connection)
        return root
    }

    @Suppress("UNCHECKED_CAST")
    private fun rules(root: File): Map<String, Map<String, Any?>> {
        val r = runCli("provision", "workflow", "check", "--root", root.path, "--output", "json")
        assertThat(r.exit).withFailMessage("exit %s: %s", r.exit, r.out).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        val json = parseJson(r.out)
        assertThat(json["ok"]).isEqualTo(false)
        return (json["rules"] as List<Map<String, Any?>>).associateBy { it["id"] as String }
    }

    /** The shape every unloaded-file case shares: config.valid FAILs naming [reason], and both file-reading rules are present and FAIL as not checked. */
    private fun assertUnloaded(root: File, file: String, vararg reason: String) {
        val rules = rules(root)
        assertThat(rules.keys).containsAll(configRules)
        val valid = rules.getValue("config.valid")
        assertThat(valid["status"]).isEqualTo("FAIL")
        assertThat(valid["detail"] as String).startsWith("no configured provisioning file loads, so nothing can be planned or applied; ").contains(file).contains(*reason)
        listOf("config.secret-delivery", "config.trust-scopes").forEach { id ->
            assertThat(rules.getValue(id)["status"]).withFailMessage("%s", id).isEqualTo("FAIL")
            assertThat(rules.getValue(id)["detail"] as String).withFailMessage("%s", id).startsWith("not checked: $file could not be loaded (see config.valid)")
        }
    }

    @Test
    fun `a tenant file with an application appended fails config valid naming the part rule — the thoryn-tenant repro`() {
        val root = project(TENANT_FILE + "  - { kind: application, name: portal, spec: { displayName: Portal } }\n")
        assertUnloaded(root, ".thoryn/provision.yaml", "does not load: invalid provisioning file '.thoryn/provision.yaml'", "`application` is application provisioning; this is a tenant file (thoryn.io/tenant/v1)")
        val table = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(table.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(table.out).contains("FAIL  config.valid").contains("FAIL  config.secret-delivery").contains("FAIL  config.trust-scopes")
            .contains("fix: correct .thoryn/provision.yaml").contains("FAILED — 3 of 15 rule(s): config.valid, config.secret-delivery, config.trust-scopes.")
            .doesNotContain("OK —")
    }

    @Test
    fun `a provisioning file that is not valid YAML fails config valid naming the parse error`() {
        assertUnloaded(project(TENANT_FILE + "  - { kind: role, name: [\n"), ".thoryn/provision.yaml", "provisioning file '.thoryn/provision.yaml' is not valid YAML")
    }

    @Test
    fun `a configured provisioning file that is not committed fails config valid naming it, and the rules that read it fail as not checked`() {
        val rules = rules(project(provision = null))
        assertThat(rules.keys).containsAll(configRules)
        assertThat(rules.getValue("config.valid")["status"]).isEqualTo("FAIL")
        assertThat(rules.getValue("config.valid")["detail"] as String).contains("configured file(s) not found in the repository: .thoryn/provision.yaml")
        assertThat(rules.getValue("config.valid")["fix"] as String).startsWith("commit them")
        assertThat(rules.getValue("config.secret-delivery")["detail"] as String).startsWith("not checked: .thoryn/provision.yaml could not be loaded")
        assertThat(rules.getValue("config.trust-scopes")["detail"] as String).startsWith("not checked: .thoryn/provision.yaml could not be loaded")
    }

    @Test
    fun `a provisioning file with an unknown apiVersion fails config valid naming the versions it accepts`() {
        assertUnloaded(project(TENANT_FILE.replace("thoryn.io/tenant/v1", "thoryn.io/tenant/v9")), ".thoryn/provision.yaml", "apiVersion must be 'thoryn.io/tenant/v1'", "'thoryn.io/application/v1'")
    }

    @Test
    fun `a connection that does not load fails config valid naming it, and trust-scopes fails as not checked`() {
        val rules = rules(project(TENANT_FILE, connection = "{}"))
        val valid = rules.getValue("config.valid")
        assertThat(valid["status"]).isEqualTo("FAIL")
        assertThat(valid["detail"] as String).startsWith("1 of 1 configured provisioning file(s) load; ").contains(".thoryn/connection.json does not load: invalid connection '.thoryn/connection.json'")
        assertThat(rules.getValue("config.secret-delivery")["status"]).isEqualTo("PASS")
        assertThat(rules.getValue("config.trust-scopes")["status"]).isEqualTo("FAIL")
        assertThat(rules.getValue("config.trust-scopes")["detail"] as String).startsWith("not checked: .thoryn/connection.json could not be loaded")
    }

    @Test
    fun `one file that loads and one that does not still fails — a rule never passes on the files that happened to load`() {
        val root = project(TENANT_FILE)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: .thoryn/provision.yaml\n    connection: .thoryn/connection.json\n  - file: .thoryn/broken.yaml\n    connection: .thoryn/connection.json\n")
        write(root, ".thoryn/broken.yaml", "x")
        val rules = rules(root)
        assertThat(rules.getValue("config.valid")["detail"] as String).startsWith("1 of 2 configured provisioning file(s) load; ").contains(".thoryn/broken.yaml does not load")
        assertThat(rules.getValue("config.secret-delivery")["status"]).isEqualTo("FAIL")
        assertThat(rules.getValue("config.trust-scopes")["status"]).isEqualTo("FAIL")
        assertThat(rules.getValue("config.trust-scopes")["detail"] as String).startsWith("not checked: .thoryn/broken.yaml could not be loaded")
    }

    @Test
    fun `the same project with a file that loads passes every rule, config rules included`() {
        val root = project(TENANT_FILE)
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(r.out).contains("PASS  config.valid").contains("every configured file loads")
            .contains("PASS  config.secret-delivery").contains("PASS  config.trust-scopes").contains("OK — 15 rule(s) pass.")
    }
}
