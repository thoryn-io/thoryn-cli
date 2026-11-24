package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File

/**
 * SSO-4474 — `thoryn provision workflow check` on a Forgejo repository: with `provider: forgejo` it checks
 * `.forgejo/workflows/thoryn-provisioning.yml` without `--file`, prints the action's effective inputs, and its JSON carries
 * the shape and the `config` object the action reads. The released action and the example stub are held to the contract.
 */
class ProvisionWorkflowCheckForgejoCommandTest : CommandTestBase() {

    private fun repo(): File = ForgejoFixtures.repo(tempHome.resolve("repo").toFile())

    @Test
    fun `a forgejo configuration makes the Forgejo stub the default, and it passes`() {
        val root = repo()
        // A repository moving from GitHub keeps both stubs for a while; the configuration's provider decides.
        File(root, ProvisioningWorkflowContract.WORKFLOW_PATH).also { it.parentFile.mkdirs() }.writeText(WorkflowFixtures.STUB)
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.err).isEmpty()
        assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(r.out).contains("file   ${ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH}").contains("shape  Forgejo stub calling the provisioning action")
            .contains("PASS  forgejo.apply-gate").contains("Effective inputs (the action's with:, defaults filled in)").contains("provider           forgejo")
        val json = JsonMapper.builder().build().readTree(runCli("provision", "workflow", "check", "--root", root.path, "--output", "json").out)
        assertThat(json["shape"].asString()).isEqualTo("forgejo_stub")
        assertThat(json["ok"].asBoolean()).isTrue()
        assertThat(json["config"]["provider"].asString()).isEqualTo("forgejo")
        assertThat(json["config"]["files"][0]["connection"].asString()).isEqualTo(".thoryn/connection.json")
    }

    @Test
    fun `a stub that applies on its own is exit 4 with the rule and its fix`() {
        val root = repo()
        val stub = File(root, ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH)
        stub.writeText(stub.readText().replace("      - uses: https://github.com/", "      - run: thoryn provision apply --yes\n      - uses: https://github.com/"))
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(r.out).contains("FAIL  forgejo.apply-gate").contains("runs its own commands").contains("fix: remove every other step")
    }

    @Test
    fun `a forgejo configuration without the Forgejo stub is a usage error naming the action`() {
        val root = repo()
        File(root, ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH).delete()
        val r = runCli("provision", "workflow", "check", "--root", root.path)
        assertThat(r.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(r.err).contains(ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH).contains(ProvisioningWorkflowContract.FORGEJO_ACTION)
    }

    @Test
    fun `the released action declares the contract's inputs and minimum release, and the example stub calls that release`() {
        val root = CiIdentityFixture.repositoryRoot()
        val action = File(root, ProvisioningWorkflowContract.FORGEJO_ACTION_PATH).readText()
        val doc = YAMLMapper.builder().build().readTree(action)
        assertThat(doc["inputs"].propertyNames().toList()).containsExactlyElementsOf(ProvisioningWorkflowContract.FORGEJO_ACTION_INPUTS.keys)
        assertThat(doc["runs"]["using"].asString()).isEqualTo("composite")
        // The bash gate repeats the minimum release; one source, pinned here.
        assertThat(action).contains("minimum=\"${ProvisioningWorkflowContract.FORGEJO_MINIMUM_RELEASE.removePrefix("cli-v")}\"")
        assertThat(ForgejoFixtures.STUB).contains("uses: ${ProvisioningWorkflowContract.FORGEJO_ACTION}@${ProvisioningWorkflowContract.FORGEJO_MINIMUM_RELEASE}")
        // A customer feature: no Thoryn-internal instance in the shipped files.
        assertThat(action + ForgejoFixtures.STUB).doesNotContain("thoryn.org")
    }
}
