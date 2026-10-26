package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISIONING_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.REUSABLE_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.WORKFLOW_CONFIG_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.repositoryRoot
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3697 / SSO-3705 / SSO-3719 (parent SSO-3659, epic SSO-3304) — holds THIS repository's App-dispatched workflow to
 * the provisioning workflow contract through the SAME rule engine `thoryn provision workflow check` runs
 * ([WorkflowCheck] over [ProvisioningWorkflowContract] — one source), plus the pins only this repository knows:
 *
 *  - `.github/workflows/thoryn-provisioning.yml` is the SUPPORTED shape — a STUB: the App's four `workflow_dispatch`
 *    inputs, the `run-name` carrying `check-run:<id>`, concurrency per mode, `permissions: {}` at the top, the apply-job
 *    marker, and ONE job that `uses:` the reusable workflow at [CiIdentityFixture.CLI_RELEASE] with the two environments
 *    (the unprotected `-plan` one and the reviewed one `connection.json` pins — Amendment 5's shape with ONE identity,
 *    SSO-3699 option B), the staging issuer, and `id-token: write`, `checks: write`, `contents: read`;
 *  - `.github/workflows/provisioning.yml` — the reusable workflow — passes the called-side rules, declares exactly the
 *    contract's inputs, carries the apply-job marker, writes nothing back (SSO-3717: no receipt pull request), and runs
 *    nothing but the pinned release's own `thoryn.jar`;
 *  - `.thoryn/workflow.yaml` is valid, names exactly `provision.yaml` + `connection.json`, and switches no removal on.
 */
class CiProvisioningWorkflowConformanceTest {

    private val root = repositoryRoot()
    private val stubFile = locate(PROVISIONING_WORKFLOW_PATH)
    private val stubText = stubFile.readText()
    private val stub: JsonNode = YAMLMapper.builder().build().readTree(stubText)
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))
    private val report = WorkflowCheck.evaluate(stubText, PROVISIONING_WORKFLOW_PATH, root = root)

    @Test
    fun `the App-dispatched workflow is the supported shape and passes every rule of the contract`() {
        assertThat(report.shape).isEqualTo(WorkflowCheck.Shape.STUB)
        assertThat(report.rules.filter { it.failed }).withFailMessage("%s", report.rules.filter { it.failed }).isEmpty()
        assertThat(report.ok).isTrue()
        assertThat(stub["name"].asString()).isEqualTo("Thoryn provisioning")
        // ~25 lines of YAML: everything else lives in the reusable workflow and .thoryn/workflow.yaml.
        assertThat(stubText.lines().count { it.isNotBlank() && !it.trimStart().startsWith("#") }).isLessThanOrEqualTo(45)
    }

    @Test
    fun `the stub pins the reusable workflow to the release, the two environments connection json implies, and the staging issuer`() {
        val job = stub["jobs"].properties().single().value
        assertThat(job["uses"].asString()).isEqualTo("${ProvisioningWorkflowContract.REUSABLE_WORKFLOW}@${CiIdentityFixture.CLI_RELEASE}")
        assertThat(ProvisioningWorkflowContract.isAtLeastMinimumRelease(CiIdentityFixture.CLI_RELEASE)).isTrue()
        val inputs = report.inputs!!
        // The environment IS the read/write separation (Amendment 5): the hub's plan profile keys on the `-plan` one, the
        // trust pins the reviewed one — never the same, and the apply one is what connection.json declares.
        assertThat(inputs["plan-environment"]).isEqualTo(CiIdentityFixture.PLAN_GITHUB_ENVIRONMENT)
        assertThat(inputs["apply-environment"]).isEqualTo(CiIdentityFixture.GITHUB_ENVIRONMENT)
        assertThat(inputs["apply-environment"]).isEqualTo(connection.github!!.environment)
        assertThat(inputs["plan-environment"]).isNotEqualTo(connection.github!!.environment)
        assertThat(inputs["issuer"]).isEqualTo(CiIdentityFixture.PLATFORM_ISSUER)
        // Not pinned twice: the reusable workflow runs the release it was called at.
        assertThat(inputs["cli-version"]).isEmpty()
        assertThat(inputs["runs-on"]).isEqualTo("ubuntu-latest") // the trust pins GitHub-hosted runners
        ProvisioningWorkflowContract.DISPATCH_INPUTS.keys.forEach { assertThat(inputs[it]).isEqualTo(ProvisioningWorkflowContract.forwarded(it)) }
    }

    @Test
    fun `the committed workflow yaml names exactly provision yaml with its connection and switches no removal on`() {
        val config = WorkflowConfig.load(locate(WORKFLOW_CONFIG_PATH))
        assertThat(report.config!!.source).isEqualTo(WORKFLOW_CONFIG_PATH)
        assertThat(config.files).containsExactly(WorkflowConfig.FileEntry(PROVISION_PATH, CONNECTION_PATH))
        assertThat(config.env).isEmpty()
        assertThat(config.fixRequest).isTrue()
        assertThat(config.prune).isFalse()
        assertThat(config.destroy).isFalse()
        assertThat(config.confirm).isNull()
        // SSO-3705 — ONE identity: there is no plan contract anywhere.
        assertThat(stubText).doesNotContain("connection.plan.json")
    }

    @Test
    fun `the reusable workflow passes the called-side rules, runs only the pinned release, and writes nothing back`() {
        val file = locate(REUSABLE_WORKFLOW_PATH)
        val text = file.readText()
        val reusable = WorkflowCheck.evaluate(text, REUSABLE_WORKFLOW_PATH, root = root)
        assertThat(reusable.shape).isEqualTo(WorkflowCheck.Shape.REUSABLE)
        assertThat(reusable.rules.filter { it.failed }).withFailMessage("%s", reusable.rules.filter { it.failed }).isEmpty()
        val doc = YAMLMapper.builder().build().readTree(text)
        // Contract v2 (SSO-3991): the third job imports; this repository's own stub stays v1 (it does not offer `import`).
        assertThat(doc["jobs"].propertyNames().toList()).containsExactly("plan", "apply", "import")
        assertThat(report.importCapable).isFalse()
        // The App dispatches `apply` only when it sees this marker; the stub carries it, and so does the job it points at.
        assertThat(text).containsPattern("(?m)^\\s*# thoryn-provisioning: apply-job\\s*$")
        assertThat(stubText).containsPattern("(?m)^\\s*# thoryn-provisioning: apply-job\\s*$")
        // No receipt pull request, no write permission (SSO-3717 / ADR 2026-10-15 platform-is-the-ledger).
        assertThat(text).doesNotContain("gh pr create").doesNotContain("receipt pull request").doesNotContain("contents: write").doesNotContain("pull-requests")
        // The CLI it runs is the release it was called at (job.workflow_ref), never a hardcoded tag.
        assertThat(text).doesNotContain("THORYN_CLI_RELEASE").doesNotContain("/.github/actions/provision@").doesNotContain("cli-version: cli-v")
            .contains("job_ref").contains("refs/tags/cli-v*")
        assertThat(text).contains("gh release download \"\$tag\" --repo thoryn-io/thoryn-cli --pattern thoryn.jar")
        // The one identity signs in from the configured connection for every file; nothing is pruned or destroyed outside the config's toggles.
        listOf("plan", "apply").forEach { job ->
            val runs = doc["jobs"][job]["steps"].toList().mapNotNull { it["run"]?.asString() }
            assertThat(runs).anyMatch { it.contains("login --connection \"\$connection\"") }
            assertThat(runs).anyMatch { it.contains("provision $job --file \"\$file\"") }
        }
        val applyRuns = doc["jobs"]["apply"]["steps"].toList().mapNotNull { it["run"]?.asString() }.joinToString("\n")
        assertThat(applyRuns).contains("if [ \"\$prune\" = \"true\" ]; then args+=(--prune); fi")
        val destroy = doc["jobs"]["apply"]["steps"].toList().single { it["run"]?.asString()?.contains("provision destroy") == true }
        assertThat(destroy["if"].asString()).isEqualTo("steps.config.outputs.destroy == 'true'")
    }
}
