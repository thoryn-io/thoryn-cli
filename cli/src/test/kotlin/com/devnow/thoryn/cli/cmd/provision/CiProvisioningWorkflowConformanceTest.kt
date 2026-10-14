package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISIONING_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3697 / SSO-3705 (parent SSO-3659) — holds `.github/workflows/thoryn-provisioning.yml` to the Thoryn GitHub
 * App's dispatch contract (oauthy `ThorynFiles.kt`, SSO-3660 / SSO-3665; the hand-adapted template is
 * thoryn-cicd's) and to Amendment 5's two-environment shape with ONE identity (SSO-3699 option B):
 *
 *  - `workflow_dispatch` with exactly the inputs the App sends (`mode`, `head_sha`, `check_run_id`, `pr_number`),
 *    a `run-name` carrying `check-run:<id>` (how the App finds the run to complete its check), concurrency per
 *    mode, and `permissions: {}` at the top (each job declares its own);
 *  - a `plan` job in the UNPROTECTED plan environment with `id-token: write`, `checks: write`, `contents: read` —
 *    exactly — that checks out `inputs.head_sha`, downloads `thoryn.jar` from the pinned release, signs in with
 *    the ONE connection contract (`connection.json` — the hub's plan profile makes that sign-in read-only in this
 *    environment) and plans the provisioning file; never a second contract;
 *  - an `apply` job, announced by the `# thoryn-provisioning: apply-job` marker the App looks for before dispatching
 *    `apply`, in the REVIEWED environment with `id-token: write`, `checks: write`, `contents: write`,
 *    `pull-requests: write` — exactly — running the composite Action pinned to the release with the same
 *    connection, `destroy: "false"`, and then the receipt pull request;
 *  - no secret anywhere, and no `${{ }}` inside a `run:` block (the template-injection rule, oauthy SSO-3635).
 */
class CiProvisioningWorkflowConformanceTest {

    private val workflowFile = locate(PROVISIONING_WORKFLOW_PATH)
    private val text = workflowFile.readText()
    private val workflow: JsonNode = YAMLMapper.builder().build().readTree(text)
    private val plan: JsonNode get() = workflow["jobs"]["plan"]
    private val apply: JsonNode get() = workflow["jobs"]["apply"]
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    private fun JsonNode.keys(): Set<String> = properties().map { it.key }.toSet()
    private fun JsonNode.steps(): List<JsonNode> = this["steps"].toList()
    private fun JsonNode.permissions(): Map<String, String> = this["permissions"].properties().associate { it.key to it.value.asString() }

    @Test
    fun `the workflow is dispatched by the App with exactly its four inputs, a run-name carrying the check-run id, concurrency per mode and no top-level permissions`() {
        assertThat(workflow["name"].asString()).isEqualTo("Thoryn provisioning")
        assertThat(workflow["run-name"].asString()).contains("check-run:\${{ inputs.check_run_id }}")
        val on = workflow["on"]
        assertThat(on.keys()).containsExactly("workflow_dispatch")
        val inputs = on["workflow_dispatch"]["inputs"]
        assertThat(inputs.keys()).containsExactlyInAnyOrder("mode", "head_sha", "check_run_id", "pr_number")
        val modes: List<String> = inputs["mode"]["options"].toList().map { it.asString() }
        assertThat(modes).containsExactly("plan", "apply")
        listOf("mode", "head_sha", "check_run_id").forEach { assertThat(inputs[it]["required"].asBoolean()).withFailMessage("input %s is required", it).isTrue() }
        assertThat(inputs["pr_number"]["required"].asBoolean()).isFalse()
        assertThat(workflow["concurrency"]["group"].asString()).isEqualTo("thoryn-provisioning-\${{ inputs.mode }}")
        assertThat(workflow["concurrency"]["cancel-in-progress"].asBoolean()).isFalse()
        // `permissions: {}` at the top — every job declares exactly what it needs.
        assertThat(workflow["permissions"].isObject() && workflow["permissions"].isEmpty).withFailMessage("top-level permissions must be {}").isTrue()
        assertThat(workflow["jobs"].keys()).containsExactly("plan", "apply")
        assertThat(workflow["env"]["THORYN_CLI_RELEASE"].asString()).isEqualTo(CiIdentityFixture.CLI_RELEASE)
        assertThat(workflow["env"]["THORYN_ISSUER"].asString()).isEqualTo(CiIdentityFixture.PLATFORM_ISSUER)
    }

    @Test
    fun `the plan job runs in the UNPROTECTED plan environment with read permissions only and plans the file as the ONE identity`() {
        assertThat(plan["if"].asString()).isEqualTo("inputs.mode == 'plan'")
        // The environment IS the read/write separation (Amendment 5): the hub's plan profile keys on it, so it must be
        // the `-plan` one, never the reviewed environment the trust pins for apply.
        assertThat(plan["environment"].asString()).isEqualTo(CiIdentityFixture.PLAN_GITHUB_ENVIRONMENT)
        assertThat(plan["environment"].asString()).isNotEqualTo(connection.github!!.environment)
        assertThat(plan.permissions()).isEqualTo(mapOf("id-token" to "write", "checks" to "write", "contents" to "read"))
        val steps = plan.steps()
        assertThat(steps.first()["uses"].asString()).startsWith("actions/checkout@")
        assertThat(steps.first()["with"]["ref"].asString()).isEqualTo("\${{ inputs.head_sha }}")
        val runs = steps.mapNotNull { it["run"]?.asString() }
        assertThat(runs).anyMatch { it.contains("gh release download \"\$THORYN_CLI_RELEASE\" --repo thoryn-io/thoryn-cli --pattern thoryn.jar") }
        val planStep = runs.single { it.contains("provision plan") }
        // SSO-3705 — ONE identity: the plan signs in with the same contract as the apply; there is no plan contract.
        assertThat(planStep).contains("login --connection \"$CONNECTION_PATH\"")
        assertThat(text).doesNotContain("connection.plan.json")
        assertThat(planStep).contains("provision plan --file \"$PROVISION_PATH\"")
        assertThat(planStep).contains("GITHUB_STEP_SUMMARY")
        assertThat(planStep).doesNotContain("provision apply").doesNotContain("provision destroy")
    }

    @Test
    fun `the apply job carries the App's marker, runs in the REVIEWED environment with the write permissions exactly, applies through the pinned Action without destroy and opens the receipt pull request`() {
        // The App dispatches `apply` only when this marker is present.
        assertThat(text).containsPattern("(?m)^\\s*# thoryn-provisioning: apply-job\\s*$")
        assertThat(apply["if"].asString()).isEqualTo("inputs.mode == 'apply'")
        assertThat(apply["environment"].asString()).isEqualTo(CiIdentityFixture.GITHUB_ENVIRONMENT)
        assertThat(apply["environment"].asString()).isEqualTo(connection.github!!.environment)
        assertThat(apply.permissions()).isEqualTo(mapOf("id-token" to "write", "checks" to "write", "contents" to "write", "pull-requests" to "write"))
        val steps = apply.steps()
        assertThat(steps.first()["uses"].asString()).startsWith("actions/checkout@")
        assertThat(steps.first()["with"]["ref"].asString()).isEqualTo("\${{ inputs.head_sha }}")
        val action = steps.single { it["uses"]?.asString()?.contains("/.github/actions/provision@") == true }
        assertThat(action["uses"].asString()).isEqualTo("thoryn-io/thoryn-cli/.github/actions/provision@${CiIdentityFixture.CLI_RELEASE}")
        val with = action["with"]
        assertThat(with["connection"].asString()).isEqualTo(CONNECTION_PATH)
        assertThat(with["file"].asString()).isEqualTo(PROVISION_PATH)
        assertThat(with["issuer"].asString()).isEqualTo(CiIdentityFixture.PLATFORM_ISSUER)
        assertThat(with["cli-version"].asString()).isEqualTo(CiIdentityFixture.CLI_RELEASE)
        // Removals are never automated: destroy off, and nothing passes --prune.
        assertThat(with["destroy"].asString()).isEqualTo("false")
        assertThat(with.keys()).doesNotContain("client-secret")
        (plan.steps() + apply.steps()).forEach { step ->
            step["run"]?.asString()?.let { assertThat(it).doesNotContain("--prune").doesNotContain("provision destroy") }
            step["with"]?.properties()?.forEach { assertThat(it.value.asString()).doesNotContain("--prune") }
        }
        val receipt = steps.last()
        assertThat(receipt["run"].asString()).contains("git add -- ':(glob).thoryn/**/*.receipt.json'")
        assertThat(receipt["run"].asString()).contains("thoryn/receipt-\$short")
        assertThat(receipt["run"].asString()).contains("gh pr create")
        assertThat(receipt["env"]["HEAD_SHA"].asString()).isEqualTo("\${{ inputs.head_sha }}")
    }

    @Test
    fun `the workflow injects no secret and interpolates no expression into a run block`() {
        assertThat(text).doesNotContain("secrets.")
        assertThat(text).doesNotContain("THORYN_CLI_CI_CLIENT_SECRET")
        // SSO-3635: a `${{ }}` inside `run:` lands in the shell's SOURCE; every value reaches a script through `env:`.
        (plan.steps() + apply.steps()).mapNotNull { it["run"]?.asString() }.forEach { run ->
            assertThat(run).withFailMessage("a run block interpolates an expression:\n%s", run).doesNotContain("\${{")
        }
    }
}
