package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.Shape
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.Status
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.stubWith
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

/**
 * SSO-3719 — the rule engine behind `thoryn provision workflow check`, rule by rule: the prescribed stub passes every
 * rule, and each rule FAILS on a stub missing exactly the property it pins, naming the fix. One mutation per rule, so a
 * rule that passes against both the fixed and the broken document is caught here (the revert→red discipline, in code).
 */
class ProvisioningWorkflowContractTest {

    private fun evaluate(text: String) = WorkflowCheck.evaluate(text, "stub.yml")
    private fun WorkflowCheck.Report.rule(id: String) = rules.single { it.id == id }

    @Test
    fun `the prescribed stub passes every rule and is the supported shape`() {
        val report = evaluate(STUB)
        assertThat(report.shape).isEqualTo(Shape.STUB)
        assertThat(report.supported).isTrue()
        assertThat(report.rules.filter { it.failed }).isEmpty()
        assertThat(report.rules.map { it.id }).containsExactly(
            "dispatch.inputs", "dispatch.run-name", "dispatch.permissions", "dispatch.concurrency", "dispatch.apply-job-marker",
            "stub.job", "stub.uses", "stub.with", "stub.permissions", "stub.secrets",
            "common.no-secrets", "common.no-expression-in-run", "config.valid",
        )
        // Effective inputs: the stub's with: plus every default of the reusable workflow.
        assertThat(report.inputs).containsEntry("plan-environment", "acme-production-plan").containsEntry("runs-on", "ubuntu-latest")
            .containsEntry("timeout-minutes", "30").containsEntry("cli-version", "").containsEntry("config", ".thoryn/workflow.yaml")
        // No .thoryn/workflow.yaml ⇒ the built-in defaults, stated.
        assertThat(report.config!!.source).isNull()
        assertThat(report.config!!.files).containsExactly(WorkflowConfig.FileEntry(".thoryn/provision.yaml", ".thoryn/connection.json"))
        assertThat(report.ok).isTrue()
    }

    companion object {
        /** rule id → (a mutation of the prescribed stub that breaks exactly that rule, text the detail or fix must carry). */
        @JvmStatic
        fun mutations(): List<Arguments> = listOf(
            Arguments.of("dispatch.inputs", stubWith("      pr_number:\n", "      pull_request:\n"), "pull_request"),
            Arguments.of("dispatch.inputs", stubWith("        options: [plan, apply]", "        options: [plan, apply, destroy]"), "options"),
            Arguments.of("dispatch.inputs", stubWith("      head_sha:\n        required: true", "      head_sha:\n        required: false"), "head_sha"),
            Arguments.of("dispatch.run-name", stubWith(" check-run:\${{ inputs.check_run_id }}\"", "\""), "check-run:"),
            Arguments.of("dispatch.permissions", stubWith("permissions: {}\n", "permissions:\n  contents: read\n"), "permissions"),
            Arguments.of("dispatch.permissions", stubWith("permissions: {}\n", ""), "no top-level"),
            Arguments.of("dispatch.concurrency", stubWith("group: thoryn-provisioning-\${{ inputs.mode }}", "group: thoryn-provisioning"), "inputs.mode"),
            Arguments.of("dispatch.concurrency", stubWith("cancel-in-progress: false", "cancel-in-progress: true"), "cancel-in-progress: true"),
            Arguments.of("dispatch.apply-job-marker", stubWith("  # thoryn-provisioning: apply-job\n", ""), "thoryn-provisioning: apply-job"),
            Arguments.of("stub.job", stubWith("    permissions:\n      id-token", "    runs-on: ubuntu-latest\n    permissions:\n      id-token"), "runs-on"),
            Arguments.of("stub.uses", stubWith("@cli-v0.36.0", "@main"), "branch"),
            Arguments.of("stub.uses", stubWith("@cli-v0.36.0", "@cli-v0.35.0"), "predates"),
            Arguments.of("stub.with", stubWith("      plan-environment: acme-production-plan\n", "      plan-env: acme-production-plan\n"), "`with.plan-env` is not an input"),
            Arguments.of("stub.with", stubWith("      plan-environment: acme-production-plan\n", ""), "plan-environment"),
            Arguments.of("stub.with", stubWith("plan-environment: acme-production-plan", "plan-environment: acme-production"), "both"),
            Arguments.of("stub.with", stubWith("mode: \${{ inputs.mode }}", "mode: plan"), "forward"),
            Arguments.of("stub.with", stubWith("issuer: https://auth.thoryn.io", "issuer: http://auth.thoryn.io"), "https"),
            Arguments.of("stub.with", stubWith("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n      runs-on: \"self hosted\""), "runs-on"),
            Arguments.of("stub.with", stubWith("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n      timeout-minutes: 0"), "timeout-minutes"),
            Arguments.of("stub.with", stubWith("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n      cli-version: cli-v0.35.0"), "cli-version"),
            Arguments.of("stub.with", stubWith("apply-environment: acme-production\n", "apply-environment: \${{ vars.ENV }}\n"), "expression"),
            Arguments.of("stub.permissions", stubWith("      contents: read", "      contents: write"), "contents"),
            Arguments.of("stub.permissions", stubWith("      checks: write\n", ""), "checks"),
            Arguments.of("stub.secrets", stubWith("    with:\n", "    secrets: inherit\n    with:\n"), "secrets"),
            Arguments.of("common.no-secrets", stubWith("issuer: https://auth.thoryn.io", "issuer: \${{ secrets.ISSUER }}"), "secrets"),
        )
    }

    @ParameterizedTest(name = "{0} fails on a stub missing it: {2}")
    @MethodSource("mutations")
    fun `each rule fails on exactly the stub that breaks it, naming the fix`(rule: String, mutated: String, expected: String) {
        val report = evaluate(mutated)
        val result = report.rule(rule)
        assertThat(result.status).withFailMessage("%s should FAIL on:\n%s\n(rules: %s)", rule, mutated, report.rules.map { "${it.id}=${it.status}" }).isEqualTo(Status.FAIL)
        assertThat(result.detail + " " + result.fix).containsIgnoringCase(expected)
        assertThat(result.fix).isNotBlank()
        assertThat(report.ok).isFalse()
        // The mutation breaks THAT rule (and at most the common ones it also trips; a secret trips every secret-shaped
        // rule and the stray-key / expression rules too) — never the whole table.
        val alsoAllowed = if (expected == "secrets") setOf("stub.secrets", "stub.job", "stub.with") else emptySet()
        assertThat(report.rules.filter { it.failed }.map { it.id }).allMatch { it == rule || it.startsWith("common.") || it in alsoAllowed }
    }

    @Test
    fun `a foreign uses cannot be verified — the check says to run it on that file`() {
        val report = evaluate(stubWith("thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0", "acme/platform/.github/workflows/thoryn.yml@v3"))
        assertThat(report.shape).isEqualTo(Shape.FOREIGN_STUB)
        assertThat(report.supported).isFalse()
        val uses = report.rule("stub.uses")
        assertThat(uses.status).isEqualTo(Status.UNVERIFIABLE)
        assertThat(uses.detail).contains("cannot verify a called workflow").contains("acme/platform/.github/workflows/thoryn.yml@v3").contains("run the check on that file")
        assertThat(report.ok).isFalse()
        // The dispatch contract is still evaluated (the App's side does not depend on the called workflow).
        assertThat(report.rule("dispatch.inputs").status).isEqualTo(Status.PASS)
        assertThat(report.inputs).isNull()
    }

    @Test
    fun `a hand-written workflow is reported as not the supported shape, with what the App would need from it`() {
        val report = evaluate(WorkflowFixtures.FULL_CUSTOM)
        assertThat(report.shape).isEqualTo(Shape.CUSTOM)
        assertThat(report.supported).isFalse()
        assertThat(report.rules.map { it.id }).containsExactly(
            "dispatch.inputs", "dispatch.run-name", "dispatch.permissions", "dispatch.concurrency", "dispatch.apply-job-marker",
            "custom.jobs", "common.no-secrets", "common.no-expression-in-run",
        )
        // Today's full workflow meets everything the App needs — so the dogfood kept working — yet it is not promoted.
        assertThat(report.rules.filter { it.failed }).isEmpty()
        assertThat(report.ok).isTrue()
        assertThat(report.config).isNull()
    }

    @Test
    fun `a hand-written workflow whose jobs share an environment or interpolate into run fails the custom rules`() {
        val shared = WorkflowFixtures.FULL_CUSTOM.replace("environment: thoryn-provision-e2e-plan", "environment: thoryn-provision-e2e")
        val custom = evaluate(shared).rule("custom.jobs")
        assertThat(custom.status).isEqualTo(Status.FAIL)
        assertThat(custom.detail).contains("share a GitHub environment")
        assertThat(custom.fix).contains(ProvisioningWorkflowContract.REUSABLE_WORKFLOW)

        val leaking = WorkflowFixtures.FULL_CUSTOM.replace("gh release download \"\$THORYN_CLI_RELEASE\"", "gh release download \"\${{ env.THORYN_CLI_RELEASE }}\"")
        val run = evaluate(leaking).rule("common.no-expression-in-run")
        assertThat(run.status).isEqualTo(Status.FAIL)
        assertThat(run.detail).contains("\${{ env.THORYN_CLI_RELEASE }}")
        assertThat(run.fix).contains("env:")
    }

    @Test
    fun `the reusable workflow in this repository passes the called-side rules`() {
        val file = com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate(ProvisioningWorkflowContract.REUSABLE_WORKFLOW_PATH)
        val report = WorkflowCheck.evaluate(file.readText(), file.path)
        assertThat(report.shape).isEqualTo(Shape.REUSABLE)
        assertThat(report.rules.filter { it.failed }).withFailMessage("%s", report.rules.filter { it.failed }).isEmpty()
        assertThat(report.rules.map { it.id }).containsExactly("reusable.inputs", "reusable.jobs", "reusable.no-write-back", "common.no-secrets", "common.no-expression-in-run", "config.valid")
    }

    @Test
    fun `the called-side rules fail on a reusable workflow that writes back, skips the fix request, or drops an input`() {
        val file = com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate(ProvisioningWorkflowContract.REUSABLE_WORKFLOW_PATH).readText()
        fun rule(text: String, id: String) = WorkflowCheck.evaluate(text, "provisioning.yml").rules.single { it.id == id }

        // One mutation per rule.
        val contentsWrite = file.replace("    # Read-only on the repository: the job converges the platform and commits nothing back (SSO-3717).\n    permissions:\n      id-token: write\n      checks: write\n      contents: read", "    permissions:\n      id-token: write\n      checks: write\n      contents: write")
        assertThat(rule(contentsWrite, "reusable.no-write-back").status).isEqualTo(Status.FAIL)
        assertThat(rule(contentsWrite, "reusable.jobs").status).isEqualTo(Status.FAIL)

        val noUpload = file.replace("          name: thoryn-provision-request\n", "          name: provision-request\n")
        val r = rule(noUpload, "reusable.jobs")
        assertThat(r.status).isEqualTo(Status.FAIL)
        assertThat(r.detail).contains("thoryn-provision-request")

        val noInput = file.replace("      timeout-minutes:\n        description: \"Job timeout in minutes, each job\"\n        required: false\n        type: number\n        default: 30\n", "")
        assertThat(rule(noInput, "reusable.inputs").status).isEqualTo(Status.FAIL)
        assertThat(rule(noInput, "reusable.inputs").detail).contains("timeout-minutes")

        val handParsed = file.replace("provision workflow check --file \"\$stub\" --config \"\$CONFIG\" --output json", "provision workflow check --file \"\$stub\" --config \"\$CONFIG\" --output yaml")
        assertThat(rule(handParsed, "reusable.jobs").detail).contains("provision workflow check --output json")

        val receipt = file.replace("            echo \"## Applied\"; echo", "            gh pr create --title receipt")
        assertThat(rule(receipt, "reusable.no-write-back").status).isEqualTo(Status.FAIL)
    }

    @Test
    fun `the contract's reusable inputs are the reusable workflow's inputs — one source`() {
        val file = com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate(ProvisioningWorkflowContract.REUSABLE_WORKFLOW_PATH)
        val doc = tools.jackson.dataformat.yaml.YAMLMapper.builder().build().readTree(file.readText())
        val declared = doc["on"]["workflow_call"]["inputs"]
        assertThat(declared.propertyNames().toList()).containsExactlyElementsOf(ProvisioningWorkflowContract.REUSABLE_INPUTS.keys)
        ProvisioningWorkflowContract.REUSABLE_INPUTS.forEach { (name, spec) ->
            val node = declared[name]
            assertThat(node["required"]?.asBoolean() ?: false).withFailMessage("%s required", name).isEqualTo(spec.required)
            assertThat(node["type"].asString()).withFailMessage("%s type", name).isEqualTo(spec.type)
            spec.default?.let { assertThat(node["default"].asString()).withFailMessage("%s default", name).isEqualTo(it) }
        }
        assertThat(ProvisioningWorkflowContract.STUB_REQUIRED_INPUTS).containsExactly("mode", "head_sha", "check_run_id", "plan-environment", "apply-environment")
        assertThat(ProvisioningWorkflowContract.isAtLeastMinimumRelease("cli-v0.36.0")).isTrue()
        assertThat(ProvisioningWorkflowContract.isAtLeastMinimumRelease("cli-v1.0.0")).isTrue()
        assertThat(ProvisioningWorkflowContract.isAtLeastMinimumRelease("cli-v0.35.9")).isFalse()
        assertThat(ProvisioningWorkflowContract.isAtLeastMinimumRelease("main")).isFalse()
    }
}
