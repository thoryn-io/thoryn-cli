package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.Shape
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.Status
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.stubWith
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3991 — workflow contract v2 (`mode: import`; thoryn-provisioning ADR 2026-09-30 amendment 2026-10-26 §13):
 *
 *  - the App dispatches `import` only to a file that is import-capable ([WorkflowCheck.Report.importCapable]): a v1 stub
 *    never is, and a stub that OFFERS `import` while calling a reusable workflow without the `import` job FAILS
 *    `dispatch.import-capable` — that dispatch would run zero jobs and report green with nothing imported;
 *  - the reusable workflow's `import` job runs in the PLAN environment, imports into a copy, previews, summarises through
 *    the CLI, applies nothing and uploads `thoryn-import` (`reusable.jobs`, `reusable.import-job`);
 *  - it writes nothing back to the repository (`reusable.no-write-back` covers the import job like the other two).
 */
class ProvisioningWorkflowContractV2Test {

    private fun evaluate(text: String) = WorkflowCheck.evaluate(text, "stub.yml")
    private fun WorkflowCheck.Report.rule(id: String) = rules.single { it.id == id }

    /** The prescribed stub, offering `import` and pinned at [ref]. */
    private fun v2Stub(ref: String = ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE) =
        stubWith("        options: [plan, apply]", "        options: [plan, apply, import]").replace("@cli-v0.36.0", "@$ref")

    // ── dispatch.import-capable ──────────────────────────────────────────────────────────────────────────────────

    @Test
    fun `a v1 stub stays valid and is never import-capable`() {
        val report = evaluate(WorkflowFixtures.STUB)
        assertThat(report.ok).isTrue()
        val rule = report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE)
        assertThat(rule.status).isEqualTo(Status.PASS)
        assertThat(rule.detail).contains("never dispatches the configuration import").contains(ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE)
        assertThat(report.importCapable).isFalse()
        assertThat(report.toStructured()["importCapable"]).isEqualTo(false)
        assertThat(report.toStructured()["contractVersion"]).isEqualTo(2)
    }

    @Test
    fun `a v1 stub pinned at the import release is still not import-capable — the App reads the options, not the pin`() {
        val report = evaluate(WorkflowFixtures.STUB.replace("@cli-v0.36.0", "@${ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE}"))
        assertThat(report.ok).isTrue()
        assertThat(report.importCapable).isFalse()
    }

    @Test
    fun `a v2 stub at the import release offers import and is import-capable`() {
        val report = evaluate(v2Stub())
        assertThat(report.rules.filter { it.failed }).withFailMessage("%s", report.rules.filter { it.failed }).isEmpty()
        assertThat(report.rule("dispatch.inputs").detail).contains("plan, apply, import")
        assertThat(report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE).status).isEqualTo(Status.PASS)
        assertThat(report.importCapable).isTrue()
        assertThat(report.toStructured()["importCapable"]).isEqualTo(true)
    }

    @Test
    fun `a stub that offers import while pinned to an older release is refused — it would run zero jobs and report green`() {
        val report = evaluate(v2Stub("cli-v0.50.0"))
        val rule = report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE)
        assertThat(rule.status).isEqualTo(Status.FAIL)
        assertThat(rule.detail).contains("@cli-v0.50.0").contains("no `import` job").contains("zero jobs")
        assertThat(rule.fix).contains(ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE).contains("drop `import`")
        assertThat(report.importCapable).isFalse()
        assertThat(report.ok).isFalse()
        // Only that rule: the stub is otherwise a valid v1-pinned stub.
        assertThat(report.rules.filter { it.failed }.map { it.id }).containsExactly(WorkflowCheck.IMPORT_CAPABLE_RULE)
    }

    @Test
    fun `a stub that offers import pinned to a commit cannot be dated — unverifiable, never a pass`() {
        val report = evaluate(v2Stub("0123456789abcdef0123456789abcdef01234567"))
        assertThat(report.rule("stub.uses").status).isEqualTo(Status.PASS)
        assertThat(report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE).status).isEqualTo(Status.UNVERIFIABLE)
        assertThat(report.importCapable).isFalse()
    }

    @Test
    fun `a stub that offers import but overrides cli-version to an older CLI is refused`() {
        val report = evaluate(v2Stub().replace("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n      cli-version: cli-v0.50.0"))
        val rule = report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE)
        assertThat(rule.status).isEqualTo(Status.FAIL)
        assertThat(rule.detail).contains("cli-version: cli-v0.50.0")
        assertThat(report.importCapable).isFalse()
    }

    @Test
    fun `mode offers only the v1 or the v2 set`() {
        val reordered = evaluate(stubWith("        options: [plan, apply]", "        options: [plan, import]"))
        assertThat(reordered.rule("dispatch.inputs").status).isEqualTo(Status.FAIL)
        assertThat(reordered.rule("dispatch.inputs").detail).contains("[plan, apply] or [plan, apply, import]")
    }

    @Test
    fun `a foreign stub that offers import is unverifiable`() {
        val report = evaluate(v2Stub().replace("thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@${ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE}", "acme/platform/.github/workflows/thoryn.yml@v3"))
        assertThat(report.shape).isEqualTo(Shape.FOREIGN_STUB)
        assertThat(report.rule(WorkflowCheck.IMPORT_CAPABLE_RULE).status).isEqualTo(Status.UNVERIFIABLE)
        assertThat(report.importCapable).isFalse()
    }

    @Test
    fun `a hand-written workflow that offers import needs an import job in the plan environment uploading thoryn-import`() {
        val offering = WorkflowFixtures.FULL_CUSTOM.replace("options: [plan, apply]", "options: [plan, apply, import]")
        check(offering != WorkflowFixtures.FULL_CUSTOM)
        val missing = evaluate(offering).rule(WorkflowCheck.IMPORT_CAPABLE_RULE)
        assertThat(missing.status).isEqualTo(Status.FAIL)
        assertThat(missing.detail).contains("no job gated `if: inputs.mode == 'import'`")

        fun withImportJob(environment: String) = offering.trimEnd() + "\n" + """
          import:
            if: inputs.mode == 'import'
            runs-on: ubuntu-latest
            environment: $environment
            permissions: { id-token: write, checks: write, contents: read }
            steps:
              - uses: actions/checkout@v4
                with: { ref: "${'$'}{{ inputs.head_sha }}" }
              - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
                with: { name: thoryn-import, path: out }
        """.trimIndent().prependIndent("  ") + "\n"
        val good = evaluate(withImportJob("thoryn-provision-e2e-plan"))
        assertThat(good.rule(WorkflowCheck.IMPORT_CAPABLE_RULE).status).withFailMessage(good.rule(WorkflowCheck.IMPORT_CAPABLE_RULE).detail).isEqualTo(Status.PASS)
        assertThat(good.importCapable).isTrue()
        val writeEnv = evaluate(withImportJob("thoryn-provision-e2e")).rule(WorkflowCheck.IMPORT_CAPABLE_RULE)
        assertThat(writeEnv.status).isEqualTo(Status.FAIL)
        assertThat(writeEnv.detail).contains("apply environment")
    }

    // ── reusable.jobs / reusable.import-job ──────────────────────────────────────────────────────────────────────

    private val reusable: String = CiIdentityFixture.locate(ProvisioningWorkflowContract.REUSABLE_WORKFLOW_PATH).readText()
    private val importStart = reusable.indexOf("\n  import:\n")

    /** Replace [old] inside the import job only (the plan / apply jobs share much of its text). */
    private fun importJobWith(old: String, new: String): String {
        check(importStart > 0) { "no import job" }
        val head = reusable.substring(0, importStart); val job = reusable.substring(importStart)
        check(job.contains(old)) { "import job has no '$old'" }
        return head + job.replaceFirst(old, new)
    }

    private fun rule(text: String, id: String) = WorkflowCheck.evaluate(text, "provisioning.yml").rules.single { it.id == id }

    @Test
    fun `the reusable workflow in this repository carries the import job and is import-capable`() {
        val report = WorkflowCheck.evaluate(reusable, "provisioning.yml")
        assertThat(report.rule(WorkflowCheck.IMPORT_JOB_RULE).status).withFailMessage(report.rule(WorkflowCheck.IMPORT_JOB_RULE).detail).isEqualTo(Status.PASS)
        assertThat(report.importCapable).isTrue()
    }

    @Test
    fun `the import job must run in the plan environment — never apply-environment`() {
        val mutated = importJobWith("environment: \${{ inputs.plan-environment }}", "environment: \${{ inputs.apply-environment }}")
        val jobs = rule(mutated, "reusable.jobs")
        assertThat(jobs.status).isEqualTo(Status.FAIL)
        assertThat(jobs.detail).contains("import must run in `environment: \${{ inputs.plan-environment }}`")
    }

    @Test
    fun `a reusable workflow without the import job fails and is not import-capable`() {
        val mutated = reusable.substring(0, importStart) + "\n"
        assertThat(rule(mutated, "reusable.jobs").detail).contains("jobs must be exactly plan, apply, import")
        assertThat(rule(mutated, WorkflowCheck.IMPORT_JOB_RULE).status).isEqualTo(Status.FAIL)
        assertThat(WorkflowCheck.evaluate(mutated, "provisioning.yml").importCapable).isFalse()
    }

    @Test
    fun `the import job is held to each property the App relies on — one mutation each`() {
        val mutations = listOf(
            importJobWith("--for-workflow \"\$file\" ", "") to "--for-workflow",
            importJobWith("--file \"\$out/\$file\" --write", "--write") to "never the checkout",
            importJobWith("--file \"\$out/\$file\" --write", "--file \"\$out/\$file\"") to "`--write` the copy",
            importJobWith("java -jar thoryn.jar provision plan --file \"\$out/\$file\" --output json", "true") to "preview",
            importJobWith("java -jar thoryn.jar provision workflow import-summary --artifact", "echo --artifact") to "import-summary",
            importJobWith("            i=\$((i + 1))\n", "            java -jar thoryn.jar provision apply --file \"\$file\" --yes\n            i=\$((i + 1))\n") to "never apply",
            importJobWith("          include-hidden-files: true\n", "") to "include-hidden-files",
            importJobWith("          if-no-files-found: error\n", "") to "if-no-files-found: error",
            importJobWith("          name: thoryn-import\n          path: \${{ runner.temp }}/thoryn-import\n          include-hidden-files: true\n          if-no-files-found: error\n          retention-days: 7", "          name: thoryn-import\n          path: \${{ runner.temp }}/thoryn-import\n          include-hidden-files: true\n          if-no-files-found: error\n          retention-days: 30") to "retention-days: 7",
            importJobWith("      - name: Upload the imported files\n", "      - name: Upload the imported files\n        if: always()\n") to "successful job",
            importJobWith("          name: thoryn-import\n", "          name: provision-import\n") to "exactly one `thoryn-import`",
        )
        mutations.forEach { (text, expected) ->
            val r = rule(text, WorkflowCheck.IMPORT_JOB_RULE)
            assertThat(r.status).withFailMessage("expected FAIL mentioning '%s', got %s: %s", expected, r.status, r.detail).isEqualTo(Status.FAIL)
            assertThat(r.detail).contains(expected)
            assertThat(WorkflowCheck.evaluate(text, "provisioning.yml").importCapable).isFalse()
        }
    }

    // ── reusable.no-write-back covers the import job ─────────────────────────────────────────────────────────────

    @Test
    fun `the import job writes nothing back — contents write, a push, a commit or a pull request each fail`() {
        val mutations = listOf(
            importJobWith("      checks: write\n      contents: read", "      checks: write\n      contents: write"),
            importJobWith("      checks: write\n      contents: read", "      checks: write\n      contents: read\n      pull-requests: write"),
            importJobWith("            i=\$((i + 1))\n", "            git push origin HEAD:thoryn/import-config\n            i=\$((i + 1))\n"),
            importJobWith("            i=\$((i + 1))\n", "            git commit -am import\n            i=\$((i + 1))\n"),
            importJobWith("            i=\$((i + 1))\n", "            gh pr create --title import\n            i=\$((i + 1))\n"),
        )
        mutations.forEach { text ->
            assertThat(rule(text, "reusable.no-write-back").status).withFailMessage("no-write-back should FAIL on:\n%s", text.substring(importStart)).isEqualTo(Status.FAIL)
        }
        // And the job as committed holds contents: read only.
        assertThat(rule(reusable, "reusable.no-write-back").status).isEqualTo(Status.PASS)
    }
}
