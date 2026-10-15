package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.E2E_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.REUSABLE_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_ACTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.provision.FixRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3710 (oauthy ADR 2026-10-15 §1, decision 2 of its open questions: "the dogfood workflows get the artifact upload
 * step NOW; the composite Action follows") — holds the REUSABLE provisioning workflow (SSO-3719: the App-dispatched stub
 * calls it, so it is where the jobs live), the manual e2e workflow and the composite Action to the fix-request contract
 * the Thoryn GitHub App consumes (SSO-3711):
 *
 *  - every job that signs in or plans asks the CLI for the request through [FixRequest.ENV] — the ENV spelling, not
 *    the flag, because the pinned release ([CiIdentityFixture.CLI_RELEASE]) predates `--fix-request` and must keep
 *    running: an unknown env var is ignored, an unknown flag is a usage error;
 *  - each such job uploads it with `actions/upload-artifact` pinned to a full commit SHA, `if: failure()`, under the
 *    artifact name the App looks for ([FixRequest.ARTIFACT_NAME]), `if-no-files-found: ignore` (no file until the pin
 *    moves to a release that writes one), `retention-days: 7` (the consent's own TTL);
 *  - the Action resolves ONE path, exposes it as the `fix-request` output, and hands it to both the sign-in and the
 *    apply step; the upload stays in the caller (an Action cannot upload an artifact for its caller's run reliably).
 *  - no `${{ }}` inside any new `run:` block (the template-injection rule, oauthy SSO-3635).
 */
class CiFixRequestConformanceTest {

    private val yaml = YAMLMapper.builder().build()
    private val provisioningText = locate(REUSABLE_WORKFLOW_PATH).readText()
    private val provisioning: JsonNode = yaml.readTree(provisioningText)
    private val e2eText = locate(E2E_WORKFLOW_PATH).readText()
    private val e2e: JsonNode = yaml.readTree(e2eText)
    private val actionText = locate(PROVISION_ACTION_PATH).readText()
    private val action: JsonNode = yaml.readTree(actionText)

    private fun JsonNode.steps(): List<JsonNode> = this["steps"].toList()

    /** The one upload step of a job: pinned, on failure only, the App's artifact name, tolerant of no file, seven days. */
    private fun assertUploadStep(step: JsonNode, expectedPath: String) {
        assertThat(step["uses"].asString()).matches("^actions/upload-artifact@[0-9a-f]{40}$")
        assertThat(step["uses"].asString()).isEqualTo("actions/upload-artifact@$UPLOAD_ARTIFACT_SHA")
        assertThat(step["if"].asString()).startsWith("failure()")
        val with = step["with"]
        assertThat(with["name"].asString()).isEqualTo(FixRequest.ARTIFACT_NAME)
        assertThat(with["path"].asString()).isEqualTo(expectedPath)
        assertThat(with["if-no-files-found"].asString()).isEqualTo("ignore")
        assertThat(with["retention-days"].asInt()).isEqualTo(7)
    }

    private fun uploadStep(job: JsonNode): JsonNode = job.steps().single { it["uses"]?.asString()?.startsWith("actions/upload-artifact@") == true }

    @Test
    fun `the reusable plan job asks for the request through THORYN_FIX_REQUEST and uploads it on failure`() {
        val plan = provisioning["jobs"]["plan"]
        val planStep = plan.steps().single { it["run"]?.asString()?.contains("provision plan") == true }
        val requestPath = "\${{ runner.temp }}/${FixRequest.FILE_NAME}"
        assertThat(planStep["env"][FixRequest.ENV].asString()).isEqualTo(requestPath)
        // The sign-in and the plan run in that step, so both producers see the variable.
        assertThat(planStep["run"].asString()).contains("login --connection").contains("provision plan")
        assertThat(planStep["run"].asString()).doesNotContain("--fix-request")
        assertUploadStep(uploadStep(plan), requestPath)
        // The upload follows the plan step (there is nothing to upload before it ran).
        assertThat(plan.steps().indexOf(uploadStep(plan))).isGreaterThan(plan.steps().indexOf(planStep))
    }

    @Test
    fun `the reusable apply job asks for the request on its apply step, uploads it on failure, and ends at Applied — no receipt pull request`() {
        val apply = provisioning["jobs"]["apply"]
        val steps = apply.steps()
        val applyStep = steps.single { it["run"]?.asString()?.contains("provision apply") == true }
        val requestPath = "\${{ runner.temp }}/${FixRequest.FILE_NAME}"
        assertThat(applyStep["env"][FixRequest.ENV].asString()).isEqualTo(requestPath)
        assertThat(applyStep["run"].asString()).contains("login --connection").doesNotContain("--fix-request")
        val upload = uploadStep(apply)
        assertUploadStep(upload, requestPath)
        assertThat(steps.indexOf(upload)).isGreaterThan(steps.indexOf(applyStep))
        // SSO-3717 — the job ends at "Applied": nothing is written back, the platform is the ledger.
        assertThat(steps.last()["name"].asString()).isEqualTo("Applied")
        assertThat(provisioningText).doesNotContain("gh pr create")
    }

    @Test
    fun `the manual e2e workflow uploads the Action's fix request on failure`() {
        val job = e2e["jobs"]["provision"]
        val action = job.steps().single { it["uses"]?.asString() == "./.github/actions/provision" }
        assertThat(action["id"].asString()).isEqualTo("provision")
        val upload = uploadStep(job)
        assertUploadStep(upload, "\${{ steps.provision.outputs.fix-request }}")
        assertThat(job.steps().indexOf(upload)).isGreaterThan(job.steps().indexOf(action))
    }

    @Test
    fun `the composite Action resolves one fix-request path, exposes it, and hands it to the sign-in and the apply steps through the env var`() {
        assertThat(action["inputs"]["fix-request"]["required"].asBoolean()).isFalse()
        assertThat(action["inputs"]["fix-request"]["default"].asString()).isEmpty()
        assertThat(action["outputs"]["fix-request"]["value"].asString()).isEqualTo("\${{ steps.fix-request.outputs.path }}")
        val steps = action["runs"]["steps"].toList()
        val resolve = steps.single { it["id"]?.asString() == "fix-request" }
        assertThat(resolve["env"]["FIX_REQUEST"].asString()).isEqualTo("\${{ inputs.fix-request }}")
        assertThat(resolve["run"].asString())
            .contains("\${FIX_REQUEST:-\$RUNNER_TEMP/${FixRequest.FILE_NAME}}")
            .contains("echo \"path=\$path\" >> \"\$GITHUB_OUTPUT\"")
        val signIn = steps.single { it["run"]?.asString()?.contains("login --connection") == true }
        val apply = steps.single { it["id"]?.asString() == "apply" }
        assertThat(steps.indexOf(resolve)).isLessThan(steps.indexOf(signIn))
        listOf(signIn, apply).forEach { step ->
            assertThat(step["env"][FixRequest.ENV].asString()).withFailMessage("step '%s' must read the resolved path", step["name"].asString())
                .isEqualTo("\${{ steps.fix-request.outputs.path }}")
            assertThat(step["run"].asString()).doesNotContain("--fix-request")
        }
        // The Action never uploads: the artifact belongs to the caller's run (the two workflows above do it).
        assertThat(steps).noneMatch { it["uses"]?.asString()?.contains("upload-artifact") == true }
    }

    @Test
    fun `no new run block interpolates an expression, and the artifact name is the App's`() {
        (provisioning["jobs"]["plan"].steps() + provisioning["jobs"]["apply"].steps() + e2e["jobs"]["provision"].steps() + action["runs"]["steps"].toList())
            .mapNotNull { it["run"]?.asString() }
            .forEach { run -> assertThat(run).withFailMessage("a run block interpolates an expression:\n%s", run).doesNotContain("\${{") }
        assertThat(FixRequest.ARTIFACT_NAME).isEqualTo("thoryn-provision-request")
        assertThat(FixRequest.FILE_NAME).isEqualTo("thoryn-provision-request.json")
        listOf(provisioningText, e2eText).forEach { assertThat(it).contains("name: ${FixRequest.ARTIFACT_NAME}") }
    }

    private companion object {
        /** `actions/upload-artifact` v4.6.2 (`gh api repos/actions/upload-artifact/git/ref/tags/v4.6.2`). */
        const val UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
    }
}
