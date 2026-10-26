package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3971 — `thoryn project init config` produces the config project in the TENANT + stub shape of the ADR 2026-10-25
 * (provisioning is tenant and applications) and of thoryn-io/thoryn-tenant: both sections load as tenant files, the
 * App-dispatched stub calls the reusable workflow at a cli-v* release (plan in `thoryn-production-plan`, apply in the
 * reviewed `thoryn-production`), `.thoryn/workflow.yaml` names each section with its connection, CODEOWNERS names the
 * reviewers — and the whole tree passes `thoryn provision workflow check`. The production trust carries the plan profile
 * the stub's plan job is minted read-only scopes by.
 */
class ProjectInitConfigWorkflowTest : ProjectTestBase() {

    private val config = arrayOf("project", "init", "config", "--reviewer", "alice", "--confirm-production")

    private fun workflowsIn(dir: Path): List<String> =
        Files.list(dir.resolve(".github/workflows")).use { s -> s.map { it.fileName.toString() }.sorted().toList() }

    @Test
    fun `init config in a clone yields tenant files, the pinned stub, workflow yaml and CODEOWNERS that pass provision workflow check`() {
        api.seedSandbox("qa")
        val dir = clone("acme/platform")

        val (exit, _, err) = runCli(*config, "--dir", dir.toString())

        assertThat(exit).describedAs(err).isEqualTo(0)
        for (section in listOf("production", "sandbox")) {
            val file = dir.resolve(".thoryn/environments/$section/provision.yaml")
            val loaded = ProvisionFile.load(file.toFile())
            assertThat(loaded.part).describedAs(section).isEqualTo(ProvisionPart.TENANT)
            assertThat(loaded.warnings).describedAs(section).isEmpty()
            assertThat(Files.readString(file)).startsWith("# Seeded by `thoryn project init config`").contains("apiVersion: thoryn.io/tenant/v1")
        }

        // The stub is the ONLY workflow — the pre-split variable-driven thoryn.yml is gone with the template.
        assertThat(workflowsIn(dir)).containsExactly("thoryn-provisioning.yml")
        val stub = Files.readString(dir.resolve(ProjectSeeds.WORKFLOW_PATH))
        assertThat(stub)
            .contains("uses: thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@${ProjectSeeds.FALLBACK_STUB_RELEASE}")
            .contains("plan-environment: thoryn-production-plan")
            .contains("apply-environment: thoryn-production")
            .contains("issuer: https://auth.stg.thoryn.org")
            .contains("# thoryn-provisioning: apply-job")
        val workflowConfig = Files.readString(dir.resolve(ProjectSeeds.WORKFLOW_CONFIG_PATH))
        assertThat(workflowConfig)
            .contains("apiVersion: thoryn.io/workflow/v1")
            .contains("  - file: .thoryn/environments/production/provision.yaml\n    connection: .thoryn/environments/production/connection.json")
            .contains("  - file: .thoryn/environments/sandbox/provision.yaml\n    connection: .thoryn/environments/sandbox/connection.json")
            .contains("  prune: false\n  destroy: false")
        assertThat(workflowConfig.indexOf("environments/production/")).isLessThan(workflowConfig.indexOf("environments/sandbox/"))
        assertThat(Files.readString(dir.resolve(".github/CODEOWNERS"))).contains("/.thoryn/environments/production/ @alice")
        assertThat(Files.exists(dir.resolve(".thoryn/ci"))).isFalse()

        val check = runCli("provision", "workflow", "check", "--root", dir.toString())
        assertThat(check.exit).describedAs(check.out + check.err).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(check.out).contains("shape  stub calling the reusable workflow").doesNotContain("FAIL").doesNotContain("UNSUPPORTED")
            .contains("PASS  config.valid").contains("PASS  config.trust-scopes")
    }

    @Test
    fun `the production trust is created with its plan profile on the stub's plan environment, the sandbox trust with none`() {
        api.seedSandbox("qa")
        val dir = clone("acme/platform")

        val (exit, out, err) = runCli(*config, "--dir", dir.toString(), "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val creates = api.writes.filter { it.method == "POST" && it.path == "/api/v1/workload-identity/trusts" }
        assertThat(creates.first { it.env == "production" }.body["plan"]).isEqualTo(mapOf("environment" to "thoryn-production-plan"))
        assertThat(creates.first { it.env == "qa" }.body).doesNotContainKey("plan")
        @Suppress("UNCHECKED_CAST")
        val connections = parseJson(out)["connections"] as List<Map<String, Any?>>
        assertThat(connections.first { it["connection"] == "production" }["planEnvironment"]).isEqualTo("thoryn-production-plan")
        assertThat(connections.first { it["connection"] == "sandbox" }["planEnvironment"]).isNull()
        @Suppress("UNCHECKED_CAST")
        assertThat(parseJson(out)["nextSteps"] as List<String>).anyMatch { it.contains("runs only when the Thoryn GitHub App dispatches it") }
    }

    @Test
    fun `an adopted production trust without a plan profile gets one, and one on another environment stops the run`() {
        api.seedSandbox("qa")
        val dir = clone("acme/platform")
        assertThat(runCli(*config, "--dir", dir.toString()).exit).isEqualTo(0)
        val production = api.trustsIn("production").single()
        production.remove("plan")

        val rerun = runCli(*config, "--dir", dir.toString())

        assertThat(rerun.exit).describedAs(rerun.err).isEqualTo(0)
        assertThat(api.writes.filter { it.path.endsWith("/plan-profile") }.map { it.body }).containsExactly(mapOf("environment" to "thoryn-production-plan"))
        assertThat(production["plan"]).isEqualTo(mapOf("environment" to "thoryn-production-plan", "scopes" to listOf("tenant:environments.read", "tenant:idp.read", "tenant:access.read")))

        production["plan"] = mapOf("environment" to "elsewhere-plan", "scopes" to listOf("tenant:environments.read"))
        val refused = runCli(*config, "--dir", dir.toString())
        assertThat(refused.exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(refused.err).contains("has its plan profile on GitHub environment 'elsewhere-plan'; the config project plans in 'thoryn-production-plan'")
    }

    @Test
    fun `a new config repository gets the stub and workflow yaml in the provisioning pull request, never on the protected default branch`() {
        api.seedSandbox("dev")

        val (exit, _, err) = runCli(*config, "--repo", "acme/platform", "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.files.getValue("acme/platform")).doesNotContainKeys(ProjectSeeds.WORKFLOW_PATH, ProjectSeeds.WORKFLOW_CONFIG_PATH)
        val branch = gh.branches.getValue("acme/platform@${ProjectSeeds.PROVISIONING_BRANCH}")
        assertThat(branch.getValue(ProjectSeeds.WORKFLOW_PATH)).contains("plan-environment: thoryn-production-plan")
        assertThat(branch.getValue(ProjectSeeds.WORKFLOW_CONFIG_PATH)).contains(".thoryn/environments/sandbox/connection.json")
    }

    @Test
    fun `an existing stub and workflow yaml in a clone are kept — the files are in control`() {
        api.seedSandbox("qa")
        val mine = "name: Thoryn provisioning\n# hand-tuned\n"
        val dir = clone("acme/platform", existing = mapOf(ProjectSeeds.WORKFLOW_PATH to mine, ProjectSeeds.WORKFLOW_CONFIG_PATH to "apiVersion: thoryn.io/workflow/v1\n"))

        val (exit, out, err) = runCli(*config, "--dir", dir.toString(), "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(Files.readString(dir.resolve(ProjectSeeds.WORKFLOW_PATH))).isEqualTo(mine)
        @Suppress("UNCHECKED_CAST")
        val files = (parseJson(out)["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>
        assertThat(files.filter { it["kind"] == ProjectSeeds.KIND_WORKFLOW }.map { it["status"] }).containsOnly("kept")
    }

    @Test
    fun `a release build pins the stub to its own cli tag, any other build to the fallback release`() {
        assertThat(ProjectSeeds.stubRelease("0.50.0")).isEqualTo("cli-v0.50.0")
        assertThat(ProjectSeeds.stubRelease("0.0.1-SNAPSHOT")).isEqualTo(ProjectSeeds.FALLBACK_STUB_RELEASE)
        assertThat(ProjectSeeds.stubRelease("unknown")).isEqualTo(ProjectSeeds.FALLBACK_STUB_RELEASE)
    }
}
