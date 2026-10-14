package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.E2E_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISIONING_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_ACTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.TRUSTS_PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.TWO_TRUST_RESIDUE
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.repositoryRoot
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionResource
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3697 / SSO-3705 (parent SSO-3659) — repo-level test binding the founder-applied trusts file
 * (`.thoryn/trusts.provision.yaml`) to the connection contract: the ONE declared trust (SSO-3689
 * `kind: workloadIdentityTrust`) must carry EXACTLY the pins and scopes `connection.json` mirrors — the file is how
 * the trust is re-created from code, and a declared field that differs from the live trust is
 * `workload_identity_trust_immutable`, so the two files cannot drift apart silently.
 *
 * ONE trust for plan and apply (SSO-3699 option B): SSO-3697's second trust is gone — the plan profile (SSO-3700; declared
 * here as `spec.plan` by SSO-3704) is a second PROFILE of the one trust, not a second trust, so a second declaration here
 * would be the never-created identity that stopped provision-e2e run 38547022158 coming back. The profile is keyed on the
 * unprotected environment the App's plan job declares and lists no scopes: the hub derives the `.read` members of the
 * trust's scopes, which must be exactly what a plan of `provision.yaml` needs ([CiIdentityFixture.scopesToPlan]).
 *
 * The file is applied by a founder, never by CI (see the file header): a production-plane trust is reached
 * through the workspace, and a file cannot declare the trust its own identity signs in with.
 */
class CiTrustsFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(TRUSTS_PROVISION_PATH))
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    private val trust: ProvisionResource get() = file.resources.single()
    private val provisionFile: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))

    @Suppress("UNCHECKED_CAST")
    private fun github(trust: ProvisionResource): Map<String, Any?> = trust.spec["github"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun scopes(trust: ProvisionResource): Set<String> = (trust.spec["scopes"] as List<Any?>).map { it.toString() }.toSet()

    @Test
    fun `the trusts file declares exactly ONE trust — thoryn-cli-ci on the production plane — and no plan twin`() {
        assertThat(file.resources.map { it.key })
            .containsExactly("${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST}/${CiIdentityFixture.TRUST_NAME}")
        // Production plane (its token must address `application:cli` and the sandbox, whose parent is the
        // workspace) — so the hub requires the confirmation, and the schema a GitHub environment pin.
        assertThat(trust.environment).withFailMessage("%s must live on the production plane", trust.key).isNull()
        assertThat(trust.spec["confirmProduction"]).withFailMessage("%s must confirm production", trust.key).isEqualTo(true)
        assertThat(trust.spec["provider"]).isEqualTo(ProvisionFile.PROVIDER_GITHUB_ACTIONS)
        assertThat(trust.readOnly).withFailMessage("%s is owned by the founder's file, not a reference", trust.key).isFalse()
        assertThat(trust.grants).withFailMessage("a trust carries no grants (its reach is its environment's)").isNull()
    }

    @Test
    fun `the trust pins this repository by its immutable ids, the REVIEWED environment, main only and GitHub-hosted runners`() {
        val pins = github(trust)
        assertThat(pins["repository"]).isEqualTo("${CiIdentityFixture.GITHUB_OWNER}/${CiIdentityFixture.GITHUB_REPOSITORY}")
        assertThat((pins["ownerId"] as Number).toLong()).isEqualTo(CiIdentityFixture.GITHUB_OWNER_ID)
        assertThat((pins["repositoryId"] as Number).toLong()).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY_ID)
        assertThat(pins["environment"]).isEqualTo(CiIdentityFixture.GITHUB_ENVIRONMENT)
        assertThat(pins["ref"]).isEqualTo(CiIdentityFixture.GITHUB_REF)
        assertThat(pins["githubHostedRunnersOnly"]).isEqualTo(true)
    }

    @Test
    fun `the trust mirrors connection json exactly — its environment pin and its six scopes`() {
        assertThat(github(trust)["environment"]).isEqualTo(connection.github!!.environment)
        assertThat(scopes(trust)).isEqualTo(connection.scopes.toSet())
    }

    @Test
    fun `the trust carries its plan profile — keyed on the UNPROTECTED plan environment, scopes omitted so the hub derives exactly what a plan needs`() {
        @Suppress("UNCHECKED_CAST")
        val plan = trust.spec[ProvisionFile.TRUST_PLAN] as? Map<String, Any?>
        assertThat(plan).withFailMessage("%s must declare spec.%s (SSO-3704 — the one trust's read-only plan profile)", trust.key, ProvisionFile.TRUST_PLAN).isNotNull()
        assertThat(plan!!["environment"]).isEqualTo(CiIdentityFixture.PLAN_GITHUB_ENVIRONMENT)
        // The two profiles are the two environments: the plan one must differ from the apply pin (`plan_environment_equals_apply`).
        assertThat(plan["environment"]).isNotEqualTo(github(trust)["environment"])
        // No explicit scopes: the hub DERIVES the `.read` members of the trust's scopes. Listing them would pin what the
        // hub already derives; omitting them keeps the profile in step with the apply scope set by construction.
        assertThat(plan.keys).withFailMessage("spec.plan lists scopes — omit them, the hub derives the .read subset").containsExactly("environment")
        val derived = scopes(trust).filter { it.endsWith(".read") }.toSet()
        assertThat(derived).withFailMessage("the derived plan scopes must be exactly what planning %s needs", PROVISION_PATH)
            .isEqualTo(CiIdentityFixture.scopesToPlan(provisionFile))
        // A strict subset of the apply scopes: read-only by construction, never the whole set.
        assertThat(derived).isSubsetOf(scopes(trust)).hasSizeLessThan(scopes(trust).size)
    }

    @Test
    fun `no committed thoryn file and no workflow mentions the retired two-trust shape`() {
        val root = repositoryRoot()
        val thoryn = java.io.File(root, ".thoryn").listFiles { f -> f.isFile && !f.name.endsWith(".receipt.json") }!!.toList()
        val files = thoryn + listOf(PROVISIONING_WORKFLOW_PATH, E2E_WORKFLOW_PATH, PROVISION_ACTION_PATH).map { java.io.File(root, it) }
        assertThat(files).hasSizeGreaterThanOrEqualTo(7)
        files.forEach { f ->
            val text = f.readText()
            TWO_TRUST_RESIDUE.forEach { token ->
                assertThat(text).withFailMessage("%s still mentions '%s' — the one trust carries its plan profile; the two-trust shape is retired (SSO-3704)", f.toRelativeString(root), token)
                    .doesNotContain(token)
            }
        }
    }
}
