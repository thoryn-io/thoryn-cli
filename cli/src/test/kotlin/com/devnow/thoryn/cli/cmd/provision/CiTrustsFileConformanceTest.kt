package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PLAN_CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.TRUSTS_PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionResource
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3697 (parent SSO-3659) — repo-level test binding the founder-applied trusts file
 * (`.thoryn/trusts.provision.yaml`) to the two connection contracts: each declared trust (SSO-3689
 * `kind: workloadIdentityTrust`) must carry EXACTLY the pins and scopes the contract that signs in with it
 * mirrors — the file is how the trusts are re-created from code, and a declared field that differs from the live
 * trust is `workload_identity_trust_immutable`, so the three files cannot drift apart silently.
 *
 * The file is applied by a founder, never by CI (see the file header): a production-plane trust is reached
 * through the workspace, and a file cannot declare the trust its own identity signs in with.
 */
class CiTrustsFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(TRUSTS_PROVISION_PATH))
    private val apply: Connection = Connection.load(locate(CONNECTION_PATH))
    private val plan: Connection = Connection.load(locate(PLAN_CONNECTION_PATH))

    private fun trust(name: String): ProvisionResource = file.resources.single { it.key == "${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST}/$name" }

    @Suppress("UNCHECKED_CAST")
    private fun github(trust: ProvisionResource): Map<String, Any?> = trust.spec["github"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun scopes(trust: ProvisionResource): Set<String> = (trust.spec["scopes"] as List<Any?>).map { it.toString() }.toSet()

    @Test
    fun `the trusts file declares exactly the apply trust and the plan trust, both on the production plane, nothing else`() {
        assertThat(file.resources.map { it.key }).containsExactly(
            "${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST}/${CiIdentityFixture.TRUST_NAME}",
            "${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST}/${CiIdentityFixture.PLAN_TRUST_NAME}",
        )
        file.resources.forEach { t ->
            // Production plane (their tokens must address `application:cli` and the sandbox, whose parent is the
            // workspace) — so the hub requires the confirmation, and the schema a GitHub environment pin.
            assertThat(t.environment).withFailMessage("%s must live on the production plane", t.key).isNull()
            assertThat(t.spec["confirmProduction"]).withFailMessage("%s must confirm production", t.key).isEqualTo(true)
            assertThat(t.spec["provider"]).isEqualTo(ProvisionFile.PROVIDER_GITHUB_ACTIONS)
            assertThat(t.readOnly).withFailMessage("%s is owned by the founder's file, not a reference", t.key).isFalse()
            assertThat(t.grants).withFailMessage("a trust carries no grants (its reach is its environment's)").isNull()
        }
    }

    @Test
    fun `both trusts pin this repository by its immutable ids, main only and GitHub-hosted runners — differing ONLY in the GitHub environment`() {
        file.resources.forEach { t ->
            val pins = github(t)
            assertThat(pins["repository"]).isEqualTo("${CiIdentityFixture.GITHUB_OWNER}/${CiIdentityFixture.GITHUB_REPOSITORY}")
            assertThat((pins["ownerId"] as Number).toLong()).isEqualTo(CiIdentityFixture.GITHUB_OWNER_ID)
            assertThat((pins["repositoryId"] as Number).toLong()).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY_ID)
            assertThat(pins["ref"]).isEqualTo(CiIdentityFixture.GITHUB_REF)
            assertThat(pins["githubHostedRunnersOnly"]).isEqualTo(true)
        }
        // Amendment 5: the environment is the ONLY pin separating the read trust from the write trust.
        assertThat(github(trust(CiIdentityFixture.TRUST_NAME))["environment"]).isEqualTo(CiIdentityFixture.GITHUB_ENVIRONMENT)
        assertThat(github(trust(CiIdentityFixture.PLAN_TRUST_NAME))["environment"]).isEqualTo(CiIdentityFixture.PLAN_GITHUB_ENVIRONMENT)
    }

    @Test
    fun `the apply trust mirrors connection json exactly — its environment pin and its six scopes`() {
        val t = trust(CiIdentityFixture.TRUST_NAME)
        assertThat(github(t)["environment"]).isEqualTo(apply.github!!.environment)
        assertThat(scopes(t)).isEqualTo(apply.scopes.toSet())
    }

    @Test
    fun `the plan trust mirrors connection plan json exactly — its environment pin and its read-only scopes`() {
        val t = trust(CiIdentityFixture.PLAN_TRUST_NAME)
        assertThat(github(t)["environment"]).isEqualTo(plan.github!!.environment)
        assertThat(scopes(t)).isEqualTo(plan.scopes.toSet())
        assertThat(scopes(t)).allMatch({ it.endsWith(".read") }, "a `.read` scope — the plan trust can write nothing")
    }
}
