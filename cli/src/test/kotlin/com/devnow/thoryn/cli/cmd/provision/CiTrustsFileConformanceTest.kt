package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.TRUSTS_PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
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
 * ONE trust for plan and apply (SSO-3699 option B): SSO-3697's second trust `thoryn-cli-ci-plan` is gone — the plan
 * profile the hub adds (SSO-3700/SSO-3704) is not a second trust, so a second declaration here would be the
 * never-created identity that stopped provision-e2e run 38547022158 coming back.
 *
 * The file is applied by a founder, never by CI (see the file header): a production-plane trust is reached
 * through the workspace, and a file cannot declare the trust its own identity signs in with.
 */
class CiTrustsFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(TRUSTS_PROVISION_PATH))
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    private val trust: ProvisionResource get() = file.resources.single()

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
}
