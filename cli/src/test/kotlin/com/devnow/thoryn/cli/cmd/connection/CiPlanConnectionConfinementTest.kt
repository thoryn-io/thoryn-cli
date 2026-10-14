package com.devnow.thoryn.cli.cmd.connection

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PLAN_CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3697 (parent SSO-3659) — repo-level **confinement** test for the READ-ONLY plan identity's contract
 * (`.thoryn/connection.plan.json`): what the App-dispatched `plan` job signs in with on every pull request.
 *
 * Oauthy converge ADR 2026-10-13, Amendment 5: a dispatched run executes on `main` in both modes, so the GitHub
 * ENVIRONMENT is the only pin separating "may read" from "may write". This contract therefore mirrors the
 * `thoryn-cli-ci-plan` trust — the same repository, the same `ref`, but the UNPROTECTED `<reviewed>-plan`
 * environment and the `.read` scopes only. A `.write` scope here, or the reviewed environment here, would hand
 * every pull request a writable production token.
 */
class CiPlanConnectionConfinementTest {

    private val plan: Connection = Connection.load(locate(PLAN_CONNECTION_PATH))
    private val apply: Connection = Connection.load(locate(CONNECTION_PATH))
    private val provisionFile: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))

    @Test
    fun `the plan connection loads as a secret-less workload identity contract of the same workspace as the apply connection`() {
        assertThat(plan.slug).isEqualTo(apply.slug)
        assertThat(plan.hubBaseUrlEnv).isEqualTo(apply.hubBaseUrlEnv)
        assertThat(plan.method).isEqualTo(Connection.AUTH_METHOD_WORKLOAD_IDENTITY)
        assertThat(plan.secretEnvOrNull).isNull()
        assertThat(plan.clientId).startsWith(CiIdentityFixture.WORKLOAD_CLIENT_ID_PREFIX)
        // Two trusts, two clients: the plan job must never sign in as the write-capable apply identity.
        assertThat(plan.clientId).isNotEqualTo(apply.clientId)
    }

    @Test
    fun `the plan connection addresses the production plane — the file it plans declares production-plane resources`() {
        assertThat(plan.audience).isEqualTo(CiIdentityFixture.AUDIENCE)
        assertThat(plan.environment).isNull()
        assertThat(plan.tokenEndpoint).isNull()
    }

    @Test
    fun `the plan connection is pinned to this repository, the UNPROTECTED plan environment and main — never the reviewed environment`() {
        val pins = plan.github
        assertThat(pins).withFailMessage("auth.github is absent — the plan contract must mirror its trust's pins").isNotNull()
        assertThat(pins!!.owner).isEqualTo(CiIdentityFixture.GITHUB_OWNER)
        assertThat(pins.repository).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY)
        assertThat(pins.ownerId).isEqualTo(CiIdentityFixture.GITHUB_OWNER_ID)
        assertThat(pins.repositoryId).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY_ID)
        // Amendment 5: the environment is the ONLY pin that separates read from write — it must be the plan one.
        assertThat(pins.environment).isEqualTo(CiIdentityFixture.PLAN_GITHUB_ENVIRONMENT)
        assertThat(pins.environment).isNotEqualTo(apply.github!!.environment)
        assertThat(pins.ref).isEqualTo(CiIdentityFixture.GITHUB_REF)
        assertThat(pins.githubHostedRunnersOnly).isTrue()
    }

    @Test
    fun `the plan connection scopes are exactly the read set planning the provisioning file needs — no write scope at all`() {
        val needed = CiIdentityFixture.scopesToPlan(provisionFile)
        assertThat(plan.scopes.toSet())
            .withFailMessage("plan connection scopes %s differ from the read set planning %s needs, %s", plan.scopes, PROVISION_PATH, needed)
            .isEqualTo(needed)
        assertThat(plan.scopes).allMatch({ it.endsWith(".read") }, "a `.read` scope")
        // …and a strict subset of the apply identity's: the plan can do nothing the apply could not.
        assertThat(apply.scopes).containsAll(plan.scopes)
        assertThat(plan.scopes).hasSizeLessThan(apply.scopes.size)
    }
}
