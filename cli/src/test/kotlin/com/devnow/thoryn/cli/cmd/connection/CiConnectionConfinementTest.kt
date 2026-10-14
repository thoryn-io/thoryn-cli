package com.devnow.thoryn.cli.cmd.connection

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.E2E_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2951 (epic SSO-2947) — repo-level **confinement** test binding THIS repo's committed connection
 * contract (`.thoryn/connection.json`) to the ADR's "scope ceiling" layer
 * (`2026-09-09-thoryn-cli-as-code-ci-connection-contract.md`).
 *
 * **SSO-3690 (parent SSO-3659).** The contract is a `workload_identity` connection: CI signs in by
 * exchanging the job's own GitHub Actions OIDC token under the `thoryn-cli-ci` trust — no secret anywhere,
 * so the file names no env var. The trust is created once by a founder and is declared in no committed
 * file (the engine has no trust kind yet, SSO-3689), so this test pins the contract to what that one
 * `thoryn workload-identity trusts create` must have carried ([CiIdentityFixture]): the production-plane
 * audience, the repository's immutable ids, the GitHub environment and `ref` pins, GitHub-hosted runners
 * only — and the scope set to EXACTLY what converging `.thoryn/provision.yaml` needs (ceiling AND floor).
 * It also holds the e2e workflow to the pins: a job that does not declare the pinned environment, or that
 * cannot request an OIDC token, cannot sign in; a job that still injects the retired secret has brought the
 * courier back.
 *
 * Until SSO-3690 the ceiling was read from the `cli-ci` application the provisioning file declared under
 * the very `clientId` the contract signed in with. That application is gone (removed once by the founder
 * with `thoryn provision apply --prune`); the identity now lives only in the platform.
 */
class CiConnectionConfinementTest {

    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))
    private val provisionFile: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))

    @Test
    fun `the committed connection loads and validates against the schema as a secret-less workload identity contract`() {
        // Connection.load throws ConnectionException on any schema violation, so a clean load is itself
        // the validation. Assert the load-bearing bindings the CI Action + the README's one-time setup depend on.
        assertThat(connection.slug).isEqualTo("thoryn")
        assertThat(connection.hubBaseUrlEnv).isEqualTo("THORYN_HUB")
        assertThat(connection.method).isEqualTo(Connection.AUTH_METHOD_WORKLOAD_IDENTITY)
        assertThat(connection.isWorkloadIdentity).isTrue()
        // No secret, no env var naming one: the job token is the credential (ladder rung 4 retired, SSO-3690).
        assertThat(connection.secretEnvOrNull).isNull()
        assertThat(connection.clientId).startsWith(CiIdentityFixture.WORKLOAD_CLIENT_ID_PREFIX)
        assertThat(connection.scopes).isNotEmpty()
    }

    @Test
    fun `the connection names the production-plane audience of the thoryn workspace, not a sandbox`() {
        // A sandbox trust's token cannot address production-plane objects (the `ci` ENVIRONMENT the file adopts and
        // whose grants it converges is one — its parent is the workspace), so the trust lives on the production
        // plane: the audience is the workspace issuer with no `/{env}` path and `auth.environment` is absent.
        assertThat(connection.audience).isEqualTo(CiIdentityFixture.AUDIENCE)
        assertThat(connection.environment).isNull()
        assertThat(connection.tokenEndpoint).isNull() // the default `<audience>/oauth2/token`
    }

    @Test
    fun `the connection mirrors the trust's GitHub pins — this repository by its immutable ids, the e2e environment, main only, hosted runners`() {
        val pins = connection.github
        assertThat(pins).withFailMessage("auth.github is absent — the contract must mirror the trust's pins so a refused sign-in names the field that differs").isNotNull()
        assertThat(pins!!.owner).isEqualTo(CiIdentityFixture.GITHUB_OWNER)
        assertThat(pins.repository).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY)
        assertThat(pins.ownerId).isEqualTo(CiIdentityFixture.GITHUB_OWNER_ID)
        assertThat(pins.repositoryId).isEqualTo(CiIdentityFixture.GITHUB_REPOSITORY_ID)
        assertThat(pins.environment).isEqualTo(CiIdentityFixture.GITHUB_ENVIRONMENT) // a production trust must pin one (D8)
        assertThat(pins.ref).isEqualTo(CiIdentityFixture.GITHUB_REF) // a pull request can never sign in
        assertThat(pins.githubHostedRunnersOnly).isTrue()
    }

    @Test
    fun `the connection scopes are exactly what converging the provisioning file needs`() {
        val needed = CiIdentityFixture.scopesToConverge(provisionFile)
        assertThat(connection.scopes.toSet())
            .withFailMessage(
                "connection scopes %s differ from the least-privilege set converging %s needs, %s — the trust is created from " +
                    "this exact list (ceiling AND floor), so the two must be equal.",
                connection.scopes,
                PROVISION_PATH,
                needed,
            )
            .isEqualTo(needed)
    }

    @Test
    fun `the e2e workflow declares the pinned GitHub environment, can request an OIDC token, and injects no secret`() {
        val workflow = locate(E2E_WORKFLOW_PATH).readText()
        // The trust's `sub` pattern is repo:<owner>/<repo>:environment:<env> — a job outside that environment is refused.
        assertThat(workflow).containsPattern(Regex("(?m)^\\s+environment:\\s*${Regex.escape(connection.github!!.environment!!)}\\s*$").toPattern())
        // Without `id-token: write` the job cannot request the OIDC token the exchange needs.
        assertThat(workflow).containsPattern(Regex("(?m)^\\s+id-token:\\s*write\\b").toPattern())
        // The courier is gone: no client-secret input, no repository secret, nothing named after the retired env var.
        assertThat(workflow).doesNotContain("client-secret:")
        assertThat(workflow).doesNotContain("secrets.")
        assertThat(workflow).doesNotContain("THORYN_CLI_CI_CLIENT_SECRET")
    }
}
