package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3308 — the report a refused workload identity sign-in prints. The platform answers every mismatch
 * with the same `invalid_client`, so the report must carry what was sent, the job's own identity, any
 * difference visible locally, and where the exact reason is (the workspace audit log) — and never the
 * job token.
 */
class WorkloadIdentityDiagnosticsTest {

    private val audience = "https://thoryn.auth.stg.thoryn.org/cli-wif"

    private val binding = WorkloadIdentityBinding(
        clientId = "wi_0123456789abcdef01234567",
        audience = audience,
        tokenEndpoint = "$audience/oauth2/token",
        scope = "tenant:environments.read",
    )

    private fun identity(
        environment: String? = null,
        eventName: String = "push",
        repository: String = "thoryn-io/thoryn-cli",
        aud: String = audience,
        runner: String = "github-hosted",
    ) = JobIdentity.of(
        FakeJobTokens.token(
            FakeJobTokens.claims(aud, repository = repository, environment = environment, eventName = eventName, runnerEnvironment = runner),
        ),
    )

    private fun refused(identity: JobIdentity) =
        WorkloadIdentityException("refused", oauthError = "invalid_client", status = 401, jobIdentity = identity)

    @Test
    fun `invalid_client names what was sent, the job's identity and the audit log — without the token`() {
        val token = FakeJobTokens.token(FakeJobTokens.claims(audience, environment = "thoryn-staging-wif"))
        val report = WorkloadIdentityDiagnostics.render(refused(JobIdentity.of(token)), binding)

        assertThat(report)
            .contains("refused the workload identity exchange (HTTP 401: invalid_client)")
            .contains("workload_identity.exchange_failed")
            .contains("thoryn audit query --event-type workload_identity.exchange_failed")
            .contains("wi_0123456789abcdef01234567")
            .contains("$audience/oauth2/token")
            .contains("tenant:environments.read")
            .contains("repo:thoryn-io/thoryn-cli:environment:thoryn-staging-wif")
            .contains("1044556677")
            .contains("187654321")
            .contains("refs/heads/main")
            .contains("github-hosted")
            .doesNotContain(token)
            .doesNotContain(token.substringAfter('.').substringBefore('.'))
    }

    @Test
    fun `pins named by the connection turn into the exact field that differs`() {
        val pins = TrustPins(owner = "acme", repository = "billing", repositoryId = 42, environment = "production", ref = "refs/heads/release")
        val report = WorkloadIdentityDiagnostics.render(refused(identity()), binding.copy(pins = pins))

        assertThat(report)
            .contains("Differences found locally:")
            .contains("repository: the trust pins 'acme/billing'; this job runs in 'thoryn-io/thoryn-cli'.")
            .contains("repository_id: the trust pins 42; this job's repository has id 1044556677")
            .contains("environment: the trust pins GitHub environment 'production'; this job declares no `environment:`")
            .contains("ref: the trust pins 'refs/heads/release'; this job runs on 'refs/heads/main'.")
    }

    @Test
    fun `matching pins report no local difference and still point at the audit log`() {
        val pins = TrustPins(owner = "thoryn-io", repository = "thoryn-cli", repositoryId = 1044556677, ownerId = 187654321)
        val report = WorkloadIdentityDiagnostics.render(refused(identity()), binding.copy(pins = pins))

        assertThat(report).contains("No difference found locally against the pins the connection names.")
            .contains("thoryn audit query")
    }

    @Test
    fun `events the platform always refuses are named even without pins`() {
        assertThat(WorkloadIdentityDiagnostics.localMismatches(identity(eventName = "pull_request_target"), audience, null))
            .anyMatch { it.startsWith("event_name: pull_request_target") }
    }

    @Test
    fun `a production audience names the pull_request and missing-environment refusals`() {
        val production = "https://thoryn.auth.stg.thoryn.org"
        val mismatches = WorkloadIdentityDiagnostics.localMismatches(identity(eventName = "pull_request", aud = production), production, null)
        assertThat(mismatches).anyMatch { it.startsWith("event_name: pull_request jobs are refused by a production trust") }
        assertThat(mismatches).anyMatch { it.startsWith("environment: a production trust requires") }
        // A sandbox audience carries /{env}: neither applies.
        assertThat(WorkloadIdentityDiagnostics.localMismatches(identity(eventName = "pull_request"), audience, null)).isEmpty()
    }

    @Test
    fun `a job token minted for another audience and a self-hosted runner on a hosted-only trust are named`() {
        val mismatches = WorkloadIdentityDiagnostics.localMismatches(
            identity(aud = "https://other.auth.stg.thoryn.org", runner = "self-hosted"),
            audience,
            TrustPins(githubHostedRunnersOnly = true),
        )
        assertThat(mismatches).anyMatch { it.startsWith("aud: the job token is for https://other.auth.stg.thoryn.org") }
        assertThat(mismatches).anyMatch { it.startsWith("runner_environment: the trust accepts only GitHub-hosted runners") }
    }

    @Test
    fun `invalid_scope says to request a subset of the trust's scopes`() {
        val e = WorkloadIdentityException("x", oauthError = "invalid_scope", status = 400, jobIdentity = identity())
        assertThat(WorkloadIdentityDiagnostics.render(e, binding))
            .contains("not within the trust's scopes (HTTP 400: invalid_scope)")
            .contains("subset of the trust's scopes")
    }

    @Test
    fun `a failure before any job token is just its message`() {
        val e = WorkloadIdentityException("no GitHub Actions job token available", oauthError = WorkloadIdentityFlow.ERROR_NOT_ON_GITHUB_ACTIONS)
        assertThat(WorkloadIdentityDiagnostics.render(e, binding)).isEqualTo("Sign-in failed: no GitHub Actions job token available")
    }
}
