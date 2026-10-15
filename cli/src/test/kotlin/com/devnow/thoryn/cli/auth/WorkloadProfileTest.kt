package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3702 (SSO-3699 option B) — the profile selector and the profile-aware refusal report. The hub decides the
 * profile from the job token's `environment` claim; the CLI only mirrors that decision to choose whether to send
 * `scope`, and names the profile the hub's `invalid_scope` description points at.
 */
class WorkloadProfileTest {

    private val audience = "https://thoryn.auth.stg.thoryn.org"

    private fun identity(environment: String?) = JobIdentity.of(FakeJobTokens.token(FakeJobTokens.claims(audience, environment = environment)))

    @Test
    fun `the job's environment claim equal to the apply environment selects apply, any other declared one selects plan`() {
        assertThat(WorkloadProfile.select(identity("prod"), applyEnvironment = "prod")).isEqualTo(WorkloadProfile.APPLY)
        assertThat(WorkloadProfile.select(identity("prod-plan"), applyEnvironment = "prod")).isEqualTo(WorkloadProfile.PLAN)
        assertThat(WorkloadProfile.select(identity("anything-else"), applyEnvironment = "prod")).isEqualTo(WorkloadProfile.PLAN)
    }

    @Test
    fun `without an apply environment, without a job environment, or for a Kubernetes token the CLI cannot tell and selects nothing`() {
        assertThat(WorkloadProfile.select(identity("prod-plan"), applyEnvironment = null)).isNull()
        assertThat(WorkloadProfile.select(identity("prod-plan"), applyEnvironment = "  ")).isNull()
        assertThat(WorkloadProfile.select(identity(null), applyEnvironment = "prod")).isNull()
        val pod = JobIdentity.of(FakeJobTokens.kubernetesToken(audience))
        assertThat(WorkloadProfile.select(pod, applyEnvironment = "prod")).isNull()
    }

    @Test
    fun `the wire values round-trip through the session stamp`() {
        assertThat(WorkloadProfile.of(Tokens.PROFILE_PLAN)).isEqualTo(WorkloadProfile.PLAN)
        assertThat(WorkloadProfile.of(Tokens.PROFILE_APPLY)).isEqualTo(WorkloadProfile.APPLY)
        assertThat(WorkloadProfile.of("other")).isNull()
        assertThat(WorkloadProfile.of(null)).isNull()
    }

    @Test
    fun `an invalid_scope naming scope_outside_plan_profile prints the plan reason, the job's environment and the fix`() {
        val binding = WorkloadIdentityBinding(
            clientId = "wi_0123456789abcdef01234567", audience = audience, tokenEndpoint = "$audience/oauth2/token",
            scope = "tenant:environments.write", pins = TrustPins(environment = "prod"), profile = null,
        )
        val e = WorkloadIdentityException("x", oauthError = "invalid_scope", status = 400, errorDescription = WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN, jobIdentity = identity("prod-plan"))

        val report = WorkloadIdentityDiagnostics.render(e, binding)

        assertThat(report)
            .contains("outside the trust's PLAN profile (HTTP 400: invalid_scope, scope_outside_plan_profile)")
            .contains("runs in GitHub environment 'prod-plan' — not the trust's apply environment 'prod'")
            // SSO-3722 — the fix is the one "To fix" block: the flag form drops --scope (a connection names the file line instead).
            .contains(com.devnow.thoryn.provision.FixRequest.OPTION_CLI_HEADING)
            .contains("job: drop --scope (the hub then mints the plan profile's read-only scopes), or request only .read scopes — never a write scope from a plan job")
    }

    @Test
    fun `an invalid_scope naming scope_outside_apply_profile points at the trust's scope list`() {
        val binding = WorkloadIdentityBinding(clientId = "wi_0123456789abcdef01234567", audience = audience, tokenEndpoint = "$audience/oauth2/token", scope = "tenant:users.write")
        val e = WorkloadIdentityException("x", oauthError = "invalid_scope", status = 400, errorDescription = WorkloadIdentityDiagnostics.REASON_OUTSIDE_APPLY, jobIdentity = identity("prod"))

        assertThat(WorkloadIdentityDiagnostics.render(e, binding))
            .contains("outside the trust's APPLY profile (HTTP 400: invalid_scope, scope_outside_apply_profile)")
            .contains("thoryn workload-identity trusts get <id>")
    }

    @Test
    fun `a plan-profile binding reports that no scope was sent on purpose and which profile it expected`() {
        val binding = WorkloadIdentityBinding(
            clientId = "wi_0123456789abcdef01234567", audience = audience, tokenEndpoint = "$audience/oauth2/token",
            scope = null, pins = TrustPins(environment = "prod"), profile = WorkloadProfile.PLAN,
        )
        val e = WorkloadIdentityException("refused", oauthError = "invalid_client", status = 401, jobIdentity = identity("prod-plan"))

        val report = WorkloadIdentityDiagnostics.render(e, binding)

        assertThat(report)
            .contains("(none requested — the hub mints the matched plan profile's read-only scopes)")
            .contains("profile              plan (job environment 'prod-plan' ≠ apply environment 'prod')")
    }

    @Test
    fun `an invalid_scope without a profile reason keeps the generic wording`() {
        val binding = WorkloadIdentityBinding(clientId = "wi_0123456789abcdef01234567", audience = audience, tokenEndpoint = "$audience/oauth2/token", scope = "tenant:x.read")
        val e = WorkloadIdentityException("x", oauthError = "invalid_scope", status = 400, errorDescription = "unknown scope", jobIdentity = identity("prod"))
        assertThat(WorkloadIdentityDiagnostics.render(e, binding))
            .contains("not within the trust's scopes (HTTP 400: invalid_scope)")
            .contains("platform said: unknown scope")
            .doesNotContain("PLAN profile")
    }
}
