package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-4472 — a refused Forgejo sign-in explained: the job's CLAIMS (never the token), the pins that differ against the
 * connection's `auth.forgejo` (the instance via `iss`, the repository and its ids), the trigger class the amendment's
 * rule refuses, and the fix for each shape — on a neutral instance.
 */
class WorkloadIdentityForgejoDiagnosticsTest {

    private val audience = "https://acme.auth.example.org"
    private val pins = ForgejoPins(
        instanceUrl = FakeJobTokens.FORGEJO_INSTANCE, owner = "acme", repository = "infra", ownerId = 7, repositoryId = 42, ref = "refs/heads/main",
    )

    private fun binding(plan: Boolean = false, pins: ForgejoPins? = this.pins, provider: String? = "forgejo") = WorkloadIdentityBinding(
        clientId = "wi_5e4f3a2b1c0d9e8f7a6b5c4d", audience = audience, tokenEndpoint = "$audience/oauth2/token", scope = null,
        provider = provider, hubDecided = true, connectionFile = ".thoryn/connection.json", requestedScope = "tenant:applications.write",
        forgejoPins = pins, forgejoPlanProfile = plan,
    )

    private fun refused(token: String) = WorkloadIdentityException(
        "the platform refused the exchange (HTTP 401: invalid_client)", oauthError = "invalid_client", status = 401, jobIdentity = JobIdentity.of(token),
    )

    @Test
    fun `the report shows the Forgejo job's claims and its trigger class, never the token`() {
        val token = FakeJobTokens.forgejoToken(audience, eventName = "workflow_dispatch")

        val report = WorkloadIdentityDiagnostics.render(refused(token), binding())

        assertThat(report).doesNotContain(token)
            .doesNotContain(token.substringAfter('.').substringBefore('.')) // not even the payload segment
            .contains("This job (claims of its Forgejo Actions OIDC token; the token itself is not shown):")
            .contains("${FakeJobTokens.FORGEJO_INSTANCE}/api/actions")
            .contains("repo:acme-7/infra-42:ref:refs/heads/main")
            .contains("acme/infra")
            .contains("trigger class        dispatch")
            .contains("No difference found locally against the pins the connection names.")
            .contains("Whoever administers the instance controls its signing keys.")
            .doesNotContain("GitHub OIDC token")
            .doesNotContain("runner_environment")
    }

    @Test
    fun `another instance, a re-created repository and a fork's owner are each named against auth-forgejo`() {
        val claims = FakeJobTokens.forgejoClaims(audience, instance = "https://forge.example.net", ownerId = "8", repositoryId = "43", eventName = "workflow_dispatch")
        val mismatches = WorkloadIdentityDiagnostics.localMismatches(JobIdentity.of(FakeJobTokens.token(claims)), audience, null, "forgejo", forgejoPins = pins)

        assertThat(mismatches).anyMatch { it.startsWith("iss: the trust pins instance '${FakeJobTokens.FORGEJO_INSTANCE}'") && it.contains("https://forge.example.net/api/actions") }
        assertThat(mismatches).anyMatch { it.startsWith("repository_id: the trust pins 42") }
        assertThat(mismatches).anyMatch { it.startsWith("repository_owner_id: the trust pins 7") }
        // A Forgejo token is never judged against GitHub's issuer.
        assertThat(mismatches).noneMatch { it.contains(WorkloadIdentityFlow.GITHUB_ACTIONS_ISSUER) }
        val fix = WorkloadIdentityDiagnostics.fixFor(refused(FakeJobTokens.token(claims)), binding())
        assertThat(fix.notes.joinToString("\n")).contains("trust: re-create it with the job's own pins")
            .contains("--provider forgejo --instance https://forge.example.net --repository acme/infra --owner-id 8 --repository-id 43 --ref refs/heads/main")
    }

    @Test
    fun `a push on the pinned ref without a plan profile is the trust's missing plan profile, with the command that adds it`() {
        val e = refused(FakeJobTokens.forgejoToken(audience, eventName = "push"))

        val mismatches = WorkloadIdentityDiagnostics.localMismatches(e.jobIdentity!!, audience, null, "forgejo", forgejoPins = pins)
        assertThat(mismatches).singleElement().satisfies({ assertThat(it).startsWith("trigger: event_not_allowed — a push on 'refs/heads/main' gets the trust's PLAN profile") })
        val notes = WorkloadIdentityDiagnostics.fixFor(e, binding()).notes
        assertThat(notes).singleElement().satisfies({ assertThat(it).contains("trusts set-plan-profile <id>").contains("auth.plan") })
        // With the plan profile mirrored, the same push is expected to plan — nothing to point at locally.
        assertThat(WorkloadIdentityDiagnostics.localMismatches(e.jobIdentity!!, audience, null, "forgejo", forgejoPins = pins, forgejoPlanProfile = true)).isEmpty()
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(e, binding())).isNull() // no GitHub-environment fix item for Forgejo
    }

    @Test
    fun `a workflow_call job is refused on every plane, and the fix is to call thoryn from the job's own steps`() {
        val e = refused(FakeJobTokens.forgejoToken("$audience/staging", eventName = "workflow_call"))
        val sandbox = binding(pins = pins.copy(ref = null)).copy(audience = "$audience/staging")

        assertThat(WorkloadIdentityDiagnostics.localMismatches(e.jobIdentity!!, sandbox.audience, null, "forgejo", forgejoPins = sandbox.forgejoPins))
            .anyMatch { it.startsWith("trigger: event_not_allowed — workflow_call jobs are always refused") }
        assertThat(WorkloadIdentityDiagnostics.fixFor(e, sandbox).notes).anyMatch { it.contains("never inside a reusable workflow") }
    }

    @Test
    fun `the flag form infers Forgejo from the token's issuer`() {
        val e = refused(FakeJobTokens.forgejoToken(audience, eventName = "workflow_dispatch"))

        val report = WorkloadIdentityDiagnostics.render(e, binding(provider = null, pins = null))

        assertThat(report).contains("claims of its Forgejo Actions OIDC token").contains("auth.forgejo")
        assertThat(WorkloadIdentityDiagnostics.trustsCreateCommand(e.jobIdentity!!, binding(provider = null, pins = null)))
            .contains("--provider forgejo --instance ${FakeJobTokens.FORGEJO_INSTANCE} --repository acme/infra --owner-id 7 --repository-id 42 --ref refs/heads/main")
            .contains("--confirm-production")
    }

    @Test
    fun `a failure before any token — outside Forgejo Actions, or a redirected token URL — names the Forgejo fix`() {
        val notOnForgejo = WorkloadIdentityException("x", oauthError = WorkloadIdentityFlow.ERROR_NOT_ON_FORGEJO_ACTIONS)
        assertThat(WorkloadIdentityDiagnostics.fixFor(notOnForgejo, binding()).notes.joinToString("\n"))
            .contains("enable-openid-connect: true").contains("auth.tokenSource")
        val redirected = WorkloadIdentityException("x", oauthError = WorkloadIdentityFlow.ERROR_JOB_TOKEN_REDIRECTED, status = 302)
        assertThat(WorkloadIdentityDiagnostics.fixFor(redirected, binding()).notes.single())
            .contains("authenticating proxy").contains("\"kind\": \"file\"")
    }
}
