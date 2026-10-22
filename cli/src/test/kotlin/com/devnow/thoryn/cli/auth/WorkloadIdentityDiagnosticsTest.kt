package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.provision.FixRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

/**
 * SSO-3308 — the report a refused workload identity sign-in prints. The platform answers every mismatch
 * with the same `invalid_client`, so the report must carry what was sent, the job's own identity, any
 * difference visible locally, and where the exact reason is (the workspace audit log) — and never the
 * job token.
 */
@org.junit.jupiter.api.TestInstance(org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS)
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
        val report = WorkloadIdentityDiagnostics.render(e, binding)
        assertThat(report).startsWith("Sign-in failed: no GitHub Actions job token available\n\n${FixRequest.OPTION_CLI_HEADING}")
        assertThat(report).doesNotContain("Sent:").contains("permissions: id-token: write")
    }

    // ── SSO-3710 — the one refusal that is a missing RIGHT, not a wrong pin ──

    private val pinned = binding.copy(pins = TrustPins(owner = "thoryn-io", repository = "thoryn-cli", repositoryId = 1044556677, ownerId = 187654321, environment = "thoryn-provision-e2e", ref = "refs/heads/main"))

    @Test
    fun `invalid_client with the job's environment as the ONLY local mismatch is a plan-profile gap, rendered with the set-plan-profile command`() {
        val e = refused(identity(environment = "thoryn-provision-e2e-plan"))

        val gap = WorkloadIdentityDiagnostics.planProfileGap(e, pinned)

        assertThat(gap).isEqualTo(WorkloadIdentityDiagnostics.PlanProfileGap(jobEnvironment = "thoryn-provision-e2e-plan", applyEnvironment = "thoryn-provision-e2e"))
        val item = gap!!.item()
        assertThat(item.kind).isEqualTo(com.devnow.thoryn.provision.FixRequest.Kind.PLAN_PROFILE)
        assertThat(item.cli).isEqualTo("thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment thoryn-provision-e2e-plan")
        // The report prints the SAME item (one rendering) right after the difference it explains.
        val report = WorkloadIdentityDiagnostics.render(e, pinned)
        assertThat(report)
            .contains("environment: the trust pins GitHub environment 'thoryn-provision-e2e'; this job runs in 'thoryn-provision-e2e-plan'.")
            .contains(FixRequest.OPTION_CLI_HEADING)
            .contains(item.cli!!)
            .contains("`thoryn workload-identity trusts list`")
    }

    @Test
    fun `any other refusal shape is no gap — a second mismatch, no environment claim, no pin, a scope refusal, a Kubernetes token`() {
        // A repository mismatch alongside the environment one: a pin problem.
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(refused(identity(environment = "thoryn-provision-e2e-plan", repository = "acme/billing")), pinned)).isNull()
        // The job declares no environment: a missing `environment:` on the job, not a missing profile.
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(refused(identity()), pinned)).isNull()
        // The connection pins no environment: the CLI cannot tell.
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(refused(identity(environment = "x")), binding)).isNull()
        // The job IS in the apply environment: whatever refused it, not the profile.
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(refused(identity(environment = "thoryn-provision-e2e")), pinned)).isNull()
        // Not invalid_client.
        val scope = WorkloadIdentityException("refused", oauthError = "invalid_scope", status = 400, jobIdentity = identity(environment = "thoryn-provision-e2e-plan"))
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(scope, pinned)).isNull()
        // A Kubernetes token has no profiles.
        val pod = JobIdentity.of(FakeJobTokens.kubernetesToken(audience))
        assertThat(WorkloadIdentityDiagnostics.planProfileGap(refused(pod), pinned.copy(provider = WorkloadIdentityDiagnostics.PROVIDER_KUBERNETES))).isNull()
        assertThat(WorkloadIdentityDiagnostics.render(refused(identity(environment = "thoryn-provision-e2e-plan", repository = "acme/billing")), pinned)).doesNotContain("set-plan-profile")
    }

    // ── SSO-3722 / SSO-3723 — EVERY refusal ends with the one "To fix" block, in two options ──

    private val link = "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/38547022158"

    /** Every refusal shape the sign-in can print, with the text its Option 1 must carry (the audited table). */
    private fun shapes(): List<Arguments> {
        val connection = pinned.copy(connectionFile = ".thoryn/connection.json")
        val noPins = binding.copy(connectionFile = ".thoryn/connection.json")
        fun scope(desc: String?, env: String = "thoryn-provision-e2e-plan") = WorkloadIdentityException("refused", oauthError = "invalid_scope", status = 400, errorDescription = desc, jobIdentity = identity(environment = env))
        val pod = JobIdentity.of(FakeJobTokens.kubernetesToken(audience, namespace = "other"))
        return listOf(
            Arguments.of("not_on_github_actions", WorkloadIdentityException("no job token", oauthError = WorkloadIdentityFlow.ERROR_NOT_ON_GITHUB_ACTIONS), binding, "permissions: id-token: write"),
            Arguments.of("job_token_request_failed", WorkloadIdentityException("GitHub refused", oauthError = WorkloadIdentityFlow.ERROR_JOB_TOKEN_REQUEST_FAILED, status = 403), binding, "permissions: id-token: write"),
            Arguments.of("token_file_unreadable", WorkloadIdentityException("no token at /x", oauthError = WorkloadIdentityFlow.ERROR_TOKEN_FILE_UNREADABLE), binding.copy(provider = WorkloadIdentityDiagnostics.PROVIDER_KUBERNETES), "serviceAccountToken"),
            Arguments.of("invalid_client, no pins known", refused(identity(environment = "x")), binding, WorkloadIdentityDiagnostics.AUDIT_COMMAND),
            Arguments.of("invalid_client, a pin differs (repository)", refused(identity(environment = "thoryn-provision-e2e", repository = "acme/billing")), connection, "--repository acme/billing --owner-id 187654321 --repository-id 1044556677 --github-environment thoryn-provision-e2e --ref refs/heads/main --scope \"tenant:environments.read\""),
            Arguments.of("invalid_client, the job declares no environment", refused(identity()), connection, "job: add `environment: thoryn-provision-e2e` to the job"),
            Arguments.of("invalid_client, the plan-profile gap", refused(identity(environment = "thoryn-provision-e2e-plan")), connection, FixRequest.setPlanProfileCommand(null, "thoryn-provision-e2e-plan")),
            Arguments.of("invalid_client, a pod on the wrong namespace", refused(pod), binding.copy(provider = WorkloadIdentityDiagnostics.PROVIDER_KUBERNETES, kubernetesPins = KubernetesPins(namespace = "forge")), "--provider kubernetes --issuer ${FakeJobTokens.KUBERNETES_ISSUER} --namespace other --service-account forge-oauth2-proxy"),
            Arguments.of("invalid_scope outside the plan profile, flag form", scope(WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN), binding, "drop --scope"),
            Arguments.of("invalid_scope outside the plan profile, connection without an apply environment", scope(WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN), noPins, ".thoryn/connection.json: names no apply environment — add auth.github.environment"),
            Arguments.of("invalid_scope outside the plan profile, connection naming the wrong apply environment", scope(WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN, env = "thoryn-provision-e2e"), connection.copy(profile = WorkloadProfile.APPLY), "auth.github.environment names 'thoryn-provision-e2e' but the hub matched the PLAN profile"),
            Arguments.of("invalid_scope outside the apply profile", scope(WorkloadIdentityDiagnostics.REASON_OUTSIDE_APPLY, env = "thoryn-provision-e2e"), connection, "auth.scopes must be a subset of the trust's scopes"),
            Arguments.of("invalid_scope, unspecified", scope(null), binding, "subset of the trust's scopes"),
            Arguments.of("token endpoint unreachable", WorkloadIdentityException("could not reach", oauthError = WorkloadIdentityFlow.ERROR_TRANSPORT, jobIdentity = identity()), binding, "make $audience/oauth2/token reachable"),
            Arguments.of("an unknown platform error", WorkloadIdentityException("server_error", oauthError = "server_error", status = 500, jobIdentity = identity()), binding, WorkloadIdentityDiagnostics.AUDIT_COMMAND),
        )
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("shapes")
    fun `every refusal ends with To fix — Option 1 naming the exact edit or command, Option 2 the run's link when known`(
        name: String, e: WorkloadIdentityException, b: WorkloadIdentityBinding, option1Text: String,
    ) {
        val withLink = WorkloadIdentityDiagnostics.render(e, b, link)
        val lines = withLink.lines()
        assertThat(lines).withFailMessage("[%s]\n%s", name, withLink).anyMatch { it == FixRequest.OPTION_CLI_HEADING }
        assertThat(lines.last()).withFailMessage("[%s]\n%s", name, withLink).isEqualTo("${FixRequest.OPTION_BROWSER_HEADING} $link")
        // The fix the request would carry is the same text (one rendering).
        val fix = WorkloadIdentityDiagnostics.fixFor(e, b)
        assertThat(fix.isEmpty).isFalse()
        val approve = FixRequest.approveRun(fix.items, link)
        if (approve != null) {
            // SSO-3738 — a right the consent can grant: with a link, Option 1 is `thoryn access approve`, never the raw command.
            assertThat(withLink.substringAfter(FixRequest.OPTION_CLI_HEADING)).withFailMessage("[%s]\n%s", name, withLink)
                .contains("thoryn access approve thoryn-io/thoryn-cli/38547022158").doesNotContain(option1Text)
            assertThat(withLink).contains(FixRequest.renderApproveBody(approve, fix.items, fix.notes))
        } else {
            assertThat(withLink.substringAfter(FixRequest.OPTION_CLI_HEADING)).withFailMessage("[%s]\n%s", name, withLink).contains(option1Text)
            assertThat(withLink).contains(FixRequest.renderOption1Body(fix.items, fix.notes))
        }
        // No link known: Option 2 says how to get one, and Option 1 is the exact edit or command (warned when a command).
        val without = WorkloadIdentityDiagnostics.render(e, b)
        assertThat(without.lines().last()).isEqualTo("${FixRequest.OPTION_BROWSER_HEADING} ${FixRequest.NO_CONSENT_LINK_LINE}")
        assertThat(without).doesNotContain(link).doesNotContain("thoryn access approve")
        assertThat(without.substringAfter(FixRequest.OPTION_CLI_HEADING)).withFailMessage("[%s]\n%s", name, without).contains(option1Text)
        assertThat(without).contains(FixRequest.renderOption1Body(fix.items, fix.notes))
    }

    @Test
    fun `the trusts create command is built from the job's own claims — sandbox from the audience, production confirmed`() {
        val sandbox = WorkloadIdentityDiagnostics.trustsCreateCommand(identity(environment = "staging"), pinned.copy(scope = "tenant:applications.write", requestedScope = "tenant:applications.write"))
        assertThat(sandbox).isEqualTo(
            "thoryn workload-identity trusts create --name <name> --environment cli-wif --repository thoryn-io/thoryn-cli --owner-id 187654321 --repository-id 1044556677 " +
                "--github-environment staging --ref refs/heads/main --scope \"tenant:applications.write\"",
        )
        val production = WorkloadIdentityDiagnostics.trustsCreateCommand(identity(environment = "prod"), binding.copy(audience = "https://thoryn.auth.stg.thoryn.org", scope = null, requestedScope = null))
        assertThat(production).endsWith("--github-environment prod --scope \"<scopes>\" --confirm-production").doesNotContain("--environment ")
    }

    @Test
    fun `a hub-decided sign-in names it in the Sent block`() {
        val e = refused(identity(environment = "forge-plan"))
        val report = WorkloadIdentityDiagnostics.render(e, binding.copy(scope = null, hubDecided = true, connectionFile = "c.json"))
        assertThat(report).contains("(none requested — the connection names no apply environment; the hub matches the profile from the job's environment claim)")
            .contains("decided by the hub (no auth.github.environment in the connection)")
    }
}
