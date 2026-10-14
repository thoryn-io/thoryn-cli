package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3702 (SSO-3699 option B) — the plan profile on `thoryn workload-identity trusts`: `create --plan-environment
 * [--plan-scope]` sends the `plan` member (scopes only when explicit — derived by the hub otherwise), refuses locally
 * what product-api (SSO-3701) would refuse with the API's own codes, `get` / `list` render the profile and both
 * subject patterns, and `set-plan-profile <id>` is the one additive mutation with every error code mapped to a
 * message. Fixtures: `trust-created-plan.json` follows the SSO-3701 response shape and carries an unknown field, so
 * the DTO parsing is proven lenient.
 */
class WorkloadIdentityPlanProfileCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(fixture(name))

    private val trustId = "7c2d9e4f-1a3b-4c5d-8e6f-9a0b1c2d3e4f"

    private val sixScopes = "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write tenant:access.read tenant:access.write"

    private fun create(vararg extra: String) = runCli(
        "workload-identity", "trusts", "create", "--name", "thoryn-cli-ci", "--repository", "thoryn-io/thoryn-cli",
        "--owner-id", "229451779", "--repository-id", "1361536515", "--github-environment", "thoryn-provision-e2e",
        "--ref", "refs/heads/main", "--github-hosted-runners-only", "--scope", sixScopes, "--confirm-production",
        "--gateway", baseUrl(), *extra,
    )

    // ── create ────────────────────────────────────────────────────────────────

    @Test
    fun `create --plan-environment sends the plan member WITHOUT scopes so the hub derives them, and prints the plan job`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-plan")))

        val (exit, out, err) = create("--plan-environment", "thoryn-provision-e2e-plan")

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val body = parseJson(server.takeRequest().body.readUtf8())
        @Suppress("UNCHECKED_CAST")
        val plan = body["plan"] as Map<String, Any?>
        assertThat(plan).containsEntry("environment", "thoryn-provision-e2e-plan").doesNotContainKey("scopes")
        // The response's profile and both subject patterns are rendered; the plan job snippet requests no scope.
        assertThat(out)
            .contains("planEnvironment").contains("thoryn-provision-e2e-plan")
            .contains("planScopes").contains("tenant:environments.read tenant:applications.read tenant:access.read")
            .contains("subjectPatterns").contains("environment:\\Qthoryn-provision-e2e-plan\\E")
            .contains("Plan profile — a job in GitHub environment 'thoryn-provision-e2e-plan' (not 'thoryn-provision-e2e')")
            .contains("environment: thoryn-provision-e2e-plan")
            .contains("thoryn login --connection .thoryn/connection.json")
            .contains("scope_outside_plan_profile")
            .doesNotContain("connection.plan.json")
    }

    @Test
    fun `create --plan-scope sends the explicit read-only subset, split and de-duplicated`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-plan")))

        val (exit, _, _) = create("--plan-environment", "thoryn-provision-e2e-plan", "--plan-scope", "tenant:environments.read,tenant:access.read", "--plan-scope", "tenant:access.read")

        assertThat(exit).isEqualTo(0)
        val body = parseJson(server.takeRequest().body.readUtf8())
        @Suppress("UNCHECKED_CAST")
        assertThat(body["plan"] as Map<String, Any?>).containsEntry("scopes", listOf("tenant:environments.read", "tenant:access.read"))
    }

    @Test
    fun `without --plan-environment the body carries no plan member at all`() {
        server.enqueue(jsonResponse(201, fixture("trust-created")))

        val (exit, out, _) = create()

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(server.takeRequest().body.readUtf8())).doesNotContainKey("plan")
        assertThat(out).doesNotContain("Plan profile").doesNotContain("planEnvironment")
    }

    @Test
    fun `create refuses locally with the API's codes — plan scopes without an environment, the apply environment, a write scope, a scope outside --scope, a kubernetes trust`() {
        val noEnv = create("--plan-scope", "tenant:environments.read")
        assertThat(noEnv.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noEnv.err).contains("plan_profile_requires_environment")

        val sameEnv = create("--plan-environment", "thoryn-provision-e2e")
        assertThat(sameEnv.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(sameEnv.err).contains("plan_environment_equals_apply")

        val write = create("--plan-environment", "thoryn-provision-e2e-plan", "--plan-scope", "tenant:environments.write")
        assertThat(write.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(write.err).contains("plan_scope_not_read_only").contains("tenant:environments.write")

        val outside = create("--plan-environment", "thoryn-provision-e2e-plan", "--plan-scope", "tenant:users.read")
        assertThat(outside.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(outside.err).contains("plan_scope_not_subset").contains("tenant:users.read")

        val kubernetes = runCli(
            "workload-identity", "trusts", "create", "--provider", "kubernetes", "--name", "pods", "--issuer", "https://oidc.example/c",
            "--scope", "tenant:applications.read", "--plan-environment", "x", "--gateway", baseUrl(),
        )
        assertThat(kubernetes.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(kubernetes.err).contains("--plan-environment").contains("apply to --provider github_actions only")

        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `the API's plan refusals are rendered with their code and a hint`() {
        server.enqueue(problem(400, "problem-plan-scope-not-read-only"))

        val (exit, _, err) = create("--plan-environment", "thoryn-provision-e2e-plan")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("plan_scope_not_read_only").contains("read-only by construction")
    }

    // ── get / list ────────────────────────────────────────────────────────────

    @Test
    fun `get renders the plan profile, both subject patterns and the plan job's no-scope sign-in — tolerating unknown fields`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", trustId, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("planEnvironment").contains("thoryn-provision-e2e-plan")
            .contains("planScopes")
            .contains("environment:\\Qthoryn-provision-e2e\\E$ | ^repo:")
            .contains("Sign in from the workflow with:")
            .contains("Plan profile — a job in GitHub environment 'thoryn-provision-e2e-plan'")
            .contains("(no --scope)")
    }

    @Test
    fun `get --json passes the API's plan and subjectPatterns through verbatim`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", trustId, "--gateway", baseUrl(), "--json")

        assertThat(exit).isEqualTo(0)
        val node = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        assertThat(node["plan"] as Map<String, Any?>).containsEntry("environment", "thoryn-provision-e2e-plan")
        assertThat(node["subjectPatterns"] as List<*>).hasSize(2)
    }

    @Test
    fun `list shows the plan environment on the pins column`() {
        server.enqueue(jsonResponse(200, """{"data":[${fixture("trust-created-plan").trim()}],"pagination":{"cursor":null,"hasMore":false}}"""))

        val (exit, out, _) = runCli("workload-identity", "trusts", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("env=thoryn-provision-e2e plan=thoryn-provision-e2e-plan")
    }

    // ── set-plan-profile ──────────────────────────────────────────────────────

    @Test
    fun `set-plan-profile posts the additive mutation and reports the unchanged wi_ client`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))

        val (exit, out, err) = runCli(
            "workload-identity", "trusts", "set-plan-profile", trustId, "--plan-environment", "thoryn-provision-e2e-plan", "--gateway", baseUrl(),
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/workload-identity/trusts/$trustId/plan-profile")
        assertThat(parseJson(req.body.readUtf8())).containsEntry("environment", "thoryn-provision-e2e-plan").doesNotContainKey("scopes")
        assertThat(out)
            .contains("now carries a plan profile")
            .contains("wi_10a7b379c79f7d1353f5798d is unchanged: nothing to re-paste")
            .contains("Plan profile — a job in GitHub environment 'thoryn-provision-e2e-plan'")
    }

    @Test
    fun `set-plan-profile --plan-scope sends the explicit scopes and refuses a write scope locally`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))
        val ok = runCli(
            "workload-identity", "trusts", "set-plan-profile", trustId, "--plan-environment", "thoryn-provision-e2e-plan",
            "--plan-scope", "tenant:access.read", "--gateway", baseUrl(),
        )
        assertThat(ok.exit).isEqualTo(0)
        assertThat(parseJson(server.takeRequest().body.readUtf8())).containsEntry("scopes", listOf("tenant:access.read"))

        val write = runCli(
            "workload-identity", "trusts", "set-plan-profile", trustId, "--plan-environment", "thoryn-provision-e2e-plan",
            "--plan-scope", "tenant:access.write", "--gateway", baseUrl(),
        )
        assertThat(write.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(write.err).contains("plan_scope_not_read_only")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `409 plan_profile_already_set says the profile is set once and the trust must be re-created to change it`() {
        server.enqueue(problem(409, "problem-plan-profile-already-set"))

        val (exit, _, err) = runCli(
            "workload-identity", "trusts", "set-plan-profile", trustId, "--plan-environment", "other-plan", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("plan_profile_already_set").contains("already has a plan profile").contains("re-create the trust")
    }

    @Test
    fun `set-plan-profile requires --plan-environment`() {
        val (exit, _, err) = runCli("workload-identity", "trusts", "set-plan-profile", trustId, "--gateway", baseUrl())
        assertThat(exit).isNotEqualTo(0)
        assertThat(err).contains("--plan-environment")
        assertThat(server.requestCount).isZero()
    }
}
