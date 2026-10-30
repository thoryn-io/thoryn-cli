package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/**
 * SSO-4086 (oauthy ADR `2026-10-30-ephemeral-sandbox-test-identities.md` §7, story E) — `thoryn env test-identity
 * create|list|revoke` against [FakeProductApi] standing in for product-api's
 * `/api/v1/environments/{envId}/test-identities` (SSO-4085, #4297): the slug → id resolution `thoryn env test-emails`
 * uses, the three secret-delivery outputs with the password leaving the process exactly once, every `errorCode` of ADR
 * §1 mapped to a sentence, and `list` / `revoke` never carrying a password.
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in
 * the PR).
 */
class EnvironmentTestIdentityCommandTest : CommandTestBase() {

    private val api = FakeProductApi()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        envId = api.seedEnvironment("staging")
        api.seedEnvironment("production", kind = "production")
        EnvironmentTestIdentityCommand.environment = { null }
    }

    @AfterEach
    fun unsetEnvironment() {
        EnvironmentTestIdentityCommand.resetEnvironmentForTest()
    }

    private fun create(vararg extra: String) =
        runCli("env", "test-identity", "create", "--env", "staging", "--gateway", baseUrl(), *extra)

    private fun minted(): Map<String, Any?> = api.testIdentities.getValue(envId).single()

    // ── create ───────────────────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun `create resolves the env slug, POSTs lifetime and label, and prints the record with the password once under a warning`() {
        api.nextTestIdentityPassword = "S3cret-pw"

        val (exit, out, err) = create("--lifetime", "PT4H", "--label", "e2e-run-123")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        val write = api.writes.single()
        assertThat("${write.method} ${write.path}").isEqualTo("POST /api/v1/environments/$envId/test-identities")
        assertThat(write.body).isEqualTo(mapOf("lifetime" to "PT4H", "label" to "e2e-run-123"))
        val rec = minted()
        assertThat(out)
            .contains("id ").contains(rec["id"].toString())
            .contains(rec["email"].toString())
            .contains("environment   = staging")
            .contains("label         = e2e-run-123")
            .contains("expiresAt     = 2026-10-30T13:00:00Z")
            .contains("Password (shown ONCE")
        assertThat(out.split("S3cret-pw")).withFailMessage("the password must appear exactly once:\n%s", out).hasSize(2)
        assertThat(err).doesNotContain("S3cret-pw")
    }

    @Test
    fun `create without options sends an empty body and the API's PT2H default applies`() {
        val (exit, _, err) = create()
        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(api.writes.single().body).isEmpty()
        assertThat(minted()["expiresAt"]).isEqualTo("2026-10-30T11:00:00Z")
    }

    @Test
    fun `create --output json prints the response once, password included`() {
        api.nextTestIdentityPassword = "J5on-pw"
        val (exit, out, _) = create("--output", "json")
        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["password"]).isEqualTo("J5on-pw")
        assertThat(json["id"]).isEqualTo(minted()["id"])
        assertThat(json["email"].toString()).endsWith("@sandbox.thoryn.invalid")
        assertThat(json["emailVerified"]).isEqualTo(true)
        assertThat(out.split("J5on-pw")).hasSize(2)
    }

    @Test
    fun `create --output env prints three export lines with every value single-quoted, a quote in the password escaped`() {
        api.nextTestIdentityPassword = "it's-a'pw"
        val (exit, out, _) = create("--output", "env")
        assertThat(exit).isEqualTo(0)
        val rec = minted()
        assertThat(out.trimEnd().lines()).containsExactly(
            "export THORYN_TEST_IDENTITY_ID='${rec["id"]}'",
            "export THORYN_TEST_USER_EMAIL='${rec["email"]}'",
            "export THORYN_TEST_USER_PASSWORD='it'\\''s-a'\\''pw'",
        )
    }

    @Test
    fun `create --output github-env prints the add-mask line FIRST and appends the three variables to the GITHUB_ENV file`() {
        val githubEnv = File(tempHome.toFile(), "github.env").also { it.writeText("EXISTING=1\n") }
        EnvironmentTestIdentityCommand.environment = { if (it == "GITHUB_ENV") githubEnv.path else null }
        api.nextTestIdentityPassword = "Gh-pw-77"

        val (exit, out, err) = create("--output", "github-env", "--label", "42-1")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        val rec = minted()
        assertThat(out.lines().first()).isEqualTo("::add-mask::Gh-pw-77")
        // The password is in the mask line and nowhere else on stdout / stderr.
        assertThat(out.split("Gh-pw-77")).hasSize(2)
        assertThat(err).doesNotContain("Gh-pw-77")
        assertThat(out).contains("appended to \$GITHUB_ENV")
        assertThat(githubEnv.readText()).isEqualTo(
            "EXISTING=1\n" +
                "THORYN_TEST_IDENTITY_ID=${rec["id"]}\n" +
                "THORYN_TEST_USER_EMAIL=${rec["email"]}\n" +
                "THORYN_TEST_USER_PASSWORD=Gh-pw-77\n",
        )
    }

    @Test
    fun `create --output github-env without GITHUB_ENV fails before anything is minted`() {
        val (exit, out, err) = create("--output", "github-env")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("\$GITHUB_ENV is not set").contains("--output env")
        assertThat(out).isEmpty()
        assertThat(api.writes).isEmpty()
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `create with an unknown --output is a usage error`() {
        val (exit, _, err) = create("--output", "dotenv")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("table|json|yaml|env|github-env")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `without --env and no selected environment, create says how to pick one`() {
        val (exit, _, err) = runCli("env", "test-identity", "create", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("Pass --env <slug>, or run `thoryn env use <slug>` first")
    }

    // ── the API's refusals, each mapped to a sentence (ADR §1) ──────────────────────────────────────────────────

    @Test
    fun `the production environment is refused by the API as not_a_sandbox and the refusal is passed through with a pointer to a sandbox`() {
        val (exit, _, err) = runCli("env", "test-identity", "create", "--env", "production", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: not_a_sandbox").contains("'production' is the production environment").contains("--env <slug>")
        assertThat(api.testIdentities.values.flatten()).isEmpty()
    }

    @Test
    fun `a missing write scope renders the shared scope guidance naming tenant_test-identities_write`() {
        api.enforceScopeGates = true
        api.callerScopes = setOf("tenant:environments.read", "tenant:test-identities.read")
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: access_denied").contains("Required scope: tenant:test-identities.write").contains("login --scope tenant:test-identities.write")
    }

    @Test
    fun `an identity that is not a manager of the sandbox is answered not_found, and the hint says the relation may be the cause`() {
        api.callerIsAdmin = false
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: not_found").contains("not a manager of environment 'staging'").contains("never 403")
    }

    @Test
    fun `a token bound to another sandbox is environment_mismatch`() {
        api.callerEnvClaim = "other-sandbox"
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: environment_mismatch").contains("bound to another environment than 'staging'")
    }

    @Test
    fun `a bad lifetime or label is refused by the API and the hint restates the grammar`() {
        val lifetime = create("--lifetime", "2h")
        assertThat(lifetime.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(lifetime.err).contains("Error: invalid_lifetime").contains("between PT5M and PT24H")
        val tooLong = create("--lifetime", "PT48H")
        assertThat(tooLong.err).contains("Error: invalid_lifetime")
        val label = create("--label", "has space")
        assertThat(label.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(label.err).contains("Error: invalid_label").contains("1 to 64 characters")
        assertThat(api.testIdentities.values.flatten()).isEmpty()
    }

    @Test
    fun `the sandbox cap is a 409 whose hint says to revoke or wait`() {
        api.testIdentityCap = 1
        assertThat(create().exit).isEqualTo(0)
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: test_identity_cap_reached").contains("maximum of live test identities").contains("if: always()")
    }

    @Test
    fun `a 429 carries Retry-After into the hint, and into the JSON error`() {
        api.nextTestIdentityProblem = Triple(429, "test_identity_rate_limited", emptyMap())
        api.testIdentityRetryAfter = 42
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: test_identity_rate_limited").contains("retry after 42 second(s)")

        api.nextTestIdentityProblem = Triple(429, "test_identity_rate_limited", emptyMap())
        val json = create("--output", "json")
        assertThat(json.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(parseJson(json.out)).containsEntry("error", "test_identity_rate_limited").containsEntry("retryAfterSeconds", 42)
        assertThat(parseJson(json.out)["hint"].toString()).contains("retry after 42 second(s)")
    }

    @ParameterizedTest(name = "{1} → {2}")
    @CsvSource(
        "503, test_identity_limiter_unavailable, fail-closed",
        "503, facade_not_configured, no identity facade configured",
        "502, upstream_identity_error, identity-service could not be reached",
        "410, test_identity_expired, past its expiresAt",
    )
    fun `every other errorCode of the surface renders its own sentence`(status: Int, code: String, expected: String) {
        api.nextTestIdentityProblem = Triple(status, code, emptyMap())
        val (exit, _, err) = create()
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: $code").contains(expected)
    }

    // ── list / revoke ────────────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun `list shows live and expired identities with their status, and never a password — in the table or the JSON`() {
        api.nextTestIdentityPassword = "L1st-pw"
        assertThat(create("--label", "run-7").exit).isEqualTo(0)
        val expired = api.seedTestIdentity(envId, label = "old", expired = true, password = "0ld-pw")

        val (exit, out, _) = runCli("env", "test-identity", "list", "--env", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("run-7").contains("live").contains(expired).contains("expired")
        assertThat(out).doesNotContain("L1st-pw").doesNotContain("0ld-pw").doesNotContain("password")
        assertThat(api.requests.last()).isEqualTo("GET /api/v1/environments/$envId/test-identities")

        // Even if the server LEAKED the password on the list (it never does), the CLI strips it before printing JSON.
        api.testIdentityListLeaksPassword = true
        val json = runCli("env", "test-identity", "list", "--env", "staging", "--output", "json", "--gateway", baseUrl())
        assertThat(json.out).doesNotContain("L1st-pw").doesNotContain("0ld-pw").doesNotContain("\"password\"")
        @Suppress("UNCHECKED_CAST")
        val rows = parseJson(json.out)["data"] as List<Map<String, Any?>>
        assertThat(rows.map { it["status"] }).containsExactlyInAnyOrder("live", "expired")
    }

    @Test
    fun `list with a missing read scope names tenant_test-identities_read`() {
        api.enforceScopeGates = true
        api.callerScopes = setOf("tenant:environments.read", "tenant:test-identities.write")
        val (exit, _, err) = runCli("env", "test-identity", "list", "--env", "staging", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Required scope: tenant:test-identities.read")
    }

    @Test
    fun `revoke DELETEs the identity and confirms without echoing anything secret`() {
        api.nextTestIdentityPassword = "R3voke-pw"
        assertThat(create().exit).isEqualTo(0)
        val id = minted()["id"].toString()

        val (exit, out, err) = runCli("env", "test-identity", "revoke", id, "--env", "staging", "--gateway", baseUrl())

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(out).contains("Revoked test identity $id in environment 'staging'")
        assertThat(out + err).doesNotContain("R3voke-pw")
        assertThat("${api.writes.last().method} ${api.writes.last().path}").isEqualTo("DELETE /api/v1/environments/$envId/test-identities/$id")
        assertThat(api.testIdentities.getValue(envId)).isEmpty()

        // Idempotent on an expired identity (the API's 204); purged or unknown is the mapped not_found.
        val expired = api.seedTestIdentity(envId, expired = true)
        assertThat(runCli("env", "test-identity", "revoke", expired, "--env", "staging", "--gateway", baseUrl()).exit).isEqualTo(0)
        val gone = runCli("env", "test-identity", "revoke", expired, "--env", "staging", "--output", "json", "--gateway", baseUrl())
        assertThat(gone.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(parseJson(gone.out)).containsEntry("error", "not_found")
        assertThat(parseJson(gone.out)["hint"].toString()).contains("No such environment or test identity")
    }

    @Test
    fun `revoke --output json emits the structured confirmation`() {
        assertThat(create().exit).isEqualTo(0)
        val id = minted()["id"].toString()
        val (exit, out, _) = runCli("env", "test-identity", "revoke", id, "--env", "staging", "--output", "json", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)).containsEntry("id", id).containsEntry("environment", "staging").containsEntry("status", "revoked")
    }

    @Test
    fun `an unknown env slug fails before any test-identity call`() {
        val (exit, _, err) = runCli("env", "test-identity", "list", "--env", "nope", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("no environment with slug 'nope'")
        assertThat(api.requests).containsExactly("GET /api/v1/environments")
    }
}
