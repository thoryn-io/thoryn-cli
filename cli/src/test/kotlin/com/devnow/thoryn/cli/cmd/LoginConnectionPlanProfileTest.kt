package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityDiagnostics
import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3702 (SSO-3699 option B) — `thoryn login --connection` with ONE `connection.json` for a trust that carries a
 * plan profile. The CLI reads the job's own OIDC `environment` claim: in the connection's apply environment
 * (`auth.github.environment`) it requests `auth.scopes` exactly as before; in any OTHER environment it sends NO
 * `scope`, so the hub mints the matched plan profile's read-only set — a plan job never asks for a write scope.
 * The session is stamped with the profile (`login --status`, `whoami`), a write refusal in a plan session says so,
 * and an `invalid_scope` naming `scope_outside_plan_profile` prints the reason and the fix.
 */
class LoginConnectionPlanProfileTest : CommandTestBase() {

    private val api = com.devnow.thoryn.cli.cmd.provision.FakeProductApi()
    private val platform = WorkloadIdentityPlatform(api = api)
    private val clientId = "wi_10a7b379c79f7d1353f5798d"
    private val applyEnvironment = "thoryn-provision-e2e"
    private val planEnvironment = "thoryn-provision-e2e-plan"
    private val scopes = listOf("tenant:environments.read", "tenant:environments.write", "tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:access.write")

    /** A production-plane audience: the workspace issuer itself. */
    private fun audience() = baseUrl()

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        WorkloadIdentityPlatform.actAsRunner(baseUrl())
        CommandSupport.resetSessionHintForTest()
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
    }

    /** The job runs in [environment]: its OIDC token carries that `environment` claim (GitHub's default `sub` follows). */
    private fun jobIn(environment: String?) {
        platform.claims = { aud -> FakeJobTokens.claims(aud, repository = "thoryn-io/thoryn-cli", environment = environment) }
    }

    private fun writeConnection(pins: String? = """"github": { "owner": "thoryn-io", "repository": "thoryn-cli", "environment": "$applyEnvironment", "ref": "refs/heads/main" }"""): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "workload_identity",
                "clientId": "$clientId",
                "audience": "${audience()}",
                "scopes": [${scopes.joinToString(", ") { "\"$it\"" }}]${pins?.let { ",\n                $it" } ?: ""}
              }
            }
            """.trimIndent(),
        )
        return file
    }

    @Test
    fun `a job in the apply environment requests the connection's scopes exactly and the session is stamped apply`() {
        jobIn(applyEnvironment)

        val (exit, out, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges.single()).containsEntry("scope", scopes.joinToString(" "))
        assertThat(out).contains("Profile: apply (GitHub environment '$applyEnvironment'")
        val stored = FileTokenStore().read()!!
        assertThat(stored.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(stored.profile).isEqualTo(Tokens.PROFILE_APPLY)
    }

    @Test
    fun `a job in ANY other environment sends no scope — the hub mints the plan profile — and the session is stamped plan`() {
        jobIn(planEnvironment)
        // The hub answers the matched (plan) profile's read-only scopes — the response `scope` is what the session keeps.
        platform.tokenResponses += WorkloadIdentityPlatform.json(
            200,
            """{"access_token":"AT-plan-1","token_type":"Bearer","expires_in":900,"scope":"tenant:environments.read tenant:applications.read tenant:access.read"}""",
        )

        val (exit, out, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val exchange = platform.exchanges.single()
        assertThat(exchange).doesNotContainKey("scope")
        assertThat(exchange).containsEntry("client_id", clientId)
        assertThat(out)
            .contains("Profile: plan (read-only) — this job runs in GitHub environment '$planEnvironment', not the trust's apply environment '$applyEnvironment'")
            .contains("Scopes: tenant:environments.read tenant:applications.read tenant:access.read")
        val stored = FileTokenStore().read()!!
        assertThat(stored.profile).isEqualTo(Tokens.PROFILE_PLAN)
        assertThat(stored.scope).isEqualTo("tenant:environments.read tenant:applications.read tenant:access.read")
        // SSO-3710 — the job's environment rides on the session, so `provision plan --fix-request` can state the run's.
        assertThat(stored.jobEnvironment).isEqualTo(planEnvironment)

        // The profile is part of the session's story: `login --status` and `whoami` both name it.
        val status = runCli("login", "--status")
        assertThat(status.exit).isEqualTo(0)
        assertThat(status.out).contains("Profile: plan (read-only")
        val whoami = runCli("whoami", "--output", "json")
        assertThat(whoami.exit).isEqualTo(0)
        assertThat(parseJson(whoami.out)["profile"].toString()).startsWith("plan (read-only")
    }

    @Test
    fun `a renewal in the plan job re-requests only the minted read-only set and keeps the profile stamp`() {
        jobIn(planEnvironment)
        platform.tokenResponses += WorkloadIdentityPlatform.json(200, """{"access_token":"AT-plan-1","token_type":"Bearer","expires_in":900,"scope":"tenant:environments.read tenant:access.read"}""")
        assertThat(runCli("login", "--connection", writeConnection().toString()).exit).isEqualTo(0)
        // Age the session past expiry; the next command renews by a fresh exchange.
        val stored = FileTokenStore().read()!!
        FileTokenStore().write(stored.copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 60))
        api.seedEnvironment("ci-sbx")

        val (exit, _, _) = runCli("env", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges).hasSize(2)
        assertThat(platform.exchanges[1]).containsEntry("scope", "tenant:environments.read tenant:access.read")
        assertThat(FileTokenStore().read()!!.profile).isEqualTo(Tokens.PROFILE_PLAN)
    }

    @Test
    fun `a write refused in a plan-profile session names the profile instead of a login-scope hint`() {
        seedTokens(
            Tokens(
                accessToken = "AT-plan", authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId, issuer = audience(),
                gateway = baseUrl(), profile = Tokens.PROFILE_PLAN, expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
                scope = "tenant:environments.read",
            ),
        )
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse =
                WorkloadIdentityPlatform.json(403, """{"type":"about:blank","status":403,"errorCode":"insufficient_scope","detail":"insufficient_scope"}""")
                    .setHeader("Content-Type", "application/problem+json")
        }

        val (exit, _, err) = runCli("workload-identity", "trusts", "delete", "trust-1", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("PLAN profile (read-only)").contains("apply job in the reviewed environment")
        assertThat(err).doesNotContain("Required scope:")
    }

    @Test
    fun `a connection without the apply environment pin behaves as before — scopes requested, no profile stamped`() {
        jobIn(planEnvironment)

        val (exit, out, _) = runCli("login", "--connection", writeConnection(pins = null).toString())

        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges.single()).containsEntry("scope", scopes.joinToString(" "))
        assertThat(out).doesNotContain("Profile:")
        assertThat(FileTokenStore().read()!!.profile).isNull()
    }

    @Test
    fun `the hub's scope_outside_plan_profile refusal prints the reason and the fix — never the token`() {
        jobIn(planEnvironment)
        platform.tokenResponses += WorkloadIdentityPlatform.json(400, """{"error":"invalid_scope","error_description":"${WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN}"}""")

        // The flag form asks for a write scope from a plan job — exactly what the hub refuses.
        val (exit, _, err) = runCli(
            "login", "--workload-identity", "--client-id", clientId, "--audience", audience(), "--gateway", baseUrl(),
            "--scope", "tenant:environments.write",
        )

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err)
            .contains("outside the trust's PLAN profile (HTTP 400: invalid_scope, scope_outside_plan_profile)")
            .contains("This job runs in GitHub environment '$planEnvironment'")
            .contains("request no scope at all")
            .contains("Never request a write scope from a plan job")
            .doesNotContain(platform.jobTokens.single())
        assertThat(FileTokenStore().read()).isNull()
    }
}
