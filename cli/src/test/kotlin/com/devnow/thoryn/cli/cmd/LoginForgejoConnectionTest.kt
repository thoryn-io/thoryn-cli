package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-4472 — `thoryn login --connection <file>` under a `forgejo` trust, end to end through the CLI against
 * [WorkloadIdentityPlatform] standing in for the Forgejo runner's token route and the platform. The job's trigger class
 * and ref select the profile (ADR 2026-10-14 Amendment 2026-11-23): the connection's scopes are requested ONLY for a
 * workflow_dispatch on the pinned ref; any other job requests none, so the hub mints the matched profile. The session
 * records the profile; a refusal explains itself from the job's claims, never the token.
 */
class LoginForgejoConnectionTest : CommandTestBase() {

    private val platform = WorkloadIdentityPlatform(api = com.devnow.thoryn.cli.cmd.provision.FakeProductApi())
    private val clientId = "wi_5e4f3a2b1c0d9e8f7a6b5c4d"

    /** A production-plane audience: the workspace issuer itself (no `/{environment}` path). */
    private fun audience() = baseUrl()

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        CommandSupport.resetSessionHintForTest()
        WorkloadIdentityPlatform.actAsRunner(baseUrl())
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
        com.devnow.thoryn.cli.cmd.provision.FixRequests.resetEnvironmentForTest()
    }

    private fun job(eventName: String, ref: String = "refs/heads/main", baseRef: String? = null) {
        platform.claims = { aud -> FakeJobTokens.forgejoClaims(aud, eventName = eventName, ref = ref, baseRef = baseRef) }
    }

    private fun writeConnection(plan: Boolean = true, extra: String = ""): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "acme" },
              "auth": {
                "method": "workload_identity",
                "provider": "forgejo",
                "clientId": "$clientId",
                "audience": "${audience()}",
                "scopes": ["tenant:applications.read", "tenant:applications.write"],
                "forgejo": { "instanceUrl": "${FakeJobTokens.FORGEJO_INSTANCE}", "owner": "acme", "repository": "infra", "ownerId": 7, "repositoryId": 42, "ref": "refs/heads/main" }${if (plan) ",\n                \"plan\": { \"scopes\": [\"tenant:applications.read\"] }" else ""}$extra
              }
            }
            """.trimIndent(),
        )
        return file
    }

    @Test
    fun `a workflow_dispatch on the pinned ref asks for the connection's scopes and signs in with the apply profile`() {
        job("workflow_dispatch")

        val (exit, out, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        // The runner was asked for a token for the trust's audience, and that token was exchanged with the scopes.
        assertThat(platform.jobTokens).hasSize(1)
        val exchange = platform.exchanges.single()
        assertThat(exchange).containsEntry("client_id", clientId)
            .containsEntry("client_assertion", platform.jobTokens.single())
            .containsEntry("scope", "tenant:applications.read tenant:applications.write")
            .doesNotContainKey("client_secret")
        assertThat(out).contains("Signed in (workload identity / client '$clientId'")
            .contains("Profile: apply (a dispatch (workflow_dispatch) on 'refs/heads/main' — the connection's scopes).")
        val stored = FileTokenStore().read()!!
        assertThat(stored.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(stored.profile).isEqualTo(Tokens.PROFILE_APPLY)
        assertThat(Files.readString(tempHome.resolve(".config/thoryn/tokens.json"))).doesNotContain(platform.jobTokens.single())
    }

    @Test
    fun `a push on the pinned ref asks for NO scope — the hub mints the plan profile — and the session records plan`() {
        job("push")

        val (exit, out, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges.single()).doesNotContainKey("scope")
        assertThat(out).contains("Profile: plan (read-only) — a push (push) on 'refs/heads/main': no scope was requested")
            .doesNotContain("Notice:")
        assertThat(FileTokenStore().read()!!.profile).isEqualTo(Tokens.PROFILE_PLAN)
    }

    @Test
    fun `a same-repository pull request into the pinned branch also asks for no scope`() {
        job("pull_request", ref = "refs/pull/9/head", baseRef = "main")

        val (exit, out, _) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges.single()).doesNotContainKey("scope")
        assertThat(out).contains("Profile: plan (read-only) — a pull request (pull_request) into 'main'")
    }

    @Test
    fun `a platform that predates the plan rule minting write scopes to a plan job is called out`() {
        job("push")
        platform.tokenResponses += WorkloadIdentityPlatform.json(
            200, """{"access_token":"AT-old-hub","token_type":"Bearer","expires_in":900,"scope":"tenant:applications.read tenant:applications.write"}""",
        )

        val (exit, out, _) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Notice: the platform minted write scopes (tenant:applications.write) to a job the plan profile is selected for")
    }

    @Test
    fun `a refused push without a plan profile is explained from the job's claims, with the command that adds one — never the token`() {
        job("push")
        platform.tokenResponses += WorkloadIdentityPlatform.json(401, """{"error":"invalid_client"}""")
        // A consent base URL IS configured: the GitHub App's link would be printed for a GitHub run, never for a Forgejo one.
        com.devnow.thoryn.cli.cmd.provision.FixRequests.environment = { key ->
            if (key == "THORYN_CONSENT_URL") "https://app.example.org" else com.devnow.thoryn.cli.auth.WorkloadIdentityFlow.runnerEnv(key)
        }

        val (exit, out, err) = runCli("login", "--connection", writeConnection(plan = false).toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(platform.exchanges.single()).doesNotContainKey("scope")
        val token = platform.jobTokens.single()
        assertThat(out + err).doesNotContain(token)
        assertThat(err).contains("claims of its Forgejo Actions OIDC token")
            .contains("trigger class        push")
            .contains("trigger: event_not_allowed — a push on 'refs/heads/main' gets the trust's PLAN profile")
            .contains("trusts set-plan-profile <id>")
            .contains("decided by the hub (a push (push) on 'refs/heads/main'")
            .doesNotContain("app.example.org") // the GitHub App's browser consent has no page for a Forgejo run
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `outside a Forgejo job the sign-in fails closed with the Forgejo fix — nothing sent`() {
        WorkloadIdentityPlatform.leaveRunner()

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains("no Forgejo Actions job token available").contains("enable-openid-connect: true")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `behind an authenticating proxy the job's own token file is read instead of the runner`() {
        WorkloadIdentityPlatform.leaveRunner()
        val tokenFile = tempHome.resolve("forgejo-token")
        val token = FakeJobTokens.forgejoToken(audience(), eventName = "workflow_dispatch").also { Files.writeString(tokenFile, it) }

        val (exit, out, err) = runCli(
            "login", "--connection", writeConnection(extra = ",\n    \"tokenSource\": { \"kind\": \"file\", \"path\": \"$tokenFile\" }").toString(),
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(platform.jobTokens).isEmpty()
        assertThat(platform.exchanges.single()).containsEntry("client_assertion", token).containsKey("scope")
        assertThat(out).contains("re-reading the identity token at $tokenFile")
        assertThat(FileTokenStore().read()!!.tokenFile).isEqualTo(tokenFile.toString())
    }
}
