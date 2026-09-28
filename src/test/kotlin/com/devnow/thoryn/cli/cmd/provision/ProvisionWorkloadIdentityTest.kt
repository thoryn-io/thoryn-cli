package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.LoginCommand
import com.devnow.thoryn.cli.cmd.WorkloadIdentityPlatform
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3308 — the provisioning path a customer pipeline runs on GitHub Actions with NO secret:
 * `thoryn login --connection .thoryn/connection.json` (a `workload_identity` contract) then
 * `thoryn provision apply`. Proves the exchanged bearer is what reaches the API, that a later command on
 * an expired session renews with a FRESH job token, that the API-key contract is untouched, and that the
 * contract's pins turn a refused sign-in into the field that differs.
 */
class ProvisionWorkloadIdentityTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val platform = WorkloadIdentityPlatform(api)
    private val hubEnv = "THORYN_TEST_WIF_HUB"

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        WorkloadIdentityPlatform.actAsRunner(baseUrl())
        System.setProperty(hubEnv, baseUrl())
        CommandSupport.resetSessionHintForTest()
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
        System.clearProperty(hubEnv)
    }

    private fun write(name: String, body: String): File =
        File(tempHome.toFile(), ".thoryn/$name").also { it.parentFile.mkdirs(); it.writeText(body) }

    private fun connection(auth: String) = write(
        "connection.json",
        """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "thoryn", "hubBaseUrlEnv": "$hubEnv" },
          "auth": $auth
        }
        """.trimIndent(),
    )

    private val workloadAuth = """
        {
          "method": "workload_identity",
          "clientId": "wi_0123456789abcdef01234567",
          "environment": "cli-wif",
          "scopes": ["tenant:environments.read", "tenant:environments.write", "tenant:applications.read", "tenant:applications.write"]
        }
    """.trimIndent()

    private val provisionFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: wif-sbx, displayName: "WIF sandbox" }
          - kind: application
            name: rp
            environment: ci
            spec: { displayName: "RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
    """.trimIndent()

    @Test
    fun `login from a workload_identity contract then provision apply — the exchanged bearer reaches every API call`() {
        val login = runCli("login", "--connection", connection(workloadAuth).path)
        assertThat(login.err).doesNotContain("Error")
        assertThat(login.exit).isEqualTo(0)

        // The audience was derived: <workspace issuer>/<environment> (a local base keeps its host).
        assertThat(platform.exchanges.single())
            .containsEntry("client_id", "wi_0123456789abcdef01234567")
            .containsEntry("scope", "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write")
            .doesNotContainKey("client_secret")
        val jobTokenRequest = server.takeRequest()
        assertThat(jobTokenRequest.requestUrl!!.queryParameter("audience")).isEqualTo("${baseUrl()}/cli-wif")
        val session = FileTokenStore().read()!!
        assertThat(session.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(session.issuer).isEqualTo("${baseUrl()}/cli-wif")
        assertThat(session.workspace).isEqualTo("thoryn")

        val file = write("provision.yaml", provisionFile)
        val apply = runCli("provision", "apply", "--file", file.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).isEmpty()
        assertThat(apply.exit).isEqualTo(0)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/environments", "POST /api/v1/applications")
        assertThat(platform.apiAuthorizations).isNotEmpty.containsOnly("Bearer AT-wif-1")
        assertThat(platform.jobTokens).hasSize(1) // a fresh session needs no second exchange

        // 15 minutes later, in the same job: the session has expired; the next command re-exchanges with a NEW job token.
        FileTokenStore().write(FileTokenStore().read()!!.copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 1))
        platform.apiAuthorizations.clear()
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(platform.jobTokens).hasSize(2).doesNotHaveDuplicates()
        assertThat(platform.exchanges.last()).containsEntry("client_assertion", platform.jobTokens.last())
        assertThat(platform.apiAuthorizations).isNotEmpty.containsOnly("Bearer AT-wif-2")
    }

    @Test
    fun `an explicit audience in the contract is used exactly and a foreign workspace's audience is refused`() {
        val explicit = connection(
            """{ "method": "workload_identity", "clientId": "wi_0123456789abcdef01234567",
                 "audience": "${baseUrl()}/other-env", "scopes": ["tenant:environments.read"] }""",
        )
        assertThat(runCli("login", "--connection", explicit.path).exit).isEqualTo(0)
        assertThat(server.takeRequest().requestUrl!!.queryParameter("audience")).isEqualTo("${baseUrl()}/other-env")

        val foreign = connection(
            """{ "method": "workload_identity", "clientId": "wi_0123456789abcdef01234567",
                 "audience": "https://acme.auth.stg.thoryn.org/cli-wif", "scopes": ["tenant:environments.read"] }""",
        )
        val refused = runCli("login", "--connection", foreign.path)
        assertThat(refused.exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(refused.err).contains("is on workspace 'acme' but the connection's workspace.slug is 'thoryn'")
    }

    @Test
    fun `the contract's pins name the field that differs when the platform refuses`() {
        platform.claims = { aud -> FakeJobTokens.claims(aud, repository = "thoryn-io/thoryn-cli", environment = null) }
        platform.tokenResponses += WorkloadIdentityPlatform.json(401, """{"error":"invalid_client"}""")
        val pinned = connection(
            """{ "method": "workload_identity", "clientId": "wi_0123456789abcdef01234567", "environment": "cli-wif",
                 "scopes": ["tenant:environments.read"],
                 "github": { "owner": "thoryn-io", "repository": "thoryn-cli", "environment": "thoryn-staging-wif" } }""",
        )

        val (exit, _, err) = runCli("login", "--connection", pinned.path)

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err)
            .contains("invalid_client")
            .contains("environment: the trust pins GitHub environment 'thoryn-staging-wif'; this job declares no `environment:`")
            .doesNotContain("repository: the trust pins")
            .doesNotContain(platform.jobTokens.single())
    }

    @Test
    fun `an API-key contract is unchanged — client_credentials with the named secret, no job token requested`() {
        System.setProperty("THORYN_TEST_WIF_SECRET", "ci-bot-secret")
        try {
            val apiKey = connection(
                """{ "method": "client_credentials", "clientId": "cli-ci", "secretEnv": "THORYN_TEST_WIF_SECRET",
                     "scopes": ["tenant:environments.read"] }""",
            )
            val (exit, _, _) = runCli("login", "--connection", apiKey.path)

            assertThat(exit).isEqualTo(0)
            assertThat(platform.jobTokens).isEmpty()
            val exchange = platform.exchanges.single()
            assertThat(exchange).containsEntry("grant_type", "client_credentials").doesNotContainKey("client_assertion")
            assertThat(FileTokenStore().read()!!.authMode).isEqualTo(Tokens.AUTH_MODE_CLIENT_CREDENTIALS)
        } finally {
            System.clearProperty("THORYN_TEST_WIF_SECRET")
        }
    }
}
