package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-3308 — `thoryn login --workload-identity` end to end through the CLI, against one MockWebServer
 * playing the GitHub runner, the platform token endpoint and the customer-plane API
 * ([WorkloadIdentityPlatform]). The runner variables are supplied as `-D` properties (the CLI reads
 * those first), the way GitHub sets them for a job with `permissions: id-token: write`.
 */
class LoginWorkloadIdentityTest : CommandTestBase() {

    private val platform = WorkloadIdentityPlatform(api = com.devnow.thoryn.cli.cmd.provision.FakeProductApi())
    private val clientId = "wi_0123456789abcdef01234567"

    private fun audience() = "${baseUrl()}/cli-wif"

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

    private fun login(vararg extra: String) = runCli(
        "login", "--workload-identity", "--client-id", clientId, "--audience", audience(), "--gateway", baseUrl(), *extra,
    )

    @Test
    fun `a job signs in with its own OIDC token and the session remembers the trust binding — no secret anywhere`() {
        val (exit, out, err) = login("--scope", "tenant:environments.read")

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Signed in (workload identity / client '$clientId' at ${audience()}").contains("Scopes: tenant:environments.read")

        val exchange = platform.exchanges.single()
        assertThat(exchange).containsEntry("grant_type", "client_credentials")
            .containsEntry("client_id", clientId)
            .containsEntry("client_assertion_type", WorkloadIdentityFlow.CLIENT_ASSERTION_TYPE)
            .containsEntry("client_assertion", platform.jobTokens.single())
            .containsEntry("scope", "tenant:environments.read")
            .doesNotContainKey("client_secret")

        val stored = FileTokenStore().read()!!
        assertThat(stored.accessToken).isEqualTo("AT-wif-1")
        assertThat(stored.refreshToken).isNull()
        assertThat(stored.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(stored.clientId).isEqualTo(clientId)
        assertThat(stored.issuer).isEqualTo(audience())
        assertThat(stored.tokenEndpoint).isEqualTo("${audience()}/oauth2/token")
        assertThat(stored.gateway).isEqualTo(baseUrl())
        // The job token is never persisted.
        assertThat(Files.readString(tempHome.resolve(".config/thoryn/tokens.json"))).doesNotContain(platform.jobTokens.single())
    }

    @Test
    fun `without --scope the request carries none, so the trust's full set is granted`() {
        val (exit, _, _) = login()
        assertThat(exit).isEqualTo(0)
        assertThat(platform.exchanges.single()).doesNotContainKey("scope")
    }

    @Test
    fun `a refused exchange prints what was sent, the job's identity and the audit-log pointer — never the token`() {
        platform.tokenResponses += WorkloadIdentityPlatform.json(401, """{"error":"invalid_client"}""")

        val (exit, _, err) = login("--scope", "tenant:environments.read")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err)
            .contains("refused the workload identity exchange (HTTP 401: invalid_client)")
            .contains("thoryn audit query --event-type workload_identity.exchange_failed")
            .contains(clientId)
            .contains(audience())
            .contains("${audience()}/oauth2/token")
            .contains("repo:thoryn-io/thoryn-cli:ref:refs/heads/main")
            .contains("1044556677")
            .doesNotContain(platform.jobTokens.single())
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `outside GitHub Actions the sign-in names the missing variables and the id-token permission`() {
        assumeTrue(System.getenv(WorkloadIdentityFlow.REQUEST_URL_ENV) == null, "running inside a job that can mint tokens")
        WorkloadIdentityPlatform.leaveRunner()

        val (exit, _, err) = login()

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains(WorkloadIdentityFlow.REQUEST_URL_ENV).contains("id-token: write")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `the trust's client id and audience are required`() {
        val noAudience = runCli("login", "--workload-identity", "--client-id", clientId)
        assertThat(noAudience.exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(noAudience.err).contains("--client-id <wi_…> --audience <audience>")

        val noClient = runCli("login", "--workload-identity", "--audience", audience())
        assertThat(noClient.exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a token endpoint off the audience's origin is refused before a job token is requested`() {
        val (exit, _, err) = login("--token-endpoint", "https://evil.example/oauth2/token")

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("not on the audience's origin")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `--audience outside --workload-identity is a usage error`() {
        val (exit, _, err) = runCli("login", "--client-credentials", "--audience", audience(), "--issuer", baseUrl())
        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("--audience and --token-endpoint apply to --workload-identity only")
    }

    @Test
    fun `an expired workload session renews itself with a FRESH job token before the API call`() {
        seedTokens(
            Tokens(
                accessToken = "AT-expired",
                expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 5,
                scope = "tenant:environments.read",
                issuer = audience(),
                gateway = baseUrl(),
                authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY,
                clientId = clientId,
                tokenEndpoint = "${audience()}/oauth2/token",
            ),
        )

        val (exit, _, err) = runCli("env", "list", "--gateway", baseUrl())

        assertThat(err).doesNotContain("Could not renew")
        assertThat(exit).isEqualTo(0)
        assertThat(platform.jobTokens).hasSize(1)
        assertThat(platform.exchanges.single()).containsEntry("client_assertion", platform.jobTokens.single())
            .containsEntry("scope", "tenant:environments.read")
        assertThat(platform.apiAuthorizations).containsOnly("Bearer AT-wif-1")
        val renewed = FileTokenStore().read()!!
        assertThat(renewed.accessToken).isEqualTo("AT-wif-1")
        assertThat(renewed.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(renewed.tokenEndpoint).isEqualTo("${audience()}/oauth2/token")
    }

    @Test
    fun `a job token is only ever minted for the audience the trust names`() {
        platform.claims = { aud -> FakeJobTokens.claims(aud, environment = "thoryn-staging-wif") }
        val (exit, _, _) = login()
        assertThat(exit).isEqualTo(0)
        val requested = server.takeRequest()
        assertThat(requested.requestUrl!!.queryParameter("audience")).isEqualTo(audience())
    }
}
