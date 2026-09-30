package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.RetiredIssuer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.net.URI

/**
 * SSO-3415 — a workspace whose custom domain went ACTIVE: its platform host answers `410 issuer_retired`
 * and NAMES the new issuer (`"issuer"`, oathy ADR 2026-09-25-custom-domains.md amendment 2026-09-28). A
 * sign-in whose issuer / audience the CLI DERIVED from the workspace slug follows it once and signs in
 * there — no change to the application project's committed files.
 *
 * One MockWebServer plays both hosts: the derived issuer is the local base (`http://localhost:<port>`,
 * a local base derives to itself) and the successor is the same server under `127.0.0.1` — the loopback
 * exception [RetiredIssuer.successorOf] makes for local stacks. The `Host` header of every request
 * proves which of the two a request was sent to.
 */
class LoginFollowsSuccessorIssuerTest : CommandTestBase() {

    private val platform = WorkloadIdentityPlatform()
    private val hubEnv = "THORYN_TEST_SUCCESSOR_HUB"
    private val secretEnv = "THORYN_TEST_SUCCESSOR_SECRET"

    /** The derived (retired) issuer's authority and the successor's, on the same server. */
    private lateinit var retiredAuthority: String
    private lateinit var successorAuthority: String

    /** Discovery documents the probe asked for. */
    private val probed = mutableListOf<String>()

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        val base = URI(baseUrl())
        retiredAuthority = "localhost:${base.port}"
        successorAuthority = "127.0.0.1:${base.port}"
        System.setProperty(hubEnv, "http://$retiredAuthority")
        System.setProperty(secretEnv, "ci-bot-secret")
        WorkloadIdentityPlatform.actAsRunner(baseUrl())
        CommandSupport.resetSessionHintForTest()
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
        System.clearProperty(hubEnv)
        System.clearProperty(secretEnv)
    }

    private fun retired(successor: String?): RetiredIssuer.Answer = RetiredIssuer.Answer(
        410,
        """{"type":"https://thoryn.io/problems/issuer_retired","title":"Gone","status":410,"errorCode":"issuer_retired",""" +
            """"detail":"This host has been retired."""" + (successor?.let { ""","issuer":"$it"""" } ?: "") + "}",
    )

    /**
     * The platform host of the workspace answers 410 naming [successorFor] (the probe is answered in-process;
     * the sign-in's own requests are real HTTP to [server]); everything else is served.
     */
    private fun movedTo(successorFor: (String) -> String?, successorAlsoRetired: Boolean = false) {
        RetiredIssuer.fetcher = { url ->
            probed += url
            val uri = URI(url)
            val issuerPath = uri.rawPath.removeSuffix("/.well-known/openid-configuration")
            when {
                uri.authority == retiredAuthority -> retired(successorFor(issuerPath))
                successorAlsoRetired -> retired("https://login.acme.com$issuerPath")
                else -> RetiredIssuer.Answer(200, "{}") // the successor serves its discovery document
            }
        }
    }

    private fun write(name: String, body: String): File =
        File(tempHome.toFile(), ".thoryn/$name").also { it.parentFile.mkdirs(); it.writeText(body) }

    private fun connection(auth: String) = write(
        "connection.json",
        """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "acme", "hubBaseUrlEnv": "$hubEnv" },
          "auth": $auth
        }
        """.trimIndent(),
    )

    private val apiKeyAuth =
        """{ "method": "client_credentials", "clientId": "cli-ci", "secretEnv": "$secretEnv", "scopes": ["tenant:applications.read"] }"""

    private val workloadAuth =
        """{ "method": "workload_identity", "clientId": "wi_0123456789abcdef01234567", "environment": "cli-wif",
             "scopes": ["tenant:environments.read"] }"""

    /** Non-probe requests the server saw, as `Host path`. */
    private fun served(): List<String> = (0 until server.requestCount).map {
        val r = server.takeRequest()
        "${r.getHeader("Host")} ${r.path}"
    }

    @Test
    fun `an API-key contract follows the workspace to its named issuer and signs in there`() {
        movedTo({ path -> "http://$successorAuthority$path" })

        val (exit, out, err) = runCli("login", "--connection", connection(apiKeyAuth).path)

        assertThat(exit).withFailMessage("stderr:\n%s", err).isEqualTo(0)
        assertThat(out).contains("Signed in")
        assertThat(err).containsOnlyOnce("Workspace 'acme' now signs in at http://$successorAuthority")
        assertThat(probed).containsExactly(
            "http://$retiredAuthority/.well-known/openid-configuration",
            "http://$successorAuthority/.well-known/openid-configuration",
        )
        // The token request went to the SUCCESSOR, and the session records it as the issuer.
        assertThat(served().filter { it.endsWith("/oauth2/token") }).containsExactly("$successorAuthority /oauth2/token")
        val session = FileTokenStore().read()!!
        assertThat(session.issuer).isEqualTo("http://$successorAuthority")
        assertThat(session.workspace).isEqualTo("acme")
        assertThat(session.platformIssuer).isEqualTo("http://$retiredAuthority")
    }

    @Test
    fun `a workload identity contract derives its audience and token endpoint from the named sandbox issuer`() {
        movedTo({ path -> "http://$successorAuthority$path" })

        val (exit, _, err) = runCli("login", "--connection", connection(workloadAuth).path)

        assertThat(exit).withFailMessage("stderr:\n%s", err).isEqualTo(0)
        assertThat(err).contains("now signs in at http://$successorAuthority/cli-wif")
        val requests = served()
        // The job token was requested FOR the successor audience (with the same /{env}) ...
        val jobTokenAudience = requests.first { it.contains(WorkloadIdentityPlatform.JOB_TOKEN_PATH) }
        assertThat(jobTokenAudience).contains("audience=http%3A%2F%2F127.0.0.1%3A").contains("%2Fcli-wif")
        // ... and exchanged at the successor's token endpoint.
        assertThat(requests.filter { it.endsWith("/oauth2/token") }).containsExactly("$successorAuthority /cli-wif/oauth2/token")
        assertThat(platform.exchanges).hasSize(1)
        val session = FileTokenStore().read()!!
        assertThat(session.issuer).isEqualTo("http://$successorAuthority/cli-wif")
        assertThat(session.tokenEndpoint).isEqualTo("http://$successorAuthority/cli-wif/oauth2/token")
        assertThat(session.workspace).isEqualTo("acme")
        // Only two discovery probes: the derived audience and its successor — the successor is not re-probed.
        assertThat(probed).hasSize(2)
    }

    @Test
    fun `a successor that is retired too is refused - one move only, nothing is requested`() {
        movedTo({ path -> "http://$successorAuthority$path" }, successorAlsoRetired = true)

        val (exit, _, err) = runCli("login", "--connection", connection(apiKeyAuth).path)

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("follows one move only").doesNotContain("login.acme.com/.well-known")
        assertThat(probed).hasSize(2)
        assertThat(server.requestCount).isEqualTo(0)
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `a non-https successor from an https platform is refused and the SSO-3413 guidance applies`() {
        System.setProperty(hubEnv, "https://auth.stg.thoryn.org")
        RetiredIssuer.fetcher = { url ->
            probed += url
            retired("http://auth.acme.com/cli-wif").takeIf { url.startsWith("https://acme.auth.stg.thoryn.org") }
        }

        val (exit, _, err) = runCli("login", "--connection", connection(workloadAuth).path)

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err).contains("has been retired").contains("Set auth.audience").doesNotContain("now signs in at")
        assertThat(probed).containsExactly("https://acme.auth.stg.thoryn.org/cli-wif/.well-known/openid-configuration")
        assertThat(platform.jobTokens).isEmpty()
    }

    @Test
    fun `an audience the user NAMED is never swapped - the refusal names the platform's successor`() {
        RetiredIssuer.fetcher = { url ->
            retired("https://auth.acme.com/cli-wif").takeIf { url.startsWith("https://acme.auth.stg.thoryn.org") }
        }

        val (exit, _, err) = runCli(
            "login", "--workload-identity", "--client-id", "wi_0123456789abcdef01234567",
            "--audience", "https://acme.auth.stg.thoryn.org/cli-wif", "--gateway", "https://api.stg.thoryn.org",
        )

        assertThat(exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(err)
            .contains("has been retired (HTTP 410 issuer_retired)")
            .contains("The platform names this workspace's current issuer: https://auth.acme.com/cli-wif")
        assertThat(platform.jobTokens).isEmpty()
        assertThat(FileTokenStore().read()).isNull()
    }
}
