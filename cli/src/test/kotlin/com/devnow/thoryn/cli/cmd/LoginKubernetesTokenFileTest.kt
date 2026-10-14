package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3684 — `thoryn login --connection <file>` with a FILE token source (a pod's projected ServiceAccount
 * token under a `kubernetes` trust), and the `--token-file` flag form, end to end through the CLI against
 * [WorkloadIdentityPlatform]. No GitHub runner variables are set: the token comes from disk, is exchanged
 * byte-identically to a job token, and a renewal re-reads the file. The file's content is never persisted.
 */
class LoginKubernetesTokenFileTest : CommandTestBase() {

    private val platform = WorkloadIdentityPlatform(api = com.devnow.thoryn.cli.cmd.provision.FakeProductApi())
    private val clientId = "wi_9a8b7c6d5e4f3a2b1c0d9e8f"

    /** A production-plane audience: the workspace issuer itself (no `/{environment}` path). */
    private fun audience() = baseUrl()

    private lateinit var tokenFile: Path

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        WorkloadIdentityPlatform.leaveRunner()
        CommandSupport.resetSessionHintForTest()
        tokenFile = tempHome.resolve("tokens/thoryn/token")
        Files.createDirectories(tokenFile.parent)
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
    }

    private fun projectToken(namespace: String = "forge", serviceAccount: String = "forge-oauth2-proxy"): String =
        FakeJobTokens.kubernetesToken(audience(), namespace, serviceAccount).also { Files.writeString(tokenFile, it + "\n") }

    private fun writeConnection(pins: String = """"kubernetes": { "issuer": "${FakeJobTokens.KUBERNETES_ISSUER}", "namespace": "forge", "serviceAccount": "forge-oauth2-proxy" }"""): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "workload_identity",
                "provider": "kubernetes",
                "clientId": "$clientId",
                "audience": "${audience()}",
                "tokenSource": { "kind": "file", "path": "$tokenFile" },
                "scopes": ["tenant:applications.write"],
                $pins
              }
            }
            """.trimIndent(),
        )
        return file
    }

    @Test
    fun `a pod signs in with the projected token read from the file — no runner, no secret, the token never stored`() {
        val token = projectToken()

        val (exit, out, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Signed in (workload identity / client '$clientId' at ${audience()}")
            .contains("re-reading the identity token at $tokenFile")
        // The exchange is the job-token exchange, byte for byte, with the FILE's content as the assertion.
        val exchange = platform.exchanges.single()
        assertThat(exchange).containsEntry("grant_type", "client_credentials")
            .containsEntry("client_id", clientId)
            .containsEntry("client_assertion_type", WorkloadIdentityFlow.CLIENT_ASSERTION_TYPE)
            .containsEntry("client_assertion", token)
            .containsEntry("scope", "tenant:applications.write")
            .doesNotContainKey("client_secret")
        // Nothing asked a GitHub runner for anything.
        assertThat(platform.jobTokens).isEmpty()

        val stored = FileTokenStore().read()!!
        assertThat(stored.authMode).isEqualTo(Tokens.AUTH_MODE_WORKLOAD_IDENTITY)
        assertThat(stored.clientId).isEqualTo(clientId)
        assertThat(stored.issuer).isEqualTo(audience())
        assertThat(stored.tokenFile).isEqualTo(tokenFile.toString())
        assertThat(stored.refreshToken).isNull()
        assertThat(Files.readString(tempHome.resolve(".config/thoryn/tokens.json"))).doesNotContain(token)
    }

    @Test
    fun `a missing token file fails closed naming the path and the projected volume — nothing is sent`() {
        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains("no identity token at '$tokenFile'").contains("the file does not exist")
            .contains("serviceAccountToken").contains("auth.tokenSource.path")
        assertThat(server.requestCount).isZero()
        assertThat(FileTokenStore().read()).isNull()
    }

    @Test
    fun `an unreadable token file (a directory where the file should be) and an empty one fail closed`() {
        Files.createDirectories(tokenFile) // the path exists but is a directory: the read fails
        val unreadable = runCli("login", "--connection", writeConnection().toString())
        assertThat(unreadable.exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(unreadable.err).contains("could not read the identity token at '$tokenFile'")

        Files.delete(tokenFile)
        Files.writeString(tokenFile, "\n")
        val empty = runCli("login", "--connection", writeConnection().toString())
        assertThat(empty.exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(empty.err).contains("the identity token file '$tokenFile' is empty")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `an expired session renews itself by RE-READING the token file — a rotated projected token is picked up`() {
        seedTokens(
            Tokens(
                accessToken = "AT-expired",
                expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 5,
                scope = "tenant:applications.write",
                issuer = audience(),
                gateway = baseUrl(),
                authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY,
                clientId = clientId,
                tokenEndpoint = "${audience()}/oauth2/token",
                tokenFile = tokenFile.toString(),
            ),
        )
        val rotated = projectToken() // what kubelet wrote since the sign-in

        val (exit, _, err) = runCli("env", "list", "--gateway", baseUrl())

        assertThat(err).doesNotContain("Could not renew")
        assertThat(exit).isEqualTo(0)
        assertThat(platform.jobTokens).isEmpty()
        assertThat(platform.exchanges.single()).containsEntry("client_assertion", rotated).containsEntry("scope", "tenant:applications.write")
        assertThat(platform.apiAuthorizations).containsOnly("Bearer AT-wif-1")
        val renewed = FileTokenStore().read()!!
        assertThat(renewed.accessToken).isEqualTo("AT-wif-1")
        assertThat(renewed.tokenFile).isEqualTo(tokenFile.toString())
    }

    @Test
    fun `a renewal whose token file is gone says where the session renews — and does not blame GitHub Actions`() {
        seedTokens(
            Tokens(
                accessToken = "AT-expired",
                expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 5,
                issuer = audience(),
                gateway = baseUrl(),
                authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY,
                clientId = clientId,
                tokenFile = tokenFile.toString(),
            ),
        )

        val (_, _, err) = runCli("env", "list", "--gateway", baseUrl())

        assertThat(err).contains("Could not renew the workload identity session")
            .contains("renews only where its identity token file is mounted")
            .contains("--token-file $tokenFile")
            .doesNotContain("GitHub Actions job that signed in")
    }

    @Test
    fun `a refusal prints the pod's identity — namespace and service account — and the pin that differs, never the token`() {
        val token = projectToken(namespace = "staging")
        platform.tokenResponses += WorkloadIdentityPlatform.json(401, """{"error":"invalid_client"}""")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err)
            .contains("refused the workload identity exchange (HTTP 401: invalid_client)")
            .contains("This pod (claims of its projected ServiceAccount token")
            .contains("system:serviceaccount:staging:forge-oauth2-proxy")
            .contains("namespace: the trust pins 'forge'; this pod runs in 'staging'")
            .contains("issuer, namespace and service account must all match")
            .doesNotContain("GitHub OIDC token")
            .doesNotContain(token)
    }

    @Test
    fun `the flag form --token-file exchanges the file too, and is refused outside --workload-identity`() {
        val token = projectToken()

        val (exit, out, err) = runCli(
            "login", "--workload-identity", "--client-id", clientId, "--audience", audience(), "--token-file", tokenFile.toString(), "--gateway", baseUrl(),
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("--token-file $tokenFile")
        assertThat(platform.exchanges.single()).containsEntry("client_assertion", token)
        assertThat(platform.jobTokens).isEmpty()
        assertThat(FileTokenStore().read()!!.tokenFile).isEqualTo(tokenFile.toString())

        val outside = runCli("login", "--client-credentials", "--token-file", tokenFile.toString(), "--issuer", baseUrl())
        assertThat(outside.exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(outside.err).contains("--token-file apply to --workload-identity only")

        val withConnection = runCli("login", "--connection", writeConnection().toString(), "--token-file", tokenFile.toString())
        assertThat(withConnection.exit).isEqualTo(LoginCommand.EXIT_USAGE)
        assertThat(withConnection.err).contains("mutually exclusive").contains("--token-file")
    }
}
