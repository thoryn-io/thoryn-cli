package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

/**
 * SSO-3927 — a sign-in that names a workspace leaves that workspace SELECTED.
 *
 * Reported against 0.42.0: `thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org` signed
 * in, and the very next `thoryn env use production` failed "no workspace selected. Run `thoryn workspace
 * switch <slug>` first". The cause was every login path calling [SelectedWorkspaceStore.clear] (SSO-2863:
 * "a fresh login resets the base tenant"). That was right when a login landed on the shared default
 * tenant; since SSO-3104 an interactive login lands ON the workspace, so clearing threw away exactly the
 * workspace the flag had just named. Since SSO-3692 a selection equal to the session's own issuer costs
 * nothing (the base token is used as-is, no exchange) — so login now writes that selection instead.
 *
 * What still holds from SSO-2863: a login never leaves a STALE selection behind. A login on another
 * workspace replaces it (and drops the previous workspace's environment); a login that names no
 * workspace (an API key on the platform base issuer) clears it.
 */
class LoginSelectsWorkspaceTest : CommandTestBase() {

    private val selection: Path get() = tempHome.resolve(".config/thoryn/workspace.json")

    @BeforeEach
    fun freshMachine() {
        clearTokens()
    }

    @AfterEach
    fun clearProps() {
        listOf(HUB_ENV, SECRET_ENV).forEach { System.clearProperty(it) }
        System.clearProperty("THORYN_CLIENT_SECRET")
    }

    /** An unsigned JWT carrying [claims] — the CLI only ever READS claims from its own access token. */
    private fun jwt(claims: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString(claims.toByteArray()) + "."
    }

    private fun enqueueDeviceCodeSignIn(accessToken: String) {
        server.enqueue(jsonResponse(200, """{"device_code":"DEV-1","user_code":"ABCD-1234","verification_uri":"${baseUrl()}/activate","expires_in":600,"interval":0}"""))
        server.enqueue(jsonResponse(200, """{"access_token":"$accessToken","refresh_token":"RT-1","token_type":"Bearer","expires_in":900}"""))
    }

    private fun environments() = jsonResponse(
        200,
        """{"environments":[{"id":"11111111-1111-1111-1111-111111111111","slug":"production","name":"Production","kind":"production","suspended":false}]}""",
    )

    // ── the reported sequence ───────────────────────────────────────────────────────────────

    @Test
    fun `login --workspace then env use production works with no workspace switch in between`() {
        val accessToken = jwt("""{"sub":"u-1","tnt":"t-acme"}""")
        enqueueDeviceCodeSignIn(accessToken)
        // Exactly ONE more response: the environment list. A token exchange (the cross-tenant path)
        // would eat it and fail the command — the selection names the session's own issuer, so none runs.
        server.enqueue(environments())

        val login = runCli("login", "--device-code", "--workspace", "acme", "--issuer", baseUrl())
        assertThat(login.exit).withFailMessage("login stderr:\n%s", login.err).isEqualTo(0)
        assertThat(login.out).contains("Workspace 'acme' is selected")

        val use = runCli("env", "use", "production", "--gateway", baseUrl())

        assertThat(use.err).doesNotContain("no workspace selected")
        assertThat(use.exit).withFailMessage("env use stderr:\n%s", use.err).isEqualTo(0)
        assertThat(use.out).contains("Now targeting environment 'production' in workspace 'acme'")
        assertThat(server.requestCount).isEqualTo(3) // device authorization, token poll, environment list
        server.takeRequest(); server.takeRequest()
        val list = server.takeRequest()
        assertThat(list.path).isEqualTo("/api/v1/environments")
        assertThat(list.getHeader("Authorization")).isEqualTo("Bearer $accessToken")

        val selected = SelectedWorkspaceStore().read()!!
        assertThat(selected.slug).isEqualTo("acme")
        assertThat(selected.tenantId).isEqualTo("t-acme") // the token's `tnt`
        assertThat(selected.tenantHubIssuer).isEqualTo(FileTokenStore().read()!!.issuer)
        assertThat(selected.environmentSlug).isEqualTo("production")
    }

    // ── re-login, no --workspace ────────────────────────────────────────────────────────────

    @Test
    fun `a login on another workspace replaces the selection and drops the old workspace's environment`() {
        SelectedWorkspaceStore().write(
            SelectedWorkspace(tenantId = "t-globex", slug = "globex", tenantHubIssuer = "https://globex.auth.example.org", environmentSlug = "sandbox"),
        )
        enqueueDeviceCodeSignIn("AT-acme")

        val login = runCli("login", "--device-code", "--workspace", "acme", "--issuer", baseUrl())

        assertThat(login.exit).withFailMessage(login.err).isEqualTo(0)
        val selected = SelectedWorkspaceStore().read()!!
        assertThat(selected.slug).isEqualTo("acme")
        assertThat(selected.tenantHubIssuer).isEqualTo(baseUrl())
        assertThat(selected.environmentSlug)
            .describedAs("globex's 'sandbox' is not an environment of acme — the selection starts on the production plane")
            .isNull()
    }

    @Test
    fun `a login without --workspace selects the default workspace it announced`() {
        enqueueDeviceCodeSignIn("AT-default")

        val login = runCli("login", "--device-code", "--issuer", baseUrl())

        assertThat(login.exit).withFailMessage(login.err).isEqualTo(0)
        assertThat(login.err).contains("Signing in on the default workspace '${ThorynConfig.DEFAULT_WORKSPACE}'")
        assertThat(SelectedWorkspaceStore().read()?.slug).isEqualTo(ThorynConfig.DEFAULT_WORKSPACE)
    }

    @Test
    fun `a failed login leaves the existing selection untouched`() {
        val before = SelectedWorkspace(tenantId = "t-globex", slug = "globex", tenantHubIssuer = "https://globex.auth.example.org", environmentSlug = "sandbox")
        SelectedWorkspaceStore().write(before)
        server.enqueue(jsonResponse(200, """{"device_code":"DEV-1","user_code":"ABCD-1234","verification_uri":"${baseUrl()}/activate","expires_in":600,"interval":0}"""))
        server.enqueue(jsonResponse(400, """{"error":"access_denied"}"""))

        val login = runCli("login", "--device-code", "--workspace", "acme", "--issuer", baseUrl())

        assertThat(login.exit).isNotEqualTo(0)
        assertThat(SelectedWorkspaceStore().read()).isEqualTo(before)
    }

    // ── machine sign-ins ────────────────────────────────────────────────────────────────────

    @Test
    fun `login --connection with an API key selects the contract's workspace`() {
        System.setProperty(HUB_ENV, baseUrl())
        System.setProperty(SECRET_ENV, "ci-bot-secret")
        server.enqueue(jsonResponse(200, """{"access_token":"AT-conn","token_type":"Bearer","expires_in":3600,"scope":"tenant:environments.read"}"""))
        server.enqueue(environments())

        val login = runCli("login", "--connection", connection(slug = "acme", auth = apiKeyAuth()).toString())
        assertThat(login.exit).withFailMessage(login.err).isEqualTo(0)
        val use = runCli("env", "use", "production", "--gateway", baseUrl())

        assertThat(use.exit).withFailMessage(use.err).isEqualTo(0)
        assertThat(SelectedWorkspaceStore().read()!!.slug).isEqualTo("acme")
        server.takeRequest()
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer AT-conn")
    }

    @Test
    fun `login --connection with a workload identity token file selects the contract's workspace`() {
        val platform = WorkloadIdentityPlatform(api = com.devnow.thoryn.cli.cmd.provision.FakeProductApi())
        server.dispatcher = platform
        WorkloadIdentityPlatform.leaveRunner()
        val tokenFile = tempHome.resolve("tokens/thoryn/token")
        Files.createDirectories(tokenFile.parent)
        Files.writeString(tokenFile, FakeJobTokens.kubernetesToken(baseUrl(), "forge", "forge-oauth2-proxy") + "\n")
        val auth = """
            "method": "workload_identity",
            "provider": "kubernetes",
            "clientId": "wi_9a8b7c6d5e4f3a2b1c0d9e8f",
            "audience": "${baseUrl()}",
            "tokenSource": { "kind": "file", "path": "$tokenFile" },
            "scopes": ["tenant:applications.write"],
            "kubernetes": { "issuer": "${FakeJobTokens.KUBERNETES_ISSUER}", "namespace": "forge", "serviceAccount": "forge-oauth2-proxy" }
        """.trimIndent()
        try {
            val login = runCli("login", "--connection", connection(slug = "acme", auth = auth).toString())

            assertThat(login.exit).withFailMessage(login.err).isEqualTo(0)
            val selected = SelectedWorkspaceStore().read()!!
            assertThat(selected.slug).isEqualTo("acme")
            assertThat(selected.tenantHubIssuer).isEqualTo(baseUrl())
        } finally {
            WorkloadIdentityPlatform.leaveRunner()
        }
    }

    @Test
    fun `an API-key login on the platform base issuer names no workspace and clears a stale selection`() {
        SelectedWorkspaceStore().write(SelectedWorkspace(tenantId = "t-globex", slug = "globex", tenantHubIssuer = "https://globex.auth.example.org"))
        System.setProperty("THORYN_CLIENT_SECRET", "s3cret")
        server.enqueue(jsonResponse(200, """{"access_token":"AT-cc","token_type":"Bearer","expires_in":3600}"""))

        val login = runCli("login", "--client-credentials", "--client-id", "svc-1", "--issuer", baseUrl())

        assertThat(login.exit).withFailMessage(login.err).isEqualTo(0)
        assertThat(Files.exists(selection))
            .describedAs("a session that names no workspace must not keep exchanging into the old one (SSO-2863)")
            .isFalse()
        assertThat(login.out).doesNotContain("is selected")
    }

    private fun apiKeyAuth() = """
        "method": "client_credentials",
        "clientId": "thoryn-cli-ci",
        "secretEnv": "$SECRET_ENV",
        "scopes": ["tenant:environments.read"]
    """.trimIndent()

    private fun connection(slug: String, auth: String): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "$slug", "hubBaseUrlEnv": "$HUB_ENV" },
              "auth": {
            $auth
              }
            }
            """.trimIndent(),
        )
        return file
    }

    private companion object {
        const val HUB_ENV = "THORYN_TEST_HUB"
        const val SECRET_ENV = "THORYN_TEST_CI_SECRET"
    }
}
