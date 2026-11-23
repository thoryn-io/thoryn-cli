package com.devnow.thoryn.cli.auth

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.net.http.HttpClient
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList

/**
 * SSO-4472 — [WorkloadIdentityFlow] for a Forgejo Actions job, against a MockWebServer standing in for the Forgejo
 * runner's token route (`<ROOT_URL>api/actions/_apis/pipelines/workflows/<run>/idtoken`, the URL Forgejo hands the job
 * as `ACTIONS_ID_TOKEN_REQUEST_URL`) and one for the platform token endpoint. The wire is GitHub's — the audience as
 * `audience=` and the runner's bearer — and the exchange is byte-identical; a redirect (an authenticating proxy in front
 * of the instance) is NEVER followed; a token FILE works the same; and every failure says Forgejo, never GitHub.
 */
class WorkloadIdentityForgejoFlowTest {

    private lateinit var forge: MockWebServer
    private lateinit var platform: MockWebServer
    private val issued = CopyOnWriteArrayList<String>()
    private val loginPageHits = CopyOnWriteArrayList<String>()

    /** What the forge's token route answers: the token (default) or a redirect to an authenticating proxy's login page. */
    @Volatile
    private var redirect = false

    private val runnerRequestToken = "forgejo-runner-request-token-not-a-real-one"

    private fun audience() = platform.url("/").toString().trimEnd('/')

    @BeforeEach
    fun start() {
        forge = MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val path = request.path ?: "/"
                    if (path.startsWith("/oauth2/start")) {
                        loginPageHits += request.getHeader("Authorization") ?: "(no bearer)"
                        return MockResponse().setResponseCode(200).setBody("<html>sign in</html>")
                    }
                    if (redirect) return MockResponse().setResponseCode(302).setHeader("Location", forge.url("/oauth2/start?rd=$path").toString())
                    if (request.getHeader("Authorization") != "Bearer $runnerRequestToken") return json(401, """{"message":"bad"}""")
                    val aud = request.requestUrl?.queryParameter("audience") ?: return json(400, """{"message":"no audience"}""")
                    val token = FakeJobTokens.token(FakeJobTokens.forgejoClaims(aud, eventName = "workflow_dispatch")).also { issued += it }
                    return json(200, """{"value":"$token"}""")
                }
            }
            start()
        }
        platform = MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    json(200, """{"access_token":"AT-forgejo","token_type":"Bearer","expires_in":900,"scope":"tenant:applications.write"}""")
            }
            start()
        }
    }

    @AfterEach
    fun stop() {
        forge.shutdown()
        platform.shutdown()
    }

    private fun json(status: Int, body: String) =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)

    private val runnerEnv: (String) -> String? = { name ->
        when (name) {
            // Forgejo's request URL already carries a query string; the CLI appends `&audience=`.
            WorkloadIdentityFlow.REQUEST_URL_ENV -> forge.url("/api/actions/_apis/pipelines/workflows/1234/idtoken?api-version=2.0").toString()
            WorkloadIdentityFlow.REQUEST_TOKEN_ENV -> runnerRequestToken
            else -> null
        }
    }

    private fun sender(): HttpSender {
        val client = HttpClient.newHttpClient()
        return HttpSender { r, h -> client.send(r, h) }
    }

    /** [oidc] null ⇒ the flow's own production runner client (the one whose redirect policy is under test). */
    private fun flow(env: (String) -> String? = runnerEnv, tokenFile: java.nio.file.Path? = null, oidc: HttpSender? = sender()) =
        if (oidc == null) {
            WorkloadIdentityFlow("wi_5e4f3a2b1c0d9e8f7a6b5c4d", audience(), "${audience()}/oauth2/token", sender(), env = env, tokenFile = tokenFile, provider = "forgejo")
        } else {
            WorkloadIdentityFlow("wi_5e4f3a2b1c0d9e8f7a6b5c4d", audience(), "${audience()}/oauth2/token", sender(), oidc, env, tokenFile = tokenFile, provider = "forgejo")
        }

    private fun form(body: String): Map<String, String> =
        body.split("&").associate { val (k, v) = it.split("=", limit = 2); URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8) }

    @Test
    fun `a Forgejo job asks its runner for a token for the trust's audience and exchanges it like any job token`() {
        val tokens = flow().run("tenant:applications.write")

        val tokenRequest = forge.takeRequest()
        assertThat(tokenRequest.getHeader("Authorization")).isEqualTo("Bearer $runnerRequestToken")
        assertThat(tokenRequest.requestUrl!!.queryParameter("api-version")).isEqualTo("2.0")
        assertThat(tokenRequest.requestUrl!!.queryParameter("audience")).isEqualTo(audience())
        val exchange = form(platform.takeRequest().body.readUtf8())
        assertThat(exchange).containsEntry("grant_type", "client_credentials")
            .containsEntry("client_id", "wi_5e4f3a2b1c0d9e8f7a6b5c4d")
            .containsEntry("client_assertion_type", WorkloadIdentityFlow.CLIENT_ASSERTION_TYPE)
            .containsEntry("client_assertion", issued.single())
            .containsEntry("scope", "tenant:applications.write")
            .doesNotContainKey("client_secret")
        assertThat(tokens.accessToken).isEqualTo("AT-forgejo")
        assertThat(tokens.refreshToken).isNull()
    }

    @Test
    fun `the job identity of a Forgejo token is recognised as Forgejo, with its instance, ids, ref and base_ref`() {
        val identity = JobIdentity.of(FakeJobTokens.forgejoToken(audience(), eventName = "pull_request", ref = "refs/pull/9/head", baseRef = "main"))
        assertThat(identity.isForgejo).isTrue()
        assertThat(identity.isKubernetes).isFalse()
        assertThat(identity.forgejoInstance).isEqualTo(FakeJobTokens.FORGEJO_INSTANCE)
        assertThat(identity.repository).isEqualTo("acme/infra")
        assertThat(identity.repositoryId).isEqualTo("42")
        assertThat(identity.repositoryOwnerId).isEqualTo("7")
        assertThat(identity.subject).isEqualTo("repo:acme-7/infra-42:pull_request")
        assertThat(identity.baseRef).isEqualTo("main")
        // A GitHub job token is not mistaken for one.
        assertThat(JobIdentity.of(FakeJobTokens.token(audience())).isForgejo).isFalse()
    }

    @Test
    fun `a redirect from the token URL (an authenticating proxy) is never followed — the runner's bearer goes nowhere else`() {
        redirect = true

        assertThatThrownBy { flow(oidc = null).run("tenant:applications.write") }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .hasMessageContaining("redirected (HTTP 302)")
            .hasMessageContaining("authenticating proxy")
            .hasMessageContaining("auth.tokenSource")
            .satisfies({ e -> assertThat((e as WorkloadIdentityException).oauthError).isEqualTo(WorkloadIdentityFlow.ERROR_JOB_TOKEN_REDIRECTED) })
        assertThat(loginPageHits).isEmpty()
        assertThat(platform.requestCount).isZero()
    }

    @Test
    fun `outside a job with enable-openid-connect the error says Forgejo and names the key and the file fallback`() {
        assertThatThrownBy { flow(env = { null }).run(null) }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .hasMessageContaining("no Forgejo Actions job token available")
            .hasMessageContaining("enable-openid-connect: true")
            .hasMessageContaining("auth.tokenSource")
            .hasMessageNotContaining("id-token: write")
            .satisfies({ e -> assertThat((e as WorkloadIdentityException).oauthError).isEqualTo(WorkloadIdentityFlow.ERROR_NOT_ON_FORGEJO_ACTIONS) })
        assertThat(forge.requestCount).isZero()
    }

    @Test
    fun `a token file stands in for the runner — read on every exchange, its content never in an error`(): Unit {
        val dir = Files.createTempDirectory("forgejo-token")
        val file = dir.resolve("token")
        val token = FakeJobTokens.forgejoToken(audience(), eventName = "workflow_dispatch")
        Files.writeString(file, token + "\n")

        flow(env = { null }, tokenFile = file).run("tenant:applications.write")

        assertThat(form(platform.takeRequest().body.readUtf8())).containsEntry("client_assertion", token)
        assertThat(forge.requestCount).isZero()
        Files.delete(file)
        assertThatThrownBy { flow(env = { null }, tokenFile = file).run(null) }
            .hasMessageContaining("no identity token at '$file'")
            .hasMessageContaining("Forgejo Actions token")
            .hasMessageNotContaining("serviceAccountToken")
    }
}
