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
import java.util.concurrent.CopyOnWriteArrayList

/**
 * SSO-3308 — [WorkloadIdentityFlow] against two MockWebServers: one standing in for the GitHub Actions
 * runner's job-token endpoint (`$ACTIONS_ID_TOKEN_REQUEST_URL`), one for the platform token endpoint.
 * Pins the wire contract of oathy #3787: the audience + bearer on the job-token request; exactly
 * `grant_type=client_credentials`, the workload `client_id`, the jwt-bearer assertion type and the job
 * token as `client_assertion` on the exchange, with NO client secret; and a FRESH job token for every
 * exchange (a job token works once).
 */
class WorkloadIdentityFlowTest {

    private lateinit var github: MockWebServer
    private lateinit var platform: MockWebServer
    private val issuedJobTokens = CopyOnWriteArrayList<String>()

    private val runnerRequestToken = "runner-request-token-not-a-real-one"

    private fun audience() = platform.url("/cli-ci").toString().trimEnd('/')

    @BeforeEach
    fun start() {
        github = MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val aud = request.requestUrl?.queryParameter("audience") ?: return MockResponse().setResponseCode(400)
                    val token = FakeJobTokens.token(aud).also { issuedJobTokens += it }
                    return json(200, """{"count":1,"value":"$token"}""")
                }
            }
            start()
        }
        platform = MockWebServer().also { it.start() }
    }

    @AfterEach
    fun stop() {
        github.shutdown()
        platform.shutdown()
    }

    private fun json(status: Int, body: String) =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)

    private val runnerEnv: (String) -> String? = { name ->
        when (name) {
            WorkloadIdentityFlow.REQUEST_URL_ENV -> github.url("/_apis/actions/token?api-version=2.0").toString()
            WorkloadIdentityFlow.REQUEST_TOKEN_ENV -> runnerRequestToken
            else -> null
        }
    }

    private fun sender(): HttpSender {
        val client = HttpClient.newHttpClient()
        return HttpSender { r, h -> client.send(r, h) }
    }

    private fun flow(env: (String) -> String? = runnerEnv) = WorkloadIdentityFlow(
        clientId = "wi_0123456789abcdef01234567",
        audience = audience(),
        tokenEndpoint = "${audience()}/oauth2/token",
        tokenSender = sender(),
        oidcSender = sender(),
        env = env,
    )

    private fun form(body: String): Map<String, String> =
        body.split("&").associate { pair ->
            val (k, v) = pair.split("=", limit = 2)
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }

    @Test
    fun `the job token is requested for the trust's audience with the runner's bearer, then exchanged with exactly the contract's fields`() {
        platform.enqueue(json(200, """{"access_token":"AT-wif","token_type":"Bearer","expires_in":900,"scope":"tenant:environments.read"}"""))

        val tokens = flow().run("tenant:environments.read")

        assertThat(tokens.accessToken).isEqualTo("AT-wif")
        assertThat(tokens.refreshToken).isNull()
        assertThat(tokens.scope).isEqualTo("tenant:environments.read")
        assertThat(tokens.expiresAtEpochSecond!! - System.currentTimeMillis() / 1000).isBetween(890L, 900L)

        val jobTokenRequest = github.takeRequest()
        assertThat(jobTokenRequest.method).isEqualTo("GET")
        assertThat(jobTokenRequest.requestUrl!!.queryParameter("api-version")).isEqualTo("2.0")
        assertThat(jobTokenRequest.requestUrl!!.queryParameter("audience")).isEqualTo(audience())
        assertThat(jobTokenRequest.getHeader("Authorization")).isEqualTo("Bearer $runnerRequestToken")

        val exchange = platform.takeRequest()
        assertThat(exchange.method).isEqualTo("POST")
        assertThat(exchange.path).isEqualTo("/cli-ci/oauth2/token")
        assertThat(exchange.getHeader("Content-Type")).startsWith("application/x-www-form-urlencoded")
        // No client secret in any shape: no Basic header, no client_secret field.
        assertThat(exchange.getHeader("Authorization")).isNull()
        val fields = form(exchange.body.readUtf8())
        assertThat(fields).containsExactlyInAnyOrderEntriesOf(
            mapOf(
                "grant_type" to "client_credentials",
                "client_id" to "wi_0123456789abcdef01234567",
                "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion" to issuedJobTokens.single(),
                "scope" to "tenant:environments.read",
            ),
        )
    }

    @Test
    fun `no scope requested sends no scope field (the trust's full set)`() {
        platform.enqueue(json(200, """{"access_token":"AT","token_type":"Bearer","expires_in":900,"scope":"tenant:a.read tenant:b.read"}"""))

        val tokens = flow().run(null)

        assertThat(form(platform.takeRequest().body.readUtf8())).doesNotContainKey("scope")
        assertThat(tokens.scope).isEqualTo("tenant:a.read tenant:b.read")
    }

    @Test
    fun `every exchange uses a fresh job token — a second run asks the runner again`() {
        platform.enqueue(json(200, """{"access_token":"AT-1","token_type":"Bearer","expires_in":900}"""))
        platform.enqueue(json(200, """{"access_token":"AT-2","token_type":"Bearer","expires_in":900}"""))

        assertThat(flow().run("tenant:environments.read").accessToken).isEqualTo("AT-1")
        assertThat(flow().run("tenant:environments.read").accessToken).isEqualTo("AT-2")

        assertThat(github.requestCount).isEqualTo(2)
        assertThat(issuedJobTokens).hasSize(2).doesNotHaveDuplicates()
        val first = form(platform.takeRequest().body.readUtf8())["client_assertion"]
        val second = form(platform.takeRequest().body.readUtf8())["client_assertion"]
        assertThat(listOf(first, second)).containsExactlyElementsOf(issuedJobTokens)
    }

    @Test
    fun `a refused exchange carries the job's public identity and the platform's code, never the job token`() {
        platform.enqueue(json(401, """{"error":"invalid_client"}"""))

        val thrown = runCatching { flow().run("tenant:environments.read") }.exceptionOrNull()

        assertThat(thrown).isInstanceOf(WorkloadIdentityException::class.java)
        val e = thrown as WorkloadIdentityException
        assertThat(e.oauthError).isEqualTo("invalid_client")
        assertThat(e.status).isEqualTo(401)
        assertThat(e.jobIdentity!!.repository).isEqualTo("thoryn-io/thoryn-cli")
        assertThat(e.jobIdentity!!.audience).containsExactly(audience())
        assertThat(e.message).doesNotContain(issuedJobTokens.single())
        assertThat(e.jobIdentity.toString()).doesNotContain(issuedJobTokens.single())
    }

    @Test
    fun `outside GitHub Actions the missing runner variables are named, and nothing is sent`() {
        assertThatThrownBy { flow(env = { null }).run("tenant:environments.read") }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .hasMessageContaining(WorkloadIdentityFlow.REQUEST_URL_ENV)
            .hasMessageContaining(WorkloadIdentityFlow.REQUEST_TOKEN_ENV)
            .hasMessageContaining("id-token: write")
            .extracting { (it as WorkloadIdentityException).oauthError }
            .isEqualTo(WorkloadIdentityFlow.ERROR_NOT_ON_GITHUB_ACTIONS)
        assertThat(github.requestCount).isZero()
        assertThat(platform.requestCount).isZero()
    }

    @Test
    fun `GitHub refusing the job-token request stops before the exchange`() {
        github.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest) = json(403, """{"message":"forbidden"}""")
        }

        assertThatThrownBy { flow().run(null) }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .hasMessageContaining("HTTP 403")
            .extracting { (it as WorkloadIdentityException).oauthError }
            .isEqualTo(WorkloadIdentityFlow.ERROR_JOB_TOKEN_REQUEST_FAILED)
        assertThat(platform.requestCount).isZero()
    }

    @Test
    fun `the token endpoint defaults to the audience's and must stay on its origin`() {
        val aud = "https://acme.auth.thoryn.io/staging"
        assertThat(WorkloadIdentityFlow.tokenEndpointFor(aud, null)).isEqualTo("https://acme.auth.thoryn.io/staging/oauth2/token")
        assertThat(WorkloadIdentityFlow.tokenEndpointFor(aud, "https://acme.auth.thoryn.io/staging/oauth2/token"))
            .isEqualTo("https://acme.auth.thoryn.io/staging/oauth2/token")
        assertThatThrownBy { WorkloadIdentityFlow.tokenEndpointFor(aud, "https://evil.example/oauth2/token") }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("not on the audience's origin")
        assertThatThrownBy { WorkloadIdentityFlow.tokenEndpointFor(aud, "http://acme.auth.thoryn.io/staging/oauth2/token") }
            .isInstanceOf(IllegalArgumentException::class.java)
    }
}
