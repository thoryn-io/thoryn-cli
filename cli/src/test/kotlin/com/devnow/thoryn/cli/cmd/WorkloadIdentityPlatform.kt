package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import java.net.URLDecoder
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * SSO-3308 — one MockWebServer [Dispatcher] standing in for the three parties of a workload identity
 * sign-in: the GitHub Actions runner's job-token endpoint ([JOB_TOKEN_PATH]), the platform token endpoint
 * (any path ending `/oauth2/token`) and, for everything else, the customer-plane API ([api], e.g. the
 * provisioning FakeProductApi). It records every job token it issued, every exchange form, and the
 * `Authorization` header of every API call, so a test can prove which bearer reached the API and that each
 * exchange spent a fresh job token.
 */
internal class WorkloadIdentityPlatform(private val api: Dispatcher? = null) : Dispatcher() {

    val jobTokens = CopyOnWriteArrayList<String>()
    val exchanges = CopyOnWriteArrayList<Map<String, String>>()
    val apiAuthorizations = CopyOnWriteArrayList<String?>()

    /** Queued non-default token-endpoint answers; when empty the exchange succeeds with `AT-wif-<n>`. */
    val tokenResponses = ConcurrentLinkedQueue<MockResponse>()

    /** The claims of the next job token, given the requested audience. */
    @Volatile
    var claims: (String) -> Map<String, Any?> = { aud -> FakeJobTokens.claims(aud) }

    private val minted = AtomicInteger()

    override fun dispatch(request: RecordedRequest): MockResponse {
        val path = request.path ?: "/"
        return when {
            path.startsWith(JOB_TOKEN_PATH) -> {
                if (request.getHeader("Authorization") != "Bearer $RUNNER_REQUEST_TOKEN") return json(401, """{"message":"bad runner token"}""")
                val aud = request.requestUrl?.queryParameter("audience") ?: return json(400, """{"message":"no audience"}""")
                val token = FakeJobTokens.token(claims(aud)).also { jobTokens += it }
                json(200, """{"count":1,"value":"$token"}""")
            }
            path.substringBefore('?').endsWith("/oauth2/token") -> {
                exchanges += form(request.body.readUtf8())
                tokenResponses.poll() ?: json(
                    200,
                    """{"access_token":"AT-wif-${minted.incrementAndGet()}","token_type":"Bearer","expires_in":900,"scope":"${exchanges.last()["scope"] ?: "tenant:environments.read"}"}""",
                )
            }
            else -> {
                apiAuthorizations += request.getHeader("Authorization")
                api?.dispatch(request) ?: MockResponse().setResponseCode(404)
            }
        }
    }

    private fun form(body: String): Map<String, String> =
        body.split("&").filter { it.contains('=') }.associate { pair ->
            val (k, v) = pair.split("=", limit = 2)
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }

    companion object {
        const val JOB_TOKEN_PATH = "/_apis/actions/token"
        const val RUNNER_REQUEST_TOKEN = "runner-request-token-not-a-real-one"

        fun json(status: Int, body: String): MockResponse =
            MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)

        /** Point the CLI at [baseUrl] as the GitHub runner (the `-D` form the CLI reads first). */
        fun actAsRunner(baseUrl: String) {
            System.setProperty(WorkloadIdentityFlow.REQUEST_URL_ENV, "$baseUrl$JOB_TOKEN_PATH?api-version=2.0")
            System.setProperty(WorkloadIdentityFlow.REQUEST_TOKEN_ENV, RUNNER_REQUEST_TOKEN)
        }

        fun leaveRunner() {
            System.clearProperty(WorkloadIdentityFlow.REQUEST_URL_ENV)
            System.clearProperty(WorkloadIdentityFlow.REQUEST_TOKEN_ENV)
        }
    }
}
