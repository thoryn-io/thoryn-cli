package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Optional
import java.util.concurrent.Flow
import javax.net.ssl.SSLSession

/**
 * SSO-2879 — unit tests for [WorkloadIdentityFlow]: building the GitHub OIDC token request,
 * assembling the RFC 8693 + RFC 7523 token-exchange form, and driving the two-leg flow
 * (GitHub OIDC fetch -> token exchange) with a stubbed [HttpSender].
 */
class WorkloadIdentityFlowTest {

    private val signer = EcPrivateKeyJwtSigner(privateKeyPem = testPem(), keyId = "kid-1")

    private val tokenResponse = """
        {"access_token":"AT-wif","token_type":"Bearer","expires_in":300,
         "scope":"tenant:applications.write tenant:federation.write"}
    """.trimIndent()

    // ── request/form shaping ─────────────────────────────────────────────────────────────────────

    @Test
    fun `buildOidcTokenRequest appends the audience and sends the ephemeral token as a bearer`() {
        val req = WorkloadIdentityFlow.buildOidcTokenRequest(
            requestUrl = "https://pipelines.actions.example/token?api-version=1.0",
            requestToken = "runner-token-xyz",
            audience = "https://hub.stg.thoryn.org",
        )
        assertThat(req.method()).isEqualTo("GET")
        // Existing query string keeps its `?`, so audience is appended with `&` and URL-encoded.
        assertThat(req.uri().toString())
            .contains("api-version=1.0")
            .contains("&audience=https%3A%2F%2Fhub.stg.thoryn.org")
        assertThat(req.headers().firstValue("Authorization")).hasValue("Bearer runner-token-xyz")
    }

    @Test
    fun `buildForm carries the token-exchange grant, id_token subject type, the assertion and client_id`() {
        val flow = flow(sender = CapturingSender())
        val body = flow.buildForm("SUBJECT-JWT", "ASSERTION-JWT", "openid tenant:applications.write")

        assertThat(body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
        assertThat(body).contains("subject_token=SUBJECT-JWT")
        assertThat(body).contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token")
        assertThat(body).contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer")
        assertThat(body).contains("client_assertion=ASSERTION-JWT")
        assertThat(body).contains("client_id=conformance-ci-github-wif")
        assertThat(body).contains("scope=openid+tenant%3Aapplications.write")
    }

    @Test
    fun `buildForm omits client_id when asked (reproducing the SSO-1608 bug)`() {
        val body = flow(sender = CapturingSender()).buildForm("S", "A", null, includeClientId = false)
        assertThat(body).doesNotContain("client_id=")
    }

    // ── happy path with an explicit subject token (no GitHub call) ────────────────────────────────

    @Test
    fun `run exchanges an explicit subject token and returns the minted token`() {
        val sender = CapturingSender(stub(200, tokenResponse))
        val flow = flow(sender = sender, explicitSubjectToken = "GH-OIDC-JWT")

        val tokens = flow.run("openid tenant:applications.write")

        assertThat(tokens.accessToken).isEqualTo("AT-wif")
        assertThat(tokens.refreshToken).isNull()
        assertThat(tokens.scope).isEqualTo("tenant:applications.write tenant:federation.write")

        val req = sender.requests.single()
        assertThat(req.uri().toString()).isEqualTo("https://ci-conformance.hub.stg.thoryn.org/oauth2/token")
        val body = sender.bodies.single()!!
        assertThat(body).contains("subject_token=GH-OIDC-JWT")
        assertThat(body).contains("client_assertion=")
        assertThat(body).contains("client_id=conformance-ci-github-wif")
    }

    // ── two-leg path: fetch GitHub OIDC token, then exchange ──────────────────────────────────────

    @Test
    fun `run fetches the GitHub OIDC token from the runner env then exchanges it`() {
        val sender = CapturingSender(
            stub(200, """{"value":"GH-OIDC-FROM-RUNNER"}"""), // leg 1: GitHub OIDC
            stub(200, tokenResponse),                          // leg 2: token exchange
        )
        val flow = flow(
            sender = sender,
            env = mapOf(
                "ACTIONS_ID_TOKEN_REQUEST_URL" to "https://runner/token",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN" to "ephemeral-xyz",
            )::get,
        )

        val tokens = flow.run("openid")

        assertThat(tokens.accessToken).isEqualTo("AT-wif")
        // Leg 1 hit the runner OIDC endpoint with the audience; leg 2 exchanged the fetched value.
        assertThat(sender.requests[0].uri().toString()).contains("https://runner/token").contains("audience=")
        assertThat(sender.bodies[1]!!).contains("subject_token=GH-OIDC-FROM-RUNNER")
    }

    @Test
    fun `run fails clearly when no subject token and not on a runner`() {
        val flow = flow(sender = CapturingSender(), env = { null })
        assertThatThrownBy { flow.run("openid") }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .extracting { (it as WorkloadIdentityException).oauthError }
            .isEqualTo("missing_subject_token")
    }

    @Test
    fun `a hub invalid_client is surfaced as the oauth error`() {
        val sender = CapturingSender(stub(401, """{"error":"invalid_client"}"""))
        val flow = flow(sender = sender, explicitSubjectToken = "GH-OIDC-JWT")
        assertThatThrownBy { flow.run("openid") }
            .isInstanceOf(WorkloadIdentityException::class.java)
            .extracting { (it as WorkloadIdentityException).oauthError }
            .isEqualTo("invalid_client")
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    private fun flow(
        sender: HttpSender,
        explicitSubjectToken: String? = null,
        env: (String) -> String? = { null },
    ) = WorkloadIdentityFlow(
        tokenEndpoint = "https://ci-conformance.hub.stg.thoryn.org/oauth2/token",
        assertionAudience = "https://hub.stg.thoryn.org/oauth2/token",
        clientId = "conformance-ci-github-wif",
        signer = signer,
        oidcAudience = "https://hub.stg.thoryn.org",
        sender = sender,
        explicitSubjectToken = explicitSubjectToken,
        env = env,
    )

    private fun stub(status: Int, body: String): HttpResponse<String> = StubResponse(status, body)

    private fun testPem(): String {
        val kp = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(kp.private.encoded)
        return "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n"
    }

    /** Captures each request the flow sends and replies from a queued list of responses (in order). */
    private class CapturingSender(vararg responses: HttpResponse<String>) : HttpSender {
        private val queue = ArrayDeque(responses.toList())
        val requests = mutableListOf<HttpRequest>()
        val bodies = mutableListOf<String?>()

        override fun send(request: HttpRequest, bodyHandler: HttpResponse.BodyHandler<String>): HttpResponse<String> {
            requests += request
            bodies += request.bodyPublisher().map { readBody(it) }.orElse(null)
            return queue.removeFirstOrNull() ?: throw IOException("no stubbed response left")
        }

        private fun readBody(publisher: HttpRequest.BodyPublisher): String {
            val sb = StringBuilder()
            publisher.subscribe(object : Flow.Subscriber<ByteBuffer> {
                override fun onSubscribe(subscription: Flow.Subscription) = subscription.request(Long.MAX_VALUE)
                override fun onNext(item: ByteBuffer) {
                    val bytes = ByteArray(item.remaining()); item.get(bytes); sb.append(String(bytes, Charsets.UTF_8))
                }
                override fun onError(throwable: Throwable) = Unit
                override fun onComplete() = Unit
            })
            return sb.toString()
        }
    }

    private class StubResponse(private val status: Int, private val body: String) : HttpResponse<String> {
        override fun statusCode(): Int = status
        override fun request(): HttpRequest = throw UnsupportedOperationException()
        override fun previousResponse(): Optional<HttpResponse<String>> = Optional.empty()
        override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
        override fun body(): String = body
        override fun sslSession(): Optional<SSLSession> = Optional.empty()
        override fun uri(): URI = URI.create("http://test")
        override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1
    }
}
