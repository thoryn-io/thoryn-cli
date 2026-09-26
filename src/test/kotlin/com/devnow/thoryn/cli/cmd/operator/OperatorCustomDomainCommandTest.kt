package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.api.OperatorHubClient
import com.devnow.thoryn.cli.auth.DpopKey
import com.devnow.thoryn.cli.auth.DpopSession
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.Base64

/**
 * SSO-3356 — `thoryn operator custom-domain entitle|revoke|status` against a MockWebServer standing in
 * for the hub behind `kubectl port-forward`. Response bodies are shaped exactly like the hub's
 * (`TenantController` → `CustomDomainEntitlementResponse` / `CustomDomainView`, the operator gate's
 * RFC 9457 refusals, Spring Security's bare `insufficient_scope` 403).
 */
class OperatorCustomDomainCommandTest : CommandTestBase() {

    private val originalFactory = OperatorCustomDomainCommand.clientFactory

    @BeforeEach
    fun seedOperatorSession() {
        seedOperator(operatorTokens())
    }

    @AfterEach
    fun restoreFactory() {
        OperatorCustomDomainCommand.clientFactory = originalFactory
    }

    @Test
    fun `entitle PUTs entitled true with the OPERATOR token and leaves the customer session alone`() {
        server.enqueue(jsonResponse(200, """{"entitled":true}"""))

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        val request = server.takeRequest()
        assertThat(request.method).isEqualTo("PUT")
        assertThat(request.path).isEqualTo("/admin/tenants/acme/custom-domain/entitlement")
        assertThat(parseJson(request.body.readUtf8())).isEqualTo(mapOf("entitled" to true))
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer ${operatorTokens().accessToken}")
        assertThat(request.getHeader("DPoP")).isNull()
        assertThat(result.out).contains("Custom domains ENABLED for workspace 'acme'")
        // The customer session (seeded by CommandTestBase) is untouched.
        assertThat(FileTokenStore().read()?.accessToken).isEqualTo("AT-test")
    }

    @Test
    fun `revoke PUTs entitled false`() {
        server.enqueue(jsonResponse(200, """{"entitled":false}"""))

        val result = runCli("operator", "custom-domain", "revoke", "acme", "--hub-url", baseUrl(), "--json")

        assertThat(result.exit).isEqualTo(0)
        val request = server.takeRequest()
        assertThat(parseJson(request.body.readUtf8())).isEqualTo(mapOf("entitled" to false))
        assertThat(parseJson(result.out)).isEqualTo(mapOf("entitled" to false))
    }

    @Test
    fun `status GETs the custom domain and renders the hub's CustomDomainView`() {
        server.enqueue(jsonResponse(200, fixture("custom-domain-verified")))

        val result = runCli("operator", "custom-domain", "status", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        val request = server.takeRequest()
        assertThat(request.method).isEqualTo("GET")
        assertThat(request.path).isEqualTo("/admin/tenants/acme/custom-domain")
        assertThat(result.out).contains("auth.acme.com").contains("VERIFIED").contains("entitled")
            .contains("_thoryn-verify.auth.acme.com").contains("acme.auth.stg.thoryn.org")
    }

    @Test
    fun `status of a workspace with no domain is not an error`() {
        server.enqueue(problem(404, fixture("problem-no-domain")))

        val result = runCli("operator", "custom-domain", "status", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        assertThat(result.out).contains("Workspace 'acme' has no custom domain.")
    }

    @Test
    fun `404 from the operator gate names both an unknown workspace and missing standing`() {
        server.enqueue(problem(404, fixture("problem-no-standing")))

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("not_found")
            .contains("does not exist")
            .contains("no operator standing")
            .contains("productApi.operatorPlatformSubjects")
    }

    @Test
    fun `404 for an unknown workspace gets the same two-sided hint`() {
        server.enqueue(problem(404, fixture("problem-unknown-workspace")))

        val result = runCli("operator", "custom-domain", "entitle", "nosuch", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("Tenant not found: nosuch").contains("'nosuch' does not exist")
    }

    @Test
    fun `403 operator_passkey_required tells the operator to sign in again with a passkey`() {
        server.enqueue(problem(403, fixture("problem-passkey-required")))

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("operator_passkey_required").contains("thoryn operator login").contains("passkey")
    }

    @Test
    fun `bare 403 insufficient_scope names the missing operator scope`() {
        server.enqueue(
            MockResponse().setResponseCode(403).setHeader(
                "WWW-Authenticate",
                """Bearer error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token.", error_uri="https://tools.ietf.org/html/rfc6750#section-3.1"""",
            ),
        )

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl(), "--json")

        assertThat(result.exit).isEqualTo(2)
        val body = parseJson(result.out)
        assertThat(body["error"]).isEqualTo("insufficient_scope")
        assertThat(body["httpStatus"]).isEqualTo(403)
        assertThat(body["hint"] as String).contains("admin:custom-domains.manage").contains("V185")
    }

    @Test
    fun `status needs only the read scope in its hint`() {
        server.enqueue(MockResponse().setResponseCode(403).setHeader("WWW-Authenticate", """Bearer error="insufficient_scope""""))

        val result = runCli("operator", "custom-domain", "status", "acme", "--hub-url", baseUrl())

        assertThat(result.err).contains("admin:custom-domains.read")
    }

    @Test
    fun `401 asks for a fresh operator sign-in`() {
        server.enqueue(MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", """Bearer error="invalid_token""""))

        val result = runCli("operator", "custom-domain", "status", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("invalid_token").contains("thoryn operator login")
    }

    @Test
    fun `without an operator session nothing is sent, even with a customer session present`() {
        FileTokenStore(FileTokenStore.operatorPath()).delete()

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(1)
        assertThat(result.err).contains("Not signed in as an operator").contains("thoryn operator login")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `an expired operator session is refused locally`() {
        seedOperator(operatorTokens().copy(expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 5))

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(1)
        assertThat(result.err).contains("expired")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a public hub host is refused before any request is made`() {
        for (publicUrl in listOf("https://hub.stg.thoryn.org", "https://thoryn.auth.stg.thoryn.org", "http://10.0.0.5:8080")) {
            val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", publicUrl)

            assertThat(result.exit).isEqualTo(64)
            assertThat(result.err).contains("kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080")
        }
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `an unreachable hub prints the port-forward to start`() {
        val closedPort = ServerSocket(0).use { it.localPort }

        val result = runCli("operator", "custom-domain", "status", "acme", "--hub-url", "http://127.0.0.1:$closedPort")

        assertThat(result.exit).isEqualTo(3)
        assertThat(result.err).contains("not reachable at http://127.0.0.1:$closedPort")
            .contains("kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080")
    }

    @Test
    fun `a DPoP-bound operator token is presented under DPoP with a proof bound to the port-forward URL`() {
        val session = DpopSession(DpopKey.generate())
        seedOperator(operatorTokens().copy(tokenType = "DPoP"))
        OperatorCustomDomainCommand.clientFactory = { url, tokens -> OperatorHubClient(url, tokens, dpop = session) }
        server.enqueue(jsonResponse(200, """{"entitled":true}"""))

        val result = runCli("operator", "custom-domain", "entitle", "acme", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        val request = server.takeRequest()
        assertThat(request.getHeader("Authorization")).startsWith("DPoP ")
        val proof = JwtClaims.of(request.getHeader("DPoP"))
        assertThat(proof["htm"].asString()).isEqualTo("PUT")
        assertThat(proof["htu"].asString()).isEqualTo("${baseUrl()}/admin/tenants/acme/custom-domain/entitlement")
        assertThat(proof["ath"]).isNotNull()
    }

    @Test
    fun `operator help lists the subcommands and the passkey requirement`() {
        val root = runCli("operator", "--help")
        assertThat(root.exit).isEqualTo(0)
        assertThat(root.out).contains("login").contains("logout").contains("custom-domain")

        val login = runCli("operator", "login", "--help")
        assertThat(login.out).contains("PASSKEY").contains("thoryn-operator")

        val entitle = runCli("operator", "custom-domain", "entitle", "--help")
        assertThat(entitle.out).contains("--hub-url").contains("http://localhost:18080")
    }

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/operator/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, body: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(body)

    private fun seedOperator(tokens: Tokens) {
        FileTokenStore(FileTokenStore.operatorPath()).write(tokens)
    }

    companion object {
        /** A display-only JWT shaped like the hub's operator access token (passkey `amr`). */
        fun operatorJwt(amr: List<String> = listOf("swk", "webauthn")): String {
            val enc = Base64.getUrlEncoder().withoutPadding()
            val header = enc.encodeToString("""{"alg":"ES256","kid":"tenant-thoryn-v1"}""".toByteArray())
            val amrJson = amr.joinToString(",") { "\"$it\"" }
            val payload = enc.encodeToString(
                """{"sub":"op-subject-1","tnt":"thoryn","amr":[$amrJson],"scope":"openid admin:custom-domains.manage admin:custom-domains.read"}"""
                    .toByteArray(),
            )
            return "$header.$payload.c2ln"
        }

        fun operatorTokens(): Tokens = Tokens(
            accessToken = operatorJwt(),
            tokenType = "Bearer",
            expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 900,
            scope = "openid admin:custom-domains.manage admin:custom-domains.read",
            clientId = OperatorSession.CLIENT_ID,
            workspace = OperatorSession.HOME_WORKSPACE,
        )
    }
}
