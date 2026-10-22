package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3856 — `thoryn operator platform-scopes get | grant | revoke | plan | apply` against a MockWebServer standing in
 * for the hub's `OperatorPlatformClientController` behind `kubectl port-forward` (oathy ADR
 * `2026-10-19-operator-grants-platform-client-scopes.md`). [FakeHub] keeps each home-workspace client's `platform:`
 * scopes and answers exactly like the hub: `200 { clientId, workspace, environment, platformScopes, changed }`,
 * idempotent writes, `404 client_not_found`, `409 machine_client_required`, and a bare 403 when the token lacks the
 * scope.
 */
class OperatorPlatformScopesCommandTest : CommandTestBase() {

    private val hub = FakeHub()

    @BeforeEach
    fun mount() {
        FileTokenStore(FileTokenStore.operatorPath()).write(operatorTokens())
        server.dispatcher = hub
    }

    // ── one at a time ──

    @Test
    fun `get reads the client's platform scopes with the operator token`() {
        hub.clients["provisioning-m2m"] = mutableListOf("platform:trusted-issuers.read")

        val result = runCli("operator", "platform-scopes", "get", "provisioning-m2m", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        val request = hub.requests.single()
        assertThat(request.method).isEqualTo("GET")
        assertThat(request.path).isEqualTo("/admin/platform-clients/provisioning-m2m/scopes")
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer ${operatorTokens().accessToken}")
        assertThat(result.out).contains("platform:trusted-issuers.read").contains("thoryn").contains("production")
    }

    @Test
    fun `grant PUTs the scope as a raw path segment with the reason and ticket for the audit row`() {
        hub.clients["provisioning-m2m"] = mutableListOf()

        val result = runCli(
            "operator", "platform-scopes", "grant", "provisioning-m2m", "platform:trusted-issuers.read",
            "--reason", "reads the issuer registry", "--ticket", "SSO-3857", "--hub-url", baseUrl(),
        )

        assertThat(result.exit).isEqualTo(0)
        val request = hub.requests.single()
        assertThat(request.method).isEqualTo("PUT")
        assertThat(request.path).isEqualTo("/admin/platform-clients/provisioning-m2m/scopes/platform:trusted-issuers.read")
        assertThat(request.body).isEqualTo(mapOf("reason" to "reads the issuer registry", "ticket" to "SSO-3857"))
        assertThat(result.out).contains("Granted platform:trusted-issuers.read to 'provisioning-m2m'")
        assertThat(hub.clients["provisioning-m2m"]).containsExactly("platform:trusted-issuers.read")
    }

    @Test
    fun `revoke DELETEs the scope and sends no body when there is no reason or ticket`() {
        hub.clients["provisioning-m2m"] = mutableListOf("platform:audit-events.append")

        val result = runCli("operator", "platform-scopes", "revoke", "provisioning-m2m", "platform:audit-events.append", "--hub-url", baseUrl(), "--json")

        assertThat(result.exit).isEqualTo(0)
        val request = hub.requests.single()
        assertThat(request.method).isEqualTo("DELETE")
        assertThat(request.path).isEqualTo("/admin/platform-clients/provisioning-m2m/scopes/platform:audit-events.append")
        assertThat(request.rawBody).isEmpty()
        assertThat(parseJson(result.out)).containsEntry("changed", true).containsEntry("platformScopes", emptyList<String>())
    }

    @Test
    fun `a non-platform scope is refused locally and nothing is sent`() {
        val result = runCli("operator", "platform-scopes", "grant", "provisioning-m2m", "tenant:applications.write", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(64)
        assertThat(result.err).contains("not a platform: scope")
        assertThat(hub.requests).isEmpty()
    }

    // ── declarative ──

    @Test
    fun `apply grants what is missing, revokes what is extra, leaves the rest, and stamps the file's ticket`() {
        hub.clients["provisioning-m2m"] = mutableListOf("platform:audit-events.append", "platform:github-installations.sync")
        hub.clients["other-m2m"] = mutableListOf("platform:trusted-issuers.read")
        val file = declaration(
            """
            apiVersion: thoryn.io/platform-scopes/v1
            ticket: SSO-3857
            clients:
              - clientId: provisioning-m2m
                scopes: [platform:trusted-issuers.read, platform:audit-events.append]
              - clientId: other-m2m
                scopes: [platform:trusted-issuers.read]
            """,
        )

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        assertThat(hub.clients["provisioning-m2m"]).containsExactlyInAnyOrder("platform:trusted-issuers.read", "platform:audit-events.append")
        assertThat(hub.clients["other-m2m"]).containsExactly("platform:trusted-issuers.read")
        val writes = hub.requests.filter { it.method != "GET" }
        assertThat(writes.map { "${it.method} ${it.path}" }).containsExactly(
            "PUT /admin/platform-clients/provisioning-m2m/scopes/platform:trusted-issuers.read",
            "DELETE /admin/platform-clients/provisioning-m2m/scopes/platform:github-installations.sync",
        )
        assertThat(writes).allSatisfy { assertThat(it.body).isEqualTo(mapOf("ticket" to "SSO-3857")) }
        // The plan is printed BEFORE any write: every GET precedes the first PUT.
        assertThat(hub.requests.take(2).map { it.method }).containsOnly("GET")
        assertThat(result.out)
            .contains("~ provisioning-m2m").contains("+ platform:trusted-issuers.read").contains("- platform:github-installations.sync")
            .contains("= other-m2m: unchanged")
            .contains("Applied: 1 granted, 1 revoked, 1 client(s) unchanged.")
    }

    @Test
    fun `applying the same file again changes nothing`() {
        hub.clients["provisioning-m2m"] = mutableListOf()
        val file = declaration(
            """
            apiVersion: thoryn.io/platform-scopes/v1
            clients:
              - clientId: provisioning-m2m
                scopes: [platform:trusted-issuers.read]
            """,
        )
        assertThat(runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl()).exit).isEqualTo(0)
        hub.requests.clear()

        val again = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(again.exit).isEqualTo(0)
        assertThat(hub.requests.map { it.method }).containsOnly("GET")
        assertThat(again.out).contains("No changes.")
    }

    @Test
    fun `plan and apply --dry-run read but never write`() {
        hub.clients["provisioning-m2m"] = mutableListOf("platform:github-installations.sync")
        val file = declaration(
            """
            apiVersion: thoryn.io/platform-scopes/v1
            clients:
              - clientId: provisioning-m2m
                scopes: [platform:trusted-issuers.read]
            """,
        )

        val plan = runCli("operator", "platform-scopes", "plan", "-f", file, "--hub-url", baseUrl())
        val dry = runCli("operator", "platform-scopes", "apply", "-f", file, "--dry-run", "--hub-url", baseUrl(), "--json")

        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("+ platform:trusted-issuers.read").contains("- platform:github-installations.sync").contains("Nothing was changed (dry run)")
        assertThat(dry.exit).isEqualTo(0)
        val body = parseJson(dry.out)
        assertThat(body["dryRun"]).isEqualTo(true)
        @Suppress("UNCHECKED_CAST")
        val client = (body["clients"] as List<Map<String, Any?>>).single()
        assertThat(client["grant"]).isEqualTo(listOf("platform:trusted-issuers.read"))
        assertThat(client["revoke"]).isEqualTo(listOf("platform:github-installations.sync"))
        assertThat(hub.requests.map { it.method }).containsOnly("GET")
        assertThat(hub.clients["provisioning-m2m"]).containsExactly("platform:github-installations.sync")
    }

    @Test
    fun `scopes empty list removes every platform scope from the client`() {
        hub.clients["provisioning-m2m"] = mutableListOf("platform:trusted-issuers.read", "platform:audit-events.append")
        val file = declaration("apiVersion: thoryn.io/platform-scopes/v1\nclients:\n  - clientId: provisioning-m2m\n    scopes: []\n")

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(0)
        assertThat(hub.clients["provisioning-m2m"]).isEmpty()
    }

    @Test
    fun `an unknown client stops the run before anything is written`() {
        hub.clients["provisioning-m2m"] = mutableListOf()
        val file = declaration(
            """
            apiVersion: thoryn.io/platform-scopes/v1
            clients:
              - clientId: provisioning-m2m
                scopes: [platform:trusted-issuers.read]
              - clientId: nosuch
                scopes: [platform:trusted-issuers.read]
            """,
        )

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("client_not_found").contains("'nosuch'").contains("PRODUCTION plane")
        assertThat(hub.requests.map { it.method }).containsOnly("GET")
        assertThat(hub.clients["provisioning-m2m"]).isEmpty()
    }

    @Test
    fun `a refusal mid-apply stops and says re-running finishes the rest`() {
        hub.clients["provisioning-m2m"] = mutableListOf()
        hub.humanClients += "provisioning-m2m"
        val file = declaration("apiVersion: thoryn.io/platform-scopes/v1\nclients:\n  - clientId: provisioning-m2m\n    scopes: [platform:trusted-issuers.read]\n")

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("machine_client_required").contains("client_credentials").contains("re-running the same file")
    }

    @Test
    fun `a token without the platform-scopes capability is told how to sign in for it`() {
        hub.denyScope = true
        val file = declaration("apiVersion: thoryn.io/platform-scopes/v1\nclients:\n  - clientId: provisioning-m2m\n    scopes: []\n")

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(2)
        assertThat(result.err).contains("admin:clients.platform-scopes")
            .contains("thoryn operator login --scope \"openid admin:clients.platform-scopes\"").contains("V207")
    }

    @Test
    fun `an invalid file is refused with every reason and nothing is sent`() {
        val file = declaration(
            """
            apiVersion: thoryn.io/platform-scopes/v2
            clients:
              - clientId: a
                scopes: [tenant:applications.read, platform:trusted-issuers.read, platform:trusted-issuers.read]
              - clientId: a
                scopes: [platform:x]
                workspace: acme
            """,
        )

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(64)
        assertThat(result.err).contains("apiVersion must be 'thoryn.io/platform-scopes/v1'")
            .contains("'tenant:applications.read' is not a platform: scope")
            .contains("lists 'platform:trusted-issuers.read' twice")
            .contains("'a' is declared twice")
            .contains("workspace is not a known field")
            .contains("'platform:x' is not a valid scope name")
        assertThat(hub.requests).isEmpty()
    }

    @Test
    fun `a public hub host is refused before the file is applied`() {
        val file = declaration("apiVersion: thoryn.io/platform-scopes/v1\nclients:\n  - clientId: a\n    scopes: []\n")

        val result = runCli("operator", "platform-scopes", "apply", "-f", file, "--hub-url", "https://thoryn.auth.stg.thoryn.org")

        assertThat(result.exit).isEqualTo(64)
        assertThat(result.err).contains("kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080")
        assertThat(hub.requests).isEmpty()
    }

    @Test
    fun `without an operator session nothing is sent`() {
        FileTokenStore(FileTokenStore.operatorPath()).delete()

        val result = runCli("operator", "platform-scopes", "get", "provisioning-m2m", "--hub-url", baseUrl())

        assertThat(result.exit).isEqualTo(1)
        assertThat(result.err).contains("Not signed in as an operator")
        assertThat(hub.requests).isEmpty()
    }

    @Test
    fun `operator help lists platform-scopes`() {
        assertThat(runCli("operator", "--help").out).contains("platform-scopes")
        assertThat(runCli("operator", "platform-scopes", "apply", "--help").out).contains("--dry-run").contains("platform-scopes.yaml")
    }

    private fun declaration(yaml: String): String {
        val path: Path = tempHome.resolve("platform-scopes-${System.nanoTime()}.yaml")
        Files.writeString(path, yaml.trimIndent() + "\n")
        return path.toString()
    }

    /** One recorded call: what the hub saw. */
    data class Call(val method: String, val path: String, val rawBody: String, val body: Map<String, Any?>?, private val headers: okhttp3.Headers) {
        fun getHeader(name: String): String? = headers[name]
    }

    /** The hub's platform-client surface, in memory. */
    class FakeHub : Dispatcher() {
        val clients = linkedMapOf<String, MutableList<String>>()
        val humanClients = mutableSetOf<String>()
        val requests: MutableList<Call> = java.util.Collections.synchronizedList(mutableListOf())
        var denyScope = false
        private val mapper = JsonMapper.builder().build()

        override fun dispatch(request: RecordedRequest): MockResponse {
            val raw = request.body.readUtf8()
            @Suppress("UNCHECKED_CAST")
            val body = raw.takeIf { it.isNotBlank() }?.let { mapper.readValue(it, Map::class.java) as Map<String, Any?> }
            val path = request.path.orEmpty()
            requests += Call(request.method.orEmpty(), path, raw, body, request.headers)
            if (denyScope) {
                return MockResponse().setResponseCode(403).setHeader("WWW-Authenticate", """Bearer error="insufficient_scope"""")
            }
            val m = Regex("^/admin/platform-clients/([^/]+)/scopes(?:/([^/]+))?$").find(path)
                ?: return problem(404, "not_found")
            val clientId = m.groupValues[1]
            val scope = m.groupValues[2].ifEmpty { null }
            val held = clients[clientId] ?: return problem(404, "client_not_found")
            val changed = when (request.method) {
                "GET" -> false
                "PUT" -> {
                    if (clientId in humanClients) return problem(409, "machine_client_required")
                    if (scope!! in held) false else held.add(scope)
                }
                "DELETE" -> held.remove(scope)
                else -> return problem(405, "method_not_allowed")
            }
            val view = mapOf("clientId" to clientId, "workspace" to "thoryn", "environment" to "production", "platformScopes" to held.toList(), "changed" to changed)
            return MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(mapper.writeValueAsString(view))
        }

        private fun problem(status: Int, code: String): MockResponse =
            MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json")
                .setBody(mapper.writeValueAsString(mapOf("type" to "about:blank", "status" to status, "detail" to "refused", "errorCode" to code)))
    }

    companion object {
        fun operatorTokens(): Tokens = OperatorCustomDomainCommandTest.operatorTokens().copy(
            scope = "openid ${OperatorSession.SCOPE_CLIENTS_PLATFORM_SCOPES}",
        )
    }
}
