package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2870 — `thoryn env ...` against a MockWebServer standing in for the api-gateway → product-api
 * `/api/v1/environments` surface (and the hub `/oauth2/token` exchange for the `use` persistence path).
 *
 * The management verbs run WITHOUT a selected workspace, so `gatewayClient` uses the base token
 * directly (one request each). `use` requires a selected workspace and exercises the token exchange
 * plus the local persistence of the chosen environment.
 */
class EnvironmentCommandTest : CommandTestBase() {

    private val envId = "11111111-1111-1111-1111-111111111111"

    @Test
    fun `list renders the environments table and marks the active one`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"environments":[
                     {"id":"$envId","slug":"production","name":"Production","kind":"production","suspended":false},
                     {"id":"22222222-2222-2222-2222-222222222222","slug":"staging","name":"Staging","kind":"sandbox","suspended":false}
                   ]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("env", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("production").contains("staging").contains("sandbox")
        // With no explicit selection the CLI resolves to the production plane → production marked active.
        assertThat(out.lines().first { it.contains("production") }).contains("*")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/environments")
        assertThat(req.method).isEqualTo("GET")
    }

    @Test
    fun `create POSTs the slug and name`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":false,"createdAt":"2026-09-05T10:00:00Z"}""",
            ),
        )

        val (exit, out, _) = runCli("env", "create", "staging", "--name", "Staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("staging")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/environments")
        assertThat(req.method).isEqualTo("POST")
        val body = parseJson(req.body.readUtf8())
        assertThat(body["slug"]).isEqualTo("staging")
        assertThat(body["name"]).isEqualTo("Staging")
    }

    @Test
    fun `rename resolves the slug to an id then PATCHes`() {
        // 1) list (slug → id), 2) the rename.
        server.enqueue(jsonResponse(200, """{"environments":[{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":false}]}"""))
        server.enqueue(jsonResponse(200, """{"id":"$envId","slug":"staging","name":"Renamed","kind":"sandbox","suspended":false}"""))

        val (exit, _, _) = runCli("env", "rename", "staging", "--name", "Renamed", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/environments")
        val patch = server.takeRequest()
        assertThat(patch.method).isEqualTo("PATCH")
        assertThat(patch.path).isEqualTo("/api/v1/environments/$envId")
        assertThat(parseJson(patch.body.readUtf8())["name"]).isEqualTo("Renamed")
    }

    @Test
    fun `suspend resolves the slug then POSTs the suspend action`() {
        server.enqueue(jsonResponse(200, """{"environments":[{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":false}]}"""))
        server.enqueue(jsonResponse(200, """{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":true,"suspendedAt":"2026-09-05T10:00:00Z"}"""))

        val (exit, _, _) = runCli("env", "suspend", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // list
        val suspend = server.takeRequest()
        assertThat(suspend.method).isEqualTo("POST")
        assertThat(suspend.path).isEqualTo("/api/v1/environments/$envId/suspend")
    }

    @Test
    fun `use validates the slug against the live list and persists the selection`() {
        // A selected workspace is required; base token needs an issuer so the exchange has a hub.
        val base = Tokens(accessToken = "AT-test", refreshToken = "RT-test", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        SelectedWorkspaceStore().write(
            SelectedWorkspace(tenantId = "t-1", slug = "acme", tenantHubIssuer = "https://acme.hub.example.org"),
        )
        // gatewayClient(applyEnvironment=false) still exchanges (a workspace is selected): exchange, then list.
        server.enqueue(jsonResponse(200, """{"access_token":"switched-token","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(jsonResponse(200, """{"environments":[{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":false}]}"""))

        val (exit, out, _) = runCli("env", "use", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("staging")
        // The selection is now persisted on the workspace record.
        assertThat(SelectedWorkspaceStore().read()?.environmentSlug).isEqualTo("staging")
    }

    @Test
    fun `use without a selected workspace fails with guidance`() {
        val (exit, _, err) = runCli("env", "use", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("workspace switch")
    }
}
