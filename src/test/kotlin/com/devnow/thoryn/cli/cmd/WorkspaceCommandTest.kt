package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-1552 — unit tests for `thoryn workspace ...`.
 *
 * The workspace surface lives on the hub (`/account/workspace[s]`), so `--hub`
 * is pointed at the MockWebServer. `create` additionally registers the tenant in
 * product-api (`POST /tenants`); with `--hub` and `--gateway` both pointed at the
 * same MockWebServer, two requests are enqueued.
 */
class WorkspaceCommandTest : CommandTestBase() {

    @Test
    fun `list hits the hub account-workspaces surface`() {
        server.enqueue(
            jsonResponse(
                200,
                """[
                  {"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/oauth2/authorization/hub-acme"},
                  {"tenantId":"t-2","slug":"globex","displayName":"Globex","archived":true,"loginUrl":"/oauth2/authorization/hub-globex"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("workspace", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("acme").contains("Globex")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/account/workspaces")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `create posts to the hub then registers the tenant in product-api`() {
        // Step 1: hub workspace create.
        server.enqueue(
            jsonResponse(
                201,
                """{"tenantId":"t-9","slug":"newco","displayName":"NewCo","archived":false,"loginUrl":"/oauth2/authorization/hub-newco"}""",
            ),
        )
        // Step 2: product-api POST /tenants.
        server.enqueue(jsonResponse(201, """{"tenantId":"t-9","slug":"newco"}"""))

        val (exit, out, _) = runCli(
            "workspace", "create",
            "--slug", "newco",
            "--display-name", "NewCo",
            "--hub", baseUrl(),
            "--gateway", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("newco")
        assertThat(parseJson(out)["productApiRegistered"]).isEqualTo(true)

        val hubReq = server.takeRequest()
        assertThat(hubReq.path).isEqualTo("/account/workspace")
        assertThat(hubReq.method).isEqualTo("POST")
        assertThat(hubReq.body.readUtf8()).contains("\"slug\":\"newco\"").contains("\"displayName\":\"NewCo\"")

        val registerReq = server.takeRequest()
        assertThat(registerReq.path).isEqualTo("/api/v1/tenants")
        assertThat(registerReq.method).isEqualTo("POST")
        assertThat(registerReq.body.readUtf8()).contains("\"tenantId\":\"t-9\"").contains("\"slug\":\"newco\"")
    }

    @Test
    fun `create reports a product-api registration failure as a warning but still succeeds`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"tenantId":"t-9","slug":"newco","displayName":"NewCo","archived":false,"loginUrl":"/x"}""",
            ),
        )
        // product-api registration fails.
        server.enqueue(jsonResponse(502, """{"errorCode":"hub_unavailable","detail":"upstream down"}"""))

        val (exit, _, err) = runCli(
            "workspace", "create",
            "--slug", "newco",
            "--display-name", "NewCo",
            "--hub", baseUrl(),
            "--gateway", baseUrl(),
        )

        // The hub workspace exists; registration is idempotent on retry, so this
        // is a warning, not a hard failure.
        assertThat(exit).isEqualTo(0)
        assertThat(err).contains("product-api registration failed")
        assertThat(err).contains("idempotent")
    }

    @Test
    fun `switch silently exchanges the current token for the target tenant and records the selection`() {
        // 1) workspace-list validation call.
        server.enqueue(
            jsonResponse(
                200,
                """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]""",
            ),
        )
        // 2) SSO-2818 token-exchange response — the hub mints a target-tenant token.
        server.enqueue(
            jsonResponse(
                200,
                """{"access_token":"acme-tenant-token","token_type":"Bearer","expires_in":900,"scope":"openid tenant:applications.read"}""",
            ),
        )

        val expectedIssuer = WorkspaceTenantHost.tenantIssuer(baseUrl(), "acme")
        val (exit, out, _) = runCli(
            "workspace", "switch", "acme",
            "--hub", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        val parsed = parseJson(out)
        assertThat(parsed["switched"]).isEqualTo("acme")
        assertThat(parsed["tenantHubIssuer"]).isEqualTo(expectedIssuer)

        // The second request is the RFC 8693 token exchange naming the target tenant.
        server.takeRequest() // list
        val exchange = server.takeRequest()
        val body = exchange.body.readUtf8()
        assertThat(body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
        assertThat(body).contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token")
        assertThat(body).contains("resource=")

        // The selection is persisted next to the token store (@TempDir home).
        val workspaceFile = tempHome.resolve(".config/thoryn/workspace.json")
        assertThat(Files.exists(workspaceFile)).isTrue()
        assertThat(Files.readString(workspaceFile)).contains("acme")

        // The exchanged token becomes the active bearer.
        val tokenFile = tempHome.resolve(".config/thoryn/tokens.json")
        assertThat(Files.readString(tokenFile)).contains("acme-tenant-token")
    }

    @Test
    fun `WorkspaceTenantHost prefixes the slug as a subdomain preserving scheme and port`() {
        assertThat(WorkspaceTenantHost.tenantIssuer("https://hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.hub.stg.thoryn.org")
        assertThat(WorkspaceTenantHost.tenantIssuer("http://localhost:54702", "acme"))
            .isEqualTo("http://acme.localhost:54702")
        // Trailing slash on the base is tolerated.
        assertThat(WorkspaceTenantHost.tenantIssuer("https://hub.example.com/", "globex"))
            .isEqualTo("https://globex.hub.example.com")
    }

    // ---- SSO-2831: archive / reactivate ------------------------------------

    @Test
    fun `archive with a matching confirm archives the workspace and sends the confirm header`() {
        server.enqueue(jsonResponse(200, """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]"""))
        server.enqueue(jsonResponse(200, """{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":true,"loginUrl":"/x"}"""))

        val (exit, out, _) = runCli("workspace", "archive", "acme", "--confirm", "acme", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["archived"]).isEqualTo(true)
        server.takeRequest() // the workspace-list lookup
        val archiveReq = server.takeRequest()
        assertThat(archiveReq.path).endsWith("/account/workspace/t-1/archive")
        assertThat(archiveReq.getHeader("X-Thoryn-Confirm")).isEqualTo("acme")
    }

    @Test
    fun `archive without confirm surfaces the name-confirmation hint (428)`() {
        server.enqueue(jsonResponse(200, """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]"""))
        server.enqueue(jsonResponse(428, """{"errorCode":"workspace_confirmation_required","detail":"confirmation required"}"""))

        val (exit, _, err) = runCli("workspace", "archive", "acme", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("thoryn workspace archive acme --confirm acme")
    }

    @Test
    fun `reactivate clears the archive flag`() {
        server.enqueue(jsonResponse(200, """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":true,"loginUrl":"/x"}]"""))
        server.enqueue(jsonResponse(200, """{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}"""))

        val (exit, out, _) = runCli("workspace", "reactivate", "acme", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["archived"]).isEqualTo(false)
    }

    @Test
    fun `archive of an unknown slug reports not-found`() {
        server.enqueue(jsonResponse(200, """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]"""))
        val (exit, _, err) = runCli("workspace", "archive", "nope", "--confirm", "nope", "--hub", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("No workspace with slug 'nope'")
    }

    @Test
    fun `switch to an unknown slug reports an error`() {
        server.enqueue(
            jsonResponse(
                200,
                """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]""",
            ),
        )
        val (exit, _, err) = runCli(
            "workspace", "switch", "nope",
            "--hub", baseUrl(),
        )
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("no workspace with slug 'nope'")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, err) = runCli("workspace", "list", "--hub", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }
}
