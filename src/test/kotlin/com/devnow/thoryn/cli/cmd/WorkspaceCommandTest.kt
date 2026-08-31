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
    fun `switch records the selection and prints the re-auth command`() {
        server.enqueue(
            jsonResponse(
                200,
                """[{"tenantId":"t-1","slug":"acme","displayName":"Acme","archived":false,"loginUrl":"/x"}]""",
            ),
        )

        // --hub points at the MockWebServer so the validation list-call is served
        // locally; the derived tenant issuer is whatever WorkspaceTenantHost
        // computes from that base URL (host prefixed with the slug).
        val expectedIssuer = WorkspaceTenantHost.tenantIssuer(baseUrl(), "acme")
        val (exit, out, _) = runCli(
            "workspace", "switch", "acme",
            "--hub", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        val parsed = parseJson(out)
        assertThat(parsed["selected"]).isEqualTo("acme")
        assertThat(parsed["tenantHubIssuer"]).isEqualTo(expectedIssuer)
        assertThat(parsed["reauthCommand"]).isEqualTo("thoryn login --issuer $expectedIssuer")

        // The selection is persisted next to the token store (user.home is the
        // @TempDir from CommandTestBase, so the store lands under .config/thoryn).
        val workspaceFile = tempHome.resolve(".config/thoryn/workspace.json")
        assertThat(Files.exists(workspaceFile)).isTrue()
        assertThat(Files.readString(workspaceFile)).contains("acme")
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
