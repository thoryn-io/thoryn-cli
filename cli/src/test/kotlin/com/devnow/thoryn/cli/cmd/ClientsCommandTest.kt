package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-1552 — unit tests for `thoryn clients ...` against a MockWebServer
 * standing in for the api-gateway → product-api `/api/v1/applications` surface.
 *
 * Secret-safety is the load-bearing assertion here:
 *  - `create` / `rotate-secret` never print the secret to a non-TTY stdout by
 *    default (the test JVM has no interactive console), and write it to a
 *    `--secret-file` when asked;
 *  - the secret never appears in the request body / URL (it is server-minted).
 */
class ClientsCommandTest : CommandTestBase() {

    @Test
    fun `list hits the applications surface and renders a table`() {
        server.enqueue(
            jsonResponse(
                200,
                """[
                  {"clientId":"app-1","displayName":"Checkout","clientType":"confidential","scopes":["openid"],"status":"active"},
                  {"clientId":"app-2","displayName":"Portal","clientType":"public","scopes":["openid","profile"],"status":"active"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("clients", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("app-1").contains("Checkout").contains("Portal")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `get fetches a single application by id`() {
        server.enqueue(jsonResponse(200, """{"clientId":"app-1","displayName":"Checkout","status":"active"}"""))

        val (exit, out, _) = runCli("clients", "get", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("app-1")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1")
        assertThat(req.method).isEqualTo("GET")
    }

    @Test
    fun `create POSTs the application body and writes the secret to a --secret-file`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"clientId":"app-9","clientSecret":"s3cr3t-once","displayName":"New App",
                    "redirectUris":["https://app.example.com/cb"],"scopes":["openid"],
                    "grantTypes":["authorization_code","refresh_token"],"status":"active",
                    "createdAt":"2026-06-09T10:00:00Z"}""".trimIndent(),
            ),
        )
        val secretFile = tempHome.resolve("secret.txt").toFile()

        val (exit, out, err) = runCli(
            "clients", "create",
            "--display-name", "New App",
            "--redirect-uri", "https://app.example.com/cb",
            "--scope", "openid",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        // The secret is written to the file, NOT to stdout.
        assertThat(Files.readString(secretFile.toPath()).trim()).isEqualTo("s3cr3t-once")
        assertThat(out).doesNotContain("s3cr3t-once")
        assertThat(err).contains("Client secret written to")
        assertThat(out).contains("app-9")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications")
        assertThat(req.method).isEqualTo("POST")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"displayName\":\"New App\"")
        assertThat(body).contains("https://app.example.com/cb")
        // The client never sends a secret — the hub mints it.
        assertThat(body).doesNotContain("clientSecret")
    }

    @Test
    fun `create refuses to print the secret to a non-interactive stdout without --force-stdout`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"clientId":"app-9","clientSecret":"leaky","displayName":"New App",
                    "redirectUris":["https://app.example.com/cb"],"status":"active",
                    "createdAt":"2026-06-09T10:00:00Z"}""".trimIndent(),
            ),
        )

        // No --secret-file and the test JVM has no TTY → the secret would be
        // headed for a pipe. The command must refuse and exit non-zero.
        val (exit, out, err) = runCli(
            "clients", "create",
            "--display-name", "New App",
            "--redirect-uri", "https://app.example.com/cb",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(out).doesNotContain("leaky")
        assertThat(err).contains("Refusing to print")
        assertThat(err).contains("--secret-file")
    }

    @Test
    fun `create with --force-stdout prints the secret with a warning`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"clientId":"app-9","clientSecret":"forced","displayName":"New App",
                    "redirectUris":["https://app.example.com/cb"],"status":"active",
                    "createdAt":"2026-06-09T10:00:00Z"}""".trimIndent(),
            ),
        )

        val (exit, out, err) = runCli(
            "clients", "create",
            "--display-name", "New App",
            "--redirect-uri", "https://app.example.com/cb",
            "--force-stdout",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("forced")
        assertThat(err).contains("WARNING").contains("shown ONCE")
    }

    @Test
    fun `update PATCHes only the supplied fields`() {
        server.enqueue(jsonResponse(200, """{"clientId":"app-1","displayName":"Renamed","status":"active"}"""))

        val (exit, _, _) = runCli(
            "clients", "update", "app-1",
            "--display-name", "Renamed",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1")
        assertThat(req.method).isEqualTo("PATCH")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"displayName\":\"Renamed\"")
        assertThat(body).doesNotContain("redirectUris")
    }

    @Test
    fun `update with no fields is a usage error`() {
        val (exit, _, err) = runCli("clients", "update", "app-1", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("at least one of")
    }

    @Test
    fun `rotate-secret writes the new secret to a file and shows the overlap window`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"newSecret":"rotated-once","newSecretId":"sid-2","previousSecretId":"sid-1",
                    "oldSecretExpiresAt":"2026-06-10T10:00:00Z"}""".trimIndent(),
            ),
        )
        val secretFile = tempHome.resolve("rotated.txt").toFile()

        val (exit, out, err) = runCli(
            "clients", "rotate-secret", "app-1",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(Files.readString(secretFile.toPath()).trim()).isEqualTo("rotated-once")
        assertThat(out).doesNotContain("rotated-once")
        assertThat(out).contains("oldSecretExpiresAt")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1/secret/rotate")
        assertThat(req.method).isEqualTo("POST")
    }

    @Test
    fun `rotate-secret surfaces a 409 rotation-in-flight error`() {
        server.enqueue(
            jsonResponse(
                409,
                """{"errorCode":"rotation_in_flight","detail":"A rotation is already in flight for this client."}""",
            ),
        )

        val (exit, _, err) = runCli("clients", "rotate-secret", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("rotation_in_flight")
    }

    @Test
    fun `delete sends DELETE and prints a confirmation`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("clients", "delete", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Deleted client 'app-1'")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1")
        assertThat(req.method).isEqualTo("DELETE")
    }

    // ── SSO-2413: production destructive-action confirmation (X-Thoryn-Confirm) ──

    @Test
    fun `delete with --confirm sends the X-Thoryn-Confirm header`() {
        server.enqueue(noContent())

        val (exit, _, _) = runCli("clients", "delete", "app-1", "--confirm", "acme-prod", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("acme-prod")
    }

    @Test
    fun `delete without --confirm sends no X-Thoryn-Confirm header (sandbox stays frictionless)`() {
        server.enqueue(noContent())

        val (exit, _, _) = runCli("clients", "delete", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.getHeader("X-Thoryn-Confirm")).isNull()
    }

    @Test
    fun `delete on a production workspace without --confirm surfaces the 428 guidance`() {
        server.enqueue(
            jsonResponse(
                428,
                """{"errorCode":"production_confirmation_required","title":"Production Confirmation Required",
                    "detail":"This action targets your production environment."}""".trimIndent(),
            ),
        )

        val (exit, _, err) = runCli("clients", "delete", "app-1", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("production workspace").contains("--confirm")
    }

    @Test
    fun `delete with a mismatched --confirm surfaces the 422 mismatch guidance`() {
        server.enqueue(
            jsonResponse(
                422,
                """{"errorCode":"production_confirmation_mismatch","title":"Production Confirmation Mismatch",
                    "detail":"The X-Thoryn-Confirm header does not match your workspace slug."}""".trimIndent(),
            ),
        )

        val (exit, _, err) = runCli("clients", "delete", "app-1", "--confirm", "wrong-slug", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("did not match")
        // The header was still sent — the server rejected the value, not its absence.
        assertThat(server.takeRequest().getHeader("X-Thoryn-Confirm")).isEqualTo("wrong-slug")
    }

    @Test
    fun `rotate-secret with --confirm sends the X-Thoryn-Confirm header`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"newSecret":"rotated-once","newSecretId":"sid-2","previousSecretId":"sid-1",
                    "oldSecretExpiresAt":"2026-06-10T10:00:00Z"}""".trimIndent(),
            ),
        )
        val secretFile = tempHome.resolve("rotated.txt").toFile()

        val (exit, _, _) = runCli(
            "clients", "rotate-secret", "app-1",
            "--confirm", "acme-prod",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications/app-1/secret/rotate")
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("acme-prod")
    }

    @Test
    fun `production-confirmation 428 in json output carries the errorCode and hint`() {
        server.enqueue(
            jsonResponse(428, """{"errorCode":"production_confirmation_required","detail":"prod"}"""),
        )

        val (exit, out, _) = runCli("clients", "delete", "app-1", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out).contains("production_confirmation_required")
        assertThat(out).contains("--confirm")
    }

    @Test
    fun `cross-tenant get returns the 404 not_found problem detail`() {
        server.enqueue(
            jsonResponse(404, """{"errorCode":"not_found","detail":"Application 'app-x' does not exist for this tenant."}"""),
        )

        val (exit, _, err) = runCli("clients", "get", "app-x", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not_found")
    }

    @Test
    fun `insufficient-scope on create prints the write-scope hint`() {
        server.enqueue(
            jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:applications.write"}"""),
        )

        val (exit, _, err) = runCli(
            "clients", "create",
            "--display-name", "X",
            "--redirect-uri", "https://x/cb",
            "--secret-file", tempHome.resolve("s.txt").toString(),
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Run: oathy login --scope tenant:applications.write")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, err) = runCli("clients", "list", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }
}
