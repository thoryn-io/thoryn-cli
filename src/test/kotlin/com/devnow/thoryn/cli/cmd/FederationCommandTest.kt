package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-1552 — unit tests for `thoryn federation ...` against a MockWebServer
 * standing in for the api-gateway → product-api `/federation-members` surface.
 *
 * Secret-safety here is on the INPUT side: the member `clientSecret` is read
 * from a `--secret-file` (or no-echo prompt), NEVER from an argv flag — there is
 * deliberately no `--client-secret` option, and passing one is an unknown-option
 * error.
 */
class FederationCommandTest : CommandTestBase() {

    @Test
    fun `list renders the members table`() {
        server.enqueue(
            jsonResponse(
                200,
                """[
                  {"id":"11111111-1111-1111-1111-111111111111","providerType":"oidc","displayName":"Identity Service","discoveryUrl":"https://id.example.com/.well-known/openid-configuration","clientId":"hub-client"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("federation", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("oidc").contains("Identity Service")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/federation-members")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `create reads the secret from --secret-file and POSTs the oidc member`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"id":"11111111-1111-1111-1111-111111111111","providerType":"oidc",
                    "displayName":"Identity Service","discoveryUrl":"https://id.example.com/.well-known/openid-configuration",
                    "clientId":"hub-client","providerConfig":{},"claimMapping":{},
                    "createdAt":"2026-06-09T10:00:00Z","updatedAt":"2026-06-09T10:00:00Z","version":1}""".trimIndent(),
            ),
        )
        val secretFile = tempHome.resolve("fed-secret.txt").toFile()
        secretFile.writeText("upstream-secret\n")

        val (exit, out, _) = runCli(
            "federation", "create",
            "--provider-type", "oidc",
            "--display-name", "Identity Service",
            "--discovery-url", "https://id.example.com/.well-known/openid-configuration",
            "--client-id", "hub-client",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Identity Service")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/federation-members")
        assertThat(req.method).isEqualTo("POST")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"providerType\":\"oidc\"")
        assertThat(body).contains("\"discoveryUrl\":\"https://id.example.com/.well-known/openid-configuration\"")
        // The secret IS sent (it's an input the operator supplies) — but it came
        // from the file, never from argv.
        assertThat(body).contains("\"clientSecret\":\"upstream-secret\"")
    }

    @Test
    fun `create passes provider-config and claim-mapping key=value pairs`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"id":"22222222-2222-2222-2222-222222222222","providerType":"okta",
                    "displayName":"Okta","discoveryUrl":"https://x.okta.com/.well-known/openid-configuration",
                    "clientId":"c","providerConfig":{"orgUrl":"https://x.okta.com"},"claimMapping":{},
                    "createdAt":"2026-06-09T10:00:00Z","updatedAt":"2026-06-09T10:00:00Z","version":1}""".trimIndent(),
            ),
        )
        val secretFile = tempHome.resolve("okta-secret.txt").toFile()
        secretFile.writeText("okta-secret")

        val (exit, _, _) = runCli(
            "federation", "create",
            "--provider-type", "okta",
            "--display-name", "Okta",
            "--discovery-url", "https://x.okta.com/.well-known/openid-configuration",
            "--client-id", "c",
            "--secret-file", secretFile.path,
            "--provider-config", "orgUrl=https://x.okta.com",
            "--claim-mapping", "email=mail",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val body = server.takeRequest().body.readUtf8()
        assertThat(body).contains("\"orgUrl\":\"https://x.okta.com\"")
        assertThat(body).contains("\"email\":\"mail\"")
    }

    @Test
    fun `there is no --client-secret flag — passing one is rejected`() {
        // Secret-safety contract: a secret must never be accepted on the command
        // line. picocli rejects the unknown option with a non-zero exit and no
        // request is made.
        val (exit, _, err) = runCli(
            "federation", "create",
            "--provider-type", "oidc",
            "--display-name", "X",
            "--discovery-url", "https://id.example.com/.well-known/openid-configuration",
            "--client-id", "c",
            "--client-secret", "should-not-exist",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isNotEqualTo(0)
        assertThat(err).contains("--client-secret")
    }

    @Test
    fun `create with no --secret-file and no TTY fails cleanly instead of leaking a prompt`() {
        // The test JVM has no interactive console, so without --secret-file the
        // command cannot obtain the secret safely; it must exit EXIT_NO_SECRET
        // (and never reach the server).
        val (exit, _, err) = runCli(
            "federation", "create",
            "--provider-type", "oidc",
            "--display-name", "X",
            "--discovery-url", "https://id.example.com/.well-known/openid-configuration",
            "--client-id", "c",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(err).contains("no interactive terminal")
        assertThat(err).contains("--secret-file")
    }

    @Test
    fun `delete sends DELETE on the member id`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli(
            "federation", "delete", "11111111-1111-1111-1111-111111111111",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Deleted federation member")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/federation-members/11111111-1111-1111-1111-111111111111")
        assertThat(req.method).isEqualTo("DELETE")
    }

    // ── SSO-2413: production destructive-action confirmation (X-Thoryn-Confirm) ──

    @Test
    fun `delete with --confirm sends the X-Thoryn-Confirm header`() {
        server.enqueue(noContent())

        val (exit, _, _) = runCli(
            "federation", "delete", "11111111-1111-1111-1111-111111111111",
            "--confirm", "acme-prod",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("DELETE")
        assertThat(req.getHeader("X-Thoryn-Confirm")).isEqualTo("acme-prod")
    }

    @Test
    fun `delete without --confirm sends no X-Thoryn-Confirm header`() {
        server.enqueue(noContent())

        val (exit, _, _) = runCli(
            "federation", "delete", "11111111-1111-1111-1111-111111111111",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().getHeader("X-Thoryn-Confirm")).isNull()
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

        val (exit, _, err) = runCli(
            "federation", "delete", "11111111-1111-1111-1111-111111111111",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("production workspace").contains("--confirm")
    }

    @Test
    fun `cross-tenant delete returns the 404 problem detail`() {
        server.enqueue(
            jsonResponse(404, """{"errorCode":"not_found","detail":"Federation member 'x' does not exist for this tenant."}"""),
        )
        val (exit, _, err) = runCli(
            "federation", "delete", "33333333-3333-3333-3333-333333333333",
            "--gateway", baseUrl(),
        )
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not_found")
    }

    @Test
    fun `insufficient-scope on create prints the federation write-scope hint`() {
        server.enqueue(
            jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:federation.write"}"""),
        )
        val secretFile = tempHome.resolve("s.txt").toFile()
        secretFile.writeText("x")

        val (exit, _, err) = runCli(
            "federation", "create",
            "--provider-type", "oidc",
            "--display-name", "X",
            "--discovery-url", "https://id.example.com/.well-known/openid-configuration",
            "--client-id", "c",
            "--secret-file", secretFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Run: oathy login --scope tenant:federation.write")
    }
}
