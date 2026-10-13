package com.devnow.thoryn.cli.cmd

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.assertj.core.api.Assertions.assertThat
import java.nio.file.Files

/**
 * SSO-1553 — unit tests for `thoryn tenant seed` against a MockWebServer
 * standing in for the api-gateway → product-api customer plane.
 *
 * The seed is a thin orchestration over EXISTING endpoints
 * (`POST /tenants`, `POST /api/v1/applications`, `POST /federation-members`);
 * the assertions verify it calls them in order, captures minted client secrets
 * to files (never a pipe), and never puts a secret in any request as the CLI's
 * own argv. The upstream federation secret is supplied via the
 * `THORYN_FEDERATION_SECRET` system property (the no-argv CI knob), set on the
 * test JVM rather than passed on the command line.
 */
class TenantSeedCommandTest : CommandTestBase() {

    @AfterEach
    fun clearFederationSecretProperty() {
        System.clearProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV)
    }

    @Test
    fun `seed creates two clients and an identity-service federation member end-to-end`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret-from-env")
        // 2 client creates, then 1 federation create.
        server.enqueue(jsonResponse(201, """{"clientId":"seed-client-1","clientSecret":"sec-1","clientType":"confidential","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"seed-client-2","clientSecret":"sec-2","clientType":"confidential","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"fed-99","providerType":"oidc","displayName":"seed-identity-service"}"""))

        val secretDir = tempHome.resolve("secrets").toFile()

        val (exit, out, err) = runCli(
            "tenant", "seed",
            "--non-interactive",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)

        // Two client secrets landed in files, NOT in stdout.
        assertThat(Files.readString(secretDir.resolve("seed-client-1.secret").toPath()).trim()).isEqualTo("sec-1")
        assertThat(Files.readString(secretDir.resolve("seed-client-2.secret").toPath()).trim()).isEqualTo("sec-2")
        assertThat(out).doesNotContain("sec-1").doesNotContain("sec-2")

        val parsed = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val clients = parsed["clients"] as List<Map<String, Any?>>
        assertThat(clients).hasSize(2)
        assertThat(clients[0]["clientId"]).isEqualTo("seed-client-1")
        assertThat(parsed["federationMemberId"]).isEqualTo("fed-99")

        // Endpoint order + bodies.
        val client1 = server.takeRequest()
        assertThat(client1.path).isEqualTo("/api/v1/applications")
        assertThat(client1.method).isEqualTo("POST")
        val client1Body = client1.body.readUtf8()
        assertThat(client1Body).contains("\"displayName\":\"seed-client-1\"")
        // The CLI never sends a client secret — the hub mints it.
        assertThat(client1Body).doesNotContain("clientSecret")

        server.takeRequest() // client 2

        val fed = server.takeRequest()
        assertThat(fed.path).isEqualTo("/api/v1/federation-members")
        assertThat(fed.method).isEqualTo("POST")
        val fedBody = fed.body.readUtf8()
        assertThat(fedBody).contains("\"providerType\":\"oidc\"")
        // The federation secret IS sent in the body (it is an input to the
        // upstream IdP registration) — but it came from the env property, never
        // from argv.
        assertThat(fedBody).contains("\"clientSecret\":\"fed-secret-from-env\"")
    }

    @Test
    fun `seed registers the tenant in product-api when tenant-id and slug are supplied`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret")
        // tenant register, then 1 client, then federation.
        server.enqueue(jsonResponse(201, """{"tenantId":"t-7","slug":"acme"}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"seed-client-1","clientSecret":"sec-1","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"fed-1","providerType":"oidc"}"""))

        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, out, _) = runCli(
            "tenant", "seed",
            "--tenant-id", "t-7",
            "--slug", "acme",
            "--clients", "1",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["tenantRegistered"]).isEqualTo(true)

        val register = server.takeRequest()
        assertThat(register.path).isEqualTo("/api/v1/tenants")
        assertThat(register.method).isEqualTo("POST")
        assertThat(register.body.readUtf8()).contains("\"tenantId\":\"t-7\"").contains("\"slug\":\"acme\"")
    }

    @Test
    fun `seed with --skip-federation provisions clients only and needs no federation secret`() {
        // No federation secret property set, and no federation request enqueued.
        server.enqueue(jsonResponse(201, """{"clientId":"seed-client-1","clientSecret":"sec-1","status":"active"}"""))

        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, out, _) = runCli(
            "tenant", "seed",
            "--clients", "1",
            "--skip-federation",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["federationMemberId"]).isNull()

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications")
        // No second request was made (only one enqueued; the federation step was skipped).
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `seed without a federation secret in non-interactive mode fails fast before any mutation`() {
        // No FEDERATION_SECRET property, no --federation-secret-file, no TTY →
        // the secret cannot be obtained; the seed must abort BEFORE creating
        // any client (so we enqueue nothing and assert zero requests).
        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, _, err) = runCli(
            "tenant", "seed",
            "--non-interactive",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(err).contains("secret")
        // Nothing was provisioned — the secret is resolved up front.
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `seed requires --secret-dir when minting client secrets`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret")
        val (exit, _, err) = runCli(
            "tenant", "seed",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--secret-dir")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `seed rejects --tenant-id without --slug`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret")
        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, _, err) = runCli(
            "tenant", "seed",
            "--tenant-id", "t-7",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--tenant-id and --slug must be supplied together")
    }

    @Test
    fun `seed surfaces an insufficient-scope error on client creation with the write-scope hint`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret")
        server.enqueue(jsonResponse(403, """{"error":"insufficient_scope","error_description":"missing tenant:applications.write"}"""))

        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, _, err) = runCli(
            "tenant", "seed",
            "--clients", "1",
            "--skip-federation",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Run: oathy login --scope tenant:applications.write")
    }

    @Test
    fun `seed reads the federation secret from --federation-secret-file`() {
        val fedSecretFile = tempHome.resolve("fed.secret")
        Files.writeString(fedSecretFile, "secret-from-file\n")
        server.enqueue(jsonResponse(201, """{"id":"fed-1","providerType":"oidc"}"""))

        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, _, _) = runCli(
            "tenant", "seed",
            "--clients", "0",
            "--federation-secret-file", fedSecretFile.toString(),
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val fed = server.takeRequest()
        assertThat(fed.path).isEqualTo("/api/v1/federation-members")
        // The trailing newline is stripped by SecretIo.readSecretInput.
        assertThat(fed.body.readUtf8()).contains("\"clientSecret\":\"secret-from-file\"")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        System.setProperty(TenantCommand.SeedSubcommand.FEDERATION_SECRET_ENV, "fed-secret")
        clearTokens()
        val secretDir = tempHome.resolve("secrets").toFile()
        val (exit, _, err) = runCli(
            "tenant", "seed",
            "--skip-federation",
            "--secret-dir", secretDir.path,
            "--gateway", baseUrl(),
        )
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }
}
