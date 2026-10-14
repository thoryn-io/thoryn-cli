package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-3683 — `thoryn clients registration-token`, the CLI verb for the Dynamic Client Registration
 * Initial Access Token mint (`POST /api/v1/applications/registration-tokens`).
 *
 * The token is a credential (it creates a client), so the SecretIo contract applies exactly as it
 * does to a client secret: the token reaches ONLY the `--out-file` (owner-only) or an interactive
 * TTY; it never reaches stdout in a pipeline, never the request body, never the JSON record.
 */
class ClientsRegistrationTokenCommandTest : CommandTestBase() {

    private val minted = """{"initialAccessToken":"IAT-ONCE-${"x".repeat(16)}",
        "expiresAt":"2026-10-14T12:00:00Z",
        "registrationEndpoint":"https://acme.auth.thoryn.io/staging/oauth2/register"}""".trimIndent()

    @Test
    fun `mints with --software-id and --ttl, writes the token to --out-file only, prints endpoint and expiry`() {
        server.enqueue(jsonResponse(201, minted))
        val outFile = tempHome.resolve("iat.txt").toFile()

        val (exit, out, err) = runCli(
            "clients", "registration-token",
            "--software-id", "com.vendor.crm",
            "--ttl", "900",
            "--out-file", outFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        // The token lands in the file — and ONLY there.
        assertThat(Files.readString(outFile.toPath()).trim()).isEqualTo("IAT-ONCE-xxxxxxxxxxxxxxxx")
        assertThat(out).doesNotContain("IAT-ONCE")
        assertThat(err).doesNotContain("IAT-ONCE")
        assertThat(err).contains("Initial access token written to")
        if (outFile.toPath().fileSystem.supportedFileAttributeViews().contains("posix")) {
            assertThat(Files.getPosixFilePermissions(outFile.toPath()))
                .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        }
        // The vendor's two other values print normally.
        assertThat(out).contains("https://acme.auth.thoryn.io/staging/oauth2/register")
        assertThat(out).contains("2026-10-14T12:00:00Z")

        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/applications/registration-tokens")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"ttlSeconds\":900")
        assertThat(body).contains("\"softwareId\":\"com.vendor.crm\"")
    }

    @Test
    fun `without flags the body carries neither ttlSeconds nor softwareId (server defaults apply)`() {
        server.enqueue(jsonResponse(201, minted))

        val (exit, _, _) = runCli(
            "clients", "registration-token",
            "--out-file", tempHome.resolve("iat.txt").toString(),
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val body = server.takeRequest().body.readUtf8()
        assertThat(body).doesNotContain("ttlSeconds").doesNotContain("softwareId")
    }

    @Test
    fun `refuses to print the token to a non-interactive stdout without --out-file or --force-stdout`() {
        server.enqueue(jsonResponse(201, minted))

        val (exit, out, err) = runCli("clients", "registration-token", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(out).doesNotContain("IAT-ONCE")
        assertThat(err).contains("Refusing to print")
        // The non-secret record still printed, so the operator sees the endpoint even on refusal.
        assertThat(out).contains("https://acme.auth.thoryn.io/staging/oauth2/register")
    }

    @Test
    fun `--force-stdout prints the token with the shown-once warning`() {
        server.enqueue(jsonResponse(201, minted))

        val (exit, out, err) = runCli("clients", "registration-token", "--force-stdout", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("IAT-ONCE-xxxxxxxxxxxxxxxx")
        assertThat(err).contains("WARNING").contains("shown ONCE")
    }

    @Test
    fun `--output json strips the token from the record`() {
        server.enqueue(jsonResponse(201, minted))
        val outFile = tempHome.resolve("iat.txt").toFile()

        val (exit, out, _) = runCli(
            "clients", "registration-token",
            "--out-file", outFile.path, "--output", "json", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json).doesNotContainKey("initialAccessToken")
        assertThat(json["registrationEndpoint"]).isEqualTo("https://acme.auth.thoryn.io/staging/oauth2/register")
        assertThat(json["expiresAt"]).isEqualTo("2026-10-14T12:00:00Z")
        assertThat(out).doesNotContain("IAT-ONCE")
    }

    @Test
    fun `--secret-file is accepted as an alias of --out-file`() {
        server.enqueue(jsonResponse(201, minted))
        val outFile = tempHome.resolve("alias.txt").toFile()

        val (exit, _, _) = runCli("clients", "registration-token", "--secret-file", outFile.path, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(Files.readString(outFile.toPath()).trim()).isEqualTo("IAT-ONCE-xxxxxxxxxxxxxxxx")
    }

    @Test
    fun `--ttl above one hour is a usage error before any request is sent`() {
        val (exit, _, err) = runCli("clients", "registration-token", "--ttl", "7200", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--ttl").contains("3600")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `insufficient scope prints the applications write login hint`() {
        server.enqueue(
            jsonResponse(
                403,
                """{"type":"about:blank","title":"Forbidden","status":403,"errorCode":"insufficient_scope","detail":"insufficient scope"}""",
            ).setHeader("WWW-Authenticate", """Bearer error="insufficient_scope""""),
        )

        val (exit, _, err) = runCli(
            "clients", "registration-token",
            "--out-file", tempHome.resolve("iat.txt").toString(), "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("tenant:applications.write")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, _) = runCli("clients", "registration-token", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
    }
}
