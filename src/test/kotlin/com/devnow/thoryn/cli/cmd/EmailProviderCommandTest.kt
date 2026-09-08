package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2917 — unit tests for `thoryn workspace email-provider ...` against a MockWebServer standing in
 * for the api-gateway → product-api `/api/v1/email-provider` surface (PR #3448).
 *
 * Secret-safety is on the INPUT side: the SMTP password is read from a `--smtp-password-file` (or a
 * no-echo prompt), NEVER from an argv flag — there is deliberately no `--smtp-password <value>` option.
 * The response never carries a password back (only `hasPassword`), so nothing secret is ever emitted.
 */
class EmailProviderCommandTest : CommandTestBase() {

    private val readView = """
        {"providerType":"byo_smtp","enabled":true,"configured":true,
         "smtpHost":"smtp.example.com","smtpPort":587,"smtpUsername":"mailer",
         "hasPassword":true,"transportSecurity":"starttls",
         "fromAddress":"[email protected]","fromName":"ACME","replyTo":null,
         "supportedProviderTypes":["byo_smtp"],"supportedTransportSecurity":["none","starttls","tls"],
         "configVersion":3,"updatedAt":"2026-09-01T10:00:00Z"}
    """.trimIndent()

    @Test
    fun `get renders the provider config and never a password`() {
        server.enqueue(jsonResponse(200, readView))

        val (exit, out, _) = runCli("workspace", "email-provider", "get", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("byo_smtp").contains("smtp.example.com").contains("hasPassword")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/email-provider")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `set reads the password from --smtp-password-file and PUTs a merge-upsert body`() {
        server.enqueue(jsonResponse(200, readView))
        val pwFile = tempHome.resolve("smtp-pw.txt").toFile()
        pwFile.writeText("s3cr3t-smtp\n")

        val (exit, out, _) = runCli(
            "workspace", "email-provider", "set",
            "--enabled", "true",
            "--smtp-host", "smtp.example.com",
            "--smtp-port", "587",
            "--smtp-username", "mailer",
            "--transport-security", "starttls",
            "--from-address", "[email protected]",
            "--smtp-password-file", pwFile.path,
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        // The response carries no password; nothing secret is emitted.
        assertThat(out).doesNotContain("s3cr3t-smtp")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/email-provider")
        assertThat(req.method).isEqualTo("PUT")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"smtpHost\":\"smtp.example.com\"")
        assertThat(body).contains("\"smtpPort\":587")
        assertThat(body).contains("\"enabled\":true")
        // The password IS sent (an input the operator supplies) — but it came from the file, never argv.
        assertThat(body).contains("\"smtpPassword\":\"s3cr3t-smtp\"")
        // Merge-upsert: fields NOT supplied are absent from the body (not sent as null).
        assertThat(body).doesNotContain("replyTo")
        assertThat(body).doesNotContain("fromName")
    }

    @Test
    fun `set with transport-security none requires --allow-insecure and errors before any call`() {
        val (exit, _, err) = runCli(
            "workspace", "email-provider", "set",
            "--transport-security", "none",
            "--enabled", "false",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--allow-insecure")
        // The guard fires before the network call — nothing was sent.
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `set with transport-security none and --allow-insecure PUTs the acknowledgement`() {
        server.enqueue(jsonResponse(200, readView))

        val (exit, _, _) = runCli(
            "workspace", "email-provider", "set",
            "--transport-security", "none",
            "--allow-insecure",
            "--enabled", "false",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("PUT")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"transportSecurity\":\"none\"")
        assertThat(body).contains("\"allowInsecureTransport\":true")
    }

    @Test
    fun `set rejects more than one password source`() {
        val pwFile = tempHome.resolve("smtp-pw.txt").toFile()
        pwFile.writeText("x\n")

        val (exit, _, err) = runCli(
            "workspace", "email-provider", "set",
            "--smtp-password-file", pwFile.path,
            "--clear-password",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("at most one of")
    }

    @Test
    fun `verify renders success and exits 0`() {
        server.enqueue(jsonResponse(200, """{"success":true,"reason":null,"outcome":"ok"}"""))

        val (exit, out, _) = runCli("workspace", "email-provider", "verify", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("OK").contains("ok")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/email-provider/verify")
        assertThat(req.method).isEqualTo("POST")
        // A connect-only check sends no recipient.
        assertThat(req.body.readUtf8()).doesNotContain("\"to\"")
    }

    @Test
    fun `verify with --to sends the recipient and a failing check exits non-zero`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"success":false,"reason":"The SMTP server rejected the configured credentials (authentication failed).","outcome":"auth_failed"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "workspace", "email-provider", "verify", "--to", "admin@example.com", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(out).contains("FAILED").contains("authentication failed").contains("auth_failed")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.body.readUtf8()).contains("\"to\":\"admin@example.com\"")
    }

    @Test
    fun `verify surfaces an insufficient-scope error with the login hint`() {
        server.enqueue(
            jsonResponse(
                403,
                """{"type":"about:blank","status":403,"title":"Forbidden","errorCode":"insufficient_scope","detail":"missing scope"}""",
            ),
        )

        val (exit, _, err) = runCli("workspace", "email-provider", "verify", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("tenant:email.write")
    }

    @Test
    fun `reset DELETEs the provider config`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("workspace", "email-provider", "reset", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("reset")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/email-provider")
        assertThat(req.method).isEqualTo("DELETE")
    }

    @Test
    fun `set surfaces an insufficient-scope error with the login hint`() {
        server.enqueue(
            jsonResponse(
                403,
                """{"type":"about:blank","status":403,"title":"Forbidden","errorCode":"insufficient_scope","detail":"missing scope"}""",
            ),
        )

        val (exit, _, err) = runCli(
            "workspace", "email-provider", "set",
            "--enabled", "false",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("tenant:email.write")
    }
}
