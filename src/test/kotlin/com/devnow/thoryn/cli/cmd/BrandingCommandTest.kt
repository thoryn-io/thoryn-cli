package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3037 — unit tests for `thoryn branding ...` against a MockWebServer standing in for the
 * api-gateway → product-api `/api/v1/login-experience/branding` surface.
 *
 * `set` is a client-side MERGE over the server's full-replace PUT: it first GETs the stored
 * branding, seeds the body from it, overlays the supplied flags, then PUTs — so the first enqueued
 * response is the GET (stored), the second is the PUT (result).
 */
class BrandingCommandTest : CommandTestBase() {

    private val view = """
        {"stored":{"logoUrl":"https://cdn.example.com/logo.svg","primaryColor":"#2563eb",
                   "backgroundColor":null,"borderRadiusPx":8,"theme":"auto"},
         "effective":{"logoUrl":"https://cdn.example.com/logo.svg","primaryColor":"#2563eb",
                   "backgroundColor":"#ffffff","borderRadiusPx":8,"theme":"auto"},
         "updatedAt":"2026-09-12T10:00:00Z"}
    """.trimIndent()

    @Test
    fun `get renders the effective branding and the overridden fields`() {
        server.enqueue(jsonResponse(200, view))

        val (exit, out, _) = runCli("branding", "get", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("#2563eb").contains("logo.svg").contains("auto")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/login-experience/branding")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `set merges a single field over the stored branding (unspecified fields preserved)`() {
        server.enqueue(jsonResponse(200, view)) // GET (stored, for the merge seed)
        server.enqueue(jsonResponse(200, view)) // PUT (result)

        val (exit, _, _) = runCli(
            "branding", "set", "--primary-color", "#111827", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val get = server.takeRequest()
        assertThat(get.method).isEqualTo("GET")
        val put = server.takeRequest()
        assertThat(put.path).isEqualTo("/api/v1/login-experience/branding")
        assertThat(put.method).isEqualTo("PUT")
        val body = put.body.readUtf8()
        // the supplied field changed …
        assertThat(body).contains("\"primaryColor\":\"#111827\"")
        // … and the unspecified stored fields were preserved (merge, not replace).
        assertThat(body).contains("\"logoUrl\":\"https://cdn.example.com/logo.svg\"")
        assertThat(body).contains("\"borderRadiusPx\":8")
        assertThat(body).contains("\"theme\":\"auto\"")
    }

    @Test
    fun `set with an empty value clears that override`() {
        server.enqueue(jsonResponse(200, view)) // GET
        server.enqueue(jsonResponse(200, view)) // PUT

        val (exit, _, _) = runCli(
            "branding", "set", "--logo-url", "", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // GET
        val put = server.takeRequest()
        assertThat(put.method).isEqualTo("PUT")
        val body = put.body.readUtf8()
        // cleared → sent as null so the server drops the override …
        assertThat(body).contains("\"logoUrl\":null")
        // … while the other stored fields are preserved.
        assertThat(body).contains("\"primaryColor\":\"#2563eb\"")
    }

    @Test
    fun `set with no fields errors before any network call`() {
        val (exit, _, err) = runCli("branding", "set", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("at least one of")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `set --var merges CSS variables over the stored map and sends them in the body`() {
        // stored already has one --thoryn-* var; --var adds another + the merge preserves the first.
        val withVars = """
            {"stored":{"primaryColor":"#2563eb","cssVariables":{"--thoryn-text":"#111827"}},
             "effective":{"logoUrl":null,"primaryColor":"#2563eb","backgroundColor":"#ffffff",
                          "borderRadiusPx":4,"theme":"auto","cssVariables":{"--thoryn-text":"#111827"}},
             "updatedAt":"2026-09-12T10:00:00Z"}
        """.trimIndent()
        server.enqueue(jsonResponse(200, withVars)) // GET (merge seed)
        server.enqueue(jsonResponse(200, withVars)) // PUT

        val (exit, _, _) = runCli(
            "branding", "set", "--var", "--thoryn-accent=#7c3aed", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // GET
        val put = server.takeRequest()
        assertThat(put.method).isEqualTo("PUT")
        val body = put.body.readUtf8()
        // the new var is set AND the stored var is preserved (merge, full-replace-safe).
        assertThat(body).contains("\"cssVariables\"")
        assertThat(body).contains("\"--thoryn-accent\":\"#7c3aed\"")
        assertThat(body).contains("\"--thoryn-text\":\"#111827\"")
    }

    @Test
    fun `set surfaces an insufficient-scope error with the login hint`() {
        server.enqueue(jsonResponse(200, view)) // GET (merge seed) succeeds …
        server.enqueue( // … then the PUT is forbidden
            jsonResponse(
                403,
                """{"type":"about:blank","status":403,"title":"Forbidden","errorCode":"insufficient_scope","detail":"missing scope"}""",
            ),
        )

        val (exit, _, err) = runCli(
            "branding", "set", "--theme", "dark", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("tenant:idp.write")
    }

    @Test
    fun `get surfaces an insufficient-scope error with the login hint`() {
        server.enqueue(
            jsonResponse(
                403,
                """{"type":"about:blank","status":403,"title":"Forbidden","errorCode":"insufficient_scope","detail":"missing scope"}""",
            ),
        )

        val (exit, _, err) = runCli("branding", "get", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("tenant:idp.read")
    }
}
