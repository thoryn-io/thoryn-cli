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

    // ── SSO-4048 — name, page title, favicon and footer links (oauthy SSO-4044) ──

    private val viewWithName = """
        {"stored":{"primaryColor":"#2563eb","displayName":"Acme","pageTitle":"Sign in to Acme",
                   "faviconUrl":"https://cdn.example.com/favicon.ico","supportUrl":"mailto:help@example.com",
                   "termsUrl":"https://example.com/terms","privacyUrl":"https://example.com/privacy"},
         "effective":{"primaryColor":"#2563eb","backgroundColor":"#ffffff","borderRadiusPx":4,"theme":"auto",
                   "displayName":"Acme","pageTitle":"Sign in to Acme","faviconUrl":"https://cdn.example.com/favicon.ico",
                   "supportUrl":"mailto:help@example.com","termsUrl":"https://example.com/terms","privacyUrl":"https://example.com/privacy"},
         "updatedAt":"2026-10-29T10:00:00Z"}
    """.trimIndent()

    @Test
    fun `set of one colour keeps the stored name, title, favicon and footer links — the PUT replaces the record`() {
        server.enqueue(jsonResponse(200, viewWithName)) // GET (merge seed)
        server.enqueue(jsonResponse(200, viewWithName)) // PUT

        val (exit, _, _) = runCli("branding", "set", "--primary-color", "#111827", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // GET
        val body = server.takeRequest().body.readUtf8()
        assertThat(body).contains("\"primaryColor\":\"#111827\"")
        assertThat(body)
            .contains("\"displayName\":\"Acme\"")
            .contains("\"pageTitle\":\"Sign in to Acme\"")
            .contains("\"faviconUrl\":\"https://cdn.example.com/favicon.ico\"")
            .contains("\"supportUrl\":\"mailto:help@example.com\"")
            .contains("\"termsUrl\":\"https://example.com/terms\"")
            .contains("\"privacyUrl\":\"https://example.com/privacy\"")
    }

    @Test
    fun `set sends each new flag under its API name, and an empty value clears it`() {
        server.enqueue(jsonResponse(200, viewWithName)) // GET
        server.enqueue(jsonResponse(200, viewWithName)) // PUT

        val (exit, _, _) = runCli(
            "branding", "set",
            "--display-name", "Acme Corp", "--page-title", "Acme — sign in", "--favicon-url", "https://cdn.acme.example/f.ico",
            "--terms-url", "https://acme.example/tos", "--privacy-url", "https://acme.example/pp", "--support-url", "",
            "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // GET
        val body = server.takeRequest().body.readUtf8()
        assertThat(body)
            .contains("\"displayName\":\"Acme Corp\"")
            .contains("\"pageTitle\":\"Acme — sign in\"")
            .contains("\"faviconUrl\":\"https://cdn.acme.example/f.ico\"")
            .contains("\"termsUrl\":\"https://acme.example/tos\"")
            .contains("\"privacyUrl\":\"https://acme.example/pp\"")
            .contains("\"supportUrl\":null")
            .contains("\"primaryColor\":\"#2563eb\"") // the stored colour rides along
    }

    @Test
    fun `get prints the name, title, favicon and footer links and lists them as overrides`() {
        server.enqueue(jsonResponse(200, viewWithName))

        val (exit, out, _) = runCli("branding", "get", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("displayName").contains("Acme")
            .contains("pageTitle").contains("Sign in to Acme")
            .contains("faviconUrl").contains("https://cdn.example.com/favicon.ico")
            .contains("supportUrl").contains("mailto:help@example.com")
            .contains("termsUrl").contains("https://example.com/terms")
            .contains("privacyUrl").contains("https://example.com/privacy")
        assertThat(out.lines().single { it.trimStart().startsWith("overrides") })
            .contains("primaryColor, displayName, pageTitle, faviconUrl, supportUrl, termsUrl, privacyUrl")
    }

    @Test
    fun `set then get round-trips the six fields through the product API, and a value identity refuses comes back as its 400`() {
        server.dispatcher = com.devnow.thoryn.cli.cmd.provision.FakeProductApi()

        val (setExit, _, _) = runCli(
            "branding", "set", "--display-name", "Acme", "--page-title", "Sign in to Acme",
            "--favicon-url", "https://cdn.acme.example/favicon.ico", "--support-url", "mailto:help@acme.example",
            "--terms-url", "https://acme.example/terms", "--privacy-url", "https://acme.example/privacy",
            "--gateway", baseUrl(),
        )
        assertThat(setExit).isEqualTo(0)

        val (getExit, out, _) = runCli("branding", "get", "--output", "json", "--gateway", baseUrl())
        assertThat(getExit).isEqualTo(0)
        val stored = tools.jackson.databind.json.JsonMapper().readTree(out)["stored"]
        assertThat(listOf("displayName", "pageTitle", "faviconUrl", "supportUrl", "termsUrl", "privacyUrl").associateWith { stored[it].asString() })
            .isEqualTo(
                mapOf(
                    "displayName" to "Acme", "pageTitle" to "Sign in to Acme", "faviconUrl" to "https://cdn.acme.example/favicon.ico",
                    "supportUrl" to "mailto:help@acme.example", "termsUrl" to "https://acme.example/terms", "privacyUrl" to "https://acme.example/privacy",
                ),
            )

        // A colour change afterwards keeps all six (the merge seeds them) …
        val (themeExit, _, _) = runCli("branding", "set", "--theme", "dark", "--gateway", baseUrl())
        assertThat(themeExit).isEqualTo(0)
        val (_, afterOut, _) = runCli("branding", "get", "--output", "json", "--gateway", baseUrl())
        val after = tools.jackson.databind.json.JsonMapper().readTree(afterOut)["stored"]
        assertThat(after["displayName"].asString()).isEqualTo("Acme")
        assertThat(after["privacyUrl"].asString()).isEqualTo("https://acme.example/privacy")

        // … and an http favicon is identity's 400, surfaced as such.
        val (badExit, _, err) = runCli("branding", "set", "--favicon-url", "http://cdn.acme.example/favicon.ico", "--gateway", baseUrl())
        assertThat(badExit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("invalid_branding_field")
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
