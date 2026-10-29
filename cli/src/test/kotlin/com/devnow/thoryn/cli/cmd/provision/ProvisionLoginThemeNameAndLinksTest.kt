package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-4048 — oauthy SSO-4044 grew the branding record by six fields: the workspace's `displayName`, an explicit browser
 * `pageTitle`, the `faviconUrl` and the footer links `supportUrl` / `termsUrl` / `privacyUrl`. `kind: loginTheme` is the WHOLE
 * record (SSO-4041), so the six join it: the loader refuses what identity refuses (`LoginBrandingAdminService.validate`), the
 * plan shows an undeclared stored one as cleared, the apply PUTs all twelve fields, and import renders them.
 */
class ProvisionLoginThemeNameAndLinksTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun file(resources: String) =
        ProvisionFile.parse(("apiVersion: thoryn.io/tenant/v1\nresources:\n" + resources.trimIndent().prependIndent("  ")).toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    /** A single-field loginTheme spec, as the loader sees it (no YAML quoting games: the value is a JSON string). */
    private fun spec(field: String, value: String) = file("- { kind: loginTheme, spec: { $field: ${tools.jackson.databind.json.JsonMapper().writeValueAsString(value)} } }")

    private fun refusal(field: String, value: String): String? =
        runCatching { spec(field, value) }.exceptionOrNull()?.let { (it as ProvisionException).message }

    // ── each rule, accepted and refused, before any call ─────────────────────

    @Test
    fun `displayName and pageTitle accept plain text up to 80 and 120 characters and a blank value`() {
        listOf(
            "displayName" to "Acme & Söhne — \"Login\"",
            "displayName" to "a".repeat(80),
            "displayName" to "  ${"a".repeat(80)}  ", // identity trims before it counts
            "displayName" to "",
            "pageTitle" to "b".repeat(120),
            "pageTitle" to "   ",
        ).forEach { (field, value) -> assertThat(refusal(field, value)).describedAs("$field=[$value]").isNull() }
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `displayName and pageTitle refuse an over-long value, angle brackets and control characters`() {
        assertThat(refusal("displayName", "a".repeat(81))).contains("spec.displayName exceeds the 80-character limit")
        assertThat(refusal("pageTitle", "b".repeat(121))).contains("spec.pageTitle exceeds the 120-character limit")
        assertThat(refusal("displayName", "<b>Acme</b>")).contains("spec.displayName must be plain text: no '<', '>' or control characters")
        assertThat(refusal("displayName", "Acme >")).contains("spec.displayName must be plain text")
        assertThat(refusal("pageTitle", "Sign in\tto Acme")).contains("spec.pageTitle must be plain text")
        // A C1 control (U+009F) is a control too — written as a YAML escape, the only way a file can carry one.
        assertThat(runCatching { file("- { kind: loginTheme, spec: { pageTitle: \"Sign in\\u009FAcme\" } }") }.exceptionOrNull())
            .hasMessageContaining("spec.pageTitle must be plain text")
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `the favicon, terms and privacy links accept https in any case up to 2000 characters, and the support link also mailto`() {
        val long = "https://cdn.acme.example/" + "x".repeat(2000 - "https://cdn.acme.example/".length)
        listOf(
            "faviconUrl" to "https://cdn.acme.example/favicon.ico",
            "faviconUrl" to long,
            "termsUrl" to "HTTPS://acme.example/terms",
            "privacyUrl" to "https://acme.example/privacy",
            "privacyUrl" to "",
            "supportUrl" to "https://acme.example/help",
            "supportUrl" to "mailto:help@acme.example",
            "supportUrl" to "MAILTO:help@acme.example",
        ).forEach { (field, value) -> assertThat(refusal(field, value)).describedAs("$field=[$value]").isNull() }
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `the links refuse another scheme, a bare scheme, whitespace, an over-long URL, and mailto anywhere but the support link`() {
        val long = "https://cdn.acme.example/" + "x".repeat(2001 - "https://cdn.acme.example/".length)
        assertThat(refusal("faviconUrl", "http://cdn.acme.example/favicon.ico")).contains("spec.faviconUrl must be an https:// URL without whitespace")
        assertThat(refusal("faviconUrl", long)).contains("spec.faviconUrl exceeds the 2000-character limit")
        assertThat(refusal("termsUrl", "https://")).contains("spec.termsUrl must be an https:// URL")
        assertThat(refusal("termsUrl", "https://acme.example/terms of use")).contains("spec.termsUrl must be an https:// URL without whitespace")
        assertThat(refusal("privacyUrl", "mailto:privacy@acme.example")).contains("spec.privacyUrl must be an https:// URL")
        assertThat(refusal("supportUrl", "ftp://acme.example/help")).contains("spec.supportUrl must be an https:// URL or a mailto: address without whitespace")
        assertThat(refusal("supportUrl", "mailto:")).contains("spec.supportUrl must be an https:// URL or a mailto: address")
        assertThat(refusal("supportUrl", "javascript:alert(1)")).contains("spec.supportUrl must be an https:// URL or a mailto: address")
        assertThat(api.requests).isEmpty()
    }

    // ── the plan and the apply see the whole record ──────────────────────────

    @Test
    fun `a stored displayName the file does not declare is planned as cleared, and apply sends all twelve fields`() {
        api.branding[null] = mutableMapOf("primaryColor" to "#0f62fe", "displayName" to "Acme", "supportUrl" to "mailto:help@acme.example")
        val f = file("""
            - kind: loginTheme
              spec:
                primaryColor: "#0f62fe"
                supportUrl: mailto:help@acme.example
                pageTitle: Sign in to Acme
                faviconUrl: https://cdn.acme.example/favicon.ico
                termsUrl: https://acme.example/terms
                privacyUrl: https://acme.example/privacy
        """)

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff.keys).containsExactlyInAnyOrder("displayName", "pageTitle", "faviconUrl", "termsUrl", "privacyUrl")
        assertThat(change.diff["displayName"]).isEqualTo("Acme → (cleared — the file does not declare it; the platform default applies)")
        assertThat(change.diff["pageTitle"]).isEqualTo("(unset) → Sign in to Acme")

        apply(f)
        val put = api.writes.single()
        assertThat(put.method + " " + put.path).isEqualTo("PUT /api/v1/login-experience/branding")
        assertThat(put.body).isEqualTo(
            ProvisionFile.LOGIN_THEME_SPEC_KEYS.associateWith { null as Any? } + mapOf(
                "primaryColor" to "#0f62fe",
                "pageTitle" to "Sign in to Acme",
                "faviconUrl" to "https://cdn.acme.example/favicon.ico",
                "supportUrl" to "mailto:help@acme.example",
                "termsUrl" to "https://acme.example/terms",
                "privacyUrl" to "https://acme.example/privacy",
            ),
        )
        assertThat(put.body.keys).containsExactlyElementsOf(ProvisionFile.LOGIN_THEME_SPEC_KEYS)
        assertThat(api.branding[null]!!).doesNotContainKey("displayName")
        assertThat(console.toString()).contains("cleared: logoUrl, backgroundColor, borderRadiusPx, theme, cssVariables, displayName")

        // Converged: no diff, no write.
        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a declared value is compared trimmed, as identity stores it — not a change`() {
        api.branding[null] = mutableMapOf("displayName" to "Acme", "termsUrl" to "https://acme.example/terms")
        val f = file("""
            - kind: loginTheme
              spec: { displayName: "  Acme  ", termsUrl: "https://acme.example/terms " }
        """)
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    // ── import round-trips ───────────────────────────────────────────────────

    @Test
    fun `import renders the name, title, favicon and footer links, and the imported entry plans as a no-op`() {
        val stored = mapOf(
            "theme" to "dark",
            "displayName" to "Acme",
            "pageTitle" to "Sign in to Acme",
            "faviconUrl" to "https://cdn.acme.example/favicon.ico",
            "supportUrl" to "mailto:help@acme.example",
            "termsUrl" to "https://acme.example/terms",
            "privacyUrl" to "https://acme.example/privacy",
        )
        api.branding[null] = stored.toMutableMap()
        val imported = engine().import(existing = null).resources.single { it.resource.kind == "loginTheme" }
        assertThat(imported.resource.spec).isEqualTo(stored)

        val yaml = tools.jackson.dataformat.yaml.YAMLMapper().writeValueAsString(mapOf("apiVersion" to "thoryn.io/tenant/v1", "resources" to listOf(imported.toEntry())))
        val f = ProvisionFile.parse(yaml.toByteArray(), "imported.yaml")
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `an unknown key next to the new fields is still refused — the record is closed`() {
        assertThatThrownBy { file("- { kind: loginTheme, spec: { displayname: Acme } }") }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("spec.displayname is not a branding field")
    }
}
