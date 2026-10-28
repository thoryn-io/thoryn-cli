package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.PlannedChange
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPlan
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-4041 — `kind: loginTheme` is the WHOLE branding record. `PUT /api/v1/login-experience/branding` replaces the stored
 * record (identity's `LoginBrandingAdminService.upsert`: an omitted field clears the stored value; `cssVariables` is one map),
 * so the plan diffs the whole record — a stored field the file does not declare is shown as cleared — and the apply PUTs the
 * full record with an explicit `null` for every undeclared field. Before this the plan diffed only the declared keys while the
 * apply replaced everything: a file setting `primaryColor` planned "1 change" and silently cleared the live logo.
 *
 * The spec grammar is identity's, checked before any call (a typo like `primaryColour` used to be dropped by the API's
 * lenient binding and so CLEAR the field it meant to set). `destroy` / `--prune` keep ADR 2026-10-15 §1 (a production-plane
 * singleton is left in place, reported with the reset a person runs); a planned removal is the PUT of the empty record (the
 * API has no DELETE).
 *
 * Every assertion here was watched failing against the pre-fix behaviour (the per-declared-key diff, the partial PUT, the
 * merging fake, the unchecked spec) before it was trusted.
 */
class ProvisionLoginThemeTest : CommandTestBase() {

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

    /** The record as the PUT writes it: every field present, `null` for what the file does not declare. */
    private fun fullRecord(vararg declared: Pair<String, Any?>): Map<String, Any?> =
        linkedMapOf<String, Any?>("logoUrl" to null, "primaryColor" to null, "backgroundColor" to null, "borderRadiusPx" to null, "theme" to null, "cssVariables" to null) + declared

    // ── the plan is honest about the PUT ─────────────────────────────────────

    @Test
    fun `a stored field the file does not declare is planned as cleared, and apply PUTs the full record so the logo really goes`() {
        api.branding[null] = mutableMapOf("logoUrl" to "https://cdn.acme.com/logo.svg", "primaryColor" to "#0f62fe")
        val f = file("""
            - kind: loginTheme
              spec: { primaryColor: "#ff0000" }
        """)

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        // Before SSO-4041 this diff was exactly ["primaryColor"]: the logo was cleared without a word.
        assertThat(change.diff.keys).containsExactlyInAnyOrder("primaryColor", "logoUrl")
        assertThat(change.diff["primaryColor"]).isEqualTo("#0f62fe → #ff0000")
        assertThat(change.diff["logoUrl"]).startsWith("https://cdn.acme.com/logo.svg → (cleared")
        assertThat(change.reason).contains("2 field(s) differ")

        apply(f)
        val put = api.writes.single()
        assertThat(put.method + " " + put.path).isEqualTo("PUT /api/v1/login-experience/branding")
        // The body IS the record: an explicit null for every field the file does not declare, nothing left to omission.
        assertThat(put.body).isEqualTo(fullRecord("primaryColor" to "#ff0000"))
        assertThat(api.branding[null]).isEqualTo(mapOf("primaryColor" to "#ff0000"))
        assertThat(console.toString()).contains("~ loginTheme:").contains("cleared: logoUrl")

        // Converged: the file is the record now — no diff, no write.
        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a file that declares exactly the stored record is a no-op`() {
        api.branding[null] = mutableMapOf("logoUrl" to "https://cdn.acme.com/logo.svg", "primaryColor" to "#0f62fe", "borderRadiusPx" to 8, "theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed"))
        val f = file("""
            - kind: loginTheme
              spec:
                logoUrl: https://cdn.acme.com/logo.svg
                primaryColor: "#0F62FE"          # identity stores colours lower-cased: the same colour, not a change
                borderRadiusPx: 8
                theme: dark
                cssVariables: { --thoryn-accent: "#7c3aed" }
        """)
        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.diff).isEmpty()
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `cssVariables is replaced as ONE map — a token the file omits is cleared with the rest, as the PUT does it`() {
        api.branding[null] = mutableMapOf("theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed", "--thoryn-text" to "#111827"))
        val f = file("""
            - kind: loginTheme
              spec:
                theme: dark
                cssVariables: { --thoryn-accent: "#7c3aed" }
        """)
        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff.keys).containsExactly("cssVariables")
        assertThat(change.diff["cssVariables"]).isEqualTo("{--thoryn-accent=#7c3aed,--thoryn-text=#111827} → {--thoryn-accent=#7c3aed}")

        apply(f)
        assertThat(api.writes.single().body).isEqualTo(fullRecord("theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed")))
        assertThat(api.branding[null]).isEqualTo(mapOf("theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed")))
    }

    @Test
    fun `an empty spec declares the platform defaults — every stored field is cleared, and with nothing stored it is a no-op that is never re-PUT`() {
        api.branding[null] = mutableMapOf("theme" to "light", "borderRadiusPx" to 8)
        val f = file("""
            - kind: loginTheme
              spec: {}
        """)
        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff.keys).containsExactlyInAnyOrder("theme", "borderRadiusPx")
        assertThat(change.diff.values).allMatch { it.contains("(cleared") }

        apply(f)
        assertThat(api.writes.single().body).isEqualTo(fullRecord())
        assertThat(api.branding[null]).isNull()

        // Nothing stored and nothing declared: the platform default is in effect — a no-op, not a create on every apply.
        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `nothing stored and a declared record is a create that PUTs the full record`() {
        val f = file("""
            - kind: loginTheme
              spec: { primaryColor: "#0f62fe", theme: light }
        """)
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.CREATE)
        apply(f)
        assertThat(api.writes.single().body).isEqualTo(fullRecord("primaryColor" to "#0f62fe", "theme" to "light"))
    }

    // ── the spec is checked before any call ─────────────────────────────────

    @Test
    fun `a typo in a field name, a non-hex colour, an http logo, an out-of-range radius, an unknown theme and an unknown CSS variable are refused before any call`() {
        assertThatThrownBy {
            file("""
                - kind: loginTheme
                  name: typo
                  spec: { primaryColour: "#0f62fe" }
                - kind: loginTheme
                  name: colour
                  spec: { primaryColor: "blue", backgroundColor: "#12345" }
                - kind: loginTheme
                  name: logo
                  spec: { logoUrl: "http://cdn.acme.com/logo.svg" }
                - kind: loginTheme
                  name: radius
                  spec: { borderRadiusPx: 65 }
                - kind: loginTheme
                  name: theme
                  spec: { theme: sepia }
                - kind: loginTheme
                  name: css
                  spec: { cssVariables: { --thoryn-brand: "#7c3aed", --thoryn-text: "red", --thoryn-font-family: "Inter; url(x)" } }
            """)
        }.isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("resources[0] (loginTheme) spec.primaryColour is not a branding field")
            .hasMessageContaining("a typo here clears the field it was meant to set")
            .hasMessageContaining("resources[1] (loginTheme) spec.primaryColor 'blue' is not a CSS hex colour")
            .hasMessageContaining("resources[1] (loginTheme) spec.backgroundColor '#12345' is not a CSS hex colour")
            .hasMessageContaining("resources[2] (loginTheme) spec.logoUrl must be an https:// URL")
            .hasMessageContaining("resources[3] (loginTheme) spec.borderRadiusPx 65 must be between 0 and 64")
            .hasMessageContaining("resources[4] (loginTheme) spec.theme 'sepia' must be one of light, dark, auto")
            .hasMessageContaining("resources[5] (loginTheme) spec.cssVariables.--thoryn-brand is not a supported CSS variable")
            .hasMessageContaining("resources[5] (loginTheme) spec.cssVariables.--thoryn-text 'red' is not a CSS hex colour")
            .hasMessageContaining("resources[5] (loginTheme) spec.cssVariables.--thoryn-font-family 'Inter; url(x)' is not a plain font-family stack")
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `a value carrying an env placeholder is left to the API, and the whole valid record parses`() {
        val f = file("""
            - kind: loginTheme
              spec:
                logoUrl: "{{env.BRAND_LOGO_URL}}"
                primaryColor: "#0f62fe"
                backgroundColor: "#fff"
                borderRadiusPx: 0
                theme: auto
                cssVariables: { --thoryn-accent: "#7c3aed", --thoryn-text: "#111827", --thoryn-muted: "#666", --thoryn-font-family: "Inter, sans-serif" }
        """)
        assertThat(f.resources.single().spec.keys).containsExactlyInAnyOrderElementsOf(ProvisionFile.LOGIN_THEME_SPEC_KEYS)
    }

    // ── destroy / --prune ────────────────────────────────────────────────────

    @Test
    fun `destroy leaves a production-plane theme in place naming the reset by hand, goes with a sandbox, and a planned removal PUTs the empty record`() {
        api.branding[null] = mutableMapOf("primaryColor" to "#0f62fe")
        val production = file("""
            - kind: loginTheme
              spec: { primaryColor: "#0f62fe" }
        """)
        // SSO-3715 (ADR 2026-10-15 §1): a non-ownable kind on the production plane is never removed by destroy — the row says
        // what a person runs, and that is the PUT of the empty record (the API has no DELETE).
        val plan = engine().planDestroy(production)
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.SKIP)
        assertThat(row.reason).contains("PRODUCTION plane").contains("never removed by destroy / --prune")
        assertThat(row.byHand).startsWith("PUT /api/v1/login-experience/branding {} (the API has no DELETE; the empty record restores the platform defaults")
        engine().destroy(plan, "acme")
        assertThat(api.writes).isEmpty()
        assertThat(api.branding[null]).isEqualTo(mapOf("primaryColor" to "#0f62fe"))

        // In a sandbox the theme goes WITH the sandbox (the environment hard-delete cascades; no call of its own).
        api.reset()
        api.seedEnvironment("ci-sbx")
        api.branding["ci-sbx"] = mutableMapOf("theme" to "dark")
        val sandbox = file("""
            - { kind: environment, name: ci, spec: { slug: ci-sbx } }
            - { kind: loginTheme, environment: ci, spec: { theme: dark } }
        """)
        val sandboxPlan = engine().planDestroy(sandbox)
        assertThat(sandboxPlan.changes.single { it.kind == "loginTheme" }.action).isEqualTo(ChangeAction.SKIP)
        assertThat(sandboxPlan.changes.single { it.kind == "loginTheme" }.reason).contains("removed with its sandbox")
        engine().destroy(sandboxPlan, "acme")
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/environments/env-1")

        // The removal itself, when a plan carries one: the empty record is PUT — every field null — and the platform defaults apply.
        api.reset()
        val removal = ProvisionPlan(listOf(PlannedChange("loginTheme", "loginTheme", ChangeAction.REMOVE, "will be removed", liveId = "login-theme")))
        val outcome = engine().destroy(removal, "acme")
        assertThat(outcome.failures).isEmpty()
        val put = api.writes.single()
        assertThat(put.method + " " + put.path).isEqualTo("PUT /api/v1/login-experience/branding")
        assertThat(put.body).isEqualTo(fullRecord())
        assertThat(api.branding[null]).isNull()
        assertThat(console.toString()).contains("- loginTheme: reset to the platform defaults")
    }

    // ── import round-trips ───────────────────────────────────────────────────

    @Test
    fun `import renders the stored record, and the imported entry plans as a no-op`() {
        api.branding[null] = mutableMapOf("logoUrl" to "https://cdn.acme.com/logo.svg", "theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed"))
        val imported = engine().import(existing = null).resources.single { it.resource.kind == "loginTheme" }
        assertThat(imported.resource.spec).isEqualTo(mapOf("logoUrl" to "https://cdn.acme.com/logo.svg", "theme" to "dark", "cssVariables" to mapOf("--thoryn-accent" to "#7c3aed")))

        val yaml = tools.jackson.dataformat.yaml.YAMLMapper().writeValueAsString(mapOf("apiVersion" to "thoryn.io/tenant/v1", "resources" to listOf(imported.toEntry())))
        val f = ProvisionFile.parse(yaml.toByteArray(), "imported.yaml")
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }
}
