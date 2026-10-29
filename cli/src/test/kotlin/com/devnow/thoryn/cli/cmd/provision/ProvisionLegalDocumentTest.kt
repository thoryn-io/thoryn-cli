package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-4057 (oauthy SSO-4047 / #4290) — `kind: legalDocument` declares the ACTIVE version of a workspace environment's
 * tenant-level Terms of Use or Privacy Policy through `/api/v1/login-experience/legal-documents/{type}`. A published version
 * never changes, so the plan is decided by the declared `version` label: the active version with that label and content is a
 * no-op; no version with the label is a publish (a create when nothing is active, an update that publishes a new version
 * otherwise); an inactive version with the label and content is re-activated; a version with the label and OTHER content is
 * refused. The body is inline or a file next to the provisioning file, held client-side to identity's rules (128 KiB, no
 * control character, no HTML). These cases are the production plane's; the sandbox, import and destroy cases are
 * [ProvisionLegalDocumentEnvironmentTest].
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in the PR).
 */
class ProvisionLegalDocumentTest : CommandTestBase() {

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

    private fun loadFromDisk(name: String, resources: String, bodies: Map<String, String> = emptyMap()): ProvisionFile {
        val dir = File(tempHome.toFile(), name).apply { mkdirs() }
        bodies.forEach { (path, content) -> File(dir, path).apply { parentFile.mkdirs() }.writeText(content) }
        val f = File(dir, "provision.yaml").apply { writeText("apiVersion: thoryn.io/tenant/v1\nresources:\n" + resources.trimIndent().prependIndent("  ") + "\n") }
        return ProvisionFile.load(f)
    }

    private fun apply(f: ProvisionFile) {
        val e = engine()
        e.apply(f, e.plan(f, false), "acme", null)
    }

    private val termsBody = "# Terms of use\n\nBy signing in you agree to **these terms**.\n"

    private fun terms(version: String, body: String = termsBody, title: String = "Acme terms of use") = """
        - kind: legalDocument
          name: terms
          spec:
            type: terms-of-use
            version: "$version"
            title: "$title"
            body: ${'"'}${body.replace("\r", "\\r").replace("\n", "\\n")}${'"'}
    """

    // ── plan / apply ─────────────────────────────────────────────────────────

    @Test
    fun `a document is published by POST and active, a re-declaration is a no-op, and no ownership check is asked`() {
        val planned = engine().plan(file(terms("2026-10")), false).changes.single()
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)

        apply(file(terms("2026-10")))
        val post = api.writes.single()
        assertThat(post.method + " " + post.path).isEqualTo("POST /api/v1/login-experience/legal-documents/terms-of-use")
        assertThat(post.env).isNull()
        assertThat(post.body).isEqualTo(mapOf("version" to "2026-10", "title" to "Acme terms of use", "body" to termsBody, "format" to "markdown"))
        val stored = api.legalDocumentsOf(null, "terms-of-use").single()
        assertThat(stored["active"]).isEqualTo(true)
        assertThat(console.toString()).contains("+ legalDocument terms: terms-of-use version 2026-10 published and active")

        // CRLF line endings and trailing whitespace are presentation, not a new text: a no-op, no write. A legal document is not
        // a platform access object (product-api gates it on tenant:compliance.* alone), so no forward check is asked for it.
        api.reset(); api.checks.clear()
        val again = engine().plan(file(terms("2026-10", body = termsBody.replace("\n", "  \r\n"))), false).changes.single()
        assertThat(again.action).isEqualTo(ChangeAction.NOOP)
        assertThat(again.liveId).isEqualTo("terms-of-use/${stored["id"]}")
        assertThat(api.checks).isEmpty()
        apply(file(terms("2026-10")))
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a new version label publishes a new version — the previous one is deactivated, never changed`() {
        val first = api.seedLegalDocument(null, "terms-of-use", "2026-01", termsBody, title = "Acme terms of use")
        val next = file(terms("2026-10", body = termsBody + "\nWe may suspend accounts that break these terms.\n"))

        val update = engine().plan(next, false).changes.single()
        assertThat(update.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(update.liveId).isEqualTo("terms-of-use/$first")
        assertThat(update.diff.keys).containsExactly("version", "body")
        assertThat(update.diff["version"]).isEqualTo("2026-01 → 2026-10 (publishes a new version; users accept it at their next sign-in)")
        assertThat(update.diff["body"]).isEqualTo("body differs (3 → 5 lines, +2 −0)")

        apply(next)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/login-experience/legal-documents/terms-of-use")
        val versions = api.legalDocumentsOf(null, "terms-of-use")
        assertThat(versions.map { "${it["version"]} ${it["active"]}" }).containsExactly("2026-01 false", "2026-10 true")
        assertThat(versions.first()["body"]).isEqualTo(termsBody)
    }

    @Test
    fun `a published label with other content is refused by plan and nothing is written`() {
        val id = api.seedLegalDocument(null, "terms-of-use", "2026-10", termsBody, title = "Acme terms of use")
        val changed = file(terms("2026-10", body = termsBody + "\nOne more clause.\n", title = "Acme terms"))

        val row = engine().plan(changed, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_LEGAL_DOCUMENT_VERSION_IMMUTABLE)
        assertThat(row.liveId).isEqualTo("terms-of-use/$id")
        assertThat(row.reason).contains("version '2026-10' of the terms-of-use in the production plane is already published with a different title and body")
            .contains("give the new text a new spec.version")
        assertThat(row.diff.keys).containsExactly("title", "body")
        assertThatThrownBy { apply(changed) }.isInstanceOf(ProvisionException::class.java)
        assertThat(api.writes).isEmpty()
        assertThat(api.legalDocumentsOf(null, "terms-of-use").single()["body"]).isEqualTo(termsBody)
    }

    @Test
    fun `an inactive version with the declared label and content is re-activated, not published again`() {
        val old = api.seedLegalDocument(null, "terms-of-use", "2026-01", termsBody, title = "Acme terms of use")
        api.seedLegalDocument(null, "terms-of-use", "2026-10", "# Terms\n\nNewer text.\n", title = "Acme terms of use")

        val row = engine().plan(file(terms("2026-01")), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.liveId).isEqualTo("terms-of-use/$old")
        assertThat(row.diff).isEqualTo(mapOf("active" to "version 2026-10 → version 2026-01 (re-activates the stored version; nothing is published)"))

        apply(file(terms("2026-01")))
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/login-experience/legal-documents/terms-of-use/$old/activate")
        assertThat(api.legalDocumentsOf(null, "terms-of-use").map { "${it["version"]} ${it["active"]}" }).containsExactly("2026-01 true", "2026-10 false")
        assertThat(console.toString()).contains("~ legalDocument terms: terms-of-use version 2026-01 re-activated")
        api.reset()
        assertThat(engine().plan(file(terms("2026-01")), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `the two types are converged separately and a text format is sent as declared`() {
        api.seedLegalDocument(null, "terms-of-use", "2026-10", termsBody, title = "Acme terms of use")
        val f = file(terms("2026-10").trimIndent() + "\n" + """
            - kind: legalDocument
              name: privacy
              spec: { type: privacy-policy, version: v1, title: Privacy, format: text, body: "We keep your email address." }
        """.trimIndent())
        assertThat(engine().plan(f, false).changes.map { "${it.name} ${it.action}" }).containsExactly("terms NOOP", "privacy CREATE")
        apply(f)
        val post = api.writes.single()
        assertThat(post.path).isEqualTo("/api/v1/login-experience/legal-documents/privacy-policy")
        assertThat(post.body["format"]).isEqualTo("text")
        assertThat(api.legalDocumentsOf(null, "privacy-policy").single()["format"]).isEqualTo("text")
    }

    // ── bodyFile ─────────────────────────────────────────────────────────────

    @Test
    fun `bodyFile is read relative to the provisioning file and held to the body rules — HTML in it is refused before any call`() {
        val f = loadFromDisk("legal-file", """
            - kind: legalDocument
              name: terms
              spec: { type: terms-of-use, version: "2026-10", title: Terms, bodyFile: legal/terms-of-use.md }
        """, mapOf("legal/terms-of-use.md" to termsBody))
        assertThat(f.resources.single().spec["body"]).isEqualTo(termsBody)
        apply(f)
        assertThat(api.writes.single().body["body"]).isEqualTo(termsBody)
        assertThat(console.toString()).contains("body=legal/terms-of-use.md")

        api.reset(); api.requests.clear()
        fun refused(name: String, content: String): String = try {
            loadFromDisk(name, """
                - { kind: legalDocument, name: t, spec: { type: privacy-policy, version: v1, title: P, bodyFile: legal/p.md } }
            """, mapOf("legal/p.md" to content)); ""
        } catch (ex: ProvisionException) { ex.message ?: "" }
        assertThat(refused("html-file", "# Privacy\n\n<script>alert(1)</script>\n"))
            .contains("(legalDocument) spec.bodyFile 'legal/p.md' html_not_allowed — it contains HTML ('<s…' on line 3)")
        assertThat(refused("big-file", "x".repeat(ProvisionFile.LEGAL_DOCUMENT_MAX_BODY_BYTES + 1)))
            .contains("spec.bodyFile 'legal/p.md' is ${ProvisionFile.LEGAL_DOCUMENT_MAX_BODY_BYTES + 1} bytes, over the ${ProvisionFile.LEGAL_DOCUMENT_MAX_BODY_BYTES}-byte limit")
        assertThat(refused("blank-file", " \n")).contains("spec.bodyFile 'legal/p.md' is blank")
        assertThat(api.requests).isEmpty()
    }

    // ── validation ───────────────────────────────────────────────────────────

    @Test
    fun `the spec is checked before any call — type, version, title, format, HTML, control characters, body source, grants, a duplicate per environment`() {
        assertThatThrownBy {
            file("""
                - { kind: legalDocument, name: typ, spec: { type: cookie-policy, version: v1, title: T, body: "x" } }
                - { kind: legalDocument, name: ver, spec: { type: terms-of-use, version: "v<2>", title: T, body: "x" } }
                - { kind: legalDocument, name: long, spec: { type: terms-of-use, version: "${"v".repeat(ProvisionFile.LEGAL_DOCUMENT_MAX_VERSION_CHARS + 1)}", title: T, body: "x" } }
                - { kind: legalDocument, name: tit, spec: { type: terms-of-use, version: v1, title: "   ", body: "x" } }
                - { kind: legalDocument, name: fmt, spec: { type: terms-of-use, version: v1, title: T, format: html, body: "x" } }
                - { kind: legalDocument, name: html, spec: { type: terms-of-use, version: v1, title: T, body: "Read <a href='x'>this</a>" } }
                - { kind: legalDocument, name: ctl, spec: { type: terms-of-use, version: v1, title: T, body: "bell \u0007" } }
                - { kind: legalDocument, name: both, spec: { type: terms-of-use, version: v1, title: T, body: "x", bodyFile: legal/x.md } }
                - { kind: legalDocument, name: none, spec: { type: terms-of-use, version: v1, title: T } }
                - { kind: legalDocument, name: granted, spec: { type: terms-of-use, version: v1, title: T, body: "x" }, grants: [ { subject: "client:ci", relation: manager } ] }
                - { kind: legalDocument, name: typo, spec: { type: privacy-policy, versionLabel: v1, version: v1, title: T, body: "x" } }
                - { kind: legalDocument, name: dup-a, spec: { type: privacy-policy, version: v1, title: T, body: "x" } }
                - { kind: legalDocument, name: dup-staging, environment: staging, spec: { type: privacy-policy, version: v1, title: T, body: "x" } }
                - { kind: legalDocument, spec: { type: privacy-policy, version: v1, title: T, body: "a < b is fine" } }
            """)
        }.isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("resources[0] (legalDocument) spec.type 'cookie-policy' must be one of terms-of-use, privacy-policy")
            .hasMessageContaining("resources[1] (legalDocument) spec.version must be plain text (no '<', '>' or control character)")
            .hasMessageContaining("resources[2] (legalDocument) spec.version is ${ProvisionFile.LEGAL_DOCUMENT_MAX_VERSION_CHARS + 1} characters, over the ${ProvisionFile.LEGAL_DOCUMENT_MAX_VERSION_CHARS}-character limit")
            .hasMessageContaining("resources[3] (legalDocument) spec.title must not be blank")
            .hasMessageContaining("resources[4] (legalDocument) spec.format 'html' must be one of markdown, text")
            .hasMessageContaining("resources[5] (legalDocument) spec.body html_not_allowed — it contains HTML ('<a…' on line 1)")
            .hasMessageContaining("resources[6] (legalDocument) spec.body contains a control character")
            .hasMessageContaining("resources[7] (legalDocument) ${ProvisionFile.ERR_LEGAL_DOCUMENT_BODY_AMBIGUOUS}")
            .hasMessageContaining("resources[8] (legalDocument) ${ProvisionFile.ERR_LEGAL_DOCUMENT_BODY_REQUIRED}")
            .hasMessageContaining("resources[9] a legalDocument cannot carry 'grants'")
            .hasMessageContaining("resources[10] spec has unknown property 'versionLabel'")
            .hasMessageContaining("duplicate legalDocument for privacy-policy — declared 3 times ('typo', 'dup-a', 'legalDocument'); one resource per (environment, type)")
            .hasMessageContaining("resources[13] (legalDocument) requires a name")
            // The same type in another environment is another document; a `<` in prose is not HTML.
            .hasMessageNotContaining("dup-staging").hasMessageNotContaining("resources[12]")
            .hasMessageNotContaining("resources[13] (legalDocument) spec.body")
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `the API's refusals at apply are named for the document, and a missing compliance scope names the scope`() {
        // A label published between plan and apply: the API's 409, said as such.
        val f = file(terms("2026-10"))
        val e = engine()
        val plan = e.plan(f, false)
        api.seedLegalDocument(null, "terms-of-use", "2026-10", "# Other\n", active = false)
        assertThatThrownBy { e.apply(f, plan, "acme", null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("legalDocument/terms: version_exists — the terms-of-use version '2026-10' in the production plane was published since the plan was made")

        // product-api gates the surface on tenant:compliance.*, not the login experience's idp area.
        api.enforceScopeGates = true
        api.callerScopes = setOf("tenant:idp.read", "tenant:idp.write")
        val failure = runCatching { engine().plan(file(terms("2026-11")), false) }.exceptionOrNull()
        assertThat(failure?.message).contains("tenant:compliance.read")
    }
}
