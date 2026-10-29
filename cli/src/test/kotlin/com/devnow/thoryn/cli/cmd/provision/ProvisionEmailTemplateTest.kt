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
import java.io.File
import java.io.PrintStream

/**
 * SSO-4042 — `kind: emailTemplate` converges ONE transactional email template override of the workspace per (type, locale)
 * through `/api/v1/login-experience/email-templates/{type}?locale=`: a `404 template_not_customized` is a create, a stored cell
 * is diffed on `subject` and the body (line endings and trailing whitespace normalised), `apply` PUTs `{ subject, bodyHtml }`,
 * a removal is the `DELETE`. The body is inline (`body`) or a file next to the provisioning file (`bodyFile`, read when the
 * file is loaded). The API's refusals (`unknown_template_variable`, `413`) surface as plain refusals naming the cell. `import` writes
 * each stored cell with its body as a file. These cases are the production plane's; SSO-4054 moved the kind onto the environment
 * axis — the sandbox cases are [ProvisionEmailTemplateEnvironmentTest].
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in the PR).
 */
class ProvisionEmailTemplateTest : CommandTestBase() {

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

    /** A provisioning file ON DISK (so `bodyFile` resolves) under a fresh directory, with [bodies] written beside it. */
    private fun loadFromDisk(name: String, resources: String, bodies: Map<String, String> = emptyMap()): ProvisionFile {
        val dir = File(tempHome.toFile(), name).apply { mkdirs() }
        bodies.forEach { (path, content) -> File(dir, path).apply { parentFile.mkdirs() }.writeText(content) }
        val f = File(dir, "provision.yaml").apply { writeText("apiVersion: thoryn.io/tenant/v1\nresources:\n" + resources.trimIndent().prependIndent("  ") + "\n") }
        return ProvisionFile.load(f)
    }

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    /** The block scalar below as YAML parses it here (the raw string ends right after the last line, so the scalar is clipped without a final newline). */
    private val welcomeBody = "<p>Hallo {{displayName}}</p>\n<p><a href=\"{{magicLinkUrl}}\">Inloggen</a></p>"
    private val welcome = """
        - kind: emailTemplate
          name: welcome-nl
          spec:
            type: magic_link
            locale: nl
            subject: "Inloggen bij Acme, {{displayName}}"
            body: |
              <p>Hallo {{displayName}}</p>
              <p><a href="{{magicLinkUrl}}">Inloggen</a></p>
    """

    // ── plan / apply ─────────────────────────────────────────────────────────

    @Test
    fun `a template is created by PUT, a re-declaration with other line endings is a no-op, and a change names subject or body`() {
        val f = file(welcome)
        assertThat(f.resources.single().environment).isNull()
        val planned = engine().plan(f, false).changes.single()
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)
        assertThat(planned.reason).contains("not found by its converge key")

        val result = apply(f)
        val put = api.writes.single()
        assertThat(put.method + " " + put.path).isEqualTo("PUT /api/v1/login-experience/email-templates/magic_link")
        assertThat(put.body).isEqualTo(mapOf("subject" to "Inloggen bij Acme, {{displayName}}", "bodyHtml" to welcomeBody))
        assertThat(api.emailTemplates["magic_link:nl"]).isEqualTo(mapOf("subject" to "Inloggen bij Acme, {{displayName}}", "bodyHtml" to welcomeBody))
        assertThat(result.resources.single().id).isEqualTo("magic_link:nl")
        assertThat(result.resources.single().attributes).isEqualTo(mapOf("type" to "magic_link", "locale" to "nl"))
        assertThat(console.toString()).contains("+ emailTemplate welcome-nl: magic_link:nl subject=")

        // CRLF line endings and trailing whitespace are presentation, not a change — a no-op, no write. The ownership check is
        // the login experience's object: product-api gates every email-template call on `login_theme:production`.
        api.reset(); api.checks.clear()
        val crlf = ProvisionFile.parse(
            ("""{"apiVersion":"thoryn.io/tenant/v1","resources":[{"kind":"emailTemplate","name":"welcome-nl","spec":{"type":"magic_link","locale":"nl",""" +
                """"subject":"Inloggen bij Acme, {{displayName}}  ","body":"<p>Hallo {{displayName}}</p>   \r\n<p><a href=\"{{magicLinkUrl}}\">Inloggen</a></p>\r\n\r\n"}}]}""").toByteArray(),
            "provision.json", yaml = false,
        )
        assertThat(crlf.resources.single().spec["body"]).isNotEqualTo(welcomeBody) // the raw bodies differ; only the normalised ones are compared
        assertThat(engine().plan(crlf, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        assertThat(api.checks.map { it.objectRef }).contains("login_theme:production")
        apply(crlf)
        assertThat(api.writes).isEmpty()

        // A changed subject names the subject; a body with one more line names the body as a line count, never as HTML.
        val changed = file(welcome.replace("Inloggen bij Acme", "Welkom bij Acme").replace("""<p><a href="{{magicLinkUrl}}">Inloggen</a></p>""", """<p><a href="{{magicLinkUrl}}">Inloggen</a></p>
              <p>Deze link verloopt na {{expiryMinutes}} minuten.</p>"""))
        val update = engine().plan(changed, false).changes.single()
        assertThat(update.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(update.liveId).isEqualTo("magic_link:nl")
        assertThat(update.diff.keys).containsExactly("subject", "body")
        assertThat(update.diff["subject"]).isEqualTo("Inloggen bij Acme, {{displayName}} → Welkom bij Acme, {{displayName}}")
        assertThat(update.diff["body"]).isEqualTo("body differs (2 → 3 lines, +1 −0)")
        assertThat(update.diff["body"]).doesNotContain("<p>")
        apply(changed)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("PUT /api/v1/login-experience/email-templates/magic_link")
        assertThat(api.emailTemplates.getValue("magic_link:nl")["subject"]).isEqualTo("Welkom bij Acme, {{displayName}}")
    }

    @Test
    fun `the base template has no locale on the wire and converges separately from a locale variant of the same type`() {
        api.emailTemplates["magic_link:nl"] = mutableMapOf("subject" to "Inloggen", "bodyHtml" to welcomeBody)
        val f = file("""
            - kind: emailTemplate
              name: welcome
              spec: { type: magic_link, subject: "Sign in to Acme, {{displayName}}", body: "<p>Hi {{displayName}}, <a href=\"{{magicLinkUrl}}\">sign in</a></p>" }
            - kind: emailTemplate
              name: welcome-nl
              spec: { type: magic_link, locale: NL, subject: "Inloggen", body: "<p>Hallo {{displayName}}</p>\n<p><a href=\"{{magicLinkUrl}}\">Inloggen</a></p>" }
        """)
        val plan = engine().plan(f, false)
        assertThat(plan.changes.map { "${it.name} ${it.action}" }).containsExactly("welcome CREATE", "welcome-nl NOOP")
        apply(f)
        assertThat(api.requests.filter { it.contains("email-templates") && it.startsWith("PUT") }).containsExactly("PUT /api/v1/login-experience/email-templates/magic_link")
        assertThat(api.emailTemplates.keys).containsExactlyInAnyOrder("magic_link:*", "magic_link:nl")
    }

    // ── bodyFile ─────────────────────────────────────────────────────────────

    @Test
    fun `bodyFile is read relative to the provisioning file when it is loaded, the plan names the file, and apply sends its content`() {
        val f = loadFromDisk("with-body-file", """
            - kind: emailTemplate
              name: reset
              spec: { type: password_reset, subject: "Reset your password", bodyFile: emails/password_reset.html }
        """, mapOf("emails/password_reset.html" to "<p>Hi {{displayName}}</p>\n<p><a href=\"{{resetUrl}}\">Reset</a> within {{expiryMinutes}} minutes.</p>\n"))
        val spec = f.resources.single().spec
        assertThat(spec["bodyFile"]).isEqualTo("emails/password_reset.html")
        assertThat(spec["body"]).isEqualTo("<p>Hi {{displayName}}</p>\n<p><a href=\"{{resetUrl}}\">Reset</a> within {{expiryMinutes}} minutes.</p>\n")

        apply(f)
        assertThat(api.writes.single().body["bodyHtml"]).isEqualTo(spec["body"])
        assertThat(console.toString()).contains("+ emailTemplate reset: password_reset:* subject=\"Reset your password\" body=emails/password_reset.html")

        // The file on disk changed ⇒ the next plan is an update; nothing is cached.
        api.reset()
        File(tempHome.toFile(), "with-body-file/emails/password_reset.html").appendText("<p>Ignore this email if you did not ask for it.</p>\n")
        val again = ProvisionFile.load(File(tempHome.toFile(), "with-body-file/provision.yaml"))
        assertThat(engine().plan(again, false).changes.single().diff["body"]).isEqualTo("body differs (2 → 3 lines, +1 −0)")
    }

    @Test
    fun `a bodyFile that is missing, escapes the directory, is blank or oversize, or is declared with body or without either is refused before any call`() {
        fun refused(name: String, resources: String, bodies: Map<String, String> = emptyMap()): String =
            try { loadFromDisk(name, resources, bodies); "" } catch (ex: ProvisionException) { ex.message ?: "" }

        assertThat(refused("missing", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: emails/missing.html } }
        """)).contains("spec.bodyFile 'emails/missing.html' not found")
        assertThat(refused("escape", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: ../outside.html } }
        """)).contains("must stay inside the provisioning file's directory (no '..')")
        assertThat(refused("absolute", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: /etc/passwd } }
        """)).contains("must be relative to the provisioning file, not absolute")
        assertThat(refused("blank", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: emails/blank.html } }
        """, mapOf("emails/blank.html" to "  \n"))).contains("spec.bodyFile 'emails/blank.html' is blank")
        assertThat(refused("oversize", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: emails/big.html } }
        """, mapOf("emails/big.html" to "x".repeat(ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES + 1)))).contains("is ${ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES + 1} bytes, over the ${ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES}-byte limit")
        assertThat(refused("both", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, body: "<p>x</p>", bodyFile: emails/x.html } }
        """, mapOf("emails/x.html" to "<p>x</p>"))).contains(ProvisionFile.ERR_EMAIL_TEMPLATE_BODY_AMBIGUOUS).contains("not both")
        assertThat(refused("neither", """
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s } }
        """)).contains(ProvisionFile.ERR_EMAIL_TEMPLATE_BODY_REQUIRED)
        // Parsed from bytes (no directory): a bodyFile has nothing to resolve against — said, never silently empty.
        assertThatThrownBy { file("""
            - { kind: emailTemplate, name: t, spec: { type: magic_link, subject: s, bodyFile: emails/x.html } }
        """) }.hasMessageContaining("cannot be resolved: this provisioning document was not read from a file")
        assertThat(api.requests).isEmpty()
    }

    // ── validation ───────────────────────────────────────────────────────────

    @Test
    fun `the spec is checked before any call — type, locale, subject, size, an unknown key, grants, a duplicate cell per environment`() {
        assertThatThrownBy {
            file("""
                - kind: emailTemplate
                  name: env
                  environment: staging
                  spec: { type: magic_link, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  name: typ
                  spec: { type: welcome_mail, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  name: loc
                  spec: { type: magic_link, locale: en-GB, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  name: subj
                  spec: { type: invitation, subject: "   ", body: "<p>x</p>" }
                - kind: emailTemplate
                  name: long
                  spec: { type: invitation, locale: nl, subject: "${"s".repeat(ProvisionFile.EMAIL_TEMPLATE_MAX_SUBJECT_CHARS + 1)}", body: "<p>x</p>" }
                - kind: emailTemplate
                  name: big
                  spec: { type: invitation, locale: de, subject: s, body: "${"x".repeat(ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES + 1)}" }
                - kind: emailTemplate
                  name: typo
                  spec: { type: security_alert, subject: s, bodyHtml: "<p>x</p>" }
                - kind: emailTemplate
                  name: granted
                  spec: { type: account_unlock, subject: s, body: "<p>x</p>" }
                  grants: [ { subject: "client:ci", relation: manager } ]
                - kind: emailTemplate
                  name: dup-a
                  spec: { type: email_verification, locale: fr, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  name: dup-b
                  spec: { type: email_verification, locale: FR, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  spec: { type: co_admin_invitation, subject: s, body: "<p>x</p>" }
                - kind: emailTemplate
                  name: dup-staging
                  environment: staging
                  spec: { type: email_verification, locale: fr, subject: s, body: "<p>x</p>" }
            """)
        }.isInstanceOf(ProvisionException::class.java)
            // SSO-4054 — `environment` is accepted (the kind is per environment), and the same cell in another environment is
            // another record: dup-staging does not join the production pair below.
            .hasMessageNotContaining("resources[0]").hasMessageNotContaining("SSO-4043").hasMessageNotContaining("dup-staging")
            .hasMessageContaining("resources[1] (emailTemplate) spec.type 'welcome_mail' must be one of magic_link, invitation, password_reset, security_alert, account_unlock, email_verification, organization_invitation, co_admin_invitation")
            .hasMessageContaining("resources[2] (emailTemplate) spec.locale 'en-GB' must be a 2-3 letter ISO 639 language code")
            .hasMessageContaining("resources[3] (emailTemplate) spec.subject must not be blank")
            .hasMessageContaining("resources[4] (emailTemplate) spec.subject is ${ProvisionFile.EMAIL_TEMPLATE_MAX_SUBJECT_CHARS + 1} characters, over the ${ProvisionFile.EMAIL_TEMPLATE_MAX_SUBJECT_CHARS}-character limit")
            .hasMessageContaining("resources[5] (emailTemplate) spec.body is ${ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES + 1} bytes, over the ${ProvisionFile.EMAIL_TEMPLATE_MAX_BODY_BYTES}-byte limit")
            .hasMessageContaining("resources[6] spec has unknown property 'bodyHtml'")
            .hasMessageContaining("resources[6] (emailTemplate) ${ProvisionFile.ERR_EMAIL_TEMPLATE_BODY_REQUIRED}")
            .hasMessageContaining("resources[7] an emailTemplate cannot carry 'grants'")
            .hasMessageContaining("duplicate emailTemplate for type email_verification locale fr — declared 2 times ('dup-a', 'dup-b'); one resource per (environment, type, locale)")
            .hasMessageContaining("resources[10] (emailTemplate) requires a name")
        assertThat(api.requests).isEmpty()
    }

    // ── the API's refusals ───────────────────────────────────────────────────

    @Test
    fun `an unknown template variable and an oversize body are the API's refusals, surfaced as plain refusals naming the cell`() {
        val wrongVariable = file("""
            - kind: emailTemplate
              name: welcome
              spec: { type: magic_link, subject: "Sign in", body: "<p><a href=\"{{resetUrl}}\">Sign in</a></p>" }
        """)
        assertThatThrownBy { apply(wrongVariable) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("emailTemplate/welcome: unknown_template_variable")
            .hasMessageContaining("Allowed variables are: displayName, expiryMinutes, magicLinkUrl.")
            .hasMessageContaining("Fix the {{variable}} names in the subject or body of magic_link:* and re-run.")
        assertThat(api.emailTemplates).isEmpty()

        // identity's 64 KiB cap is mirrored client-side, so the fake's cap is lowered to see the 413 travel through the engine.
        api.emailTemplateMaxBodyBytes = 40
        val oversize = file("""
            - kind: emailTemplate
              name: welcome
              spec: { type: magic_link, subject: "Sign in", body: "<p>Hello {{displayName}}, <a href=\"{{magicLinkUrl}}\">sign in</a> now please</p>" }
        """)
        assertThatThrownBy { apply(oversize) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("emailTemplate/welcome: template_body_too_large (HTTP 413)")
            .hasMessageContaining("Shorten the body of magic_link:* and re-run.")
    }

    // ── destroy / --prune ────────────────────────────────────────────────────

    @Test
    fun `destroy leaves the workspace's template in place naming the DELETE a person runs, and a planned removal DELETEs the cell`() {
        apply(file(welcome))
        api.reset()
        // SSO-3715 (ADR 2026-10-15 §1): a non-ownable kind on the production plane — every email template is, tenant-wide — is
        // never removed by destroy / --prune; the row names the call a person makes (the CLI has no email-templates verb).
        val plan = engine().planDestroy(file(welcome))
        val row = plan.changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.SKIP)
        assertThat(row.reason).contains("PRODUCTION plane").contains("never removed by destroy / --prune")
        assertThat(row.byHand).isEqualTo("DELETE /api/v1/login-experience/email-templates/magic_link?locale=nl (resets it to the built-in default; the CLI has no `email-templates` command)")
        engine().destroy(plan, "acme")
        assertThat(api.writes).isEmpty()
        assertThat(api.emailTemplates).containsKey("magic_link:nl")

        // The removal itself, when a plan carries one: the DELETE of exactly that cell, the sibling cell untouched.
        api.emailTemplates["magic_link:*"] = mutableMapOf("subject" to "Sign in", "bodyHtml" to "<p>x</p>")
        val removal = ProvisionPlan(listOf(PlannedChange("emailTemplate", "welcome-nl", ChangeAction.REMOVE, "will be removed", liveId = "magic_link:nl", attributes = mapOf("type" to "magic_link", "locale" to "nl"))))
        val outcome = engine().destroy(removal, "acme")
        assertThat(outcome.failures).isEmpty()
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/login-experience/email-templates/magic_link")
        assertThat(api.emailTemplates.keys).containsExactly("magic_link:*")
        assertThat(console.toString()).contains("- emailTemplate welcome-nl: magic_link:nl reset to the built-in default")
    }

    // ── import ───────────────────────────────────────────────────────────────

    @Test
    fun `import renders each listed cell with its body as a file — locale variants included — and import --write round-trips to an all-noop plan`() {
        api.emailTemplates["magic_link:*"] = mutableMapOf("subject" to "Sign in to Acme, {{displayName}}", "bodyHtml" to "<p>Hi {{displayName}}</p>\n<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>\n")
        api.emailTemplates["password_reset:*"] = mutableMapOf("subject" to "Reset your Acme password", "bodyHtml" to "<p><a href=\"{{resetUrl}}\">Reset</a></p>\n")
        api.emailTemplates["magic_link:nl"] = mutableMapOf("subject" to "Inloggen", "bodyHtml" to welcomeBody)

        val result = engine().import(existing = null)
        val templates = result.resources.filter { it.resource.kind == "emailTemplate" }.associateBy { it.resource.name }
        assertThat(templates.keys).containsExactlyInAnyOrder("magic-link", "magic-link-nl", "password-reset")
        assertThat(templates.getValue("magic-link").resource.spec).isEqualTo(mapOf("type" to "magic_link", "subject" to "Sign in to Acme, {{displayName}}", "bodyFile" to "emails/magic_link.html"))
        assertThat(templates.getValue("magic-link").files).isEqualTo(mapOf("emails/magic_link.html" to "<p>Hi {{displayName}}</p>\n<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>\n"))
        assertThat(templates.getValue("magic-link").liveId).isEqualTo("magic_link:*")
        assertThat(templates.getValue("magic-link").resource.readOnly).isFalse()
        assertThat(templates.getValue("magic-link").toStructured()["files"]).isEqualTo(listOf("emails/magic_link.html"))
        // SSO-4054 — the listing names the locale variant, so it is imported with its locale and its own body file.
        assertThat(templates.getValue("magic-link-nl").resource.spec).isEqualTo(mapOf("type" to "magic_link", "locale" to "nl", "subject" to "Inloggen", "bodyFile" to "emails/magic_link.nl.html"))
        assertThat(templates.getValue("magic-link-nl").files).isEqualTo(mapOf("emails/magic_link.nl.html" to welcomeBody))
        assertThat(templates.getValue("magic-link-nl").liveId).isEqualTo("magic_link:nl")
        assertThat(result.skipped).noneMatch { it.contains("emailTemplate") }
        // The listing once, then each listed cell once by address — no type that is not stored is asked for.
        assertThat(api.requests.filter { it.contains("/email-templates") }).containsExactly(
            "GET /api/v1/login-experience/email-templates",
            "GET /api/v1/login-experience/email-templates/magic_link", "GET /api/v1/login-experience/email-templates/magic_link", "GET /api/v1/login-experience/email-templates/password_reset",
        )
        assertThat(api.writes).isEmpty()

        // Through the CLI: the files land next to the provisioning file, the appended file plans as all no-ops, a second import adds nothing.
        val dir = File(tempHome.toFile(), "import-cli/.thoryn").apply { mkdirs() }
        val target = File(dir, "provision.yaml")
        val dry = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--part", "tenant")
        assertThat(dry.exit).withFailMessage(dry.err).isEqualTo(0)
        assertThat(dry.out).contains("kind: emailTemplate").contains("bodyFile: emails/magic_link.html")
        assertThat(dry.err).contains("3 file(s) would be written next to ${target.path}: emails/magic_link.html, emails/magic_link.nl.html, emails/password_reset.html")
        assertThat(File(dir, "emails")).doesNotExist()

        val written = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(written.exit).withFailMessage(written.err).isEqualTo(0)
        assertThat(written.out).contains("3 file(s) written beside it (emails/magic_link.html, emails/magic_link.nl.html, emails/password_reset.html)")
        assertThat(File(dir, "emails/magic_link.nl.html").readText()).isEqualTo(welcomeBody)
        assertThat(File(dir, "emails/magic_link.html").readText()).isEqualTo("<p>Hi {{displayName}}</p>\n<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>\n")
        assertThat(File(dir, "emails/password_reset.html").readText()).isEqualTo("<p><a href=\"{{resetUrl}}\">Reset</a></p>\n")
        assertThat(target.readText()).contains("bodyFile: emails/magic_link.html").doesNotContain("<p>")

        val plan = runCli("provision", "plan", "--file", target.path, "--gateway", baseUrl())
        assertThat(plan.exit).withFailMessage(plan.err).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove, 3 unchanged.")
        val again = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--write")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("Nothing to import")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `import never overwrites a body file that already exists with other content`() {
        api.emailTemplates["magic_link:*"] = mutableMapOf("subject" to "Sign in", "bodyHtml" to "<p>live</p>")
        val dir = File(tempHome.toFile(), "import-clobber/.thoryn").apply { mkdirs() }
        File(dir, "emails/magic_link.html").apply { parentFile.mkdirs() }.writeText("<p>hand-written</p>")
        val target = File(dir, "provision.yaml")
        val written = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(written.exit).isNotEqualTo(0)
        assertThat(written.err).contains("emails/magic_link.html already exists with different content; the import does not overwrite a template body")
        assertThat(File(dir, "emails/magic_link.html").readText()).isEqualTo("<p>hand-written</p>")
        assertThat(target).doesNotExist()
    }
}
