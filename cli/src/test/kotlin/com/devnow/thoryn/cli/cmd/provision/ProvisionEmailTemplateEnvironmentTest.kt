package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.PlannedChange
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPlan
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-4054 (oauthy SSO-4043 / #4289) — `kind: emailTemplate` on the environment axis. identity keys a template on
 * (tenant, environment, type, locale) and product-api routes every email-template call by `X-Thoryn-Environment`; the admin
 * read and the listing are EXACT per environment, and only the send path falls back sandbox → production → built-in default.
 * So: a resource's `environment` picks the plane exactly as for `loginTheme`; a sandbox that declares no copy of a cell
 * inherits production's and is not drift; planning compares with the environment's OWN row, never the inherited one; import
 * reads each plane's listing and writes each environment's bodies in its own files; a removal resets the cell in its own
 * environment only.
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in the PR).
 */
class ProvisionEmailTemplateEnvironmentTest : CommandTestBase() {

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

    private fun template(subject: String, body: String) = mutableMapOf<String, Any?>("subject" to subject, "bodyHtml" to body)

    private val productionBody = "<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>"
    private val stagingBody = "<p>[staging] <a href=\"{{magicLinkUrl}}\">Sign in</a></p>"

    @Test
    fun `a sandbox template is planned, gated and applied in its own environment — the PUT carries the header and production is untouched`() {
        api.seedEnvironment("staging")
        api.emailTemplates["magic_link:*"] = template("Sign in", productionBody)
        val f = file("""
            - { kind: environment, name: staging, spec: { slug: staging } }
            - kind: emailTemplate
              name: welcome-staging
              environment: staging
              spec: { type: magic_link, subject: "[staging] Sign in", body: '$stagingBody' }
        """)

        val planned = engine().plan(f, false).changes.single { it.kind == "emailTemplate" }
        // The sandbox stores no copy: a create in the sandbox, even though production stores the cell.
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)
        assertThat(planned.environment).isEqualTo("staging")

        val e = engine()
        val result = e.apply(f, e.plan(f, false), "acme", null)
        val put = api.writes.single { it.path.contains("email-templates") }
        assertThat(put.method + " " + put.path).isEqualTo("PUT /api/v1/login-experience/email-templates/magic_link")
        assertThat(put.env).isEqualTo("staging")
        assertThat(api.sandboxEmailTemplates.getValue("staging")["magic_link:*"]).isEqualTo(mapOf("subject" to "[staging] Sign in", "bodyHtml" to stagingBody))
        assertThat(api.emailTemplates["magic_link:*"]).isEqualTo(mapOf("subject" to "Sign in", "bodyHtml" to productionBody))
        assertThat(result.resources.single { it.kind == "emailTemplate" }.environment).isEqualTo("staging")
        assertThat(console.toString()).contains("+ emailTemplate welcome-staging: magic_link:* (environment staging) subject=")

        // Re-planned: the sandbox's own row matches — a no-op, and the ownership check is the sandbox's login experience.
        api.reset(); api.checks.clear()
        assertThat(engine().plan(f, false).changes.single { it.kind == "emailTemplate" }.action).isEqualTo(ChangeAction.NOOP)
        assertThat(api.checks.map { it.objectRef }).contains("login_theme:staging").doesNotContain("login_theme:production")
    }

    @Test
    fun `a sandbox without its own cell plans no change and imports nothing — production's copy is inherited, not drift`() {
        api.seedEnvironment("staging")
        api.emailTemplates["magic_link:*"] = template("Sign in", productionBody)

        // Import lists each plane: production's cell is rendered once, on the production plane; the sandbox stores nothing, so
        // nothing is rendered for it (the listing is exact — it never shows the copy the sandbox inherits).
        val imported = engine().import(existing = null).resources.filter { it.resource.kind == "emailTemplate" }
        assertThat(imported.map { "${it.resource.name} ${it.resource.environment}" }).containsExactly("magic-link null")

        // A file declaring production's cell and the sandbox — no sandbox copy — plans nothing for the sandbox and writes nothing.
        val f = file("""
            - { kind: environment, name: staging, spec: { slug: staging } }
            - kind: emailTemplate
              name: welcome
              spec: { type: magic_link, subject: "Sign in", body: '$productionBody' }
        """)
        val plan = engine().plan(f, false)
        assertThat(plan.changes.filter { it.kind == "emailTemplate" }.map { "${it.name} ${it.action} ${it.environment}" }).containsExactly("welcome NOOP null")
        val e = engine()
        e.apply(f, e.plan(f, false), "acme", null)
        assertThat(api.writes).isEmpty()
        assertThat(api.sandboxEmailTemplates["staging"].orEmpty()).isEmpty()
    }

    @Test
    fun `a sandbox's plan compares with the sandbox's own row, never the copy it inherits from production`() {
        api.seedEnvironment("staging")
        api.emailTemplates["magic_link:*"] = template("Sign in", productionBody)
        // A product-api whose sandbox GET answered the resolved (production) row would make a sandbox declaration identical to
        // production's look like "exists and matches" — and the sandbox would never get its own copy.
        api.emailTemplateGetResolves = true
        val f = file("""
            - { kind: environment, name: staging, spec: { slug: staging } }
            - kind: emailTemplate
              name: welcome-staging
              environment: staging
              spec: { type: magic_link, subject: "Sign in", body: '$productionBody' }
        """)
        val planned = engine().plan(f, false).changes.single { it.kind == "emailTemplate" }
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)
        assertThat(planned.liveId).isNull()
    }

    @Test
    fun `per-environment import reads each plane's listing with its header and writes each environment's bodies in its own files`() {
        api.seedEnvironment("staging")
        api.emailTemplates["magic_link:*"] = template("Sign in", productionBody)
        api.emailTemplates["magic_link:nl"] = template("Inloggen", "<p><a href=\"{{magicLinkUrl}}\">Inloggen</a></p>")
        api.emailTemplatesOf("staging")["magic_link:*"] = template("[staging] Sign in", stagingBody)
        api.emailTemplatesOf("staging")["password_reset:*"] = template("[staging] Reset", "<p><a href=\"{{resetUrl}}\">Reset</a></p>")

        val templates = engine().import(existing = null).resources.filter { it.resource.kind == "emailTemplate" }.associateBy { it.resource.name }
        assertThat(templates.keys).containsExactlyInAnyOrder("magic-link", "magic-link-nl", "magic-link-staging", "password-reset-staging")
        val staging = templates.getValue("magic-link-staging")
        assertThat(staging.resource.environment).isEqualTo("staging")
        // The sandbox's OWN subject and body — read through the sandbox's header, not production's.
        assertThat(staging.resource.spec).isEqualTo(mapOf("type" to "magic_link", "subject" to "[staging] Sign in", "bodyFile" to "emails/staging/magic_link.html"))
        assertThat(staging.files).isEqualTo(mapOf("emails/staging/magic_link.html" to stagingBody))
        assertThat(templates.getValue("magic-link").resource.environment).isNull()
        assertThat(templates.getValue("magic-link").files).isEqualTo(mapOf("emails/magic_link.html" to productionBody))
        assertThat(templates.getValue("magic-link-nl").files.keys).containsExactly("emails/magic_link.nl.html")
        assertThat(templates.getValue("password-reset-staging").files.keys).containsExactly("emails/staging/password_reset.html")

        // Through the CLI: every body lands in its environment's file, and the written file plans as all no-ops.
        val dir = File(tempHome.toFile(), "per-env-import/.thoryn").apply { mkdirs() }
        val target = File(dir, "provision.yaml")
        val written = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(written.exit).withFailMessage(written.err).isEqualTo(0)
        assertThat(File(dir, "emails/magic_link.html").readText()).isEqualTo(productionBody)
        assertThat(File(dir, "emails/staging/magic_link.html").readText()).isEqualTo(stagingBody)
        assertThat(File(dir, "emails/staging/password_reset.html")).exists()
        assertThat(target.readText()).contains("environment: staging").contains("bodyFile: emails/staging/magic_link.html")
        val plan = runCli("provision", "plan", "--file", target.path, "--gateway", baseUrl())
        assertThat(plan.exit).withFailMessage(plan.err).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a removal resets the cell in its own environment only, and destroy lists a sandbox's DELETE with the header`() {
        api.seedEnvironment("staging")
        api.emailTemplates["magic_link:*"] = template("Sign in", productionBody)
        api.emailTemplatesOf("staging")["magic_link:*"] = template("[staging] Sign in", stagingBody)

        val removal = ProvisionPlan(listOf(PlannedChange("emailTemplate", "welcome-staging", ChangeAction.REMOVE, "will be removed", liveId = "magic_link:*", environment = "staging", attributes = mapOf("type" to "magic_link", "locale" to "*"))))
        val outcome = engine().destroy(removal, null)
        assertThat(outcome.failures).isEmpty()
        val delete = api.writes.single()
        assertThat(delete.method + " " + delete.path).isEqualTo("DELETE /api/v1/login-experience/email-templates/magic_link")
        assertThat(delete.env).isEqualTo("staging")
        assertThat(api.sandboxEmailTemplates.getValue("staging")).isEmpty()
        assertThat(api.emailTemplates.keys).containsExactly("magic_link:*")
        assertThat(console.toString()).contains("- emailTemplate welcome-staging: magic_link:* (environment staging) reset to the built-in default")

        // destroy of a sandbox template whose sandbox this file does not declare: left in place, the row names the call a person
        // makes — in THAT environment.
        api.reset()
        api.emailTemplatesOf("staging")["magic_link:*"] = template("[staging] Sign in", stagingBody)
        val row = engine().planDestroy(file("""
            - kind: emailTemplate
              name: welcome-staging
              environment: staging
              spec: { type: magic_link, subject: "[staging] Sign in", body: '$stagingBody' }
        """)).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.SKIP)
        assertThat(row.byHand).isEqualTo(
            "DELETE /api/v1/login-experience/email-templates/magic_link with header X-Thoryn-Environment: staging " +
                "(resets that environment's copy — it then sends production's; the CLI has no `email-templates` command)",
        )
        assertThat(api.writes).isEmpty()
    }
}
