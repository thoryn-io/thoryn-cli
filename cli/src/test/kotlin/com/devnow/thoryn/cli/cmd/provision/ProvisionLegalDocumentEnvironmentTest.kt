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
 * SSO-4057 (oauthy SSO-4047 / #4290) — `kind: legalDocument` on the environment axis, import and destroy. identity keys a
 * tenant-level document on (tenant, environment, type) and resolves a sign-in's document as the application's own, else the
 * tenant's for THAT environment, else none — there is no fallback from a sandbox to production. So: `environment` picks the
 * plane (the `X-Thoryn-Environment` header); a sandbox with no document of its own has none, and a declaration for it is a
 * create; import renders each environment's ACTIVE document in its own body file (`legal/[<slug>/]<type>.md|.txt`) and never
 * the inactive versions; destroy never removes a production document (a version users accepted cannot be deleted).
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in the PR).
 */
class ProvisionLegalDocumentEnvironmentTest : CommandTestBase() {

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

    private val productionTerms = "# Terms\n\nProduction terms.\n"
    private val stagingTerms = "# Terms\n\nStaging terms — test data only.\n"

    @Test
    fun `a sandbox document is planned and published in its own environment — a production document is no fallback`() {
        api.seedEnvironment("staging")
        api.seedLegalDocument(null, "terms-of-use", "2026-10", productionTerms, title = "Terms")
        // The sandbox declares the very text production has: still a create IN the sandbox, which has no document of its own.
        val f = file("""
            - { kind: environment, name: staging, spec: { slug: staging } }
            - kind: legalDocument
              name: terms-staging
              environment: staging
              spec: { type: terms-of-use, version: "2026-10", title: Terms, body: "# Terms\n\nProduction terms.\n" }
        """)
        val planned = engine().plan(f, false).changes.single { it.kind == "legalDocument" }
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)
        assertThat(planned.environment).isEqualTo("staging")

        val e = engine()
        e.apply(f, e.plan(f, false), "acme", null)
        val post = api.writes.single { it.path.contains("legal-documents") }
        assertThat(post.method + " " + post.path).isEqualTo("POST /api/v1/login-experience/legal-documents/terms-of-use")
        assertThat(post.env).isEqualTo("staging")
        assertThat(api.legalDocumentsOf("staging", "terms-of-use").map { it["version"] }).containsExactly("2026-10")
        assertThat(api.legalDocumentsOf(null, "terms-of-use").single()["active"]).isEqualTo(true)
        assertThat(console.toString()).contains("+ legalDocument terms-staging: terms-of-use version 2026-10 (environment staging) published and active")

        api.reset()
        assertThat(engine().plan(f, false).changes.single { it.kind == "legalDocument" }.action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `import renders each environment's active document in its own body file, skips inactive versions, and round-trips to an all-noop plan`() {
        api.seedEnvironment("staging")
        api.seedLegalDocument(null, "terms-of-use", "2026-01", "# Terms\n\nOld.\n", title = "Terms")
        val activeId = api.seedLegalDocument(null, "terms-of-use", "2026-10", productionTerms, title = "Terms")
        api.seedLegalDocument(null, "privacy-policy", "v1", "We keep your email address.\n", title = "Privacy", format = "text")
        api.seedLegalDocument("staging", "terms-of-use", "s1", stagingTerms, title = "Staging terms")
        // A sandbox type whose only version was deleted (inactive): nothing active, nothing rendered.
        api.seedLegalDocument("staging", "privacy-policy", "s0", "Gone.\n", title = "Gone", active = false)

        val docs = engine().import(existing = null).resources.filter { it.resource.kind == "legalDocument" }.associateBy { it.resource.name }
        assertThat(docs.keys).containsExactlyInAnyOrder("terms-of-use", "privacy-policy", "terms-of-use-staging")
        val terms = docs.getValue("terms-of-use")
        assertThat(terms.resource.environment).isNull()
        assertThat(terms.resource.spec).isEqualTo(mapOf("type" to "terms-of-use", "version" to "2026-10", "title" to "Terms", "bodyFile" to "legal/terms-of-use.md"))
        assertThat(terms.files).isEqualTo(mapOf("legal/terms-of-use.md" to productionTerms))
        assertThat(terms.liveId).isEqualTo("terms-of-use/$activeId")
        val privacy = docs.getValue("privacy-policy")
        assertThat(privacy.resource.spec).isEqualTo(mapOf("type" to "privacy-policy", "version" to "v1", "title" to "Privacy", "format" to "text", "bodyFile" to "legal/privacy-policy.txt"))
        val staging = docs.getValue("terms-of-use-staging")
        assertThat(staging.resource.environment).isEqualTo("staging")
        assertThat(staging.files).isEqualTo(mapOf("legal/staging/terms-of-use.md" to stagingTerms))
        assertThat(api.writes).isEmpty()

        // Through the CLI: the bodies land next to the file, and the written file plans as all no-ops.
        val dir = File(tempHome.toFile(), "legal-import/.thoryn").apply { mkdirs() }
        val target = File(dir, "provision.yaml")
        val written = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(written.exit).withFailMessage(written.err).isEqualTo(0)
        assertThat(File(dir, "legal/terms-of-use.md").readText()).isEqualTo(productionTerms)
        assertThat(File(dir, "legal/privacy-policy.txt").readText()).isEqualTo("We keep your email address.\n")
        assertThat(File(dir, "legal/staging/terms-of-use.md").readText()).isEqualTo(stagingTerms)
        assertThat(target.readText()).contains("kind: legalDocument").contains("bodyFile: legal/staging/terms-of-use.md")
        val plan = runCli("provision", "plan", "--file", target.path, "--gateway", baseUrl())
        assertThat(plan.exit).withFailMessage(plan.err).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove")
        val again = runCli("provision", "import", "--file", target.path, "--gateway", baseUrl(), "--write")
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("Nothing to import")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `destroy never removes a production document, a sandbox's goes with its sandbox, and a planned removal soft-deletes unless accepted`() {
        val accepted = api.seedLegalDocument(null, "terms-of-use", "2026-10", productionTerms, title = "Terms", acceptances = 3)
        val production = file("""
            - kind: legalDocument
              name: terms
              spec: { type: terms-of-use, version: "2026-10", title: Terms, body: "# Terms\n\nProduction terms.\n" }
        """)
        val row = engine().planDestroy(production).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.SKIP)
        assertThat(row.reason).contains("PRODUCTION plane").contains("never removed by destroy / --prune")
        assertThat(row.byHand).startsWith("DELETE /api/v1/login-experience/legal-documents/terms-of-use/$accepted (soft-deletes that version")
            .contains("refused 409 document_accepted once a user accepted it")
        engine().destroy(engine().planDestroy(production), "acme")
        assertThat(api.writes).isEmpty()

        // A sandbox document whose sandbox the file declares (and may remove) goes with the sandbox: no call of its own.
        api.seedEnvironment("staging")
        api.seedLegalDocument("staging", "terms-of-use", "s1", stagingTerms, title = "Staging terms")
        val sandbox = engine().planDestroy(file("""
            - { kind: environment, name: staging, spec: { slug: staging } }
            - kind: legalDocument
              name: terms-staging
              environment: staging
              spec: { type: terms-of-use, version: s1, title: Staging terms, body: "# Terms\n\nStaging terms — test data only.\n" }
        """)).changes.single { it.kind == "legalDocument" }
        assertThat(sandbox.action).isEqualTo(ChangeAction.SKIP)
        assertThat(sandbox.reason).contains("removed with its sandbox 'staging'")

        // The removal itself, when a plan carries one: the DELETE in the row's environment; an accepted version is refused 409.
        val stagingId = api.legalDocumentsOf("staging", "terms-of-use").single()["id"]
        val removal = ProvisionPlan(listOf(PlannedChange("legalDocument", "terms-staging", ChangeAction.REMOVE, "will be removed", liveId = "terms-of-use/$stagingId", environment = "staging", attributes = mapOf("type" to "terms-of-use", "version" to "s1"))))
        assertThat(engine().destroy(removal, null).failures).isEmpty()
        val delete = api.writes.single()
        assertThat(delete.method + " " + delete.path).isEqualTo("DELETE /api/v1/login-experience/legal-documents/terms-of-use/$stagingId")
        assertThat(delete.env).isEqualTo("staging")
        assertThat(api.legalDocumentsOf("staging", "terms-of-use").single()["active"]).isEqualTo(false)

        val refused = ProvisionPlan(listOf(PlannedChange("legalDocument", "terms", ChangeAction.REMOVE, "will be removed", liveId = "terms-of-use/$accepted", attributes = mapOf("type" to "terms-of-use", "version" to "2026-10"))))
        val outcome = engine().destroy(refused, "acme")
        assertThat(outcome.failures.joinToString()).contains("document_accepted — users have accepted this terms-of-use version")
        assertThat(api.legalDocumentsOf(null, "terms-of-use").single()["active"]).isEqualTo(true)
    }
}
