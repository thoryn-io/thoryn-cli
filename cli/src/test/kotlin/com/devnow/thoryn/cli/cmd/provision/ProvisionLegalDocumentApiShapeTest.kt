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
import java.io.PrintStream

/**
 * SSO-4072 (oauthy #4294) — `kind: legalDocument` against the API a declarative client needs: the plan reads the ACTIVE version
 * with its body (`GET …/{type}/active`, `404 no_active_document` ⇒ none); the listing is summaries without bodies, so a label's
 * stored body is read by id; a DELETED version is flagged (`deleted`, `deletedAt`) and its label refused — it cannot be activated
 * (`409 document_deleted`) and stays taken; CommonMark autolinks are Markdown, not HTML, on the server's vectors.
 *
 * Every assertion was watched failing against a reverted implementation before it was trusted (the control table in the PR).
 */
class ProvisionLegalDocumentApiShapeTest : CommandTestBase() {

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

    private val v1Body = "# Terms\n\nVersion one.\n"
    private val v2Body = "# Terms\n\nVersion two.\n"

    private fun terms(version: String, body: String) = file("""
        - kind: legalDocument
          name: terms
          spec: { type: terms-of-use, version: "$version", title: Terms, body: "${body.replace("\n", "\\n")}" }
    """)

    private fun legalReads() = api.requests.filter { it.contains("/legal-documents/") }

    @Test
    fun `a matching active version is planned from the active read alone — no listing, no other read`() {
        api.seedLegalDocument(null, "terms-of-use", "v1", v1Body, title = "Terms")
        assertThat(engine().plan(terms("v1", v1Body), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        assertThat(legalReads()).containsExactly("GET /api/v1/login-experience/legal-documents/terms-of-use/active")
    }

    @Test
    fun `an inactive version with the declared label but other content is read by id and refused as immutable`() {
        val v1 = api.seedLegalDocument(null, "terms-of-use", "v1", v1Body, title = "Terms")
        api.seedLegalDocument(null, "terms-of-use", "v2", v2Body, title = "Terms")

        val row = engine().plan(terms("v1", "# Terms\n\nVersion one, edited.\n"), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_LEGAL_DOCUMENT_VERSION_IMMUTABLE)
        assertThat(row.diff.keys).containsExactly("body")
        // The listing carries no body: the label's version is read by id for the comparison.
        assertThat(legalReads()).contains("GET /api/v1/login-experience/legal-documents/terms-of-use/$v1")
    }

    @Test
    fun `a deleted version's label is refused by plan, never re-activated, and an inactive one still is`() {
        val v1 = api.seedLegalDocument(null, "terms-of-use", "v1", v1Body, title = "Terms", deleted = true)
        api.seedLegalDocument(null, "terms-of-use", "v2", v2Body, title = "Terms")

        val row = engine().plan(terms("v1", v1Body), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionEngine.ERROR_LEGAL_DOCUMENT_VERSION_DELETED)
        assertThat(row.liveId).isEqualTo("terms-of-use/$v1")
        assertThat(row.reason).contains("version 'v1' of the terms-of-use in the production plane was deleted at 2026-10-29T12:00:00Z")
            .contains("give the document a new spec.version")
        assertThatThrownBy { engine().let { e -> e.apply(terms("v1", v1Body), e.plan(terms("v1", v1Body), false), "acme", null) } }
            .isInstanceOf(ProvisionException::class.java)
        assertThat(api.writes).isEmpty()

        // "Deleted" is the API's flag, not "inactive": an inactive version that was never deleted is re-activated.
        api.seedLegalDocument(null, "terms-of-use", "v0", v1Body, title = "Terms", active = false)
        assertThat(engine().plan(terms("v0", v1Body), false).changes.single().diff.keys).containsExactly("active")
    }

    @Test
    fun `a version deleted between plan and apply is the API's 409 document_deleted, named for the document`() {
        val v1 = api.seedLegalDocument(null, "terms-of-use", "v1", v1Body, title = "Terms", active = false)
        api.seedLegalDocument(null, "terms-of-use", "v2", v2Body, title = "Terms")
        val f = terms("v1", v1Body)
        val e = engine()
        val plan = e.plan(f, false)
        assertThat(plan.changes.single().diff.keys).containsExactly("active")
        api.legalDocumentsOf(null, "terms-of-use").single { it["id"] == v1 }["deletedAt"] = "2026-10-29T13:00:00Z"

        assertThatThrownBy { e.apply(f, plan, "acme", null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("legalDocument/terms: document_deleted — the terms-of-use version 'v1' in the production plane was deleted since the plan was made")
            .hasMessageContaining("give the document a new spec.version")
    }

    @Test
    fun `a product-api that predates the active read is refused, never planned as a create, and import says so`() {
        api.legalDocumentsPredateActive = true
        api.seedLegalDocument(null, "terms-of-use", "v1", v1Body, title = "Terms")

        assertThatThrownBy { engine().plan(terms("v2", v2Body), false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("answered 404 not_found — this product-api predates the active-version read (oauthy #4294)")
        assertThat(api.writes).isEmpty()

        val imported = engine().import(existing = null)
        assertThat(imported.resources).noneMatch { it.resource.kind == "legalDocument" }
        assertThat(imported.skipped).anyMatch { it.startsWith("legalDocument (the production plane) — not imported: GET /api/v1/login-experience/legal-documents/terms-of-use/active answered 404 not_found") }
    }

    @Test
    fun `CommonMark autolinks are accepted and HTML is refused, on the server's own vectors`() {
        (LegalDocumentRulesVectors.ACCEPTED + LegalDocumentRulesVectors.ACCEPTED_SPACING).forEach { body ->
            assertThat(ProvisionFile.legalDocumentBodyProblem(body)).withFailMessage("refused: %s", body).isNull()
        }
        LegalDocumentRulesVectors.REFUSED.forEach { body ->
            assertThat(ProvisionFile.legalDocumentBodyProblem(body)).withFailMessage("accepted: %s", body).startsWith(ProvisionFile.ERR_HTML_NOT_ALLOWED)
        }
        // Through a file and the API: an autolinked contact line is published as written.
        val body = "# Privacy\n\nQuestions? Mail <privacy@acme.example> or see <https://acme.example/privacy>.\n"
        val e = engine()
        val f = file("""
            - kind: legalDocument
              name: privacy
              spec: { type: privacy-policy, version: v1, title: Privacy, body: "${body.replace("\n", "\\n")}" }
        """)
        e.apply(f, e.plan(f, false), "acme", null)
        assertThat(api.legalDocumentsOf(null, "privacy-policy").single()["body"]).isEqualTo(body)
    }
}
