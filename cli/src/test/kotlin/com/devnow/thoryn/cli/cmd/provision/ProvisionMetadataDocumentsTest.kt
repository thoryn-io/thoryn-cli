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
 * SSO-4345 — the `metadataDocuments` kind: an environment's Client ID Metadata Document policy as code (oauthy SSO-4335 /
 * SSO-4338). It converges by its environment, as the whole record the API replaces (hosts as a set, lower-cased; a lifetime
 * the file leaves out is neither compared nor sent); its access object is the environment (`manager`); a widening apply
 * without a fresh passkey sign-in names the login to run and changes nothing; the file's rules mirror the hub's; `import`
 * renders a written policy and skips the defaults.
 */
class ProvisionMetadataDocumentsTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        envId = api.seedEnvironment("ci-sbx")
        api.seedEnvironment("production", kind = "production")
    }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = api.caller,
    )

    private fun file(resources: String) =
        ProvisionFile.parse(("apiVersion: thoryn.io/tenant/v1\nresources:\n" + resources.trimIndent().prependIndent("  ")).toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    private fun puts() = api.writes.filter { it.method == "PUT" && it.path == "/api/v1/environments/$envId/client-id-metadata-documents" }

    @Test
    fun `the policy converges by its environment — PUT of the whole record, no-op when equal, one update carrying the change`() {
        val f = file("- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: true, allowedHosts: [Clients.Example.com] } }")

        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.CREATE)
        apply(f)
        assertThat(puts().single().body).isEqualTo(
            mapOf("enabled" to true, "allowedHosts" to listOf("clients.example.com"), "refreshTokensEnabled" to false),
        )
        assertThat(puts().single().env).isEqualTo("ci-sbx")

        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()

        val changed = file(
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: true, allowedHosts: [clients.example.com], " +
                "refreshTokensEnabled: true, refreshTokenTtlSeconds: 86400 } }",
        )
        val plan = engine().plan(changed, false).changes.single()
        assertThat(plan.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(plan.diff.keys).containsExactlyInAnyOrder("refreshTokensEnabled", "refreshTokenTtlSeconds")
        apply(changed)
        assertThat((puts().single().body["refreshTokenTtlSeconds"] as Number).toLong()).isEqualTo(86_400L)
        assertThat(puts().single().body).doesNotContainKey("refreshTokenAbsoluteMaxTtlSeconds")
    }

    @Test
    fun `a widening apply without a fresh passkey sign-in names the login to run and changes nothing`() {
        api.metadataDocumentWidening = "step_up"
        val f = file("- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: true, allowedHosts: [clients.example.com] } }")

        assertThatThrownBy { apply(f) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .hasMessageContaining("nothing was changed")
        assertThat(api.metadataDocumentPolicies).isEmpty()
    }

    @Test
    fun `an identity that does not manage the environment is refused at plan`() {
        api.callerIsAdmin = false
        val f = file("- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: false } }")

        val change = engine().plan(f, false).changes.single()

        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.reason).contains("manager").contains("environment:$envId")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `the file's rules mirror the hub's`() {
        listOf(
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: true } }" to "enabling needs at least one host",
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: false, refreshTokenTtlSeconds: 60 } }" to "from 3600",
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: false, refreshTokenTtlSeconds: 86400, refreshTokenAbsoluteMaxTtlSeconds: 3600 } }" to
                "must not be shorter",
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: false, scopes: [x] } }" to "scopes",
            "- { kind: metadataDocuments, environment: ci-sbx, spec: { enabled: false }, grants: [{ subject: 'client:x', relation: viewer }] }" to
                "cannot carry 'grants'",
        ).forEach { (yaml, message) ->
            assertThatThrownBy { file(yaml) }.describedAs(yaml).isInstanceOf(ProvisionException::class.java).hasMessageContaining(message)
        }
    }

    @Test
    fun `import renders a written policy and skips one that still has its defaults`() {
        val prodId = api.environments.first { it["slug"] == "production" }["id"].toString()
        api.metadataDocumentPolicies[prodId] = mutableMapOf(
            "environmentId" to prodId, "environment" to "production", "enabled" to true, "allowedHosts" to listOf("clients.example.com"),
            "refreshTokensEnabled" to true, "refreshTokenTtlSeconds" to 86_400L, "refreshTokenAbsoluteMaxTtlSeconds" to 604_800L,
            "updatedAt" to "2026-11-09T10:00:00Z",
        )

        val imported = engine().import(existing = null).resources.filter { it.resource.kind == ProvisionFile.KIND_METADATA_DOCUMENTS }

        assertThat(imported).hasSize(1)
        val r = imported.single()
        assertThat(r.resource.environment).isNull()
        assertThat(r.liveId).isEqualTo(prodId)
        assertThat(r.resource.spec).isEqualTo(
            mapOf(
                "enabled" to true, "allowedHosts" to listOf("clients.example.com"), "refreshTokensEnabled" to true,
                "refreshTokenTtlSeconds" to 86_400L, "refreshTokenAbsoluteMaxTtlSeconds" to 604_800L,
            ),
        )
        assertThat(api.writes).isEmpty()
    }
}
