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
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3941 — an application's `tokenClaims` converges through `/api/v1/applications/{clientId}/token-claims`, like the other
 * application settings: switched on after the create, read back and diffed only when DECLARED (the sources as a set), an
 * update touches only the toggle, `{ enabled: false }` switches it off, and an omitted `tokenClaims` leaves the live toggle
 * alone. The source NAMES pass through to product-api, which decides — so a source the server gains later works unchanged.
 */
class ProvisionTokenClaimsTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun portal(tokenClaims: String?) = ProvisionFile.parse(
        (
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: portal
                spec:
                  clientId: portal
                  displayName: "Acme Portal"
                  redirectUris: ["https://app.acme.example/cb"]
            """.trimIndent() + (tokenClaims?.let { "\n      tokenClaims: $it" } ?: "")
            ).toByteArray(),
        "provision.yaml",
    )

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    @Test
    fun `a create switches claims in the token on after the client exists, the application body never carries it, and a second apply is a no-op`() {
        val f = portal("{ sources: [permissions, org] }")
        apply(f)

        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly(
            "POST /api/v1/applications",
            "PUT /api/v1/applications/portal/token-claims",
        )
        assertThat(api.writes.first().body).doesNotContainKey("tokenClaims")
        // SSO-3945 — the PUT replaces the configuration, so it always states the mapping: here, explicitly none.
        assertThat(api.writes.last().body).isEqualTo(mapOf("sources" to listOf("permissions", "org"), "roleMapping" to null))
        assertThat(api.tokenClaims["portal"]).containsExactly("permissions", "org")

        api.reset()
        val again = engine().plan(f, false).changes.single()
        assertThat(again.action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `drift in the sources is an update of the toggle alone — the application is not patched — and order is not drift`() {
        api.seedApplication(null, "Acme Portal", listOf("https://app.acme.example/cb"), clientId = "portal")
        api.tokenClaims["portal"] = listOf("org")
        val f = portal("{ sources: [permissions] }")

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff).isEqualTo(mapOf("tokenClaims" to "sources [org] → sources [permissions]"))
        apply(f)
        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly("PUT /api/v1/applications/portal/token-claims")
        assertThat(api.tokenClaims["portal"]).containsExactly("permissions")

        api.tokenClaims["portal"] = listOf("org", "permissions")
        assertThat(engine().plan(portal("{ sources: [permissions, org] }"), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `sources default to permissions, and enabled false switches claims in the token off`() {
        api.seedApplication(null, "Acme Portal", listOf("https://app.acme.example/cb"), clientId = "portal")
        val on = portal("{}")
        assertThat(engine().plan(on, false).changes.single().diff).isEqualTo(mapOf("tokenClaims" to "off → sources [permissions]"))
        apply(on)
        assertThat(api.tokenClaims["portal"]).containsExactly("permissions")

        api.reset()
        val off = portal("{ enabled: false }")
        assertThat(engine().plan(off, false).changes.single().diff).isEqualTo(mapOf("tokenClaims" to "sources [permissions] → off"))
        apply(off)
        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly("DELETE /api/v1/applications/portal/token-claims")
        assertThat(api.tokenClaims).doesNotContainKey("portal")
        api.reset()
        assertThat(engine().plan(off, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `an omitted tokenClaims leaves the live toggle alone — not read, not diffed, not switched off`() {
        api.seedApplication(null, "Acme Portal", listOf("https://app.acme.example/cb"), clientId = "portal")
        api.tokenClaims["portal"] = listOf("permissions")
        val f = portal(null)

        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
        assertThat(api.requests).noneMatch { it.contains("token-claims") }
        assertThat(api.tokenClaims["portal"]).containsExactly("permissions")
    }

    @Test
    fun `a source name is passed through to the platform, which decides — refused by name today, converged the day it is accepted`() {
        api.seedApplication(null, "Acme Portal", listOf("https://app.acme.example/cb"), clientId = "portal")
        val f = portal("{ sources: [permissions, risk] }")
        // The file accepts it: the CLI holds no list of sources.
        assertThat(engine().plan(f, false).changes.single().diff.keys).containsExactly("tokenClaims")

        assertThatThrownBy { apply(f) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("application/portal: spec.tokenClaims refused by the platform — unsupported_claim_source")
        assertThat(api.writes.single().body).isEqualTo(mapOf("sources" to listOf("permissions", "risk"), "roleMapping" to null))

        api.supportedClaimSources = api.supportedClaimSources + "risk"
        api.reset()
        apply(f)
        assertThat(api.tokenClaims["portal"]).containsExactly("permissions", "risk")
    }

    @Test
    fun `the file refuses a malformed tokenClaims — empty or blank sources, sources with enabled false, unknown members`() {
        fun violations(tc: String) = ProvisionFile.validate(
            YAMLMapper().readTree("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: application, name: a, spec: { displayName: A, tokenClaims: $tc } }"),
        )
        assertThat(violations("{ sources: [permissions, \"metadata:dept\", some-future-source] }")).isEmpty()
        assertThat(violations("{ enabled: false }")).isEmpty()
        assertThat(violations("{ sources: [] }")).anyMatch { it.contains("non-empty list") }
        assertThat(violations("{ sources: [\"\"] }")).anyMatch { it.contains("non-empty source name") }
        assertThat(violations("{ sources: [org, org] }")).anyMatch { it.contains("lists 'org' twice") }
        assertThat(violations("{ enabled: false, sources: [org] }")).anyMatch { it.contains("takes no sources") }
        assertThat(violations("{ mapping: {} }")).anyMatch { it.contains("unknown property 'mapping'") }
        assertThat(violations("{ enabled: false, roleMapping: { a: b } }")).anyMatch { it.contains("takes no roleMapping") }
        assertThat(violations("[permissions]")).anyMatch { it.contains("must be an object") }
    }
}
