package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3810 / SSO-3807 (oauthy) — an `application` declares `allowTokenIntrospection` (RFC 7662) and `accessTokenFormat`
 * (`self-contained` | `reference`) like every other application setting: sent on create, read back, diffed only when
 * declared (an omitted one keeps the live value), and an update sends exactly the differing fields. The loader refuses
 * introspection on a public client and an unknown format with product-api's codes; the plan predicts
 * `token_introspection_not_grantable` (turning it ON needs `manager` on the environment); an apply-time refusal names the
 * resource, the code and the fix.
 */
class ProvisionIntrospectionAndTokenFormatTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val clientId = "wi_repo"
    private val subject = "client:$clientId"
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
    }

    private fun engine(subject: String? = null) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, subject: String? = null): ApplyResult {
        val e = engine(subject)
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    /** The orders resource server in the sandbox, with [extra] appended to its spec. */
    private fun orders(extra: String, environment: String? = "ci-sbx") = file(
        "apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: orders\n" +
            (environment?.let { "    environment: $it\n" } ?: "") +
            "    spec:\n      clientId: orders\n      displayName: \"Orders API\"\n      clientType: confidential\n" +
            "      grantTypes: [client_credentials]\n      scopes: [tenant:applications.read]\n" +
            extra.trimIndent().prependIndent("      "),
    )

    private fun live(): MutableMap<String, Any?> = api.applications.single { it["clientId"] == "orders" }

    // ── converge ──

    @Test
    fun `a create sends both settings, and a second plan and apply are a no-op`() {
        val f = orders("allowTokenIntrospection: true\naccessTokenFormat: reference")
        apply(f)
        val create = api.writes.single { it.method == "POST" && it.path == "/api/v1/applications" }.body
        assertThat(create).containsEntry("allowTokenIntrospection", true).containsEntry("accessTokenFormat", "reference")

        api.reset()
        val again = engine().plan(f, false).changes.single()
        assertThat(again.action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `drift on either setting converges with exactly the differing field, and an omitted setting keeps the live value`() {
        val f = orders("allowTokenIntrospection: true\naccessTokenFormat: reference")
        apply(f)
        live()["accessTokenFormat"] = "self-contained"
        api.reset()

        val row = engine().plan(f, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.diff.keys).containsExactly(ProvisionFile.SPEC_ACCESS_TOKEN_FORMAT)
        apply(f)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("accessTokenFormat" to "reference"))

        // A file that omits both says nothing about them: the live values stay.
        api.reset()
        assertThat(engine().plan(orders(""), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    // ── loader ──

    @Test
    fun `introspection on a public client and an unknown token format are refused by the loader with product-api's codes`() {
        assertThatThrownBy {
            file(
                """
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: application
                    name: spa
                    spec:
                      displayName: SPA
                      clientType: public
                      redirectUris: ["https://spa.acme.example/cb"]
                      allowTokenIntrospection: true
                """,
            )
        }.isInstanceOf(ProvisionException::class.java).hasMessageContaining(ProvisionFile.ERR_TOKEN_INTROSPECTION_REQUIRES_CONFIDENTIAL_CLIENT)

        assertThatThrownBy { orders("accessTokenFormat: opaque") }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining(ProvisionFile.SPEC_ACCESS_TOKEN_FORMAT)
    }

    @Test
    fun `the schema publishes both properties - the format as its two exact values - and the public-client rule`() {
        val json = JsonMapper.builder().build()
        val schema: JsonNode = json.readTree(javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)!!.readBytes().toString(Charsets.UTF_8))
        val rules = schema["\$defs"]["resource"]["allOf"].toList()
        val props = rules.first { it["if"]["properties"]?.get("kind")?.get("const")?.asString() == "application" && it["if"]["properties"].size() == 1 }["then"]["properties"]["spec"]["properties"]
        assertThat(props[ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION]["type"].asString()).isEqualTo("boolean")
        assertThat(props[ProvisionFile.SPEC_ACCESS_TOKEN_FORMAT]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.ACCESS_TOKEN_FORMATS)
        val rule = rules.first { it["if"]["properties"]?.get("spec")?.get("properties")?.get(ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION)?.get("const")?.asBoolean() == true }
        assertThat(rule["then"]["properties"]["spec"]["not"]["properties"]["clientType"]["const"].asString()).isEqualTo(ProvisionFile.CLIENT_TYPE_PUBLIC)
    }

    // ── the plan gate (who may turn introspection on) ──

    /** The repository's CI identity OWNS the live orders application (so it manages it) and nothing else. */
    private fun repositoryOwnsOrders(env: String? = "ci-sbx", introspectionOn: Boolean = false) {
        api.callerIsAdmin = false
        api.caller = subject
        api.seedApplication(env, "Orders API", emptyList(), clientId = "orders")
        live()["grantTypes"] = listOf("client_credentials")
        live()["scopes"] = listOf("tenant:applications.read")
        live()["clientType"] = "confidential"
        live()["allowTokenIntrospection"] = introspectionOn
        api.seedGrant(subject, "owner", "application:orders")
    }

    @Test
    fun `turning introspection on without manager on the environment is a red plan naming that right, and the right fixes it`() {
        repositoryOwnsOrders()
        val f = orders("allowTokenIntrospection: true")

        val row = engine(subject).plan(f, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE)
        assertThat(row.fix!!.kind).isEqualTo(FixRequest.Kind.MANAGER)
        assertThat(row.fix!!.objectRef).isEqualTo("environment:$envId")
        assertThatThrownBy { apply(f, subject) }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("nothing was written")
        assertThat(api.writes).isEmpty()

        api.seedGrant(subject, "manager", "environment:$envId")
        assertThat(engine(subject).plan(f, false).changes.single().action).isEqualTo(ChangeAction.UPDATE)
        apply(f, subject)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowTokenIntrospection" to true))
    }

    @Test
    fun `turning introspection off, or re-declaring the stored value, and changing the format are never refused`() {
        repositoryOwnsOrders(introspectionOn = true)
        assertThat(engine(subject).plan(orders("allowTokenIntrospection: true"), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        val narrowed = orders("allowTokenIntrospection: false\naccessTokenFormat: reference")
        assertThat(engine(subject).plan(narrowed, false).changes.single().action).isEqualTo(ChangeAction.UPDATE)
        apply(narrowed, subject)
        assertThat(api.writes.single { it.method == "PATCH" }.body)
            .isEqualTo(mapOf("allowTokenIntrospection" to false, "accessTokenFormat" to "reference"))
    }

    @Test
    fun `on the production plane the right is the workspace's manager - a note, never a grant to a repository identity`() {
        repositoryOwnsOrders(env = null)
        val row = engine(subject).plan(orders("allowTokenIntrospection: true", environment = null), false).changes.single()
        assertThat(row.error).isEqualTo(ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE)
        assertThat(row.fix).isNull()
        assertThat(row.fixNote).isEqualTo(ProvisionEngine.TOKEN_INTROSPECTION_WORKSPACE_NOTE)
    }

    @Test
    fun `an apply-time refusal names the resource, the code and the fix, never a missing scope`() {
        repositoryOwnsOrders()
        api.seedGrant(subject, "manager", "environment:$envId")
        api.nextApplicationWriteProblem = Triple(403, ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE, emptyMap())
        assertThatThrownBy { apply(orders("allowTokenIntrospection: true"), subject) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("application/orders: ${ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE}")
            .hasMessageContaining("thoryn access grant $subject manager environment:$envId")
    }

    // ── SSO-3811 — the DPoP rungs ──

    @Test
    fun `SSO-3811 - dpopAllowed and dpopRequired are sent on create, converged on drift, and never gated`() {
        val f = orders("dpopAllowed: true\ndpopRequired: true")
        apply(f)
        assertThat(api.writes.single { it.method == "POST" && it.path == "/api/v1/applications" }.body)
            .containsEntry("dpopAllowed", true).containsEntry("dpopRequired", true)

        live()["dpopRequired"] = false
        api.reset()
        val row = engine().plan(f, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.diff.keys).containsExactly(ProvisionFile.SPEC_DPOP_REQUIRED)
        apply(f)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("dpopRequired" to true))

        assertThatThrownBy { orders("dpopAllowed: \"yes\"") }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("spec.dpopAllowed")
    }
}

