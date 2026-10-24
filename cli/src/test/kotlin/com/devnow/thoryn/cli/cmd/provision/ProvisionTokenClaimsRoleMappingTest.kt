package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3945 (oauthy SSO-3943) — `tokenClaims.roleMapping`: role name → the value the application receives in its `roles`
 * claim. `PUT …/token-claims` REPLACES the configuration (a body without `roleMapping` stores none), so the engine diffs the
 * sources (a set) and the mapping (a map) together, sends the mapping with EVERY PUT, and plans the removal of a live mapping
 * the file does not declare — out loud. The file refuses exactly what product-api's `RoleMappingRules` refuses, no more.
 */
class ProvisionTokenClaimsRoleMappingTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun forge(tokenClaims: String) = ProvisionFile.parse(
        (
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge
                spec:
                  clientId: forge
                  displayName: "Forge"
                  redirectUris: ["https://forge.acme.example/cb"]
                  tokenClaims: $tokenClaims
            """.trimIndent()
            ).toByteArray(),
        "provision.yaml",
    )

    private fun seedForge(sources: List<String>, mapping: Map<String, String>?) {
        api.seedApplication(null, "Forge", listOf("https://forge.acme.example/cb"), clientId = "forge")
        api.tokenClaims["forge"] = sources
        mapping?.let { api.roleMappings["forge"] = it }
    }

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    private fun puts() = api.writes.filter { it.method == "PUT" && it.path.endsWith("/token-claims") }

    @Test
    fun `a declared role mapping rides on the create's PUT with its roles source, and a second apply is a no-op`() {
        val f = forge("{ sources: [roles], roleMapping: { forge-maintainer: Maintainers } }")
        apply(f)

        assertThat(puts().single().body).isEqualTo(mapOf("sources" to listOf("roles"), "roleMapping" to mapOf("forge-maintainer" to "Maintainers")))
        assertThat(api.roleMappings["forge"]).isEqualTo(mapOf("forge-maintainer" to "Maintainers"))
        assertThat(console.toString()).contains("claims in the token sources [roles] roleMapping {forge-maintainer: Maintainers}")

        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an apply never drops a live mapping the file declares — a change to the sources alone still sends the mapping`() {
        seedForge(listOf("roles"), mapOf("forge-maintainer" to "Maintainers"))
        val f = forge("{ sources: [roles, permissions], roleMapping: { forge-maintainer: Maintainers } }")

        val change = engine().plan(f, false).changes.single()
        assertThat(change.diff).isEqualTo(mapOf("tokenClaims" to "sources [roles] → sources [roles,permissions]"))
        apply(f)

        assertThat(puts().single().body).isEqualTo(
            mapOf("sources" to listOf("roles", "permissions"), "roleMapping" to mapOf("forge-maintainer" to "Maintainers")),
        )
        assertThat(api.tokenClaims["forge"]).containsExactly("roles", "permissions")
        assertThat(api.roleMappings["forge"]).isEqualTo(mapOf("forge-maintainer" to "Maintainers"))
    }

    @Test
    fun `omitting the mapping in the file plans its removal and says why, and the apply removes it`() {
        seedForge(listOf("roles"), mapOf("forge-maintainer" to "Maintainers", "forge-admin" to "Admins"))
        val f = forge("{ sources: [roles] }")

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff).isEqualTo(
            mapOf(
                "tokenClaims" to "roleMapping removed — the file declares none and the PUT replaces the whole configuration: " +
                    "- forge-admin: Admins, - forge-maintainer: Maintainers",
            ),
        )
        apply(f)

        assertThat(puts().single().body).isEqualTo(mapOf("sources" to listOf("roles"), "roleMapping" to null))
        assertThat(api.roleMappings).doesNotContainKey("forge")
        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `entries added, removed and changed are each shown, the mapping is replaced whole, and key order is not drift`() {
        seedForge(listOf("roles"), mapOf("alpha" to "x", "bravo" to "y", "charlie" to "z"))
        val f = forge("{ sources: [roles], roleMapping: { delta: w, bravo: Y2, alpha: x } }")

        assertThat(engine().plan(f, false).changes.single().diff)
            .isEqualTo(mapOf("tokenClaims" to "roleMapping ~ bravo: y → Y2, - charlie: z, + delta: w"))
        apply(f)
        assertThat(api.roleMappings["forge"]).isEqualTo(mapOf("delta" to "w", "bravo" to "Y2", "alpha" to "x"))

        api.reset()
        assertThat(engine().plan(forge("{ sources: [roles], roleMapping: { alpha: x, bravo: Y2, delta: w } }"), false).changes.single().action)
            .isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `switching claims on shows the mapping it brings, and an empty mapping is not the same as none`() {
        api.seedApplication(null, "Forge", listOf("https://forge.acme.example/cb"), clientId = "forge")
        assertThat(engine().plan(forge("{ sources: [roles], roleMapping: { forge-maintainer: Maintainers } }"), false).changes.single().diff)
            .isEqualTo(mapOf("tokenClaims" to "off → sources [roles] roleMapping {forge-maintainer: Maintainers}"))

        api.tokenClaims["forge"] = listOf("roles")
        val empty = forge("{ sources: [roles], roleMapping: {} }")
        assertThat(engine().plan(empty, false).changes.single().diff)
            .isEqualTo(mapOf("tokenClaims" to "roleMapping none → {} (an empty mapping lets no role through)"))
        apply(empty)
        assertThat(puts().single().body).isEqualTo(mapOf("sources" to listOf("roles"), "roleMapping" to emptyMap<String, String>()))
    }

    // ── the file mirrors product-api's RoleMappingRules — no stricter ──

    private fun violations(tc: String) = ProvisionFile.validate(
        YAMLMapper().readTree("apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: a\n    spec:\n      displayName: A\n      tokenClaims: $tc"),
    )

    private fun mappingOf(entries: Map<String, String>) =
        "{ sources: [roles], roleMapping: ${JsonMapper.builder().build().writeValueAsString(entries)} }"

    @Test
    fun `the file accepts every mapping product-api accepts — 100 entries, a 200-character name, a 128-character value, the full value alphabet`() {
        assertThat(violations("{ sources: [roles], roleMapping: { forge-maintainer: Maintainers } }")).isEmpty()
        assertThat(violations("{ sources: [permissions, roles], roleMapping: {} }")).isEmpty()
        assertThat(violations(mappingOf((1..100).associate { "role-$it" to "v$it" }))).isEmpty()
        assertThat(violations(mappingOf(mapOf("r".repeat(200) to "a" + "b".repeat(127))))).isEmpty()
        // A role name is any non-blank text without control characters — spaces and non-ASCII included.
        assertThat(violations(mappingOf(mapOf("Forge Maintainers ✓" to "a.b_c-d:e@f/g", "x" to "0tenant:ok", "y" to "tenantish:fine")))).isEmpty()
    }

    @Test
    fun `the file refuses a mapping product-api would refuse, naming spec tokenClaims roleMapping`() {
        fun refused(tc: String, why: String) =
            assertThat(violations(tc)).anyMatch { it.contains("spec.tokenClaims.roleMapping") && it.contains(why) }

        refused("{ sources: [permissions], roleMapping: { a: b } }", "requires the 'roles' claim source")
        refused("{ roleMapping: { a: b } }", "requires the 'roles' claim source") // the default sources are [permissions]
        refused(mappingOf((1..101).associate { "role-$it" to "v" }), "holds 101 entries; at most 100")
        refused(mappingOf(mapOf("r".repeat(201) to "v")), "1 to 200 characters")
        refused(mappingOf(mapOf("   " to "v")), "not blank")
        refused(mappingOf(mapOf("forge\tadmin" to "v")), "without control characters")
        refused(mappingOf(mapOf("a" to "-leading")), "start with a letter or digit")
        refused(mappingOf(mapOf("a" to "has space")), "contain only letters, digits")
        refused(mappingOf(mapOf("a" to "v".repeat(129))), "1 to 128 characters")
        refused(mappingOf(mapOf("a" to "TENANT:clients.write")), "reserved platform scope prefix")
        refused(mappingOf(mapOf("a" to "holder:x")), "reserved platform scope prefix")
        refused("{ sources: [roles], roleMapping: { a: 1.10 } }", "must be a string — quote it")
        refused("{ sources: [roles], roleMapping: [a, b] }", "must be an object")
    }

    @Test
    fun `the schema pins the same rules the loader enforces`() {
        val json = JsonMapper.builder().build()
        val schema: JsonNode = json.readTree(javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)!!.readBytes())
        val app = schema["\$defs"]["resource"]["allOf"].toList()
            .first { it["if"]["properties"]?.get("kind")?.get("const")?.asString() == "application" && it["if"]["properties"].size() == 1 }
        val tokenClaims = app["then"]["properties"]["spec"]["properties"]["tokenClaims"]
        val mapping = tokenClaims["properties"]["roleMapping"]

        assertThat(mapping["maxProperties"].asInt()).isEqualTo(ProvisionFile.ROLE_MAPPING_MAX_ENTRIES)
        assertThat(mapping["propertyNames"]["maxLength"].asInt()).isEqualTo(ProvisionFile.ROLE_MAPPING_MAX_ROLE_NAME_LENGTH)
        assertThat(mapping["additionalProperties"]["pattern"].asString()).isEqualTo(ProvisionFile.ROLE_MAPPING_VALUE_GRAMMAR.pattern)
        assertThat(tokenClaims.toString()).contains("\"const\":\"roles\"")
    }
}
