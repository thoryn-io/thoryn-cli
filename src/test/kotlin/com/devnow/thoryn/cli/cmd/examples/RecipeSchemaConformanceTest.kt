package com.devnow.thoryn.cli.cmd.examples

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-2871 (Phase 0, SSO-2872) — dogfood the recipe schema against a real example.
 *
 * The bundled `simple-signin` recipe MUST conform to `examples/recipe.schema.json`. The check reads
 * the CLOSED action/assert allowlists **from the schema itself**, so the recipe is literally tied to
 * the schema's product-boundary allowlist (the load-bearing invariant: a recipe can only express
 * supported product APIs). A full JSON-Schema engine is deliberately NOT pulled in at this phase —
 * Phase 5's conformance CI runs the recipe repo's recipes against a standalone validator; here we
 * validate the parts that matter (allowlist membership, required fields, unique step ids, and that
 * every `{{placeholder}}` references a declared param or a prior step).
 */
class RecipeSchemaConformanceTest {

    private val yaml = YAMLMapper()
    private val json = JsonMapper.builder().build()

    private val schema: JsonNode = json.readTree(
        readResource("/examples/recipe.schema.json"),
    )

    private fun readResource(path: String): String =
        javaClass.getResourceAsStream(path)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing test resource $path")

    /** The enum at properties/<container>/items/properties/<field>. */
    private fun allowlist(container: String, field: String): Set<String> =
        schema["properties"][container]["items"]["properties"][field]["enum"].toList().map { it.asString() }.toSet()

    private val placeholder = Regex("""\{\{\s*([a-zA-Z0-9_.]+)\s*}}""")

    /**
     * Structural conformance of a recipe to the schema's contract. Returns human-readable violation
     * messages (empty ⇒ conformant), so the negative tests can assert on WHY a recipe is rejected.
     */
    private fun violations(recipe: JsonNode): List<String> {
        val v = mutableListOf<String>()

        if (recipe["apiVersion"]?.asString() != "thoryn.io/examples/v1") v += "apiVersion must be thoryn.io/examples/v1"
        val id = recipe["id"]?.asString()
        if (id.isNullOrBlank()) v += "id is required"
        if (recipe["version"]?.asString()?.matches(Regex("""^\d+\.\d+\.\d+$""")) != true) v += "version must be semver"
        if (recipe["summary"]?.asString().isNullOrBlank()) v += "summary is required"

        val steps = recipe["steps"]?.toList() ?: emptyList()
        if (steps.isEmpty()) v += "steps must be non-empty"

        val stepActions = allowlist("steps", "action")
        val assertActions = allowlist("verify", "assert")
        val teardownActions = allowlist("teardown", "action")

        val stepIds = mutableListOf<String>()
        steps.forEach { step ->
            val sid = step["id"]?.asString()
            if (sid.isNullOrBlank()) v += "each step needs an id"
            else stepIds += sid
            val action = step["action"]?.asString()
            if (action == null || action !in stepActions) v += "step '${sid ?: "?"}' action '$action' not in the allowlist $stepActions"
        }
        if (stepIds.size != stepIds.toSet().size) v += "step ids must be unique: $stepIds"

        recipe["verify"]?.toList()?.forEach { a ->
            val assertion = a["assert"]?.asString()
            if (assertion == null || assertion !in assertActions) v += "verify assert '$assertion' not in $assertActions"
        }
        recipe["teardown"]?.toList()?.forEach { t ->
            val action = t["action"]?.asString()
            if (action == null || action !in teardownActions) v += "teardown action '$action' not in $teardownActions"
        }

        // Every {{placeholder}} must reference a declared param, a (prior) step id, or the reserved
        // `generate` namespace the interpreter resolves ({{generate.slug8}} / {{generate.uuid}}, SSO-2873).
        val params = recipe["params"]?.toList()?.mapNotNull { it["name"]?.asString() }?.toSet() ?: emptySet()
        val knownRoots = params + stepIds.toSet() + "generate"
        placeholder.findAll(recipe.toString()).forEach { m ->
            val root = m.groupValues[1].substringBefore('.')
            if (root !in knownRoots) v += "placeholder '{{${m.groupValues[1]}}}' references unknown '$root' (params=$params steps=$stepIds)"
        }
        return v
    }

    @Test
    fun `the bundled simple-signin recipe conforms to the schema`() {
        val recipe = yaml.readTree(readResource("/examples/recipes/simple-signin/recipe.yaml"))
        assertThat(violations(recipe)).isEmpty()
    }

    @Test
    fun `the bundled ci-signin recipe conforms to the schema`() {
        // SSO-2944 — the workspace-less recipe is structurally conformant: its only step
        // (applications.create), its verify (applications.get), and its teardown (applications.delete)
        // are all in the closed allowlists, and it declares NO hub.createWorkspace / hub.deleteWorkspace.
        val recipe = yaml.readTree(readResource("/examples/recipes/ci-signin/recipe.yaml"))
        assertThat(violations(recipe)).isEmpty()
        val actions = recipe["steps"].toList().map { it["action"].asString() }
        assertThat(actions).doesNotContain("hub.createWorkspace")
        assertThat(recipe["teardown"].toList().map { it["action"].asString() }).doesNotContain("hub.deleteWorkspace")
    }

    @Test
    fun `every step action in simple-signin is in the schema allowlist`() {
        val recipe = yaml.readTree(readResource("/examples/recipes/simple-signin/recipe.yaml"))
        val used = recipe["steps"].toList().map { it["action"].asString() }
        assertThat(allowlist("steps", "action")).containsAll(used)
    }

    @Test
    fun `identity registerUser is a supported step action and a recipe using it conforms`() {
        // SSO-2907 — the create-user action is in the closed allowlist…
        assertThat(allowlist("steps", "action")).contains("identity.registerUser")
        // …and a recipe that provisions a user under a workspace is structurally conformant.
        val recipe = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: register-user
            version: 1.0.0
            summary: provision a sign-in-able user
            steps:
              - { id: ws, action: hub.createWorkspace, with: { slug: "ex-{{generate.slug8}}" } }
              - { id: user, action: identity.registerUser, with: { email: "u@{{ws.slug}}.example", password: pw, emailVerified: true } }
            """.trimIndent(),
        )
        assertThat(violations(recipe)).isEmpty()
    }

    @Test
    fun `a recipe using an action outside the allowlist is rejected`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: rogue
            version: 1.0.0
            summary: tries a non-product action
            steps:
              - { id: seed, action: db.seedClient, with: { clientId: x } }
            """.trimIndent(),
        )
        assertThat(violations(bad)).anyMatch { it.contains("db.seedClient") && it.contains("allowlist") }
    }

    @Test
    fun `a recipe missing required fields is rejected`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            version: 1.0.0
            summary: no id, no steps
            """.trimIndent(),
        )
        assertThat(violations(bad)).contains("id is required", "steps must be non-empty")
    }

    @Test
    fun `a placeholder referencing an unknown root is rejected`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: dangling
            version: 1.0.0
            summary: references an undeclared param
            steps:
              - { id: app, action: applications.create, with: { displayName: "{{nope}}" } }
            """.trimIndent(),
        )
        assertThat(violations(bad)).anyMatch { it.contains("{{nope}}") }
    }
}
