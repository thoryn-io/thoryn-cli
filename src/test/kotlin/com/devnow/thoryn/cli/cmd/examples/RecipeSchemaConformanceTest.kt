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

        // SSO-3100 — a recipe declares a provisioning file, steps, or both (the schema's top-level anyOf):
        // `steps` is omitted (not empty) when the provisioning file carries everything.
        val provision = recipe["provision"]?.takeIf { !it.isNull }?.asString()
        val provisionPattern = Regex(schema["properties"]["provision"]["pattern"].asString())
        if (provision != null && !provisionPattern.matches(provision)) v += "provision '$provision' must be a recipe-relative .yaml/.yml/.json path"
        val steps = recipe["steps"]?.toList() ?: emptyList()
        if (steps.isEmpty() && provision == null) v += "steps must be non-empty"
        else if (steps.isEmpty() && recipe.has("steps")) v += "steps must be omitted, not empty, when the provisioning file carries everything"

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
        // SSO-3100 — `{{provision.<kind>.<name>.<field>}}` addresses what the provisioning file created.
        val knownRoots = params + stepIds.toSet() + "generate" + (if (provision != null) setOf("provision") else emptySet())
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
    fun `clients createMachine is NOT an example-recipe step action`() {
        // SSO-2952 — secret-bearing machine-client provisioning was relocated OFF the example-recipe
        // surface, reverting the SSO-2950 allowlist widening; SSO-3113 then retired the `provision
        // ci-identity` command it moved to, so a machine client is DECLARED in a provisioning file and
        // minted by `provision apply --secret-file`. Either way a recipe that tries to mint one is
        // rejected — the closed allowlist keeps every recipe DATA producing a secret-free receipt.
        assertThat(allowlist("steps", "action")).doesNotContain("clients.createMachine")
        assertThat(allowlist("verify", "assert")).doesNotContain("clients.createMachine")
        assertThat(allowlist("teardown", "action")).doesNotContain("clients.createMachine")
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: rogue-machine
            version: 1.0.0
            summary: tries to mint a secret-bearing machine client from a recipe
            steps:
              - { id: mc, action: clients.createMachine, with: { clientType: confidential, grantTypes: ["client_credentials"] } }
            """.trimIndent(),
        )
        assertThat(violations(bad)).anyMatch { it.contains("clients.createMachine") && it.contains("allowlist") }
    }

    @Test
    fun `env delete is a supported teardown action and an ephemeral-sandbox recipe conforms`() {
        // SSO-2961 — the teardown allowlist carries `env.delete` (product-api DELETE /environments/{id},
        // SSO-2960), and env.create stays in the step allowlist, so an ephemeral-sandbox recipe that
        // provisions into a fresh sandbox and hard-deletes it on teardown is structurally conformant.
        assertThat(allowlist("teardown", "action")).contains("env.delete")
        assertThat(allowlist("steps", "action")).contains("env.create")
        val recipe = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: ephemeral-sandbox
            version: 1.0.0
            summary: provision into an ephemeral sandbox and hard-delete it on teardown
            steps:
              - { id: env, action: env.create, with: { slug: "sbx-{{generate.slug8}}", name: Ephemeral } }
              - { id: app, action: applications.create, with: { displayName: RP, redirectUris: ["http://127.0.0.1/cb"] } }
            teardown:
              - { action: applications.delete, id: "{{app.clientId}}" }
              - { action: env.delete, id: "{{env.id}}" }
            """.trimIndent(),
        )
        assertThat(violations(recipe)).isEmpty()
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
    fun `a recipe may reference a provisioning file and then needs no steps`() {
        // SSO-3100 — the schema's top-level anyOf: `provision` OR `steps` (or both); `steps` is no longer
        // required, and provisioned resources are addressable as {{provision.<kind>.<name>.<field>}}.
        assertThat(schema["required"].toList().map { it.asString() }).doesNotContain("steps")
        assertThat(schema["anyOf"].toList().map { it["required"][0].asString() }).containsExactlyInAnyOrder("provision", "steps")
        val recipe = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: provisioned-signin
            version: 1.0.0
            summary: everything comes from the provisioning file
            provision: ./provision.yaml
            verify:
              - assert: applications.get
                id: "{{provision.application.rp.clientId}}"
                expect: { status: active }
            """.trimIndent(),
        )
        assertThat(violations(recipe)).isEmpty()
        // A provisioning file plus EXTRA steps is fine too, and the step may reference the provisioned app.
        val withSteps = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: provisioned-plus
            version: 1.0.0
            summary: provisioning file plus an extra step
            provision: provision.yaml
            steps:
              - { id: fed, action: federation.create, with: { providerType: okta, displayName: "Okta for {{provision.application.rp.clientId}}" } }
            """.trimIndent(),
        )
        assertThat(violations(withSteps)).isEmpty()
    }

    @Test
    fun `zero steps is allowed only with a provisioning file, and the provision path stays recipe-relative`() {
        val noSteps = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: empty
            version: 1.0.0
            summary: neither steps nor provision
            """.trimIndent(),
        )
        assertThat(violations(noSteps)).contains("steps must be non-empty")
        val emptySteps = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: empty-steps
            version: 1.0.0
            summary: an explicit empty steps list next to a provisioning file
            provision: ./provision.yaml
            steps: []
            """.trimIndent(),
        )
        assertThat(violations(emptySteps)).anyMatch { it.contains("omitted, not empty") }
        // The schema pattern confines `provision` to the recipe's own directory (no `..`, not absolute).
        val pattern = Regex(schema["properties"]["provision"]["pattern"].asString())
        assertThat(pattern.matches("./provision.yaml")).isTrue()
        assertThat(pattern.matches("infra/provision.yml")).isTrue()
        assertThat(pattern.matches("provision.json")).isTrue()
        assertThat(pattern.matches("../provision.yaml")).isFalse()
        assertThat(pattern.matches("/etc/provision.yaml")).isFalse()
        assertThat(pattern.matches("provision.txt")).isFalse()
        // Without `provision`, a {{provision.*}} placeholder is dangling.
        val dangling = yaml.readTree(
            """
            apiVersion: thoryn.io/examples/v1
            id: dangling-provision
            version: 1.0.0
            summary: references a provisioned app without a provisioning file
            steps:
              - { id: app, action: applications.create, with: { displayName: "{{provision.application.rp.clientId}}" } }
            """.trimIndent(),
        )
        assertThat(violations(dangling)).anyMatch { it.contains("{{provision.application.rp.clientId}}") }
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
