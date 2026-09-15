package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import com.devnow.thoryn.cli.cmd.provision.ProvisionReceiptStore
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files

/**
 * SSO-3100 (epic SSO-3087) — a recipe is an ORCHESTRATION file over a provisioning file: `examples
 * apply` converges the referenced `provision.yaml` FIRST (through the same engine as `thoryn provision
 * apply`, against the in-memory [FakeProductApi]), exposes what it owns as `{{provision.<kind>.<name>.…}}`,
 * runs the recipe's own verify, records the resources on the recipe receipt, and `teardown` destroys
 * everything child-first. A second apply issues no writes; a broken provisioning file fails closed.
 */
class RecipeProvisionOrchestrationTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var stateStore: ExampleStateStore
    private lateinit var recipeDir: File

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        stateStore = ExampleStateStore(dir = tempHome.resolve("examples-state"))
        recipeDir = Files.createDirectory(tempHome.resolve("recipe-src")).toFile()
    }

    private fun context(): ExampleContext {
        val base = Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        return ExampleContext(hub = baseUrl(), gateway = baseUrl(), tokens = base, state = stateStore, out = PrintStream(console), err = PrintStream(console))
    }

    /** A recipe read from a temp dir, its `provision` file resolved NEXT TO it (as the catalog / bundle lay it out). */
    private fun recipe(recipeJson: String, provisionYaml: String?): Recipe {
        provisionYaml?.let { File(recipeDir, "provision.yaml").writeText(it.trimIndent()) }
        val bytes = recipeJson.trimIndent().toByteArray()
        return Recipe(JsonMapper.builder().build().readTree(bytes), bytes, RecipeFiles { rel -> File(recipeDir, rel).takeIf { it.isFile }?.readBytes() })
    }

    private val provisionedRecipe = """
        {
          "apiVersion": "thoryn.io/examples/v1",
          "id": "sandbox-demo",
          "version": "1.0.0",
          "summary": "everything comes from the provisioning file",
          "provision": "./provision.yaml",
          "params": [
            { "name": "workspaceSlug", "prompt": "Standing workspace", "default": "acme" },
            { "name": "envSlug", "prompt": "Sandbox slug", "default": "demo-sbx" },
            { "name": "demoPassword", "prompt": "Demo user password", "default": "Demo-Pw1!", "secret": true }
          ],
          "verify": [
            { "assert": "applications.get", "id": "{{provision.application.rp.clientId}}", "expect": { "status": "active" } }
          ]
        }
    """

    private val provisionYaml = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: sandbox
            spec: { slug: "{{env.envSlug}}", displayName: "Demo sandbox" }
          - kind: application
            name: rp
            environment: sandbox
            spec: { displayName: "Demo RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"], scopes: [openid, profile] }
          - kind: user
            name: demo
            environment: sandbox
            spec: { email: demo@example.com, passwordEnv: demoPassword, emailVerified: true }
          - kind: loginMethods
            environment: sandbox
            spec: { methods: [password, magic_code] }
    """

    @Test
    fun `apply provisions the file first, exposes provision placeholders, and a second apply issues no writes`() {
        val ctx = context()
        val r = recipe(provisionedRecipe, provisionYaml)
        val example = RecipeExample(r, receiptStore = ReceiptStore(dir = tempHome.resolve("receipts")))

        assertThat(example.setup(ctx)).isEqualTo(0)

        // Environment first (production plane), then its dependants INSIDE the sandbox whose slug came from the recipe param.
        assertThat(api.provisioningWrites.map { it.method + " " + it.path }).containsExactly(
            "POST /api/v1/environments", "POST /api/v1/applications", "POST /api/v1/users", "PUT /api/v1/login-methods",
        )
        assertThat(api.provisioningWrites[0].body["slug"]).isEqualTo("demo-sbx")
        assertThat(api.provisioningWrites.drop(1).map { it.env }).allMatch { it == "demo-sbx" }
        // The secret param fed `passwordEnv: demoPassword` — sent to the API, never persisted anywhere.
        assertThat(api.provisioningWrites[2].body["password"]).isEqualTo("Demo-Pw1!")
        assertThat(api.provisioningWrites[3].body["methods"]).isEqualTo(listOf("password", "magic_code"))
        // The caller's OWN token throughout (workspace-less recipe) — no workspace create, no exchange.
        assertThat(server.requestCount).isGreaterThan(4)

        // The provisioning receipt lives next to the example state, and carries no secret.
        val receiptPath = stateStore.provisionReceiptPath("sandbox-demo").toFile()
        assertThat(receiptPath).exists()
        assertThat(receiptPath.readText()).doesNotContain("Demo-Pw1!")
        val provisionReceipt = ProvisionReceiptStore().read(receiptPath)!!
        assertThat(provisionReceipt.resources.map { it.key }).containsExactly("environment/sandbox", "application/rp", "user/demo", "loginMethods/loginMethods")
        assertThat(provisionReceipt.workspace).isEqualTo("acme")

        // The recipe's verify resolved {{provision.application.rp.clientId}} and passed.
        val clientId = provisionReceipt.resources[1].id
        val receipt = ReceiptStore(dir = tempHome.resolve("receipts")).read("sandbox-demo")!!
        assertThat(receipt.verify).containsExactly(VerifyResult("applications.get", clientId, mapOf("status" to "active"), passed = true))
        // Every provisioned resource is on the recipe receipt (kind / id / non-secret attributes).
        assertThat(receipt.resources.map { it.kind }).containsExactly("environment", "application", "user", "loginMethods")
        assertThat(receipt.resources[0].attributes).containsEntry("slug", "demo-sbx").containsEntry("name", "sandbox")
        assertThat(receipt.resources[2].attributes).containsEntry("email", "demo@example.com").doesNotContainKey("password")
        assertThat(receipt.environment).isEqualTo("demo-sbx")
        assertThat(receipt.attestation).isNotNull

        // `examples run` finds the client id + the sandbox from the provisioning result (no applications.create step).
        val state = stateStore.read("sandbox-demo")!!
        assertThat(state.clientId).isEqualTo(clientId)
        assertThat(state.redirectUri).isEqualTo("http://127.0.0.1/callback")
        assertThat(state.environmentSlug).isEqualTo("demo-sbx")
        assertThat(state.environmentId).isNull() // the provisioning destroy owns the sandbox; env.delete must not double-delete
        assertThat(state.workspaceSlug).isEqualTo("acme")
        assertThat(console.toString()).contains("[provision] ./provision.yaml").contains("environment: demo-sbx")

        // A second apply (fresh interpreter, same receipt) converges to a no-op: NO provisioning writes.
        api.reset()
        RecipeInterpreter(ctx, r, trustPropagationBudgetMs = 2_000).setup()
        assertThat(api.provisioningWrites).isEmpty()
        assertThat(console.toString()).contains("0 to create, 0 to update, 0 to adopt, 4 unchanged")
    }

    @Test
    fun `teardown destroys everything the provisioning file created, child-first, and clears the receipts`() {
        val ctx = context()
        val r = recipe(provisionedRecipe, provisionYaml)
        val example = RecipeExample(r, receiptStore = ReceiptStore(dir = tempHome.resolve("receipts")))
        assertThat(example.setup(ctx)).isEqualTo(0)
        val owned = ProvisionReceiptStore().read(stateStore.provisionReceiptPath("sandbox-demo").toFile())!!.resources
        api.reset()

        assertThat(example.teardown(ctx)).isEqualTo(0)

        // Reverse creation order, the sandbox last (its hard-delete is confirmed by its OWN slug).
        assertThat(api.provisioningWrites.map { it.method + " " + it.path }).containsExactly(
            "DELETE /api/v1/login-methods",
            "DELETE /api/v1/users/${owned[2].id}",
            "DELETE /api/v1/applications/${owned[1].id}",
            "DELETE /api/v1/environments/${owned[0].id}",
        )
        assertThat(api.provisioningWrites.last().confirm).isEqualTo("demo-sbx")
        assertThat(api.environments).isEmpty()
        assertThat(api.applications).isEmpty()
        assertThat(api.users).isEmpty()
        assertThat(api.loginMethods).isEmpty()
        // Nothing owned remains: provisioning receipt, recipe receipt and state are all gone.
        assertThat(stateStore.provisionReceiptPath("sandbox-demo").toFile()).doesNotExist()
        assertThat(stateStore.read("sandbox-demo")).isNull()
        assertThat(ReceiptStore(dir = tempHome.resolve("receipts")).read("sandbox-demo")).isNull()
    }

    @Test
    fun `a failed removal keeps the provisioning receipt and the example state for a retry`() {
        val ctx = context()
        val r = recipe(provisionedRecipe, provisionYaml)
        val example = RecipeExample(r, receiptStore = ReceiptStore(dir = tempHome.resolve("receipts")))
        assertThat(example.setup(ctx)).isEqualTo(0)
        // Someone deleted the sandbox out of band → the environment hard-delete 404s.
        api.environments.clear()

        assertThat(example.teardown(ctx)).isNotEqualTo(0)

        val remaining = ProvisionReceiptStore().read(stateStore.provisionReceiptPath("sandbox-demo").toFile())!!
        assertThat(remaining.resources.map { it.kind }).containsExactly("environment")
        assertThat(stateStore.read("sandbox-demo")).isNotNull
        assertThat(console.toString()).contains("re-run `thoryn examples teardown sandbox-demo`")
    }

    @Test
    fun `a provisioning file with a secret value or an unknown kind fails closed before any write`() {
        val ctx = context()
        val secret = recipe(
            provisionedRecipe,
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: user, name: demo, spec: { email: demo@example.com, password: "hunter2" } }
            """,
        )
        assertThatThrownBy { RecipeInterpreter(ctx, secret, trustPropagationBudgetMs = 2_000).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("spec.password")
            .hasMessageContaining("passwordEnv")
        assertThat(api.provisioningWrites).isEmpty()

        val unknownKind = recipe(
            provisionedRecipe,
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: dbSeed, name: x, spec: { table: client } }
            """,
        )
        assertThatThrownBy { RecipeInterpreter(ctx, unknownKind, trustPropagationBudgetMs = 2_000).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("dbSeed")
            .hasMessageContaining("allowlist")
        assertThat(api.provisioningWrites).isEmpty()

        // A declared file that does not ship next to the recipe, or escapes its directory, is refused too.
        File(recipeDir, "provision.yaml").delete()
        val missing = recipe(provisionedRecipe, null)
        assertThatThrownBy { RecipeInterpreter(ctx, missing, trustPropagationBudgetMs = 2_000).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("does not ship next to it")
        val escaping = recipe(provisionedRecipe.replace("./provision.yaml", "../provision.yaml"), provisionYaml)
        assertThatThrownBy { RecipeInterpreter(ctx, escaping, trustPropagationBudgetMs = 2_000).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("recipe-relative")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `an unset secret env var fails closed, and a process env var is the fallback after recipe params`() {
        val ctx = context()
        val noParam = recipe(provisionedRecipe.replace("""{ "name": "demoPassword", "prompt": "Demo user password", "default": "Demo-Pw1!", "secret": true }""", """{ "name": "unused", "prompt": "x", "default": "y" }"""), provisionYaml)
        // Neither a recipe param nor the process env carries `demoPassword` → refused before the user create.
        assertThatThrownBy { RecipeInterpreter(ctx, noParam, trustPropagationBudgetMs = 2_000, provisionEnv = { null }).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("demoPassword")
            .hasMessageContaining("not set")
        // Fail-closed happened mid-apply: the environment + app are owned (receipt persisted), the user never created.
        assertThat(api.users).isEmpty()
        assertThat(ProvisionReceiptStore().read(stateStore.provisionReceiptPath("sandbox-demo").toFile())!!.resources.map { it.kind })
            .containsExactly("environment", "application")

        // With the value in the process environment the same run converges (env + app adopted, user created).
        api.reset()
        RecipeInterpreter(ctx, noParam, trustPropagationBudgetMs = 2_000, provisionEnv = { if (it == "demoPassword") "From-Env-1!" else null }).setup()
        assertThat(api.provisioningWrites.map { it.method + " " + it.path }).containsExactly("POST /api/v1/users", "PUT /api/v1/login-methods")
        assertThat(api.provisioningWrites[0].body["password"]).isEqualTo("From-Env-1!")
    }

    @Test
    fun `a recipe that creates its own workspace cannot also carry a provisioning file`() {
        val ctx = context()
        val r = recipe(
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "ws-plus-provision",
              "version": "1.0.0",
              "summary": "invalid combination",
              "provision": "./provision.yaml",
              "steps": [ { "id": "ws", "action": "hub.createWorkspace", "with": { "slug": "ex-{{generate.slug8}}" } } ]
            }
            """,
            provisionYaml,
        )
        assertThatThrownBy { RecipeInterpreter(ctx, r, trustPropagationBudgetMs = 2_000).setup() }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("hub.createWorkspace")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `a bundled recipe resolves its sibling provisioning file from the classpath`() {
        // The test-resource fixture mirrors the bundle layout: examples/recipes/<id>/{recipe.json,provision.yaml}.
        val r = Recipe.load("provisioned-fixture")
        assertThat(r.provision).isEqualTo("./provision.yaml")
        val file = r.provisionFile()!!
        assertThat(file.source).isEqualTo("recipes/provisioned-fixture/provision.yaml")
        assertThat(file.resources.map { it.key }).containsExactly("environment/sandbox", "application/rp")
        // A recipe without `provision` (the shipped ones) has none — behaviour unchanged.
        assertThat(Recipe.load("simple-signin").provision).isNull()
        assertThat(Recipe.load("simple-signin").provisionFile()).isNull()
    }
}
