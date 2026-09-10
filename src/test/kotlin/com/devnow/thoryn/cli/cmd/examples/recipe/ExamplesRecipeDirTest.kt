package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import com.devnow.thoryn.cli.cmd.examples.ExamplesCommand
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-2967 — `examples apply|verify|teardown --recipe-dir <path>` runs a recipe authored in
 * `thoryn-examples` straight from a checked-out directory, WITHOUT bundling it into the CLI. These
 * tests exercise the loader's resolution semantics, prove an external recipe runs through the SAME
 * interpreter (and records its provenance on the receipt), and prove the closed action allowlist still
 * gates an external recipe.
 */
class ExamplesRecipeDirTest : CommandTestBase() {

    private fun context(): ExampleContext {
        val base = Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        return ExampleContext(
            hub = baseUrl(),
            gateway = baseUrl(),
            tokens = base,
            state = ExampleStateStore(dir = tempHome.resolve("examples-state")),
        )
    }

    /** A workspace-less external recipe (caller's own token; no workspace create / token-exchange). */
    private val externalRecipeJson = """
        {
          "apiVersion": "thoryn.io/examples/v1",
          "id": "external-signin-test",
          "version": "1.0.0",
          "summary": "external recipe run straight from a checked-out directory",
          "steps": [
            { "id": "app", "action": "applications.create",
              "with": { "displayName": "RP", "redirectUris": ["http://127.0.0.1/cb"] } }
          ],
          "verify": [
            { "assert": "applications.get", "id": "{{app.clientId}}", "expect": { "status": "active" } }
          ]
        }
    """.trimIndent()

    @Test
    fun `a recipe loaded from a --recipe-dir directory runs through the interpreter and records its source`() {
        val dir = Files.createDirectories(tempHome.resolve("thoryn-examples/external-signin-test"))
        val recipeFile = dir.resolve("recipe.json")
        Files.writeString(recipeFile, externalRecipeJson)

        // The command's loader resolves <dir>/recipe.json and stamps the provenance the receipt records.
        val loaded = ExamplesCommand.loadRecipe(name = null, recipeDir = dir.toFile())
        assertThat(loaded.recipe.id).isEqualTo("external-signin-test")
        assertThat(loaded.source).isEqualTo("recipe-dir:${recipeFile.toAbsolutePath()}")

        val ctx = context()
        // applications.create (caller's own token) → verify applications.get → best-effort attestation.
        server.enqueue(jsonResponse(201, """{"clientId":"app-ext","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-ext","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(
            ctx, loaded.recipe, source = loaded.source, trustPropagationBudgetMs = 2_000,
        ).setup()

        assertThat(run.state.example).isEqualTo("external-signin-test")
        assertThat(run.state.clientId).isEqualTo("app-ext")
        assertThat(run.receipt.resources).anyMatch { it.kind == "application" && it.id == "app-ext" }
        assertThat(run.receipt.verify).anyMatch { it.assert == "applications.get" && it.passed }
        // SSO-2967 — the receipt records that this run came from a --recipe-dir, not the bundled catalog.
        assertThat(run.receipt.source).isEqualTo("recipe-dir:${recipeFile.toAbsolutePath()}")

        // Drove the SAME product-API calls a bundled recipe would, with the caller's own token.
        val appReq = server.takeRequest()
        assertThat(appReq.method).isEqualTo("POST")
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-ext")
    }

    @Test
    fun `--recipe-dir resolves the id-nested recipe when the directory is a catalog root`() {
        val catalogRoot = Files.createDirectories(tempHome.resolve("thoryn-examples-catalog"))
        val nested = Files.createDirectories(catalogRoot.resolve("external-signin-test"))
        val recipeFile = nested.resolve("recipe.json")
        Files.writeString(recipeFile, externalRecipeJson)

        // No recipe.json directly under the root — resolution falls back to <root>/<name>/recipe.json.
        val loaded = ExamplesCommand.loadRecipe(name = "external-signin-test", recipeDir = catalogRoot.toFile())
        assertThat(loaded.recipe.id).isEqualTo("external-signin-test")
        assertThat(loaded.source).isEqualTo("recipe-dir:${recipeFile.toAbsolutePath()}")
    }

    @Test
    fun `--recipe-dir pointing at a missing recipe fails with a clear error naming the paths tried`() {
        val emptyDir = Files.createDirectories(tempHome.resolve("no-recipe-here"))

        assertThatThrownBy { Recipe.resolveExternalRecipeFile(emptyDir, "sandbox-signin") }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining(emptyDir.resolve("recipe.json").toString())
            .hasMessageContaining(emptyDir.resolve("sandbox-signin").resolve("recipe.json").toString())

        // The command-level loader surfaces the same failure (so `apply`/`verify`/`teardown` can report it).
        assertThatThrownBy { ExamplesCommand.loadRecipe(name = "sandbox-signin", recipeDir = emptyDir.toFile()) }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("no recipe.json under --recipe-dir")
    }

    @Test
    fun `an external recipe using a non-allowlisted action is still rejected by the interpreter`() {
        // SSO-2967 — an external recipe is DATA over the SAME closed action allowlist. A step naming an
        // action the interpreter does not dispatch is rejected, and no product-API call is made — the
        // product-boundary guarantee holds regardless of where the recipe was loaded from.
        val dir = Files.createDirectories(tempHome.resolve("thoryn-examples/rogue"))
        Files.writeString(
            dir.resolve("recipe.json"),
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "rogue-recipe",
              "version": "1.0.0",
              "summary": "tries an action the interpreter never dispatches",
              "steps": [
                { "id": "boom", "action": "database.seed",
                  "with": { "table": "clients", "row": { "clientId": "backdoor" } } }
              ]
            }
            """.trimIndent(),
        )

        val loaded = ExamplesCommand.loadRecipe(name = null, recipeDir = dir.toFile())
        val ctx = context()

        assertThatThrownBy {
            RecipeInterpreter(ctx, loaded.recipe, source = loaded.source, trustPropagationBudgetMs = 2_000).setup()
        }
            .isInstanceOf(RecipeUnsupportedActionException::class.java)
            .hasMessageContaining("database.seed")
        assertThat(server.requestCount).isEqualTo(0)
    }
}
