package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleRegistry
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-2968 — recipe STEPS resolve from the fetched, verified, cached catalog (not only from the
 * bundled jar resources), so a recipe published only in the signed catalog (e.g. `sandbox-signin`)
 * can run through the SAME [RecipeInterpreter] over the SAME closed action allowlist. Resolution
 * order: cached-and-verified first, then bundled, else a clear "run `examples update`" error.
 *
 * The cache dir here is the real one [RecipeCatalog] writes (`~/.config/thoryn/recipes-cache`);
 * [CommandTestBase] points `user.home` at a @TempDir, so writing a `recipe.json` under a tag dir
 * stands in for a previously-verified catalog without re-implementing the Ed25519 fetch/verify.
 */
class RecipeResolutionTest : CommandTestBase() {

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

    /** Write `recipe.json` into the cache dir a real (verified) catalog extraction would produce. */
    private fun writeCachedRecipe(id: String, json: String, tag: String = "v1.0.0-cache") {
        val dir = tempHome.resolve(".config/thoryn/recipes-cache/$tag/recipes/$id")
        Files.createDirectories(dir)
        Files.writeString(dir.resolve("recipe.json"), json)
    }

    private fun sandboxSigninRecipe(id: String = "sandbox-signin", version: String = "9.9.9"): String = """
        {
          "apiVersion": "thoryn.io/examples/v1",
          "id": "$id",
          "version": "$version",
          "summary": "catalog-only sign-in recipe",
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
    fun `a catalog-only recipe present in the verified cache runs setup through the interpreter`() {
        writeCachedRecipe("sandbox-signin", sandboxSigninRecipe())
        val ctx = context()
        // Workspace-less recipe → the caller's own token; only the app create, verify, and attest calls.
        server.enqueue(jsonResponse(201, """{"clientId":"cat-app-1","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"cat-app-1","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        // The id is NOT bundled — it resolves ONLY from the verified cache, then runs the same interpreter.
        val recipe = Recipe.resolve("sandbox-signin")
        assertThat(recipe.id).isEqualTo("sandbox-signin")
        assertThat(recipe.version).isEqualTo("9.9.9")

        val run = RecipeInterpreter(ctx, recipe, trustPropagationBudgetMs = 2_000).setup()
        assertThat(run.state.example).isEqualTo("sandbox-signin")
        assertThat(run.state.clientId).isEqualTo("cat-app-1")
        assertThat(run.receipt.resources).anyMatch { it.kind == "application" && it.id == "cat-app-1" }
        assertThat(run.receipt.verify).anyMatch { it.assert == "applications.get" && it.passed }

        val appReq = server.takeRequest()
        assertThat(appReq.method).isEqualTo("POST")
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer AT-test")

        // The registry resolves the same catalog-only recipe for the setup/run/teardown verbs.
        val example = ExampleRegistry.byName("sandbox-signin")
        assertThat(example).isNotNull
        assertThat(example!!.name).isEqualTo("sandbox-signin")
    }

    @Test
    fun `a bundled recipe still resolves when nothing is cached`() {
        // No cache written — resolution falls back to the recipe bundled with this CLI version.
        val recipe = Recipe.resolve("simple-signin")
        assertThat(recipe.id).isEqualTo("simple-signin")
        assertThat(recipe.digest).startsWith("sha256:")
        assertThat(ExampleRegistry.byName("simple-signin")).isNotNull
    }

    @Test
    fun `a cached recipe is preferred over a bundled one of the same id`() {
        writeCachedRecipe("simple-signin", sandboxSigninRecipe(id = "simple-signin", version = "99.0.0-from-cache"))
        // The bundled simple-signin exists, but the verified cache wins — proving the resolution order.
        val recipe = Recipe.resolve("simple-signin")
        assertThat(recipe.id).isEqualTo("simple-signin")
        assertThat(recipe.version).isEqualTo("99.0.0-from-cache")
    }

    @Test
    fun `an id that is neither bundled nor cached fails with a run examples update message`() {
        assertThatThrownBy { Recipe.resolve("no-such-recipe-xyz") }
            .isInstanceOf(RecipeException::class.java)
            .hasMessageContaining("no-such-recipe-xyz")
            .hasMessageContaining("thoryn examples update")
        // The registry surfaces the same "not found" as a null (the command layer prints the hint).
        assertThat(ExampleRegistry.byName("no-such-recipe-xyz")).isNull()
    }

    @Test
    fun `a fetched recipe with a non-allowlisted action is still rejected by the interpreter`() {
        // A catalog recipe is DATA over the SAME interpreter: an action outside the closed allowlist is
        // refused exactly as a bundled one would be — a fetched recipe can run nothing extra.
        writeCachedRecipe(
            "danger-recipe",
            """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "danger-recipe",
              "version": "1.0.0",
              "summary": "tries an action outside the allowlist",
              "steps": [
                { "id": "boom", "action": "danger.wipe", "with": { "target": "everything" } }
              ]
            }
            """.trimIndent(),
        )
        val ctx = context()

        val recipe = Recipe.resolve("danger-recipe")
        val ex = runCatching { RecipeInterpreter(ctx, recipe, trustPropagationBudgetMs = 2_000).setup() }.exceptionOrNull()

        assertThat(ex).isInstanceOf(RecipeUnsupportedActionException::class.java)
        assertThat(ex!!.message).contains("danger.wipe")
        // No product API call was made — the interpreter rejected the action before any egress.
        assertThat(server.requestCount).isEqualTo(0)
    }
}
