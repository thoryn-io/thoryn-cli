package com.devnow.thoryn.cli.cmd.examples.recipe

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * SSO-2871 Phase 1 (SSO-2873) — a parsed recipe.
 *
 * Read as a bundled **JSON** resource (`/examples/recipes/<id>/recipe.json`). Recipes are AUTHORED as
 * YAML; an equivalent `recipe.json` ships alongside (a drift guard test asserts they match) so the
 * CLI runtime needs no YAML parser and the GraalVM native image is unchanged. Kept as a thin JsonNode
 * wrapper (no data-class deserialization) so the native image needs no reflection config for a recipe
 * model.
 */
internal class Recipe(val root: JsonNode, rawBytes: ByteArray = root.toString().toByteArray()) {
    val id: String get() = root["id"].asString()
    val summary: String get() = root["summary"].asString()
    val version: String get() = root["version"].asString()

    /** SSO-2875 — `sha256:<hex>` over the recipe's bytes, recorded in a run's receipt to pin exactly
     *  which recipe (and version) was applied. */
    val digest: String = "sha256:" + MessageDigest.getInstance("SHA-256").digest(rawBytes)
        .joinToString("") { "%02x".format(it) }
    val params: List<JsonNode> get() = root["params"]?.toList().orEmpty()
    val steps: List<JsonNode> get() = root["steps"]?.toList().orEmpty()
    val verify: List<JsonNode> get() = root["verify"]?.toList().orEmpty()
    val teardown: List<JsonNode> get() = root["teardown"]?.toList().orEmpty()

    companion object {
        private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

        /** Load a bundled recipe by id, or throw [RecipeException] if none is packaged. */
        fun load(id: String): Recipe {
            val path = "/examples/recipes/$id/recipe.json"
            val bytes = Recipe::class.java.getResourceAsStream(path)?.use { it.readBytes() }
                ?: throw RecipeException("no bundled recipe '$id' ($path)")
            return Recipe(mapper.readTree(bytes), bytes)
        }

        /**
         * SSO-2967 — resolve an EXTERNAL recipe file authored in `thoryn-examples` (not bundled),
         * checked out on disk. Callers may pass either the recipe's own directory (`<dir>/recipe.json`)
         * or a catalog root (`<dir>/<id>/recipe.json`). Prefers the direct file; falls back to the
         * `<id>`-nested one when an [id] is supplied. Throws [RecipeException] naming the paths tried
         * when neither exists.
         */
        fun resolveExternalRecipeFile(dir: Path, id: String?): Path {
            val direct = dir.resolve("recipe.json")
            if (Files.isRegularFile(direct)) return direct
            val nested = id?.let { dir.resolve(it).resolve("recipe.json") }
            if (nested != null && Files.isRegularFile(nested)) return nested
            throw RecipeException(
                "no recipe.json under --recipe-dir '$dir' (tried '$direct'" +
                    (nested?.let { " and '$it'" }
                        ?: "; pass a recipe name to also try '<dir>/<name>/recipe.json'") + ")",
            )
        }

        /**
         * SSO-2967 — parse a recipe from a file on disk, EXACTLY as [load] parses a bundled resource
         * (same JsonNode wrapper, same byte-digest). An external recipe is therefore DATA over the same
         * model + interpreter as a bundled one — the interpreter's closed action allowlist still gates
         * execution. Throws [RecipeException] on unreadable/invalid content.
         */
        fun loadFromFile(file: Path): Recipe {
            val bytes = try {
                Files.readAllBytes(file)
            } catch (ex: Exception) {
                throw RecipeException("could not read recipe file '$file' (${ex.message})")
            }
            return try {
                Recipe(mapper.readTree(bytes), bytes)
            } catch (ex: Exception) {
                throw RecipeException("recipe file '$file' is not valid JSON (${ex.message})")
            }
        }
    }
}
