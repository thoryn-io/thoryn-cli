package com.devnow.thoryn.cli.cmd.examples.recipe

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
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
    }
}
