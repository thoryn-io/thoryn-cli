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
            val bytes = bundledBytes(id)
                ?: throw RecipeException("no bundled recipe '$id' (/examples/recipes/$id/recipe.json)")
            return of(bytes)
        }

        /**
         * SSO-2968 — resolve a recipe's STEPS by id for the run verbs (`setup` / `apply` / `teardown` /
         * `verify`), so a recipe published only in the signed catalog (e.g. `sandbox-signin`) can run —
         * not just the recipes bundled into this CLI jar. Resolution order:
         *
         *   1. a recipe present in the **already-cached, previously-verified** catalog (the same cache
         *      [RecipeCatalog] writes) — parsed with the SAME model [load] uses, so it runs through the
         *      identical [RecipeInterpreter] over the identical closed action allowlist;
         *   2. else the recipe **bundled** with this CLI version (bundled recipes keep working unchanged);
         *   3. else [RecipeException] telling the caller to run `thoryn examples update` first.
         *
         * Signature verification is NOT re-done here: [RecipeCatalog.cachedRecipeBytes] returns bytes
         * ONLY from a catalog dir that was Ed25519-verified against the pinned key at fetch time
         * (`examples update` / `catalog --remote`). Fetching stays EXPLICIT — this reads the cache, it
         * never fetches.
         */
        fun resolve(id: String, catalog: RecipeCatalog = RecipeCatalog()): Recipe {
            catalog.cachedRecipeBytes(id)?.let { return of(it) }
            bundledBytes(id)?.let { return of(it) }
            throw RecipeException(
                "no recipe '$id' — it is neither bundled with this CLI nor in the verified catalog cache. " +
                    "Run `thoryn examples update` first to fetch the signed catalog.",
            )
        }

        /** Parse recipe JSON bytes into a [Recipe] (shared by [load] and [resolve] so a bundled and a
         *  catalog-fetched recipe use the identical model). */
        internal fun of(bytes: ByteArray): Recipe = Recipe(mapper.readTree(bytes), bytes)

        private fun bundledBytes(id: String): ByteArray? =
            Recipe::class.java.getResourceAsStream("/examples/recipes/$id/recipe.json")?.use { it.readBytes() }
    }
}
