package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.cmd.provision.ProvisionException
import com.devnow.thoryn.cli.cmd.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.nio.file.Files
import java.security.MessageDigest

/**
 * SSO-3100 — the files that ship NEXT TO a recipe (`recipes/<id>/…`): today the provisioning file the
 * recipe's `provision` key references. Resolved from the same source the recipe came from — the
 * extracted, signature-verified catalog dir, or the CLI's bundled classpath resources — so a recipe
 * can never pull a sibling from anywhere else. Returns `null` when the file is absent.
 */
internal fun interface RecipeFiles {
    fun read(relativePath: String): ByteArray?

    companion object {
        /** A recipe with no sibling files (a test-constructed recipe). */
        val NONE: RecipeFiles = RecipeFiles { null }

        /** The recipe's bundled classpath directory (`/examples/recipes/<id>/`). */
        fun bundled(id: String): RecipeFiles = RecipeFiles { rel ->
            Recipe::class.java.getResourceAsStream("/examples/recipes/$id/$rel")?.use { it.readBytes() }
        }

        /** The newest cached, previously-verified catalog extraction holding the recipe. */
        fun cached(id: String, catalog: RecipeCatalog): RecipeFiles = RecipeFiles { rel ->
            catalog.cachedAsset(id, rel)?.let { Files.readAllBytes(it) }
        }
    }
}

/**
 * SSO-2871 Phase 1 (SSO-2873) — a parsed recipe.
 *
 * Read as a bundled **JSON** resource (`/examples/recipes/<id>/recipe.json`). Recipes are AUTHORED as
 * YAML; an equivalent `recipe.json` ships alongside (a drift guard test asserts they match) so the
 * CLI runtime needs no YAML parser for the recipe itself. Kept as a thin JsonNode wrapper (no
 * data-class deserialization) so the native image needs no reflection config for a recipe model.
 *
 * SSO-3100 — a recipe may reference a **provisioning file** (`provision: ./provision.yaml`, the
 * `provision.schema.json` desired-state contract) that ships next to it; [provisionFile] loads it
 * through [files], the same source the recipe itself came from.
 */
internal class Recipe(
    val root: JsonNode,
    rawBytes: ByteArray = root.toString().toByteArray(),
    /** SSO-3100 — how sibling files (the provisioning file) are read; [RecipeFiles.NONE] for an in-memory recipe. */
    private val files: RecipeFiles = RecipeFiles.NONE,
) {
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

    /** SSO-3100 — the recipe-relative provisioning file path (`./provision.yaml`), or null when the recipe declares none. */
    val provision: String? get() = root["provision"]?.takeIf { !it.isNull }?.asString()?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * SSO-3100 — load + validate the referenced provisioning file, or `null` when the recipe declares
     * none. The path is confined to the recipe's own directory (no `..` segment, no absolute path) and
     * read through [files] — never from the working directory. Throws [RecipeException] when the recipe
     * names a file that is missing, escapes its directory, or fails `provision.schema.json` validation
     * (a secret-valued key, an unknown kind, …): a recipe with a broken provisioning file never starts.
     */
    fun provisionFile(): ProvisionFile? {
        val declared = provision ?: return null
        val rel = declared.removePrefix("./")
        val segments = rel.split('/')
        if (declared.startsWith("/") || segments.any { it.isBlank() || it == "." || it == ".." }) {
            throw RecipeException("recipe '$id' provision path '$declared' must be a plain recipe-relative path (no '..', not absolute)")
        }
        val bytes = files.read(rel)
            ?: throw RecipeException("recipe '$id' references provisioning file '$declared', which does not ship next to it (recipes/$id/$rel)")
        return try {
            ProvisionFile.parse(bytes, "recipes/$id/$rel", yaml = !rel.endsWith(".json", ignoreCase = true))
        } catch (ex: ProvisionException) {
            throw RecipeException("recipe '$id': ${ex.message}")
        }
    }

    companion object {
        private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

        /** Load a bundled recipe by id, or throw [RecipeException] if none is packaged. */
        fun load(id: String): Recipe {
            val bytes = bundledBytes(id)
                ?: throw RecipeException("no bundled recipe '$id' (/examples/recipes/$id/recipe.json)")
            return of(bytes, RecipeFiles.bundled(id))
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
         * never fetches. SSO-3100: the recipe's sibling provisioning file resolves from the SAME source
         * (the verified catalog dir, or the bundled classpath dir).
         */
        fun resolve(id: String, catalog: RecipeCatalog = RecipeCatalog()): Recipe {
            catalog.cachedRecipeBytes(id)?.let { return of(it, RecipeFiles.cached(id, catalog)) }
            bundledBytes(id)?.let { return of(it, RecipeFiles.bundled(id)) }
            throw RecipeException(
                "no recipe '$id' — it is neither bundled with this CLI nor in the verified catalog cache. " +
                    "Run `thoryn examples update` first to fetch the signed catalog.",
            )
        }

        /** Parse recipe JSON bytes into a [Recipe] (shared by [load] and [resolve] so a bundled and a
         *  catalog-fetched recipe use the identical model). */
        internal fun of(bytes: ByteArray, files: RecipeFiles = RecipeFiles.NONE): Recipe = Recipe(mapper.readTree(bytes), bytes, files)

        private fun bundledBytes(id: String): ByteArray? =
            Recipe::class.java.getResourceAsStream("/examples/recipes/$id/recipe.json")?.use { it.readBytes() }
    }
}
