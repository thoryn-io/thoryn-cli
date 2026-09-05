package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.config.ThorynConfig
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import tools.jackson.databind.json.JsonMapper
import java.io.ByteArrayInputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Base64
import java.util.zip.ZipInputStream
import kotlin.io.path.Path

/** SSO-2874 — a fetch/verify failure for the remote recipe catalog. */
internal class RecipeCatalogException(message: String) : RuntimeException(message)

/** A recipe as advertised by the (verified) remote catalog. */
internal data class RemoteRecipe(val id: String, val version: String, val summary: String)

/** The outcome of a verified catalog fetch: the resolved tag, the cache dir, and the recipes it holds. */
internal data class CatalogInfo(val tag: String, val dir: Path, val recipes: List<RemoteRecipe>)

/**
 * SSO-2874 — fetches the recipe catalog from the public `thoryn-examples` GitHub releases, **verifies
 * its Ed25519 signature against the pinned key before using anything**, and caches the extracted
 * recipes. A tampered/unsigned bundle is refused (nothing extracted). The bundle ships `recipe.json`
 * (generated from the authored YAML by the release workflow) so the CLI needs no runtime YAML parser.
 *
 * Fetching is EXPLICIT (`examples catalog --remote` / `examples update`); the CLI otherwise uses its
 * bundled recipes, so normal/CI/offline use makes no network call.
 */
internal class RecipeCatalog(
    private val apiBase: String = ThorynConfig.EXAMPLES_RELEASE_API,
    private val repo: String = ThorynConfig.EXAMPLES_REPO,
    private val publicKeySpkiB64: String = ThorynConfig.EXAMPLES_SIGNING_PUBLIC_KEY_SPKI_B64,
    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build(),
    private val mapper: ObjectMapper = JsonMapper.builder().build(),
    private val cacheDir: Path = defaultCacheDir(),
) {
    /** Fetch + verify + cache the signed catalog for [tag] (null = the latest release). */
    fun update(tag: String?): CatalogInfo {
        val release = getRelease(tag)
        val zipUrl = assetUrl(release, "catalog.zip")
            ?: throw RecipeCatalogException("the release has no 'catalog.zip' asset")
        val sigUrl = assetUrl(release, "catalog.zip.sig")
            ?: throw RecipeCatalogException("the release has no 'catalog.zip.sig' asset — unsigned catalogs are refused")

        val zipBytes = download(zipUrl)
        val signature = decodeSignature(download(sigUrl))
        if (!Ed25519Verifier.verify(publicKeySpkiB64, zipBytes, signature)) {
            throw RecipeCatalogException(
                "catalog signature did NOT verify against the pinned release key — refusing (the bundle was tampered with, or signed by a different key).",
            )
        }

        val tagName = release["tag_name"]?.asString() ?: (tag ?: "latest")
        val dir = cacheDir.resolve(sanitize(tagName))
        extractZip(zipBytes, dir)
        return CatalogInfo(tagName, dir, listRecipes(dir))
    }

    // ── GitHub release API ──────────────────────────────────────────────────────────────────────

    private fun getRelease(tag: String?): JsonNode {
        val path = if (tag == null) "/repos/$repo/releases/latest" else "/repos/$repo/releases/tags/$tag"
        val body = getString("${apiBase.trimEnd('/')}$path")
        return mapper.readTree(body)
    }

    private fun assetUrl(release: JsonNode, name: String): String? =
        release["assets"]?.toList().orEmpty()
            .firstOrNull { it["name"]?.asString() == name }
            ?.get("browser_download_url")?.asString()

    private fun getString(url: String): String {
        val response = http.send(request(url).build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw RecipeCatalogException("GET $url returned HTTP ${response.statusCode()}")
        }
        return response.body()
    }

    private fun download(url: String): ByteArray {
        val response = http.send(request(url).build(), HttpResponse.BodyHandlers.ofByteArray())
        if (response.statusCode() !in 200..299) {
            throw RecipeCatalogException("download $url returned HTTP ${response.statusCode()}")
        }
        return response.body()
    }

    private fun request(url: String): HttpRequest.Builder =
        HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(30))
            .header("Accept", "application/json")
            .header("User-Agent", "thoryn-cli") // GitHub requires a User-Agent.
            .GET()

    /** The `.sig` asset carries the base64 of the raw 64-byte Ed25519 signature. */
    private fun decodeSignature(bytes: ByteArray): ByteArray =
        try {
            Base64.getDecoder().decode(String(bytes, Charsets.UTF_8).trim())
        } catch (ex: Exception) {
            throw RecipeCatalogException("the signature asset is not valid base64 (${ex.message})")
        }

    // ── extract + list ───────────────────────────────────────────────────────────────────────────

    private fun extractZip(zipBytes: ByteArray, dir: Path) {
        if (Files.exists(dir)) dir.toFile().deleteRecursively()
        Files.createDirectories(dir)
        ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val target = dir.resolve(entry.name).normalize()
                if (!target.startsWith(dir)) throw RecipeCatalogException("zip entry escapes the cache dir: ${entry.name}") // zip-slip guard
                if (entry.isDirectory) {
                    Files.createDirectories(target)
                } else {
                    Files.createDirectories(target.parent)
                    Files.newOutputStream(target).use { zis.copyTo(it) }
                }
                entry = zis.nextEntry
            }
        }
    }

    /** Read `recipes/<id>/recipe.json` from an extracted catalog. */
    private fun listRecipes(dir: Path): List<RemoteRecipe> {
        val recipesDir = dir.resolve("recipes")
        if (!Files.isDirectory(recipesDir)) return emptyList()
        return Files.list(recipesDir).use { stream ->
            stream.sorted()
                .map { it.resolve("recipe.json") }
                .filter { Files.isRegularFile(it) }
                .map { runCatching { toRemoteRecipe(mapper.readTree(it.toFile())) }.getOrNull() }
                .toList()
                .filterNotNull()
        }
    }

    private fun toRemoteRecipe(node: JsonNode): RemoteRecipe = RemoteRecipe(
        id = node["id"].asString(),
        version = node["version"]?.asString() ?: "",
        summary = node["summary"]?.asString() ?: "",
    )

    private fun sanitize(tag: String): String = tag.replace(Regex("[^A-Za-z0-9._-]"), "_")

    companion object {
        fun defaultCacheDir(): Path {
            val home = System.getProperty("user.home") ?: error("user.home is not set")
            val isWindows = System.getProperty("os.name", "").startsWith("Windows", ignoreCase = true)
            return if (isWindows) {
                Path("${System.getenv("APPDATA") ?: "$home/AppData/Roaming"}/thoryn/recipes-cache")
            } else {
                Path("$home/.config/thoryn/recipes-cache")
            }
        }
    }
}
