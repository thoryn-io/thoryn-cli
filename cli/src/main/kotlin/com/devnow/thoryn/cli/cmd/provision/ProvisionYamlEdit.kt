package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.output.YamlWriter
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.node.ArrayNode
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * The ONE way the CLI edits a provisioning file's text (SSO-3659 `thoryn provision import --write`; reused by
 * `thoryn project init app --config-repo`, SSO-3669): entries are rendered as a `resources:` list fragment and
 * APPENDED under the file's `resources:` list — only when that list is the last top-level key, so the appended
 * entries belong to it — which keeps every other line of the file (its comments included) byte for byte. A
 * fresh file gets the header. There is deliberately no second YAML editor: [converge] REPLACES an existing
 * entry by re-rendering the whole document from its parsed tree, which is the one case where the file's
 * comments are lost — the caller says so.
 */
internal object ProvisionYamlEdit {

    private val json = JsonMapper.builder().build()
    private val yaml = YAMLMapper.builder().build()

    /** `apiVersion: …\nresources:\n` — the header of a fresh file. */
    const val HEADER: String = "apiVersion: ${ProvisionFile.API_VERSION}\nresources:\n"

    /** [entries] (an array node) as a `resources:` list fragment, indented for the file (two spaces, as the schema examples are written). */
    fun fragment(entries: JsonNode): String {
        if (!entries.isArray || entries.isEmpty) return ""
        return YamlWriter.write(entries).lines().filter { it.isNotEmpty() }.joinToString("\n") { "  $it" } + "\n"
    }

    /** A fresh file carrying [fragment]. */
    fun fresh(fragment: String): String = HEADER + fragment

    /**
     * [text] with [fragment] appended under its `resources:` list. Throws [ProvisionException] when `resources` is
     * not the last top-level key (the entries would not belong to it); a file without a `resources` key gets one.
     */
    fun append(text: String, fragment: String, source: String): String {
        val root = parse(text, source)
        val lastKey = root.properties().lastOrNull()?.key
        val base = text + (if (text.endsWith("\n") || text.isEmpty()) "" else "\n")
        return when {
            root.has("resources") && lastKey == "resources" -> base + fragment
            !root.has("resources") -> base + "resources:\n" + fragment
            else -> throw ProvisionException("$source: 'resources' is not the last top-level key, so entries cannot be appended to it — add them by hand")
        }
    }

    enum class Outcome { ADDED, UPDATED, UNCHANGED }

    /** [converge]'s result: the file's new text (the original when [outcome] is [Outcome.UNCHANGED]) and what happened. */
    class Converged(val content: String, val outcome: Outcome)

    /**
     * Converge ONE entry into [text] (null ⇒ no file yet): the resource [matches] names is added when absent
     * ([fragment] appended — the rest of the file, comments included, is kept), left alone when it already equals
     * [entry] (structurally — key order and quoting do not count), and REPLACED when it differs (the document is
     * re-rendered from its tree: its comments are lost). [header] is prepended to an appended fragment (comment
     * lines for a human reader); it plays no part in the comparison.
     */
    fun converge(text: String?, entry: JsonNode, source: String, header: String = "", matches: (JsonNode) -> Boolean): Converged {
        val fragment = header + fragment(json.createArrayNode().add(entry))
        if (text == null || text.isBlank()) return Converged(fresh(fragment), Outcome.ADDED)
        val root = parse(text, source)
        val resources = root["resources"]?.takeIf { it.isArray }
        val index = resources?.toList()?.indexOfFirst(matches) ?: -1
        if (index < 0) return Converged(append(text, fragment, source), Outcome.ADDED)
        if (resources!!.get(index) == entry) return Converged(text, Outcome.UNCHANGED)
        (resources as ArrayNode).set(index, entry)
        return Converged(YamlWriter.write(root), Outcome.UPDATED)
    }

    private fun parse(text: String, source: String): JsonNode {
        val root = try {
            yaml.readTree(text)
        } catch (ex: Exception) {
            throw ProvisionException("$source is not valid YAML: ${ex.message}")
        }
        if (root == null || root.isNull || root.isMissingNode) return json.createObjectNode()
        if (!root.isObject) throw ProvisionException("$source is not a YAML mapping (apiVersion + resources)")
        return root
    }
}
