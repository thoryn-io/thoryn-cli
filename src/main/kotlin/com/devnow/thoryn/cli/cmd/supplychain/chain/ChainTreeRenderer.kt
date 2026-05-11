package com.devnow.thoryn.cli.cmd.supplychain.chain

import tools.jackson.databind.JsonNode
import java.io.PrintStream

/**
 * Render a chain-of-custody DAG node as a unicode-box ASCII tree, mirroring
 * the layout the console (SSO-964 / SSO-967) uses for the same payloads.
 *
 * Used by `thoryn supply-chain chain walk` (upward walk) and
 * `thoryn supply-chain chain descendants` (downward walk). Both endpoints
 * return the same recursive shape:
 *
 * ```jsonc
 * {
 *   "verdict": "VALID",
 *   "actionType": "received",
 *   "credentialId": "RETAIL-203",
 *   "parents":     [ ... ],   // walk-upward
 *   "descendants": [ ... ],   // walk-downward (or "children")
 *   ...
 * }
 * ```
 *
 * The renderer is intentionally untyped — it inspects whichever branch field
 * is present and walks that. That keeps the CLI decoupled from the exact
 * JSON shapes the dependency endpoints settle on, which is the right
 * trade-off for a thin client whose dependencies (SSO-962 / SSO-964 / SSO-965
 * / SSO-967) are still in flight.
 */
internal object ChainTreeRenderer {

    /**
     * Field names that, when present, hold the child list for a recursive
     * walk. Tried in order; first array hit wins. This handles both the
     * upward walk (`parents`) and the downward walk (`descendants` /
     * `children`) without the caller having to specify which.
     */
    private val CHILD_KEYS = listOf("parents", "descendants", "children")

    /**
     * Print [root] as a unicode-box tree to [out]. Each line carries the
     * credential ID, action type, and verdict in a fixed layout:
     *
     * ```
     * RETAIL-203 (received) — VALID
     *   └─ ROAST-2026-W18 (processed_combined) — VALID
     *        ├─ PLOT-A (origin) — VALID
     *        └─ PLOT-B (origin) — VALID
     * ```
     *
     * Truncated / fan-degree-exceeded placeholder nodes render with the
     * server-supplied verdict and remaining-depth or parent-count as
     * applicable (per SSO-964's `TRUNCATED` and `FAN_DEGREE_EXCEEDED` shapes).
     */
    fun render(root: JsonNode, out: PrintStream) {
        val verdict = root["verdict"]?.asString() ?: "?"
        val credentialId = root["credentialId"]?.asString() ?: "?"
        val actionType = root["actionType"]?.asString() ?: "?"
        out.println("$credentialId ($actionType) — $verdict")
        val children = pickChildren(root)
        renderChildren(children, prefix = "", out = out)
    }

    private fun renderChildren(children: List<JsonNode>, prefix: String, out: PrintStream) {
        for ((idx, child) in children.withIndex()) {
            val isLast = idx == children.size - 1
            val branch = if (isLast) "└─ " else "├─ "
            val verdict = child["verdict"]?.asString() ?: "?"
            val credentialId = child["credentialId"]?.asString()
                ?: child["remainingDepth"]?.let { "(truncated, $it deeper)" }
                ?: child["parents"]?.let { "(fan-degree-exceeded)" }
                ?: "?"
            val actionType = child["actionType"]?.asString() ?: "?"
            out.println("$prefix$branch$credentialId ($actionType) — $verdict")
            val grand = pickChildren(child)
            val childPrefix = prefix + if (isLast) "   " else "│  "
            renderChildren(grand, prefix = childPrefix, out = out)
        }
    }

    private fun pickChildren(node: JsonNode): List<JsonNode> {
        for (key in CHILD_KEYS) {
            val branch = node[key]
            if (branch != null && branch.isArray) {
                return branch.toList()
            }
        }
        return emptyList()
    }
}
