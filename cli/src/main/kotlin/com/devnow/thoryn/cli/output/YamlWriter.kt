package com.devnow.thoryn.cli.output

import tools.jackson.databind.JsonNode

/**
 * Minimal YAML emitter sufficient for the shapes the CLI produces.
 *
 * We deliberately avoid pulling in SnakeYAML so the GraalVM native-image
 * stays small. Inputs are constrained to what Jackson hands us: maps, lists,
 * strings, numbers, booleans, nulls. Strings are quoted only when they
 * contain YAML-significant characters (`:`, `#`, `-`, `*`, leading
 * whitespace, etc.) — a conservative quoting rule rather than the full YAML
 * 1.2 reserved-character set.
 */
internal object YamlWriter {

    fun write(node: JsonNode): String {
        val sb = StringBuilder()
        if (node.isNull) {
            sb.appendLine("null")
        } else {
            emit(node, sb, indent = 0, atTopLevel = true)
        }
        return sb.toString()
    }

    private fun emit(node: JsonNode, sb: StringBuilder, indent: Int, atTopLevel: Boolean) {
        when {
            node.isObject -> emitObject(node, sb, indent, atTopLevel)
            node.isArray -> emitArray(node, sb, indent, atTopLevel)
            else -> sb.append(scalar(node)).append('\n')
        }
    }

    private fun emitObject(node: JsonNode, sb: StringBuilder, indent: Int, atTopLevel: Boolean) {
        if (node.isEmpty) {
            sb.append("{}\n")
            return
        }
        val pad = " ".repeat(indent)
        var first = true
        for (entry in node.properties()) {
            val key = entry.key
            val v = entry.value
            if (!first || !atTopLevel) sb.append(pad)
            first = false
            sb.append(yamlKey(key)).append(':')
            when {
                v.isObject && !v.isEmpty -> {
                    sb.append('\n')
                    emit(v, sb, indent + 2, atTopLevel = false)
                }
                v.isArray && !v.isEmpty -> {
                    sb.append('\n')
                    emit(v, sb, indent, atTopLevel = false)
                }
                else -> {
                    sb.append(' ').append(scalar(v)).append('\n')
                }
            }
        }
    }

    private fun emitArray(node: JsonNode, sb: StringBuilder, indent: Int, atTopLevel: Boolean) {
        if (node.isEmpty) {
            sb.append("[]\n")
            return
        }
        val pad = " ".repeat(indent)
        for (item in node) {
            sb.append(pad).append("- ")
            when {
                item.isObject && !item.isEmpty -> {
                    // First key inlined; remaining keys indented by 2 from the
                    // dash so the structure reads as one list item.
                    val iter = item.properties().iterator()
                    if (!iter.hasNext()) {
                        sb.append("{}\n")
                        continue
                    }
                    val firstEntry = iter.next()
                    sb.append(yamlKey(firstEntry.key)).append(':')
                    val fv = firstEntry.value
                    when {
                        fv.isObject && !fv.isEmpty -> {
                            sb.append('\n')
                            emit(fv, sb, indent + 4, atTopLevel = false)
                        }
                        fv.isArray && !fv.isEmpty -> {
                            sb.append('\n')
                            emit(fv, sb, indent + 2, atTopLevel = false)
                        }
                        else -> sb.append(' ').append(scalar(fv)).append('\n')
                    }
                    while (iter.hasNext()) {
                        val next = iter.next()
                        sb.append(" ".repeat(indent + 2)).append(yamlKey(next.key)).append(':')
                        val nv = next.value
                        when {
                            nv.isObject && !nv.isEmpty -> {
                                sb.append('\n')
                                emit(nv, sb, indent + 4, atTopLevel = false)
                            }
                            nv.isArray && !nv.isEmpty -> {
                                sb.append('\n')
                                emit(nv, sb, indent + 2, atTopLevel = false)
                            }
                            else -> sb.append(' ').append(scalar(nv)).append('\n')
                        }
                    }
                }
                item.isArray -> {
                    sb.append('\n')
                    emit(item, sb, indent + 2, atTopLevel = false)
                }
                else -> sb.append(scalar(item)).append('\n')
            }
        }
    }

    private fun scalar(node: JsonNode): String = when {
        node.isNull -> "null"
        node.isBoolean -> if (node.asBoolean()) "true" else "false"
        node.isNumber -> node.asString()
        node.isTextual -> yamlString(node.asString())
        else -> yamlString(node.toString())
    }

    /**
     * Quote a string only if it contains a YAML-significant character.
     * Conservative: matches the cases the supply-chain DTOs actually produce
     * (URLs, dates, status codes, free-form display names).
     */
    private fun yamlString(s: String): String {
        if (s.isEmpty()) return "\"\""
        if (s == "null" || s == "true" || s == "false" || s == "yes" || s == "no") {
            return "\"$s\""
        }
        val needsQuote = s.first().isWhitespace() ||
            s.last().isWhitespace() ||
            s.contains(':') ||
            s.contains('#') ||
            s.contains('\n') ||
            s.contains('"') ||
            s.contains('\'') ||
            s.startsWith('-') ||
            s.startsWith('*') ||
            s.startsWith('&') ||
            s.startsWith('?') ||
            s.startsWith('|') ||
            s.startsWith('>') ||
            s.startsWith('!') ||
            s.startsWith('%') ||
            s.startsWith('@') ||
            s.startsWith('`') ||
            s.startsWith('{') ||
            s.startsWith('[')
        return if (needsQuote) {
            "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        } else {
            s
        }
    }

    private fun yamlKey(k: String): String = yamlString(k)
}
