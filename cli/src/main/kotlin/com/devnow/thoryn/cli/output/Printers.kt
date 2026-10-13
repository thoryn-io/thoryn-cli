package com.devnow.thoryn.cli.output

import tools.jackson.databind.SerializationFeature
import tools.jackson.databind.cfg.DateTimeFeature
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.PrintStream

/**
 * Three printers used by every `thoryn supply-chain` subcommand. Each accepts
 * a Kotlin value (a list of rows for tables, an arbitrary tree for
 * JSON/YAML) and emits to the supplied [PrintStream] — typically [System.out].
 *
 * **Why hand-rolled, not jackson-yaml** — the CLI is GraalVM-native-image
 * bound and jackson-yaml pulls in SnakeYAML, which doubles reflection
 * footprint. A 30-line YAML emitter that handles the shapes we actually
 * emit (maps of primitives and lists of maps of primitives) is enough; we
 * don't need full YAML 1.2 fidelity.
 */
object Printers {

    private val jsonMapper: JsonMapper = JsonMapper.builder()
        .addModule(kotlinModule())
        .configure(SerializationFeature.INDENT_OUTPUT, true)
        .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false)
        // Jackson 3 moved date-as-string control to DateTimeFeature; the
        // built-in java.time support is auto-registered by databind 3.x.
        .configure(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS, false)
        .build()

    /**
     * Print [value] as a pretty JSON tree. Used by every `--output json`
     * branch; also used by structured-error reporting.
     */
    fun json(value: Any?, out: PrintStream = System.out) {
        out.println(jsonMapper.writeValueAsString(value))
    }

    /**
     * Print [value] as YAML. The emitter handles `Map<String, Any?>` and
     * `List<Map<String, Any?>>` (and primitives). Anything else is converted
     * via Jackson first, then re-emitted — that keeps the call sites simple
     * (pass a data class, get YAML) without baking in SnakeYAML.
     */
    fun yaml(value: Any?, out: PrintStream = System.out) {
        val tree = jsonMapper.valueToTree<tools.jackson.databind.JsonNode>(value)
        out.println(YamlWriter.write(tree).trimEnd('\n'))
    }

    /**
     * Print [rows] as a fixed-width, left-aligned table. [columns] is the
     * ordered list of column titles; each row is a list of cell values whose
     * `toString()` is rendered. Missing cells render as the empty string;
     * extra cells are dropped.
     */
    fun table(columns: List<String>, rows: List<List<Any?>>, out: PrintStream = System.out) {
        if (columns.isEmpty()) return
        val widths = IntArray(columns.size) { columns[it].length }
        val cellRows: List<List<String>> = rows.map { row ->
            columns.indices.map { idx ->
                val cell = row.getOrNull(idx)
                val str = cell?.toString() ?: ""
                if (str.length > widths[idx]) widths[idx] = str.length
                str
            }
        }
        out.println(formatRow(columns, widths))
        out.println(formatRow(widths.map { "-".repeat(it) }, widths))
        for (row in cellRows) {
            out.println(formatRow(row, widths))
        }
        if (rows.isEmpty()) {
            // Surface the empty-result case so a user piping into `wc -l`
            // doesn't have to count header rows by hand.
            out.println("(no rows)")
        }
    }

    /**
     * Pretty-print a single key/value record (e.g. `policy show` or
     * `issuer-bridge show`) as a two-column table. Mirrors the layout of
     * the existing `thoryn audit-replay` PASS output.
     */
    fun record(fields: List<Pair<String, Any?>>, out: PrintStream = System.out) {
        if (fields.isEmpty()) {
            out.println("(no fields)")
            return
        }
        val keyWidth = fields.maxOf { it.first.length }
        for ((k, v) in fields) {
            val rendered = v?.toString() ?: "(null)"
            out.println("  ${k.padEnd(keyWidth)} = $rendered")
        }
    }

    private fun formatRow(cells: List<String>, widths: IntArray): String {
        val sb = StringBuilder()
        for (i in cells.indices) {
            if (i > 0) sb.append("  ")
            val padded = cells[i].padEnd(widths.getOrElse(i) { cells[i].length })
            sb.append(padded)
        }
        return sb.toString()
    }
}
