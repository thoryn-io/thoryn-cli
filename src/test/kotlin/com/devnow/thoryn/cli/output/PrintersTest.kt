package com.devnow.thoryn.cli.output

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-959 — unit tests for [Printers] (table / JSON / YAML emitters).
 */
class PrintersTest {

    @Test
    fun `table emits header underline and row separator widths`() {
        val out = captureOut { stream ->
            Printers.table(
                columns = listOf("id", "name", "active"),
                rows = listOf(
                    listOf("a", "alpha", true),
                    listOf("bb", "long-name", false),
                ),
                out = stream,
            )
        }
        val lines = out.lines().filter { it.isNotEmpty() }
        // 1 header + 1 underline + 2 data rows = 4 lines.
        assertThat(lines).hasSize(4)
        // Header
        assertThat(lines[0]).contains("id").contains("name").contains("active")
        // Underline row uses dashes sized to widest column value
        assertThat(lines[1]).contains("--")
        // Data rows include cell values
        assertThat(lines[2]).contains("alpha")
        assertThat(lines[3]).contains("long-name")
    }

    @Test
    fun `table with no rows prints a no-rows marker`() {
        val out = captureOut { stream ->
            Printers.table(
                columns = listOf("col"),
                rows = emptyList(),
                out = stream,
            )
        }
        assertThat(out).contains("(no rows)")
    }

    @Test
    fun `json output is pretty-printed and stable`() {
        val out = captureOut { stream ->
            Printers.json(mapOf("a" to 1, "b" to "two"), stream)
        }
        // Indented (multi-line) and contains both keys.
        assertThat(out).contains("\"a\"")
        assertThat(out).contains("\"two\"")
        assertThat(out.lines().count { it.isNotBlank() }).isGreaterThan(2)
    }

    @Test
    fun `yaml output renders simple map`() {
        val out = captureOut { stream ->
            Printers.yaml(mapOf("name" to "alpha", "count" to 5), stream)
        }
        assertThat(out).contains("name: alpha")
        assertThat(out).contains("count: 5")
    }

    @Test
    fun `yaml output renders list of maps with first key inlined`() {
        val out = captureOut { stream ->
            Printers.yaml(
                listOf(
                    mapOf("id" to "a", "name" to "alpha"),
                    mapOf("id" to "b", "name" to "beta"),
                ),
                stream,
            )
        }
        // Each item begins with `- id: <value>` followed by indented `name:`.
        assertThat(out).contains("- id: a")
        assertThat(out).contains("name: alpha")
        assertThat(out).contains("- id: b")
    }

    @Test
    fun `record prints aligned key-equals-value pairs`() {
        val out = captureOut { stream ->
            Printers.record(
                listOf(
                    "id" to "row-1",
                    "tenantId" to "tenant-acme",
                    "outcome" to "VALID",
                ),
                stream,
            )
        }
        val lines = out.lines().filter { it.isNotBlank() }
        assertThat(lines).hasSize(3)
        // The widest key is "tenantId" (8 chars); all `=` columns must align.
        val equalsPositions = lines.map { it.indexOf('=') }
        assertThat(equalsPositions.distinct()).hasSize(1)
    }

    private fun captureOut(block: (PrintStream) -> Unit): String {
        val buffer = ByteArrayOutputStream()
        val stream = PrintStream(buffer)
        block(stream)
        stream.flush()
        return buffer.toString(Charsets.UTF_8)
    }
}
