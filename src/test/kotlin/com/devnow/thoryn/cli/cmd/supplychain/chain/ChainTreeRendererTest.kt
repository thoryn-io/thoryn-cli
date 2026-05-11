package com.devnow.thoryn.cli.cmd.supplychain.chain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-970 — unit tests for [ChainTreeRenderer].
 *
 * Decoupled from the gateway / token store. Drives JSON nodes directly to
 * keep the surface tight; the dependency PRs may still settle the exact
 * field names, and these tests document which keys the renderer reads.
 */
class ChainTreeRendererTest {

    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    @Test
    fun `linear chain depth 3 renders each level under the previous`() {
        val node = mapper.readTree(
            """
            {
              "credentialId": "RETAIL-203",
              "actionType": "received",
              "verdict": "VALID",
              "parents": [
                {
                  "credentialId": "ROAST-W18",
                  "actionType": "processed_combined",
                  "verdict": "VALID",
                  "parents": [
                    {"credentialId":"PLOT-A","actionType":"origin","verdict":"VALID"}
                  ]
                }
              ]
            }
            """.trimIndent(),
        )

        val out = capture { ChainTreeRenderer.render(node, it) }
        assertThat(out).contains("RETAIL-203 (received) — VALID")
        assertThat(out).contains("ROAST-W18 (processed_combined) — VALID")
        assertThat(out).contains("PLOT-A (origin) — VALID")
    }

    @Test
    fun `fan-in depth 1 renders all parents at the same indent`() {
        val node = mapper.readTree(
            """
            {
              "credentialId": "ROAST-W18",
              "actionType": "processed_combined",
              "verdict": "VALID",
              "parents": [
                {"credentialId":"PLOT-A","actionType":"origin","verdict":"VALID"},
                {"credentialId":"PLOT-B","actionType":"origin","verdict":"VALID"},
                {"credentialId":"PLOT-C","actionType":"origin","verdict":"VALID"}
              ]
            }
            """.trimIndent(),
        )

        val out = capture { ChainTreeRenderer.render(node, it) }
        assertThat(out).contains("├─ PLOT-A")
        assertThat(out).contains("├─ PLOT-B")
        assertThat(out).contains("└─ PLOT-C")
    }

    @Test
    fun `descendants branch is used when parents is absent`() {
        val node = mapper.readTree(
            """
            {
              "credentialId": "ROOT",
              "actionType": "origin",
              "verdict": "VALID",
              "descendants": [
                {"credentialId":"D-1","actionType":"split","verdict":"VALID"},
                {"credentialId":"D-2","actionType":"split","verdict":"VALID"}
              ]
            }
            """.trimIndent(),
        )

        val out = capture { ChainTreeRenderer.render(node, it) }
        assertThat(out).contains("ROOT (origin) — VALID")
        assertThat(out).contains("D-1")
        assertThat(out).contains("D-2")
    }

    @Test
    fun `truncated node placeholder is surfaced in the layout`() {
        val node = mapper.readTree(
            """
            {
              "credentialId": "LEAF",
              "actionType": "received",
              "verdict": "VALID",
              "parents": [
                {"verdict":"TRUNCATED","remainingDepth":3,"actionType":"truncated"}
              ]
            }
            """.trimIndent(),
        )

        val out = capture { ChainTreeRenderer.render(node, it) }
        assertThat(out).contains("LEAF (received) — VALID")
        assertThat(out).contains("TRUNCATED")
        assertThat(out).contains("truncated")
    }

    private fun capture(block: (PrintStream) -> Unit): String {
        val baos = ByteArrayOutputStream()
        PrintStream(baos, true, Charsets.UTF_8).use(block)
        return baos.toString(Charsets.UTF_8)
    }
}
