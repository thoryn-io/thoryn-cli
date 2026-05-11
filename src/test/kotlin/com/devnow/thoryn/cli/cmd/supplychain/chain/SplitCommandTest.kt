package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.zip.ZipFile

/**
 * SSO-970 — unit tests for `thoryn supply-chain chain split`.
 *
 * The split path posts `action=split` to
 * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/issue` and the
 * server (SSO-962 + SSO-963) returns N children. The CLI's job is to
 * stream the children into a ZIP — one `<batchId>/credential.jws` per
 * child + (optionally) one `<batchId>/qr.pdf` per child. This test fakes
 * the response with a handful of children and asserts the ZIP shape.
 */
class SplitCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `split writes one credential jws + one qr pdf per child to the output ZIP`(@TempDir tmp: Path) {
        val pdfBytes = byteArrayOf(0x25, 0x50, 0x44, 0x46) + ByteArray(8)
        val pdfBase64 = Base64.getEncoder().encodeToString(pdfBytes)
        val responseBody = """
            {
              "splitEventId": "urn:split:01",
              "elapsedMs": 4200,
              "children": [
                {"credentialId":"urn:vc:r1","outgoingBatchId":"RETAIL-001",
                 "jws":"jws-1","qrPdfBase64":"$pdfBase64"},
                {"credentialId":"urn:vc:r2","outgoingBatchId":"RETAIL-002",
                 "jws":"jws-2","qrPdfBase64":"$pdfBase64"},
                {"credentialId":"urn:vc:r3","outgoingBatchId":"RETAIL-003",
                 "jws":"jws-3","qrPdfBase64":"$pdfBase64"}
              ]
            }
        """.trimIndent()
        gateway.enqueue(jsonResponse(200, responseBody))

        val target = tmp.resolve("retail.zip")
        val (exit, out, _) = runCli(
            "supply-chain", "chain", "split",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--template", "retail-1kg",
            "--count", "3",
            "--prefix", "RETAIL",
            "--start", "1",
            "--output-zip", target.toString(),
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(target).exists()
        assertThat(out).contains("urn:split:01")

        ZipFile(target.toFile()).use { zip ->
            val entryNames = zip.entries().toList().map { it.name }
            assertThat(entryNames).contains(
                "RETAIL-001/credential.jws",
                "RETAIL-001/qr.pdf",
                "RETAIL-002/credential.jws",
                "RETAIL-002/qr.pdf",
                "RETAIL-003/credential.jws",
                "RETAIL-003/qr.pdf",
            )
            val jws1 = zip.getInputStream(zip.getEntry("RETAIL-001/credential.jws"))
                .readBytes()
                .toString(Charsets.UTF_8)
            assertThat(jws1).isEqualTo("jws-1")
        }

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path)
            .isEqualTo("/api/v1/issuer-bridges/bridge-mill-1/intermediary/issue")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"action\":\"split\"")
        assertThat(body).contains("\"template\":{")
        assertThat(body).contains("\"id\":\"retail-1kg\"")
        assertThat(body).contains("\"count\":3")
    }

    @Test
    fun `split with no qr-pdf-base64 still writes the credential jws entries`(@TempDir tmp: Path) {
        gateway.enqueue(
            jsonResponse(
                200,
                """
                {
                  "splitEventId": "urn:split:02",
                  "children": [
                    {"credentialId":"urn:vc:r1","outgoingBatchId":"RETAIL-001","jws":"jws-1"},
                    {"credentialId":"urn:vc:r2","outgoingBatchId":"RETAIL-002","jws":"jws-2"}
                  ]
                }
                """.trimIndent(),
            ),
        )

        val target = tmp.resolve("retail.zip")
        val (exit, _, _) = runCli(
            "supply-chain", "chain", "split",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--template", "retail-1kg",
            "--count", "2",
            "--output-zip", target.toString(),
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        ZipFile(target.toFile()).use { zip ->
            val names = zip.entries().toList().map { it.name }
            assertThat(names).containsExactlyInAnyOrder(
                "RETAIL-001/credential.jws",
                "RETAIL-002/credential.jws",
            )
        }
    }

    @Test
    fun `split with count zero is rejected with EXIT_USAGE`(@TempDir tmp: Path) {
        val target = tmp.resolve("retail.zip")
        val (exit, _, err) = runCli(
            "supply-chain", "chain", "split",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--template", "retail-1kg",
            "--count", "0",
            "--output-zip", target.toString(),
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("--count must be a positive integer")
        assertThat(Files.exists(target)).isFalse()
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `403 on split prints the intermediary write scope hint`(@TempDir tmp: Path) {
        gateway.enqueue(jsonResponse(403, """{"error":"insufficient_scope"}"""))
        val target = tmp.resolve("retail.zip")

        val (exit, _, err) = runCli(
            "supply-chain", "chain", "split",
            "--bridge-id", "bridge-mill-1",
            "--parent", "urn:vc:01",
            "--template", "retail-1kg",
            "--count", "1",
            "--output-zip", target.toString(),
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains(
            "oathy login --scope tenant:supply-chain.issuer-bridge.intermediary.write",
        )
    }
}
