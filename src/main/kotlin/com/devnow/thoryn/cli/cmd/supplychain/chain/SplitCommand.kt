package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.Callable
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * `thoryn supply-chain chain split --bridge-id <id> --parent <urn>
 *   --template retail-1kg --count 850 --output-zip retail.zip`
 *
 * Split path of the intermediary flow (SSO-962 + SSO-963): 1 parent → N
 * children, issued in one atomic bulk-issue transaction. Calls
 * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/issue` with
 * `action=split` and a templated children list. The product-api forwards
 * to `POST /broker/internal/credentials/bulk` and returns N credential
 * IDs + N compact JWS payloads (+ optional per-child QR-PDF bytes).
 *
 * Scope: `tenant:supply-chain.issuer-bridge.intermediary.write`.
 *
 * **Bulk-streaming output:** for `--count 850`, the response payload is
 * 850 × (JWS + QR-PDF). Even at ~50 KB per child that is ~40 MB — the CLI
 * writes a ZIP using `ZipOutputStream` so peak memory tracks one child at a
 * time, not N. Each child contributes one entry per artefact:
 *
 * ```
 * retail.zip
 * ├── RETAIL-001/credential.jws
 * ├── RETAIL-001/qr.pdf          (only if QR-PDF was generated)
 * ├── RETAIL-002/credential.jws
 * ├── RETAIL-002/qr.pdf
 * └── ...
 * ```
 *
 * **Template + count semantics:** `--template <id>` resolves a pre-defined
 * row template stored in the Trust Registry (SSO-969). The CLI passes the
 * template ID through to the server; the server expands it on its side so
 * the row shapes are consistent across console and CLI. `--count` selects
 * how many children to issue from the template.
 *
 * **Prefix + start** are optional knobs that override the template's
 * defaults — useful for CI pipelines that want deterministic outgoing batch
 * IDs (e.g. `RETAIL-001..RETAIL-850`).
 */
@Command(
    name = "split",
    description = ["Mint N children from one parent (SSO-962 split path) + write per-child QR-PDFs as ZIP."],
    mixinStandardHelpOptions = true,
)
class SplitCommand : Callable<Int> {

    @Option(
        names = ["--bridge-id"],
        description = ["Issuer-bridge that signs the outgoing children."],
        required = true,
    )
    lateinit var bridgeId: String

    @Option(
        names = ["--parent"],
        description = ["Credential URN of the single parent (incoming) credential."],
        required = true,
    )
    lateinit var parent: String

    @Option(
        names = ["--template"],
        description = ["Pre-defined row template ID, resolved by the server (Trust Registry)."],
        required = true,
    )
    lateinit var template: String

    @Option(
        names = ["--count"],
        description = ["Number of children to mint (1..maxBulkSize, default cap 1000)."],
        required = true,
    )
    var count: Int = 0

    @Option(
        names = ["--prefix"],
        description = ["Optional override for the template's outgoing-batch-ID prefix (e.g. RETAIL)."],
    )
    var prefix: String? = null

    @Option(
        names = ["--start"],
        description = ["Optional override for the template's start index (e.g. 1 for `RETAIL-001`)."],
    )
    var start: Int? = null

    @Option(
        names = ["--output-zip"],
        description = ["Write N JWS + QR-PDF artefacts to this ZIP file."],
        required = true,
    )
    lateinit var outputZip: Path

    @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
    var gateway: String = ThorynConfig.DEFAULT_GATEWAY

    @Option(
        names = ["--output"],
        description = ["Output format: json|yaml|table (default: table)."],
    )
    var outputRaw: String? = null

    override fun call(): Int {
        val format = SupplyChainCommandSupport.parseFormat(outputRaw)
            ?: return SupplyChainCommandSupport.EXIT_USAGE
        if (count <= 0) {
            System.err.println("Error: --count must be a positive integer (was $count).")
            return SupplyChainCommandSupport.EXIT_USAGE
        }
        val tokens = SupplyChainCommandSupport.readTokens()
            ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
        val client = SupplyChainCommandSupport.client(gateway, tokens)
        val body: Map<String, Any?> = linkedMapOf<String, Any?>(
            "action" to "split",
            "parentCredentialIds" to listOf(parent),
            "template" to linkedMapOf<String, Any?>(
                "id" to template,
                "count" to count,
            ).apply {
                if (prefix != null) put("prefix", prefix)
                if (start != null) put("start", start)
            },
        )
        return try {
            val response = client.intermediaryIssue(bridgeId, body)
            val children = response["children"]
            if (children == null || !children.isArray) {
                System.err.println(
                    "Error: response did not carry a 'children' array (got: $response).",
                )
                return SupplyChainCommandSupport.EXIT_IO_ERROR
            }
            val written = writeZip(outputZip, children)
            emitSummary(format, response, written)
            SupplyChainCommandSupport.EXIT_OK
        } catch (ex: ProductApiException) {
            SupplyChainCommandSupport.renderError(
                format = format,
                ex = ex,
                requiredScope = "tenant:supply-chain.issuer-bridge.intermediary.write",
            )
        } catch (ex: Exception) {
            System.err.println("Request failed: ${ex.message}")
            SupplyChainCommandSupport.EXIT_IO_ERROR
        }
    }

    /**
     * Stream every child entry to the ZIP without holding the full set in
     * memory. `Files.newOutputStream` + `ZipOutputStream` is enough — each
     * iteration writes one entry and discards the bytes. Returns the number
     * of entries written.
     */
    private fun writeZip(target: Path, children: JsonNode): Int {
        var written = 0
        Files.newOutputStream(target).use { fos ->
            ZipOutputStream(fos).use { zos ->
                for (child in children) {
                    val outgoingBatchId = child["outgoingBatchId"]?.asString()
                        ?: child["credentialId"]?.asString()
                        ?: "child-${written.toString().padStart(4, '0')}"
                    val jws = child["jws"]?.asString()
                    if (jws != null) {
                        zos.putNextEntry(ZipEntry("$outgoingBatchId/credential.jws"))
                        zos.write(jws.toByteArray(Charsets.UTF_8))
                        zos.closeEntry()
                    }
                    val qrPdfBase64 = child["qrPdfBase64"]?.asString()
                    if (qrPdfBase64 != null) {
                        val bytes = try {
                            Base64.getDecoder().decode(qrPdfBase64)
                        } catch (_: Exception) {
                            null
                        }
                        if (bytes != null) {
                            zos.putNextEntry(ZipEntry("$outgoingBatchId/qr.pdf"))
                            zos.write(bytes)
                            zos.closeEntry()
                        }
                    }
                    written++
                }
            }
        }
        System.err.println("Wrote $written entries to $target")
        return written
    }

    private fun emitSummary(format: OutputFormat, response: JsonNode, entriesWritten: Int) {
        val summary = linkedMapOf<String, Any?>(
            "splitEventId" to response["splitEventId"]?.asString(),
            "childrenIssued" to (response["children"]?.size() ?: 0),
            "entriesWritten" to entriesWritten,
            "outputZip" to outputZip.toString(),
            "elapsedMs" to response["elapsedMs"]?.asInt(),
        )
        when (format) {
            OutputFormat.JSON -> Printers.json(summary)
            OutputFormat.YAML -> Printers.yaml(summary)
            OutputFormat.TABLE -> Printers.record(summary.toList())
        }
    }
}
