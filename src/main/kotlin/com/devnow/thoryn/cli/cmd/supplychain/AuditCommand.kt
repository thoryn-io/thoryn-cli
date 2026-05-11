package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.AuditReplayCommand
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.File
import java.nio.file.Files
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain audit ...` — SSO-956 parity for the walletless audit-log
 * browser + receipt-PDF export.
 *
 * URL shapes (per `features/SSO-956-supply-chain-audit-log-browser-receipt-pdf.md`):
 *
 *  - `GET /api/v1/audit-log` — query params: `from, to, credentialClass,
 *     issuerKid, outcome, policyVersion, deviceId, cursor, limit`
 *  - `GET /api/v1/audit-log/{auditRowId}`
 *  - `GET /api/v1/audit-log/{auditRowId}/receipt.pdf`
 *  - `GET /api/v1/audit-log/{auditRowId}/receipt.json`
 *
 * `replay <auditRowId>` is a convenience wrapper around the existing
 * `thoryn audit-replay` (SSO-940b): it fetches the receipt JSON over the
 * gateway, writes it to a temp file, then delegates verification to the
 * same [AuditReplayCommand] used by the standalone `thoryn audit-replay`.
 * No re-implementation of crypto.
 *
 * Scope: `tenant:supply-chain.audit.read` for all subcommands.
 */
@Command(
    name = "audit",
    description = ["Browse the walletless audit log; download signed PDF receipts; replay receipts offline."],
    mixinStandardHelpOptions = true,
    subcommands = [
        AuditCommand.SearchSubcommand::class,
        AuditCommand.GetSubcommand::class,
        AuditCommand.ReceiptSubcommand::class,
        AuditCommand.ReplaySubcommand::class,
    ],
)
class AuditCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn supply-chain audit <subcommand>")
        System.err.println("Subcommands: search | get | receipt | replay")
        return SupplyChainCommandSupport.EXIT_USAGE
    }

    /** `thoryn supply-chain audit search [--from <date>] [--to <date>] ...` */
    @Command(
        name = "search",
        description = ["Search the audit log with filters."],
        mixinStandardHelpOptions = true,
    )
    class SearchSubcommand : Callable<Int> {

        @Option(names = ["--from"], description = ["From date (ISO-8601)."])
        var from: String? = null

        @Option(names = ["--to"], description = ["To date (ISO-8601)."])
        var to: String? = null

        @Option(names = ["--credential-class"])
        var credentialClass: String? = null

        @Option(names = ["--issuer-kid"])
        var issuerKid: String? = null

        @Option(
            names = ["--outcome"],
            description = ["VALID | SIGNATURE_INVALID | REVOKED | VALID_REVOCATION_UNCHECKED | STATUS_UNKNOWN"],
        )
        var outcome: String? = null

        @Option(names = ["--policy-version"])
        var policyVersion: String? = null

        @Option(names = ["--device-id"])
        var deviceId: String? = null

        @Option(names = ["--cursor"], description = ["Opaque pagination cursor from a previous response."])
        var cursor: String? = null

        @Option(names = ["--limit"], description = ["Page size (max 200)."])
        var limit: Int? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            val query = linkedMapOf<String, String?>(
                "from" to from,
                "to" to to,
                "credentialClass" to credentialClass,
                "issuerKid" to issuerKid,
                "outcome" to outcome,
                "policyVersion" to policyVersion,
                "deviceId" to deviceId,
                "cursor" to cursor,
                "limit" to limit?.toString(),
            )
            return try {
                val body = client.searchAuditLog(query)
                SupplyChainCommandSupport.emitList(
                    format = format,
                    body = body,
                    tableHeaders = SEARCH_HEADERS,
                    rowMapper = ::auditRow,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.audit.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** `thoryn supply-chain audit get <auditRowId>` */
    @Command(
        name = "get",
        description = ["Show a single audit row."],
        mixinStandardHelpOptions = true,
    )
    class GetSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Audit row ID."])
        lateinit var auditRowId: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            return try {
                val body = client.getAuditLogRow(auditRowId)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::auditRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.audit.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain audit receipt <auditRowId> [--pdf] [-o file]`
     *
     *  - Default: JSON receipt to stdout (matches
     *    `GET /api/v1/audit-log/{id}/receipt.json` shape).
     *  - `--pdf`: binary PDF/A-3 to stdout (or to `-o file`).
     *
     * Per the SSO-959 acceptance criteria, `--pdf > receipt.pdf` writes a
     * binary PDF to stdout (verified by `pdfinfo`).
     */
    @Command(
        name = "receipt",
        description = ["Download a signed receipt for an audit row (JSON by default; --pdf for PDF/A-3)."],
        mixinStandardHelpOptions = true,
    )
    class ReceiptSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Audit row ID."])
        lateinit var auditRowId: String

        @Option(
            names = ["--pdf"],
            description = ["Emit binary PDF/A-3 (default: JSON)."],
        )
        var pdf: Boolean = false

        @Option(
            names = ["--chain"],
            description = [
                "SSO-968: include the credential's chain-of-custody walk. Only valid " +
                    "with --pdf. The PDF gains one section per chain link plus a final " +
                    "'how to verify offline' page. If the produced PDF would exceed 20 MB " +
                    "the server falls back to a ZIP-of-PDFs (one per link); the response " +
                    "content-type indicates which format the server returned.",
            ],
        )
        var chain: Boolean = false

        @Option(
            names = ["-o", "--output-file"],
            description = ["Write the receipt to this file instead of stdout."],
        )
        var outputFile: File? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            if (chain && !pdf) {
                System.err.println("--chain requires --pdf; chain output is PDF-only.")
                return SupplyChainCommandSupport.EXIT_USAGE
            }
            return try {
                if (pdf) {
                    val bytes = if (chain) {
                        client.getAuditLogReceiptPdf(auditRowId, includeChain = true)
                    } else {
                        client.getAuditLogReceiptPdf(auditRowId)
                    }
                    val target = outputFile
                    if (target != null) {
                        Files.write(target.toPath(), bytes)
                        System.err.println("Wrote ${bytes.size} bytes to ${target.absolutePath}")
                    } else {
                        // Binary to stdout — the caller pipes to a file.
                        System.out.write(bytes)
                        System.out.flush()
                    }
                } else {
                    val body = client.getAuditLogReceiptJson(auditRowId)
                    val target = outputFile
                    if (target != null) {
                        Files.writeString(target.toPath(), body.toString())
                        System.err.println("Wrote receipt JSON to ${target.absolutePath}")
                    } else {
                        Printers.json(body)
                    }
                }
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                // No --output flag on this subcommand: use TABLE-style error
                // reporting (one-line stderr).
                SupplyChainCommandSupport.renderError(
                    format = OutputFormat.TABLE,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.audit.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain audit replay <auditRowId>`
     *
     * Alias for the existing `thoryn audit-replay` flow: fetches the
     * receipt JSON from the gateway, writes it to a temp file, then
     * delegates to [AuditReplayCommand] for the actual verification. Same
     * exit-code semantics as the standalone command:
     *
     *  - `0` PASS / OFFLINE_VERIFIED_BROKER_AGREED
     *  - `1` INVALID_SIGNATURE
     *  - `2` UNVERIFIABLE
     *  - `3` MALFORMED
     *
     * Plus the supply-chain prefix's own codes:
     *  - `1` NOT_SIGNED_IN (only when called without `thoryn login` first)
     *
     * Per the SSO-959 spec, this subcommand is parity-by-delegation — the
     * existing crypto code is the single source of truth.
     */
    @Command(
        name = "replay",
        description = ["Replay an audit-row receipt offline (alias for `thoryn audit-replay`)."],
        mixinStandardHelpOptions = true,
    )
    class ReplaySubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Audit row ID."])
        lateinit var auditRowId: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(
            names = ["--jwks-url"],
            description = ["Override the historical-JWKS URL (default: \${DEFAULT-VALUE})."],
            defaultValue = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json",
        )
        var jwksUrl: String = "https://wallet-broker.stg.thoryn.org/.well-known/historical-jwks.json"

        override fun call(): Int {
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)

            val receiptBody: JsonNode = try {
                client.getAuditLogReceiptJson(auditRowId)
            } catch (ex: ProductApiException) {
                return SupplyChainCommandSupport.renderError(
                    format = OutputFormat.TABLE,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.audit.read",
                )
            } catch (ex: Exception) {
                System.err.println("Failed to fetch receipt: ${ex.message}")
                return SupplyChainCommandSupport.EXIT_IO_ERROR
            }

            val tempFile = Files.createTempFile("thoryn-audit-replay-", ".json").toFile()
            tempFile.deleteOnExit()
            tempFile.writeText(receiptBody.toString())

            // Delegate to the existing replay command — same crypto path,
            // same exit codes. Construct a fresh CommandLine instead of
            // touching AuditReplayCommand's internals.
            return CommandLine(AuditReplayCommand()).execute(
                tempFile.absolutePath,
                "--jwks-url", jwksUrl,
            )
        }
    }

    companion object {
        internal val SEARCH_HEADERS: List<String> = listOf(
            "auditRowId", "timestamp", "credentialClass", "outcome",
            "issuerKid", "policyVersion", "retentionHorizon",
        )

        internal fun auditRow(node: JsonNode): List<Any?> = listOf(
            node["auditRowId"]?.asString() ?: node["rowId"]?.asString(),
            node["timestamp"]?.asString() ?: node["createdAt"]?.asString(),
            node["credentialClass"]?.asString(),
            node["outcome"]?.asString(),
            node["issuerKid"]?.asString(),
            node["policyVersion"]?.asString(),
            node["retentionHorizon"]?.asString(),
        )

        internal fun auditRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "auditRowId" to (node["auditRowId"]?.asString() ?: node["rowId"]?.asString()),
            "timestamp" to (node["timestamp"]?.asString() ?: node["createdAt"]?.asString()),
            "credentialClass" to node["credentialClass"]?.asString(),
            "outcome" to node["outcome"]?.asString(),
            "issuerKid" to node["issuerKid"]?.asString(),
            "policyVersion" to node["policyVersion"]?.asString(),
            "retentionHorizon" to node["retentionHorizon"]?.asString(),
            "deviceId" to node["deviceId"]?.asString(),
            "requestId" to node["requestId"]?.asString(),
            "tenantId" to node["tenantId"]?.asString(),
        )
    }
}
