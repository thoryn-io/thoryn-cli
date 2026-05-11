package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain chain issue --bridge-id <id> --parent <urn>
 *   --action processed_combined --batch-id <id> --quantity 850kg
 *   --output-jws receipt.jws`
 *
 * Combine path of the intermediary flow (SSO-962): N parents → 1 outgoing
 * credential. Calls
 * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/issue` with the
 * supplied action; the product-api routes through
 * `POST /broker/internal/credentials/bulk` (SSO-963) under the hood.
 *
 * Allowed actions for this subcommand (the **combine** half of SSO-962's
 * action picker): `processed_combined`, `packaged_combined`. The `split`
 * variant lives in [SplitCommand] because its inputs and outputs differ.
 *
 * Scope: `tenant:supply-chain.issuer-bridge.intermediary.write`.
 *
 * On success the response carries `credentialId` + compact JWS. If
 * `--output-jws <file>` is supplied, the JWS is written there in compact
 * form (one line, no newline at end); otherwise it goes to stdout under
 * `--output json` / `--output yaml`, or is rendered as a record in
 * `--output table`.
 */
@Command(
    name = "issue",
    description = ["Mint one combined credential from N parents (SSO-962 combine path)."],
    mixinStandardHelpOptions = true,
)
class IssueCommand : Callable<Int> {

    @Option(
        names = ["--bridge-id"],
        description = ["Issuer-bridge that signs the outgoing credential."],
        required = true,
    )
    lateinit var bridgeId: String

    @Option(
        names = ["--parent"],
        description = [
            "Credential URN of a parent (incoming) credential. Repeat once per " +
                "parent for the combine path; the server reconciles quantities " +
                "against the receive list.",
        ],
        required = true,
    )
    lateinit var parents: Array<String>

    @Option(
        names = ["--action"],
        description = [
            "One of: processed_combined | packaged_combined. (Use `thoryn " +
                "supply-chain chain split` for the split path.)",
        ],
        required = true,
    )
    lateinit var action: String

    @Option(
        names = ["--batch-id"],
        description = ["Outgoing batch ID, e.g. `ROAST-2026-W18`."],
        required = true,
    )
    lateinit var batchId: String

    @Option(
        names = ["--quantity"],
        description = [
            "Outgoing quantity with unit, e.g. `850kg`, `1200lb`, `300stuks`. " +
                "Numeric prefix + alphabetic unit suffix; the CLI splits and " +
                "forwards both as a structured `{amount, unit}` object.",
        ],
        required = true,
    )
    lateinit var quantity: String

    @Option(
        names = ["--subject"],
        description = ["Subject DID of the outgoing credential (defaults to the bridge's own DID)."],
    )
    var subject: String? = null

    @Option(
        names = ["--notes"],
        description = ["Optional free-form notes attached to the action audit row."],
    )
    var notes: String? = null

    @Option(
        names = ["--output-jws"],
        description = ["Write the resulting compact JWS to this file."],
    )
    var outputJws: Path? = null

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
        if (action !in ALLOWED_ACTIONS) {
            System.err.println(
                "Error: --action must be one of ${ALLOWED_ACTIONS.joinToString(" | ")} (was '$action').",
            )
            return SupplyChainCommandSupport.EXIT_USAGE
        }
        val parsedQty = parseQuantity(quantity) ?: run {
            System.err.println(
                "Error: --quantity must be <amount><unit> (e.g. 850kg, 300stuks); got '$quantity'.",
            )
            return SupplyChainCommandSupport.EXIT_USAGE
        }
        if (parents.isEmpty()) {
            System.err.println("Error: at least one --parent is required.")
            return SupplyChainCommandSupport.EXIT_USAGE
        }
        val tokens = SupplyChainCommandSupport.readTokens()
            ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
        val client = SupplyChainCommandSupport.client(gateway, tokens)
        val body: Map<String, Any?> = linkedMapOf<String, Any?>(
            "action" to action,
            "parentCredentialIds" to parents.toList(),
            "outgoing" to linkedMapOf<String, Any?>(
                "batchId" to batchId,
                "quantity" to linkedMapOf<String, Any?>(
                    "amount" to parsedQty.first,
                    "unit" to parsedQty.second,
                ),
            ).apply {
                if (subject != null) put("subject", subject)
                if (notes != null) put("notes", notes)
            },
        )
        return try {
            val response = client.intermediaryIssue(bridgeId, body)
            outputJws?.let { writeJws(it, response) }
            SupplyChainCommandSupport.emitRecord(
                format = format,
                body = response,
                recordFields = ::issueRecordFields,
            )
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

    private fun writeJws(target: Path, response: JsonNode) {
        // The intermediary/issue response for combine returns `{ credentialId,
        // jws, auditRowId, ... }`. The split path returns a `children` array;
        // that's handled by SplitCommand.
        val jws = response["jws"]?.asString()
            ?: response["children"]?.takeIf { it.isArray && it.size() == 1 }?.get(0)?.get("jws")?.asString()
        if (jws == null) {
            System.err.println("Warning: response did not include a compact JWS; skipping --output-jws write.")
            return
        }
        Files.writeString(target, jws)
        System.err.println("Wrote ${jws.length} characters of compact JWS to $target")
    }

    companion object {
        internal val ALLOWED_ACTIONS: List<String> = listOf(
            "processed_combined",
            "packaged_combined",
        )

        /**
         * Split a `<amount><unit>` string into a numeric amount and an
         * alphabetic unit. Trailing whitespace is tolerated, embedded
         * whitespace is not. Returns null on a malformed input.
         */
        internal fun parseQuantity(raw: String): Pair<Number, String>? {
            val trimmed = raw.trim()
            val splitAt = trimmed.indexOfFirst { !(it.isDigit() || it == '.' || it == ',') }
            if (splitAt <= 0) return null
            val amountStr = trimmed.substring(0, splitAt).replace(',', '.')
            val unitStr = trimmed.substring(splitAt).trim()
            if (unitStr.isEmpty()) return null
            val amount = amountStr.toDoubleOrNull() ?: return null
            // Preserve int-vs-double in the serialised payload so the server
            // doesn't get `1.0` when the operator typed `1kg`.
            val isInt = !amountStr.contains('.')
            return Pair(if (isInt) amount.toLong() as Number else amount as Number, unitStr)
        }

        internal fun issueRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "credentialId" to node["credentialId"]?.asString(),
            "splitEventId" to node["splitEventId"]?.asString(),
            "auditRowId" to node["auditRowId"]?.asString(),
            "action" to node["action"]?.asString(),
            "issuedAt" to node["issuedAt"]?.asString(),
            "jwsLength" to node["jws"]?.asString()?.length,
            "qrPdfBase64Bytes" to node["qrPdfBase64"]?.asString()?.let {
                runCatching { Base64.getDecoder().decode(it).size }.getOrNull()
            },
        )
    }
}
