package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain chain revoke <urn> --reason "..." [--dry-run]`
 *
 * Direct revoke with downward propagation (SSO-965): flip the credential's
 * Status List 2021 bit + automatically write `REVOKED_VIA_PARENT` for every
 * descendant. Calls `POST /broker/internal/credentials/{id}/revoke` on the
 * gateway.
 *
 * Scope: `tenant:supply-chain.issuer-bridge.revoke`.
 *
 * **`--dry-run`** swaps the destructive POST for a `GET .../descendants`
 * call and renders the **blast radius** — exactly what the console's
 * SSO-965 modal shows BEFORE commit. The exit code is still 0 on a
 * successful dry-run; nothing is mutated. This is the audited gap between
 * an operator's "I think I want to do this" and "I am committing this".
 *
 * **`--reason`** must be at least 10 characters (server enforces; the CLI
 * mirrors client-side per SSO-957 / SSO-965 convention).
 */
@Command(
    name = "revoke",
    description = ["Revoke a credential and propagate REVOKED_VIA_PARENT to descendants (SSO-965); --dry-run shows blast radius."],
    mixinStandardHelpOptions = true,
)
class RevokeCommand : Callable<Int> {

    @Parameters(
        index = "0",
        description = ["Credential URN to revoke."],
    )
    lateinit var credentialUrn: String

    @Option(
        names = ["--reason"],
        description = ["Required revoke reason (>= 10 chars). Ignored on --dry-run."],
        required = false,
    )
    var reason: String? = null

    @Option(
        names = ["--dry-run"],
        description = [
            "Skip the actual revoke; fetch descendants and print the blast " +
                "radius the operator is about to flip.",
        ],
    )
    var dryRun: Boolean = false

    @Option(
        names = ["--depth"],
        description = ["Depth cap for the dry-run descendant walk (default: server default, 5)."],
    )
    var depth: Int? = null

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
        val tokens = SupplyChainCommandSupport.readTokens()
            ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
        val client = SupplyChainCommandSupport.client(gateway, tokens)
        return try {
            if (dryRun) {
                val descendants = client.getCredentialDescendants(credentialUrn, depth)
                renderBlastRadius(format, descendants)
                SupplyChainCommandSupport.EXIT_OK
            } else {
                val reasonResolved = reason
                if (reasonResolved == null || reasonResolved.length < 10) {
                    System.err.println("Error: --reason must be at least 10 characters (use --dry-run to preview without committing).")
                    return SupplyChainCommandSupport.EXIT_USAGE
                }
                val response = client.revokeCredentialWithPropagation(credentialUrn, reasonResolved)
                renderRevokeResult(format, response)
                SupplyChainCommandSupport.EXIT_OK
            }
        } catch (ex: ProductApiException) {
            SupplyChainCommandSupport.renderError(
                format = format,
                ex = ex,
                requiredScope = "tenant:supply-chain.issuer-bridge.revoke",
            )
        } catch (ex: Exception) {
            System.err.println("Request failed: ${ex.message}")
            SupplyChainCommandSupport.EXIT_IO_ERROR
        }
    }

    private fun renderBlastRadius(format: OutputFormat, descendants: JsonNode) {
        when (format) {
            OutputFormat.JSON -> Printers.json(descendants)
            OutputFormat.YAML -> Printers.yaml(descendants)
            OutputFormat.TABLE -> {
                println("Dry-run — blast radius for $credentialUrn")
                val total = descendants["total"]?.asInt()
                    ?: descendants["count"]?.asInt()
                    ?: descendants["descendants"]?.size()
                    ?: 0
                println("  Direct revoke target: $credentialUrn")
                println("  Descendants flipped to REVOKED_VIA_PARENT: $total")
                val byAction = descendants["byActionType"]
                if (byAction != null && byAction.isObject) {
                    println("  Breakdown by actionType:")
                    for (entry in byAction.properties()) {
                        val v = entry.value
                        val rendered = when {
                            v == null -> "?"
                            v.isNumber -> v.asInt().toString()
                            v.isTextual -> v.asString()
                            else -> v.toString()
                        }
                        println("    - ${entry.key}: $rendered")
                    }
                }
                println("Nothing committed. Re-run without --dry-run to apply.")
            }
        }
    }

    private fun renderRevokeResult(format: OutputFormat, response: JsonNode) {
        SupplyChainCommandSupport.emitRecord(
            format = format,
            body = response,
            recordFields = { node ->
                listOf(
                    "credentialId" to node["credentialId"]?.asString(),
                    "revocationKind" to (node["revocationKind"]?.asString() ?: "DIRECT"),
                    "revokedAt" to node["revokedAt"]?.asString(),
                    "auditRowId" to node["auditRowId"]?.asString(),
                    "descendantsFlipped" to (
                        node["descendantsFlipped"]?.asInt()
                            ?: node["propagatedCount"]?.asInt()
                            ?: 0
                        ),
                )
            },
        )
    }
}
