package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain chain walk <leaf-urn> [--depth 5] [--output ...]`
 *
 * Chain walker (SSO-964): verify the leaf credential, walk
 * `parentCredentialIds` upward at-time-of-handling, and return the
 * aggregate verdict (lowest common denominator). Calls
 * `POST /broker/verify/walletless?walkChain=true` on the gateway.
 *
 * Scope: standard verifier authority — `tenant:supply-chain.issuer-bridge.read`
 * is the closest match the CLI tracks today; the broker endpoint accepts
 * any bearer with the verifier role. (The exact scope is settled by
 * SSO-949 and SSO-964 server-side; the CLI surfaces whichever
 * `insufficient_scope` the server returns.)
 *
 * **Output:**
 *  - `--output table` (default) — ASCII tree via [ChainTreeRenderer], plus a
 *    one-line aggregate verdict header.
 *  - `--output json` / `--output yaml` — the raw walk-DAG response.
 */
@Command(
    name = "walk",
    description = ["Walk the chain upward from a leaf credential and render the DAG (SSO-964)."],
    mixinStandardHelpOptions = true,
)
class WalkCommand : Callable<Int> {

    @Parameters(
        index = "0",
        description = ["Leaf credential URN to walk upward from (e.g. urn:vc:01HXY...). Pass `-` to read a compact JWS from stdin."],
    )
    lateinit var leaf: String

    @Option(
        names = ["--depth"],
        description = ["Depth cap; the server's hard cap is 5 (SSO-964). Defaults to the server default."],
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
        val resolvedLeaf = if (leaf == "-") {
            // Stdin path — useful for `cat foo.jws | thoryn supply-chain chain walk -`.
            System.`in`.bufferedReader().readText().trim()
        } else {
            leaf
        }
        val body: Map<String, Any?> = linkedMapOf<String, Any?>(
            "credential" to resolvedLeaf,
        ).apply {
            if (depth != null) put("depthCap", depth)
        }
        return try {
            val response = client.verifyWalletlessWithChain(body)
            when (format) {
                OutputFormat.JSON -> Printers.json(response)
                OutputFormat.YAML -> Printers.yaml(response)
                OutputFormat.TABLE -> {
                    val aggregate = response["verdict"]?.asString() ?: "?"
                    val auditRowId = response["auditRowId"]?.asString() ?: "?"
                    println("Aggregate verdict: $aggregate")
                    println("Audit row:         $auditRowId")
                    println()
                    val chain = response["chain"] ?: response
                    ChainTreeRenderer.render(chain, System.out)
                }
            }
            SupplyChainCommandSupport.EXIT_OK
        } catch (ex: ProductApiException) {
            SupplyChainCommandSupport.renderError(
                format = format,
                ex = ex,
                requiredScope = "tenant:supply-chain.issuer-bridge.read",
            )
        } catch (ex: Exception) {
            System.err.println("Request failed: ${ex.message}")
            SupplyChainCommandSupport.EXIT_IO_ERROR
        }
    }
}
