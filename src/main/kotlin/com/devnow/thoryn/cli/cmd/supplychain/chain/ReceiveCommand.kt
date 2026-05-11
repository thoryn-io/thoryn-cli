package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain chain receive --bridge-id <id> --parent-jws <jws-or-urn>
 *   [--parent-jws <...>]`
 *
 * Verifies N incoming credentials without state change — the operator's
 * pre-action sanity check before the Receive screen in SSO-962. Calls
 * `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/receive` on the
 * gateway; the product-api dispatches each parent to
 * `POST /broker/verify/walletless` and returns a normalised verdict per
 * parent for the operator to acknowledge.
 *
 * Scope: `tenant:supply-chain.issuer-bridge.intermediary.read`.
 *
 * `--parent-jws` is repeatable. Each value is either a compact JWS
 * (`eyJhbGc…`) or a credential URN (`urn:vc:01HXY…`); the product-api
 * accepts both and disambiguates on the server side.
 */
@Command(
    name = "receive",
    description = ["Verify N incoming credentials without state change (SSO-962 Receive screen)."],
    mixinStandardHelpOptions = true,
)
class ReceiveCommand : Callable<Int> {

    @Option(
        names = ["--bridge-id"],
        description = ["Issuer-bridge that is doing the receiving (your tenant's processing bridge)."],
        required = true,
    )
    lateinit var bridgeId: String

    @Option(
        names = ["--parent-jws"],
        description = [
            "Compact JWS or credential URN of an incoming parent credential. " +
                "Repeat once per parent.",
        ],
        required = true,
    )
    lateinit var parentJws: Array<String>

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
        if (parentJws.isEmpty()) {
            System.err.println("Error: at least one --parent-jws is required.")
            return SupplyChainCommandSupport.EXIT_USAGE
        }
        val tokens = SupplyChainCommandSupport.readTokens()
            ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
        val client = SupplyChainCommandSupport.client(gateway, tokens)
        val body: Map<String, Any?> = mapOf("parents" to parentJws.toList())
        return try {
            val response = client.intermediaryReceive(bridgeId, body)
            SupplyChainCommandSupport.emitList(
                format = format,
                body = response,
                tableHeaders = HEADERS,
                rowMapper = ::parentRow,
            )
            SupplyChainCommandSupport.EXIT_OK
        } catch (ex: ProductApiException) {
            SupplyChainCommandSupport.renderError(
                format = format,
                ex = ex,
                requiredScope = "tenant:supply-chain.issuer-bridge.intermediary.read",
            )
        } catch (ex: Exception) {
            System.err.println("Request failed: ${ex.message}")
            SupplyChainCommandSupport.EXIT_IO_ERROR
        }
    }

    companion object {
        internal val HEADERS: List<String> = listOf(
            "credentialId", "actor", "batchId", "quantity", "validUntil", "verdict",
        )

        internal fun parentRow(node: JsonNode): List<Any?> = listOf(
            node["credentialId"]?.asString(),
            node["actor"]?.asString() ?: node["issuer"]?.asString(),
            node["batchId"]?.asString(),
            node["quantity"]?.let { q ->
                val amount = q["amount"]?.asString() ?: ""
                val unit = q["unit"]?.asString() ?: ""
                if (amount.isNotEmpty()) "$amount$unit" else null
            },
            node["validUntil"]?.asString(),
            node["verdict"]?.asString(),
        )
    }
}
