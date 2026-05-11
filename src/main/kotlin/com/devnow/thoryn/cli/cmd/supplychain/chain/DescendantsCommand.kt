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
 * `thoryn supply-chain chain descendants <urn> [--depth 5] [--holder]`
 *
 * Downward DAG view. Two consumers, two endpoints:
 *
 *  - **Operator view (default)** — `GET /broker/internal/credentials/{id}/descendants`
 *    (SSO-965). Used by the issuer-bridge ops console to compute the
 *    pre-revoke blast radius. Scope: `tenant:supply-chain.issuer-bridge.revoke`.
 *  - **Holder view (`--holder`)** — `GET /api/v1/holder/credentials/{id}/descendants`
 *    (SSO-967). Used by the producer-facing holder portal for the
 *    afstammingen view. Respects the tenant's `hideDownstreamFromProducers`
 *    privacy toggle — returns `{ descendants: null, reason: "tenant_privacy_policy" }`
 *    when the toggle is on. Scope: standard holder-portal authority.
 *
 * The CLI surfaces both because they answer different questions for
 * different roles — an operator can see their own tenant's downstream
 * unconditionally; a producer holder reaches across tenant boundaries and
 * must respect the downstream tenant's privacy policy. Per the SSO-970 spec,
 * picking which endpoint to hit is the operator's choice; documenting the
 * default (operator) in the PR is mandatory.
 *
 * **Default = operator endpoint** because that's the "I have the URN and I
 * want to know what flips if I revoke it" question the issuer-bridge ops
 * console asks. The holder afstammingen view from `apps/holder` is more
 * naturally invoked from the holder portal itself; the `--holder` flag is
 * present for parity but is the less common CLI path.
 */
@Command(
    name = "descendants",
    description = ["Show the downward DAG (operator: SSO-965 blast radius; --holder: SSO-967 afstammingen)."],
    mixinStandardHelpOptions = true,
)
class DescendantsCommand : Callable<Int> {

    @Parameters(
        index = "0",
        description = ["Credential URN to walk downward from."],
    )
    lateinit var credentialUrn: String

    @Option(
        names = ["--depth"],
        description = ["Depth cap (default: server default, 5)."],
    )
    var depth: Int? = null

    @Option(
        names = ["--holder"],
        description = [
            "Use the holder-portal endpoint (SSO-967, respects the tenant " +
                "privacy toggle) instead of the operator endpoint (SSO-965).",
        ],
    )
    var holder: Boolean = false

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
            val body = if (holder) {
                client.getHolderCredentialDescendants(credentialUrn, depth)
            } else {
                client.getCredentialDescendants(credentialUrn, depth)
            }
            when (format) {
                OutputFormat.JSON -> Printers.json(body)
                OutputFormat.YAML -> Printers.yaml(body)
                OutputFormat.TABLE -> {
                    // SSO-967: tenant privacy toggle short-circuits the response.
                    val reason = body["reason"]?.asString()
                    val descendants = body["descendants"]
                    if (descendants != null && descendants.isNull && reason != null) {
                        println("Path hidden by tenant policy.")
                        println("Reason: $reason")
                    } else if (descendants != null && descendants.isArray) {
                        println("Descendants of $credentialUrn:")
                        // Render as a single-rooted tree by wrapping the
                        // operator endpoint's flat list under the credential
                        // we just asked about.
                        val root = body
                        ChainTreeRenderer.render(root, System.out)
                    } else {
                        // Fallback to the recursive renderer on the full body
                        // (handles the nested-shape variant SSO-967 uses).
                        ChainTreeRenderer.render(body, System.out)
                    }
                }
            }
            SupplyChainCommandSupport.EXIT_OK
        } catch (ex: ProductApiException) {
            val requiredScope = if (holder) {
                "tenant:supply-chain.issuer-bridge.read"
            } else {
                "tenant:supply-chain.issuer-bridge.revoke"
            }
            SupplyChainCommandSupport.renderError(
                format = format,
                ex = ex,
                requiredScope = requiredScope,
            )
        } catch (ex: Exception) {
            System.err.println("Request failed: ${ex.message}")
            SupplyChainCommandSupport.EXIT_IO_ERROR
        }
    }
}
