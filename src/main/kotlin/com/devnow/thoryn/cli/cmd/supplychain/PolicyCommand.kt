package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain policy ...` — SSO-955 parity for the per-credential-class
 * verification-policy editor.
 *
 * URL shapes (per `features/SSO-955-supply-chain-verification-policy-editor.md`):
 *
 *  - `GET /api/v1/verification-policies`
 *  - `GET /api/v1/verification-policies/{credentialClass}`
 *  - `PUT /api/v1/verification-policies/{credentialClass}` — body:
 *    `{requireFreshRevocation, statusListCacheTtlSeconds, retentionHorizonYears}`
 *
 * Scopes:
 *  - `tenant:supply-chain.policy.read` — list, show
 *  - `tenant:supply-chain.policy.write` — set
 */
@Command(
    name = "policy",
    description = ["Manage per-credential-class verification policy (require-fresh-revocation, cache TTL, retention horizon)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        PolicyCommand.ListSubcommand::class,
        PolicyCommand.ShowSubcommand::class,
        PolicyCommand.SetSubcommand::class,
    ],
)
class PolicyCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn supply-chain policy <subcommand>")
        System.err.println("Subcommands: list | show | set")
        return SupplyChainCommandSupport.EXIT_USAGE
    }

    /** `thoryn supply-chain policy list` */
    @Command(
        name = "list",
        description = ["List verification policies, one row per credential class."],
        mixinStandardHelpOptions = true,
    )
    class ListSubcommand : Callable<Int> {

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
                val body = client.listVerificationPolicies()
                SupplyChainCommandSupport.emitList(
                    format = format,
                    body = body,
                    tableHeaders = LIST_HEADERS,
                    rowMapper = ::policyRow,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.policy.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** `thoryn supply-chain policy show --credential-class <class>` */
    @Command(
        name = "show",
        description = ["Show the verification policy for a credential class."],
        mixinStandardHelpOptions = true,
    )
    class ShowSubcommand : Callable<Int> {

        @Option(names = ["--credential-class"], required = true)
        lateinit var credentialClass: String

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
                val body = client.getVerificationPolicy(credentialClass)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::policyRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.policy.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain policy set --credential-class <class>
     *   --require-fresh-revocation <bool>
     *   --status-list-cache-ttl-seconds <int>
     *   --retention-horizon-years <int>`
     */
    @Command(
        name = "set",
        description = ["Update the verification policy for a credential class."],
        mixinStandardHelpOptions = true,
    )
    class SetSubcommand : Callable<Int> {

        @Option(names = ["--credential-class"], required = true)
        lateinit var credentialClass: String

        @Option(
            names = ["--require-fresh-revocation"],
            description = ["true → 503 on status-list unreachable; false → 200 VALID_REVOCATION_UNCHECKED (amber)."],
            arity = "1",
            paramLabel = "<bool>",
        )
        var requireFreshRevocation: Boolean? = null

        @Option(
            names = ["--status-list-cache-ttl-seconds"],
            description = ["Status-list cache TTL in seconds (min 60, max 3600, default 300)."],
        )
        var statusListCacheTtlSeconds: Int? = null

        @Option(
            names = ["--retention-horizon-years"],
            description = ["Audit-row retention horizon in years (min 1, max 25, default 7)."],
        )
        var retentionHorizonYears: Int? = null

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
            val body = linkedMapOf<String, Any?>()
            requireFreshRevocation?.let { body["requireFreshRevocation"] = it }
            statusListCacheTtlSeconds?.let { body["statusListCacheTtlSeconds"] = it }
            retentionHorizonYears?.let { body["retentionHorizonYears"] = it }
            if (body.isEmpty()) {
                System.err.println(
                    "Error: pass at least one of --require-fresh-revocation, " +
                        "--status-list-cache-ttl-seconds, --retention-horizon-years.",
                )
                return SupplyChainCommandSupport.EXIT_USAGE
            }
            return try {
                val response = client.setVerificationPolicy(credentialClass, body)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = response,
                    recordFields = ::policyRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.policy.write",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf(
            "credentialClass", "requireFreshRevocation", "cacheTtlSeconds",
            "retentionYears", "policyVersion", "updatedAt",
        )

        internal fun policyRow(node: JsonNode): List<Any?> = listOf(
            node["credentialClass"]?.asString(),
            node["requireFreshRevocation"]?.asBoolean(),
            node["statusListCacheTtlSeconds"]?.asInt(),
            node["retentionHorizonYears"]?.asInt(),
            node["policyVersion"]?.asString(),
            node["updatedAt"]?.asString(),
        )

        internal fun policyRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "credentialClass" to node["credentialClass"]?.asString(),
            "requireFreshRevocation" to node["requireFreshRevocation"]?.asBoolean(),
            "statusListCacheTtlSeconds" to node["statusListCacheTtlSeconds"]?.asInt(),
            "retentionHorizonYears" to node["retentionHorizonYears"]?.asInt(),
            "policyVersion" to node["policyVersion"]?.asString(),
            "updatedAt" to node["updatedAt"]?.asString(),
            "updatedBy" to node["updatedBy"]?.asString(),
        )
    }
}
