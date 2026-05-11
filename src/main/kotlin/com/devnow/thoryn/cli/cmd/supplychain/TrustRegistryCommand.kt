package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain trust-registry ...` — SSO-954 parity.
 *
 * Subcommands: `list`, `add`, `preview`, `remove`. URL shapes are pinned
 * by `features/SSO-954-supply-chain-trust-registry-editor.md`:
 *
 *  - `GET    /api/v1/trust-registry/credential-classes/{classId}/issuers`
 *  - `POST   /api/v1/trust-registry/credential-classes/{classId}/issuers`
 *  - `DELETE /api/v1/trust-registry/credential-classes/{classId}/issuers/{issuerId}`
 *  - `POST   /api/v1/trust-registry/issuers/preview`
 *
 * Scopes (per ADR `2026-05-10-supply-chain-self-service-namespacing.md` §1):
 *
 *  - `tenant:supply-chain.trust-registry.read` — list, preview
 *  - `tenant:supply-chain.trust-registry.write` — add, remove
 */
@Command(
    name = "trust-registry",
    description = ["Manage the trust registry — which issuers your tenant accepts per credential class."],
    mixinStandardHelpOptions = true,
    subcommands = [
        TrustRegistryCommand.ListSubcommand::class,
        TrustRegistryCommand.AddSubcommand::class,
        TrustRegistryCommand.PreviewSubcommand::class,
        TrustRegistryCommand.RemoveSubcommand::class,
    ],
)
class TrustRegistryCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn supply-chain trust-registry <subcommand>")
        System.err.println("Subcommands: list | add | preview | remove")
        return SupplyChainCommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn supply-chain trust-registry list --credential-class <class>`
     */
    @Command(
        name = "list",
        description = ["List trusted issuers for a credential class."],
        mixinStandardHelpOptions = true,
    )
    class ListSubcommand : Callable<Int> {

        @Option(
            names = ["--credential-class"],
            description = ["Credential class, e.g. FSISustainabilityCertification."],
            required = true,
        )
        lateinit var credentialClass: String

        @Option(
            names = ["--gateway"],
            description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."],
            defaultValue = ThorynConfig.DEFAULT_GATEWAY,
        )
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
                val body = client.listTrustRegistryIssuers(credentialClass)
                SupplyChainCommandSupport.emitList(
                    format = format,
                    body = body,
                    tableHeaders = TR_LIST_HEADERS,
                    rowMapper = ::trustRegistryRow,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.trust-registry.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain trust-registry add --credential-class <class>
     *   --issuer <issuer> [--display-name <name>] [--soft-deprecate-on <date>]`
     */
    @Command(
        name = "add",
        description = ["Add a trusted issuer for a credential class."],
        mixinStandardHelpOptions = true,
    )
    class AddSubcommand : Callable<Int> {

        @Option(names = ["--credential-class"], required = true)
        lateinit var credentialClass: String

        @Option(
            names = ["--issuer"],
            description = ["Issuer DID or HTTPS URL."],
            required = true,
        )
        lateinit var issuer: String

        @Option(names = ["--display-name"])
        var displayName: String? = null

        @Option(
            names = ["--soft-deprecate-on"],
            description = ["ISO-8601 date when the issuer becomes soft-deprecated, e.g. 2027-01-01."],
        )
        var softDeprecateOn: String? = null

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
            val body = linkedMapOf<String, Any?>(
                "issuer" to issuer,
            )
            displayName?.let { body["displayName"] = it }
            softDeprecateOn?.let { body["softDeprecateOn"] = it }

            return try {
                val response = client.addTrustRegistryIssuer(credentialClass, body)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = response,
                    recordFields = ::trustRegistryRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.trust-registry.write",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain trust-registry preview --issuer <issuer>`
     *
     * Resolves the issuer's JWKS and reports kid + alg without mutating
     * registry state. Used by the console's add-issuer slide-over before
     * the operator commits.
     */
    @Command(
        name = "preview",
        description = ["Resolve an issuer's JWKS and report kid + alg (no state mutation)."],
        mixinStandardHelpOptions = true,
    )
    class PreviewSubcommand : Callable<Int> {

        @Option(names = ["--issuer"], required = true)
        lateinit var issuer: String

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
                val body = client.previewTrustRegistryIssuer(mapOf("issuer" to issuer))
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::trustRegistryRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.trust-registry.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain trust-registry remove --credential-class <class>
     *   --issuer <issuerId>`
     */
    @Command(
        name = "remove",
        description = ["Remove a trusted issuer for a credential class."],
        mixinStandardHelpOptions = true,
    )
    class RemoveSubcommand : Callable<Int> {

        @Option(names = ["--credential-class"], required = true)
        lateinit var credentialClass: String

        @Option(
            names = ["--issuer"],
            description = ["Issuer ID (DID or URL) to remove."],
            required = true,
        )
        lateinit var issuer: String

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
                client.removeTrustRegistryIssuer(credentialClass, issuer)
                when (format) {
                    OutputFormat.JSON -> com.devnow.thoryn.cli.output.Printers.json(
                        mapOf("removed" to true, "issuer" to issuer, "credentialClass" to credentialClass),
                    )
                    OutputFormat.YAML -> com.devnow.thoryn.cli.output.Printers.yaml(
                        mapOf("removed" to true, "issuer" to issuer, "credentialClass" to credentialClass),
                    )
                    OutputFormat.TABLE -> println("Removed issuer '$issuer' from credential class '$credentialClass'.")
                }
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.trust-registry.write",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    companion object {
        internal val TR_LIST_HEADERS: List<String> = listOf(
            "issuerId", "displayName", "jwksUri", "currentKid", "state",
        )

        internal fun trustRegistryRow(node: JsonNode): List<Any?> = listOf(
            node["issuerId"]?.asString() ?: node["issuer"]?.asString(),
            node["displayName"]?.asString(),
            node["jwksUri"]?.asString(),
            node["currentKid"]?.asString(),
            node["state"]?.asString(),
        )

        internal fun trustRegistryRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "issuerId" to (node["issuerId"]?.asString() ?: node["issuer"]?.asString()),
            "displayName" to node["displayName"]?.asString(),
            "jwksUri" to node["jwksUri"]?.asString(),
            "currentKid" to node["currentKid"]?.asString(),
            "alg" to node["alg"]?.asString(),
            "state" to node["state"]?.asString(),
            "softDeprecateOn" to node["softDeprecateOn"]?.asString(),
        )
    }
}
