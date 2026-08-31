package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.File
import java.util.concurrent.Callable

/**
 * `thoryn federation ...` — federation-member CRUD, a thin wrapper over
 * product-api's `/federation-members` surface (SSO-1034; generic-OIDC provider
 * type added by SSO-1548) reached through the api-gateway.
 *
 * A "federation member" is an upstream IdP a tenant attaches so its users sign
 * in through that IdP rather than Thoryn's own identity-service. SSO-1548 added
 * the `oidc` provider type so Thoryn's own identity-service (or any generic
 * OIDC provider) can be attached by discovery URL + clientId + clientSecret —
 * no external IdP required.
 *
 * **Secret-safety (hard requirement).** The member's `clientSecret` is an INPUT
 * the operator supplies. It is read via a no-echo terminal prompt or a
 * `--secret-file` ([SecretIo.readSecretInput]) — there is deliberately NO
 * `--client-secret <value>` flag, because a secret in argv lands in shell
 * history and the process table. The response never carries the secret back
 * (product-api strips it), so there is nothing secret to emit on output.
 *
 * Subcommands:
 *  - `list`   — GET    /federation-members
 *  - `create` — POST   /federation-members  (clientSecret read no-echo / --secret-file)
 *  - `delete` — DELETE /federation-members/{memberId}
 *
 * Scopes: GET → `tenant:federation.read`; create/delete → `tenant:federation.write`.
 */
@Command(
    name = "federation",
    description = ["Manage federation members (upstream IdPs) in your tenant."],
    mixinStandardHelpOptions = true,
    subcommands = [
        FederationCommand.ListSubcommand::class,
        FederationCommand.CreateSubcommand::class,
        FederationCommand.DeleteSubcommand::class,
    ],
)
class FederationCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn federation <subcommand>")
        System.err.println("Subcommands: list | create | delete")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn federation list` */
    @Command(name = "list", description = ["List federation members in your tenant."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(gateway, tokens)
            return try {
                val body = client.listFederationMembers()
                CommandSupport.emitList(format, body, LIST_HEADERS, ::memberRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:federation.read")
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn federation create --provider-type oidc --display-name <n>
     *   --discovery-url <url> --client-id <id> [--secret-file <path>] [...]`
     *
     * The member `clientSecret` is read via no-echo prompt or `--secret-file` —
     * never an argv flag. `--provider-config k=v` (repeatable) supplies the
     * per-provider config map (e.g. `tenantId=<uuid>` for entra-id,
     * `orgUrl=https://x.okta.com` for okta).
     */
    @Command(name = "create", description = ["Attach a federation member (generic OIDC / identity-service / Entra / Okta / Google)."], mixinStandardHelpOptions = true)
    class CreateSubcommand : Callable<Int> {

        @Option(names = ["--provider-type"], description = ["oidc (generic / identity-service), entra-id, okta, or google."], defaultValue = "oidc")
        var providerType: String = "oidc"

        @Option(names = ["--display-name"], description = ["Human-readable member name."], required = true)
        lateinit var displayName: String

        @Option(names = ["--discovery-url"], description = ["OIDC discovery document URL (…/.well-known/openid-configuration)."], required = true)
        lateinit var discoveryUrl: String

        @Option(names = ["--client-id"], description = ["Client ID registered with the upstream IdP."], required = true)
        lateinit var clientId: String

        @Option(names = ["--secret-file"], description = ["Read the member client secret from this file (avoids exposing it on the command line). When omitted you are prompted with no echo."])
        var secretFile: File? = null

        @Option(names = ["--provider-config"], description = ["Per-provider config entry key=value (repeatable), e.g. tenantId=<uuid>, orgUrl=https://x.okta.com, hd=example.com."])
        var providerConfig: Array<String> = emptyArray()

        @Option(names = ["--claim-mapping"], description = ["Claim-mapping override key=value (repeatable). Omit to use the per-provider defaults."])
        var claimMapping: Array<String> = emptyArray()

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE

            val config = parseKeyValues(providerConfig) ?: return CommandSupport.EXIT_USAGE
            val mapping = parseKeyValues(claimMapping) ?: return CommandSupport.EXIT_USAGE

            // Secret-safety: read the upstream client secret WITHOUT it ever
            // appearing in argv — no-echo prompt or --secret-file.
            val clientSecret = SecretIo.readSecretInput(
                secretFile = secretFile,
                prompt = "Upstream IdP client secret for '$displayName': ",
            ) ?: return SecretIo.EXIT_NO_SECRET

            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(gateway, tokens)

            val body = linkedMapOf<String, Any?>(
                "providerType" to providerType,
                "displayName" to displayName,
                "discoveryUrl" to discoveryUrl,
                "clientId" to clientId,
                "clientSecret" to clientSecret,
            )
            if (config.isNotEmpty()) body["providerConfig"] = config
            if (mapping.isNotEmpty()) body["claimMapping"] = mapping

            return try {
                val response = client.createFederationMember(body)
                CommandSupport.emitRecord(format, response, ::memberRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:federation.write")
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                CommandSupport.EXIT_IO_ERROR
            }
        }

        /** Parse repeatable `k=v` flags into a map; null (with a stderr message) on a malformed entry. */
        private fun parseKeyValues(entries: Array<String>): Map<String, String>? {
            val map = linkedMapOf<String, String>()
            for (entry in entries) {
                val idx = entry.indexOf('=')
                if (idx <= 0) {
                    System.err.println("Error: malformed key=value '$entry' (expected key=value).")
                    return null
                }
                map[entry.substring(0, idx)] = entry.substring(idx + 1)
            }
            return map
        }
    }

    /** `thoryn federation delete <memberId>` */
    @Command(name = "delete", description = ["Detach a federation member."], mixinStandardHelpOptions = true)
    class DeleteSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Federation member ID (UUID)."])
        lateinit var memberId: String

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(gateway, tokens)
            return try {
                client.deleteFederationMember(memberId, confirm)
                CommandSupport.emitValue(
                    format,
                    mapOf("deleted" to true, "memberId" to memberId),
                    "Deleted federation member '$memberId'.",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:federation.write")
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf(
            "id", "providerType", "displayName", "discoveryUrl", "clientId",
        )

        internal fun memberRow(node: JsonNode): List<Any?> = listOf(
            node["id"]?.asString(),
            node["providerType"]?.asString(),
            node["displayName"]?.asString(),
            node["discoveryUrl"]?.asString(),
            node["clientId"]?.asString(),
        )

        internal fun memberRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "id" to node["id"]?.asString(),
            "providerType" to node["providerType"]?.asString(),
            "displayName" to node["displayName"]?.asString(),
            "discoveryUrl" to node["discoveryUrl"]?.asString(),
            "clientId" to node["clientId"]?.asString(),
            "createdAt" to node["createdAt"]?.asString(),
            "updatedAt" to node["updatedAt"]?.asString(),
            "version" to node["version"]?.asString(),
        )
    }
}
