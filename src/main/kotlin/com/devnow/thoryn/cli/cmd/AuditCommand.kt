package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn audit query` — query the tenant's audit log (configuration changes +
 * authentication events), a thin wrapper over product-api's gateway-routed,
 * `tenant:audit.read`-gated `/audit/events` surface.
 *
 * This is distinct from `thoryn supply-chain audit` (the walletless
 * credential-verification audit log under `tenant:supply-chain.audit.read`).
 * The tenant config/auth audit-event query backend lands under epic SSO-725; the
 * CLI is a thin marshaller that surfaces whatever the server returns, so it
 * works the moment the backend ships. Until then the server answers 501 and the
 * CLI reports that cleanly.
 *
 * Scope: `tenant:audit.read`.
 */
@Command(
    name = "audit",
    description = ["Query your tenant's audit log (configuration + authentication events)."],
    mixinStandardHelpOptions = true,
    subcommands = [AuditCommand.QuerySubcommand::class],
)
class AuditCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn audit <subcommand>")
        System.err.println("Subcommands: query")
        return CommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn audit query [--from <date>] [--to <date>] [--event-type <t>]
     *   [--actor <sub>] [--limit <n>] [--cursor <c>]`
     */
    @Command(name = "query", description = ["Query audit events with optional filters."], mixinStandardHelpOptions = true)
    class QuerySubcommand : Callable<Int> {

        @Option(names = ["--from"], description = ["From timestamp (ISO-8601)."])
        var from: String? = null

        @Option(names = ["--to"], description = ["To timestamp (ISO-8601)."])
        var to: String? = null

        @Option(names = ["--event-type"], description = ["Filter by event type / action."])
        var eventType: String? = null

        @Option(names = ["--actor"], description = ["Filter by actor subject."])
        var actor: String? = null

        @Option(names = ["--limit"], description = ["Page size."])
        var limit: Int? = null

        @Option(names = ["--cursor"], description = ["Opaque pagination cursor from a previous response."])
        var cursor: String? = null

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(gateway, tokens)
            val query = linkedMapOf<String, String?>(
                "from" to from,
                "to" to to,
                "eventType" to eventType,
                "actor" to actor,
                "limit" to limit?.toString(),
                "cursor" to cursor,
            )
            return try {
                val body = client.queryAuditEvents(query)
                CommandSupport.emitList(format, body, QUERY_HEADERS, ::auditEventRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:audit.read")
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    companion object {
        internal val QUERY_HEADERS: List<String> = listOf(
            "timestamp", "action", "actorSub", "outcome", "rowId",
        )

        internal fun auditEventRow(node: JsonNode): List<Any?> = listOf(
            node["timestamp"]?.asString() ?: node["createdAt"]?.asString(),
            node["action"]?.asString() ?: node["eventType"]?.asString(),
            node["actorSub"]?.asString() ?: node["actor"]?.asString(),
            node["outcome"]?.asString(),
            node["rowId"]?.asString() ?: node["id"]?.asString(),
        )
    }
}
