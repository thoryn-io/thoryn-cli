package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn env ...` — select & manage the ENVIRONMENTS of the currently-selected workspace
 * (SSO-2870, closing the SSO-2408 CLI gap). A workspace holds N durable **sandbox** environments plus
 * one platform-managed **production** environment; the customer plane is environment-scoped, so a
 * client/user/… created in a sandbox is invisible to a request that resolves to a different environment.
 *
 * The CLI had no environment dimension, so it was hard-wired to the production plane and
 * `thoryn clients list` returned an empty set for a workspace whose clients live in a sandbox. This
 * command adds the missing piece: `env use <slug>` records the selected environment on the workspace
 * selection ([SelectedWorkspaceStore]), and [CommandSupport.gatewayClient] then rides it on every
 * request as the `X-Thoryn-Environment` header — the same admin selector the console uses.
 *
 * A thin wrapper over product-api's `/api/v1/environments` (SSO-2410). Scopes: read →
 * `tenant:environments.read`, write → `tenant:environments.write` (already granted to `thoryn-cli`,
 * hub V119). Management calls use an environment-UNSCOPED client so they keep working even when the
 * current selection is stale/suspended.
 *
 * Subcommands:
 *  - `list`        — GET  /api/v1/environments (marks the active one)
 *  - `use <slug>`  — record the selected environment (local; validated against the live list)
 *  - `create`      — POST /api/v1/environments  (a sandbox)
 *  - `rename`      — PATCH /api/v1/environments/{id}
 *  - `suspend`     — POST /api/v1/environments/{id}/suspend
 *  - `reactivate`  — POST /api/v1/environments/{id}/reactivate
 *
 * There is no standalone `delete` subcommand yet. A sandbox CAN be hard-deleted through product-api's
 * `DELETE /api/v1/environments/{id}` (SSO-2960) — the example-recipe `env.delete` teardown action
 * (SSO-2961) uses it to tear down an ephemeral sandbox; a `thoryn env delete` command is future work.
 */
@Command(
    name = "env",
    description = ["Select and manage the environments (sandboxes + production) of your workspace."],
    mixinStandardHelpOptions = true,
    subcommands = [
        EnvironmentCommand.ListSubcommand::class,
        EnvironmentCommand.UseSubcommand::class,
        EnvironmentCommand.CreateSubcommand::class,
        EnvironmentCommand.RenameSubcommand::class,
        EnvironmentCommand.SuspendSubcommand::class,
        EnvironmentCommand.ReactivateSubcommand::class,
    ],
)
class EnvironmentCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn env <subcommand>")
        System.err.println("Subcommands: list | use | create | rename | suspend | reactivate")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn env list` — the workspace's environments, marking the one the CLI currently targets. */
    @Command(name = "list", description = ["List the environments in your workspace."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            // A null selection ⇒ the CLI resolves to the production plane; mark that as active.
            val active = runCatching { store.read()?.environmentSlug }.getOrNull()
                ?: ThorynConfig.PRODUCTION_ENV_SLUG
            return try {
                val envs = client.listEnvironments().environmentsArray()
                CommandSupport.emitList(format, envs, LIST_HEADERS, rowMapper = { row(it, active) })
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn env use <slug>` — target an environment for subsequent commands.
     *
     * Records the selected environment on the current workspace selection; every later command then
     * sends `X-Thoryn-Environment: <slug>`. Validated against the live list so a typo fails fast. Use
     * the workspace's production slug (`production`) to return to the production plane.
     */
    @Command(name = "use", description = ["Select an environment for subsequent commands (e.g. a sandbox)."], mixinStandardHelpOptions = true)
    class UseSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Environment slug (a sandbox, or 'production')."])
        lateinit var slug: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val selected = runCatching { store.read() }.getOrNull()
            if (selected == null) {
                System.err.println("Error: no workspace selected. Run `thoryn workspace switch <slug>` first —")
                System.err.println("environments live inside a workspace.")
                return CommandSupport.EXIT_USAGE
            }
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val target = slug.trim()

            val match = try {
                client.listEnvironments().environmentsArray().toList()
                    .firstOrNull { it["slug"]?.asString() == target }
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.read")
            } catch (ex: Exception) {
                return CommandSupport.renderRequestFailure(ex, gateway)
            }
            if (match == null) {
                System.err.println("Error: no environment with slug '$target' in workspace '${selected.slug}'.")
                System.err.println("Run `thoryn env list` to see this workspace's environments.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            if (match["suspended"]?.asBoolean() == true) {
                System.err.println("Warning: environment '$target' is suspended; requests to it may be rejected.")
            }

            store.write(selected.copy(environmentSlug = target))
            CommandSupport.emitValue(
                format,
                mapOf("environment" to target, "workspace" to selected.slug),
                "Now targeting environment '$target' in workspace '${selected.slug}'.",
            )
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn env create <slug> --name <name>` — create a sandbox environment. */
    @Command(name = "create", description = ["Create a sandbox environment."], mixinStandardHelpOptions = true)
    class CreateSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Environment slug (URL-safe: letters, digits, '-', '_')."])
        lateinit var slug: String

        @Option(names = ["--name"], description = ["Human-readable environment name."], required = true)
        lateinit var name: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val env = client.createEnvironment(mapOf("slug" to slug.trim(), "name" to name.trim()))
                CommandSupport.emitRecord(format, env, ::recordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn env rename <slug> --name <name>` — change an environment's display name (slug is immutable). */
    @Command(name = "rename", description = ["Rename an environment (display name only; slug is immutable)."], mixinStandardHelpOptions = true)
    class RenameSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Environment slug to rename."])
        lateinit var slug: String

        @Option(names = ["--name"], description = ["New display name."], required = true)
        lateinit var name: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val id = resolveIdOrNull(client, slug.trim(), format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val env = client.renameEnvironment(id, mapOf("name" to name.trim()))
                CommandSupport.emitRecord(format, env, ::recordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn env suspend <slug> [--confirm <slug>]` — suspend a sandbox (production cannot be suspended). */
    @Command(name = "suspend", description = ["Suspend a sandbox environment."], mixinStandardHelpOptions = true)
    class SuspendSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Sandbox environment slug to suspend."])
        lateinit var slug: String

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val id = resolveIdOrNull(client, slug.trim(), format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val env = client.suspendEnvironment(id, confirm)
                CommandSupport.emitRecord(format, env, ::recordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn env reactivate <slug>` — clear a sandbox suspension. */
    @Command(name = "reactivate", description = ["Reactivate a suspended sandbox environment."], mixinStandardHelpOptions = true)
    class ReactivateSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Sandbox environment slug to reactivate."])
        lateinit var slug: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val id = resolveIdOrNull(client, slug.trim(), format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val env = client.reactivateEnvironment(id)
                CommandSupport.emitRecord(format, env, ::recordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf("slug", "name", "kind", "suspended", "active")

        /** The `environments` array from the list envelope (`{ "environments": [...] }`). */
        internal fun JsonNode.environmentsArray(): JsonNode = this["environments"] ?: this

        internal fun row(node: JsonNode, activeSlug: String?): List<Any?> {
            val slug = node["slug"]?.asString()
            return listOf(
                slug,
                node["name"]?.asString(),
                node["kind"]?.asString(),
                node["suspended"]?.asBoolean() ?: false,
                if (slug != null && slug == activeSlug) "*" else "",
            )
        }

        internal fun recordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "id" to node["id"]?.asString(),
            "slug" to node["slug"]?.asString(),
            "name" to node["name"]?.asString(),
            "kind" to node["kind"]?.asString(),
            "suspended" to (node["suspended"]?.asBoolean() ?: false),
            "createdAt" to node["createdAt"]?.asString(),
            "suspendedAt" to node["suspendedAt"]?.asString(),
        )

        /**
         * Resolve an environment SLUG to its UUID `id` (the CRUD verbs are keyed by id). Prints a
         * user-facing error and returns null when the slug is unknown or the list call fails.
         */
        internal fun resolveIdOrNull(
            client: ProductApiClient,
            slug: String,
            format: com.devnow.thoryn.cli.output.OutputFormat,
            gateway: String,
        ): String? {
            val match = try {
                client.listEnvironments().environmentsArray().toList()
                    .firstOrNull { it["slug"]?.asString() == slug }
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.read")
                return null
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
                return null
            }
            if (match == null) {
                System.err.println("Error: no environment with slug '$slug' in your workspace.")
                System.err.println("Run `thoryn env list` to see your environments.")
                return null
            }
            return match["id"]?.asString()
        }
    }
}
