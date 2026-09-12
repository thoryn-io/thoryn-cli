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
 *  - `get <id>`    — GET  /api/v1/environments/{id} (a single record)
 *  - `use <slug>`  — record the selected environment (local; validated against the live list)
 *  - `create`      — POST /api/v1/environments  (a sandbox)
 *  - `rename`      — PATCH /api/v1/environments/{id}
 *  - `suspend`     — POST /api/v1/environments/{id}/suspend
 *  - `reactivate`  — POST /api/v1/environments/{id}/reactivate
 *  - `delete <id>` — DELETE /api/v1/environments/{id} (SSO-2960; IRREVERSIBLE, confirm-guarded)
 *
 * `delete` (SSO-2964) hard-deletes a **sandbox** and purges every environment-scoped row within it.
 * It reuses product-api's `DELETE /api/v1/environments/{id}` (SSO-2960) — the same endpoint the
 * example-recipe `env.delete` teardown action (SSO-2961) drives — under the SSO-2413 destructive-action
 * confirmation contract: `--confirm <slug>` must equal the environment's OWN slug and rides as the
 * `X-Thoryn-Confirm` header; the production plane refuses deletion outright.
 */
@Command(
    name = "env",
    description = ["Select and manage the environments (sandboxes + production) of your workspace."],
    mixinStandardHelpOptions = true,
    subcommands = [
        EnvironmentCommand.ListSubcommand::class,
        EnvironmentCommand.GetSubcommand::class,
        EnvironmentCommand.UseSubcommand::class,
        EnvironmentCommand.CreateSubcommand::class,
        EnvironmentCommand.RenameSubcommand::class,
        EnvironmentCommand.SuspendSubcommand::class,
        EnvironmentCommand.ReactivateSubcommand::class,
        EnvironmentCommand.DeleteSubcommand::class,
        EnvironmentCommand.TestEmailsSubcommand::class,
    ],
)
class EnvironmentCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn env <subcommand>")
        System.err.println("Subcommands: list | get | use | create | rename | suspend | reactivate | delete | test-emails")
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

    /** `thoryn env get <id>` — a single environment record by its UUID id (CRUD symmetry with `list`). */
    @Command(name = "get", description = ["Show a single environment by id."], mixinStandardHelpOptions = true)
    class GetSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Environment id (UUID; see `thoryn env list`)."])
        lateinit var id: String

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val env = client.getEnvironment(id.trim())
                CommandSupport.emitRecord(format, env, ::recordFields)
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

    /**
     * `thoryn env delete <id> --confirm <slug>` — IRREVERSIBLY hard-delete a **sandbox** environment
     * and purge every environment-scoped row within it (product-api `DELETE /api/v1/environments/{id}`,
     * SSO-2960).
     *
     * SSO-2413 destructive-action confirmation, keyed to the environment (not the workspace): `--confirm`
     * MUST equal the target environment's OWN slug and rides as the `X-Thoryn-Confirm` header. Because the
     * action is irreversible, the CLI refuses to call the endpoint at all when `--confirm` is absent —
     * it prints the guidance and exits non-zero without touching the server. The platform-managed
     * production plane cannot be deleted (`409 cannot_delete_production_environment`).
     */
    @Command(name = "delete", description = ["Hard-delete a sandbox environment (irreversible)."], mixinStandardHelpOptions = true)
    class DeleteSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Environment id (UUID; see `thoryn env list`)."])
        lateinit var id: String

        @Option(
            names = ["--confirm"],
            description = [
                "Confirm this IRREVERSIBLE delete by passing the environment's OWN slug. " +
                    "Required; the slug must match the target environment.",
            ],
        )
        var confirm: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val slug = confirm?.trim()
            if (slug.isNullOrEmpty()) {
                System.err.println(
                    "This is a destructive, irreversible action: it hard-deletes the environment " +
                        "and purges every resource within it.",
                )
                System.err.println("Re-run with --confirm <environment-slug> to proceed.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                client.deleteEnvironment(id.trim(), slug)
                CommandSupport.emitValue(
                    format,
                    mapOf("deleted" to true, "id" to id.trim()),
                    "Deleted environment '${id.trim()}'.",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                // 409 cannot_delete_production_environment — a clearer message than the generic HTTP render.
                if (ex.httpStatus == 409 && ex.errorCode == "cannot_delete_production_environment") {
                    System.err.println("Error: cannot delete the production plane — it is platform-managed and permanent.")
                    return CommandSupport.EXIT_HTTP_ERROR
                }
                // 428 (confirm required) / 422 (confirm mismatch) / 404 (not found) / 403 (missing scope)
                // all route through the shared renderer (SSO-2413 confirm hints + scope-login hint).
                CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn env test-emails ...` (SSO-3026) — read a sandbox environment's **test inbox**: the
     * transactional emails the sandbox SUPPRESSES instead of really sending (verification links, …),
     * captured so a developer can complete a sandbox email flow without a real mailbox. Read-only,
     * scope `tenant:environments.read`. The target environment is the one selected by `thoryn env use`,
     * or an explicit `--env <slug>`; a production environment captured nothing, so its inbox is empty.
     *
     *  - `list`        — GET /api/v1/environments/{id}/test-emails (newest first; client-side `--to` /
     *                    `--channel` filters help find one in a round trip; `--limit` bounds the page)
     *  - `get <id>`    — GET /api/v1/environments/{id}/test-emails/{id} (one email, incl. its action link)
     */
    @Command(
        name = "test-emails",
        description = ["Read a sandbox environment's captured test emails (the suppressed-email inbox)."],
        mixinStandardHelpOptions = true,
        subcommands = [
            TestEmailsSubcommand.ListSub::class,
            TestEmailsSubcommand.GetSub::class,
        ],
    )
    class TestEmailsSubcommand : Callable<Int> {
        override fun call(): Int {
            System.err.println("Usage: thoryn env test-emails <list|get>")
            return CommandSupport.EXIT_USAGE
        }

        /** `thoryn env test-emails list [--env <slug>] [--to <email>] [--channel <ch>] [--limit N]`. */
        @Command(name = "list", description = ["List a sandbox's captured test emails (newest first)."], mixinStandardHelpOptions = true)
        class ListSub : Callable<Int> {

            @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
            var env: String? = null

            @Option(names = ["--to"], description = ["Only show emails addressed to this recipient (client-side filter)."])
            var to: String? = null

            @Option(names = ["--channel"], description = ["Only show this channel, e.g. email_verification (client-side filter)."])
            var channel: String? = null

            @Option(names = ["--limit"], description = ["Max emails to return (1-200; default 50)."])
            var limit: Int? = null

            @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
            var gateway: String = ThorynConfig.DEFAULT_GATEWAY

            @Option(names = ["--output"])
            var outputRaw: String? = null

            internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

            override fun call(): Int {
                val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
                val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
                gateway = CommandSupport.resolveGateway(gateway, tokens)
                val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
                val targetSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
                val envId = resolveIdOrNull(client, targetSlug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
                return try {
                    val raw = client.listTestEmails(envId, limit).emailsArray()
                    val filtered = tools.jackson.databind.node.JsonNodeFactory.instance.arrayNode()
                    raw.forEach { node ->
                        val toOk = to == null || node["to"]?.asString().equals(to, ignoreCase = true)
                        val chOk = channel == null || node["channel"]?.asString() == channel
                        if (toOk && chOk) filtered.add(node)
                    }
                    CommandSupport.emitList(format, filtered, TEST_EMAIL_HEADERS, rowMapper = ::testEmailRow)
                    CommandSupport.EXIT_OK
                } catch (ex: ProductApiException) {
                    CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.read")
                } catch (ex: Exception) {
                    CommandSupport.renderRequestFailure(ex, gateway)
                }
            }
        }

        /** `thoryn env test-emails get <emailId> [--env <slug>]` — one captured email incl. its action link. */
        @Command(name = "get", description = ["Show one captured test email (incl. its action link)."], mixinStandardHelpOptions = true)
        class GetSub : Callable<Int> {

            @Parameters(index = "0", description = ["Test-email id (UUID; see `thoryn env test-emails list`)."])
            lateinit var id: String

            @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
            var env: String? = null

            @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
            var gateway: String = ThorynConfig.DEFAULT_GATEWAY

            @Option(names = ["--output"])
            var outputRaw: String? = null

            internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

            override fun call(): Int {
                val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
                val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
                gateway = CommandSupport.resolveGateway(gateway, tokens)
                val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
                val targetSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
                val envId = resolveIdOrNull(client, targetSlug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
                return try {
                    val email = client.getTestEmail(envId, id.trim())
                    CommandSupport.emitRecord(format, email, ::testEmailFields)
                    CommandSupport.EXIT_OK
                } catch (ex: ProductApiException) {
                    CommandSupport.renderError(format, ex, requiredScope = "tenant:environments.read")
                } catch (ex: Exception) {
                    CommandSupport.renderRequestFailure(ex, gateway)
                }
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

        internal val TEST_EMAIL_HEADERS: List<String> = listOf("id", "channel", "to", "subject", "createdAt")

        /** The `emails` array from the inbox list envelope (`{ "emails": [...] }`). */
        internal fun JsonNode.emailsArray(): JsonNode = this["emails"] ?: this

        internal fun testEmailRow(node: JsonNode): List<Any?> = listOf(
            node["id"]?.asString(),
            node["channel"]?.asString(),
            node["to"]?.asString(),
            node["subject"]?.asString(),
            node["createdAt"]?.asString(),
        )

        internal fun testEmailFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "id" to node["id"]?.asString(),
            "channel" to node["channel"]?.asString(),
            "to" to node["to"]?.asString(),
            "subject" to node["subject"]?.asString(),
            "actionLink" to node["actionLink"]?.asString(),
            "createdAt" to node["createdAt"]?.asString(),
        )

        /** The environment slug the CLI currently targets (from the workspace selection), or null. */
        internal fun selectedEnvSlug(store: SelectedWorkspaceStore): String? =
            runCatching { store.read()?.environmentSlug }.getOrNull()?.takeIf { it.isNotBlank() }

        /** Shared "no environment to read" guidance for the test-inbox subcommands. */
        internal fun missingEnv(): Int {
            System.err.println("Error: no environment selected. Pass --env <slug>, or run `thoryn env use <slug>` first.")
            return CommandSupport.EXIT_USAGE
        }

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
