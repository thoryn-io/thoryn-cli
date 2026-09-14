package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn users ...` — manage the DIRECTORY USERS of the caller's workspace (SSO-3081).
 *
 * The customer plane exposes user lifecycle over `/api/v1/users`; the CLI had `identity.registerUser`
 * (via the examples recipe) but no user-facing surface to LIST or change a user's account status. This
 * command adds that: `list` (optionally filtered by `--email` / `--status`), and the lifecycle verbs
 * `suspend` / `reactivate`. Suspending a user marks their account non-ACTIVE so their next sign-in is
 * refused (the hosted login shows the suspended notice rather than the generic invalid-credentials
 * error) — which is exactly the branch the thoryn-examples suspended-login negative e2e asserts.
 *
 * Users are environment-scoped, so these commands honour the currently-selected environment
 * ([CommandSupport.gatewayClient] with `applyEnvironment = true`); with no environment selected the
 * request resolves to the production plane. `suspend` is a production-destructive action gated by the
 * SSO-2413 confirmation contract — on the production plane `--confirm <workspace-slug>` is required
 * (product-api answers `428` when absent, `422` on mismatch); a sandbox plane is ungated. Scopes:
 * `list` → `tenant:users.read`; `suspend` / `reactivate` → `tenant:users.write` (and `suspend`/
 * `reactivate` addressed by `--email` also need `tenant:users.read` to resolve the id).
 */
@Command(
    name = "users",
    description = ["Manage the directory users of your workspace (list, suspend, reactivate)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        UsersCommand.ListSubcommand::class,
        UsersCommand.SuspendSubcommand::class,
        UsersCommand.ReactivateSubcommand::class,
    ],
)
class UsersCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn users <subcommand>")
        System.err.println("Subcommands: list | suspend | reactivate")
        return CommandSupport.EXIT_USAGE
    }

    @Command(name = "list", description = ["List the directory users in your workspace."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--email"], description = ["Filter to the user with this email."])
        var email: String? = null

        @Option(names = ["--status"], description = ["Filter by account status (e.g. ACTIVE, SUSPENDED)."])
        var status: String? = null

        @Option(names = ["--limit"], description = ["Maximum users to return."])
        var limit: Int? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = clientFor(gateway, tokens, environment)
            return try {
                val users = client.listUsers(email = email, status = status, limit = limit)
                CommandSupport.emitList(format, users, LIST_HEADERS, rowMapper = ::row)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:users.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn users suspend (<id> | --email <email>) [--confirm <workspace-slug>]`. */
    @Command(name = "suspend", description = ["Suspend a user so their next sign-in is refused."], mixinStandardHelpOptions = true)
    class SuspendSubcommand : Callable<Int> {

        @Parameters(index = "0", arity = "0..1", description = ["User id (UUID). Omit and use --email to address by email."])
        var id: String? = null

        @Option(names = ["--email"], description = ["Address the user by email instead of id (resolves via a directory lookup)."])
        var email: String? = null

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = clientFor(gateway, tokens, environment)
            val userId = resolveUserId(client, id, email, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                client.suspendUser(userId, confirm)
                CommandSupport.emitValue(format, mapOf("id" to userId, "status" to "suspended"), "Suspended user $userId")
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:users.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn users reactivate (<id> | --email <email>)` — clear a suspension (not confirmation-gated). */
    @Command(name = "reactivate", description = ["Reactivate a suspended user."], mixinStandardHelpOptions = true)
    class ReactivateSubcommand : Callable<Int> {

        @Parameters(index = "0", arity = "0..1", description = ["User id (UUID). Omit and use --email to address by email."])
        var id: String? = null

        @Option(names = ["--email"], description = ["Address the user by email instead of id (resolves via a directory lookup)."])
        var email: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = clientFor(gateway, tokens, environment)
            val userId = resolveUserId(client, id, email, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                client.reactivateUser(userId)
                CommandSupport.emitValue(format, mapOf("id" to userId, "status" to "reactivated"), "Reactivated user $userId")
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:users.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        internal const val ENVIRONMENT_OPTION_DESC =
            "Target environment slug (rides X-Thoryn-Environment). Use for a client-credentials/CI " +
                "session that hasn't run `workspace switch` + `env use` (SSO-3068). Omit to use the " +
                "environment selected by `env use`."

        /**
         * Build the client for the target environment. An explicit `--environment` rides
         * `X-Thoryn-Environment` directly (the client-credentials/CI path, SSO-3068 — a CI session
         * clears the SelectedWorkspaceStore, so `env use` can't select one); otherwise the environment
         * comes from `env use` via [CommandSupport.gatewayClient].
         */
        internal fun clientFor(gateway: String, tokens: com.devnow.thoryn.cli.auth.Tokens, environment: String?): ProductApiClient =
            if (!environment.isNullOrBlank()) {
                CommandSupport.client(gateway, tokens, environmentSlug = environment)
            } else {
                CommandSupport.gatewayClient(gateway, tokens)
            }

        internal val LIST_HEADERS: List<String> = listOf("id", "email", "status", "emailVerified", "createdAt")

        internal fun row(node: JsonNode): List<Any?> = listOf(
            node["id"]?.asString(),
            node["email"]?.asString(),
            node["status"]?.asString(),
            node["emailVerified"]?.asBoolean() ?: false,
            node["createdAt"]?.asString(),
        )

        /**
         * Resolve the target user id from an explicit [id] positional or an [email]. Exactly one must be
         * supplied. An `--email` is resolved with a `tenant:users.read` directory lookup: zero matches or
         * more than one both fail (never guess). Returns null (and prints guidance to [err]) on any of
         * these; the caller then returns [CommandSupport.EXIT_HTTP_ERROR] / [CommandSupport.EXIT_USAGE].
         */
        internal fun resolveUserId(
            client: ProductApiClient,
            id: String?,
            email: String?,
            gateway: String,
            err: PrintStream = System.err,
        ): String? {
            val trimmedId = id?.trim()?.takeIf { it.isNotEmpty() }
            val trimmedEmail = email?.trim()?.takeIf { it.isNotEmpty() }
            if (trimmedId != null && trimmedEmail != null) {
                err.println("Error: pass EITHER a user id OR --email, not both.")
                return null
            }
            if (trimmedId != null) return trimmedId
            if (trimmedEmail == null) {
                err.println("Error: provide a user id, or --email <email> to address the user by email.")
                return null
            }
            val matches = try {
                // The customer-plane collection envelope is `{ "data": [...], "pagination": {...} }`
                // (product-api ListEnvelope); fall back to `items` for any older/other surface.
                val envelope = client.listUsers(email = trimmedEmail)
                val arr = envelope.get("data")?.takeIf { it.isArray } ?: envelope.get("items")
                if (arr != null && arr.isArray) arr.toList() else emptyList()
            } catch (ex: ProductApiException) {
                err.println("Error: could not look up '$trimmedEmail' (${ex.errorCode ?: ex.message}). A --email lookup needs tenant:users.read.")
                return null
            } catch (ex: Exception) {
                err.println("Error: could not reach $gateway to resolve '$trimmedEmail': ${ex.message}")
                return null
            }
            return when (matches.size) {
                1 -> matches[0]["id"]?.asString()?.takeIf { it.isNotBlank() }.also {
                    if (it == null) err.println("Error: the directory row for '$trimmedEmail' carried no id.")
                }
                0 -> {
                    err.println("Error: no user with email '$trimmedEmail' in the selected environment.")
                    null
                }
                else -> {
                    err.println("Error: '$trimmedEmail' matched ${matches.size} users; address the user by id instead.")
                    null
                }
            }
        }
    }
}
