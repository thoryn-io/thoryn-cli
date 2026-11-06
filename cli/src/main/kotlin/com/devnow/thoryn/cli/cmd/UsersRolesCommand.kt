package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn users roles ...` — the RBAC roles a person holds (SSO-3941; product-api SSO-1891 `UserRolesController`).
 *
 * A role is defined per ENVIRONMENT (declare it with `kind: role` in a provisioning file); these commands assign one to a
 * person in the selected environment (`--environment`, else `env use`, else the production plane), exactly like the
 * other `users` commands. The user is addressed by the **subject** product-api keys an assignment on — the `sub` claim of
 * that person's tokens, the `subject` column of `thoryn users list` — by their directory id (product-api resolves it to the
 * subject, SSO-4284), or by `--email`; the role by its NAME (or its id). product-api refuses an identifier no sign-in
 * produced, so an assignment can no longer be stored where no token reads it. The role's permissions then reach the person's tokens
 * through an application that has claims in the token switched on (`tokenClaims: { sources: [permissions] }`).
 *
 * Scopes: `list` → `tenant:roles.read`; `add` / `remove` → `tenant:roles.write` plus `tenant:roles.read` to resolve the
 * role name. `remove` is idempotent and, like the API, needs no `--confirm` (it narrows access; product-api does not gate it).
 */
@Command(
    name = "roles",
    description = ["List, add and remove the RBAC roles a user holds in the selected environment."],
    mixinStandardHelpOptions = true,
    subcommands = [
        UsersRolesCommand.ListSubcommand::class,
        UsersRolesCommand.AddSubcommand::class,
        UsersRolesCommand.RemoveSubcommand::class,
    ],
)
class UsersRolesCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn users roles <subcommand>")
        System.err.println("Subcommands: list | add | remove")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn users roles list <user>` — the roles the user holds, with their names. */
    @Command(name = "list", description = ["List the roles a user holds."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Parameters(index = "0", arity = "0..1", paramLabel = "<user>", description = [USER_PARAM_DESC])
        var user: String? = null

        @Option(names = ["--email"], description = [EMAIL_OPTION_DESC])
        var email: String? = null

        @Option(names = ["--environment"], description = [UsersCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = UsersCommand.clientFor(gateway, tokens, environment)
            val target = resolveUser(client, user, email, gateway) ?: return CommandSupport.EXIT_USAGE
            return try {
                val assignments = allPages { cursor -> client.listUserRoles(target.id, cursor = cursor) }
                val names = allPages { cursor -> client.listRoles(cursor = cursor) }
                    .mapNotNull { r -> r.str("id")?.let { id -> id to (r.str("name") ?: id) } }.toMap()
                val rows = assignments.map { a ->
                    linkedMapOf(
                        "roleId" to a.str("roleId"),
                        "role" to a.str("roleId")?.let { names[it] },
                        "organizationId" to a.str("orgId"),
                        "assignedBy" to a.str("assignedBy"),
                        "assignedAt" to a.str("assignedAt"),
                    )
                }
                when (format) {
                    OutputFormat.TABLE -> Printers.table(LIST_HEADERS, rows.map { it.values.toList() }, System.out)
                    else -> CommandSupport.emitValue(format, mapOf("user" to target.label, "roles" to rows), "")
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_READ)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn users roles add <user> <role>` — assign the role (by name or id) in the selected environment. */
    @Command(name = "add", description = ["Give a user a role (by name or id)."], mixinStandardHelpOptions = true)
    class AddSubcommand : Callable<Int> {

        @Parameters(arity = "1..2", paramLabel = "<user> <role>", description = [USER_ROLE_PARAMS_DESC])
        var args: List<String> = emptyList()

        @Option(names = ["--email"], description = [EMAIL_OPTION_DESC])
        var email: String? = null

        @Option(names = ["--environment"], description = [UsersCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val (userArg, role) = splitUserAndRole(args, email) ?: return CommandSupport.EXIT_USAGE
            val client = UsersCommand.clientFor(gateway, tokens, environment)
            val target = resolveUser(client, userArg, email, gateway) ?: return CommandSupport.EXIT_USAGE
            val resolved = resolveRole(client, role, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            val subject = target.label
            return try {
                val assignment = client.assignUserRole(target.id, resolved.id)
                // product-api stores the assignment under the platform subject; show it when it differs from the input.
                val stored = assignment.str("userId")?.takeIf { it != subject }
                CommandSupport.emitValue(
                    format,
                    linkedMapOf("user" to subject, "subject" to (stored ?: target.id), "roleId" to resolved.id, "role" to resolved.name, "status" to "assigned"),
                    "Gave $subject${stored?.let { " (subject $it)" } ?: ""} the role ${resolved.name} (${resolved.id})",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                // Already held: the desired state is reached — say so and succeed (re-runnable from a script).
                if (ex.httpStatus == 409 && ex.errorCode == "assignment_exists") {
                    CommandSupport.emitValue(
                        format,
                        mapOf("user" to subject, "roleId" to resolved.id, "role" to resolved.name, "status" to "unchanged"),
                        "$subject already holds the role ${resolved.name} (${resolved.id})",
                    )
                    return CommandSupport.EXIT_OK
                }
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn users roles remove <user> <role>` — take the role away (idempotent). */
    @Command(name = "remove", description = ["Take a role away from a user (by name or id)."], mixinStandardHelpOptions = true)
    class RemoveSubcommand : Callable<Int> {

        @Parameters(arity = "1..2", paramLabel = "<user> <role>", description = [USER_ROLE_PARAMS_DESC])
        var args: List<String> = emptyList()

        @Option(names = ["--email"], description = [EMAIL_OPTION_DESC])
        var email: String? = null

        @Option(names = ["--environment"], description = [UsersCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val (userArg, role) = splitUserAndRole(args, email) ?: return CommandSupport.EXIT_USAGE
            val client = UsersCommand.clientFor(gateway, tokens, environment)
            val target = resolveUser(client, userArg, email, gateway) ?: return CommandSupport.EXIT_USAGE
            val resolved = resolveRole(client, role, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            val subject = target.label
            return try {
                client.unassignUserRole(target.id, resolved.id)
                CommandSupport.emitValue(
                    format,
                    mapOf("user" to subject, "roleId" to resolved.id, "role" to resolved.name, "status" to "removed"),
                    "Removed the role ${resolved.name} (${resolved.id}) from $subject",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        internal const val SCOPE_READ = "tenant:roles.read"
        internal const val SCOPE_WRITE = "tenant:roles.write"

        internal const val USER_PARAM_DESC =
            "The user's subject (the `sub` of their tokens, the `subject` column of `thoryn users list`) or their directory id. " +
                "Omit it and use --email to address the user by email."
        internal const val USER_ROLE_PARAMS_DESC =
            "The user (their subject or directory id; omit it with --email), then the role's name (as declared with `kind: role`) or its id."
        internal const val EMAIL_OPTION_DESC =
            "Address the user by email instead (resolved with a directory lookup; needs tenant:users.read)."
        internal const val ROLE_PARAM_DESC =
            "The role's name (as declared with `kind: role`), or its id."

        internal val LIST_HEADERS: List<String> = listOf("roleId", "role", "organizationId", "assignedBy", "assignedAt")

        /** The user a command addresses: [id] goes in the request path, [label] in what the command prints. */
        internal data class TargetUser(val id: String, val label: String)

        /**
         * SSO-4284 — the user from a positional [user] (a subject or directory id, sent as is: product-api resolves a
         * directory id) or from [email] (the directory row's `subject`, else its `id`, which product-api then resolves or
         * refuses with a reason). Exactly one of the two. Null, with guidance on [err], when neither or both are given or
         * the email lookup fails.
         */
        internal fun resolveUser(
            client: ProductApiClient,
            user: String?,
            email: String?,
            gateway: String,
            err: PrintStream = System.err,
        ): TargetUser? {
            val trimmedUser = user?.trim()?.takeIf { it.isNotEmpty() }
            val trimmedEmail = email?.trim()?.takeIf { it.isNotEmpty() }
            if (trimmedUser != null && trimmedEmail != null) {
                err.println("Error: pass EITHER a user OR --email, not both.")
                return null
            }
            if (trimmedUser != null) return TargetUser(trimmedUser, trimmedUser)
            if (trimmedEmail == null) {
                err.println("Error: provide the user (their subject or directory id), or --email <email>.")
                return null
            }
            val row = UsersCommand.lookupByEmail(client, trimmedEmail, gateway, err) ?: return null
            val id = row.str("subject") ?: row.str("id")
            if (id == null) {
                err.println("Error: the directory row for '$trimmedEmail' carried no id.")
                return null
            }
            return TargetUser(id, trimmedEmail)
        }

        /** `add` / `remove` positionals: `<user> <role>`, or only `<role>` when [email] addresses the user. */
        internal fun splitUserAndRole(args: List<String>, email: String?, err: PrintStream = System.err): Pair<String?, String>? =
            when {
                email.isNullOrBlank() && args.size == 2 -> args[0] to args[1]
                !email.isNullOrBlank() && args.size == 1 -> null to args[0]
                email.isNullOrBlank() -> {
                    err.println("Error: provide the user and the role: <user> <role>, or --email <email> <role>.")
                    null
                }
                else -> {
                    err.println("Error: with --email, give only the role: --email <email> <role>.")
                    null
                }
            }

        /** A role resolved from the user's input: its id and its name. */
        internal data class ResolvedRole(val id: String, val name: String)

        /**
         * Resolve [input] to a role of the selected environment: by NAME first (a role's name is unique per environment), else
         * by id. Not found ⇒ null, with guidance on [err] (the roles that do exist, so a typo is visible).
         */
        internal fun resolveRole(client: ProductApiClient, input: String, gateway: String, err: PrintStream = System.err): ResolvedRole? {
            val wanted = input.trim()
            if (wanted.isEmpty()) {
                err.println("Error: provide a role name (or id).")
                return null
            }
            val roles = try {
                allPages { cursor -> client.listRoles(cursor = cursor) }
            } catch (ex: ProductApiException) {
                err.println("Error: could not list the roles to resolve '$wanted' (${ex.errorCode ?: ex.message}). Resolving a role needs $SCOPE_READ.")
                return null
            } catch (ex: Exception) {
                err.println("Error: could not reach $gateway to resolve '$wanted': ${ex.message}")
                return null
            }
            val match = roles.firstOrNull { it.str("name") == wanted } ?: roles.firstOrNull { it.str("id") == wanted }
            val id = match?.str("id")
            if (match == null || id == null) {
                val known = roles.mapNotNull { it.str("name") }.sorted()
                err.println(
                    "Error: no role '$wanted' in the selected environment" +
                        (if (known.isEmpty()) " (it has no roles — declare one with `kind: role` in a provisioning file)." else ". Roles there: ${known.joinToString(", ")}."),
                )
                return null
            }
            return ResolvedRole(id, match.str("name") ?: id)
        }

        /** Every item of a cursor-paginated ListEnvelope (`{ data, pagination: { cursor, hasMore } }`). */
        internal fun allPages(fetch: (cursor: String?) -> JsonNode): List<JsonNode> {
            val items = mutableListOf<JsonNode>()
            var cursor: String? = null
            repeat(MAX_PAGES) {
                val body = fetch(cursor)
                body["data"]?.takeIf { it.isArray }?.let { items += it.toList() }
                cursor = body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
                if (cursor == null || body["pagination"]?.get("hasMore")?.asBoolean(true) == false) return items
            }
            return items
        }

        private const val MAX_PAGES = 50

        private fun JsonNode.str(field: String): String? = this[field]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() }
    }
}
