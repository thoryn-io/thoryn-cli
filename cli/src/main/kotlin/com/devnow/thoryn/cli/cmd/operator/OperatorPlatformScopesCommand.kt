package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.api.OperatorHubClient
import com.devnow.thoryn.cli.api.OperatorHubException
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.Callable

/**
 * `thoryn operator platform-scopes …` (SSO-3856, parent SSO-3851) — put a `platform:` scope on a machine client of the
 * platform HOME workspace's production plane, and take it away, through the hub's operator capability
 * `admin:clients.platform-scopes` (oathy ADR `2026-10-19-operator-grants-platform-client-scopes.md`, runbook
 * `docs/content/operate/operator-plane/platform-client-scopes.mdx`):
 *
 *  - `get <clientId>`                 — `GET    /admin/platform-clients/{clientId}/scopes`
 *  - `grant <clientId> <scope>`       — `PUT    /admin/platform-clients/{clientId}/scopes/{scope}`
 *  - `revoke <clientId> <scope>`      — `DELETE /admin/platform-clients/{clientId}/scopes/{scope}`
 *  - `plan -f <file>`                 — read each declared client, print what `apply` would change; writes nothing
 *  - `apply -f <file> [--dry-run]`    — print that plan, then `PUT` what is missing and `DELETE` what is extra
 *
 * The declaration file is [PlatformScopesFile] (`.thoryn/platform-scopes.yaml`, kept in the repository that owns the
 * workload). `apply` is the reproducible path the ADR asks for: the file is reviewed in git, the hub calls are
 * idempotent, so re-applying an applied file changes nothing (and the hub writes no audit row for a no-op).
 *
 * The session is the operator session (`thoryn operator login`, passkey) and the hub is reached over the
 * port-forward (`--hub-url`), exactly as `thoryn operator custom-domain`. The scope is NOT in the operator login's
 * default request — an operator token should carry no power the operator is not about to use — so sign in with
 * `thoryn operator login --scope "openid admin:clients.platform-scopes"` first.
 */
@Command(
    name = "platform-scopes",
    description = [
        "Grant and revoke platform: scopes on machine clients of the platform home workspace (operator plane),",
        "one at a time or declaratively from a reviewed file (apply -f .thoryn/platform-scopes.yaml).",
    ],
    mixinStandardHelpOptions = true,
    subcommands = [
        OperatorPlatformScopesCommand.GetSubcommand::class,
        OperatorPlatformScopesCommand.GrantSubcommand::class,
        OperatorPlatformScopesCommand.RevokeSubcommand::class,
        OperatorPlatformScopesCommand.PlanSubcommand::class,
        OperatorPlatformScopesCommand.ApplySubcommand::class,
    ],
)
class OperatorPlatformScopesCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn operator platform-scopes <subcommand>")
        System.err.println("Subcommands: get | grant | revoke | plan | apply")
        System.err.println()
        System.err.println("  1. thoryn operator login --scope \"openid ${OperatorSession.SCOPE_CLIENTS_PLATFORM_SCOPES}\"")
        System.err.println("  2. ${OperatorSession.PORT_FORWARD_COMMAND}   # in another terminal")
        System.err.println("  3. thoryn operator platform-scopes apply -f ${PlatformScopesFile.DEFAULT_PATH}")
        return CommandSupport.EXIT_USAGE
    }

    /** What every subcommand shares: the port-forward target, the operator session, the output format. */
    abstract class Base : Callable<Int> {
        @Option(
            names = ["--hub-url"],
            description = [
                "The hub's PRIVATE address — the kubectl port-forward (default: \${DEFAULT-VALUE}). " +
                    "Public hosts are refused: /admin is not served on any public address.",
            ],
            defaultValue = OperatorSession.DEFAULT_HUB_URL,
        )
        var hubUrl: String = OperatorSession.DEFAULT_HUB_URL

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        @Option(names = ["--json"], description = ["Machine-readable output; shorthand for --output json."])
        var json: Boolean = false

        // Read at call time, not construction time: the streams are whatever System.out / System.err are then.
        internal val out: PrintStream get() = System.out
        internal val err: PrintStream get() = System.err

        /** Validate the arguments before anything is sent; a non-null answer is the exit code. */
        open fun validate(): Int? = null

        abstract fun run(client: OperatorHubClient, format: OutputFormat): Int

        override fun call(): Int {
            if (json && outputRaw != null && !outputRaw.equals("json", ignoreCase = true)) {
                err.println("Error: --json cannot be combined with --output $outputRaw.")
                return CommandSupport.EXIT_USAGE
            }
            val format = CommandSupport.parseFormat(if (json) "json" else outputRaw, err) ?: return CommandSupport.EXIT_USAGE
            validate()?.let { return it }
            OperatorHubTarget.refusal(hubUrl)?.let {
                err.println("Error: $it")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = OperatorSession.readUsable(err) ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = clientFactory(hubUrl.trim().trimEnd('/'), tokens)
            return try {
                run(client, format)
            } catch (ex: OperatorHubException) {
                renderError(ex, format)
            } catch (ex: Exception) {
                OperatorCustomDomainCommand.renderUnreachable(ex, hubUrl, err)
            }
        }

        protected fun renderError(ex: OperatorHubException, format: OutputFormat, clientId: String? = null): Int {
            val hint = hintFor(ex, clientId)
            when (format) {
                OutputFormat.TABLE -> {
                    err.println("Error: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}${ex.detail?.let { " — $it" }.orEmpty()}")
                    err.println(hint)
                }
                else -> {
                    val structured = linkedMapOf<String, Any?>(
                        "error" to (ex.errorCode ?: "unknown"),
                        "errorDescription" to ex.detail,
                        "httpStatus" to ex.httpStatus,
                        "clientId" to clientId,
                        "hint" to hint,
                    ).filterValues { it != null }
                    if (format == OutputFormat.JSON) Printers.json(structured, out) else Printers.yaml(structured, out)
                }
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }
    }

    /** `get` / `grant` / `revoke` name one client. */
    abstract class ClientBase : Base() {
        @Parameters(index = "0", paramLabel = "<clientId>", description = ["A client of the platform home workspace's production plane."])
        lateinit var clientId: String

        override fun validate(): Int? {
            if (clientId.isBlank()) {
                err.println("Error: name the client, e.g. `thoryn operator platform-scopes get provisioning-m2m`.")
                return CommandSupport.EXIT_USAGE
            }
            return null
        }

        override fun call(): Int {
            clientId = clientId.trim()
            return super.call()
        }
    }

    @Command(
        name = "get",
        description = ["Show a home-workspace client's platform: scopes."],
        mixinStandardHelpOptions = true,
    )
    class GetSubcommand : ClientBase() {
        override fun run(client: OperatorHubClient, format: OutputFormat): Int {
            val body = try {
                client.getPlatformScopes(clientId)
            } catch (ex: OperatorHubException) {
                return renderError(ex, format, clientId)
            }
            CommandSupport.emitRecord(format, body, ::scopesFields, out)
            return CommandSupport.EXIT_OK
        }
    }

    /** `grant` / `revoke`: one scope, with the audit row's `reason` / `ticket`. */
    abstract class ChangeBase : ClientBase() {
        @Parameters(index = "1", paramLabel = "<scope>", description = ["A platform: scope, e.g. platform:trusted-issuers.read."])
        lateinit var scope: String

        @Option(names = ["--reason"], description = ["Why — recorded on the audit row (at most 500 characters)."])
        var reason: String? = null

        @Option(names = ["--ticket"], description = ["The ticket this change belongs to — recorded on the audit row (at most 64 characters)."])
        var ticket: String? = null

        override fun validate(): Int? {
            super.validate()?.let { return it }
            scope = scope.trim()
            if (!scope.startsWith(PlatformScopesFile.NAMESPACE)) {
                err.println(
                    "Error: '$scope' is not a platform: scope. This capability manages platform: scopes only; a client's " +
                        "tenant: and OIDC scopes are granted through the product (its provisioning file or the client API).",
                )
                return CommandSupport.EXIT_USAGE
            }
            auditFieldsRefusal(reason, ticket)?.let { err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            return null
        }
    }

    @Command(
        name = "grant",
        description = [
            "Add one platform: scope to a client_credentials client of the platform home workspace (idempotent).",
            "Audited on the home workspace's trail as CLIENT_PLATFORM_SCOPE_GRANTED.",
        ],
        mixinStandardHelpOptions = true,
    )
    class GrantSubcommand : ChangeBase() {
        override fun run(client: OperatorHubClient, format: OutputFormat): Int {
            val body = try {
                client.grantPlatformScope(clientId, scope, reason, ticket)
            } catch (ex: OperatorHubException) {
                return renderError(ex, format, clientId)
            }
            val changed = body["changed"]?.asBoolean() == true
            CommandSupport.emitValue(
                format,
                body,
                if (changed) "Granted $scope to '$clientId'. It now holds: ${scopesOf(body).joinToString(" ").ifEmpty { "(none)" }}"
                else "Unchanged: '$clientId' already holds $scope.",
                out,
            )
            return CommandSupport.EXIT_OK
        }
    }

    @Command(
        name = "revoke",
        description = [
            "Remove one platform: scope from a client of the platform home workspace (idempotent).",
            "Audited on the home workspace's trail as CLIENT_PLATFORM_SCOPE_REVOKED.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RevokeSubcommand : ChangeBase() {
        override fun run(client: OperatorHubClient, format: OutputFormat): Int {
            val body = try {
                client.revokePlatformScope(clientId, scope, reason, ticket)
            } catch (ex: OperatorHubException) {
                return renderError(ex, format, clientId)
            }
            val changed = body["changed"]?.asBoolean() == true
            CommandSupport.emitValue(
                format,
                body,
                if (changed) "Revoked $scope from '$clientId'. It now holds: ${scopesOf(body).joinToString(" ").ifEmpty { "(none)" }}"
                else "Unchanged: '$clientId' does not hold $scope.",
                out,
            )
            return CommandSupport.EXIT_OK
        }
    }

    /** `plan` and `apply`: converge a [PlatformScopesFile]. */
    abstract class ConvergeBase : Base() {
        @Option(
            names = ["-f", "--file"],
            description = ["The platform-scopes declaration (default: \${DEFAULT-VALUE})."],
            defaultValue = PlatformScopesFile.DEFAULT_PATH,
        )
        var file: String = PlatformScopesFile.DEFAULT_PATH

        @Option(names = ["--reason"], description = ["Overrides the file's reason on every audit row (at most 500 characters)."])
        var reason: String? = null

        @Option(names = ["--ticket"], description = ["Overrides the file's ticket on every audit row (at most 64 characters)."])
        var ticket: String? = null

        /** True when nothing may be written. */
        abstract val dryRun: Boolean

        private lateinit var declaration: PlatformScopesFile

        override fun validate(): Int? {
            auditFieldsRefusal(reason, ticket)?.let { err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            declaration = try {
                PlatformScopesFile.load(Path.of(file))
            } catch (ex: PlatformScopesFile.InvalidException) {
                err.println("Error: ${ex.source} cannot be applied:")
                ex.violations.forEach { err.println("  - $it") }
                return CommandSupport.EXIT_USAGE
            } catch (ex: Exception) {
                err.println("Error: could not read $file — ${CommandSupport.describeThrowable(ex)}")
                return CommandSupport.EXIT_IO_ERROR
            }
            return null
        }

        override fun run(client: OperatorHubClient, format: OutputFormat): Int {
            // 1. Read every declared client before writing anything: a refusal here (no standing, missing scope,
            //    unknown client) stops the run with nothing changed, and the plan printed is the whole plan.
            val plans = declaration.clients.map { desired ->
                val live = try {
                    client.getPlatformScopes(desired.clientId)
                } catch (ex: OperatorHubException) {
                    return renderError(ex, format, desired.clientId)
                }
                PlatformScopesPlan.of(desired, scopesOf(live))
            }
            val table = format == OutputFormat.TABLE
            if (table) printPlan(plans)

            // 2. Converge, in file order: grants first, then revokes, client by client.
            val applied = linkedMapOf<String, MutableList<Map<String, Any?>>>()
            if (!dryRun) {
                for ((desired, plan) in declaration.clients.zip(plans)) {
                    val rowReason = reason ?: desired.reason ?: declaration.reason
                    val rowTicket = ticket ?: desired.ticket ?: declaration.ticket
                    val done = applied.getOrPut(plan.clientId) { mutableListOf() }
                    val steps = plan.grant.map { "grant" to it } + plan.revoke.map { "revoke" to it }
                    for ((action, scope) in steps) {
                        val body = try {
                            if (action == "grant") client.grantPlatformScope(plan.clientId, scope, rowReason, rowTicket)
                            else client.revokePlatformScope(plan.clientId, scope, rowReason, rowTicket)
                        } catch (ex: OperatorHubException) {
                            if (table) {
                                err.println("Stopped: could not $action $scope on '${plan.clientId}'. Changes made before this one stand;")
                                err.println("re-running the same file finishes the rest (every call is idempotent).")
                            }
                            return renderError(ex, format, plan.clientId)
                        }
                        val changed = body["changed"]?.asBoolean() == true
                        done += mapOf("action" to action, "scope" to scope, "changed" to changed)
                        if (table) out.println("  ${if (action == "grant") "granted" else "revoked"} $scope ${if (action == "grant") "to" else "from"} ${plan.clientId}${if (changed) "" else " (already done)"}")
                    }
                }
            }

            val granted = plans.sumOf { it.grant.size }
            val revoked = plans.sumOf { it.revoke.size }
            val unchangedClients = plans.count { !it.changes }
            if (table) {
                out.println(
                    when {
                        granted + revoked == 0 -> "No changes. Every declared client already holds exactly its declared platform: scopes."
                        dryRun -> "Plan: $granted to grant, $revoked to revoke, $unchangedClients client(s) unchanged. Nothing was changed (dry run)."
                        else -> "Applied: $granted granted, $revoked revoked, $unchangedClients client(s) unchanged."
                    },
                )
            } else {
                val result = linkedMapOf(
                    "dryRun" to dryRun,
                    "clients" to plans.map { p ->
                        linkedMapOf(
                            "clientId" to p.clientId,
                            "live" to p.live,
                            "grant" to p.grant,
                            "revoke" to p.revoke,
                            "unchanged" to p.unchanged,
                            "applied" to applied[p.clientId].orEmpty(),
                        )
                    },
                    "summary" to linkedMapOf("grant" to granted, "revoke" to revoked, "unchangedClients" to unchangedClients),
                )
                if (format == OutputFormat.JSON) Printers.json(result, out) else Printers.yaml(result, out)
            }
            return CommandSupport.EXIT_OK
        }

        private fun printPlan(plans: List<PlatformScopesPlan>) {
            out.println("Platform-client scopes in the platform home workspace's production plane (${plans.size} client(s)):")
            plans.forEach { p ->
                if (!p.changes) {
                    out.println("  = ${p.clientId}: unchanged (${p.unchanged.joinToString(" ").ifEmpty { "no platform: scopes" }})")
                    return@forEach
                }
                out.println("  ~ ${p.clientId}")
                p.grant.forEach { out.println("      + $it") }
                p.revoke.forEach { out.println("      - $it") }
                p.unchanged.forEach { out.println("        $it") }
            }
        }
    }

    @Command(
        name = "plan",
        description = ["Read each client a platform-scopes file declares and print what `apply` would change. Writes nothing."],
        mixinStandardHelpOptions = true,
    )
    class PlanSubcommand : ConvergeBase() {
        override val dryRun: Boolean get() = true
    }

    @Command(
        name = "apply",
        description = [
            "Converge the platform: scopes of the clients a file declares: print the plan, then grant what is missing",
            "and revoke what is extra. Idempotent. Clients the file does not name are not touched.",
        ],
        mixinStandardHelpOptions = true,
    )
    class ApplySubcommand : ConvergeBase() {
        @Option(names = ["--dry-run"], description = ["Print the plan and stop (the same as `plan`)."])
        var dryRunFlag: Boolean = false

        override val dryRun: Boolean get() = dryRunFlag
    }

    companion object {
        /** Test seam — builds the hub client for a resolved URL + session (the same factory custom-domain uses). */
        internal var clientFactory: (String, Tokens) -> OperatorHubClient = { url, tokens ->
            OperatorCustomDomainCommand.clientFactory(url, tokens)
        }

        fun scopesOf(body: JsonNode): List<String> =
            body["platformScopes"]?.takeIf { it.isArray }?.toList().orEmpty().mapNotNull { it.asString()?.takeIf { s -> s.isNotBlank() } }

        fun scopesFields(body: JsonNode): List<Pair<String, Any?>> = listOf(
            "clientId" to body["clientId"]?.asString(),
            "workspace" to body["workspace"]?.asString(),
            "environment" to body["environment"]?.asString(),
            "platformScopes" to scopesOf(body).joinToString(" ").ifEmpty { "(none)" },
        ).filter { it.second != null }

        internal fun auditFieldsRefusal(reason: String?, ticket: String?): String? = when {
            (reason?.length ?: 0) > PlatformScopesFile.MAX_REASON -> "--reason is ${reason!!.length} characters; the hub accepts at most ${PlatformScopesFile.MAX_REASON}."
            (ticket?.length ?: 0) > PlatformScopesFile.MAX_TICKET -> "--ticket is ${ticket!!.length} characters; the hub accepts at most ${PlatformScopesFile.MAX_TICKET}."
            else -> null
        }

        /** The one thing the operator can do about a refusal from the platform-client surface. */
        internal fun hintFor(ex: OperatorHubException, clientId: String?): String {
            val client = clientId?.let { "'$it'" } ?: "the client"
            return when (ex.errorCode) {
                "operator_passkey_required" ->
                    "The operator session did not come from a passkey sign-in. Run `${OperatorSession.LOGIN_HINT}` " +
                        "and choose your passkey (not a password or a recovery code)."
                "client_not_found" ->
                    "No client $client in the platform home workspace's PRODUCTION plane (a sandbox twin does not count). " +
                        "Create it through the product first — provisioning-as-code or the client API — with the client_credentials grant."
                "machine_client_required" ->
                    "$client has no client_credentials grant. A platform: scope is for a workload: give the client the " +
                        "client_credentials grant through the product, or use a machine client (a workload identity's wi_ client qualifies)."
                "not_a_platform_scope" -> "This capability manages platform: scopes only."
                "unknown_platform_scope" ->
                    "The hub grants only its closed set of platform-client scopes (platform:trusted-issuers.read, " +
                        "platform:audit-events.append, platform:github-installations.sync). Check the spelling; a new one needs a hub change."
                "invalid_reason", "invalid_ticket" ->
                    "Shorten it: reason at most ${PlatformScopesFile.MAX_REASON} characters, ticket at most ${PlatformScopesFile.MAX_TICKET}."
                "platform_home_unavailable" -> "The platform home workspace is missing or suspended on this hub. Nothing was changed."
                "audit_unavailable" -> "The audit row could not be written, so the hub undid the change. Retry; check the audit outbox."
                "unknown_tenant" ->
                    "The hub resolved no tenant for this request's Host. Call it on the port-forward address " +
                        "(--hub-url ${OperatorSession.DEFAULT_HUB_URL}), not on another host name."
                "insufficient_scope" -> missingScopeHint()
                else -> when (ex.httpStatus) {
                    403 -> missingScopeHint()
                    404 ->
                        "Not found. Either your identity holds no operator standing in this environment (the hub answers that " +
                            "with 404 so the operator surface cannot be probed — standing is appointed only by the deployment value " +
                            "productApi.operatorPlatformSubjects), or this hub predates the platform-client surface (oathy hub V207, SSO-3854)."
                    401 -> "The hub did not accept the operator token (expired, or from another environment). Run `${OperatorSession.LOGIN_HINT}`."
                    else -> "The hub refused the request (HTTP ${ex.httpStatus})."
                }
            }
        }

        private fun missingScopeHint(): String =
            "The operator token lacks ${OperatorSession.SCOPE_CLIENTS_PLATFORM_SCOPES}; the operator login does not request it " +
                "by default. Sign in with it: `thoryn operator login --scope \"openid ${OperatorSession.SCOPE_CLIENTS_PLATFORM_SCOPES}\"` " +
                "(the hub grants it to thoryn-operator from hub V207)."
    }
}
