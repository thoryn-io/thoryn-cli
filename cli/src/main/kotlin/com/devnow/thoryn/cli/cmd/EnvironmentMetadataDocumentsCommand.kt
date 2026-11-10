package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.missingEnv
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.resolveIdOrNull
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.selectedEnvSlug
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.time.Duration
import java.time.format.DateTimeParseException
import java.util.concurrent.Callable

/**
 * `thoryn env metadata-documents ...` (SSO-4345; oauthy SSO-4335 / SSO-4338, ADR 2026-11-05-client-id-metadata-documents
 * C1, D2, D3) — an environment's **Client ID Metadata Document policy**: whether a client the workspace never registered
 * (an MCP client, say) may identify itself by the `https` URL of a metadata document it publishes, from which `client_id`
 * hosts, and whether such clients get rotating refresh tokens, and for how long. Off, with no host, until a manager
 * changes it.
 *
 * A thin wrapper over product-api's `GET/PUT /api/v1/environments/{envId}/client-id-metadata-documents`:
 * `tenant:environments.read` / `.write` (oauthy SSO-4369) and `manager` on the environment (a workspace admin holds it on every one); an
 * environment the caller does not manage is `404 not_found`, never 403. Same environment resolution as the other `env`
 * subcommands: `--env <slug>` or the selected environment (`thoryn env use`).
 *
 * Subcommands:
 *  - `show [--env]` — the policy;
 *  - `set [--env] [--enable|--disable] [--add-host h]… [--remove-host h]… [--hosts a,b] [--refresh-tokens on|off]
 *    [--refresh-idle PT72H] [--refresh-max P7D]` — change it.
 *
 * **`set` reads, changes, writes.** The API replaces the whole policy, so `set` reads it, applies only the flags given and
 * writes the result; an unchanged policy is not written. A change made by someone else between the read and the write is
 * overwritten (product-api's own compare-and-set covers its read, not this one), so run `show` afterwards when two people
 * may be changing the same environment. A refresh-token lifetime left out keeps its value.
 *
 * **Widening is a person's elevated act** (product-api `client_id_metadata_documents.widen`): enabling, adding a host,
 * turning refresh tokens on or lengthening a lifetime needs a passkey sign-in from the last five minutes (RFC 9470 step-up;
 * the CLI names the `thoryn login --acr-values … --max-age …` to run, then retry), and a machine identity (API key,
 * workload identity) is refused. Narrowing needs `manager` only.
 */
@Command(
    name = "metadata-documents",
    description = ["Show or change whether clients may identify themselves by a Client ID Metadata Document URL in an environment."],
    mixinStandardHelpOptions = true,
    subcommands = [
        EnvironmentMetadataDocumentsCommand.ShowSub::class,
        EnvironmentMetadataDocumentsCommand.SetSub::class,
    ],
)
class EnvironmentMetadataDocumentsCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn env metadata-documents <show|set>")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn env metadata-documents show [--env <slug>] [--output table|json|yaml]`. */
    @Command(name = "show", description = ["Show an environment's Client ID Metadata Document policy."], mixinStandardHelpOptions = true)
    class ShowSub : Callable<Int> {

        @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
        var env: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val slug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
            val envId = resolveIdOrNull(client, slug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                print(format, client.getClientIdMetadataDocumentPolicy(envId))
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderProblem(format, ex, SCOPE_READ, slug)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn env metadata-documents set [--env <slug>] <changes>`. */
    @Command(
        name = "set",
        description = [
            "Change an environment's Client ID Metadata Document policy. Only the flags you give change; enabling, adding a " +
                "host, turning refresh tokens on or lengthening a lifetime needs a passkey sign-in from the last five minutes.",
        ],
        mixinStandardHelpOptions = true,
    )
    class SetSub : Callable<Int> {

        @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
        var env: String? = null

        @Option(names = ["--enable"], description = ["Let clients identify themselves by a metadata-document URL (needs at least one allowed host)."])
        var enable: Boolean = false

        @Option(names = ["--disable"], description = ["Turn the method off: every URL client_id is an unknown client again. Keeps the host list."])
        var disable: Boolean = false

        @Option(names = ["--add-host"], description = ["Allow a client_id host, e.g. clients.example.com (repeatable)."])
        var addHosts: List<String> = emptyList()

        @Option(names = ["--remove-host"], description = ["Stop allowing a client_id host (repeatable)."])
        var removeHosts: List<String> = emptyList()

        @Option(names = ["--hosts"], description = ["Replace the whole host list with this comma-separated one ('' clears it). Not with --add-host / --remove-host."])
        var hosts: String? = null

        @Option(names = ["--refresh-tokens"], description = ["on|off — whether these clients get rotating refresh tokens."])
        var refreshTokens: String? = null

        @Option(names = ["--refresh-idle"], description = ["Refresh-token idle window, an ISO-8601 duration from PT1H to P90D (default PT72H)."])
        var refreshIdle: String? = null

        @Option(names = ["--refresh-max"], description = ["Total refresh-token lifetime, an ISO-8601 duration from PT1H to P90D, at least the idle window (default P7D)."])
        var refreshMax: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val change = change(System.err) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val slug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
            val envId = resolveIdOrNull(client, slug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val current = client.getClientIdMetadataDocumentPolicy(envId)
                val body = change.applyTo(current)
                if (unchanged(current, body)) {
                    if (format == OutputFormat.TABLE) System.err.println("No change: environment '$slug' already has this policy.")
                    print(format, current)
                    return CommandSupport.EXIT_OK
                }
                print(format, client.putClientIdMetadataDocumentPolicy(envId, body))
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderProblem(format, ex, SCOPE_WRITE, slug)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** The flags as a [PolicyChange], or null (with a usage error on [err]) when they contradict or say nothing. */
        internal fun change(err: PrintStream): PolicyChange? {
            if (enable && disable) return usage(err, "--enable and --disable contradict each other; give one.")
            if (hosts != null && (addHosts.isNotEmpty() || removeHosts.isNotEmpty())) {
                return usage(err, "--hosts replaces the whole list; it cannot be combined with --add-host or --remove-host.")
            }
            val refresh = when (refreshTokens?.trim()?.lowercase()) {
                null -> null
                "on", "true" -> true
                "off", "false" -> false
                else -> return usage(err, "--refresh-tokens must be on or off (was '$refreshTokens').")
            }
            val idle = refreshIdle?.let { parseLifetime(it, "--refresh-idle", err) ?: return null }
            val max = refreshMax?.let { parseLifetime(it, "--refresh-max", err) ?: return null }
            if (idle != null && max != null && max < idle) return usage(err, "--refresh-max must not be shorter than --refresh-idle.")
            val change = PolicyChange(
                enabled = if (enable) true else if (disable) false else null,
                replaceHosts = hosts?.split(',')?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() },
                addHosts = addHosts.flatMap { it.split(',') }.map { it.trim().lowercase() }.filter { it.isNotEmpty() },
                removeHosts = removeHosts.flatMap { it.split(',') }.map { it.trim().lowercase() }.filter { it.isNotEmpty() },
                refreshTokensEnabled = refresh,
                refreshTokenTtlSeconds = idle,
                refreshTokenAbsoluteMaxTtlSeconds = max,
            )
            if (change.isEmpty()) {
                return usage(
                    err,
                    "nothing to change: give --enable/--disable, --add-host/--remove-host/--hosts, --refresh-tokens, --refresh-idle or --refresh-max.",
                )
            }
            return change
        }

        private fun usage(err: PrintStream, message: String): PolicyChange? {
            err.println("Error: $message")
            return null
        }

        private fun parseLifetime(raw: String, flag: String, err: PrintStream): Long? {
            val seconds = try {
                Duration.parse(raw.trim().uppercase()).seconds
            } catch (_: DateTimeParseException) {
                err.println("Error: $flag must be an ISO-8601 duration such as PT72H or P7D (was '$raw').")
                return null
            }
            if (seconds !in MIN_LIFETIME_SECONDS..MAX_LIFETIME_SECONDS) {
                err.println("Error: $flag must be from PT1H (1 hour) to P90D (90 days) (was '$raw').")
                return null
            }
            return seconds
        }
    }

    /** What `set` changes; a null / empty member leaves that part of the policy as it is. */
    internal data class PolicyChange(
        val enabled: Boolean? = null,
        val replaceHosts: List<String>? = null,
        val addHosts: List<String> = emptyList(),
        val removeHosts: List<String> = emptyList(),
        val refreshTokensEnabled: Boolean? = null,
        val refreshTokenTtlSeconds: Long? = null,
        val refreshTokenAbsoluteMaxTtlSeconds: Long? = null,
    ) {
        fun isEmpty(): Boolean = enabled == null && replaceHosts == null && addHosts.isEmpty() && removeHosts.isEmpty() &&
            refreshTokensEnabled == null && refreshTokenTtlSeconds == null && refreshTokenAbsoluteMaxTtlSeconds == null

        /** The whole policy to PUT: [current] with this change applied. A lifetime is sent only when it changes. */
        fun applyTo(current: JsonNode): Map<String, Any?> {
            val currentHosts = current["allowedHosts"]?.takeIf { it.isArray }?.toList()?.map { it.asString().trim().lowercase() }.orEmpty()
            val hosts = (replaceHosts ?: (currentHosts + addHosts)).filter { it !in removeHosts }.distinct()
            return buildMap {
                put("enabled", enabled ?: (current["enabled"]?.asBoolean() ?: false))
                put("allowedHosts", hosts)
                put("refreshTokensEnabled", refreshTokensEnabled ?: (current["refreshTokensEnabled"]?.asBoolean() ?: false))
                refreshTokenTtlSeconds?.let { put("refreshTokenTtlSeconds", it) }
                refreshTokenAbsoluteMaxTtlSeconds?.let { put("refreshTokenAbsoluteMaxTtlSeconds", it) }
            }
        }
    }

    companion object {
        const val SCOPE_READ = "tenant:environments.read"
        const val SCOPE_WRITE = "tenant:environments.write"
        const val MIN_LIFETIME_SECONDS: Long = 3_600
        const val MAX_LIFETIME_SECONDS: Long = 7_776_000

        /** Whether writing [body] would leave [current] as it is (hosts compared as a set). */
        internal fun unchanged(current: JsonNode, body: Map<String, Any?>): Boolean {
            val currentHosts = current["allowedHosts"]?.takeIf { it.isArray }?.toList()?.map { it.asString() }.orEmpty().toSet()
            return (current["enabled"]?.asBoolean() ?: false) == body["enabled"] &&
                currentHosts == (body["allowedHosts"] as List<*>).toSet() &&
                (current["refreshTokensEnabled"]?.asBoolean() ?: false) == body["refreshTokensEnabled"] &&
                listOf("refreshTokenTtlSeconds", "refreshTokenAbsoluteMaxTtlSeconds").all { f ->
                    body[f] == null || current[f]?.takeIf { it.isNumber }?.asLong() == body[f]
                }
        }

        /** A duration in seconds as the table shows it: whole days from a week up, else whole hours, else seconds. */
        internal fun human(seconds: Long?): String? = when {
            seconds == null -> null
            seconds >= 604_800 && seconds % 86_400 == 0L -> "${seconds / 86_400}d"
            seconds % 3_600 == 0L -> "${seconds / 3_600}h"
            else -> "${seconds}s"
        }

        internal fun print(format: OutputFormat, policy: JsonNode, out: PrintStream = System.out) {
            when (format) {
                OutputFormat.JSON -> Printers.json(policy, out)
                OutputFormat.YAML -> Printers.yaml(policy, out)
                OutputFormat.TABLE -> Printers.record(
                    listOf(
                        "environment" to policy["environment"]?.asString(),
                        "enabled" to (policy["enabled"]?.asBoolean() ?: false),
                        "allowedHosts" to policy["allowedHosts"]?.takeIf { it.isArray }?.toList()?.joinToString(", ") { it.asString() }?.ifEmpty { "(none)" },
                        "refreshTokens" to if (policy["refreshTokensEnabled"]?.asBoolean() == true) "on" else "off",
                        "refreshIdle" to human(policy["refreshTokenTtlSeconds"]?.takeIf { it.isNumber }?.asLong()),
                        "refreshMax" to human(policy["refreshTokenAbsoluteMaxTtlSeconds"]?.takeIf { it.isNumber }?.asLong()),
                        "updatedAt" to (policy["updatedAt"]?.takeIf { !it.isNull }?.asString() ?: "(never changed: the defaults)"),
                    ),
                    out,
                )
            }
        }

        /**
         * A refusal of the policy surface: the step-up and the person-only rule of a widening write in words, then a sentence
         * per product-api / hub `errorCode`; anything else goes to [CommandSupport.renderError] (a scope `403` keeps its
         * login hint). Returns [CommandSupport.EXIT_HTTP_ERROR].
         */
        internal fun renderProblem(
            format: OutputFormat,
            ex: ProductApiException,
            requiredScope: String,
            slug: String,
            out: PrintStream = System.out,
            err: PrintStream = System.err,
        ): Int {
            if (ex.isStepUpRequired) {
                val exit = CommandSupport.renderError(format, ex, requiredScope = null, out = out, err = err)
                if (format == OutputFormat.TABLE) {
                    val acr = ex.stepUpAcrValues ?: WorkloadIdentityCommand.PASSKEY_ACR
                    val maxAge = ex.stepUpMaxAge ?: 300
                    err.println(
                        "Enabling the method, adding a host, turning refresh tokens on or lengthening a lifetime needs a passkey " +
                            "sign-in from the last ${maxAge / 60} minutes. Sign in again, then retry:",
                    )
                    err.println("  thoryn login --acr-values $acr --max-age $maxAge")
                }
                return exit
            }
            val hint = hintFor(ex, slug) ?: return CommandSupport.renderError(format, ex, requiredScope = requiredScope, out = out, err = err)
            val structured = linkedMapOf<String, Any?>(
                "error" to (ex.errorCode ?: "unknown"),
                "errorDescription" to ex.errorDescription,
                "httpStatus" to ex.httpStatus,
                "hint" to hint,
            )
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, out)
                OutputFormat.YAML -> Printers.yaml(structured, out)
                OutputFormat.TABLE -> {
                    err.println("Error: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}${ex.errorDescription?.let { " — $it" } ?: ""}")
                    err.println(hint)
                }
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }

        /** The sentence for each error code of the policy surface; null for a code another renderer owns. */
        internal fun hintFor(ex: ProductApiException, slug: String): String? = when (ex.errorCode) {
            "not_found" ->
                "No such environment in this workspace — or your identity is not a manager of environment '$slug' (a relation you " +
                    "lack is answered as not found, never 403). Check `thoryn env list` and `thoryn access mine --type environment`."
            "environment_mismatch" ->
                "This session's token is bound to another environment than '$slug': sign in for '$slug', or pass the environment that token is for with --env."
            "elevated_action_requires_person" ->
                "Widening the policy is a person's act: a workspace manager runs `thoryn env metadata-documents set` signed in with a " +
                    "passkey. A machine identity (API key, workload identity) may only narrow it."
            "elevation_evidence_required" ->
                "The platform could not confirm a fresh passkey sign-in. Sign in again with " +
                    "`thoryn login --acr-values ${WorkloadIdentityCommand.PASSKEY_ACR} --max-age 300` and retry."
            "invalid_allowed_host" ->
                "Each host is a DNS name such as clients.example.com: no scheme (https://), port, path, wildcard or IP address."
            "too_many_allowed_hosts" -> "At most 50 client_id hosts may be allowed per environment."
            "allowed_host_is_issuer" ->
                "A host Thoryn issues tokens on (a platform host, a workspace host or a custom domain) cannot be an allowed client_id host."
            "allowed_hosts_required" -> "Enabling needs at least one allowed host: add one with --add-host <host>."
            "invalid_refresh_token_lifetime" ->
                "Each refresh-token lifetime is from PT1H to P90D, and --refresh-max must not be shorter than --refresh-idle."
            "policy_changed" ->
                "Someone changed the policy at the same moment; nothing was written. Run `thoryn env metadata-documents show --env $slug` and retry."
            else -> null
        }
    }
}
