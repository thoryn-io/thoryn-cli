package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.examples.Prompt
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Duration
import java.util.concurrent.Callable

/**
 * `thoryn keys …` (SSO-3369) — on-demand rotation of one of the selected environment's signing keys,
 * a thin wrapper over product-api's `/api/v1/signing-keys/{kind}/rotations` (oathy SSO-3369) reached
 * through the api-gateway.
 *
 * Kinds:
 *  - `sign-in` — the key that signs the environment's ID and access tokens. The authorization hub
 *    rotates it as soon as it is asked (the answer is normally already `DONE`).
 *  - `security-events` — the key that signs the environment's security events to relying parties
 *    (SSF SETs, webhook fallback, DSAR data-return, veto callbacks). Its rotator picks the request up
 *    within about two minutes.
 *
 * Either way the new version signs everything from then on and the previous version stays published,
 * so what it signed keeps validating.
 *
 * Subcommands:
 *  - `rotate --kind <kind> [--wait] [--timeout <d>] [--yes]` — POST /api/v1/signing-keys/{kind}/rotations
 *  - `rotations [list] --kind <kind> [--limit n] [--cursor c]` — GET  /api/v1/signing-keys/{kind}/rotations
 *  - `rotations get <id> --kind <kind>`                         — GET  /api/v1/signing-keys/{kind}/rotations/{id}
 *
 * Every subcommand takes `--environment <slug>` (else the environment `env use` selected), `--output
 * json|yaml|table` and `--json`. Scopes: `rotate` → `tenant:keys.rotate` (workspace admins only — for
 * anyone else the API answers 404); reading → `tenant:keys.read` (both granted by oathy hub V183 and
 * part of the default `thoryn login` set).
 */
@Command(
    name = "keys",
    description = ["Rotate your environment's signing keys on demand (sign-in tokens, security events)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        KeysCommand.RotateSubcommand::class,
        KeysCommand.RotationsCommand::class,
    ],
)
class KeysCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn keys <subcommand>")
        System.err.println("Subcommands: rotate | rotations [list | get <id>]")
        return CommandSupport.EXIT_USAGE
    }

    /** Options every `keys` subcommand shares. */
    abstract class Base : Callable<Int> {
        // Validated in call() rather than `required = true`: picocli would otherwise demand it on the
        // `rotations` parent when the option is given to its `get` / `list` subcommand.
        @Option(names = ["--kind"], description = ["Which key: sign-in | security-events (required)."])
        var kindRaw: String? = null

        /** The validated `--kind`. */
        val kind: String get() = kindRaw.orEmpty()

        @Option(names = ["--environment"], description = [UsersCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(
            names = ["--gateway"],
            description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."],
            defaultValue = ThorynConfig.DEFAULT_GATEWAY,
        )
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        @Option(names = ["--json"], description = ["Machine-readable output; shorthand for --output json."])
        var json: Boolean = false

        /** The scope the subcommand needs, for the `thoryn login --scope …` hint on a 403. */
        abstract val requiredScope: String

        override fun call(): Int {
            if (json && outputRaw != null && !outputRaw.equals("json", ignoreCase = true)) {
                System.err.println("Error: --json cannot be combined with --output $outputRaw.")
                return CommandSupport.EXIT_USAGE
            }
            val format = CommandSupport.parseFormat(if (json) "json" else outputRaw) ?: return CommandSupport.EXIT_USAGE
            if (kindRaw == null) {
                System.err.println("Error: --kind is required (${KINDS.joinToString(" | ")}).")
                return CommandSupport.EXIT_USAGE
            }
            if (kind !in KINDS) {
                System.err.println("Error: --kind must be one of ${KINDS.joinToString(" | ")} (was '$kind').")
                return CommandSupport.EXIT_USAGE
            }
            val precheck = precheck()
            if (precheck != null) return precheck
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = UsersCommand.clientFor(gateway, tokens, environment)
            return try {
                run(client, format)
            } catch (ex: ProductApiException) {
                renderKeysError(format, ex, requiredScope, kind)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** Local validation before any network call; a non-null exit code stops the command. */
        open fun precheck(): Int? = null

        abstract fun run(client: ProductApiClient, format: OutputFormat): Int
    }

    /** `thoryn keys rotate --kind <kind> [--wait] [--timeout <d>] [--yes]` */
    @Command(
        name = "rotate",
        description = [
            "Request a new version of one of the environment's signing keys (workspace admins).",
            "New tokens/messages are signed with the new version; the old one stays published, so what it",
            "signed keeps validating.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RotateSubcommand : Base() {

        @Option(names = ["--wait"], description = ["Wait until the new key version is published (or the request fails)."])
        var wait: Boolean = false

        @Option(
            names = ["--timeout"],
            description = ["With --wait: give up after this long, e.g. 90s, 5m (default: 5m)."],
        )
        var timeoutRaw: String = "5m"

        @Option(names = ["--poll-interval"], hidden = true, description = ["With --wait: time between checks (default: 3s)."])
        var pollRaw: String = "3s"

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        override val requiredScope: String = SCOPE_ROTATE

        private lateinit var timeout: Duration
        private lateinit var poll: Duration

        override fun precheck(): Int? {
            timeout = parseDuration(timeoutRaw) ?: return usage("--timeout", timeoutRaw)
            poll = parseDuration(pollRaw) ?: return usage("--poll-interval", pollRaw)
            if (yes) return null
            val where = environment?.let { "environment '$it'" } ?: "the selected environment"
            val confirmed = Prompt.confirm(
                "Rotate the ${describe(kind)} of $where? New ${signs(kind)} will be signed with a new key version; " +
                    "the previous version stays published, so what it signed keeps validating.",
            )
            if (confirmed) return null
            System.err.println(
                if (Prompt.interactive()) "Aborted." else "Refusing to rotate without confirmation; re-run with --yes.",
            )
            return CommandSupport.EXIT_USAGE
        }

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            var body = client.requestSigningKeyRotation(kind)
            val id = text(body, "id") ?: return render(format, body, CommandSupport.EXIT_OK)
            if (format == OutputFormat.TABLE) {
                System.out.println("Rotation requested: $id  (${text(body, "kind")}, ${text(body, "environment")})")
            }
            if (wait && state(body) == STATE_PENDING) {
                if (format == OutputFormat.TABLE) System.out.println("Waiting for the key's rotator…")
                val deadline = System.nanoTime() + timeout.toNanos()
                while (state(body) == STATE_PENDING && System.nanoTime() < deadline) {
                    Thread.sleep(poll.toMillis())
                    body = client.getSigningKeyRotation(kind, id)
                }
                if (state(body) == STATE_PENDING) {
                    if (format == OutputFormat.TABLE) {
                        System.err.println(
                            "Still PENDING after ${timeoutRaw}. Follow it with: thoryn keys rotations get $id --kind $kind",
                        )
                    } else {
                        CommandSupport.emitRecord(format, body, ::rotationFields)
                    }
                    return CommandSupport.EXIT_CHECK_FAILED
                }
            }
            return render(format, body, if (state(body) == STATE_FAILED) CommandSupport.EXIT_CHECK_FAILED else CommandSupport.EXIT_OK)
        }

        private fun render(format: OutputFormat, body: JsonNode, exit: Int): Int {
            when (format) {
                OutputFormat.TABLE -> System.out.println(summary(body, kind))
                else -> CommandSupport.emitRecord(format, body, ::rotationFields)
            }
            return exit
        }

        private fun usage(option: String, raw: String): Int {
            System.err.println("Error: $option must be a duration such as 90s or 5m (was '$raw').")
            return CommandSupport.EXIT_USAGE
        }
    }

    /** `thoryn keys rotations [list] --kind <kind>` — the environment's requests, newest first. */
    @Command(
        name = "rotations",
        description = ["List the environment's on-demand rotation requests for a key (or `get <id>`)."],
        mixinStandardHelpOptions = true,
        subcommands = [RotationsListSubcommand::class, RotationsGetSubcommand::class],
    )
    class RotationsCommand : Base() {
        @Option(names = ["--limit"], description = ["Maximum requests to return (default: 50)."])
        var limit: Int? = null

        @Option(names = ["--cursor"], description = ["Continue a previous listing (the `pagination.cursor` it returned)."])
        var cursor: String? = null

        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int = list(client, format, kind, limit, cursor)
    }

    /** `thoryn keys rotations list --kind <kind>` */
    @Command(name = "list", description = ["List the environment's on-demand rotation requests for a key."], mixinStandardHelpOptions = true)
    class RotationsListSubcommand : Base() {
        @Option(names = ["--limit"], description = ["Maximum requests to return (default: 50)."])
        var limit: Int? = null

        @Option(names = ["--cursor"], description = ["Continue a previous listing (the `pagination.cursor` it returned)."])
        var cursor: String? = null

        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int = list(client, format, kind, limit, cursor)
    }

    /** `thoryn keys rotations get <id> --kind <kind>` */
    @Command(name = "get", description = ["Show one rotation request."], mixinStandardHelpOptions = true)
    class RotationsGetSubcommand : Base() {
        @Parameters(index = "0", paramLabel = "<id>", description = ["The request id (from `keys rotate`)."])
        lateinit var id: String

        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.getSigningKeyRotation(kind, id.trim())
            when (format) {
                OutputFormat.TABLE -> {
                    Printers.record(rotationFields(body), System.out)
                    System.out.println()
                    System.out.println(summary(body, kind))
                }
                else -> CommandSupport.emitRecord(format, body, ::rotationFields)
            }
            return CommandSupport.EXIT_OK
        }
    }

    companion object {
        const val SCOPE_READ: String = "tenant:keys.read"
        const val SCOPE_ROTATE: String = "tenant:keys.rotate"
        const val KIND_SIGN_IN: String = "sign-in"
        const val KIND_SECURITY_EVENTS: String = "security-events"
        val KINDS: List<String> = listOf(KIND_SIGN_IN, KIND_SECURITY_EVENTS)

        const val STATE_PENDING: String = "PENDING"
        const val STATE_DONE: String = "DONE"
        const val STATE_FAILED: String = "FAILED"

        private val LIST_HEADERS = listOf("ID", "STATE", "ENVIRONMENT", "REQUESTED", "VERSION", "KID / REASON")

        internal fun list(client: ProductApiClient, format: OutputFormat, kind: String, limit: Int?, cursor: String?): Int {
            val body = client.listSigningKeyRotations(kind, limit, cursor)
            CommandSupport.emitList(format, body, LIST_HEADERS, rowMapper = { row: JsonNode ->
                listOf(
                    text(row, "id"),
                    text(row, "state"),
                    text(row, "environment"),
                    text(row, "requestedAt"),
                    row["keyVersion"]?.takeUnless { it.isNull }?.asInt(),
                    text(row, "kid") ?: text(row, "failureReason"),
                )
            })
            if (format == OutputFormat.TABLE) {
                body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.let {
                    System.out.println("More: thoryn keys rotations list --kind $kind --cursor $it")
                }
            }
            return CommandSupport.EXIT_OK
        }

        private fun text(node: JsonNode, field: String): String? =
            node[field]?.takeUnless { it.isNull }?.asString()

        private fun state(node: JsonNode): String? = text(node, "state")

        fun rotationFields(body: JsonNode): List<Pair<String, Any?>> = listOf(
            "id" to text(body, "id"),
            "kind" to text(body, "kind"),
            "environment" to text(body, "environment"),
            "state" to text(body, "state"),
            "requestedAt" to text(body, "requestedAt"),
            "completedAt" to text(body, "completedAt"),
            "keyVersion" to body["keyVersion"]?.takeUnless { it.isNull }?.asInt(),
            "kid" to text(body, "kid"),
            "failureReason" to text(body, "failureReason"),
        ).filter { it.second != null }

        /** One plain sentence for the request's state. */
        fun summary(body: JsonNode, kind: String): String = when (state(body)) {
            STATE_DONE -> "DONE — new version ${body["keyVersion"]?.asInt()}, kid ${text(body, "kid")}. " +
                "The previous version stays published, so what it signed keeps validating."
            STATE_FAILED -> "FAILED — ${failureText(text(body, "failureReason"))}"
            STATE_PENDING -> if (kind == KIND_SECURITY_EVENTS) {
                "PENDING — the rotator picks it up within about two minutes. Add --wait to follow it."
            } else {
                "PENDING — the hub has not completed it yet. Follow it with: thoryn keys rotations get ${text(body, "id")} --kind $kind"
            }
            else -> "State: ${state(body)}"
        }

        fun failureText(reason: String?): String = when (reason) {
            "key_not_provisioned" ->
                "this environment has not signed anything with that key yet, so there is nothing to rotate (its first key is created on first use)."
            "timed_out" -> "the request was not completed within 30 minutes. Ask again; if it repeats, contact support."
            null -> "no reason reported."
            else -> "$reason."
        }

        private fun describe(kind: String): String =
            if (kind == KIND_SIGN_IN) "sign-in token signing key" else "security-event signing key"

        private fun signs(kind: String): String =
            if (kind == KIND_SIGN_IN) "ID and access tokens" else "security events to your relying parties"

        /** `90s`, `5m`, `1h`, a bare number of seconds, or an ISO-8601 duration (`PT5M`). */
        internal fun parseDuration(raw: String): Duration? {
            val value = raw.trim().lowercase()
            val match = Regex("^(\\d+)([smh]?)$").matchEntire(value)
            if (match != null) {
                val n = match.groupValues[1].toLong()
                return when (match.groupValues[2]) {
                    "m" -> Duration.ofMinutes(n)
                    "h" -> Duration.ofHours(n)
                    else -> Duration.ofSeconds(n)
                }
            }
            return runCatching { Duration.parse(raw.trim().uppercase()) }.getOrNull()?.takeUnless { it.isNegative }
        }

        /**
         * Error rendering with key-rotation guidance on top of [CommandSupport.renderError]: the 404
         * that stands for "not an admin" (never 403), the pending request to follow, and when the
         * cooldown ends.
         */
        fun renderKeysError(format: OutputFormat, ex: ProductApiException, requiredScope: String, kind: String): Int {
            val extra = runCatching { JsonMapper.builder().build().readTree(ex.rawBody) }.getOrNull()
            val hint = when (ex.errorCode) {
                "signing_key_not_found" ->
                    "Only workspace admins can rotate keys, and only in an environment they can reach. Check --environment."
                "signing_key_rotation_not_found" -> "No such request in this workspace for that --kind."
                "unknown_key_kind" -> "Use --kind ${KINDS.joinToString(" or ")}."
                "rotation_pending" -> extra?.get("pendingRequestId")?.asString()?.let {
                    "A rotation of this key is still pending. Follow it with: thoryn keys rotations get $it --kind $kind"
                }
                "rotation_cooldown" -> extra?.get("retryAt")?.asString()?.let {
                    "This key was rotated on request recently. A new request is accepted from $it."
                }
                "hub_unavailable", "upstream_hub_error" -> "Nothing was rotated; try again in a moment."
                else -> null
            }
            val exit = CommandSupport.renderError(format, ex, requiredScope = requiredScope)
            if (hint != null && format == OutputFormat.TABLE) System.err.println(hint)
            return exit
        }
    }
}
