package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import com.devnow.thoryn.cli.output.Timestamps
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.File
import java.io.PrintStream
import java.time.Instant
import java.util.concurrent.Callable

/**
 * `thoryn clients ...` — OAuth client (relying-party) CRUD + secret rotation,
 * a thin wrapper over product-api's `/api/v1/applications` surface
 * (SSO-1027 / SSO-1028) reached through the api-gateway.
 *
 * **Client-surface choice (SSO-1552).** The CLI targets `/api/v1/applications`
 * for ALL client ops — NOT the thinner `/clients` smoke-test surface — so the
 * CLI and the web console share exactly one contract (the applications surface
 * is the console's, and the only one that carries secret rotation). The
 * `list` subcommand is repointed from the old `/clients` to `/api/v1/applications`
 * accordingly; its output shape is unchanged for scripting.
 *
 * **Secret-safety (hard requirement).** A created client's secret and a rotated
 * secret are returned ONCE by the server. They are emitted via [SecretIo] —
 * written to a `--secret-file` or printed to an interactive TTY with a WARN;
 * printing to a non-TTY pipe is refused unless `--force-stdout` is given. No
 * secret value is ever accepted as, or printed as part of, a command-line
 * argument.
 *
 * Subcommands:
 *  - `list`          — GET  /api/v1/applications
 *  - `get`           — GET  /api/v1/applications/{clientId}
 *  - `create`        — POST /api/v1/applications  (secret emitted via SecretIo)
 *  - `update`        — PATCH /api/v1/applications/{clientId}
 *  - `rotate-secret` — POST /api/v1/applications/{clientId}/secret/rotate
 *  - `secret-state`  — GET  /api/v1/applications/{clientId}/secrets/state (SSO-3957; the rotation
 *    state in plain words — see [SecretStateSubcommand])
 *  - `delete`        — DELETE /api/v1/applications/{clientId}
 *  - `registration-token` — POST /api/v1/applications/registration-tokens (SSO-3683; the
 *    Initial Access Token emitted via SecretIo — see [RegistrationTokenSubcommand])
 *
 * Scopes: GET (incl. `secret-state`) → `tenant:applications.read`; create/update/rotate/delete/
 * registration-token → `tenant:applications.write`.
 */
@Command(
    name = "clients",
    description = ["Manage OAuth clients (relying parties) in your tenant."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ClientsCommand.ListSubcommand::class,
        ClientsCommand.GetSubcommand::class,
        ClientsCommand.CreateSubcommand::class,
        ClientsCommand.UpdateSubcommand::class,
        ClientsCommand.RotateSecretSubcommand::class,
        ClientsCommand.SecretStateSubcommand::class,
        ClientsCommand.DeleteSubcommand::class,
        ClientsCommand.RegistrationTokenSubcommand::class,
    ],
)
class ClientsCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn clients <subcommand>")
        System.err.println("Subcommands: list | get | create | update | rotate-secret | secret-state | delete | registration-token")
        return CommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn clients registration-token [--software-id <id>] [--ttl <seconds>] [--out-file <path>]`
     *
     * SSO-3683 (oauthy ADR 2026-10-14 §2(b)) — mints a Dynamic Client Registration (RFC 7591)
     * **Initial Access Token** for your workspace and the SELECTED environment, to hand to a
     * third-party vendor whose software registers its own OAuth client at the workspace's
     * `registration_endpoint`. The token is single-use, pinned to your workspace and environment,
     * expires after `--ttl` (default and maximum one hour), and may only grant the client scopes you
     * hold yourself; `--software-id` additionally pins it to one piece of software.
     *
     * **Secret-safety.** The token IS a credential (it creates a client). It is emitted through
     * [SecretIo] exactly like a client secret: written to `--out-file` (owner-only, `0600`) or printed
     * to an interactive TTY with a WARN; printing to a non-TTY stdout is refused unless
     * `--force-stdout`. It is stripped from the `--output json|yaml|table` record, which carries the
     * two values the vendor needs next to it: `registrationEndpoint` and `expiresAt`.
     */
    @Command(
        name = "registration-token",
        description = [
            "Mint a single-use Dynamic Client Registration token (RFC 7591) a third party redeems at your " +
                "workspace's registration_endpoint. The token is shown once.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RegistrationTokenSubcommand : Callable<Int> {

        @Option(names = ["--software-id"], description = ["Pin the token to one software_id: the registration must carry the same value."])
        var softwareId: String? = null

        @Option(names = ["--ttl"], description = ["Lifetime in seconds (default and maximum: 3600)."])
        var ttlSeconds: Long? = null

        @Option(
            names = ["--out-file", "--secret-file"],
            description = ["Write the token to this file (owner-only) instead of printing it to a TTY/pipe."],
        )
        var outFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing the token to a non-interactive stdout (pipe/redirect). Off by default to avoid leaking it into a pipeline."])
        var forceStdout: Boolean = false

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        lateinit var gateway: String

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            if (ttlSeconds != null && ttlSeconds!! !in 1..MAX_TTL_SECONDS) {
                System.err.println("Error: --ttl must be between 1 and $MAX_TTL_SECONDS seconds.")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens)

            val body = linkedMapOf<String, Any?>(
                "ttlSeconds" to ttlSeconds,
                "softwareId" to softwareId?.trim()?.takeIf { it.isNotEmpty() },
            )
            return try {
                val response = client.mintRegistrationToken(body)
                emitMintedToken(response, format)
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /**
         * The record (`registrationEndpoint`, `expiresAt`) prints normally; the one-shot
         * `initialAccessToken` goes through [SecretIo] and is stripped from the JSON/YAML/table view
         * so it cannot leak through `--output json` into a pipeline.
         */
        private fun emitMintedToken(response: JsonNode, format: OutputFormat): Int {
            val token = response["initialAccessToken"]?.asString()
            val safe = stripRegistrationToken(response)
            CommandSupport.emitRecord(format, safe, ::registrationTokenRecordFields)
            if (token.isNullOrEmpty()) {
                System.err.println("Error: the server returned no initialAccessToken.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            val emitted = SecretIo.emitSecret(
                label = "Initial access token",
                secret = token,
                secretFile = outFile,
                forceStdout = forceStdout,
            )
            return if (emitted) CommandSupport.EXIT_OK else SecretIo.EXIT_NO_SECRET
        }

        companion object {
            /** product-api's cap (`RegistrationTokenService.MAX_TTL_SECONDS`); refused client-side with a usage error. */
            const val MAX_TTL_SECONDS: Long = 3600
        }
    }

    /** `thoryn clients list` */
    @Command(name = "list", description = ["List OAuth clients in your tenant."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.listApplications()
                CommandSupport.emitList(format, body, LIST_HEADERS, ::clientRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn clients get <clientId>` */
    @Command(name = "get", description = ["Show a single OAuth client."], mixinStandardHelpOptions = true)
    class GetSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.getApplication(clientId)
                CommandSupport.emitRecord(format, body, ::clientRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn clients create --display-name <n> --redirect-uri <uri> [...]`
     *
     * The client secret is minted server-side and returned once; it is emitted
     * via [SecretIo] (never printed as part of argv, never into a pipe by
     * default). For confidential clients without `--secret-file`, an interactive
     * TTY is required (or pass `--force-stdout` to acknowledge the leak risk).
     */
    @Command(name = "create", description = ["Register a new OAuth client. The client secret is shown once."], mixinStandardHelpOptions = true)
    class CreateSubcommand : Callable<Int> {

        @Option(names = ["--display-name"], description = ["Human-readable client name."], required = true)
        lateinit var displayName: String

        @Option(names = ["--redirect-uri"], description = ["Redirect URI (repeatable). At least one required."], required = true)
        lateinit var redirectUris: Array<String>

        @Option(names = ["--scope"], description = ["Scope to grant the client (repeatable). Must be a subset of your own active scopes."])
        var scopes: Array<String> = emptyArray()

        @Option(names = ["--grant-type"], description = ["Grant type (repeatable). Default: authorization_code, refresh_token."])
        var grantTypes: Array<String> = emptyArray()

        @Option(names = ["--client-type"], description = ["confidential (default) or public (PKCE-only, no secret)."], defaultValue = "confidential")
        var clientType: String = "confidential"

        @Option(names = ["--client-id"], description = ["Optional explicit client ID (auto-generated when omitted)."])
        var clientId: String? = null

        @Option(names = ["--secret-file"], description = ["Write the minted client secret to this file (owner-only). Avoids printing it to a TTY/pipe."])
        var secretFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing the secret to a non-interactive stdout (pipe/redirect). Off by default to avoid leaking it into a pipeline."])
        var forceStdout: Boolean = false

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)

            val body = linkedMapOf<String, Any?>(
                "displayName" to displayName,
                "redirectUris" to redirectUris.toList(),
                "clientType" to clientType,
            )
            if (scopes.isNotEmpty()) body["scopes"] = scopes.toList()
            if (grantTypes.isNotEmpty()) body["grantTypes"] = grantTypes.toList()
            clientId?.let { body["clientId"] = it }

            return try {
                val response = client.createApplication(body)
                emitCreatedClient(response, format)
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /**
         * Print the created client's non-secret fields normally, then emit the
         * one-shot `clientSecret` through [SecretIo]. The secret is stripped
         * from the JSON/YAML/table view so it can't leak through `--output json`
         * into a pipeline.
         */
        private fun emitCreatedClient(response: JsonNode, format: OutputFormat): Int {
            val secret = response["clientSecret"]?.asString()
            val safe = stripSecret(response)
            CommandSupport.emitRecord(format, safe, ::createdClientRecordFields)
            if (!secret.isNullOrEmpty()) {
                val emitted = SecretIo.emitSecret(
                    label = "Client secret",
                    secret = secret,
                    secretFile = secretFile,
                    forceStdout = forceStdout,
                )
                if (!emitted) return SecretIo.EXIT_NO_SECRET
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn clients update <clientId> [--display-name ...] [--redirect-uri ...] [--scope ...]` */
    @Command(name = "update", description = ["Update a client's display name, redirect URIs, or scopes."], mixinStandardHelpOptions = true)
    class UpdateSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(names = ["--display-name"])
        var displayName: String? = null

        @Option(names = ["--redirect-uri"], description = ["Replacement redirect URI (repeatable). Replaces the full set when supplied."])
        var redirectUris: Array<String>? = null

        @Option(names = ["--scope"], description = ["Replacement scope (repeatable). Replaces the full set when supplied."])
        var scopes: Array<String>? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            if (displayName == null && redirectUris == null && scopes == null) {
                System.err.println("Error: supply at least one of --display-name, --redirect-uri, --scope.")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            val body = linkedMapOf<String, Any?>()
            displayName?.let { body["displayName"] = it }
            redirectUris?.let { body["redirectUris"] = it.toList() }
            scopes?.let { body["scopes"] = it.toList() }
            return try {
                val response = client.updateApplication(clientId, body)
                CommandSupport.emitRecord(format, response, ::clientRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn clients rotate-secret <clientId> [--secret-file <path>]`
     *
     * The new secret is returned once and emitted via [SecretIo]. The previous
     * secret keeps validating for a 24h overlap (the response carries
     * `oldSecretExpiresAt`).
     *
     * **A rotation already in flight (SSO-3957).** The server refuses a second rotation while the
     * previous secret is still in its overlap window (`409 rotation_in_flight`). That is a state, not
     * a fault, so instead of the generic error line the command says when the next rotation is
     * allowed — from the server's hint when the 409 carries one, otherwise by reading
     * `secret-state` — that the previous secret keeps working until then, and where the incident
     * path is. Exit code stays [CommandSupport.EXIT_HTTP_ERROR]: the server refused the call, which
     * is what that code has always meant to scripts.
     */
    @Command(
        name = "rotate-secret",
        description = [
            "Rotate a client's secret. The new secret is shown once; the old one stays valid for 24h. " +
                "While that window is open a second rotation is refused (409) and the command says from when " +
                "it is allowed again — see `thoryn clients secret-state`.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RotateSecretSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(names = ["--secret-file"], description = ["Write the new secret to this file (owner-only) instead of a TTY/pipe."])
        var secretFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing the secret to a non-interactive stdout. Off by default."])
        var forceStdout: Boolean = false

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val response = client.rotateApplicationSecret(clientId, confirm)
                val secret = response["newSecret"]?.asString()
                val safe = stripNewSecret(response)
                CommandSupport.emitRecord(format, safe, ::rotateRecordFields)
                if (!secret.isNullOrEmpty()) {
                    val emitted = SecretIo.emitSecret(
                        label = "New client secret",
                        secret = secret,
                        secretFile = secretFile,
                        forceStdout = forceStdout,
                    )
                    if (!emitted) return SecretIo.EXIT_NO_SECRET
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                if (ex.errorCode == ERROR_CODE_ROTATION_IN_FLIGHT) {
                    // SSO-3957 — the hint rides the 409 when product-api could read the hub's state; when
                    // it could not, ask for the state ourselves. Either failing leaves the time unknown
                    // and the message still names the command that shows it.
                    val availableAt = rotationAvailableAtFrom(ex)
                        ?: runCatching { Timestamps.instantOf(client.getApplicationSecretState(clientId)["rotationAvailableAt"]) }
                            .getOrNull()
                    return renderRotationInFlight(format, ex, clientId, availableAt)
                }
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn clients secret-state <clientId>`
     *
     * SSO-3957 — the live rotation state of a client's secret, read from
     * `GET /api/v1/applications/{clientId}/secrets/state` (SSO-1028). `rotate-secret` prints the
     * overlap window once, at rotation time; this shows it again, from the server, whenever you ask:
     * whether a previous secret is still working and until when, whether a new rotation is allowed
     * right now, and if not, from when. `--output json|yaml` prints the server's body as it arrived
     * (`previousSecretId`, `previousExpiresAt`, `rotationAvailable`, `rotationAvailableAt`); the table
     * adds the age of each time and a one-line reading of the state.
     *
     * A read: `tenant:applications.read`.
     */
    @Command(
        name = "secret-state",
        description = [
            "Show a client's secret rotation state: whether the previous secret still works and until when, " +
                "and whether (or from when) a new rotation is allowed.",
        ],
        mixinStandardHelpOptions = true,
    )
    class SecretStateSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.getApplicationSecretState(clientId)
                CommandSupport.emitRecord(format, body, ::secretStateRecordFields)
                if (format == OutputFormat.TABLE) println(secretStateSummary(body))
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn clients delete <clientId>` */
    @Command(name = "delete", description = ["Delete an OAuth client."], mixinStandardHelpOptions = true)
    class DeleteSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                client.deleteApplication(clientId, confirm)
                CommandSupport.emitValue(
                    format,
                    mapOf("deleted" to true, "clientId" to clientId),
                    "Deleted client '$clientId'.",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf(
            "clientId", "displayName", "clientType", "scopes", "status",
        )

        internal fun clientRow(node: JsonNode): List<Any?> = listOf(
            node["clientId"]?.asString(),
            node["displayName"]?.asString(),
            node["clientType"]?.asString(),
            node["scopes"]?.let { joinArray(it) },
            node["status"]?.asString(),
        )

        internal fun clientRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "clientId" to node["clientId"]?.asString(),
            "displayName" to node["displayName"]?.asString(),
            "clientType" to node["clientType"]?.asString(),
            "redirectUris" to node["redirectUris"]?.let { joinArray(it) },
            "scopes" to node["scopes"]?.let { joinArray(it) },
            "grantTypes" to node["grantTypes"]?.let { joinArray(it) },
            "status" to node["status"]?.asString(),
            "createdAt" to node["createdAt"]?.asString(),
        )

        internal fun createdClientRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "clientId" to node["clientId"]?.asString(),
            "displayName" to node["displayName"]?.asString(),
            "redirectUris" to node["redirectUris"]?.let { joinArray(it) },
            "scopes" to node["scopes"]?.let { joinArray(it) },
            "grantTypes" to node["grantTypes"]?.let { joinArray(it) },
            "status" to node["status"]?.asString(),
            "createdAt" to node["createdAt"]?.asString(),
        )

        /** SSO-3683 — the mint record WITHOUT the token (it rides SecretIo). */
        internal fun registrationTokenRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "registration_endpoint" to node["registrationEndpoint"]?.asString(),
            "expires_at" to node["expiresAt"]?.asString(),
        )

        internal fun stripRegistrationToken(node: JsonNode): JsonNode {
            if (node is tools.jackson.databind.node.ObjectNode) {
                return node.deepCopy().apply { remove("initialAccessToken") }
            }
            return node
        }

        internal fun rotateRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "newSecretId" to node["newSecretId"]?.asString(),
            "previousSecretId" to node["previousSecretId"]?.asString(),
            "oldSecretExpiresAt" to node["oldSecretExpiresAt"]?.asString(),
        )

        // ── SSO-3957: secret rotation state ─────────────────────────────────────────────────────────

        /** RFC 9457 `errorCode` product-api emits with 409 while a previous secret's overlap window is open. */
        internal const val ERROR_CODE_ROTATION_IN_FLIGHT: String = "rotation_in_flight"

        /**
         * Where to read about ending the previous secret now or replacing a lost new secret. Those are
         * incident paths SSO-3956 is building on the server; this CLI does not claim commands for them
         * yet, so the pointer is to the README, which says what exists and what is planned.
         */
        internal const val ROTATION_INCIDENT_PATH_HINT: String =
            "To end the previous secret now, or to replace a lost new secret, see \"Rotation state\" in the thoryn CLI " +
                "README (incident paths, SSO-3956)."

        /**
         * The `secret-state` table: the four server fields, times rendered with their age
         * (`2026-06-10T10:00:00Z (in 23h 59m)`), absent values as `-`.
         */
        internal fun secretStateRecordFields(node: JsonNode, now: Instant = Instant.now()): List<Pair<String, Any?>> = listOf(
            "previousSecretId" to (node["previousSecretId"]?.takeIf { !it.isNull }?.asString() ?: "-"),
            "previousExpiresAt" to (Timestamps.render(node["previousExpiresAt"], now) ?: "-"),
            "rotationAvailable" to (node["rotationAvailable"]?.takeIf { !it.isNull }?.asBoolean() ?: "-"),
            "rotationAvailableAt" to (Timestamps.render(node["rotationAvailableAt"], now) ?: "-"),
        )

        /**
         * One line that reads the state out in plain words. `rotationAvailable` decides which: when it
         * is false the previous secret is still working and the window end is the moment a rotation is
         * allowed again (the hub sets both from the same overlap row).
         */
        internal fun secretStateSummary(node: JsonNode, now: Instant = Instant.now()): String {
            val available = node["rotationAvailable"]?.takeIf { !it.isNull }?.asBoolean()
            val until = Timestamps.render(node["previousExpiresAt"], now)
                ?: Timestamps.render(node["rotationAvailableAt"], now)
            return when {
                available == true ->
                    "No rotation is in flight: only the current secret works, and you can rotate now."
                available == false && until != null ->
                    "A rotation is in flight: the previous secret keeps working until $until. " +
                        "The next rotation is allowed from then."
                available == false ->
                    "A rotation is in flight: the previous secret still works and a new rotation is not allowed yet."
                else -> "The server did not say whether a rotation is allowed."
            }
        }

        /**
         * The moment the next rotation is allowed, as the 409 itself carries it: a structured
         * `rotationAvailableAt` member of the problem body when product-api sends one (the SSO-3956
         * schema), otherwise the ISO instant inside the `detail` sentence
         * (`… The next rotation is available at 2026-06-10T10:00:00Z.`). Null when the 409 carries
         * neither — the caller then asks `secret-state`.
         */
        internal fun rotationAvailableAtFrom(ex: ProductApiException): Instant? {
            val structured = runCatching { PROBLEM_MAPPER.readTree(ex.rawBody)["rotationAvailableAt"] }.getOrNull()
            Timestamps.instantOf(structured)?.let { return it }
            val inDetail = ex.errorDescription?.let { ISO_INSTANT_IN_TEXT.find(it)?.value } ?: return null
            return runCatching { Instant.parse(inDetail) }.getOrNull()
                ?: runCatching { java.time.OffsetDateTime.parse(inDetail).toInstant() }.getOrNull()
        }

        /**
         * Render `409 rotation_in_flight` as the state it is. TABLE prints, to stderr: the error line
         * (so `rotation_in_flight` stays greppable), when the next rotation is allowed and that the
         * previous secret keeps working until then (or, when the time is unknown, the command that
         * shows it), and the incident-path pointer. JSON/YAML carry the same as `rotationAvailableAt`
         * + `hint` next to the stable `error`, so a script can wait for the time rather than parse
         * prose. Returns [CommandSupport.EXIT_HTTP_ERROR] — the server refused the call.
         */
        internal fun renderRotationInFlight(
            format: OutputFormat,
            ex: ProductApiException,
            clientId: String,
            availableAt: Instant?,
            now: Instant = Instant.now(),
            out: PrintStream = System.out,
            err: PrintStream = System.err,
        ): Int {
            val whenLine = if (availableAt != null) {
                val at = "${availableAt.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)} (${Timestamps.age(availableAt, now)})"
                "The previous secret keeps working until $at. The next rotation is allowed from then."
            } else {
                "The previous secret keeps working until its overlap window ends; `thoryn clients secret-state $clientId` " +
                    "shows when, and from when the next rotation is allowed."
            }
            val structured = linkedMapOf<String, Any?>(
                "error" to ERROR_CODE_ROTATION_IN_FLIGHT,
                "errorDescription" to ex.errorDescription,
                "httpStatus" to ex.httpStatus,
                "rotationAvailableAt" to availableAt?.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)?.toString(),
                "hint" to "$whenLine $ROTATION_INCIDENT_PATH_HINT",
            )
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, out)
                OutputFormat.YAML -> Printers.yaml(structured, out)
                OutputFormat.TABLE -> {
                    val description = ex.errorDescription?.let { " — $it" } ?: ""
                    err.println("Error: $ERROR_CODE_ROTATION_IN_FLIGHT$description")
                    err.println(whenLine)
                    err.println(ROTATION_INCIDENT_PATH_HINT)
                }
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }

        /** An ISO-8601 instant inside prose: `2026-06-10T10:00:00Z`, with an optional fraction or offset. */
        private val ISO_INSTANT_IN_TEXT = Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})""")

        private val PROBLEM_MAPPER: tools.jackson.databind.ObjectMapper = tools.jackson.databind.json.JsonMapper.builder().build()

        private fun joinArray(node: JsonNode): String? =
            if (node.isArray) node.joinToString(",") { it.asString() } else node.asString()

        /**
         * Return a copy of the create response with `clientSecret` removed so the
         * record/JSON/YAML views never carry the one-shot secret — it is emitted
         * separately via [SecretIo].
         */
        internal fun stripSecret(node: JsonNode): JsonNode {
            if (node.isObject) (node as tools.jackson.databind.node.ObjectNode).remove("clientSecret")
            return node
        }

        internal fun stripNewSecret(node: JsonNode): JsonNode {
            if (node.isObject) (node as tools.jackson.databind.node.ObjectNode).remove("newSecret")
            return node
        }
    }
}
