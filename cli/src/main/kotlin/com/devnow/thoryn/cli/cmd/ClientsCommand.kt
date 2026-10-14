package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.File
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
 *  - `delete`        — DELETE /api/v1/applications/{clientId}
 *  - `registration-token` — POST /api/v1/applications/registration-tokens (SSO-3683; the
 *    Initial Access Token emitted via SecretIo — see [RegistrationTokenSubcommand])
 *
 * Scopes: GET → `tenant:applications.read`; create/update/rotate/delete/registration-token →
 * `tenant:applications.write`.
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
        ClientsCommand.DeleteSubcommand::class,
        ClientsCommand.RegistrationTokenSubcommand::class,
    ],
)
class ClientsCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn clients <subcommand>")
        System.err.println("Subcommands: list | get | create | update | rotate-secret | delete | registration-token")
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
     */
    @Command(name = "rotate-secret", description = ["Rotate a client's secret. The new secret is shown once; the old one stays valid for 24h."], mixinStandardHelpOptions = true)
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
                CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
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
