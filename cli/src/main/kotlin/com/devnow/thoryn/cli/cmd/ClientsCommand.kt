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
 *  - `rotate-secret` — POST /api/v1/applications/{clientId}/secret/rotate (`--replace` sends
 *    `replaceInFlight: true`, SSO-3967 — replace a lost new secret inside the overlap window)
 *  - `revoke-previous-secret` — POST /api/v1/applications/{clientId}/secret/revoke-previous
 *    (SSO-3967; end the previous secret now — see [RevokePreviousSecretSubcommand])
 *  - `secret-state`  — GET  /api/v1/applications/{clientId}/secrets/state (SSO-3957; the rotation
 *    state in plain words — see [SecretStateSubcommand])
 *  - `delete`        — DELETE /api/v1/applications/{clientId}
 *  - `registration-token` — POST /api/v1/applications/registration-tokens (SSO-3683; the
 *    Initial Access Token emitted via SecretIo — see [RegistrationTokenSubcommand])
 *
 * Scopes: GET (incl. `secret-state`) → `tenant:applications.read`; create/update/rotate/
 * revoke-previous-secret/delete/registration-token → `tenant:applications.write`.
 *
 * **Elevated acts (SSO-3967, product-api SSO-3956).** `revoke-previous-secret` and
 * `rotate-secret --replace` are incident-response acts the server grants only to a PERSON whose
 * sign-in used a passkey within the last five minutes (RFC 9470 step-up). The CLI renders the two
 * refusals in words: `403 insufficient_user_authentication` → the exact `thoryn login --acr-values …
 * --max-age …` to run and retry; `403 elevated_action_requires_person` → a machine identity cannot
 * do this, a workspace admin must. See [renderElevatedActError].
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
        ClientsCommand.RevokePreviousSecretSubcommand::class,
        ClientsCommand.SecretStateSubcommand::class,
        ClientsCommand.DeleteSubcommand::class,
        ClientsCommand.RegistrationTokenSubcommand::class,
    ],
)
class ClientsCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn clients <subcommand>")
        System.err.println(
            "Subcommands: list | get | create | update | rotate-secret | revoke-previous-secret | secret-state | delete | registration-token",
        )
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
     * `secret-state` — that the previous secret keeps working until then, and the two commands that
     * end the window early. Exit code stays [CommandSupport.EXIT_HTTP_ERROR]: the server refused the
     * call, which is what that code has always meant to scripts.
     *
     * **`--replace` (SSO-3967; product-api SSO-3956).** Inside an open window, when the NEW secret was
     * lost before it reached the deployment, `--replace` sends `replaceInFlight: true`: the server mints
     * a replacement, the superseded in-flight secret stops working at once, and the previous secret
     * keeps its original expiry (so there are never three valid secrets). The secret output path is
     * the same [SecretIo] one. It is an elevated act — see [renderElevatedActError].
     */
    @Command(
        name = "rotate-secret",
        description = [
            "Rotate a client's secret. The new secret is shown once; the old one stays valid for 24h. " +
                "While that window is open a second rotation is refused (409) and the command says from when " +
                "it is allowed again — see `thoryn clients secret-state`. To replace a new secret that was lost " +
                "inside the window, add --replace (needs a passkey sign-in from the last 5 minutes).",
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

        @Option(
            names = ["--replace"],
            description = [
                "Replace a rotation that is in flight (for example a new secret that was lost): the superseded " +
                    "secret stops working at once; the previous one keeps its expiry.",
            ],
        )
        var replace: Boolean = false

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
                val response = client.rotateApplicationSecret(clientId, confirm, replaceInFlight = replace)
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
                // SSO-3967 — only `--replace` is an elevated act; the two 403s below never come without it.
                renderElevatedActError(format, ex, requiredScope = "tenant:applications.write", act = ACT_REPLACE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn clients revoke-previous-secret <clientId> [--revoke-tokens] [--confirm <workspace-slug>]`
     *
     * SSO-3967 (product-api SSO-3956) — end the PREVIOUS secret of a rotation in flight now, instead
     * of at the end of its 24 h overlap window: the incident response to a leaked previous secret.
     * `POST /api/v1/applications/{clientId}/secret/revoke-previous`, body `{ "revokeTokens": <bool> }`.
     * Idempotent — with nothing in flight the server answers `200` with `previousSecretRevoked: false`
     * and the command says nothing changed. `--revoke-tokens` also revokes the client's live
     * authorizations (refresh tokens, stored reference tokens, device codes); self-contained access
     * tokens already issued verify by signature until they expire, and the output says so.
     *
     * The table output is plain words (what no longer works, what still does); `--output json|yaml`
     * is the server body as it arrived (`previousSecretId`, `previousSecretRevoked`, `tokensRevoked`,
     * `revokedAuthorizations`, `rotationAvailable`). After a revoke the next rotation is available at
     * once (`rotationAvailable: true`).
     *
     * Destructive on the production plane: `--confirm <workspace-slug>` as `delete` / `rotate-secret`
     * (`428 production_confirmation_required` without it). An elevated act — see
     * [renderElevatedActError]. Scope `tenant:applications.write`.
     */
    @Command(
        name = "revoke-previous-secret",
        description = [
            "End the previous secret of a rotation in flight NOW (for example after it leaked) instead of at the end " +
                "of its 24h window. Only the current secret signs in afterwards; the next rotation is allowed at once. " +
                "Needs a passkey sign-in from the last 5 minutes. Idempotent when nothing is in flight.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RevokePreviousSecretSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Client ID."])
        lateinit var clientId: String

        @Option(
            names = ["--revoke-tokens"],
            description = [
                "Also revoke this client's live sessions/tokens (refresh tokens, stored reference tokens, device codes). " +
                    "Self-contained access tokens already issued stay valid until they expire.",
            ],
        )
        var revokeTokens: Boolean = false

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

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
                val body = client.revokePreviousApplicationSecret(clientId, confirm, revokeTokens = revokeTokens)
                when (format) {
                    OutputFormat.JSON -> Printers.json(body)
                    OutputFormat.YAML -> Printers.yaml(body)
                    OutputFormat.TABLE -> revokePreviousSecretSummary(body).forEach(::println)
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderElevatedActError(format, ex, requiredScope = "tenant:applications.write", act = ACT_REVOKE_PREVIOUS)
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
                if (format == OutputFormat.TABLE) println(secretStateSummary(body, clientId = clientId))
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
         * SSO-3967 — the two ways out of an open overlap window, named with the client at hand: end the
         * previous secret now (it leaked), or replace a new secret that was lost before it reached the
         * deployment. Printed on `409 rotation_in_flight` and under an in-flight `secret-state`.
         * (Replaces the SSO-3957 README pointer that stood here while the server side was being built.)
         */
        internal fun rotationIncidentPathHint(clientId: String): String =
            "To end the previous secret now: `thoryn clients revoke-previous-secret $clientId`. " +
                "To replace a lost new secret: `thoryn clients rotate-secret $clientId --replace`."

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
         * allowed again (the hub sets both from the same overlap row). While a rotation is in flight
         * and a [clientId] is known, a second line names the two commands that end the window early.
         */
        internal fun secretStateSummary(node: JsonNode, now: Instant = Instant.now(), clientId: String? = null): String {
            val available = node["rotationAvailable"]?.takeIf { !it.isNull }?.asBoolean()
            val until = Timestamps.render(node["previousExpiresAt"], now)
                ?: Timestamps.render(node["rotationAvailableAt"], now)
            val reading = when {
                available == true ->
                    "No rotation is in flight: only the current secret works, and you can rotate now."
                available == false && until != null ->
                    "A rotation is in flight: the previous secret keeps working until $until. " +
                        "The next rotation is allowed from then."
                available == false ->
                    "A rotation is in flight: the previous secret still works and a new rotation is not allowed yet."
                else -> "The server did not say whether a rotation is allowed."
            }
            return if (available == false && clientId != null) "$reading\n${rotationIncidentPathHint(clientId)}" else reading
        }

        // ── SSO-3967: the two incident-response acts ────────────────────────────────────────────────

        /** What the act is called in the step-up / person-only guidance. */
        internal const val ACT_REVOKE_PREVIOUS: String = "Ending the previous secret now"
        internal const val ACT_REPLACE: String = "Replacing a rotation in flight"

        /**
         * The `revoke-previous-secret` table output, in plain words and from the server's booleans — never
         * from what the caller asked for: `--revoke-tokens` is reported only when the server says it did.
         */
        internal fun revokePreviousSecretSummary(node: JsonNode): List<String> {
            val lines = mutableListOf<String>()
            val revoked = node["previousSecretRevoked"]?.takeIf { !it.isNull }?.asBoolean()
            lines += when (revoked) {
                true -> "The previous secret no longer works. Only the current secret signs in."
                false -> "There was no previous secret; nothing changed."
                null -> "The server did not say whether a previous secret was revoked."
            }
            if (node["tokensRevoked"]?.takeIf { !it.isNull }?.asBoolean() == true) {
                val n = node["revokedAuthorizations"]?.takeIf { !it.isNull }?.asInt() ?: 0
                lines += "$n live sessions/tokens of this client were revoked (self-contained access tokens already " +
                    "issued stay valid until they expire)."
            }
            return lines
        }

        /**
         * Error rendering for the two elevated acts, on top of [CommandSupport.renderError]. The server
         * grants them only to a PERSON with a passkey sign-in from the last five minutes (RFC 9470):
         *
         *  - `403 insufficient_user_authentication` (recognised by its `WWW-Authenticate` challenge) — the
         *    same guidance `thoryn workload-identity trusts set-scopes` prints: what [act] needs, then the
         *    exact `thoryn login --acr-values <acr> --max-age <s>` to run, then retry. The challenge's own
         *    `acr_values` / `max_age` are used when it carries them.
         *  - `403 elevated_action_requires_person` — a machine identity (API key, workload identity) cannot
         *    do this; a workspace admin must, signed in with a passkey.
         *
         * Neither is a missing CALLER scope, so neither gets the `thoryn login --scope` line
         * ([ProductApiException.isInsufficientScope] would otherwise claim the person-only 403). Every
         * other refusal keeps [CommandSupport.renderError] with [requiredScope].
         */
        internal fun renderElevatedActError(
            format: OutputFormat,
            ex: ProductApiException,
            requiredScope: String,
            act: String,
            err: PrintStream = System.err,
        ): Int {
            if (ex.isStepUpRequired) {
                val exit = CommandSupport.renderError(format, ex, requiredScope = null, err = err)
                if (format == OutputFormat.TABLE) {
                    val acr = ex.stepUpAcrValues ?: WorkloadIdentityCommand.PASSKEY_ACR
                    val maxAge = ex.stepUpMaxAge ?: 300
                    err.println("$act needs a passkey sign-in from the last ${maxAge / 60} minutes. Sign in again, then retry:")
                    err.println("  thoryn login --acr-values $acr --max-age $maxAge")
                }
                return exit
            }
            if (ex.errorCode == ERROR_CODE_ELEVATED_ACTION_REQUIRES_PERSON) {
                val exit = CommandSupport.renderError(format, ex, requiredScope = null, err = err)
                if (format == OutputFormat.TABLE) {
                    err.println(
                        "$act is a person's act: a machine identity (API key, workload identity) cannot do this. " +
                            "A workspace admin must run it, signed in with a passkey " +
                            "(thoryn login --acr-values ${WorkloadIdentityCommand.PASSKEY_ACR} --max-age 300).",
                    )
                }
                return exit
            }
            return CommandSupport.renderError(format, ex, requiredScope = requiredScope, err = err)
        }

        /** RFC 9457 `errorCode` product-api emits (403) when a machine token attempts an elevated act. */
        internal const val ERROR_CODE_ELEVATED_ACTION_REQUIRES_PERSON: String = "elevated_action_requires_person"

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
                "hint" to "$whenLine ${rotationIncidentPathHint(clientId)}",
            )
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, out)
                OutputFormat.YAML -> Printers.yaml(structured, out)
                OutputFormat.TABLE -> {
                    val description = ex.errorDescription?.let { " — $it" } ?: ""
                    err.println("Error: $ERROR_CODE_ROTATION_IN_FLIGHT$description")
                    err.println(whenLine)
                    err.println(rotationIncidentPathHint(clientId))
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
