package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.io.File
import java.util.concurrent.Callable

/**
 * `thoryn workspace email-provider ...` (SSO-2917, epic SSO-2906) — the tenant's
 * bring-your-own SMTP transport config, a thin wrapper over product-api's
 * `/api/v1/email-provider` surface (PR #3448) reached through the api-gateway.
 *
 * Configuring a BYO-SMTP provider makes the tenant's transactional mail (invitations,
 * password resets, verifications) leave the tenant's own domain rather than the platform
 * sender. This is per-workspace configuration, so it lives under the `workspace` command
 * group — but unlike the hub-routed `workspace` subcommands it is tenant-scoped and
 * GATEWAY-routed (product-api enforces the `tnt` claim), so each subcommand builds a
 * [CommandSupport.gatewayClient] (honouring an active `workspace switch`).
 *
 * **Secret-safety (hard requirement, epic SSO-1545).** The SMTP password is an INPUT the
 * operator supplies. It is read via a no-echo terminal prompt (`--prompt-password`) or a
 * `--smtp-password-file` ([SecretIo.readSecretInput]) — there is deliberately NO
 * `--smtp-password <value>` flag, because a secret in argv lands in shell history and the
 * process table. The password is WRITE-ONLY end to end: the response never carries it back
 * (product-api's read view exposes only `hasPassword`), so there is nothing secret to emit.
 *
 * Subcommands:
 *  - `get`   — GET    /api/v1/email-provider  (renders `hasPassword`, never a value)
 *  - `set`   — PUT    /api/v1/email-provider  (merge-upsert; only supplied fields change)
 *  - `reset` — DELETE /api/v1/email-provider  (reset to the platform sender)
 *
 * Scopes: `get` → `tenant:email.read`; `set` / `reset` → `tenant:email.write` (granted to
 * `thoryn-cli` by hub V149; request them with `thoryn login --scope all-tenant-config`).
 */
@Command(
    name = "email-provider",
    description = ["Configure your workspace's bring-your-own SMTP email provider."],
    mixinStandardHelpOptions = true,
    subcommands = [
        EmailProviderCommand.GetSubcommand::class,
        EmailProviderCommand.SetSubcommand::class,
        EmailProviderCommand.VerifySubcommand::class,
        EmailProviderCommand.ResetSubcommand::class,
    ],
)
class EmailProviderCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn workspace email-provider <subcommand>")
        System.err.println("Subcommands: get | set | verify | reset")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn workspace email-provider get` */
    @Command(name = "get", description = ["Show the workspace's configured email provider (never the password)."], mixinStandardHelpOptions = true)
    class GetSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.getEmailProvider()
                CommandSupport.emitRecord(format, body, ::providerRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:email.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn workspace email-provider set [--smtp-host ...] [--enabled true|false] ...`
     *
     * Merge-upsert: only the fields you pass change; omitted fields keep their stored value.
     * The SMTP password is supplied WITHOUT touching argv — `--prompt-password` (no-echo
     * prompt) or `--smtp-password-file <path>`. `--clear-password` sends a blank value to
     * remove the stored ciphertext. When none of those is passed the password is left
     * unchanged.
     */
    @Command(name = "set", description = ["Configure (merge-upsert) the workspace's SMTP email provider."], mixinStandardHelpOptions = true)
    class SetSubcommand : Callable<Int> {

        @Option(names = ["--provider-type"], description = ["Provider type token (today only byo_smtp)."])
        var providerType: String? = null

        @Option(names = ["--enabled"], description = ["Activate (true) or deactivate (false) the BYO-SMTP transport."], arity = "1")
        var enabled: Boolean? = null

        @Option(names = ["--smtp-host"], description = ["SMTP server hostname."])
        var smtpHost: String? = null

        @Option(names = ["--smtp-port"], description = ["SMTP server port."])
        var smtpPort: Int? = null

        @Option(names = ["--smtp-username"], description = ["SMTP auth username."])
        var smtpUsername: String? = null

        @Option(names = ["--prompt-password"], description = ["Prompt (no echo) for the SMTP password. Mutually exclusive with --smtp-password-file / --clear-password."])
        var promptPassword: Boolean = false

        @Option(names = ["--smtp-password-file"], description = ["Read the SMTP password from this file (avoids exposing it on the command line)."])
        var smtpPasswordFile: File? = null

        @Option(names = ["--clear-password"], description = ["Clear the stored SMTP password (sends a blank value)."])
        var clearPassword: Boolean = false

        @Option(names = ["--transport-security"], description = ["Transport security token: starttls (default), ssl, or none."])
        var transportSecurity: String? = null

        @Option(
            names = ["--allow-insecure"],
            description = ["Acknowledge plaintext SMTP. REQUIRED together with --transport-security none, which sends mail without transport security."],
        )
        var allowInsecure: Boolean = false

        @Option(names = ["--from-address"], description = ["From: address for outbound mail."])
        var fromAddress: String? = null

        @Option(names = ["--from-name"], description = ["From: display name for outbound mail."])
        var fromName: String? = null

        @Option(names = ["--reply-to"], description = ["Reply-To: address for outbound mail."])
        var replyTo: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE

            // SSO-2921: plaintext SMTP (--transport-security none) is opt-in. Fail before any
            // network call unless the operator explicitly acknowledges with --allow-insecure.
            if (transportSecurity?.trim()?.equals("none", ignoreCase = true) == true && !allowInsecure) {
                System.err.println(
                    "Error: --transport-security none sends mail in plaintext. " +
                        "Re-run with --allow-insecure to acknowledge, or choose starttls / ssl.",
                )
                return CommandSupport.EXIT_USAGE
            }

            // Resolve the write-only SMTP password without it ever appearing in argv.
            val passwordSources = listOf(promptPassword, smtpPasswordFile != null, clearPassword).count { it }
            if (passwordSources > 1) {
                System.err.println("Error: pass at most one of --prompt-password, --smtp-password-file, --clear-password.")
                return CommandSupport.EXIT_USAGE
            }
            val smtpPassword: String? = when {
                clearPassword -> ""
                promptPassword || smtpPasswordFile != null ->
                    SecretIo.readSecretInput(
                        secretFile = smtpPasswordFile,
                        prompt = "SMTP password: ",
                    ) ?: return SecretIo.EXIT_NO_SECRET
                else -> null // leave the stored value unchanged
            }

            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)

            // Merge-upsert: send ONLY the fields the operator supplied (null ⇒ keep stored value).
            val body = linkedMapOf<String, Any?>()
            providerType?.let { body["providerType"] = it }
            enabled?.let { body["enabled"] = it }
            smtpHost?.let { body["smtpHost"] = it }
            smtpPort?.let { body["smtpPort"] = it }
            smtpUsername?.let { body["smtpUsername"] = it }
            smtpPassword?.let { body["smtpPassword"] = it }
            transportSecurity?.let { body["transportSecurity"] = it }
            // Only send the acknowledgement when the operator asked for it (merge-upsert;
            // omitted ⇒ identity keeps the stored acknowledgement).
            if (allowInsecure) body["allowInsecureTransport"] = true
            fromAddress?.let { body["fromAddress"] = it }
            fromName?.let { body["fromName"] = it }
            replyTo?.let { body["replyTo"] = it }

            return try {
                val response = client.putEmailProvider(body)
                CommandSupport.emitRecord(format, response, ::providerRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:email.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn workspace email-provider verify [--to <address>]` (SSO-2923) — dial the
     * configured BYO-SMTP transport and report whether it works, so a mistyped relay is caught
     * before a real password-reset or invitation depends on it.
     *
     * Without `--to` it runs a connect/handshake+auth probe (no mail is sent). With `--to
     * <address>` it sends a real test message to that address through YOUR OWN SMTP server. The
     * exit code is 0 when the transport verifies, and non-zero ([CommandSupport.EXIT_CHECK_FAILED])
     * when it does not — so `thoryn ... verify && ...` gates on a working transport.
     */
    @Command(name = "verify", description = ["Verify the workspace's configured BYO-SMTP transport (optionally send a test email)."], mixinStandardHelpOptions = true)
    class VerifySubcommand : Callable<Int> {

        @Option(names = ["--to"], description = ["Send a real test email to this address (through your own SMTP server). Omit for a connect-only check."])
        var to: String? = null

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.verifyEmailProvider(to?.trim()?.ifBlank { null })
                val success = body["success"]?.asBoolean() ?: false
                val reason = body["reason"]?.takeUnless { it.isNull }?.asString()
                val outcome = body["outcome"]?.asString() ?: "unknown"
                val tableLine = if (success) {
                    "OK: the configured BYO-SMTP transport verified successfully (outcome=$outcome)."
                } else {
                    "FAILED: ${reason ?: "the BYO-SMTP transport did not verify."} (outcome=$outcome)"
                }
                CommandSupport.emitValue(format, body, tableLine)
                if (success) CommandSupport.EXIT_OK else CommandSupport.EXIT_CHECK_FAILED
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:email.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn workspace email-provider reset` — reset to the platform sender (DELETE). */
    @Command(name = "reset", description = ["Reset the workspace to the platform email sender (removes the BYO-SMTP config)."], mixinStandardHelpOptions = true)
    class ResetSubcommand : Callable<Int> {

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
                client.deleteEmailProvider(confirm)
                CommandSupport.emitValue(
                    format,
                    mapOf("reset" to true),
                    "Email provider reset to the platform sender.",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:email.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        /**
         * Record fields for the `EmailProviderResponse`. The password is NEVER rendered —
         * the response carries only `hasPassword` (write-only credential custody), which is
         * surfaced here so the operator can see whether a password is stored.
         */
        internal fun providerRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "providerType" to node["providerType"]?.asString(),
            "enabled" to node["enabled"]?.asString(),
            "configured" to node["configured"]?.asString(),
            "smtpHost" to node["smtpHost"]?.asString(),
            "smtpPort" to node["smtpPort"]?.asString(),
            "smtpUsername" to node["smtpUsername"]?.asString(),
            "hasPassword" to node["hasPassword"]?.asString(),
            "transportSecurity" to node["transportSecurity"]?.asString(),
            "insecureTransportAcknowledged" to node["insecureTransportAcknowledged"]?.asString(),
            "fromAddress" to node["fromAddress"]?.asString(),
            "fromName" to node["fromName"]?.asString(),
            "replyTo" to node["replyTo"]?.asString(),
            "supportedProviderTypes" to node["supportedProviderTypes"]?.toString(),
            "supportedTransportSecurity" to node["supportedTransportSecurity"]?.toString(),
            "configVersion" to node["configVersion"]?.asString(),
            "updatedAt" to node["updatedAt"]?.asString(),
        )
    }
}
