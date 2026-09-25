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
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn domain …` (SSO-3303, epic SSO-3290) — your workspace's ONE custom domain (`auth.acme.com`),
 * a thin wrapper over product-api's `/api/v1/custom-domain` surface (oathy SSO-3303) reached through
 * the api-gateway.
 *
 * A custom domain moves the workspace's whole sign-in surface — and its token issuer — onto a host
 * you own. You claim the host, create the two DNS records the claim returns (a TXT ownership record
 * and a CNAME to the workspace's platform host), verify, and watch it move PENDING → VERIFIED →
 * ACTIVE. The workspace is always the one you are signed in to (the token's `tnt`); there is no
 * workspace argument.
 *
 * Subcommands:
 *  - `add <host> [--accept-re-sign-in]` — PUT    /api/v1/custom-domain
 *  - `status`                           — GET    /api/v1/custom-domain
 *  - `verify`                           — POST   /api/v1/custom-domain/verify
 *  - `remove [--yes]`                   — DELETE /api/v1/custom-domain (confirmation prompt)
 *
 * Scopes: `status` → `tenant:domains.read`; `add` / `verify` / `remove` → `tenant:domains.write`
 * (granted to the CLI's login clients by oathy hub V181; part of the default `thoryn login` set). Only
 * workspace admins can change the domain; for anyone else the API answers 404. Every subcommand
 * takes `--output json|yaml|table` (and `--json` as a shorthand for `--output json`).
 */
@Command(
    name = "domain",
    description = ["Manage your workspace's custom domain (for example auth.acme.com)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        DomainCommand.AddSubcommand::class,
        DomainCommand.StatusSubcommand::class,
        DomainCommand.VerifySubcommand::class,
        DomainCommand.RemoveSubcommand::class,
    ],
)
class DomainCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn domain <subcommand>")
        System.err.println("Subcommands: add | status | verify | remove")
        return CommandSupport.EXIT_USAGE
    }

    /** Options every `domain` subcommand shares. */
    abstract class Base : Callable<Int> {
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
            val precheck = precheck()
            if (precheck != null) return precheck
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                run(client, format)
            } catch (ex: ProductApiException) {
                renderDomainError(format, ex, requiredScope)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** Local validation before any network call; a non-null exit code stops the command. */
        open fun precheck(): Int? = null

        abstract fun run(client: ProductApiClient, format: OutputFormat): Int
    }

    /** `thoryn domain add <host> [--accept-re-sign-in]` */
    @Command(
        name = "add",
        description = [
            "Claim a custom domain for the workspace and print the DNS records to create.",
            "Use a subdomain you control (auth.<your-domain>); apex domains are refused.",
        ],
        mixinStandardHelpOptions = true,
    )
    class AddSubcommand : Base() {

        @Parameters(index = "0", paramLabel = "<host>", description = ["The host to claim, e.g. auth.acme.com."])
        lateinit var host: String

        @Option(
            names = ["--accept-re-sign-in"],
            description = [
                "Required when the workspace already has production users: accept that the issuer changes and every",
                "production user signs in again once. Recorded on the claim and in the audit log.",
            ],
        )
        var acceptReSignIn: Boolean = false

        override val requiredScope: String = SCOPE_WRITE

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.putCustomDomain(host.trim(), acceptReSignIn)
            when (format) {
                OutputFormat.TABLE -> {
                    val out = System.out
                    out.println("Custom domain ${text(body, "domain")} claimed (state: ${text(body, "state")}).")
                    printNextSteps(body, out)
                }
                else -> CommandSupport.emitRecord(format, body, ::domainRecordFields)
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn domain status` */
    @Command(name = "status", description = ["Show the workspace's custom domain, its DNS records and verification state."], mixinStandardHelpOptions = true)
    class StatusSubcommand : Base() {
        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.getCustomDomain()
            when (format) {
                OutputFormat.TABLE -> {
                    val out = System.out
                    if (text(body, "state") == STATE_NONE) {
                        out.println("This workspace has no custom domain.")
                        if (body["entitled"]?.asBoolean() == true) {
                            out.println("Claim one with: thoryn domain add <host>   (for example auth.acme.com)")
                        } else {
                            out.println(NOT_ENTITLED_HINT)
                        }
                        return CommandSupport.EXIT_OK
                    }
                    Printers.record(domainRecordFields(body), out)
                    out.println()
                    printRecords(body, out)
                    out.println()
                    out.println(explain(body))
                }
                else -> CommandSupport.emitRecord(format, body, ::domainRecordFields)
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn domain verify` — exit 0 when verified, [CommandSupport.EXIT_CHECK_FAILED] when the DNS does not prove it yet. */
    @Command(name = "verify", description = ["Check the domain's DNS records now."], mixinStandardHelpOptions = true)
    class VerifySubcommand : Base() {
        override val requiredScope: String = SCOPE_WRITE

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.verifyCustomDomain()
            when (format) {
                OutputFormat.TABLE -> {
                    System.out.println("Verified: ${text(body, "domain")} is ${text(body, "state")}.")
                    System.out.println(explain(body))
                }
                else -> CommandSupport.emitRecord(format, body, ::domainRecordFields)
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn domain remove [--yes]` */
    @Command(name = "remove", description = ["Remove the workspace's custom domain (asks for confirmation)."], mixinStandardHelpOptions = true)
    class RemoveSubcommand : Base() {

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        override val requiredScope: String = SCOPE_WRITE

        override fun precheck(): Int? {
            if (yes) return null
            val confirmed = Prompt.confirm(
                "Remove the workspace's custom domain? If it is ACTIVE, the workspace's issuer moves back to its " +
                    "platform host and every user signs in again.",
            )
            if (confirmed) return null
            System.err.println(
                if (Prompt.interactive()) "Aborted." else "Refusing to remove without confirmation; re-run with --yes.",
            )
            return CommandSupport.EXIT_USAGE
        }

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            client.deleteCustomDomain()
            CommandSupport.emitValue(format, mapOf("removed" to true), "Custom domain removed.")
            return CommandSupport.EXIT_OK
        }
    }

    companion object {
        const val SCOPE_READ: String = "tenant:domains.read"
        const val SCOPE_WRITE: String = "tenant:domains.write"
        const val STATE_NONE: String = "NONE"

        private const val NOT_ENTITLED_HINT: String =
            "Custom domains are not enabled for this workspace. Contact Thoryn to enable them."

        private fun text(node: JsonNode, field: String): String? =
            node[field]?.takeUnless { it.isNull }?.asString()

        /** The key/value view used by `status` and by `--output yaml|table` of the other subcommands. */
        fun domainRecordFields(body: JsonNode): List<Pair<String, Any?>> {
            val last = body["lastVerification"]?.takeUnless { it.isNull }
            val suspension = body["suspension"]?.takeUnless { it.isNull }
            return listOf(
                "domain" to text(body, "domain"),
                "state" to text(body, "state"),
                "entitled" to body["entitled"]?.asBoolean(),
                "issuer" to text(body, "issuer"),
                "customIssuer" to text(body, "customIssuer"),
                "certificate" to text(body, "certificateState"),
                "cnameTarget" to text(body, "cnameTarget"),
                "claimedAt" to text(body, "claimedAt"),
                "expiresAt" to text(body, "expiresAt"),
                "verifiedAt" to text(body, "verifiedAt"),
                "lastCheck" to last?.let { listOfNotNull(text(it, "result"), text(it, "reason"), text(it, "checkedAt")).joinToString(" · ") },
                "suspended" to suspension?.let { listOfNotNull(text(it, "reason"), text(it, "suspendedAt")).joinToString(" · ") },
                "reSignInAccepted" to body["reSignInAccepted"]?.asBoolean(),
            ).filter { it.second != null }
        }

        /** The DNS records, as a table the admin can copy from. */
        fun printRecords(body: JsonNode, out: PrintStream) {
            val records = body["dnsRecords"]?.takeIf { it.isArray }?.toList().orEmpty()
            if (records.isEmpty()) return
            out.println("DNS records to create at your DNS provider:")
            Printers.table(
                listOf("TYPE", "NAME", "VALUE"),
                records.map { listOf(text(it, "type"), text(it, "name"), text(it, "value")) },
                out,
            )
        }

        private fun printNextSteps(body: JsonNode, out: PrintStream) {
            out.println()
            printRecords(body, out)
            out.println()
            out.println("The CNAME must point directly at ${text(body, "cnameTarget")} (turn off any CDN proxy for it).")
            out.println("Then run: thoryn domain verify   (pending claims are also re-checked every 15 minutes)")
            text(body, "expiresAt")?.let { out.println("The claim expires at $it if it is not verified.") }
        }

        /** One human sentence per state — "it didn't work" with no detail is what this avoids. */
        fun explain(body: JsonNode): String {
            val reason = body["lastVerification"]?.takeUnless { it.isNull }?.let { text(it, "reason") }
            return when (text(body, "state")) {
                "PENDING" -> if (reason == null) {
                    "Waiting for the DNS records above. Create them, then run: thoryn domain verify"
                } else {
                    "DNS does not prove the claim yet: ${reasonText(reason)}"
                }
                "VERIFIED" -> "Ownership and routing are proven. The certificate is being issued (certificate: " +
                    "${text(body, "certificateState")}); the workspace keeps issuing on ${text(body, "issuer")} until the domain is ACTIVE."
                "ACTIVE" -> "Live: the workspace issues on ${text(body, "issuer")}. Relying parties must use this issuer."
                "SUSPENDED" -> "Suspended — a daily re-check failed: ${reasonText(reason)} Restore the record; " +
                    "the domain returns to VERIFIED when it verifies again (thoryn domain verify)."
                else -> "State: ${text(body, "state")}"
            }
        }

        fun reasonText(reason: String?): String = when (reason) {
            "txt_record_missing" -> "the TXT ownership record is missing or carries another value."
            "cname_missing" -> "the domain has no CNAME record."
            "cname_mismatch" -> "the CNAME points somewhere other than the workspace's platform host."
            null -> "no reason reported."
            else -> "$reason."
        }

        /**
         * Error rendering with domain-specific guidance on top of [CommandSupport.renderError]. A `403
         * entitlement_required` is NOT a scope problem, so it gets its own hint instead of the
         * `thoryn login --scope` one; a failing DNS proof exits [CommandSupport.EXIT_CHECK_FAILED] so a
         * script can poll `verify` until it succeeds.
         */
        fun renderDomainError(format: OutputFormat, ex: ProductApiException, requiredScope: String): Int {
            val hint = when (ex.errorCode) {
                "entitlement_required" -> NOT_ENTITLED_HINT
                "production_users_present" ->
                    "Re-run with --accept-re-sign-in to accept that every production user signs in again once."
                "domain_not_allowed" -> "Use a subdomain you control, for example auth.<your-domain>."
                "verification_failed" -> "Check the records with `thoryn domain status`; DNS changes can take a while to propagate."
                "claim_expired" -> "Claim the domain again (thoryn domain add <host>) and publish the new TXT value."
                "custom_domain_exists" -> "Remove the current domain first: thoryn domain remove"
                "custom_domain_not_found" ->
                    "The workspace has no custom domain, or your account is not an admin of this workspace."
                "dns_unavailable" -> "Nothing changed; try again in a moment."
                else -> null
            }
            val exit = if (ex.errorCode == "entitlement_required") {
                CommandSupport.renderError(format, ex, requiredScope = null)
            } else {
                CommandSupport.renderError(format, ex, requiredScope = requiredScope)
            }
            if (hint != null && format == OutputFormat.TABLE) System.err.println(hint)
            return if (ex.errorCode == "verification_failed") CommandSupport.EXIT_CHECK_FAILED else exit
        }
    }
}
