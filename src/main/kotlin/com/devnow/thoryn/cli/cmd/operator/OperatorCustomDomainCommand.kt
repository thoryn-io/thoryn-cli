package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.api.OperatorHubClient
import com.devnow.thoryn.cli.api.OperatorHubException
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.DpopSession
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.DomainCommand
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.net.ConnectException
import java.net.http.HttpConnectTimeoutException
import java.util.concurrent.Callable

/**
 * `thoryn operator custom-domain …` (SSO-3356) — the operator half of a workspace's custom domain:
 * turning the feature on or off for a workspace (the per-workspace ENTITLEMENT, off by default) and
 * reading its state. Everything after the entitlement — claim, verify, remove — the workspace's own
 * admins do with `thoryn domain …`.
 *
 * Calls the hub's operator surface directly (oathy `TenantController`, ADR 2026-09-25 §6 as amended
 * 2026-09-26):
 *
 *  - `entitle <workspace>` — `PUT /admin/tenants/{slug}/custom-domain/entitlement {"entitled": true}`
 *  - `revoke <workspace>`  — the same with `false` (does NOT remove an existing domain)
 *  - `status <workspace>`  — `GET /admin/tenants/{slug}/custom-domain`
 *
 * Each needs the operator session (`thoryn operator login`, passkey) and the port-forward to the hub
 * (`--hub-url`, default `http://localhost:18080`). The hub re-checks operator standing and the passkey
 * on every call and audits the entitlement change on the workspace's own trail with the operator's
 * subject as the actor.
 */
@Command(
    name = "custom-domain",
    description = ["Enable or disable custom domains for a workspace, and read its custom-domain state (operator plane)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        OperatorCustomDomainCommand.EntitleSubcommand::class,
        OperatorCustomDomainCommand.RevokeSubcommand::class,
        OperatorCustomDomainCommand.StatusSubcommand::class,
    ],
)
class OperatorCustomDomainCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn operator custom-domain <subcommand> <workspace>")
        System.err.println("Subcommands: entitle | revoke | status")
        return CommandSupport.EXIT_USAGE
    }

    abstract class Base : Callable<Int> {
        @Parameters(index = "0", paramLabel = "<workspace>", description = ["The workspace slug."])
        lateinit var workspace: String

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

        /** The operator scope this call needs, for the refusal hint. */
        abstract val requiredScope: String

        abstract fun run(client: OperatorHubClient, slug: String, format: OutputFormat, out: PrintStream): Int

        override fun call(): Int {
            val err = System.err
            if (json && outputRaw != null && !outputRaw.equals("json", ignoreCase = true)) {
                err.println("Error: --json cannot be combined with --output $outputRaw.")
                return CommandSupport.EXIT_USAGE
            }
            val format = CommandSupport.parseFormat(if (json) "json" else outputRaw) ?: return CommandSupport.EXIT_USAGE
            val slug = workspace.trim()
            if (slug.isEmpty()) {
                err.println("Error: name the workspace, e.g. `thoryn operator custom-domain status acme`.")
                return CommandSupport.EXIT_USAGE
            }
            OperatorHubTarget.refusal(hubUrl)?.let {
                err.println("Error: $it")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = OperatorSession.readUsable(err) ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = clientFactory(hubUrl.trim().trimEnd('/'), tokens)
            return try {
                run(client, slug, format, System.out)
            } catch (ex: OperatorHubException) {
                renderError(ex, slug, requiredScope, format, System.out, err)
            } catch (ex: Exception) {
                renderUnreachable(ex, hubUrl, err)
            }
        }
    }

    @Command(
        name = "entitle",
        description = [
            "Turn custom domains ON for a workspace. Its admins can then claim a domain with `thoryn domain add`.",
            "Audited on the workspace's trail as custom_domain.entitlement_granted.",
        ],
        mixinStandardHelpOptions = true,
    )
    class EntitleSubcommand : Base() {
        override val requiredScope: String = OperatorSession.SCOPE_CUSTOM_DOMAINS_MANAGE

        override fun run(client: OperatorHubClient, slug: String, format: OutputFormat, out: PrintStream): Int {
            val body = client.setCustomDomainEntitlement(slug, entitled = true)
            CommandSupport.emitValue(
                format,
                body,
                "Custom domains ENABLED for workspace '$slug' (entitled: ${body["entitled"]?.asBoolean()}). " +
                    "Its admins can now run `thoryn domain add <host>`.",
                out,
            )
            return CommandSupport.EXIT_OK
        }
    }

    @Command(
        name = "revoke",
        description = [
            "Turn custom domains OFF for a workspace. An existing domain is NOT removed (its admins remove it",
            "with `thoryn domain remove`); new claims are refused. Audited as custom_domain.entitlement_revoked.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RevokeSubcommand : Base() {
        override val requiredScope: String = OperatorSession.SCOPE_CUSTOM_DOMAINS_MANAGE

        override fun run(client: OperatorHubClient, slug: String, format: OutputFormat, out: PrintStream): Int {
            val body = client.setCustomDomainEntitlement(slug, entitled = false)
            CommandSupport.emitValue(
                format,
                body,
                "Custom domains DISABLED for workspace '$slug' (entitled: ${body["entitled"]?.asBoolean()}). " +
                    "An existing domain keeps its state until it is removed.",
                out,
            )
            return CommandSupport.EXIT_OK
        }
    }

    @Command(
        name = "status",
        description = ["Show a workspace's custom domain: state, entitlement, DNS records, last check."],
        mixinStandardHelpOptions = true,
    )
    class StatusSubcommand : Base() {
        override val requiredScope: String = OperatorSession.SCOPE_CUSTOM_DOMAINS_READ

        override fun run(client: OperatorHubClient, slug: String, format: OutputFormat, out: PrintStream): Int {
            val body = try {
                client.getCustomDomain(slug)
            } catch (ex: OperatorHubException) {
                if (ex.httpStatus != 404 || ex.errorCode != ERROR_NO_DOMAIN) throw ex
                // The workspace exists and the caller is an operator (the gate passed); it simply has
                // no domain. The hub's operator read carries the entitlement only alongside a domain.
                CommandSupport.emitValue(
                    format,
                    mapOf("workspace" to slug, "state" to "NONE"),
                    "Workspace '$slug' has no custom domain.\n" +
                        "The hub reports the entitlement only once a domain is claimed; `entitle` / `revoke` print " +
                        "the resulting flag, and the workspace's admins see it with `thoryn domain status`.",
                    out,
                )
                return CommandSupport.EXIT_OK
            }
            when (format) {
                OutputFormat.TABLE -> {
                    Printers.record(statusFields(body), out)
                    val records = body["dnsRecords"]?.takeIf { it.isArray }?.toList().orEmpty()
                    if (records.isNotEmpty()) {
                        out.println()
                        Printers.table(
                            listOf("TYPE", "NAME", "VALUE"),
                            records.map { listOf(text(it, "type"), text(it, "name"), text(it, "value")) },
                            out,
                        )
                    }
                }
                else -> CommandSupport.emitRecord(format, body, ::statusFields, out)
            }
            return CommandSupport.EXIT_OK
        }
    }

    companion object {
        /** `CustomDomainException.NOT_FOUND` — the workspace has no custom domain (past the operator gate). */
        const val ERROR_NO_DOMAIN: String = "custom_domain_not_found"

        /** Test seam — builds the hub client for a resolved URL + session. */
        internal var clientFactory: (String, Tokens) -> OperatorHubClient = { url, tokens ->
            val bound = DpopSession.schemeFor(tokens).equals(DpopSession.SCHEME, ignoreCase = true)
            OperatorHubClient(url, tokens, dpop = if (bound) Dpop.session() else null)
        }

        private fun text(node: JsonNode, field: String): String? =
            node[field]?.takeUnless { it.isNull }?.asString()

        /** The hub's `CustomDomainView` (oathy `CustomDomainService.kt`) as a key/value record. */
        fun statusFields(body: JsonNode): List<Pair<String, Any?>> = listOf(
            "domain" to text(body, "domain"),
            "state" to text(body, "state"),
            "entitled" to body["entitled"]?.takeUnless { it.isNull }?.asBoolean(),
            "claimedAt" to text(body, "claimedAt"),
            "claimExpiresAt" to text(body, "claimExpiresAt"),
            "verifiedAt" to text(body, "verifiedAt"),
            "lastCheckedAt" to text(body, "lastCheckedAt"),
            "suspendedAt" to text(body, "suspendedAt"),
            "failureReason" to text(body, "failureReason")?.let { DomainCommand.reasonText(it) },
            "reissueAccepted" to body["reissueAccepted"]?.takeUnless { it.isNull }?.asBoolean(),
        ).filter { it.second != null }

        /**
         * Map a refusal from the operator surface to the one thing the operator can do about it.
         * Structured formats get the same guidance as a `hint` field.
         */
        internal fun renderError(
            ex: OperatorHubException,
            slug: String,
            requiredScope: String,
            format: OutputFormat,
            out: PrintStream,
            err: PrintStream,
        ): Int {
            val hint = hintFor(ex, slug, requiredScope)
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
                        "hint" to hint,
                    )
                    if (format == OutputFormat.JSON) Printers.json(structured, out) else Printers.yaml(structured, out)
                }
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }

        internal fun hintFor(ex: OperatorHubException, slug: String, requiredScope: String): String = when {
            ex.errorCode == "operator_passkey_required" ->
                "The operator session did not come from a passkey sign-in. Run `${OperatorSession.LOGIN_HINT}` " +
                    "and choose your passkey (not a password or a recovery code)."
            ex.errorCode == "insufficient_scope" || (ex.httpStatus == 403 && ex.errorCode == null) ->
                "The operator token lacks $requiredScope. Run `${OperatorSession.LOGIN_HINT}` again — a token minted " +
                    "before the hub granted this scope to thoryn-operator (hub V185) does not carry it."
            ex.errorCode == "unknown_tenant" ->
                "The hub resolved no tenant for this request's Host. Call it on the port-forward address " +
                    "(--hub-url ${OperatorSession.DEFAULT_HUB_URL}), not on another host name."
            ex.errorCode == ERROR_NO_DOMAIN ->
                "Workspace '$slug' has no custom domain."
            ex.httpStatus == 404 ->
                "Not found. Either the workspace '$slug' does not exist, or your identity holds no operator standing " +
                    "in this environment (the hub answers both with 404 so the operator surface cannot be probed). " +
                    "Check the slug; standing is appointed only by the deployment value " +
                    "productApi.operatorPlatformSubjects — confirm your platform subject is listed."
            ex.httpStatus == 401 ->
                "The hub did not accept the operator token (expired, or from another environment). " +
                    "Run `${OperatorSession.LOGIN_HINT}`."
            ex.errorCode == "custom_domain_not_entitled" ->
                "Custom domains are not enabled for '$slug'. Run `thoryn operator custom-domain entitle $slug`."
            else -> "The hub refused the request (HTTP ${ex.httpStatus})."
        }

        /** Transport failure — almost always a missing port-forward. */
        internal fun renderUnreachable(ex: Throwable, hubUrl: String, err: PrintStream): Int {
            val root = generateSequence(ex) { it.cause }.take(8).last()
            val refused = root is ConnectException || root is HttpConnectTimeoutException ||
                ex is ConnectException || ex is HttpConnectTimeoutException
            if (refused) {
                err.println("Error: the hub is not reachable at $hubUrl.")
                err.println("Start the port-forward in another terminal (it needs cluster access):")
                err.println("    ${OperatorSession.PORT_FORWARD_COMMAND}")
                err.println("then re-run this command.")
                return CommandSupport.EXIT_IO_ERROR
            }
            return CommandSupport.renderRequestFailure(ex, hubUrl, err)
        }
    }
}
