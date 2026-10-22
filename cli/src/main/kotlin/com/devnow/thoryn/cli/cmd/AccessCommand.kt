package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.provision.AccessRefs
import com.devnow.thoryn.provision.FixRequest
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn access ...` — SSO-3113 (epic SSO-3108, "least-privilege CI identities"): manage the ACCESS
 * GRANTS of your workspace — who (a SUBJECT) may do what (a RELATION) on which resource (an OBJECT).
 * A grant is the unit a least-privilege CI identity is confined with: instead of holding every
 * `tenant:*` scope on the whole workspace, a machine client is made `manager` of ONE sandbox
 * environment (`client:cli-ci manager environment:<id>`) and can touch nothing else.
 *
 * A thin wrapper over product-api's `/api/v1/access` surface (the SSO-3112 contract), the same shape
 * as `thoryn env` — the CLI marshals, attaches the bearer, renders. Grants are WORKSPACE-level (an
 * object ref carries its own environment id), so the calls ride no `X-Thoryn-Environment` selection.
 * Scopes: read → `tenant:access.read`, write → `tenant:access.write`.
 *
 * Reference grammar (`<type>:<id>`):
 *  - subjects: `member:<sub>`, `client:<clientId>`
 *  - objects:  `workspace:<tenantId>`, `environment:<id>`, `application:<clientId>`, `user:<id>`,
 *              `federation_member:<id>`, `email_provider:<envSlug>`, `login_theme:<envSlug>`,
 *              `login_flow:<envSlug>`, `login_methods:<envSlug>`, `custom_domain:<tenantId>` (SSO-3434),
 *              `trust:<trustId>` (SSO-3774 — a workload-identity trust; ownable since oauthy SSO-3772)
 *  - relations: `manager`, `viewer`, and (SSO-3667 / SSO-3673) `owner` — the ONE owning workload identity of an
 *    `application` / `environment`, grantable and revocable by a workspace admin only; a second owner is
 *    `409 owner_already_set`. `owner` is deliberately not accepted in a provisioning file's `grants:`.
 *
 * Subcommands:
 *  - `grant <subject> <relation> <object>`  — POST   /api/v1/access/grants (idempotent: 201, or 200 when it exists)
 *  - `revoke <subject> <relation> <object>` — DELETE /api/v1/access/grants (body-identified; 204)
 *  - `list [--object …] [--subject …]`      — GET    /api/v1/access/grants?object=…|subject=… (ListEnvelope, `data`)
 *  - `mine [--type …] [--relation …]`       — GET    /api/v1/access/mine?type=…&relation=… (`{ data: [ "<type>:<id>" ] }`)
 *  - `approve <owner>/<repo>/<run_id> | <consent URL>` — SSO-3738: opens the hub consent for a red provisioning run's
 *    missing rights in the browser (or prints its address); no API call, grants nothing itself ([AccessApprove])
 *  - `reserve | reservations | release`      — SSO-3792: application CREATION SLOTS (`/api/v1/access/application-slots`),
 *    a workspace admin's approval that a workload identity creates one named application — see [AccessReservations]
 *
 * The same grammar backs the `grants:` block of a provisioning file (`thoryn provision apply`
 * converges grants per resource — see `ProvisionFile`).
 */
@Command(
    name = "access",
    description = ["Manage least-privilege access grants: who may manage or view which resource."],
    mixinStandardHelpOptions = true,
    subcommands = [
        AccessCommand.GrantSubcommand::class,
        AccessCommand.RevokeSubcommand::class,
        AccessCommand.ListSubcommand::class,
        AccessCommand.MineSubcommand::class,
        AccessCommand.ApproveSubcommand::class,
        // SSO-3792 — application creation slots (oauthy ADR 2026-10-17).
        AccessReservations.ReserveSubcommand::class,
        AccessReservations.ReservationsSubcommand::class,
        AccessReservations.ReleaseSubcommand::class,
    ],
)
class AccessCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn access <subcommand>")
        System.err.println("Subcommands: grant | revoke | list | mine | approve | reserve | reservations | release")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn access grant <subject> <relation> <object>` — create a grant (idempotent). */
    @Command(name = "grant", description = ["Grant a subject a relation on an object, e.g. `client:cli-ci manager environment:<id>`."], mixinStandardHelpOptions = true)
    class GrantSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Subject: member:<sub> or client:<clientId>."])
        lateinit var subject: String

        @Parameters(index = "1", description = ["Relation: manager, viewer, or owner (workspace admins only; one owner per application / environment)."])
        lateinit var relation: String

        @Parameters(index = "2", paramLabel = "<object>", description = ["Object: <type>:<id>, e.g. environment:<id>, application:<clientId>."])
        lateinit var objectRef: String

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = subject.trim(); val rel = relation.trim(); val o = objectRef.trim()
            validate(s, rel, o)?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val grant = client.createGrant(s, rel, o)
                CommandSupport.emitRecord(format, grant, ::grantFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                trustRefusalHint(s, rel, o, ex)?.let { System.err.println(it) }
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn access revoke <subject> <relation> <object>` — remove a grant (204). */
    @Command(name = "revoke", description = ["Revoke a subject's relation on an object."], mixinStandardHelpOptions = true)
    class RevokeSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Subject: member:<sub> or client:<clientId>."])
        lateinit var subject: String

        @Parameters(index = "1", description = ["Relation: manager, viewer, or owner."])
        lateinit var relation: String

        @Parameters(index = "2", paramLabel = "<object>", description = ["Object: <type>:<id>."])
        lateinit var objectRef: String

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = subject.trim(); val rel = relation.trim(); val o = objectRef.trim()
            validate(s, rel, o)?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                client.deleteGrant(s, rel, o)
                CommandSupport.emitValue(
                    format,
                    linkedMapOf("revoked" to true, "subject" to s, "relation" to rel, "object" to o),
                    "Revoked: $s $rel $o",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                trustRefusalHint(s, rel, o, ex)?.let { System.err.println(it) }
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn access list --object <ref> | --subject <ref>` — the grants on an object, or held by a subject. */
    @Command(name = "list", description = ["List the grants on an object (--object) or held by a subject (--subject)."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--object"], paramLabel = "<object>", description = ["Object ref (<type>:<id>) whose grants to list."])
        var objectRef: String? = null

        @Option(names = ["--subject"], description = ["Subject ref (member:<sub> | client:<clientId>) whose grants to list."])
        var subject: String? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val o = objectRef?.trim()?.takeIf { it.isNotEmpty() }
            val s = subject?.trim()?.takeIf { it.isNotEmpty() }
            if (o == null && s == null) {
                System.err.println("Error: pass --object <type>:<id> and/or --subject <member|client>:<id>.")
                return CommandSupport.EXIT_USAGE
            }
            o?.let { validateObject(it) }?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            s?.let { validateSubject(it) }?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val grants = client.listGrants(objectRef = o, subjectRef = s)
                CommandSupport.emitList(format, grants, GRANT_HEADERS, rowMapper = ::grantRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_READ)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn access mine [--type <objectType>] [--relation <relation>]` — the objects the caller holds a relation on. */
    @Command(name = "mine", description = ["List the objects you (this session's subject) have access to."], mixinStandardHelpOptions = true)
    class MineSubcommand : Callable<Int> {

        @Option(names = ["--type"], description = ["Object type filter, e.g. environment, application."])
        var type: String? = null

        @Option(names = ["--relation"], description = ["Relation filter: manager, viewer, or owner."])
        var relation: String? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val t = type?.trim()?.takeIf { it.isNotEmpty() }
            if (t != null && t !in OBJECT_TYPES) {
                System.err.println("Error: --type must be one of ${OBJECT_TYPES.joinToString(", ")} (was '$t').")
                return CommandSupport.EXIT_USAGE
            }
            val rel = relation?.trim()?.takeIf { it.isNotEmpty() }
            if (rel != null && rel !in RELATIONS) {
                System.err.println("Error: --relation must be one of ${RELATIONS.joinToString(", ")} (was '$rel').")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val mine = client.listMyAccess(type = t, relation = rel)
                CommandSupport.emitList(format, mine, MINE_HEADERS, rowMapper = { listOf(it.asString()) })
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = SCOPE_READ)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * SSO-3738 — `thoryn access approve <owner>/<repo>/<run_id> | <consent URL>`: Option 1 of a red provisioning check.
     * Opens the run's by-run consent address — the same hub consent the check run's Option-2 link opens — in the browser,
     * or prints it to open on any device. It grants nothing: a workspace admin approves on Thoryn's consent screen. The
     * address and how its base is resolved: [AccessApprove].
     */
    @Command(
        name = "approve",
        description = [
            "Open Thoryn's consent for the rights a red provisioning run asks for (the check run's Option 1).",
            "Grants nothing itself: a workspace admin approves on Thoryn's consent screen.",
        ],
        mixinStandardHelpOptions = true,
    )
    class ApproveSubcommand : Callable<Int> {

        @Parameters(
            index = "0",
            paramLabel = "<run>",
            description = ["The run: <owner>/<repository>/<run_id> as the check run prints it, or the consent URL (https://…/github/consent/run/<owner>/<repository>/<run_id>)."],
        )
        lateinit var run: String

        @Option(
            names = ["--consent-url"],
            paramLabel = "<base-url>",
            description = ["The consent base URL (https://starters.<your Thoryn domain>). Default: the repository's .thoryn/workflow.yaml consentUrl, else derived from your signed-in platform."],
        )
        var consentUrl: String? = null

        @Option(names = ["--no-browser"], description = ["Print the address instead of opening a browser (also: THORYN_NO_BROWSER=1)."])
        var noBrowser: Boolean = false

        override fun call(): Int = when (val r = AccessApprove.resolve(run, consentUrl)) {
            is AccessApprove.Resolution.Refused -> {
                System.err.println("Error: ${r.message}")
                CommandSupport.EXIT_USAGE
            }
            is AccessApprove.Resolution.Ok -> {
                AccessApprove.deliver(r.target, noBrowser)
                CommandSupport.EXIT_OK
            }
        }
    }

    companion object {
        // SSO-3662 — the grammar lives in the engine library (AccessRefs); these names stay for the CLI.
        const val SCOPE_READ: String = AccessRefs.SCOPE_READ
        const val SCOPE_WRITE: String = AccessRefs.SCOPE_WRITE
        val SUBJECT_TYPES: Set<String> = AccessRefs.SUBJECT_TYPES
        val OBJECT_TYPES: Set<String> = AccessRefs.OBJECT_TYPES
        val RELATIONS: Set<String> = AccessRefs.RELATIONS
        val REF_PATTERN: Regex = AccessRefs.REF_PATTERN
        val ADMIN_USERSET_PATTERN: Regex = AccessRefs.ADMIN_USERSET_PATTERN

        internal val GRANT_HEADERS: List<String> = listOf("subject", "relation", "object", "createdAt")
        internal val MINE_HEADERS: List<String> = listOf("object")

        internal fun grantRow(node: JsonNode): List<Any?> = listOf(
            node["subject"]?.asString(),
            node["relation"]?.asString(),
            node["object"]?.asString(),
            node["createdAt"]?.asString(),
        )

        internal fun grantFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "subject" to node["subject"]?.asString(),
            "relation" to node["relation"]?.asString(),
            "object" to node["object"]?.asString(),
            "createdAt" to node["createdAt"]?.asString(),
        )

        /** SSO-3774 — product-api's I6 refusal (oauthy ADR 2026-10-16): `owner` / `manager` on a trust for that trust's OWN `wi_`. */
        const val ERROR_TRUST_SELF_MANAGEMENT: String = "trust_self_management"

        /**
         * SSO-3774 — what to do when a grant / revoke on a `trust:<id>` is refused, printed on stderr above the error (so a
         * `--output json` stdout stays one document), or null when the refusal is not one of these:
         *  - `400 trust_self_management` (oauthy S1 I6): no identity may own or manage the trust it SIGNS IN WITH — the
         *    subject is that trust's own `wi_` client. Grant the right to the repository identity that converges the trust.
         *  - `404` on a `trust:` object: the trust is not in this workspace — or the platform predates trust objects (a
         *    product-api before oauthy S1 answers a grant naming `trust:` with an opaque `404 not_found`; there a trust is
         *    reached through its environment, `manager environment:<id>`).
         */
        fun trustRefusalHint(subject: String, relation: String, objectRef: String, ex: ProductApiException): String? {
            if (!objectRef.startsWith("${AccessRefs.OBJECT_TYPE_TRUST}:")) return null
            return when {
                ex.errorCode == ERROR_TRUST_SELF_MANAGEMENT ->
                    "Refused ($ERROR_TRUST_SELF_MANAGEMENT): $subject is the workload client of $objectRef itself, and no identity may own or manage the trust " +
                        "it signs in with (oauthy ADR 2026-10-16 I6) — it could re-pin the identity it signs in as. Grant `$relation` on $objectRef to the " +
                        "repository identity that converges this trust (its own, different `wi_` client), never to the trust's own."
                ex.httpStatus == 404 ->
                    "Not found: $objectRef is not a trust of this workspace (`${FixRequest.LIST_TRUSTS_COMMAND}` shows the ids — add `--environment <slug>` for a " +
                        "sandbox), or this platform predates trust objects (oauthy SSO-3772) — there a trust is reached through its environment: " +
                        "`thoryn access grant $subject manager environment:<id>`."
                else -> null
            }
        }

        /** A human-readable violation for a subject ref, or null when it conforms. */
        fun validateSubject(raw: String): String? = AccessRefs.validateSubject(raw)
        fun validateObject(raw: String): String? = AccessRefs.validateObject(raw)
        fun validateRelation(raw: String): String? = AccessRefs.validateRelation(raw)
        fun validate(subject: String, relation: String, objectRef: String): String? = AccessRefs.validate(subject, relation, objectRef)
    }
}
