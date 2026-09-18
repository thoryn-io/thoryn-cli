package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
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
 *              `login_flow:<envSlug>`, `login_methods:<envSlug>`
 *  - relations: `manager`, `viewer`
 *
 * Subcommands:
 *  - `grant <subject> <relation> <object>`  — POST   /api/v1/access/grants (idempotent: 201, or 200 when it exists)
 *  - `revoke <subject> <relation> <object>` — DELETE /api/v1/access/grants (body-identified; 204)
 *  - `list [--object …] [--subject …]`      — GET    /api/v1/access/grants?object=…|subject=… (ListEnvelope, `data`)
 *  - `mine [--type …] [--relation …]`       — GET    /api/v1/access/mine?type=…&relation=… (`{ data: [ "<type>:<id>" ] }`)
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
    ],
)
class AccessCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn access <subcommand>")
        System.err.println("Subcommands: grant | revoke | list | mine")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn access grant <subject> <relation> <object>` — create a grant (idempotent). */
    @Command(name = "grant", description = ["Grant a subject a relation on an object, e.g. `client:cli-ci manager environment:<id>`."], mixinStandardHelpOptions = true)
    class GrantSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Subject: member:<sub> or client:<clientId>."])
        lateinit var subject: String

        @Parameters(index = "1", description = ["Relation: manager or viewer."])
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

        @Parameters(index = "1", description = ["Relation: manager or viewer."])
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

        @Option(names = ["--relation"], description = ["Relation filter: manager or viewer."])
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

    companion object {
        const val SCOPE_READ: String = "tenant:access.read"
        const val SCOPE_WRITE: String = "tenant:access.write"

        /** Subject types of the SSO-3112 contract. */
        val SUBJECT_TYPES: Set<String> = setOf("member", "client")

        /** Object types of the SSO-3112 contract (the `<type>` half of an object ref). */
        val OBJECT_TYPES: Set<String> = setOf(
            "workspace", "environment", "application", "user", "federation_member",
            "email_provider", "login_theme", "login_flow", "login_methods",
        )

        /** Relations of the SSO-3112 contract. */
        val RELATIONS: Set<String> = setOf("manager", "viewer")

        /** `<type>:<id>` — a non-empty type token, a colon, a non-empty id with no whitespace. */
        val REF_PATTERN: Regex = Regex("^([a-z_]+):(\\S+)$")

        /**
         * The workspace-admin USERSET subject (`workspace:<tenantId>#admin`) the server seeds on every
         * object: `thoryn provision apply` never revokes it, whatever the file says.
         */
        val ADMIN_USERSET_PATTERN: Regex = Regex("^workspace:\\S+#admin$")

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

        /** A human-readable violation for a subject ref, or null when it conforms. */
        fun validateSubject(raw: String): String? {
            val m = REF_PATTERN.matchEntire(raw) ?: return "subject '$raw' must be <type>:<id> with type one of ${SUBJECT_TYPES.joinToString(", ")}"
            return if (m.groupValues[1] !in SUBJECT_TYPES) "subject type '${m.groupValues[1]}' must be one of ${SUBJECT_TYPES.joinToString(", ")}" else null
        }

        /** A human-readable violation for an object ref, or null when it conforms. */
        fun validateObject(raw: String): String? {
            val m = REF_PATTERN.matchEntire(raw) ?: return "object '$raw' must be <type>:<id> with type one of ${OBJECT_TYPES.joinToString(", ")}"
            return if (m.groupValues[1] !in OBJECT_TYPES) "object type '${m.groupValues[1]}' must be one of ${OBJECT_TYPES.joinToString(", ")}" else null
        }

        /** A human-readable violation for a relation, or null when it conforms. */
        fun validateRelation(raw: String): String? =
            if (raw !in RELATIONS) "relation '$raw' must be one of ${RELATIONS.joinToString(", ")}" else null

        /** The first violation across the three, or null when the triple conforms. */
        fun validate(subject: String, relation: String, objectRef: String): String? =
            validateSubject(subject) ?: validateRelation(relation) ?: validateObject(objectRef)
    }
}
