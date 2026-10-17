package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.provision.AccessRefs
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * SSO-3792 (oauthy ADR `2026-10-17-consent-approved-application-creation-slots.md` §2 / §6; product-api SSO-3789) —
 * `thoryn access reserve | reservations | release`: application CREATION SLOTS. A slot is a workspace admin's approval that
 * ONE workload identity (`client:wi_…`, a repository's) creates ONE named application on ONE plane, once, within 30 days —
 * the right a red provisioning plan asks for (fix-request kind `creator`) when the file declares a production application
 * that does not exist yet. The repository's own apply then creates it with its own token and becomes its owner; the slot
 * is consumed by that create, and swept by any other creation of the name.
 *
 * Thin wrappers over `/api/v1/access/application-slots` (workspace-level: the plane is a field, never the
 * `X-Thoryn-Environment` header):
 *  - `reserve <subject> application:<clientId> [--environment <slug>]` — `POST` (`tenant:access.write`, workspace admins only;
 *    `201` reserved, `200` the same reservation already held; `409 application_exists` / `application_slot_held` /
 *    `reserved_client_id`; every other miss the opaque `404`)
 *  - `reservations [--subject <ref>]` — `GET` (`tenant:access.read`; an admin sees every slot, anyone else the slots it
 *    holds); `--subject` filters the answer here
 *  - `release application:<clientId>` — `DELETE …/{clientId}` (`tenant:access.write`; the holder releases, an admin revokes)
 *
 * Kept out of [AccessCommand]'s file on purpose: the grants grammar (`<subject> <relation> <object>`) does not apply — a
 * slot is not a relation on an object that exists, and the grants API never writes one (ADR §1).
 */
object AccessReservations {

    internal val SLOT_HEADERS: List<String> = listOf("object", "subject", "environment", "createdAt", "expiresAt", "expired")

    internal fun slotRow(node: JsonNode): List<Any?> = listOf(
        node["object"]?.asString(),
        node["subject"]?.asString(),
        node["environment"]?.takeIf { !it.isNull }?.asString(),
        node["createdAt"]?.takeIf { !it.isNull }?.asString(),
        node["expiresAt"]?.takeIf { !it.isNull }?.asString(),
        node["expired"]?.asBoolean(),
    )

    internal fun slotFields(node: JsonNode): List<Pair<String, Any?>> = SLOT_HEADERS.zip(slotRow(node))

    /** The object of a slot: `application:<clientId>` — the access API's spelling (percent-encoded id), nothing else. */
    fun validateApplicationRef(raw: String): String? {
        val m = AccessRefs.REF_PATTERN.matchEntire(raw) ?: return "object '$raw' must be application:<clientId>"
        return if (m.groupValues[1] != ProvisionEngine.OBJECT_TYPE_APPLICATION) "a creation slot names an application: application:<clientId> (was '${m.groupValues[1]}:…')" else null
    }

    /** The subject of a slot: a workload identity's client (`client:wi_…`) — never a person (`member:`). */
    fun validateSlotSubject(raw: String): String? {
        AccessRefs.validateSubject(raw)?.let { return it }
        return if (!raw.startsWith("client:")) "a creation slot is held by a workload identity: client:<wi_…> (a person creates the application themselves)" else null
    }

    /**
     * What to do when product-api refuses a reservation or a release, printed on stderr above the error (so a
     * `--output json` stdout stays one document), or null when the refusal is not one of these.
     */
    fun refusalHint(subject: String?, objectRef: String, environment: String?, ex: ProductApiException): String? = when {
        ex.errorCode == ERROR_APPLICATION_EXISTS ->
            "Refused ($ERROR_APPLICATION_EXISTS): $objectRef already exists in this workspace (on some plane) — a creation slot is only for a name that " +
                "does not exist. If ${subject ?: "the repository"} is to own it, grant that instead: `${FixRequest.grantCommand(subject, AccessRefs.RELATION_OWNER, objectRef)}`."
        ex.errorCode == ERROR_SLOT_HELD ->
            "Refused ($ERROR_SLOT_HELD): another identity holds an unexpired creation slot for $objectRef. `thoryn access reservations` shows it; " +
                "`thoryn access release $objectRef` revokes it (workspace admins), then reserve again."
        ex.errorCode == ERROR_RESERVED_CLIENT_ID ->
            "Refused ($ERROR_RESERVED_CLIENT_ID): the platform reserves this client id; no one creates it. Pick another clientId in the file."
        ex.httpStatus == 404 && environment != null ->
            "Not found: a reservation needs a workspace admin's session (`workspace:<id>#admin`), a subject that is the workload client of one of this " +
                "workspace's trusts (`${FixRequest.LIST_TRUSTS_COMMAND}`), and an environment slug of this workspace ('$environment'; `production` for the " +
                "production plane). The platform answers the same 404 for each, and a platform from before creation slots (oauthy SSO-3789) answers it too."
        ex.httpStatus == 404 ->
            "Not found: no creation slot for $objectRef that you hold or may revoke (the holder releases its own; a workspace admin revokes any)."
        else -> null
    }

    const val ERROR_APPLICATION_EXISTS: String = "application_exists"
    const val ERROR_SLOT_HELD: String = "application_slot_held"
    const val ERROR_RESERVED_CLIENT_ID: String = "reserved_client_id"

    /** `thoryn access reserve <subject> application:<clientId> [--environment <slug>]` — approve one creation. */
    @Command(
        name = "reserve",
        description = [
            "Approve that a workload identity creates ONE named application on ONE plane, once, within 30 days (a creation slot; workspace admins).",
            "e.g. `thoryn access reserve client:wi_… application:forge-forgejo-login --environment production`.",
        ],
        mixinStandardHelpOptions = true,
    )
    class ReserveSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Subject: client:<wi_…> — the workload client of one of this workspace's trusts."])
        lateinit var subject: String

        @Parameters(index = "1", paramLabel = "<object>", description = ["The application to be created: application:<clientId>."])
        lateinit var objectRef: String

        @Option(names = ["--environment"], paramLabel = "<slug>", description = ["The plane it may be created in: an environment slug, or production (default)."])
        var environment: String = ProvisionEngine.PRODUCTION_ENV_SLUG

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = subject.trim(); val o = objectRef.trim(); val env = environment.trim()
            (validateSlotSubject(s) ?: validateApplicationRef(o) ?: if (env.isEmpty()) "--environment must name a plane (production, or an environment slug)" else null)
                ?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val slot = client.reserveApplicationSlot(s, o, env)
                CommandSupport.emitRecord(format, slot, ::slotFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                refusalHint(s, o, env, ex)?.let { System.err.println(it) }
                CommandSupport.renderError(format, ex, requiredScope = AccessRefs.SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn access reservations [--subject <ref>]` — the creation slots you may see. */
    @Command(name = "reservations", description = ["List application creation slots (an admin sees every slot, anyone else the slots it holds)."], mixinStandardHelpOptions = true)
    class ReservationsSubcommand : Callable<Int> {

        @Option(names = ["--subject"], description = ["Only the slots held by this subject (client:<wi_…>)."])
        var subject: String? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = subject?.trim()?.takeIf { it.isNotEmpty() }
            s?.let { AccessRefs.validateSubject(it) }?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                val listing = client.listApplicationSlots()
                val body = if (s == null) listing else filtered(listing, s)
                CommandSupport.emitList(format, body, SLOT_HEADERS, rowMapper = ::slotRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                if (ex.httpStatus == 404) System.err.println("Not found: this platform predates application creation slots (oauthy SSO-3789).")
                CommandSupport.renderError(format, ex, requiredScope = AccessRefs.SCOPE_READ)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** The ListEnvelope with `data` narrowed to [subject]'s slots (the API has no filter; the listing is small). */
        private fun filtered(listing: JsonNode, subject: String): JsonNode {
            val copy = listing.deepCopy()
            val data = copy["data"]
            if (copy is tools.jackson.databind.node.ObjectNode && data != null && data.isArray) {
                copy.set("data", copy.arrayNode().addAll(data.filter { it["subject"]?.asString() == subject }))
            }
            return copy
        }
    }

    /** `thoryn access release application:<clientId>` — release (the holder) or revoke (an admin) a creation slot. */
    @Command(name = "release", description = ["Release a creation slot you hold, or (workspace admins) revoke anyone's."], mixinStandardHelpOptions = true)
    class ReleaseSubcommand : Callable<Int> {

        @Parameters(index = "0", paramLabel = "<object>", description = ["The application the slot is for: application:<clientId>."])
        lateinit var objectRef: String

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val o = objectRef.trim()
            validateApplicationRef(o)?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val clientId = ProvisionEngine.decodePlatformId(o.substringAfter(':'))
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            return try {
                client.releaseApplicationSlot(clientId)
                CommandSupport.emitValue(format, linkedMapOf("released" to true, "object" to o), "Released: the creation slot for $o")
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                refusalHint(null, o, null, ex)?.let { System.err.println(it) }
                CommandSupport.renderError(format, ex, requiredScope = AccessRefs.SCOPE_WRITE)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }
}
