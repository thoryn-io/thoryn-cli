package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain issuer-bridge ...` — SSO-957 parity for the
 * issuer-bridge operations console.
 *
 * URL shapes (per `features/SSO-957-supply-chain-issuer-bridge-ops-console.md`):
 *
 *  - `GET    /api/v1/issuer-bridges`
 *  - `GET    /api/v1/issuer-bridges/{bridgeId}`
 *  - `GET    /api/v1/issuer-bridges/{bridgeId}/credentials`
 *  - `POST   /api/v1/issuer-bridges/{bridgeId}/credentials/{credId}/revoke`
 *  - `POST   /api/v1/issuer-bridges/{bridgeId}/keys` — step=generate
 *  - `PATCH  /api/v1/issuer-bridges/{bridgeId}/keys/{kid}` — step=publish|cut-over|monitor|retire
 *
 * Scopes:
 *  - `tenant:supply-chain.issuer-bridge.read` — list, show, credentials
 *  - `tenant:supply-chain.issuer-bridge.revoke` — revoke
 *  - `tenant:supply-chain.issuer-bridge.rotate-key` — rotate-key
 */
@Command(
    name = "issuer-bridge",
    description = ["Operate issuer bridges (config + outbox health + revocation + key rotation)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        IssuerBridgeCommand.ListSubcommand::class,
        IssuerBridgeCommand.ShowSubcommand::class,
        IssuerBridgeCommand.CredentialsSubcommand::class,
        IssuerBridgeCommand.RevokeSubcommand::class,
        IssuerBridgeCommand.RotateKeySubcommand::class,
    ],
)
class IssuerBridgeCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn supply-chain issuer-bridge <subcommand>")
        System.err.println("Subcommands: list | show | credentials | revoke | rotate-key")
        return SupplyChainCommandSupport.EXIT_USAGE
    }

    /** `thoryn supply-chain issuer-bridge list` */
    @Command(
        name = "list",
        description = ["List registered issuer bridges with heartbeat and status."],
        mixinStandardHelpOptions = true,
    )
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            return try {
                val body = client.listIssuerBridges()
                SupplyChainCommandSupport.emitList(
                    format = format,
                    body = body,
                    tableHeaders = LIST_HEADERS,
                    rowMapper = ::bridgeRow,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.issuer-bridge.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** `thoryn supply-chain issuer-bridge show <bridgeId>` */
    @Command(
        name = "show",
        description = ["Show a single issuer bridge: config + last heartbeat + outbox counters."],
        mixinStandardHelpOptions = true,
    )
    class ShowSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Bridge ID."])
        lateinit var bridgeId: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            return try {
                val body = client.getIssuerBridge(bridgeId)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::bridgeRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.issuer-bridge.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** `thoryn supply-chain issuer-bridge credentials --bridge-id <id> ...` */
    @Command(
        name = "credentials",
        description = ["List credentials issued by a bridge."],
        mixinStandardHelpOptions = true,
    )
    class CredentialsSubcommand : Callable<Int> {

        @Option(names = ["--bridge-id"], required = true)
        lateinit var bridgeId: String

        @Option(
            names = ["--status"],
            description = ["active | revoked | expired"],
        )
        var status: String? = null

        @Option(names = ["--grower-id"])
        var growerId: String? = null

        @Option(names = ["--limit"], description = ["Page size (max 200)."])
        var limit: Int? = null

        @Option(names = ["--cursor"], description = ["Opaque pagination cursor."])
        var cursor: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            val query = linkedMapOf<String, String?>(
                "status" to status,
                "growerId" to growerId,
                "limit" to limit?.toString(),
                "cursor" to cursor,
            )
            return try {
                val body = client.listIssuerBridgeCredentials(bridgeId, query)
                SupplyChainCommandSupport.emitList(
                    format = format,
                    body = body,
                    tableHeaders = CRED_HEADERS,
                    rowMapper = ::credentialRow,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.issuer-bridge.read",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain issuer-bridge revoke --bridge-id <id>
     *   --credential-id <cid> --reason "..."`
     *
     * Mirrors the console's revoke modal — reason of ≥ 10 chars is enforced
     * server-side (per SSO-957 acceptance criteria); the CLI bails early on
     * obvious empties.
     */
    @Command(
        name = "revoke",
        description = ["Revoke a credential — flips the Status List 2021 bit + writes a STATUS_LIST_REVOKED audit row."],
        mixinStandardHelpOptions = true,
    )
    class RevokeSubcommand : Callable<Int> {

        @Option(names = ["--bridge-id"], required = true)
        lateinit var bridgeId: String

        @Option(names = ["--credential-id"], required = true)
        lateinit var credentialId: String

        @Option(
            names = ["--reason"],
            description = ["Required reason (>= 10 chars)."],
            required = true,
        )
        lateinit var reason: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            if (reason.length < 10) {
                System.err.println("Error: --reason must be at least 10 characters.")
                return SupplyChainCommandSupport.EXIT_USAGE
            }
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            return try {
                val body = client.revokeIssuerBridgeCredential(bridgeId, credentialId, reason)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::revocationRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.issuer-bridge.revoke",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn supply-chain issuer-bridge rotate-key --bridge-id <id>
     *   --step <generate|publish|cut-over|monitor|retire>`
     *
     * The CLI is a thin wrapper around the five-step state machine in
     * `IssuerKeyRotationService`. Each step is idempotent server-side; the
     * CLI does not enforce ordering — the server picks up the current step
     * from the most-recent audit row.
     */
    @Command(
        name = "rotate-key",
        description = ["Drive a step of the five-step key-rotation wizard."],
        mixinStandardHelpOptions = true,
    )
    class RotateKeySubcommand : Callable<Int> {

        @Option(names = ["--bridge-id"], required = true)
        lateinit var bridgeId: String

        @Option(
            names = ["--step"],
            description = ["One of: generate | publish | cut-over | monitor | retire"],
            required = true,
        )
        lateinit var step: String

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = SupplyChainCommandSupport.parseFormat(outputRaw)
                ?: return SupplyChainCommandSupport.EXIT_USAGE
            if (step !in ALLOWED_STEPS) {
                System.err.println("Error: --step must be one of ${ALLOWED_STEPS.joinToString(" | ")} (was '$step').")
                return SupplyChainCommandSupport.EXIT_USAGE
            }
            val tokens = SupplyChainCommandSupport.readTokens()
                ?: return SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN
            val client = SupplyChainCommandSupport.client(gateway, tokens)
            return try {
                val body = client.rotateIssuerBridgeKey(bridgeId, step)
                SupplyChainCommandSupport.emitRecord(
                    format = format,
                    body = body,
                    recordFields = ::rotationRecordFields,
                )
                SupplyChainCommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                SupplyChainCommandSupport.renderError(
                    format = format,
                    ex = ex,
                    requiredScope = "tenant:supply-chain.issuer-bridge.rotate-key",
                )
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                SupplyChainCommandSupport.EXIT_IO_ERROR
            }
        }
    }

    companion object {
        internal val ALLOWED_STEPS: List<String> = listOf(
            "generate", "publish", "cut-over", "monitor", "retire",
        )

        internal val LIST_HEADERS: List<String> = listOf(
            "bridgeId", "vendor", "currentKid", "lastHeartbeat",
            "credentialsLive", "status",
        )

        internal val CRED_HEADERS: List<String> = listOf(
            "credentialId", "growerId", "issuedAt", "status",
        )

        internal fun bridgeRow(node: JsonNode): List<Any?> = listOf(
            node["bridgeId"]?.asString(),
            node["vendor"]?.asString(),
            node["currentKid"]?.asString(),
            node["lastHeartbeatAt"]?.asString(),
            node["credentialsLive"]?.asInt(),
            node["status"]?.asString(),
        )

        internal fun bridgeRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "bridgeId" to node["bridgeId"]?.asString(),
            "vendor" to node["vendor"]?.asString(),
            "currentKid" to node["currentKid"]?.asString(),
            "vaultKeyAlias" to node["vaultKeyAlias"]?.asString(),
            "apiEndpointUrl" to node["apiEndpointUrl"]?.asString(),
            "scheduleCron" to node["scheduleCron"]?.asString(),
            "lastHeartbeatAt" to node["lastHeartbeatAt"]?.asString(),
            "credentialsLive" to node["credentialsLive"]?.asInt(),
            "status" to node["status"]?.asString(),
            "queued" to node["queued"]?.asInt(),
            "signed" to node["signed"]?.asInt(),
            "encoded" to node["encoded"]?.asInt(),
            "failed" to node["failed"]?.asInt(),
        )

        internal fun credentialRow(node: JsonNode): List<Any?> = listOf(
            node["credentialId"]?.asString(),
            node["growerId"]?.asString(),
            node["issuedAt"]?.asString(),
            node["status"]?.asString(),
        )

        internal fun revocationRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "credentialId" to node["credentialId"]?.asString(),
            "status" to node["status"]?.asString(),
            "revokedAt" to node["revokedAt"]?.asString(),
            "auditRowId" to node["auditRowId"]?.asString(),
        )

        internal fun rotationRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "bridgeId" to node["bridgeId"]?.asString(),
            "step" to node["step"]?.asString(),
            "kid" to node["kid"]?.asString(),
            "previousKid" to node["previousKid"]?.asString(),
            "auditRowId" to node["auditRowId"]?.asString(),
            "transitionedAt" to node["transitionedAt"]?.asString(),
        )
    }
}
