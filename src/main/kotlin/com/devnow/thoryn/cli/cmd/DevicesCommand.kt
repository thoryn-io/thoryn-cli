package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Timestamps
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import java.util.concurrent.Callable

/**
 * `thoryn devices ...` — SSO-3228 — the machines signed in to your account, and how to end one.
 *
 * Every machine the CLI signs in from holds its own DPoP key (RFC 9449, SSO-3199) in that machine's
 * OS keychain, and the tokens it receives are sender-constrained to that key. The key therefore
 * stands in for the machine, and registering it gives it a name you can recognise and revoke.
 *
 *  - `list`   — GET hub `/account/devices`: your devices, when each was last seen, the coarse
 *    networks its key is known on (the SSO-3229 per-key activity, carried in the same response),
 *    and — SSO-3271 — what each one is doing now: its `state` (`signed_in` / `idle` / `revoked` /
 *    `unregistered`), how many live sessions are bound to its key, and which workspace and plane
 *    each belongs to.
 *  - `revoke` — POST hub `/account/devices/{id}/revoke`: ends that machine's sessions and refuses
 *    its key from then on. **Your other machines are untouched** — that is the whole point, and the
 *    difference from signing out everywhere.
 *
 * **Surface.** Like the workspace commands these live on the HUB (`/account/[**]`, `SCOPE_openid`),
 * not behind the api-gateway, so they call the hub directly via `--hub` (defaulting to the hub
 * recorded at `thoryn login`).
 *
 * A key you have used but never registered — one minted by an older CLI — still appears, marked
 * unregistered. It carries no id, so it cannot be revoked individually; signing in again from that
 * machine registers it.
 *
 * **Every session field is read tolerantly.** A hub older than SSO-3271 sends no `state` and no
 * `sessions`, and those columns then read `-` rather than the command failing or inventing a value.
 * Tolerantly means `NullNode`-aware too: `node["x"]` answers a `NullNode` for an explicit JSON
 * `null`, which is not Kotlin's null — the SSO-3228 lesson that made an unregistered key look
 * revoked and sent a revoke to `/account/devices/null/revoke`.
 */
@Command(
    name = "devices",
    description = ["List and revoke the devices (DPoP keys) signed in to your account."],
    mixinStandardHelpOptions = true,
    subcommands = [
        DevicesCommand.ListSubcommand::class,
        DevicesCommand.RevokeSubcommand::class,
    ],
)
class DevicesCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn devices <subcommand>")
        System.err.println("Subcommands: list | revoke")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn devices list` */
    @Command(
        name = "list",
        description = ["List the devices signed in to your account, with each key's recent activity."],
        mixinStandardHelpOptions = true,
    )
    class ListSubcommand : Callable<Int> {

        @Option(
            names = ["--hub"],
            description = ["Override the hub base URL (default: the hub recorded at `thoryn login`)."],
            defaultValue = ThorynConfig.DEFAULT_HUB,
        )
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)
            return try {
                val body = client.listDevices()
                // The hub answers `{ "devices": [...] }` — not the customer-plane `ListEnvelope`
                // (`{data,pagination}`) `emitList` unwraps, and not a bare array. Unwrapping it HERE
                // rather than hoping the shared helper recognises it is the SSO-3082 lesson: a list
                // command that guesses its own envelope reports "none" against a working backend.
                CommandSupport.emitList(format, devicesArray(body), LIST_HEADERS, ::deviceRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                // `/account/[**]` is gated by SCOPE_openid, so a 403 here is not a missing tenant
                // scope and no `--scope` hint is offered.
                CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, hub)
            }
        }
    }

    /** `thoryn devices revoke <id-or-name>` */
    @Command(
        name = "revoke",
        description = [
            "Revoke a device: ends that machine's sessions and refuses its key. Your other devices keep working.",
        ],
        mixinStandardHelpOptions = true,
    )
    class RevokeSubcommand : Callable<Int> {

        @Parameters(
            index = "0",
            paramLabel = "<device>",
            description = ["The device id, or its name as shown by `thoryn devices list`."],
        )
        lateinit var device: String

        @Option(names = ["--reason"], description = ["Why — recorded in your workspace's audit log."])
        var reason: String? = null

        @Option(
            names = ["--hub"],
            description = ["Override the hub base URL (default: the hub recorded at `thoryn login`)."],
            defaultValue = ThorynConfig.DEFAULT_HUB,
        )
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)

            return try {
                val deviceId = resolveId(devicesOf(client.listDevices()))
                    ?: return CommandSupport.EXIT_USAGE
                val body = client.revokeDevice(deviceId, reason)
                CommandSupport.emitRecord(format, body, { n: JsonNode ->
                    listOf(
                        "id" to n["id"]?.asString(),
                        "name" to n["name"]?.asString(),
                        "revokedAt" to n["revokedAt"]?.asString(),
                        "revokedSessions" to n["revokedSessions"]?.asInt(),
                    )
                })
                if (format == OutputFormat.TABLE) {
                    System.err.println(
                        "Revoked. That machine's sessions are ended and its key is refused; your other " +
                            "devices keep working. Signing in from it again registers a NEW device.",
                    )
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, hub)
            }
        }

        /**
         * The device id to revoke: [device] itself when it names one, else the single device whose
         * name matches.
         *
         * Resolving a NAME requires the list, so the command reads it first. An ambiguous name is
         * refused rather than resolved to the newest match — revoking the wrong machine signs
         * someone out of a working one, and the ids are right there in the error.
         */
        private fun resolveId(devices: List<JsonNode>): String? {
            val byId = devices.firstOrNull { it.textOrNull("id") == device }
            if (byId != null) return device

            val named = devices.filter { it.textOrNull("name") == device }
            return when {
                named.size == 1 -> named.single().textOrNull("id").also {
                    if (it == null) {
                        System.err.println(
                            "'$device' is a key that has never been registered as a device, so there is " +
                                "nothing to revoke individually. Sign in from that machine to register it.",
                        )
                    }
                }

                named.size > 1 -> {
                    System.err.println("More than one device is called '$device'. Revoke it by id:")
                    named.forEach {
                        System.err.println(
                            "  ${it.textOrNull("id")}  (last seen ${Timestamps.render(it["lastSeenAt"]) ?: "never"})",
                        )
                    }
                    null
                }

                else -> {
                    System.err.println("No device '$device'. Run `thoryn devices list` to see yours.")
                    null
                }
            }
        }
    }

    companion object {

        val LIST_HEADERS: List<String> = listOf(
            "NAME", "ID", "STATE", "SESSIONS", "LAST SEEN", "WORKSPACES", "CLIENT", "NETWORKS",
        )

        /** The `devices` array of a `GET /account/devices` response — see the unwrap note above. */
        fun devicesOf(body: JsonNode): List<JsonNode> =
            body["devices"]?.takeIf { it.isArray }?.toList() ?: emptyList()

        /**
         * The same devices as a bare array, which is what every output format renders: the table
         * rows come from it, and `--output json|yaml` prints the array rather than the hub's
         * `{devices:[…]}` wrapper, so a script can pipe it straight into `jq '.[]'`.
         */
        fun devicesArray(body: JsonNode): JsonNode =
            mapper.createArrayNode().apply { devicesOf(body).forEach { add(it) } }

        private val mapper = ObjectMapper()

        fun deviceRow(device: JsonNode): List<Any?> = listOf(
            device.textOrNull("name") ?: "(unregistered)",
            device.textOrNull("id") ?: "-",
            state(device),
            sessionCount(device),
            // SSO-3275 — NOT `asString()`: the hub declares `lastSeenAt` as an `Instant`, and the
            // released CLI printed whatever that hub's Jackson put on the wire — live, an epoch
            // (`LAST SEEN 1789848418`), which answers nobody's question. [Timestamps] decides the
            // rendering, and accepts every shape an `Instant` serialises to.
            Timestamps.render(device["lastSeenAt"]) ?: "-",
            workspaces(device),
            device.textOrNull("clientId") ?: "-",
            device["recentNetworks"]?.takeIf { it.isArray }?.joinToString(", ") { it.asString() } ?: "-",
        )

        /**
         * SSO-3271 — what the device is doing, as the hub reports it.
         *
         * Read tolerantly: an older hub sends no `state`, and the column then falls back to what
         * SSO-3228's fields alone can say — revoked, unregistered, or registered. It never guesses
         * `signed_in`, because registration is not a session and claiming otherwise is exactly the
         * confusion this field exists to end.
         */
        private fun state(device: JsonNode): String = device.textOrNull("state") ?: when {
            device.textOrNull("revokedAt") != null -> "revoked"
            device["registered"]?.takeIf { !it.isNull }?.asBoolean() == false -> "unregistered"
            else -> "registered"
        }

        /** The live sessions bound to this device's key; `-` when the hub does not report them. */
        private fun sessionCount(device: JsonNode): String =
            device["sessions"]?.takeIf { !it.isNull }?.get("active")?.takeIf { !it.isNull }?.asInt()?.toString()
                ?: "-"

        /** Which workspace and plane each live session belongs to (`acme/production`). */
        private fun workspaces(device: JsonNode): String {
            val entries = device["sessions"]?.takeIf { !it.isNull }
                ?.get("workspaces")?.takeIf { it.isArray }
                ?: return "-"
            val rendered = entries.mapNotNull { entry ->
                val tenant = entry.textOrNull("tenantSlug") ?: return@mapNotNull null
                val environment = entry.textOrNull("environmentSlug")
                if (environment == null) tenant else "$tenant/$environment"
            }
            return rendered.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: "-"
        }

        /**
         * A string field, or null when it is absent **or JSON `null`**.
         *
         * `node["x"]` answers a `NullNode` for an explicit `null`, which is NOT Kotlin's null — so a
         * bare `node["x"]?.asString()` reads a JSON `null` as a present value. Every field this
         * command reads can legitimately be null in the hub's response (an unregistered key has no
         * `id` and no `name`, a live device has no `revokedAt`), and getting it wrong was not
         * cosmetic: it made an unregistered key look revoked, and sent a revoke to
         * `/account/devices/null/revoke`.
         */
        private fun JsonNode.textOrNull(field: String): String? =
            this[field]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotEmpty() }
    }
}
