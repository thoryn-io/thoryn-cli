package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import java.time.Instant
import java.util.concurrent.Callable

/**
 * `thoryn whoami` — SSO-2860 (CLI maturity) — show who / where you are signed in as, offline.
 *
 * Reads the locally-stored token (no network) and surfaces the identity it carries: the subject,
 * tenant (`tnt`), client, granted scopes, the hub + gateway this session authenticated against, and
 * the token's expiry with a human status (valid / expires-in / EXPIRED). The `sub` and `tnt` come
 * from the access token's (unverified, display-only) claims via [JwtClaims]; everything else is on
 * the [com.devnow.thoryn.cli.auth.Tokens] record. The raw token is never printed.
 *
 * SSO-3271 adds `--check`, the one online part: it asks the hub for THIS device's `state` and the
 * sessions bound to its key. Opt-in, because offline is a promise worth keeping — and because it is
 * the only way to learn what the local token cannot say. A device revoked from another machine
 * leaves an access token that still validates locally until it expires, so `tokenStatus: valid`
 * beside `deviceState: revoked` is both possible and exactly what you need to see.
 *
 * - **1 (not signed in)** when there is no token — run `thoryn login`.
 * - **0** with the identity in the requested `--output` format (`table` key/value, `json`, `yaml`).
 */
@Command(
    name = "whoami",
    description = ["Show the signed-in identity: subject, tenant, client, scopes, and token expiry (offline)."],
    mixinStandardHelpOptions = true,
)
class WhoamiCommand : Callable<Int> {

    @Option(names = ["--output"])
    var outputRaw: String? = null

    /**
     * SSO-3271 — ask the hub what it thinks of THIS device, instead of answering from the local
     * token alone.
     *
     * Opt-in because everything else here is offline and that is a promise worth keeping. It is
     * also the only way to learn the one thing the local token cannot tell you: a device revoked
     * from elsewhere leaves an access token that still looks perfectly valid until it expires, so
     * `tokenStatus: valid` and `deviceState: revoked` is a real and important combination.
     */
    @Option(
        names = ["--check"],
        description = ["Ask the hub for this device's state and sessions (the only online part of whoami)."],
    )
    var check: Boolean = false

    @Option(
        names = ["--hub"],
        description = ["With --check: override the hub base URL (default: the hub recorded at `thoryn login`)."],
        defaultValue = ThorynConfig.DEFAULT_HUB,
    )
    var hub: String = ThorynConfig.DEFAULT_HUB

    override fun call(): Int {
        val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
        val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN

        val claims = JwtClaims.of(tokens.accessToken)
        val expEpoch = tokens.expiresAtEpochSecond ?: claims["exp"]?.asLong()
        val (expiresAtIso, status) = tokenStatus(expEpoch)
        // SSO-2867 — since SSO-2863 a `workspace switch` no longer rewrites the base token (its `tnt`
        // stays the login tenant); it records a SelectedWorkspace that commands exchange into per call.
        // Surface it so `tenant` (the base token) and the workspace you're actually operating in agree.
        val selectedWorkspace = runCatching { SelectedWorkspaceStore().read() }.getOrNull()
        val activeWorkspace = selectedWorkspace?.slug
        // SSO-2870 — the environment the CLI is targeting inside that workspace (a sandbox, or
        // production when unset). Rides on every request as X-Thoryn-Environment.
        val activeEnvironment = selectedWorkspace?.environmentSlug
        // SSO-3199 — the installation's DPoP key (RFC 9449) and whether THIS token is bound to it.
        // Only the PUBLIC thumbprint is ever surfaced: the private key never leaves the secure store.
        val keyThumbprint = runCatching { Dpop.session()?.thumbprint }.getOrNull()
        val boundThumbprint = claims["cnf"]?.get("jkt")?.asString()
        // SSO-3228 — the name this machine's key is registered under, recorded at login. Absent for
        // a session whose token is not bound, or one signed in by a CLI that did not register.
        val deviceName = tokens.deviceName?.takeIf { it.isNotBlank() }
        // SSO-3227 — WHICH protection class that key has. The difference between "this token cannot be
        // replayed from another machine" and "…and malware running as me cannot sign proofs either" is
        // exactly the key class, so it is reported rather than left to be assumed.
        val keyClassLine = runCatching { dpopKeyClass() }.getOrNull()

        val node = mapper.createObjectNode().apply {
            put("subject", claims["sub"]?.asString())
            put("tenant", claims["tnt"]?.asString())
            activeWorkspace?.let { put("activeWorkspace", it) }
            activeEnvironment?.let { put("activeEnvironment", it) }
            put("clientId", claims["client_id"]?.asString() ?: claims["azp"]?.asString())
            claims["name"]?.asString()?.let { put("name", it) }
            claims["email"]?.asString()?.let { put("email", it) }
            put("issuer", tokens.issuer)
            put("gateway", tokens.gateway)
            put("scopes", tokens.scope ?: claims["scope"]?.asString())
            put("tokenExpiresAt", expiresAtIso)
            put("tokenStatus", status)
            // SSO-3199 — RFC 9449. `dpopKeyThumbprint` is this installation's `jkt`; `dpopBound` says
            // whether the stored access token is sender-constrained to it (`cnf.jkt`, minted by the hub).
            keyThumbprint?.let { put("dpopKeyThumbprint", it) }
            // SSO-3227 — the key's protection class, plus why anything stronger was passed over.
            keyClassLine?.let { put("dpopKeyClass", it) }
            put("dpopBound", dpopBinding(tokens.tokenType, boundThumbprint, keyThumbprint))
            // SSO-3228 — which DEVICE this is, so `thoryn devices revoke <name>` names something the
            // user has already seen. `id` is what a revoke takes when two machines share a name.
            deviceName?.let { put("device", it) }
            tokens.deviceId?.takeIf { it.isNotBlank() }?.let { put("deviceId", it) }
        }

        // SSO-3271 — the hub's view of this device, when asked for. Everything above stayed offline.
        if (check) {
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)
            try {
                val mine = thisDevice(client.listDevices(), boundThumbprint ?: keyThumbprint, deviceName)
                if (mine == null) {
                    // Honest rather than convenient: the hub knows no device for this key. Usually a
                    // session that predates device registration; occasionally a key registered on
                    // another workspace. Either way, inventing a state would be worse than saying so.
                    node.put("deviceState", "unknown (the hub has no device for this installation's key)")
                } else {
                    val deviceState = mine.textOrNull("state") ?: "unknown"
                    node.put("deviceState", deviceState)
                    mine["sessions"]?.takeIf { !it.isNull }?.let { node.set("deviceSessions", it) }
                    // SSO-3279 — `deviceState: revoked` beside `tokenStatus: valid` is the whole
                    // reason `--check` exists, and on its own it reads like a contradiction. Say what
                    // it means for the person in front of the terminal: the token in the keychain
                    // goes on being accepted until it expires, and the renewal after that is refused.
                    if (deviceState == DEVICE_STATE_REVOKED) node.put("deviceNotice", revokedNotice(expiresAtIso))
                }
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                return CommandSupport.renderRequestFailure(ex, hub)
            }
        }

        CommandSupport.emitRecord(format, node, { n: JsonNode ->
            listOf(
                "subject" to n["subject"]?.asString(),
                "tenant" to n["tenant"]?.asString(),
                "activeWorkspace" to n["activeWorkspace"]?.asString(),
                "activeEnvironment" to n["activeEnvironment"]?.asString(),
                "clientId" to n["clientId"]?.asString(),
                "name" to n["name"]?.asString(),
                "email" to n["email"]?.asString(),
                "issuer" to n["issuer"]?.asString(),
                "gateway" to n["gateway"]?.asString(),
                "scopes" to n["scopes"]?.asString(),
                "tokenExpiresAt" to n["tokenExpiresAt"]?.asString(),
                "tokenStatus" to n["tokenStatus"]?.asString(),
                "dpopKeyThumbprint" to n["dpopKeyThumbprint"]?.asString(),
                "dpopKeyClass" to n["dpopKeyClass"]?.asString(),
                "dpopBound" to n["dpopBound"]?.asString(),
                "device" to n["device"]?.asString(),
                "deviceId" to n["deviceId"]?.asString(),
                "deviceState" to n["deviceState"]?.asString(),
                "deviceSessions" to n["deviceSessions"]?.let(::describeSessions),
            ).filter { it.second != null }
        })
        // SSO-3279 — the notice is a SENTENCE, and a key/value row is the wrong shape for one: it
        // would wrap inside a column and read as another field. So the table prints it after the
        // record, marked, on stderr — while `--output json|yaml` carries it as `deviceNotice`, a
        // field a script can branch on rather than a line it would have to match on text.
        if (format == OutputFormat.TABLE) {
            node["deviceNotice"]?.takeIf { !it.isNull }?.asString()?.let { System.err.println("Notice: $it") }
        }
        return CommandSupport.EXIT_OK
    }

    /**
     * SSO-3279 — what a revoked device means for THIS session, in one sentence.
     *
     * Deliberately not an error and deliberately not an exit code: nothing has failed yet. The
     * access token in the keychain still validates — a resource server checks its signature and
     * expiry, not the device register — so every command keeps working until it expires. What is
     * already gone is the renewal: the refresh is bound to a key the hub now refuses.
     */
    private fun revokedNotice(expiresAtIso: String?): String =
        "this device is revoked — the current access token is accepted until " +
            "${expiresAtIso ?: "it expires"}; the next refresh will be refused. " +
            "Run `thoryn login` to register a new device."

    /**
     * The entry in `GET /account/devices` that is THIS installation, matched by key thumbprint.
     *
     * The thumbprint is the identity that matters: it is what the token is bound to and what a
     * revoke acts on. The locally-recorded device NAME is only a fallback for a session whose token
     * is not bound yet (pre-cutover), and it is deliberately only used when it matches exactly one
     * device — two machines may share a name, and naming the wrong one here would be a lie about
     * which machine is signed in.
     */
    private fun thisDevice(body: JsonNode, thumbprint: String?, deviceName: String?): JsonNode? {
        val devices = DevicesCommand.devicesOf(body)
        thumbprint?.let { jkt -> devices.firstOrNull { it.textOrNull("jkt") == jkt }?.let { return it } }
        return deviceName?.let { name -> devices.filter { it.textOrNull("name") == name }.singleOrNull() }
    }

    /** `2 live (acme/production)` — the one-line form of the `sessions` object for the table view. */
    private fun describeSessions(sessions: JsonNode): String {
        val active = sessions["active"]?.takeIf { !it.isNull }?.asInt() ?: return "unknown"
        val workspaces = sessions["workspaces"]?.takeIf { it.isArray }
            ?.mapNotNull { entry ->
                val tenant = entry.textOrNull("tenantSlug") ?: return@mapNotNull null
                entry.textOrNull("environmentSlug")?.let { "$tenant/$it" } ?: tenant
            }
            .orEmpty()
        return if (workspaces.isEmpty()) "$active live" else "$active live (${workspaces.joinToString(", ")})"
    }

    /** A string field, or null when absent or JSON `null` — see `DevicesCommand`'s note on `NullNode`. */
    private fun JsonNode.textOrNull(field: String): String? =
        this[field]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotEmpty() }

    /**
     * SSO-3227 — one line describing where the DPoP private key lives, and — when it is not in the
     * secure element — why not. The "why not" is the useful half: *"software key in the OS keychain
     * (secure element: this binary is not code-signed …)"* tells an operator what to fix, where a bare
     * "software" tells them nothing.
     */
    private fun dpopKeyClass(): String {
        val resolution = Dpop.resolution()
        val active = resolution.keyClass
        val label = "${active.wireValue} — ${active.description}"
        val strongerSkipped = resolution.skipped.firstOrNull() ?: return label
        return "$label (${strongerSkipped.first.wireValue} unavailable: ${strongerSkipped.second})"
    }

    /**
     * SSO-3199 — how the stored access token relates to this installation's DPoP key (RFC 9449 §6.1).
     *
     * `no` is the expected answer until the hub flips the `cli` client to `dpop_required`: a token
     * minted without a bound `cnf.jkt` is presented as a plain bearer, which is why shipping the proof
     * ahead of the hub change is safe. A `cnf.jkt` that does NOT match the local key means the token
     * was minted by another installation (or the key was rotated since) — it will be refused once the
     * resource servers enforce the binding, so say so rather than printing a bare "yes".
     */
    private fun dpopBinding(tokenType: String, boundThumbprint: String?, keyThumbprint: String?): String = when {
        boundThumbprint == null && tokenType.equals("DPoP", ignoreCase = true) ->
            "yes (token_type=DPoP; no cnf.jkt in the access token)"
        boundThumbprint == null -> "no (bearer token — the hub does not bind this client's tokens yet)"
        keyThumbprint == null -> "yes (cnf.jkt $boundThumbprint; local key unavailable)"
        boundThumbprint == keyThumbprint -> "yes (cnf.jkt matches this installation's key)"
        else -> "MISMATCH (cnf.jkt $boundThumbprint is not this installation's key — run `thoryn login`)"
    }

    private fun tokenStatus(expEpoch: Long?): Pair<String?, String> {
        if (expEpoch == null) return null to "unknown"
        val remaining = expEpoch - Instant.now().epochSecond
        val iso = Instant.ofEpochSecond(expEpoch).toString()
        return if (remaining <= 0) {
            iso to "EXPIRED — run `thoryn login`"
        } else {
            iso to "valid (expires in ${humanDuration(remaining)})"
        }
    }

    private fun humanDuration(seconds: Long): String {
        val h = seconds / 3600
        val m = (seconds % 3600) / 60
        val s = seconds % 60
        return when {
            h > 0 -> "${h}h ${m}m"
            m > 0 -> "${m}m ${s}s"
            else -> "${s}s"
        }
    }

    private companion object {
        val mapper = ObjectMapper()

        /** SSO-3271's wire value for a device the hub refuses — the one state that needs explaining. */
        const val DEVICE_STATE_REVOKED = "revoked"
    }
}
