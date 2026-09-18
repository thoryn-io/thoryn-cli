package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.JwtClaims
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

        val node: JsonNode = mapper.createObjectNode().apply {
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
            put("dpopBound", dpopBinding(tokens.tokenType, boundThumbprint, keyThumbprint))
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
                "dpopBound" to n["dpopBound"]?.asString(),
            ).filter { it.second != null }
        })
        return CommandSupport.EXIT_OK
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
    }
}
