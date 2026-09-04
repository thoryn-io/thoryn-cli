package com.devnow.thoryn.cli.cmd

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
        val activeWorkspace = runCatching { SelectedWorkspaceStore().read() }.getOrNull()?.slug

        val node: JsonNode = mapper.createObjectNode().apply {
            put("subject", claims["sub"]?.asString())
            put("tenant", claims["tnt"]?.asString())
            activeWorkspace?.let { put("activeWorkspace", it) }
            put("clientId", claims["client_id"]?.asString() ?: claims["azp"]?.asString())
            claims["name"]?.asString()?.let { put("name", it) }
            claims["email"]?.asString()?.let { put("email", it) }
            put("issuer", tokens.issuer)
            put("gateway", tokens.gateway)
            put("scopes", tokens.scope ?: claims["scope"]?.asString())
            put("tokenExpiresAt", expiresAtIso)
            put("tokenStatus", status)
        }

        CommandSupport.emitRecord(format, node, { n: JsonNode ->
            listOf(
                "subject" to n["subject"]?.asString(),
                "tenant" to n["tenant"]?.asString(),
                "activeWorkspace" to n["activeWorkspace"]?.asString(),
                "clientId" to n["clientId"]?.asString(),
                "name" to n["name"]?.asString(),
                "email" to n["email"]?.asString(),
                "issuer" to n["issuer"]?.asString(),
                "gateway" to n["gateway"]?.asString(),
                "scopes" to n["scopes"]?.asString(),
                "tokenExpiresAt" to n["tokenExpiresAt"]?.asString(),
                "tokenStatus" to n["tokenStatus"]?.asString(),
            ).filter { it.second != null }
        })
        return CommandSupport.EXIT_OK
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
