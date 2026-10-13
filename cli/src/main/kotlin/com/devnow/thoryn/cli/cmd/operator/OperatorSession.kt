package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.TokenStore
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import java.io.PrintStream
import java.net.InetAddress
import java.net.URI

/**
 * SSO-3356 — the operator session and the rules around it, shared by `thoryn operator …`.
 *
 * The operator plane (oathy ADR `2026-09-18-operator-workspace-ownership-transfer.md` §3 / §4, amended
 * 2026-09-26) is a different trust plane from the customer plane: `admin:*` scopes, minted by the hub
 * only to a PASSKEY sign-in of an identity that holds operator standing, on the dedicated public native
 * client `thoryn-operator` in the `thoryn` home workspace. Its session is therefore kept in its own
 * token-store slot ([TokenStoreFactory.operator]) and never mixed with the `thoryn login` session.
 */
object OperatorSession {

    /** The operator client seeded by oathy hub V174 under the `thoryn` home (public, PKCE, loopback). */
    const val CLIENT_ID: String = "thoryn-operator"

    /** The platform home workspace — the only place operator standing (`platform:thoryn#operator`) lives. */
    const val HOME_WORKSPACE: String = "thoryn"

    /** `admin:custom-domains.manage` — the entitlement toggle, claim / verify / remove (oathy hub V185). */
    const val SCOPE_CUSTOM_DOMAINS_MANAGE: String = "admin:custom-domains.manage"

    /** `admin:custom-domains.read` — the status read (manage also satisfies it). */
    const val SCOPE_CUSTOM_DOMAINS_READ: String = "admin:custom-domains.read"

    /**
     * What `thoryn operator login` requests by default: exactly the operator scopes the CLI has
     * commands for. The client also holds `admin:workspaces.transfer` / `.retire` and
     * `admin:devices.revoke`, but nothing in the CLI calls those surfaces yet, and an operator token
     * should carry no power the operator is not about to use (pass `--scope` to ask for more).
     */
    const val DEFAULT_SCOPE: String = "openid $SCOPE_CUSTOM_DOMAINS_MANAGE $SCOPE_CUSTOM_DOMAINS_READ"

    /** The `kubectl port-forward` the operator runs to reach the hub (`/admin` is on no public address). */
    const val DEFAULT_HUB_URL: String = "http://localhost:18080"

    const val PORT_FORWARD_COMMAND: String = "kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080"

    /** RFC 8176 `amr` values the hub accepts as a passkey sign-in (oathy `OperatorPlane.PASSKEY_AMR`). */
    val PASSKEY_AMR: Set<String> = setOf("swk", "hwk", "webauthn")

    const val LOGIN_HINT: String = "thoryn operator login"

    /** Test seam — the operator slot of the token store. */
    internal var storeFactory: () -> TokenStore = { TokenStoreFactory.operator() }

    fun store(): TokenStore = storeFactory()

    /**
     * The stored operator session, or null after printing why it cannot be used. Operator tokens have
     * no refresh token (hub V174 — an operator re-earns the session with a passkey), so an expired one
     * simply means signing in again.
     */
    fun readUsable(err: PrintStream = System.err, now: Long = System.currentTimeMillis() / 1000): Tokens? {
        val tokens = runCatching { store().read() }.getOrNull()
        if (tokens == null) {
            err.println("Not signed in as an operator. Run `$LOGIN_HINT` (a passkey sign-in is required).")
            return null
        }
        val exp = tokens.expiresAtEpochSecond
        if (exp != null && exp <= now) {
            err.println(
                "Your operator session has expired (operator tokens last 15 minutes and are not renewed). " +
                    "Run `$LOGIN_HINT` and sign in with your passkey again.",
            )
            return null
        }
        return tokens
    }

    /** True when the token's (display-only, unverified) `amr` claim names a passkey. */
    fun usedPasskey(accessToken: String?): Boolean {
        val amr = JwtClaims.of(accessToken)["amr"] ?: return false
        val values = if (amr.isArray) amr.toList().mapNotNull { it.asString() } else listOfNotNull(amr.asString())
        return values.any { it in PASSKEY_AMR }
    }
}

/**
 * SSO-3356 — where operator calls may be sent.
 *
 * `/admin` is served on no public address; an operator reaches the hub through `kubectl port-forward`
 * (or, in-cluster, the hub Service name). Sending an operator token to a public host would put an
 * `admin:*` credential on the internet for a request the edge refuses anyway — so the CLI refuses
 * first. Allowed: loopback (`localhost`, `127.0.0.0/8`, `::1`), a single-label host (`thoryn-hub`), and
 * a Kubernetes Service name (`*.svc`, `*.svc.cluster.local`). Anything else is refused.
 */
object OperatorHubTarget {

    /** Null when [url] is an acceptable operator target, otherwise the reason it is refused. */
    fun refusal(url: String): String? {
        val uri = runCatching { URI(url.trim()) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val host = uri?.host?.lowercase()?.removePrefix("[")?.removeSuffix("]")
        if (uri == null || host.isNullOrBlank() || (scheme != "http" && scheme != "https")) {
            return "--hub-url must be an http(s) URL such as ${OperatorSession.DEFAULT_HUB_URL} (was '$url')."
        }
        if (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/") {
            return "--hub-url must be the hub's origin with no path (was '$url')."
        }
        if (isPrivateTarget(host)) return null
        return "Refusing to send an operator token to '$host'. The hub serves /admin on no public address; " +
            "reach it through `${OperatorSession.PORT_FORWARD_COMMAND}` and use --hub-url ${OperatorSession.DEFAULT_HUB_URL}."
    }

    internal fun isPrivateTarget(host: String): Boolean {
        if (host == "localhost") return true
        if (!host.contains('.') && !host.contains(':')) return true // a single-label Service name, e.g. thoryn-hub
        if (host.endsWith(".svc") || host.endsWith(".svc.cluster.local")) return true
        // IP literals only — never resolve a name here (a DNS answer is not a reason to trust a host).
        val looksLikeIp = host.contains(':') || host.all { it.isDigit() || it == '.' }
        if (!looksLikeIp) return false
        return runCatching { InetAddress.getByName(host).isLoopbackAddress }.getOrDefault(false)
    }
}
