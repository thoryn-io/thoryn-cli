package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.auth.AuthorizationCodeException
import com.devnow.thoryn.cli.auth.AuthorizationCodeFlow
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.DpopCapability
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.LoopbackRedirectServer
import com.devnow.thoryn.cli.auth.LoopbackTimeoutException
import com.devnow.thoryn.cli.auth.PkceUtil
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.BrowserLauncher
import com.devnow.thoryn.cli.cmd.LoginCommand
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.PrintStream
import java.time.Duration
import java.util.concurrent.Callable

/**
 * `thoryn operator login` (SSO-3356) — sign in to the operator plane.
 *
 * Authorization Code + PKCE on a literal loopback redirect (RFC 8252 §7.3), exactly like
 * `thoryn login`, but:
 *
 *  - on the platform HOME workspace (`--workspace thoryn`, the default) — operator standing is the
 *    `platform:thoryn#operator` grant, which exists only there;
 *  - with the operator client `thoryn-operator` (oathy hub V174: public, PKCE-mandatory,
 *    `http://127.0.0.1/callback` + `http://[::1]/callback`, matched port-agnostically — SSO-2801);
 *  - requesting the operator scopes ([OperatorSession.DEFAULT_SCOPE]);
 *  - with `prompt=login`, so an existing browser session on the home (perhaps a password sign-in)
 *    is not silently reused: the hub mints an `admin:*` scope only to a PASSKEY sign-in
 *    (`OperatorScopeRequestValidator`), so the operator must actually perform one;
 *  - storing the result in the OPERATOR slot ([TokenStoreFactory.operator]), never over the
 *    customer session.
 *
 * DPoP follows `thoryn login`: a proof rides the token request (and `dpop_jkt` the authorize request)
 * when the hub advertises DPoP. The hub binds only for a client that participates — `thoryn-operator`
 * does not today (neither `dpop_required` nor `dpop_allowed`, not in the cutover list), so it ignores
 * both and issues a Bearer token; should the client ever be flipped, the token comes back `DPoP` and
 * the operator commands present it with a proof whose `htu` is the port-forward URL.
 *
 * No refresh token: the operator client does not issue one (hub V174), and the access token lives 15
 * minutes. Re-run this command when it expires.
 */
@Command(
    name = "login",
    description = [
        "Sign in as a Thoryn operator: a PASSKEY sign-in on the `thoryn` home workspace with the operator",
        "client. Stored separately from your `thoryn login` session, which is left untouched.",
    ],
    mixinStandardHelpOptions = true,
)
class OperatorLoginCommand : Callable<Int> {

    @Option(
        names = ["--issuer", "--hub"],
        description = [
            "Platform BASE ISSUER, e.g. https://auth.stg.thoryn.org. Default: \$${ThorynConfig.ISSUER_ENV}, " +
                "else the platform of your previous operator sign-in, else of your `thoryn login` session.",
        ],
    )
    var issuerOption: String? = null

    @Option(
        names = ["--workspace"],
        description = ["The platform home workspace to sign in on (default: \${DEFAULT-VALUE})."],
        defaultValue = OperatorSession.HOME_WORKSPACE,
    )
    var workspace: String = OperatorSession.HOME_WORKSPACE

    @Option(
        names = ["--client-id"],
        description = ["The operator OAuth client (default: \${DEFAULT-VALUE})."],
        defaultValue = OperatorSession.CLIENT_ID,
    )
    var clientId: String = OperatorSession.CLIENT_ID

    @Option(
        names = ["--scope"],
        description = ["Space-separated scopes to request (default: \${DEFAULT-VALUE})."],
        defaultValue = OperatorSession.DEFAULT_SCOPE,
    )
    var scope: String = OperatorSession.DEFAULT_SCOPE

    @Option(
        names = ["--status"],
        description = ["Print the operator session's status and exit. Does not sign in."],
    )
    var statusOnly: Boolean = false

    @Option(
        names = ["--dev"],
        description = ["Allow an http:// issuer for a non-loopback host (local development only)."],
    )
    var devMode: Boolean = false

    internal var out: PrintStream = System.out
    internal var err: PrintStream = System.err

    override fun call(): Int {
        if (statusOnly) return printStatus()

        val store = OperatorSession.store()
        val base = ThorynConfig.resolveHubBase(
            explicit = issuerOption,
            previousSessionIssuer = runCatching { store.read() }.getOrNull()?.issuer
                ?: runCatching { TokenStoreFactory.default().read() }.getOrNull()?.issuer,
        )
        if (base == null) {
            err.println(
                "Error: no Thoryn platform selected. Name it once, e.g.\n" +
                    "    thoryn operator login --issuer https://auth.stg.thoryn.org\n" +
                    "or export ${ThorynConfig.ISSUER_ENV}.",
            )
            return EXIT_USAGE
        }
        val slug = workspace.trim().ifEmpty { OperatorSession.HOME_WORKSPACE }
        if (slug != OperatorSession.HOME_WORKSPACE) {
            err.println(
                "Note: operator standing lives on the platform home '${OperatorSession.HOME_WORKSPACE}'; " +
                    "signing in on '$slug' will be refused unless that is this deployment's home workspace.",
            )
        }
        val issuer = ThorynConfig.tenantIssuer(base.url, slug)
        return runLoopback(issuer, slug)
    }

    private fun runLoopback(issuer: String, slug: String): Int {
        val verifier = PkceUtil.newCodeVerifier()
        val state = PkceUtil.newState()
        val server = LoopbackRedirectServer()
        return try {
            server.start()
            val redirectUri = server.redirectUri
            val parameters = authorizeParameters(
                clientId = clientId,
                redirectUri = redirectUri,
                scope = scope.trim(),
                codeChallenge = PkceUtil.codeChallenge(verifier),
                state = state,
                dpopJkt = dpopJkt(issuer),
            )
            val carried = LoginCommand.carryAuthorizeRequest(issuer, clientId, parameters, clientSecret = null, err = err)
                ?: return EXIT_LOGIN_FAILED

            out.println("Opening your browser to sign in as an operator on '$slug' ($issuer).")
            out.println()
            out.println("    A PASSKEY sign-in is required. Choose your passkey — not a password, not a")
            out.println("    recovery code. The hub issues operator scopes only to a passkey sign-in.")
            out.println()
            out.println("If the browser doesn't open, visit this URL:")
            out.println()
            out.println("    ${carried.authorizeUrl}")
            out.println()
            browser(carried.authorizeUrl)
            out.println("Waiting for the sign-in redirect (${LoginCommand.humanWait(carried.wait)})…")

            val params = server.awaitCallback(carried.wait)
            params["error"]?.let { error ->
                reportAuthorizeError(error, params["error_description"])
                return EXIT_LOGIN_FAILED
            }
            if (params["state"] != state) {
                err.println("Sign-in failed: state mismatch — discarding the callback (possible CSRF).")
                return EXIT_LOGIN_FAILED
            }
            val code = params["code"]
            if (code.isNullOrBlank()) {
                err.println("Sign-in failed: the authorization server returned no code.")
                return EXIT_LOGIN_FAILED
            }
            val tokens = AuthorizationCodeFlow(
                issuer = issuer,
                clientId = clientId,
                clientSecret = null, // public native client — PKCE is the binding
                redirectUri = redirectUri,
                codeVerifier = verifier,
                sender = sender(),
                devMode = devMode,
            ).exchange(code)
            val session = tokens.copy(issuer = issuer, clientId = clientId, workspace = slug, gateway = null)
            OperatorSession.store().write(session)
            reportSignedIn(session)
            EXIT_OK
        } catch (e: LoopbackTimeoutException) {
            err.println("Sign-in timed out: ${e.message}")
            EXIT_LOGIN_FAILED
        } catch (e: AuthorizationCodeException) {
            err.println("Sign-in failed: ${e.message}")
            EXIT_LOGIN_FAILED
        } finally {
            server.close()
        }
    }

    private fun reportAuthorizeError(error: String, description: String?) {
        val desc = description?.takeIf { it.isNotBlank() }?.let { " — $it" }.orEmpty()
        err.println("Sign-in failed: $error$desc")
        when (error) {
            // The hub refuses an admin:* scope request identically for "no operator standing" and "not a
            // passkey sign-in" (OperatorScopeRequestValidator — deliberately indistinguishable on the wire).
            "invalid_scope" -> err.println(
                "The hub refused the operator scopes. Either this identity holds no operator standing in this " +
                    "environment (appointed only by the deployment value productApi.operatorPlatformSubjects), or " +
                    "the sign-in did not use a passkey. Run `${OperatorSession.LOGIN_HINT}` again and choose your passkey.",
            )
            "unauthorized_client", "invalid_client" -> err.println(
                "The operator client '$clientId' is not usable on this workspace. It exists only on the platform " +
                    "home '${OperatorSession.HOME_WORKSPACE}' (oathy hub V174).",
            )
            else -> Unit
        }
    }

    private fun reportSignedIn(tokens: Tokens) {
        val claims = JwtClaims.of(tokens.accessToken)
        out.println()
        out.println("Signed in as an operator (session stored separately from `thoryn login`).")
        claims["sub"]?.asString()?.let { out.println("Subject: $it") }
        tokens.scope?.let { out.println("Scopes:  $it") }
        tokens.expiresAtEpochSecond?.let {
            val mins = ((it - System.currentTimeMillis() / 1000) / 60).coerceAtLeast(0)
            out.println("Expires: in ${mins}m (no refresh — sign in again when it expires)")
        }
        val granted = tokens.scope?.split(' ')?.toSet().orEmpty()
        val missing = scope.split(' ').filter { it.startsWith("admin:") && it !in granted }
        if (tokens.scope != null && missing.isNotEmpty()) {
            err.println("Warning: the token does not carry ${missing.joinToString(", ")} — the matching operator commands will be refused.")
        }
        if (claims.has("amr") && !OperatorSession.usedPasskey(tokens.accessToken)) {
            err.println(
                "Warning: this sign-in did not use a passkey (amr=${claims["amr"]}); every operator call will be " +
                    "refused with operator_passkey_required. Sign in again and choose your passkey.",
            )
        }
        out.println()
        out.println("Next: in another terminal run `${OperatorSession.PORT_FORWARD_COMMAND}`, then e.g.")
        out.println("    thoryn operator custom-domain status <workspace>")
    }

    private fun printStatus(): Int {
        val tokens = runCatching { OperatorSession.store().read() }.getOrNull()
        if (tokens == null) {
            out.println("Not signed in as an operator. Run `${OperatorSession.LOGIN_HINT}`.")
            return 1
        }
        val now = System.currentTimeMillis() / 1000
        val exp = tokens.expiresAtEpochSecond
        when {
            exp == null -> out.println("Operator session present (expiry unknown).")
            exp <= now -> out.println("Operator session EXPIRED. Run `${OperatorSession.LOGIN_HINT}`.")
            else -> out.println("Operator session valid for ${(exp - now) / 60}m.")
        }
        tokens.issuer?.let { out.println("Issuer:  $it") }
        JwtClaims.of(tokens.accessToken)["sub"]?.asString()?.let { out.println("Subject: $it") }
        tokens.scope?.let { out.println("Scopes:  $it") }
        out.println("Passkey: ${if (OperatorSession.usedPasskey(tokens.accessToken)) "yes" else "no (operator calls will be refused)"}")
        return if (exp != null && exp <= now) 1 else 0
    }

    /** Same gate as `thoryn login`: name our DPoP key only when the hub advertises DPoP. */
    private fun dpopJkt(issuer: String): String? =
        if (DpopCapability.advertisedBy(issuer.trimEnd('/'))) Dpop.session(provision = true)?.thumbprint else null

    companion object {
        const val EXIT_OK: Int = 0
        const val EXIT_USAGE: Int = 64
        const val EXIT_LOGIN_FAILED: Int = 72

        /** Test seam — opens the authorize URL. */
        internal var browser: (String) -> Unit = { BrowserLauncher.open(it) }

        /** Test seam — the token-endpoint transport (DPoP-proofed when the hub advertises it). */
        internal var sender: () -> HttpSender = { Dpop.sender(Duration.ofSeconds(10)) }

        /**
         * The authorize parameters: `thoryn login`'s own set ([LoginCommand.authorizeParameters] —
         * PKCE S256, state, `dpop_jkt`) plus `prompt=login` (OIDC Core §3.1.2.1), so the operator
         * performs a fresh sign-in where they can pick the passkey instead of the hub reusing an
         * existing — possibly password — session on the home workspace.
         */
        internal fun authorizeParameters(
            clientId: String,
            redirectUri: String,
            scope: String,
            codeChallenge: String,
            state: String,
            dpopJkt: String?,
        ): List<Pair<String, String>> =
            LoginCommand.authorizeParameters(clientId, redirectUri, scope, codeChallenge, state, dpopJkt) +
                ("prompt" to "login")
    }
}
