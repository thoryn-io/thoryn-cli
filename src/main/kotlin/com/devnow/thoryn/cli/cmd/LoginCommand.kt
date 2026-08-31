package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.AuthorizationCodeException
import com.devnow.thoryn.cli.auth.AuthorizationCodeFlow
import com.devnow.thoryn.cli.auth.ClientCredentialsException
import com.devnow.thoryn.cli.auth.ClientCredentialsFlow
import com.devnow.thoryn.cli.auth.DeviceCodeException
import com.devnow.thoryn.cli.auth.DeviceCodeFlow
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.IssuerUrlValidationException
import com.devnow.thoryn.cli.auth.IssuerUrlValidator
import com.devnow.thoryn.cli.auth.LoopbackRedirectServer
import com.devnow.thoryn.cli.auth.LoopbackTimeoutException
import com.devnow.thoryn.cli.auth.PkceUtil
import com.devnow.thoryn.cli.auth.ScopeRegistry
import com.devnow.thoryn.cli.auth.TokenStore
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.net.http.HttpClient
import java.time.Duration
import java.util.concurrent.Callable

/**
 * `thoryn login` — three sign-in modes:
 *
 *  - **Authorization Code + PKCE with loopback redirect** (default, SSO-2820) — the
 *    interactive browser flow (RFC 8252 native app + RFC 7636 PKCE): opens the browser, captures the
 *    redirect on a single-shot literal-loopback listener, and redeems the code for tokens.
 *  - **Device-code (RFC 8628)** via `--device-code` — interactive, but on a
 *    second device; useful on headless-but-human machines.
 *  - **Client-credentials (RFC 6749 §4.4)** via `--client-credentials`
 *    (SSO-1553) — fully NON-interactive (no browser, no second device), for
 *    CI / automation / service accounts. Exchanges `client_id` +
 *    `client_secret` for a machine token. The secret is sourced from
 *    `THORYN_CLIENT_SECRET` (env / `-D`), `--client-secret-file <path>`, or a
 *    no-echo prompt — NEVER an argv flag (SSO-1553 secret-safety rule).
 */
@Command(
    name = "login",
    description = [
        "Sign in to Thoryn. Default: Authorization Code + PKCE (loopback). " +
            "--device-code on headless-but-human machines; --client-credentials for CI/automation.",
    ],
    mixinStandardHelpOptions = true,
)
class LoginCommand : Callable<Int> {

    @Option(
        names = ["--issuer"],
        description = ["Override the hub issuer URL (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_ISSUER,
    )
    var issuer: String = ThorynConfig.DEFAULT_ISSUER

    @Option(
        names = ["--client-id"],
        description = ["Override the OAuth client ID (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_CLIENT_ID,
    )
    var clientId: String = ThorynConfig.DEFAULT_CLIENT_ID

    @Option(
        names = ["--scope"],
        description = ["Space-separated scopes to request (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_SCOPE,
    )
    var scope: String = ThorynConfig.DEFAULT_SCOPE

    @Option(
        names = ["--device-code"],
        description = ["Use the device-code flow (RFC 8628) instead of loopback redirect. Useful on headless machines."],
    )
    var useDeviceCode: Boolean = false

    /**
     * SSO-1553 — fully non-interactive client-credentials grant for
     * CI/automation. Exchanges `--client-id` + the resolved client secret for a
     * machine token with no browser and no second device.
     */
    @Option(
        names = ["--client-credentials"],
        description = ["Use the client-credentials grant (RFC 6749 §4.4) — non-interactive, for CI/automation/service accounts. No browser."],
    )
    var useClientCredentials: Boolean = false

    /**
     * SSO-1553 — read the client secret from a file (owner-only) instead of the
     * `THORYN_CLIENT_SECRET` env var or a prompt. There is deliberately NO
     * `--client-secret <value>` flag: a secret in argv lands in shell history
     * and `ps aux`.
     */
    @Option(
        names = ["--client-secret-file"],
        description = ["Read the client secret from this file (for --client-credentials / --device-code). Falls back to THORYN_CLIENT_SECRET, then a no-echo prompt. Never pass the secret as an argument."],
    )
    var clientSecretFile: File? = null

    @Option(
        names = ["--status"],
        description = ["Print sign-in status and exit. Does not initiate a new flow."],
    )
    var statusOnly: Boolean = false

    /**
     * SSO-1145: bypass the `http://` non-loopback issuer-URL guard for local
     * development scenarios where TLS is not available. A WARN is printed to
     * stderr whenever this flag is active so the operator is aware.
     *
     * Never use `--dev` in a production or staging workflow — the access token
     * will be transmitted in plaintext.
     */
    @Option(
        names = ["--dev"],
        description = ["Allow http:// issuers for non-loopback hosts (local development only). Prints a WARN."],
    )
    var devMode: Boolean = false

    private val tokenStore: TokenStore = TokenStoreFactory.default()

    /**
     * SSO-959: expand `all-supply-chain` (and any other client-side
     * wildcards) into the literal scope set the hub will see. The hub does
     * not understand wildcards — they are a CLI ergonomic.
     */
    private fun expandedScope(): String = ScopeRegistry.expand(scope)

    override fun call(): Int {
        if (statusOnly) {
            return printStatus()
        }
        // SSO-1145: validate the issuer URL before any network activity begins.
        try {
            IssuerUrlValidator.validate(issuer, devMode)
        } catch (e: IssuerUrlValidationException) {
            System.err.println("Error: ${e.message}")
            return EXIT_USAGE
        }
        if (useClientCredentials && useDeviceCode) {
            System.err.println("Error: --client-credentials and --device-code are mutually exclusive.")
            return EXIT_USAGE
        }
        if (useClientCredentials) {
            return runClientCredentialsFlow()
        }
        if (useDeviceCode) {
            return runDeviceCodeFlow()
        }
        return runLoopbackFlow()
    }

    /**
     * SSO-1553 — resolve the client secret WITHOUT it ever appearing in argv.
     *
     * Resolution order:
     *  1. `THORYN_CLIENT_SECRET` env var / `-D` system property — the canonical
     *     CI knob (set once in the pipeline env, never on the command line).
     *  2. `--client-secret-file <path>` — owner-only file; bytes never touch argv.
     *  3. A no-echo terminal prompt (interactive only; refuses on a non-TTY).
     *
     * Returns null (after printing guidance) when no secret could be obtained.
     */
    private fun resolveClientSecret(promptLabel: String): String? {
        ThorynConfig.resolveClientSecret()?.let { return it }
        return SecretIo.readSecretInput(
            secretFile = clientSecretFile,
            prompt = promptLabel,
        )
    }

    private fun runClientCredentialsFlow(): Int {
        val secret = resolveClientSecret("Client secret for '$clientId': ")
        if (secret == null) {
            System.err.println(
                "No client secret available for --client-credentials. Set THORYN_CLIENT_SECRET, " +
                    "pass --client-secret-file <path>, or run interactively to be prompted.",
            )
            return EXIT_USAGE
        }

        val flow = ClientCredentialsFlow(
            issuer = issuer,
            clientId = clientId,
            clientSecret = secret,
            sender = realHttpSender(),
        )

        return try {
            val tokens = flow.run(expandedScope())
            tokenStore.write(tokens)
            println("Signed in (client-credentials / service account '$clientId').")
            tokens.scope?.let { println("Scopes: $it") }
            EXIT_OK
        } catch (e: ClientCredentialsException) {
            System.err.println("Sign-in failed: ${e.message}")
            EXIT_CLIENT_CREDENTIALS_FAILED
        }
    }

    private fun runDeviceCodeFlow(): Int {
        val secret = resolveClientSecret("Client secret for '$clientId': ")
        if (secret == null) {
            System.err.println(
                "No client secret available. The device-code endpoint requires confidential " +
                    "client authentication; set THORYN_CLIENT_SECRET, pass --client-secret-file <path>, " +
                    "or run interactively to be prompted.",
            )
            return EXIT_USAGE
        }

        val flow = DeviceCodeFlow(
            issuer = issuer,
            clientId = clientId,
            clientSecret = secret,
            sender = realHttpSender(),
            // SSO-1993: pass the --dev flag through so the flow's own issuer
            // guard honours the same loopback-bypass the command validated with.
            devMode = devMode,
        )

        return try {
            val tokens = flow.run(expandedScope()) { authorization ->
                val verifyUrl = authorization.verificationUriComplete ?: authorization.verificationUri
                println()
                println("To sign in, open this URL on any device:")
                println()
                println("    $verifyUrl")
                println()
                println("…and enter the code:  ${authorization.userCode}")
                println()
                println("Waiting for sign-in (expires in ${authorization.expiresIn / 60} minutes)…")
            }
            tokenStore.write(tokens)
            println()
            println("Signed in.")
            0
        } catch (e: DeviceCodeException) {
            System.err.println()
            System.err.println("Sign-in failed: ${e.message}")
            EXIT_DEVICE_CODE_FAILED
        }
    }

    /**
     * SSO-2820 — the default interactive sign-in: Authorization Code + PKCE (RFC 7636) with a
     * literal-loopback redirect (RFC 8252 §7.3). Starts a single-shot local listener, opens the
     * browser at the authorize URL, waits for the `?code=&state=` redirect, verifies `state`,
     * redeems the code (+ PKCE verifier) at `/oauth2/token`, and stores the tokens.
     *
     * Public client by default (no secret — PKCE is the authorize↔token binding); if a client secret
     * is available (`THORYN_CLIENT_SECRET` / `--client-secret-file`) the exchange authenticates the
     * client with HTTP Basic instead. No interactive secret prompt here — a loopback sign-in is
     * meant to be one keystroke.
     */
    private fun runLoopbackFlow(): Int {
        val verifier = PkceUtil.newCodeVerifier()
        val challenge = PkceUtil.codeChallenge(verifier)
        val state = PkceUtil.newState()
        val server = LoopbackRedirectServer()
        return try {
            server.start()
            val redirectUri = server.redirectUri
            val authorizeUrl = buildString {
                append(issuer.trimEnd('/'))
                append("/oauth2/authorize")
                append("?response_type=code")
                append("&client_id=").append(urlEncode(clientId))
                append("&redirect_uri=").append(urlEncode(redirectUri))
                append("&scope=").append(urlEncode(expandedScope()))
                append("&code_challenge=").append(urlEncode(challenge))
                append("&code_challenge_method=S256")
                append("&state=").append(urlEncode(state))
            }

            println("Opening your browser to sign in…")
            println("If it doesn't open, visit this URL:")
            println()
            println("    $authorizeUrl")
            println()
            BrowserLauncher.open(authorizeUrl)
            println("Waiting for the sign-in redirect (${LOOPBACK_TIMEOUT.toMinutes()} min)…")

            val params = server.awaitCallback(LOOPBACK_TIMEOUT)

            // RFC 6749 §4.1.2.1 — the AS may redirect back with an error instead of a code.
            params["error"]?.let { err ->
                val desc = params["error_description"].orEmpty()
                System.err.println("Sign-in failed: $err${if (desc.isNotBlank()) " — $desc" else ""}")
                return EXIT_LOOPBACK_FAILED
            }
            // RFC 6749 §10.12 — reject a callback whose state does not match the one we sent (CSRF).
            val returnedState = params["state"]
            if (returnedState != state) {
                System.err.println("Sign-in failed: state mismatch — discarding the callback (possible CSRF).")
                return EXIT_LOOPBACK_FAILED
            }
            val code = params["code"]
            if (code.isNullOrBlank()) {
                System.err.println("Sign-in failed: the authorization server returned no code.")
                return EXIT_LOOPBACK_FAILED
            }

            // Public client by default; use the secret only if one is already available (no prompt).
            val secret = ThorynConfig.resolveClientSecret() ?: clientSecretFile
                ?.takeIf { it.isFile }
                ?.readText()
                ?.trim()
                ?.takeIf { it.isNotBlank() }
            val flow = AuthorizationCodeFlow(
                issuer = issuer,
                clientId = clientId,
                clientSecret = secret,
                redirectUri = redirectUri,
                codeVerifier = verifier,
                sender = realHttpSender(),
                devMode = devMode,
            )
            val tokens = flow.exchange(code)
            tokenStore.write(tokens)
            println()
            println("Signed in.")
            tokens.scope?.let { println("Scopes: $it") }
            EXIT_OK
        } catch (e: LoopbackTimeoutException) {
            System.err.println("Sign-in timed out: ${e.message}")
            EXIT_LOOPBACK_FAILED
        } catch (e: AuthorizationCodeException) {
            System.err.println("Sign-in failed: ${e.message}")
            EXIT_LOOPBACK_FAILED
        } finally {
            server.close()
        }
    }

    private fun printStatus(): Int {
        val tokens = tokenStore.read()
        if (tokens == null) {
            println("Not signed in. Run `thoryn login`.")
            return 1
        }
        println("Signed in.")
        tokens.scope?.let { println("Scopes: $it") }
        return 0
    }

    private fun realHttpSender(): HttpSender {
        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()
        return HttpSender { request, handler -> client.send(request, handler) }
    }

    private fun urlEncode(s: String): String =
        java.net.URLEncoder.encode(s, Charsets.UTF_8)

    companion object {
        const val EXIT_OK = 0
        const val EXIT_USAGE = 65
        const val EXIT_DEVICE_CODE_FAILED = 70

        /** SSO-1553 — client-credentials grant rejected by the hub (bad secret, scope, …). */
        const val EXIT_CLIENT_CREDENTIALS_FAILED = 71

        /** SSO-2820 — the interactive loopback flow failed (timeout, state mismatch, error redirect, bad code). */
        const val EXIT_LOOPBACK_FAILED = 72

        /** SSO-2820 — how long to wait for the browser sign-in redirect on the loopback listener. */
        private val LOOPBACK_TIMEOUT: Duration = Duration.ofMinutes(5)
    }
}
