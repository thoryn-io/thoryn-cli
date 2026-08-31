package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.ClientCredentialsException
import com.devnow.thoryn.cli.auth.ClientCredentialsFlow
import com.devnow.thoryn.cli.auth.DeviceCodeException
import com.devnow.thoryn.cli.auth.DeviceCodeFlow
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.IssuerUrlValidationException
import com.devnow.thoryn.cli.auth.IssuerUrlValidator
import com.devnow.thoryn.cli.auth.LoopbackRedirectServer
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
 *  - **Authorization Code + PKCE with loopback redirect** (default) — the
 *    interactive browser flow. The full loopback dance lands alongside SSO-735.
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
        return runLoopbackPreview()
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

    private fun runLoopbackPreview(): Int {
        // Loopback flow — full HTTP server + code exchange ships alongside SSO-735.
        // For now, bind a real loopback listener (proves the SSO-805 RFC 8252 §7.3
        // literal-IP behaviour end-to-end) and print the authorize URL the browser
        // would open so the wiring is visible. The server is closed before the
        // command exits — the actual /callback dance lives in SSO-735.
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
            println("Authorization URL (preview — full loopback dance lands in a follow-up):")
            println(authorizeUrl)
            println()
            println("Redirect URI (RFC 8252 §7.3 literal loopback): $redirectUri")
            println("PKCE verifier: ${verifier.take(8)}… (32 bytes random)")
            println("PKCE challenge: $challenge")
            println()
            System.err.println(
                "Loopback flow is wired but the local HTTP server / code exchange / token storage " +
                    "lands in a focused follow-up alongside SSO-735. Use `thoryn login --device-code` for the working flow.",
            )
            EXIT_NOT_IMPLEMENTED
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
        const val EXIT_NOT_IMPLEMENTED = 64
        const val EXIT_USAGE = 65
        const val EXIT_DEVICE_CODE_FAILED = 70

        /** SSO-1553 — client-credentials grant rejected by the hub (bad secret, scope, …). */
        const val EXIT_CLIENT_CREDENTIALS_FAILED = 71
    }
}
