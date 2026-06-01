package com.devnow.thoryn.cli.cmd

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
import java.net.http.HttpClient
import java.time.Duration
import java.util.concurrent.Callable

/**
 * `thoryn login` — Authorization Code + PKCE with loopback redirect, or
 * device-code flow (RFC 8628) on headless machines via `--device-code`.
 *
 * The full loopback flow (random local port + tiny HTTP server) lands
 * alongside SSO-735 (E2E web). Device-code is fully implemented here and
 * works against the hub's existing `/oauth2/device_authorization` endpoint.
 */
@Command(
    name = "login",
    description = ["Sign in to Thoryn (Authorization Code + PKCE, loopback redirect; --device-code on headless machines)."],
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
        if (useDeviceCode) {
            return runDeviceCodeFlow()
        }
        return runLoopbackPreview()
    }

    private fun runDeviceCodeFlow(): Int {
        val secret = ThorynConfig.resolveClientSecret()
        if (secret == null) {
            System.err.println(
                "THORYN_CLIENT_SECRET is not set. The device-code endpoint currently " +
                    "requires confidential client authentication; export your client secret and retry.",
            )
            return EXIT_USAGE
        }

        val flow = DeviceCodeFlow(
            issuer = issuer,
            clientId = clientId,
            clientSecret = secret,
            sender = realHttpSender(),
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
        const val EXIT_NOT_IMPLEMENTED = 64
        const val EXIT_USAGE = 65
        const val EXIT_DEVICE_CODE_FAILED = 70
    }
}
