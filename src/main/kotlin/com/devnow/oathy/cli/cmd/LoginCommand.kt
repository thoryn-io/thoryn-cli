package com.devnow.oathy.cli.cmd

import com.devnow.oathy.cli.auth.FileTokenStore
import com.devnow.oathy.cli.auth.PkceUtil
import com.devnow.oathy.cli.auth.TokenStore
import com.devnow.oathy.cli.config.OathyConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.util.concurrent.Callable

/**
 * `oathy login` — kick off Authorization Code + PKCE with a loopback redirect.
 *
 * The full loopback flow (random local port, browser open, code exchange,
 * token storage) is implemented in `LoopbackOAuthFlow`. This command is the
 * scaffold entry point; it generates a verifier, prints the authorize URL,
 * and stores a placeholder so subsequent commands can be wired against the
 * keychain interface. The actual loopback HTTP server lands in a focused
 * follow-up alongside SSO-735 (E2E web flow), which is the test-bed for the
 * full end-to-end OAuth dance.
 *
 * Implementation note: keeping the scaffold minimal here lets reviewers
 * confirm the CLI surface (commands, exit codes, config) before the moving
 * parts of the OAuth flow ship.
 */
@Command(
    name = "login",
    description = ["Sign in to Thoryn (Authorization Code + PKCE, loopback redirect)."],
    mixinStandardHelpOptions = true,
)
class LoginCommand : Callable<Int> {

    @Option(
        names = ["--issuer"],
        description = ["Override the hub issuer URL (default: \${DEFAULT-VALUE})."],
        defaultValue = OathyConfig.DEFAULT_ISSUER,
    )
    var issuer: String = OathyConfig.DEFAULT_ISSUER

    @Option(
        names = ["--client-id"],
        description = ["Override the OAuth client ID (default: \${DEFAULT-VALUE})."],
        defaultValue = OathyConfig.DEFAULT_CLIENT_ID,
    )
    var clientId: String = OathyConfig.DEFAULT_CLIENT_ID

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

    private val tokenStore: TokenStore = FileTokenStore()

    override fun call(): Int {
        if (statusOnly) {
            return printStatus()
        }
        if (useDeviceCode) {
            System.err.println("Device-code flow lands in SSO-732. Use the loopback flow for now.")
            return EXIT_NOT_IMPLEMENTED
        }

        val verifier = PkceUtil.newCodeVerifier()
        val challenge = PkceUtil.codeChallenge(verifier)
        val state = PkceUtil.newState()

        // The full loopback flow (random port + tiny HTTP server + code exchange) lands
        // in a focused follow-up. For the scaffold we print the authorize URL the user
        // would have been redirected to; this is enough to confirm wiring without
        // spinning up the HTTP server.
        val authorizeUrl = buildString {
            append(issuer.trimEnd('/'))
            append("/oauth2/authorize")
            append("?response_type=code")
            append("&client_id=").append(urlEncode(clientId))
            append("&redirect_uri=").append(urlEncode("http://127.0.0.1:<random>/callback"))
            append("&scope=").append(urlEncode("openid offline_access tenant:clients.read"))
            append("&code_challenge=").append(urlEncode(challenge))
            append("&code_challenge_method=S256")
            append("&state=").append(urlEncode(state))
        }

        println("Authorization URL (preview — full loopback dance lands in a follow-up):")
        println(authorizeUrl)
        println()
        println("PKCE verifier: ${verifier.take(8)}… (32 bytes random)")
        println("PKCE challenge: $challenge")
        println()
        System.err.println(
            "oathy login is wired but the loopback HTTP server / code exchange / token storage " +
                "lands in a focused follow-up alongside SSO-735.",
        )
        return EXIT_NOT_IMPLEMENTED
    }

    private fun printStatus(): Int {
        val tokens = tokenStore.read()
        if (tokens == null) {
            println("Not signed in. Run `oathy login`.")
            return 1
        }
        println("Signed in.")
        tokens.scope?.let { println("Scopes: $it") }
        return 0
    }

    private fun urlEncode(s: String): String =
        java.net.URLEncoder.encode(s, Charsets.UTF_8)

    companion object {
        const val EXIT_NOT_IMPLEMENTED = 64
    }
}
