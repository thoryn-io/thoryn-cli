package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.AuthorizationCodeException
import com.devnow.thoryn.cli.auth.AuthorizationCodeFlow
import com.devnow.thoryn.cli.auth.ClientCredentialsException
import com.devnow.thoryn.cli.auth.ClientCredentialsFlow
import com.devnow.thoryn.cli.auth.DeviceCodeException
import com.devnow.thoryn.cli.auth.DeviceCodeFlow
import com.devnow.thoryn.cli.auth.EcPrivateKeyJwtSigner
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.IssuerUrlValidationException
import com.devnow.thoryn.cli.auth.IssuerUrlValidator
import com.devnow.thoryn.cli.auth.LoopbackRedirectServer
import com.devnow.thoryn.cli.auth.LoopbackTimeoutException
import com.devnow.thoryn.cli.auth.PkceUtil
import com.devnow.thoryn.cli.auth.ScopeRegistry
import com.devnow.thoryn.cli.auth.TokenStore
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityException
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
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
 *  - **Client-credentials / API-key (RFC 6749 §4.4)** via `--client-credentials`
 *    (SSO-1553; API-key ergonomics + re-mint SSO-2941) — fully NON-interactive
 *    (no browser, no second device), for CI / automation / service accounts.
 *    Exchanges `client_id` + `client_secret` for a machine token. Credentials are
 *    sourced from `THORYN_API_KEY=<client-id>:<client-secret>` (the single-knob CI
 *    key), or `--client-id` + the secret from `THORYN_CLIENT_SECRET` (env / `-D`),
 *    `--client-secret-file <path>`, or a no-echo prompt — NEVER an argv flag
 *    (SSO-1553 secret-safety rule). A client-credentials token carries no refresh
 *    token, so on expiry the CLI RE-MINTS from the stored client id + the
 *    env-supplied secret (SSO-2941, see [CommandSupport.forceRefresh]).
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

    /**
     * SSO-2827 — the customer-plane gateway this session should use for the
     * gateway-routed command trees (`clients`, `federation`, `audit`). Recorded
     * in the token session so those commands default to it instead of localhost.
     * When omitted it is derived from `--issuer` ([ThorynConfig.gatewayForIssuer]:
     * `hub.<env>` → `api.<env>`), falling back to the local-dev gateway.
     */
    @Option(
        names = ["--gateway"],
        description = ["Override the customer-plane gateway URL recorded for this session. Default: derived from --issuer (hub.<env> -> api.<env>), else http://localhost:8991."],
    )
    var gateway: String? = null

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
        description = [
            "Use the client-credentials grant (RFC 6749 §4.4) — non-interactive, for CI/automation/service accounts. " +
                "No browser. Credentials from THORYN_API_KEY=<client-id>:<client-secret>, or --client-id + " +
                "THORYN_CLIENT_SECRET / --client-secret-file. Auto re-mints on expiry (no refresh token).",
        ],
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

    /**
     * SSO-2879 — secret-less sign-in for the thoryn-examples recipe-conformance CI: exchange the
     * GitHub Actions OIDC token for a hub access token via Workload Identity Federation, with the
     * exchange client authenticating by `private_key_jwt` (no shared secret). See [runWorkloadIdentityFlow].
     */
    @Option(
        names = ["--workload-identity", "--github-oidc"],
        description = ["Sign in via GitHub Actions OIDC -> hub Workload Identity Federation (RFC 8693). Non-interactive, secret-less; for CI. Requires the CI signing key (THORYN_CI_WIF_SIGNING_KEY / --wif-signing-key-file)."],
    )
    var useWorkloadIdentity: Boolean = false

    @Option(
        names = ["--tenant"],
        description = ["Workspace slug whose tenant the WIF token targets (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_WIF_TENANT_SLUG,
    )
    var wifTenantSlug: String = ThorynConfig.DEFAULT_WIF_TENANT_SLUG

    @Option(
        names = ["--wif-client-id"],
        description = ["OAuth client id of the private_key_jwt exchange client (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_WIF_CLIENT_ID,
    )
    var wifClientId: String = ThorynConfig.DEFAULT_WIF_CLIENT_ID

    @Option(
        names = ["--wif-key-id"],
        description = ["kid of the CI signing key, matching the hub-registered public JWKS (default: \${DEFAULT-VALUE})."],
        defaultValue = ThorynConfig.DEFAULT_WIF_KEY_ID,
    )
    var wifKeyId: String = ThorynConfig.DEFAULT_WIF_KEY_ID

    /**
     * SSO-2879 — the PKCS#8 PEM private key for the client assertion, read from a file. Falls back to
     * the `THORYN_CI_WIF_SIGNING_KEY` env var (the canonical CI knob). Never a flag value — a key in
     * argv lands in shell history and `ps aux`.
     */
    @Option(
        names = ["--wif-signing-key-file"],
        description = ["Read the WIF private_key_jwt signing key (PKCS#8 PEM) from this file. Falls back to THORYN_CI_WIF_SIGNING_KEY. Never pass the key as an argument."],
    )
    var wifSigningKeyFile: File? = null

    /**
     * SSO-2879 — the OIDC token `audience` requested from GitHub (== the hub's registered
     * `allowed_audience`). Defaults to `--issuer`. Also the base for the client-assertion `aud`.
     */
    @Option(
        names = ["--audience"],
        description = ["Audience requested for the GitHub OIDC token (WIF). Default: the --issuer value."],
    )
    var wifAudience: String? = null

    /**
     * SSO-2879 — supply the subject token explicitly instead of fetching it from the GitHub Actions
     * runner (local testing off-runner). Falls back to the `THORYN_CI_WIF_SUBJECT_TOKEN` env var.
     */
    @Option(
        names = ["--subject-token"],
        description = ["Use this GitHub OIDC token as the WIF subject_token instead of fetching it from the runner (testing). Falls back to THORYN_CI_WIF_SUBJECT_TOKEN."],
    )
    var wifSubjectToken: String? = null

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
     * SSO-2827 — stamp the hub issuer + gateway this login used onto the token
     * before persisting, so later commands default to them. The gateway is the
     * explicit `--gateway` when given, otherwise derived from `--issuer`.
     */
    private fun withSession(tokens: Tokens): Tokens =
        tokens.copy(
            issuer = issuer,
            gateway = gateway?.takeIf { it.isNotBlank() } ?: ThorynConfig.gatewayForIssuer(issuer),
        )

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
        val exclusiveModes = listOf(useClientCredentials, useDeviceCode, useWorkloadIdentity).count { it }
        if (exclusiveModes > 1) {
            System.err.println("Error: --client-credentials, --device-code and --workload-identity are mutually exclusive.")
            return EXIT_USAGE
        }
        if (useWorkloadIdentity) {
            return runWorkloadIdentityFlow()
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
        val creds = resolveClientCredentials() ?: return EXIT_USAGE

        val flow = ClientCredentialsFlow(
            issuer = issuer,
            clientId = creds.clientId,
            clientSecret = creds.secret,
            sender = realHttpSender(),
        )

        return try {
            val tokens = flow.run(expandedScope())
            // SSO-2941 — stamp the session as an API-key / client-credentials session and record the
            // client id (NOT the secret) so `CommandSupport.forceRefresh` can re-mint a fresh token
            // on expiry from the env-supplied secret, rather than a refresh_token redemption (a
            // client_credentials grant returns no refresh token — RFC 6749 §4.4.3).
            tokenStore.write(
                withSession(tokens).copy(
                    authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                    clientId = creds.clientId,
                ),
            )
            // SSO-2863 — a fresh login resets the base tenant; drop any stale `workspace switch`
            // selection so later commands don't silently re-exchange into an old workspace.
            SelectedWorkspaceStore().clear()
            println("Signed in (client-credentials / service account '${creds.clientId}').")
            tokens.scope?.let { println("Scopes: $it") }
            EXIT_OK
        } catch (e: ClientCredentialsException) {
            System.err.println("Sign-in failed: ${e.message}")
            EXIT_CLIENT_CREDENTIALS_FAILED
        }
    }

    /** SSO-2941 — a resolved API-key credential pair for the client-credentials grant. */
    private data class ClientCredentials(val clientId: String, val secret: String)

    /**
     * SSO-2941 — resolve the client-credentials `client_id` + `client_secret` WITHOUT the secret
     * ever appearing in argv.
     *
     * Precedence:
     *  1. `THORYN_API_KEY=<client-id>:<client-secret>` — the single-knob CI credential. It carries
     *     BOTH halves; the `--client-id` flag then only needs to match (a mismatch is a hard error
     *     rather than a silent guess).
     *  2. `--client-id` (default `thoryn-cli`) + the secret resolved by [resolveClientSecret]
     *     (`THORYN_CLIENT_SECRET` env/`-D`, then `--client-secret-file`, then a no-echo prompt).
     *
     * Returns null (after printing guidance) when no usable credential could be obtained.
     */
    private fun resolveClientCredentials(): ClientCredentials? {
        ThorynConfig.resolveApiKey()?.let { apiKey ->
            val explicitId = clientId.takeIf { it != ThorynConfig.DEFAULT_CLIENT_ID }
            if (explicitId != null && explicitId != apiKey.clientId) {
                System.err.println(
                    "Error: --client-id '$explicitId' conflicts with the client id carried by " +
                        "${ThorynConfig.API_KEY_ENV} ('${apiKey.clientId}'). Pass one or the other.",
                )
                return null
            }
            return ClientCredentials(apiKey.clientId, apiKey.clientSecret)
        }
        val secret = resolveClientSecret("Client secret for '$clientId': ")
        if (secret == null) {
            System.err.println(
                "No client secret available for --client-credentials. Set ${ThorynConfig.API_KEY_ENV} " +
                    "(<client-id>:<client-secret>) or THORYN_CLIENT_SECRET, pass --client-secret-file <path>, " +
                    "or run interactively to be prompted.",
            )
            return null
        }
        return ClientCredentials(clientId, secret)
    }

    /**
     * SSO-2879 — the secret-less WIF sign-in. Resolves the CI signing key (env / file), signs a
     * `private_key_jwt` client assertion, and exchanges the GitHub Actions OIDC token for a hub
     * access token via [WorkloadIdentityFlow].
     *
     * Two hub URLs (see [WorkloadIdentityFlow]): the request is POSTed to the TENANT-SUBDOMAIN token
     * endpoint (`{slug}.hub…/oauth2/token`, so the hub resolves the ci-conformance tenant) while the
     * assertion `aud` is the DEFAULT-issuer token endpoint (`--issuer`/oauth2/token). The requested
     * scope defaults to the client's exact registered set ([ThorynConfig.DEFAULT_WIF_SCOPE]) unless
     * the caller overrode `--scope`.
     */
    private fun runWorkloadIdentityFlow(): Int {
        val signingKeyPem = ThorynConfig.readWifSigningKey(wifSigningKeyFile)
        if (signingKeyPem == null) {
            System.err.println(
                "No WIF signing key available. Set ${ThorynConfig.WIF_SIGNING_KEY_ENV} (PKCS#8 PEM) " +
                    "or pass --wif-signing-key-file <path>.",
            )
            return EXIT_USAGE
        }
        val signer = try {
            EcPrivateKeyJwtSigner(privateKeyPem = signingKeyPem, keyId = wifKeyId)
        } catch (e: IllegalArgumentException) {
            System.err.println("Sign-in failed: invalid WIF signing key — ${e.message}")
            return EXIT_WORKLOAD_IDENTITY_FAILED
        }

        val base = issuer.trimEnd('/')
        val oidcAudience = wifAudience?.takeIf { it.isNotBlank() } ?: base
        val subjectToken = wifSubjectToken?.takeIf { it.isNotBlank() }
            ?: ThorynConfig.readWifSubjectTokenOverride()
        // Request the client's exact registered scope set by default; honour an explicit --scope.
        val requestedScope = if (scope == ThorynConfig.DEFAULT_SCOPE) ThorynConfig.DEFAULT_WIF_SCOPE else expandedScope()

        val flow = WorkloadIdentityFlow(
            tokenEndpoint = "${ThorynConfig.tenantIssuer(base, wifTenantSlug)}/oauth2/token",
            assertionAudience = "$base/oauth2/token",
            clientId = wifClientId,
            signer = signer,
            oidcAudience = oidcAudience,
            sender = realHttpSender(),
            explicitSubjectToken = subjectToken,
        )

        return try {
            val tokens = flow.run(requestedScope)
            tokenStore.write(withSession(tokens))
            SelectedWorkspaceStore().clear()
            println("Signed in (workload-identity / '$wifClientId' in tenant '$wifTenantSlug').")
            tokens.scope?.let { println("Scopes: $it") }
            EXIT_OK
        } catch (e: WorkloadIdentityException) {
            System.err.println("Sign-in failed: ${e.message}")
            e.bodySnippet?.takeIf { e.oauthError == "unknown" }?.let { System.err.println("  hub response: $it") }
            EXIT_WORKLOAD_IDENTITY_FAILED
        }
    }

    private fun runDeviceCodeFlow(): Int {
        // SSO-2822: the default `thoryn-cli` is now a PUBLIC client (RFC 8252) — device-code needs no
        // secret (client_id-only, RFC 8628 §3.1). A CONFIDENTIAL client may still supply one via
        // THORYN_CLIENT_SECRET / --client-secret-file; we resolve it if present but never prompt.
        val secret = ThorynConfig.resolveClientSecret()
            ?: clientSecretFile?.takeIf { it.isFile }?.readText()?.trim()?.takeIf { it.isNotBlank() }

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
            tokenStore.write(withSession(tokens))
            // SSO-2863 — a fresh login resets the base tenant; drop any stale `workspace switch`
            // selection so later commands don't silently re-exchange into an old workspace.
            SelectedWorkspaceStore().clear()
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
            tokenStore.write(withSession(tokens))
            // SSO-2863 — a fresh login resets the base tenant; drop any stale `workspace switch`
            // selection so later commands don't silently re-exchange into an old workspace.
            SelectedWorkspaceStore().clear()
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
        // SSO-2834 — report real access-token validity, not just token presence. A stale access
        // token auto-refreshes on the next command when a refresh token is stored (offline_access).
        val exp = tokens.expiresAtEpochSecond
        val now = System.currentTimeMillis() / 1000
        val canRefresh = !tokens.refreshToken.isNullOrBlank()
        when {
            exp == null -> println("Signed in (access-token expiry unknown).")
            exp <= now && canRefresh -> println("Signed in — access token expired; it will auto-refresh on the next command.")
            exp <= now -> println("Signed in — access token EXPIRED. Run `thoryn login` to re-authenticate.")
            else -> {
                val mins = (exp - now) / 60
                val suffix = if (canRefresh) ", auto-refreshes near expiry" else ""
                println("Signed in — access token valid for ${mins}m$suffix.")
            }
        }
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

        /** SSO-2879 — the workload-identity (GitHub OIDC -> WIF) sign-in failed. */
        const val EXIT_WORKLOAD_IDENTITY_FAILED = 73

        /** SSO-2820 — how long to wait for the browser sign-in redirect on the loopback listener. */
        private val LOOPBACK_TIMEOUT: Duration = Duration.ofMinutes(5)
    }
}
