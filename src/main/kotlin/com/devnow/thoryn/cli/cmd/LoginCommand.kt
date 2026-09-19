package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.AuthorizationCodeException
import com.devnow.thoryn.cli.auth.AuthorizationCodeFlow
import com.devnow.thoryn.cli.auth.ClientCredentialsException
import com.devnow.thoryn.cli.auth.ClientCredentialsFlow
import com.devnow.thoryn.cli.auth.DeviceCodeException
import com.devnow.thoryn.cli.auth.DeviceCodeFlow
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.DpopCapability
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
import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.connection.ConnectionException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
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

    /**
     * SSO-3182 — the hub BASE URL of the platform to sign in to (`https://hub.<env>`). No localhost default:
     * unset, it resolves from `THORYN_HUB`, then the previous session's hub, then the baked-in production
     * hub (none yet) — see [ThorynConfig.resolveHubBase]. Nothing resolved ⇒ fail fast with guidance.
     */
    @Option(
        names = ["--issuer"],
        description = [
            "Hub BASE URL of the Thoryn platform, e.g. ${ThorynConfig.STAGING_ISSUER} (staging). " +
                "Interactive sign-in happens on <workspace>.<hub>. Default: \$${ThorynConfig.HUB_ENV}, else the hub of " +
                "your previous sign-in on this machine.",
        ],
    )
    var issuerOption: String? = null

    /** The resolved issuer the flows use: the hub base, then (interactive flows) the workspace's tenant hub. */
    private var issuer: String = ""

    /**
     * SSO-3104 — the workspace an interactive sign-in (loopback / device-code) happens on: the issuer
     * becomes `https://<slug>.hub.<env>` ([ThorynConfig.tenantIssuer]) and the session's `tnt` is that
     * workspace. REQUIRED for those flows — the shared default tenant is not a sign-in target. Falls
     * back to the `THORYN_WORKSPACE` env var. The non-interactive modes bind their tenant elsewhere
     * (`--connection` from the contract's workspace; `--client-credentials` from the key's `tnt`).
     */
    @Option(
        names = ["--workspace"],
        description = ["Workspace slug to sign in on (interactive flows sign in at <slug>.<hub>). Default: \${env:THORYN_WORKSPACE}, else `thoryn`."],
        defaultValue = "\${env:THORYN_WORKSPACE}",
    )
    var workspace: String? = null

    /**
     * SSO-2827 — the customer-plane gateway this session should use for the
     * gateway-routed command trees (`clients`, `federation`, `audit`). Recorded
     * in the token session so those commands default to it instead of localhost.
     * When omitted it is derived from `--issuer` ([ThorynConfig.gatewayForIssuer]:
     * `hub.<env>` → `api.<env>`), falling back to the local-dev gateway.
     */
    @Option(
        names = ["--gateway"],
        description = ["Override the customer-plane gateway URL recorded for this session. Default: derived from the hub (hub.<env> -> api.<env>)."],
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
     * SSO-2948 (epic SSO-2947) — sign in from a declarative **connection contract**
     * (`connection.schema.json`): a schema-backed JSON file describing the workspace + the machine
     * client to authenticate as. The CLI owns the derivation the CI Action used to hand-roll in bash:
     * it derives the per-tenant issuer (`https://<slug>.hub.<env>`) and gateway from `workspace.slug`
     * + the hub base (the env var named by `workspace.hubBaseUrlEnv`, default THORYN_HUB), reads the
     * client secret from the env var named by `auth.secretEnv` (failing closed if unset/empty),
     * requests EXACTLY `auth.scopes`, and stamps the session. Mutually exclusive with the manual
     * `--issuer` / `--gateway` / `--scope` / `--client-credentials` (and other-mode) flags — the
     * contract is the single source of the binding.
     */
    @Option(
        names = ["--connection"],
        description = ["Sign in from a connection contract (connection.schema.json). Derives issuer/gateway from workspace.slug; reads the client secret from the env var named by auth.secretEnv; requests exactly auth.scopes. Mutually exclusive with --issuer/--gateway/--scope/--client-credentials."],
    )
    var connectionFile: File? = null

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
            // SSO-3104 — remember which client signed in, so refresh / workspace exchange use the same one.
            clientId = tokens.clientId ?: clientId,
            // SSO-3182 — remember the workspace, so an unrenewable session prints the exact re-login line.
            workspace = signedInWorkspace,
            // The gateway derives from the hub BASE (`hub.<env>` → `api.<env>`), never from a tenant host.
            gateway = gateway?.takeIf { it.isNotBlank() } ?: ThorynConfig.gatewayForIssuer(baseIssuer),
        )

    /** The hub base URL (before any workspace prefixing). */
    private var baseIssuer: String = ""

    /** SSO-3182 — the workspace an interactive flow signed in on (null for the machine flows). */
    private var signedInWorkspace: String? = null

    /**
     * SSO-3182 — resolve the hub base ([ThorynConfig.resolveHubBase]) into [issuer] / [baseIssuer], or
     * print the no-platform guidance and return false. A hub taken from `THORYN_HUB` or the previous
     * session is announced on stderr so the user sees which platform they are signing in to.
     */
    private fun resolveIssuer(): Boolean {
        val previous = runCatching { tokenStore.read() }.getOrNull()?.issuer
        val hub = ThorynConfig.resolveHubBase(issuerOption, previous)
        if (hub == null) {
            System.err.println(ThorynConfig.NO_HUB_GUIDANCE)
            return false
        }
        when (hub.source) {
            ThorynConfig.HubSource.ENV -> System.err.println("Using hub ${hub.url} (from ${ThorynConfig.HUB_ENV}).")
            ThorynConfig.HubSource.PREVIOUS_SESSION ->
                System.err.println("Using hub ${hub.url} (from your previous sign-in; pass --issuer to choose another).")
            else -> Unit
        }
        issuer = hub.url
        baseIssuer = hub.url
        return true
    }

    /**
     * SSO-3104 / SSO-3138 — resolve the interactive sign-in issuer: the issuer becomes the workspace's
     * tenant hub. The workspace is `--workspace`, else THORYN_WORKSPACE, else the platform default
     * [ThorynConfig.DEFAULT_WORKSPACE] (`thoryn`) — announced on stderr so a user who meant another
     * workspace sees how to choose it. The shared `default` tenant is never a sign-in target.
     */
    private fun selectWorkspaceIssuer(): Boolean {
        val explicit = workspace?.trim()?.takeIf { it.isNotEmpty() }
        val slug = explicit ?: ThorynConfig.DEFAULT_WORKSPACE.also {
            System.err.println(
                "Signing in on the default workspace '$it' — pass `--workspace <slug>` " +
                    "(or export ${ThorynConfig.WORKSPACE_ENV}) to sign in on another workspace.",
            )
        }
        baseIssuer = issuer
        signedInWorkspace = slug
        issuer = ThorynConfig.tenantIssuer(issuer, slug)
        return true
    }

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
        // SSO-2948 — the connection contract is the single source of the auth binding; it derives its
        // own issuer/gateway/scopes, so it runs before the manual-flag path and is exclusive with it.
        if (connectionFile != null) {
            return runConnectionFlow(connectionFile!!)
        }
        // SSO-3182 — no localhost default: resolve the platform's hub or fail fast with guidance.
        if (!resolveIssuer()) return EXIT_USAGE
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
            baseIssuer = issuer
            return runClientCredentialsFlow()
        }
        // SSO-3104 — the interactive flows sign in ON A WORKSPACE, never on the shared default tenant.
        if (!selectWorkspaceIssuer()) return EXIT_USAGE
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
     * SSO-2948 — sign in from a declarative connection contract. Derives issuer + gateway from the
     * workspace slug (via [ThorynConfig.tenantIssuer] / [ThorynConfig.gatewayForIssuer]), resolves the
     * client secret from the env var the contract NAMES (failing closed if unset/empty), and runs the
     * existing client-credentials flow requesting EXACTLY the contract's scopes, then stamps the
     * session so later commands need no host flags.
     */
    private fun runConnectionFlow(file: File): Int {
        // The contract is the single source of the binding — refuse to also honour the manual flags.
        val conflicting = buildList {
            if (issuerOption != null) add("--issuer")
            if (!gateway.isNullOrBlank()) add("--gateway")
            if (scope != ThorynConfig.DEFAULT_SCOPE) add("--scope")
            if (clientId != ThorynConfig.DEFAULT_CLIENT_ID) add("--client-id")
            if (useClientCredentials) add("--client-credentials")
            if (useDeviceCode) add("--device-code")
            if (useWorkloadIdentity) add("--workload-identity")
        }
        if (conflicting.isNotEmpty()) {
            System.err.println(
                "Error: --connection is mutually exclusive with ${conflicting.joinToString(", ")}. " +
                    "The connection contract is the single source of the workspace, client and scopes.",
            )
            return EXIT_USAGE
        }

        val connection = try {
            Connection.load(file)
        } catch (e: ConnectionException) {
            System.err.println("Error: ${e.message}")
            return EXIT_USAGE
        }

        // Resolve the hub base from the env var the contract names (-D property first, then env, so
        // tests and `java -jar -D…` work), falling back to the CLI's baked-in platform hub. SSO-3182 — no
        // localhost fallback: with neither, fail closed naming the env var.
        val hubBase = resolveNamedEnv(connection.hubBaseUrlEnv) ?: ThorynConfig.PLATFORM_HUB ?: run {
            System.err.println(
                "Error: the hub base URL env var '${connection.hubBaseUrlEnv}' (named by the connection's " +
                    "workspace.hubBaseUrlEnv) is unset or empty. Export it, e.g. " +
                    "${connection.hubBaseUrlEnv}=${ThorynConfig.STAGING_ISSUER}.",
            )
            return EXIT_USAGE
        }
        val derivedIssuer = ThorynConfig.tenantIssuer(hubBase, connection.slug)
        val derivedGateway = ThorynConfig.gatewayForIssuer(hubBase)

        try {
            IssuerUrlValidator.validate(derivedIssuer, devMode)
        } catch (e: IssuerUrlValidationException) {
            System.err.println("Error: derived issuer '$derivedIssuer' is invalid — ${e.message}")
            return EXIT_USAGE
        }

        // Fail closed when the named secret env var is unset/empty — the secret is NEVER in the file.
        val secret = resolveNamedEnv(connection.secretEnv)
        if (secret == null) {
            System.err.println(
                "Error: the client secret env var '${connection.secretEnv}' (named by the connection's " +
                    "auth.secretEnv) is unset or empty. Export it before signing in.",
            )
            return EXIT_CLIENT_CREDENTIALS_FAILED
        }

        val flow = ClientCredentialsFlow(
            issuer = derivedIssuer,
            clientId = connection.clientId,
            clientSecret = secret,
            sender = realHttpSender(),
        )
        // Request EXACTLY the declared scopes — the hub grants only what is requested, so the
        // contract's scope list is both the ceiling and the floor (no ScopeRegistry expansion).
        val requestedScope = connection.scopes.joinToString(" ")

        return try {
            val tokens = flow.run(requestedScope)
            tokenStore.write(
                tokens.copy(
                    issuer = derivedIssuer,
                    gateway = derivedGateway,
                    authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                    clientId = connection.clientId,
                ),
            )
            // SSO-2863 — a fresh login resets the base tenant; drop any stale workspace selection.
            SelectedWorkspaceStore().clear()
            println("Signed in (connection '${connection.slug}' / service account '${connection.clientId}').")
            tokens.scope?.let { println("Scopes: $it") }
            EXIT_OK
        } catch (e: ClientCredentialsException) {
            System.err.println("Sign-in failed: ${e.message}")
            EXIT_CLIENT_CREDENTIALS_FAILED
        }
    }

    /**
     * SSO-2948 — resolve an env var BY NAME, `-D` system property first then the environment (the
     * project-wide no-argv secret-resolution order, see [ThorynConfig.resolveClientSecret]). Returns
     * null when unset or blank so the caller can fail closed.
     */
    private fun resolveNamedEnv(name: String): String? =
        System.getProperty(name)?.takeIf { it.isNotBlank() }
            ?: System.getenv(name)?.takeIf { it.isNotBlank() }

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
            noRefreshTokenNotice(tokens, expandedScope(), deviceCode = true)?.let { System.err.println(it) }
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
            val authorizeUrl = authorizeUrl(
                issuer = issuer,
                clientId = clientId,
                redirectUri = redirectUri,
                scope = expandedScope(),
                codeChallenge = challenge,
                state = state,
                dpopJkt = dpopJkt(),
            )

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
            noRefreshTokenNotice(tokens, expandedScope(), deviceCode = false)?.let { System.err.println(it) }
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
            println("Not signed in. Run `thoryn login --workspace <slug>`.")
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
            exp <= now -> println("Signed in — access token EXPIRED. Run `${reLoginCommand(tokens)}` to re-authenticate.")
            else -> {
                val mins = (exp - now) / 60
                val suffix = if (canRefresh) ", auto-refreshes near expiry" else ", no refresh token — run `${reLoginCommand(tokens)}` when it expires"
                println("Signed in — access token valid for ${mins}m$suffix.")
            }
        }
        tokens.scope?.let { println("Scopes: $it") }
        return 0
    }

    /**
     * SSO-3199 — every login token-endpoint round-trip (authorization-code redemption, device-code
     * polling, client-credentials, workload identity) goes out with an RFC 9449 DPoP proof, so the hub
     * can bind `cnf.jkt` into the issued access token. Degrades to a plain sender when no secure store
     * for the DPoP key is available.
     */
    private fun realHttpSender(): HttpSender = Dpop.sender(Duration.ofSeconds(10))

    private fun urlEncode(s: String): String =
        java.net.URLEncoder.encode(s, Charsets.UTF_8)

    /**
     * SSO-3225 — the RFC 9449 §10 `dpop_jkt` for this authorize request: the RFC 7638 thumbprint of
     * the installation key that will sign the proof on the token request, or null when no proof
     * will be sent.
     *
     * ## Why the authorize request needs this at all
     *
     * Since SSO-3199 the ACCESS TOKEN is bound to whichever key signs the token-request proof. The
     * authorization CODE was bound to nothing — and this flow puts the code on a **literal-loopback
     * redirect** (RFC 8252 §7.3): `http://127.0.0.1:<port>`, in the clear, on a machine that may be
     * running other software. Anything that can read that redirect could redeem the code with its
     * OWN key and receive a token sender-constrained to the attacker. `dpop_jkt` names our key on
     * the way IN, so the hub can refuse a redemption by any other key (`invalid_grant`).
     *
     * PKCE already guards this leg, and the two compose rather than overlap: PKCE's `code_verifier`
     * is a secret held in this process's memory for one run, `dpop_jkt` binds to the long-lived
     * keychain key that the resulting token is bound to anyway.
     *
     * ## The gate is the same one the proof itself uses
     *
     * [DpopCapability] — the hub must advertise `dpop_signing_alg_values_supported` — and it is
     * asked FIRST, exactly as in [Dpop.sender]: on a platform that does not do DPoP this must not
     * touch the key store, so no key is generated and no "DPoP is disabled" warning is printed for
     * a feature that would not have been used. Sending `dpop_jkt` to a hub that ignores unknown
     * authorize parameters would be harmless, but a hub that validates them strictly would reject
     * the sign-in outright, and a released binary meets platforms older than itself.
     *
     * The memo key matches: `DpopCapability.hubBaseOf("<issuer>/oauth2/token")` strips the endpoint
     * path back to this same base, so the authorize probe and the later token-request probe share
     * one answer and one HTTP call.
     *
     * Null when the platform does not advertise DPoP, or when no key store is available — in both
     * cases no proof will ride on the token request either, so naming a key would bind the code to
     * something we could not then prove.
     */
    private fun dpopJkt(): String? =
        if (DpopCapability.advertisedBy(issuer.trimEnd('/'))) Dpop.session()?.thumbprint else null

    companion object {
        /**
         * SSO-3182 — the exact re-login line for a session: `thoryn login --workspace <slug>` when the
         * session recorded (or its tenant issuer names) a workspace, else plain `thoryn login`.
         */
        internal fun reLoginCommand(tokens: Tokens?): String {
            val slug = tokens?.workspace?.takeIf { it.isNotBlank() } ?: ThorynConfig.workspaceOfIssuer(tokens?.issuer)
            return if (slug != null) "thoryn login --workspace $slug" else "thoryn login"
        }

        /**
         * SSO-3182 — the notice printed after an interactive sign-in that asked for `offline_access` but got
         * NO refresh token back. The hub (Spring Authorization Server's `OAuth2RefreshTokenGenerator`) issues
         * none to a PUBLIC client on the authorization-code grant, so a loopback session of the public `cli`
         * client silently ended at the ~15-minute access-token expiry — the `HTTP 401` / "Could not enter
         * workspace" symptom of SSO-3182. Device-code grants do receive one. Null when a refresh token was
         * issued or `offline_access` was not requested.
         */
        internal fun noRefreshTokenNotice(tokens: Tokens, requestedScope: String, deviceCode: Boolean): String? {
            if (!tokens.refreshToken.isNullOrBlank()) return null
            if ("offline_access" !in requestedScope.split(' ', ',')) return null
            val remaining = tokens.expiresAtEpochSecond?.let { (it - System.currentTimeMillis() / 1000) / 60 }
                ?.takeIf { it >= 0 }?.let { " (in about ${it}m)" }.orEmpty()
            val alternative = if (deviceCode) "" else " `thoryn login --device-code` sessions do renew."
            return "Note: the hub issued no refresh token for this sign-in, so this session cannot renew itself — " +
                "it ends when the access token expires$remaining; run `thoryn login` again then.$alternative"
        }

        /**
         * SSO-2820 / SSO-3225 — the `/oauth2/authorize` URL for the interactive loopback sign-in.
         *
         * Extracted from the flow so the wire shape can be asserted directly: every parameter here
         * is a protocol commitment, and [dpopJkt] in particular is a security binding whose absence
         * is silent (RFC 9449 §10 — a code that names no key is redeemable by any key, which is
         * exactly the pre-SSO-3225 behaviour and looks identical from the outside).
         *
         * [dpopJkt] null omits the parameter entirely rather than sending an empty one: "no key
         * named" and "a key named badly" are very different requests to the hub.
         */
        internal fun authorizeUrl(
            issuer: String,
            clientId: String,
            redirectUri: String,
            scope: String,
            codeChallenge: String,
            state: String,
            dpopJkt: String?,
        ): String = buildString {
            append(issuer.trimEnd('/'))
            append("/oauth2/authorize")
            append("?response_type=code")
            append("&client_id=").append(encode(clientId))
            append("&redirect_uri=").append(encode(redirectUri))
            append("&scope=").append(encode(scope))
            append("&code_challenge=").append(encode(codeChallenge))
            append("&code_challenge_method=S256")
            append("&state=").append(encode(state))
            dpopJkt?.takeIf { it.isNotBlank() }?.let { append("&dpop_jkt=").append(encode(it)) }
        }

        private fun encode(s: String): String = java.net.URLEncoder.encode(s, Charsets.UTF_8)

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
