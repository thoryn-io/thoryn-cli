package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.util.concurrent.Callable

/**
 * `thoryn tenant ...` — tenant-level provisioning helpers (SSO-1553, epic
 * SSO-1545).
 *
 * Today the only subcommand is `seed`: a one-shot, ZERO-interaction provisioner
 * that turns a freshly-authenticated service account into a ready-to-test tenant
 * — a couple of sample OAuth clients plus an identity-service federation member,
 * optionally registering the tenant in product-api first.
 *
 * It is a thin orchestration over the SAME product-api endpoints the `clients`,
 * `federation`, and `workspace` commands use (so the audit trail and validation
 * rules are identical) — it does not call any new server endpoint.
 */
@Command(
    name = "tenant",
    description = ["Tenant-level provisioning helpers (seed a ready-to-test tenant)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        TenantCommand.SeedSubcommand::class,
    ],
)
class TenantCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn tenant <subcommand>")
        System.err.println("Subcommands: seed")
        return CommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn tenant seed --non-interactive --secret-dir <dir> [options]`
     *
     * One-shot provisioner for a ready-to-test tenant. Designed to run in CI
     * after `thoryn login --client-credentials` against the tenant's hub
     * subdomain (so the stored token carries the tenant's `tnt` claim, which
     * product-api's customer-plane endpoints require).
     *
     * Steps (each a call to an EXISTING, audited product-api endpoint):
     *
     *  1. **(optional) Register the tenant in product-api** — `POST /tenants`,
     *     the one tenant-provisioning endpoint exempt from the `tnt`-claim
     *     filter (SSO-912). Runs only when both `--tenant-id` and `--slug` are
     *     supplied; idempotent, so re-running the seed is safe. (Creating a
     *     brand-new HUB workspace via `/account/workspace` is a user / openid
     *     flow, not a service-account one — see `thoryn workspace create` for
     *     that; a machine token operates a tenant that already exists.)
     *  2. **Create sample OAuth clients** — `POST /api/v1/applications`
     *     (`--clients` of them, default 2). Each minted secret is written to a
     *     `0600` file under `--secret-dir` (NEVER printed to a pipe).
     *  3. **Attach an identity-service federation member** — `POST
     *     /federation-members` with `providerType=oidc` (SSO-1548), unless
     *     `--skip-federation` is set.
     *
     * **Secret-safety (SSO-1553 hard rule).** No secret is ever passed as an
     * argv value:
     *  - Created-client secrets are server-minted and written to files under
     *    `--secret-dir`.
     *  - The upstream federation `clientSecret` is read from
     *    `--federation-secret-file`, `THORYN_FEDERATION_SECRET` (env / `-D`), or
     *    a no-echo prompt — never `--federation-secret <value>`.
     *  - The CLI's OWN client secret (for the preceding `login
     *    --client-credentials`) is handled by `LoginCommand`, never persisted.
     *
     * **`--non-interactive`** asserts the run must not block on a prompt: if any
     * required secret can only come from a TTY, the command fails fast with a
     * clear error rather than hanging in CI. (The seed is non-interactive
     * regardless; the flag makes the intent explicit and turns "would prompt"
     * into a hard error — `--secret-dir` becomes required.)
     */
    @Command(
        name = "seed",
        description = ["Provision a ready-to-test tenant (sample clients + identity-service federation member), fully non-interactively."],
        mixinStandardHelpOptions = true,
    )
    class SeedSubcommand : Callable<Int> {

        @Option(
            names = ["--non-interactive"],
            description = ["Fail fast (no prompt) if a required secret is not supplied via env/file. Recommended in CI; makes --secret-dir required."],
        )
        var nonInteractive: Boolean = false

        @Option(
            names = ["--secret-dir"],
            description = ["Directory to write minted client-secret files into (0600). Required with --non-interactive."],
        )
        var secretDir: File? = null

        @Option(
            names = ["--clients"],
            description = ["Number of sample OAuth clients to create (default: 2)."],
        )
        var clientCount: Int = 2

        @Option(
            names = ["--name-prefix"],
            description = ["Display-name / id prefix for the seeded resources (default: \${DEFAULT-VALUE})."],
            defaultValue = "seed",
        )
        var namePrefix: String = "seed"

        @Option(
            names = ["--redirect-uri"],
            description = ["Redirect URI for the seeded clients (default: https://example.test/login/oauth2/code/{clientId})."],
        )
        var redirectUri: String? = null

        @Option(
            names = ["--client-scope"],
            description = ["Scope to grant each seeded client (repeatable; default: openid). Must be a subset of your own active scopes."],
        )
        var clientScopes: Array<String> = emptyArray()

        // ── Tenant registration (optional) ──────────────────────────────────

        @Option(
            names = ["--tenant-id"],
            description = ["Hub tenant UUID to register in product-api (POST /tenants). Supply with --slug to run the registration step."],
        )
        var tenantId: String? = null

        @Option(
            names = ["--slug"],
            description = ["Hub tenant slug for the product-api registration step."],
        )
        var slug: String? = null

        // ── Federation member ───────────────────────────────────────────────

        @Option(
            names = ["--skip-federation"],
            description = ["Skip attaching the identity-service federation member."],
        )
        var skipFederation: Boolean = false

        @Option(
            names = ["--federation-discovery-url"],
            description = ["OIDC discovery URL for the seeded identity-service member (default: \${DEFAULT-VALUE})."],
            defaultValue = "http://localhost:54702/.well-known/openid-configuration",
        )
        var federationDiscoveryUrl: String = "http://localhost:54702/.well-known/openid-configuration"

        @Option(
            names = ["--federation-client-id"],
            description = ["Client ID registered with the upstream identity-service (default: \${DEFAULT-VALUE})."],
            defaultValue = "identity-service",
        )
        var federationClientId: String = "identity-service"

        @Option(
            names = ["--federation-secret-file"],
            description = ["File holding the upstream federation client secret. Falls back to THORYN_FEDERATION_SECRET, then a no-echo prompt. Never pass the secret as an argument."],
        )
        var federationSecretFile: File? = null

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            if (clientCount < 0) {
                System.err.println("Error: --clients must be >= 0.")
                return CommandSupport.EXIT_USAGE
            }
            // Secret-dir is mandatory whenever we will mint client secrets: a
            // minted secret can only be surfaced safely to a file (a pipe is
            // refused). --non-interactive enforces it unconditionally so CI
            // can't accidentally rely on a TTY.
            if ((nonInteractive || clientCount > 0) && secretDir == null) {
                System.err.println(
                    "Error: --secret-dir <dir> is required to capture the ${clientCount} minted client secret(s) safely " +
                        "(they are never printed to a pipe). Pass --secret-dir, or --clients 0 to skip client creation.",
                )
                return CommandSupport.EXIT_USAGE
            }
            secretDir?.let { dir ->
                if (!dir.exists() && !dir.mkdirs()) {
                    System.err.println("Error: could not create --secret-dir '${dir.path}'.")
                    return CommandSupport.EXIT_IO_ERROR
                }
                if (!dir.isDirectory) {
                    System.err.println("Error: --secret-dir '${dir.path}' is not a directory.")
                    return CommandSupport.EXIT_USAGE
                }
            }
            if ((tenantId == null) != (slug == null)) {
                System.err.println("Error: --tenant-id and --slug must be supplied together (or neither).")
                return CommandSupport.EXIT_USAGE
            }

            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN

            // Resolve the federation secret UP FRONT (before any mutation) so a
            // missing secret fails the whole seed cleanly rather than half-way
            // through. Only needed when we will attach the member.
            val federationSecret: String? = if (skipFederation) {
                null
            } else {
                val resolved = resolveFederationSecret()
                if (resolved == null) {
                    // resolveFederationSecret already printed guidance.
                    return SecretIo.EXIT_NO_SECRET
                }
                resolved
            }

            val client = CommandSupport.client(gateway, tokens)
            val result = SeedResult()

            // ── Step 1: register tenant in product-api (optional) ───────────
            if (tenantId != null && slug != null) {
                try {
                    val registered = client.registerTenant(mapOf("tenantId" to tenantId, "slug" to slug))
                    result.tenant = registered["tenantId"]?.asString() ?: tenantId
                    result.tenantRegistered = true
                } catch (ex: ProductApiException) {
                    // A tnt-bearing token re-registering its own tenant should
                    // succeed (POST /tenants is idempotent). Surface a hard error
                    // here — the rest of the seed depends on the tenant existing.
                    return CommandSupport.renderError(format, ex)
                } catch (ex: Exception) {
                    System.err.println("Request failed during tenant registration: ${ex.message}")
                    return CommandSupport.EXIT_IO_ERROR
                }
            }

            // ── Step 2: sample OAuth clients ────────────────────────────────
            for (i in 1..clientCount) {
                val name = "$namePrefix-client-$i"
                val redirect = redirectUri ?: "https://example.test/login/oauth2/code/$name"
                val body = linkedMapOf<String, Any?>(
                    "displayName" to name,
                    "redirectUris" to listOf(redirect),
                    "clientType" to "confidential",
                )
                body["scopes"] = if (clientScopes.isNotEmpty()) clientScopes.toList() else listOf("openid")
                try {
                    val response = client.createApplication(body)
                    val clientId = response["clientId"]?.asString() ?: name
                    val secret = response["clientSecret"]?.asString()
                    var secretPath: String? = null
                    if (!secret.isNullOrEmpty()) {
                        val secretFile = File(secretDir, "$clientId.secret")
                        val emitted = SecretIo.emitSecret(
                            label = "Client secret for '$clientId'",
                            secret = secret,
                            secretFile = secretFile,
                            forceStdout = false,
                        )
                        if (!emitted) {
                            // Should not happen (secretDir is set) — but if the
                            // write failed, fail loud so the operator notices the
                            // secret was lost.
                            return SecretIo.EXIT_NO_SECRET
                        }
                        secretPath = secretFile.absolutePath
                    }
                    result.clients.add(SeededClient(clientId, secretPath))
                } catch (ex: ProductApiException) {
                    return CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
                } catch (ex: Exception) {
                    System.err.println("Request failed creating client '$name': ${ex.message}")
                    return CommandSupport.EXIT_IO_ERROR
                }
            }

            // ── Step 3: identity-service federation member ──────────────────
            if (!skipFederation && federationSecret != null) {
                val body = linkedMapOf<String, Any?>(
                    "providerType" to "oidc",
                    "displayName" to "$namePrefix-identity-service",
                    "discoveryUrl" to federationDiscoveryUrl,
                    "clientId" to federationClientId,
                    "clientSecret" to federationSecret,
                )
                try {
                    val response = client.createFederationMember(body)
                    result.federationMemberId = response["id"]?.asString()
                } catch (ex: ProductApiException) {
                    return CommandSupport.renderError(format, ex, requiredScope = "tenant:federation.write")
                } catch (ex: Exception) {
                    System.err.println("Request failed attaching federation member: ${ex.message}")
                    return CommandSupport.EXIT_IO_ERROR
                }
            }

            emit(format, result)
            return CommandSupport.EXIT_OK
        }

        /**
         * Resolve the upstream federation client secret without it ever touching
         * argv. Env / `-D` first (the CI knob), then `--federation-secret-file`,
         * then a no-echo prompt (refused on a non-TTY — i.e. CI without a file).
         */
        private fun resolveFederationSecret(): String? {
            System.getProperty(FEDERATION_SECRET_ENV)?.takeIf { it.isNotBlank() }?.let { return it }
            System.getenv(FEDERATION_SECRET_ENV)?.takeIf { it.isNotBlank() }?.let { return it }
            return SecretIo.readSecretInput(
                secretFile = federationSecretFile,
                prompt = "Upstream identity-service client secret for federation member: ",
            )
        }

        private fun emit(format: OutputFormat, result: SeedResult) {
            val structured = linkedMapOf<String, Any?>(
                "tenant" to result.tenant,
                "tenantRegistered" to result.tenantRegistered,
                "clients" to result.clients.map {
                    linkedMapOf("clientId" to it.clientId, "secretFile" to it.secretFile)
                },
                "federationMemberId" to result.federationMemberId,
            )
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, System.out)
                OutputFormat.YAML -> Printers.yaml(structured, System.out)
                OutputFormat.TABLE -> {
                    println("Seeded tenant.")
                    result.tenant?.let { println("  tenant:            $it (registered=${result.tenantRegistered})") }
                    result.clients.forEach {
                        println("  client:            ${it.clientId}  (secret → ${it.secretFile ?: "n/a"})")
                    }
                    result.federationMemberId?.let { println("  federation member: $it (identity-service / oidc)") }
                    if (result.clients.isNotEmpty()) {
                        System.err.println(
                            "Minted ${result.clients.size} client secret(s) written under ${secretDir?.absolutePath}. " +
                                "Shown once; not retrievable later.",
                        )
                    }
                }
            }
        }

        companion object {
            /** Env / system-property name for the upstream federation client secret. */
            const val FEDERATION_SECRET_ENV: String = "THORYN_FEDERATION_SECRET"
        }
    }

    /** Accumulates what the seed provisioned, for the final output. */
    private class SeedResult {
        var tenant: String? = null
        var tenantRegistered: Boolean = false
        val clients: MutableList<SeededClient> = mutableListOf()
        var federationMemberId: String? = null
    }

    private data class SeededClient(val clientId: String, val secretFile: String?)
}
