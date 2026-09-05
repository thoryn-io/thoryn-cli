package com.devnow.thoryn.cli.config

/**
 * Default endpoints baked into the CLI binary.
 *
 * Production builds will overwrite these via `-D` properties or a generated
 * `oathy.properties` resource at release time. For local development the
 * defaults point at `localhost` services so a developer can `thoryn login`
 * against a hub running on their own machine.
 *
 * Known environments (override via `--issuer` and `--gateway`):
 *
 *  - Local dev: `http://localhost:54702` (hub) and `http://localhost:8991` (gateway)
 *  - Staging:   `https://hub.stg.thoryn.org` (hub) and the matching staging gateway
 *  - Production (TBD)
 */
object ThorynConfig {
    const val DEFAULT_ISSUER = "http://localhost:54702"

    /**
     * SSO-2821 — the default OAuth client id for `thoryn login`.
     *
     * MUST match the client the hub actually seeds for the CLI: `thoryn-cli` (hub migration V32),
     * a confidential customer-plane `authorization_code` + `refresh_token` + device-code client with
     * literal-loopback redirect URIs (`http://127.0.0.1/callback`, `http://[::1]/callback`, V136) and
     * the `tenant:*` scope set. The former default `oathy-cli` was never seeded, so `thoryn login`
     * failed out of the box unless the user passed `--client-id thoryn-cli`. `thoryn-cli` is
     * confidential, so interactive/device/CI sign-in still needs the client secret via
     * `THORYN_CLIENT_SECRET` / `--client-secret-file` (see [resolveClientSecret]).
     */
    const val DEFAULT_CLIENT_ID = "thoryn-cli"

    /**
     * SSO-2870 — the reserved slug of a workspace's platform-managed PRODUCTION environment (mirrors
     * `core` `TrustedTenantIssuers.PRODUCTION_ENV_SLUG`). A CLI session with no explicit `env use`
     * selection resolves to this production plane, so `env list` marks it active by default.
     */
    const val PRODUCTION_ENV_SLUG = "production"

    /**
     * SSO-2874 — the public example-recipe catalog (`thoryn examples catalog --remote` / `update`).
     * [EXAMPLES_RELEASE_API] is the GitHub REST base for its releases (a seam tests point at a stub);
     * a signed release attaches `catalog.zip` + `catalog.zip.sig`.
     */
    const val EXAMPLES_REPO = "thoryn-io/thoryn-examples"
    const val EXAMPLES_RELEASE_API = "https://api.github.com"

    /**
     * SSO-2874 — the CLI's pinned TRUST ANCHOR for the recipe catalog: the Ed25519 release-signing
     * PUBLIC key (X.509 SubjectPublicKeyInfo, base64). A fetched `catalog.zip` is used only if its
     * detached signature verifies against this key, so a tampered or unsigned catalog is refused. The
     * private half is held only as the `THORYN_EXAMPLES_SIGNING_KEY` secret in the thoryn-examples repo
     * (the release workflow signs with it) — never in this repo. Rotating the key is a CLI release.
     */
    const val EXAMPLES_SIGNING_PUBLIC_KEY_SPKI_B64 =
        "MCowBQYDK2VwAyEAs8l5WV3Oi7Tl46e8NrGEHqeni4e5KsUW+H/3m3w/rgU="
    const val DEFAULT_GATEWAY = "http://localhost:8991"

    /** Convenience constant — pass to `--issuer` to point the CLI at the staging hub. */
    const val STAGING_ISSUER = "https://hub.stg.thoryn.org"

    /** The staging gateway (customer-plane ingress) matching [STAGING_ISSUER]. */
    const val STAGING_GATEWAY = "https://api.stg.thoryn.org"

    /**
     * SSO-2827 — best-effort gateway base URL for a hub [issuer], used at
     * `thoryn login` to record the session's gateway when `--gateway` isn't given.
     *
     * Thoryn deployments name the customer-plane gateway by swapping the `hub.`
     * label of the hub host for `api.` (hub.stg.thoryn.org → api.stg.thoryn.org,
     * hub.thoryn.org → api.thoryn.org), preserving scheme/port/path. A hub host
     * that doesn't start with `hub.` (local dev `localhost`, or a bespoke
     * topology) has no derivable gateway, so we fall back to [DEFAULT_GATEWAY];
     * pass `thoryn login --gateway <url>` to set it explicitly there.
     */
    fun gatewayForIssuer(issuer: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return DEFAULT_GATEWAY
            if (!host.startsWith("hub.")) return DEFAULT_GATEWAY
            val apiHost = "api." + host.removePrefix("hub.")
            java.net.URI(uri.scheme, uri.userInfo, apiHost, uri.port, null, null, null)
                .toString()
                .trimEnd('/')
        } catch (_: Exception) {
            DEFAULT_GATEWAY
        }
    }

    /** Local-dev identity-service base URL (the CLI examples' user-facing sign-in host). */
    const val DEFAULT_IDENTITY = "http://localhost:9099"

    /**
     * SSO-2830 — the identity-service base host for a tenant `slug`, derived from the
     * hub [issuer]. identity-service is tenant-scoped by REQUEST HOST (SSO-1920), so a
     * user provisioned for tenant X can only sign in when the login leg hits
     * `{slug}.identity.<env>`. Thoryn names the identity host by swapping the hub's
     * `hub.` label for `identity.` (hub.stg.thoryn.org → identity.stg.thoryn.org) and
     * prefixing the tenant slug (→ `{slug}.identity.stg.thoryn.org`), preserving
     * scheme/port. A hub host that isn't `hub.<env>` (local dev) has no derivable
     * identity host, so we fall back to [DEFAULT_IDENTITY] (no slug prefix locally).
     */
    fun tenantIdentityHost(issuer: String, slug: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return DEFAULT_IDENTITY
            if (!host.startsWith("hub.")) return DEFAULT_IDENTITY
            val identityHost = "$slug.identity." + host.removePrefix("hub.")
            java.net.URI(uri.scheme, uri.userInfo, identityHost, uri.port, null, null, null)
                .toString()
                .trimEnd('/')
        } catch (_: Exception) {
            DEFAULT_IDENTITY
        }
    }

    /**
     * SSO-2830 — the tenant hub issuer for a workspace `slug`, derived from the base
     * hub [issuer] by prefixing the slug on the hub host (hub.stg.thoryn.org →
     * `{slug}.hub.stg.thoryn.org`). This is the issuer a per-tenant relying party
     * authenticates against so the minted token carries the tenant's `tnt` claim.
     * A non-`hub.` host (local dev) is returned unchanged.
     */
    fun tenantIssuer(issuer: String, slug: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return issuer.trimEnd('/')
            if (!host.startsWith("hub.")) return issuer.trimEnd('/')
            java.net.URI(uri.scheme, uri.userInfo, "$slug.$host", uri.port, null, null, null)
                .toString()
                .trimEnd('/')
        } catch (_: Exception) {
            issuer.trimEnd('/')
        }
    }

    /**
     * Default scope set requested by `thoryn login`.
     *
     * SSO-1552 — the device-flow login requests the tenant-configuration scopes
     * (`tenant:applications.{read,write}`, `tenant:federation.{read,write}`,
     * `tenant:audit.read`) so the `clients`, `federation`, and `audit` command
     * trees are authorized out of the box. `workspace` create/list ride on
     * `SCOPE_openid` (the hub `/account/[*]` surface) and need no extra scope.
     * The legacy workforce-era `tenant:clients.read` / `tenant:users.read` are
     * retained so `thoryn clients list` against an older deployment keeps
     * working; the hub drops scopes the tenant admin doesn't hold.
     */
    const val DEFAULT_SCOPE =
        "openid offline_access " +
            "tenant:applications.read tenant:applications.write " +
            "tenant:federation.read tenant:federation.write " +
            "tenant:audit.read " +
            // SSO-2870 — the environment select/manage surface (`thoryn env`). Granted to the
            // thoryn-cli client in hub V119; the hub drops it for an admin who doesn't hold it.
            "tenant:environments.read tenant:environments.write " +
            "tenant:clients.read tenant:users.read"

    /**
     * Default hub base URL for the workspace surface (`/account/[*]`), which is
     * NOT routed through the api-gateway. `thoryn workspace` commands default to
     * the same value as `--issuer` and can be overridden with `--hub`.
     */
    const val DEFAULT_HUB = DEFAULT_ISSUER

    /**
     * Client secret read from the `THORYN_CLIENT_SECRET` env var. The hub's
     * device-authorization endpoint currently requires confidential client
     * authentication (Basic Auth or `client_secret_post`); a true public
     * client branch on that endpoint is a hub-side follow-up.
     *
     * For local dev the user sets this to the secret of whatever client
     * they registered. CI uses a per-pipeline secret; production binaries
     * may bundle a release-time-injected value.
     *
     * Resolution order (first non-blank wins):
     *   1. `THORYN_CLIENT_SECRET` system property — used by tests (no env-var
     *      reflection hacks) and by `java -jar` invocations that prefer `-D`
     *      flags over a separately-set env var.
     *   2. `THORYN_CLIENT_SECRET` environment variable — the canonical
     *      knob documented for end users.
     */
    fun resolveClientSecret(): String? =
        System.getProperty("THORYN_CLIENT_SECRET")?.takeIf { it.isNotBlank() }
            ?: System.getenv("THORYN_CLIENT_SECRET")?.takeIf { it.isNotBlank() }
}
