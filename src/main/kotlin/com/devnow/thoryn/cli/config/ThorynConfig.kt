package com.devnow.thoryn.cli.config

/**
 * Endpoints, defaults and env knobs baked into the CLI binary.
 *
 * SSO-3182 — a released CLI has NO localhost default for the platform it signs in to. `thoryn login`
 * resolves the platform BASE ISSUER ([resolveHubBase]) from, in order: `--issuer`, the [ISSUER_ENV]
 * env var (`THORYN_ISSUER`, or its `THORYN_HUB` alias), the platform of the previous session on this
 * machine, and finally the baked-in [PLATFORM_HUB] — which stays `null` until the production platform
 * domain is live (a product decision). With none of them, login fails fast with guidance instead of
 * silently opening `http://localhost:54702/oauth2/authorize` (what 0.17/0.18 did).
 *
 * SSO-3296 (epic SSO-3289) — the public authentication host moves from `{slug}.hub.<domain>` to
 * `{slug}.auth.<domain>`. **Nothing in this file hard-codes the word.** Every composed host derives its
 * label from the base issuer the CLI was pointed at ([DEFAULT_TENANT_HOST_LABELS], [labelIndex]), so
 * one binary is correct before AND after the SSO-3297 staging cutover. The single value that must move
 * at cutover is [STAGING_ISSUER], a convenience/help-text constant.
 *
 * Known platforms:
 *
 *  - Staging:    `https://hub.stg.thoryn.org` ([STAGING_ISSUER]) / `https://api.stg.thoryn.org`
 *                — becomes `https://auth.stg.thoryn.org` at the SSO-3297 cutover
 *  - Local dev:  `http://localhost:54702` ([LOCAL_DEV_HUB]) / `http://localhost:8991` — pass
 *    `--issuer http://localhost:54702` (or export THORYN_ISSUER) explicitly
 *  - Production: not live yet ([PLATFORM_HUB] is `null`; it will be `https://auth.thoryn.io`)
 */
object ThorynConfig {
    /** SSO-3182 — the local-dev hub (a hub running on the developer's machine). Never an implicit default for login. */
    const val LOCAL_DEV_HUB = "http://localhost:54702"

    /**
     * SSO-3296 — the env var naming the platform BASE ISSUER (`https://<label>.<env>`) `thoryn login`
     * signs in to when `--issuer` is not passed. This is the DOCUMENTED name; [HUB_ENV] (`THORYN_HUB`)
     * stays an accepted alias so recipes, CI connections and shell profiles written before the
     * SSO-3289 host rename keep working unchanged.
     */
    const val ISSUER_ENV = "THORYN_ISSUER"

    /**
     * SSO-3182 — the legacy env var naming the hub BASE URL. Kept as a silent alias of [ISSUER_ENV]
     * (SSO-3296): `THORYN_HUB` is a customer-facing spelling of an INTERNAL component word, which is
     * the whole reason epic SSO-3289 exists. Still the name the connection contract's
     * `workspace.hubBaseUrlEnv` defaults to, so connection files that omit the field keep resolving.
     */
    const val HUB_ENV = "THORYN_HUB"

    /**
     * SSO-3296 — the env vars naming the platform base issuer, in resolution order. `THORYN_ISSUER`
     * is the documented name; `THORYN_HUB` is the retained alias.
     */
    val ISSUER_ENV_NAMES = listOf(ISSUER_ENV, HUB_ENV)

    /**
     * SSO-3296 — the HOST LABEL separating a workspace slug from the platform apex in a public Thoryn
     * host: `{slug}.{label}.{apex}` (e.g. `acme.auth.stg.thoryn.org`, base `auth.stg.thoryn.org`).
     *
     * The CLI **never assumes** a label. It READS the one already present in the base issuer it was
     * pointed at (`--issuer`, [ISSUER_ENV]/[HUB_ENV], the previous session, [PLATFORM_HUB]) and reuses
     * it when composing a workspace issuer, the gateway host or the sign-in host. That is what makes
     * one binary correct on both sides of the SSO-3297 staging cutover with no flag, no discovery probe
     * and no re-release: pointed at `https://hub.stg.thoryn.org` it composes `acme.hub.stg.thoryn.org`;
     * pointed at `https://auth.stg.thoryn.org` it composes `acme.auth.stg.thoryn.org`.
     *
     * Per ADR `2026-09-22-public-issuer-host-auth-subdomain.md` `auth` is the public word and `hub`
     * retires to being an internal component name. Both are recognised here because staging serves
     * `hub.` until SSO-3297 flips `OAUTHY_TENANCY_PLATFORM_DOMAIN`; the hub advertises no host template
     * in its discovery document (SSO-3291 deliberately added no new property), so the base issuer the
     * operator already supplies is the only non-guessing source of the label.
     */
    val DEFAULT_TENANT_HOST_LABELS = listOf("auth", "hub")

    /**
     * SSO-3296 — escape hatch naming an ADDITIONAL host label to recognise, for a topology whose base
     * host is neither `auth.` nor `hub.` (a bespoke deployment, or a future word) without waiting for a
     * CLI release. Takes precedence over [DEFAULT_TENANT_HOST_LABELS]. A custom domain
     * (`auth.acme.com`, epic SSO-3290) needs no label: such an issuer is passed through verbatim.
     */
    const val TENANT_HOST_LABEL_ENV = "THORYN_TENANT_HOST_LABEL"

    /** SSO-3296 — the recognised host labels: [TENANT_HOST_LABEL_ENV] first, then the built-ins. */
    fun tenantHostLabels(env: (String) -> String? = { System.getProperty(it) ?: System.getenv(it) }): List<String> {
        val override = env(TENANT_HOST_LABEL_ENV)?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        return if (override == null) DEFAULT_TENANT_HOST_LABELS else listOf(override) + DEFAULT_TENANT_HOST_LABELS
    }

    /**
     * SSO-3296 — index of the first host component that is a recognised platform label, else `-1`.
     *
     * `0` means [host] is a BASE host (`auth.stg.thoryn.org`); `1` means it is a WORKSPACE host
     * (`acme.auth.stg.thoryn.org`) whose slug is the first component. Anything else — a deeper match,
     * no match, `localhost`, an IP literal, a custom domain — is `-1`, and every helper below then
     * leaves the URL alone rather than guessing a host.
     */
    internal fun labelIndex(host: String, labels: List<String> = tenantHostLabels()): Int {
        val idx = host.lowercase().split('.').indexOfFirst { it in labels }
        return if (idx == 0 || idx == 1) idx else -1
    }

    private fun withHost(uri: java.net.URI, host: String): String =
        java.net.URI(uri.scheme, uri.userInfo, host, uri.port, null, null, null).toString().trimEnd('/')

    /**
     * SSO-3182 — the production platform's base issuer baked into a release, or `null` while the
     * production domain is not live. OPEN QUESTION (product owner): set this once production serves
     * traffic. SSO-3296 — per ADR `2026-09-22-public-issuer-host-auth-subdomain.md` the production
     * value is `https://auth.thoryn.io`, so a bare `thoryn login --workspace <slug>` would then reach
     * `https://<slug>.auth.thoryn.io`.
     */
    val PLATFORM_HUB: String? = null

    /** SSO-3182 — where a resolved hub base came from (for the one-line notice `thoryn login` prints). */
    enum class HubSource { FLAG, ENV, PREVIOUS_SESSION, PLATFORM }

    data class HubBase(val url: String, val source: HubSource)

    /**
     * SSO-3182 — resolve the hub BASE URL `thoryn login` signs in to, or null when nothing names one:
     *  1. [explicit] (`--issuer`);
     *  2. the [ISSUER_ENV] (`THORYN_ISSUER`) system property then environment variable, else the
     *     [HUB_ENV] (`THORYN_HUB`) alias (SSO-3296) — so a pre-rename shell profile or CI job that
     *     exports only `THORYN_HUB` keeps resolving;
     *  3. the base hub of the previous session on this machine ([previousSessionIssuer], the stored
     *     tenant issuer, normalised by [baseHubOf]) — so `thoryn login --workspace thoryn` after the first
     *     `--issuer` sign-in reuses the same platform, which is what the "run `thoryn login`" recovery
     *     hints rely on;
     *  4. the baked-in [platformHub] ([PLATFORM_HUB]).
     */
    fun resolveHubBase(
        explicit: String?,
        previousSessionIssuer: String?,
        env: (String) -> String? = { System.getProperty(it) ?: System.getenv(it) },
        platformHub: String? = PLATFORM_HUB,
    ): HubBase? {
        explicit?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }?.let { return HubBase(it, HubSource.FLAG) }
        for (name in ISSUER_ENV_NAMES) {
            env(name)?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }?.let { return HubBase(it, HubSource.ENV) }
        }
        previousSessionIssuer?.takeIf { it.isNotBlank() }?.let { return HubBase(baseHubOf(it), HubSource.PREVIOUS_SESSION) }
        platformHub?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }?.let { return HubBase(it, HubSource.PLATFORM) }
        return null
    }

    /**
     * SSO-3182 — the platform BASE of an issuer: a workspace issuer `https://<slug>.<label>.<env>`
     * becomes `https://<label>.<env>`; a base issuer (`<label>.<env>`) or a single-host local hub is
     * returned unchanged. SSO-3296 — label-driven ([labelIndex]), so this holds for `auth.` and `hub.`.
     */
    fun baseHubOf(issuer: String): String {
        val trimmed = issuer.trim().trimEnd('/')
        return try {
            val uri = java.net.URI(trimmed)
            val host = uri.host ?: return trimmed
            if (labelIndex(host) != 1) return trimmed
            withHost(uri, host.substringAfter('.'))
        } catch (_: Exception) {
            trimmed
        }
    }

    /**
     * SSO-3182 — the workspace slug of a workspace issuer `https://<slug>.<label>.<env>`, else null.
     * SSO-3296 — label-driven, so `acme.auth.stg.thoryn.org` and `acme.hub.stg.thoryn.org` both yield
     * `acme`, while a base issuer (`auth.stg.thoryn.org`) correctly yields null.
     */
    fun workspaceOfIssuer(issuer: String?): String? {
        if (issuer.isNullOrBlank()) return null
        return try {
            val host = java.net.URI(issuer.trim()).host ?: return null
            if (labelIndex(host) != 1) null else host.substringBefore('.')
        } catch (_: Exception) {
            null
        }
    }

    /** SSO-3182 — the guidance `thoryn login` prints when no platform issuer could be resolved. */
    val NO_HUB_GUIDANCE: String =
        """
        Error: no Thoryn platform selected — this CLI has no built-in issuer yet.
        Name the platform base issuer once; later sign-ins on this machine reuse it:
            thoryn login --workspace <slug> --issuer $STAGING_ISSUER      # Thoryn staging
        or export $ISSUER_ENV=$STAGING_ISSUER. For a platform on your own machine: --issuer $LOCAL_DEV_HUB
        """.trimIndent()

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
    const val DEFAULT_CLIENT_ID = "cli"

    /**
     * SSO-3104 — the env var that names the workspace `thoryn login` signs in on when `--workspace` is
     * not passed. Interactive sign-in is always ON A WORKSPACE (`https://<slug>.<label>.<env>`): the
     * shared default tenant is not a sign-in target any more.
     */
    const val WORKSPACE_ENV = "THORYN_WORKSPACE"

    /**
     * SSO-3138 — the workspace an interactive `thoryn login` signs in on when neither `--workspace` nor
     * [WORKSPACE_ENV] names one: the platform's own default workspace. An explicit choice always wins,
     * and the shared `default` TENANT is still never a sign-in target.
     */
    const val DEFAULT_WORKSPACE = "thoryn"

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

    /**
     * SSO-2879 (epic SSO-2871) — defaults for `thoryn login --workload-identity`, the secret-less
     * sign-in the thoryn-examples recipe-conformance CI uses (GitHub Actions OIDC -> hub WIF
     * token-exchange, replacing the static `THORYN_CI_CLIENT_SECRET`). The values match hub
     * migration V143's seeded `ci-conformance` tenant + `conformance-ci-github-wif` exchange client.
     */
    const val DEFAULT_WIF_CLIENT_ID = "conformance-ci-github-wif"

    /** The workspace slug whose tenant-subdomain token endpoint the WIF request is POSTed to (V143). */
    const val DEFAULT_WIF_TENANT_SLUG = "ci-conformance"

    /** The `kid` of the CI signing key — matches the inline public JWKS seeded in hub V143. */
    const val DEFAULT_WIF_KEY_ID = "ci-conformance-wif-v1"

    /** Env var holding the PKCS#8 PEM of the CI private_key_jwt signing key (the GitHub secret). */
    const val WIF_SIGNING_KEY_ENV = "THORYN_CI_WIF_SIGNING_KEY"

    /** Optional env override for the GitHub OIDC subject token (local testing without a runner). */
    const val WIF_SUBJECT_TOKEN_ENV = "THORYN_CI_WIF_SUBJECT_TOKEN"

    /**
     * The scope set requested by `--workload-identity` — EXACTLY the `conformance-ci-github-wif`
     * client's registered scopes (V143, + `tenant:users.*` from V146/SSO-2907). It must be a subset
     * of the client's registered set: the WIF exchange bounds the minted token to
     * `requested ∩ client-registered` and rejects `invalid_scope` when the request exceeds it (a WIF
     * subject token carries no scope of its own). ORDERING (project_console_scope_grant_ordering): the
     * hub grant (V146) MUST deploy before a CLI requesting the added scope runs, else this request is
     * an `invalid_scope` — the migration ships in the same PR and deploys ahead of any CLI re-release.
     */
    const val DEFAULT_WIF_SCOPE =
        "openid tenant:applications.read tenant:applications.write " +
            "tenant:federation.read tenant:federation.write " +
            "tenant:users.read tenant:users.write"

    /**
     * Convenience constant — pass to `--issuer` to point the CLI at the staging platform. Used ONLY in
     * help text, the no-platform guidance and the connection error message; it is never a silent
     * default, so changing it cannot re-point an existing session.
     *
     * **SSO-3297 CUTOVER — this is the CLI's one-line flip.** Staging serves `hub.stg.thoryn.org`
     * until the big-bang deploy flips `OAUTHY_TENANCY_PLATFORM_DOMAIN`; on that day this becomes
     * `https://auth.stg.thoryn.org` and nothing else in the CLI changes, because every composed host
     * derives its label from the base issuer at runtime ([DEFAULT_TENANT_HOST_LABELS]).
     */
    const val STAGING_ISSUER = "https://hub.stg.thoryn.org"

    /** The staging gateway (customer-plane ingress) matching [STAGING_ISSUER]. */
    const val STAGING_GATEWAY = "https://api.stg.thoryn.org"

    /**
     * SSO-2827 — best-effort gateway base URL for a hub [issuer], used at
     * `thoryn login` to record the session's gateway when `--gateway` isn't given.
     *
     * Thoryn deployments name the customer-plane gateway by swapping the platform
     * LABEL of the base issuer host for `api.` (auth.stg.thoryn.org →
     * api.stg.thoryn.org, hub.stg.thoryn.org → api.stg.thoryn.org), preserving
     * scheme/port/path. SSO-3296 — label-driven ([labelIndex]), so this holds on
     * both sides of the SSO-3297 cutover; the customer plane's own host
     * (`api.<env>`) is unchanged by that cutover (ADR §1). A host whose first
     * component is not a recognised label (local dev `localhost`, a bespoke
     * topology, a custom domain) has no derivable gateway, so we fall back to
     * [DEFAULT_GATEWAY]; pass `thoryn login --gateway <url>` explicitly there.
     */
    fun gatewayForIssuer(issuer: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return DEFAULT_GATEWAY
            if (labelIndex(host) != 0) return DEFAULT_GATEWAY
            withHost(uri, "api." + host.substringAfter('.'))
        } catch (_: Exception) {
            DEFAULT_GATEWAY
        }
    }

    /** Local-dev identity-service base URL (the CLI examples' user-facing sign-in host). */
    const val DEFAULT_IDENTITY = "http://localhost:9099"

    /**
     * SSO-2830 — the identity-service base URL for a workspace `slug`, derived from the base
     * [issuer]. identity-service is tenant-scoped by REQUEST HOST (SSO-1920), so a user provisioned
     * for workspace X can only sign in when the login leg hits that workspace's directory host.
     *
     * SSO-3296 — the SHAPE follows the base issuer's label, so one binary is right on both sides of
     * the SSO-3297 cutover:
     *
     *  - label `hub` (pre-cutover): the separate directory host, hub's `hub.` label swapped for
     *    `identity.` and the slug prefixed — `https://{slug}.identity.stg.thoryn.org`.
     *  - any other label (`auth`, or a [TENANT_HOST_LABEL_ENV] override): SAME-ORIGIN, identity
     *    mounted under the reserved `/id` context path on the workspace host (ADR §2) —
     *    `https://{slug}.auth.stg.thoryn.org/id`.
     *
     * A base host whose first component is not a recognised label (local dev) has no derivable
     * directory host, so we fall back to [DEFAULT_IDENTITY] (no slug prefix locally).
     */
    fun tenantIdentityHost(issuer: String, slug: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return DEFAULT_IDENTITY
            if (labelIndex(host) != 0) return DEFAULT_IDENTITY
            val label = host.substringBefore('.').lowercase()
            val apex = host.substringAfter('.')
            if (label == LEGACY_TENANT_HOST_LABEL) {
                withHost(uri, "$slug.$LEGACY_IDENTITY_LABEL.$apex")
            } else {
                withHost(uri, "$slug.$host") + IDENTITY_CONTEXT_PATH
            }
        } catch (_: Exception) {
            DEFAULT_IDENTITY
        }
    }

    /** SSO-3296 — the pre-SSO-3297 host label, the only one with a SEPARATE directory host. */
    const val LEGACY_TENANT_HOST_LABEL = "hub"

    /** SSO-3296 — the label of the retired standalone identity host (`{slug}.identity.<env>`). */
    const val LEGACY_IDENTITY_LABEL = "identity"

    /**
     * SSO-3296 — the reserved path prefix identity-service is mounted under on the shared workspace
     * host (its Spring `server.servlet.context-path`, ADR §2). Two characters, so it can never collide
     * with a workspace or environment slug (`TrustedTenantIssuers.SLUG_PATTERN` has a 3-char floor).
     */
    const val IDENTITY_CONTEXT_PATH = "/id"

    /**
     * SSO-2830 — the WORKSPACE issuer for a `slug`, derived from the base [issuer] by prefixing the
     * slug on the base host (auth.stg.thoryn.org → `{slug}.auth.stg.thoryn.org`). This is the issuer
     * a per-workspace relying party authenticates against, so the minted token carries that
     * workspace's `tnt` claim.
     *
     * SSO-3296 — the label is READ from [issuer] ([labelIndex]), never assumed, so this composes the
     * `hub.` shape today and the `auth.` shape after the SSO-3297 cutover from the same binary. A base
     * host whose first component is not a recognised label (local dev, a custom domain — ADR §5, where
     * the issuer IS the custom host) is returned unchanged.
     *
     * The SANDBOX issuer keeps its PATH form — workspace issuer + `/{env}` (ADR §3) — and is composed
     * by the caller, not here; only the host word moved.
     */
    fun tenantIssuer(issuer: String, slug: String): String {
        return try {
            val uri = java.net.URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return issuer.trimEnd('/')
            if (labelIndex(host) != 0) return issuer.trimEnd('/')
            withHost(uri, "$slug.$host")
        } catch (_: Exception) {
            issuer.trimEnd('/')
        }
    }

    /**
     * Default scope set requested by an interactive `thoryn login`.
     *
     * SSO-3182 — EXACTLY the scope set the CLI's login client `cli` is registered with (declared in this
     * repo's `.thoryn/provision.yaml`; `CiProvisionFileConformanceTest` pins the two equal), so a bare
     * `thoryn login` authorizes every command — including `provision apply` of a file with `grants:`
     * (`tenant:access.write`), login themes / methods / flows (`tenant:idp.*`) and an email provider
     * (`tenant:email.*`) — without a hand-typed `--scope`. Requesting a scope the client does NOT hold is
     * an `invalid_scope` sign-in failure (SSO-2278), which is why the set is pinned to the client's. The
     * hub mints only the subset the signing-in admin actually holds, so a broad request grants nothing
     * extra. `workspace` create/list ride on `SCOPE_openid` (the hub `/account/[*]` surface).
     *
     * History: SSO-1552 (tenant-config set), SSO-2870 (`environments.*`), SSO-2917 (`email.*`),
     * SSO-3037 (`idp.*`), SSO-3113 (`access.*`, held back from the default until SSO-3112 deployed the
     * grant to the hub — hub V161; the `cli` client carries it from `.thoryn/provision.yaml`).
     */
    const val DEFAULT_SCOPE =
        "openid offline_access " +
            "tenant:applications.read tenant:applications.write " +
            "tenant:clients.read " +
            "tenant:users.read tenant:users.write " +
            "tenant:federation.read tenant:federation.write " +
            "tenant:audit.read " +
            "tenant:environments.read tenant:environments.write " +
            "tenant:email.read tenant:email.write " +
            "tenant:idp.read tenant:idp.write " +
            "tenant:access.read tenant:access.write"

    /**
     * The `--hub` / `--gateway` "not given" sentinel of the post-login commands (SSO-2827): they use the
     * hub / gateway RECORDED AT `thoryn login` ([com.devnow.thoryn.cli.cmd.CommandSupport.resolveHub]).
     * The local-dev value is reached only with no session at all — and every such command needs a
     * session first (`Not signed in. Run thoryn login`), so it is never a silent production default.
     */
    const val DEFAULT_HUB = LOCAL_DEV_HUB

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

    /**
     * SSO-2941 — the single-knob API-key env var for non-interactive `thoryn login
     * --client-credentials`, holding `<client-id>:<client-secret>` so CI can supply
     * both halves with one secret. The client id is everything before the FIRST
     * colon; the secret is the rest (so a secret may itself contain a colon).
     *
     * As with every other secret knob it is read from a `-D` system property first
     * (tests / `java -jar -D…`) then the environment variable — and never from argv.
     */
    const val API_KEY_ENV: String = "THORYN_API_KEY"

    /** SSO-2941 — a parsed [API_KEY_ENV] value: a service-account client id + its secret. */
    data class ApiKey(val clientId: String, val clientSecret: String)

    /**
     * SSO-2941 — resolve [API_KEY_ENV] into an [ApiKey], or null when it is unset or
     * malformed. A well-formed value is `<client-id>:<client-secret>` with a non-empty
     * id and a non-empty secret; anything else (no colon, empty half) returns null so
     * the caller can print actionable guidance rather than sending a broken grant.
     */
    fun resolveApiKey(): ApiKey? {
        val raw = System.getProperty(API_KEY_ENV)?.takeIf { it.isNotBlank() }
            ?: System.getenv(API_KEY_ENV)?.takeIf { it.isNotBlank() }
            ?: return null
        val idx = raw.indexOf(':')
        if (idx <= 0 || idx >= raw.length - 1) return null
        return ApiKey(clientId = raw.substring(0, idx), clientSecret = raw.substring(idx + 1))
    }

    /**
     * SSO-2941 — resolve the client secret used to RE-MINT an expired API-key session
     * (see [com.devnow.thoryn.cli.cmd.CommandSupport.forceRefresh]). The secret half of
     * [API_KEY_ENV] wins, else `THORYN_CLIENT_SECRET`.
     *
     * Re-mint runs deep inside a command with no access to the login command's
     * per-invocation `--client-secret-file` / no-echo prompt, so it resolves from the
     * environment ONLY — which is exactly how CI already supplies the credential (set
     * once in the pipeline env). An interactive operator whose secret was only ever a
     * file / prompt simply re-runs `thoryn login --client-credentials` on expiry.
     */
    fun resolveApiKeySecret(): String? =
        resolveApiKey()?.clientSecret ?: resolveClientSecret()

    /**
     * SSO-2879 — resolve the WIF private_key_jwt signing key (PKCS#8 PEM) for `login --workload-identity`.
     *
     * Resolution order (first non-blank wins), keeping the key out of argv:
     *   1. `--wif-signing-key-file <path>` — a file (typical when a CI step writes the secret to disk).
     *   2. `THORYN_CI_WIF_SIGNING_KEY` system property — used by tests / `-D` invocations.
     *   3. `THORYN_CI_WIF_SIGNING_KEY` environment variable — the canonical GitHub-secret knob.
     */
    fun readWifSigningKey(file: java.io.File?): String? {
        file?.takeIf { it.isFile }?.readText()?.takeIf { it.isNotBlank() }?.let { return it }
        return System.getProperty(WIF_SIGNING_KEY_ENV)?.takeIf { it.isNotBlank() }
            ?: System.getenv(WIF_SIGNING_KEY_ENV)?.takeIf { it.isNotBlank() }
    }

    /** SSO-2879 — optional off-runner subject-token override (system property then env). */
    fun readWifSubjectTokenOverride(): String? =
        System.getProperty(WIF_SUBJECT_TOKEN_ENV)?.takeIf { it.isNotBlank() }
            ?: System.getenv(WIF_SUBJECT_TOKEN_ENV)?.takeIf { it.isNotBlank() }
}
