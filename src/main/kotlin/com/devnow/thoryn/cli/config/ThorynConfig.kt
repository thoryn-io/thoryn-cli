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
    const val DEFAULT_CLIENT_ID = "oathy-cli"
    const val DEFAULT_GATEWAY = "http://localhost:8991"

    /** Convenience constant — pass to `--issuer` to point the CLI at the staging hub. */
    const val STAGING_ISSUER = "https://hub.stg.thoryn.org"

    /** Default scope set requested by `thoryn login`. */
    const val DEFAULT_SCOPE = "openid offline_access tenant:clients.read tenant:users.read"

    /**
     * Client secret read from the `THORYN_CLIENT_SECRET` env var. The hub's
     * device-authorization endpoint currently requires confidential client
     * authentication (Basic Auth or `client_secret_post`); a true public
     * client branch on that endpoint is a hub-side follow-up.
     *
     * For local dev the user sets this to the secret of whatever client
     * they registered. CI uses a per-pipeline secret; production binaries
     * may bundle a release-time-injected value.
     */
    fun resolveClientSecret(): String? =
        System.getenv("THORYN_CLIENT_SECRET")?.takeIf { it.isNotBlank() }
}
