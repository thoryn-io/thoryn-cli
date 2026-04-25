package com.devnow.oathy.cli.config

/**
 * Default endpoints baked into the CLI binary.
 *
 * Production builds will overwrite these via `-D` properties or a generated
 * `oathy.properties` resource at release time. For local development the
 * defaults point at `localhost` services so a developer can `oathy login`
 * against a hub running on their own machine.
 *
 * Known environments (override via `--issuer` and `--gateway`):
 *
 *  - Local dev: `http://localhost:54702` (hub) and `http://localhost:8991` (gateway)
 *  - Staging:   `https://hub.stg.thoryn.org` (hub) and the matching staging gateway
 *  - Production (TBD)
 */
object OathyConfig {
    const val DEFAULT_ISSUER = "http://localhost:54702"
    const val DEFAULT_CLIENT_ID = "oathy-cli"
    const val DEFAULT_GATEWAY = "http://localhost:8991"

    /** Convenience constant — pass to `--issuer` to point the CLI at the staging hub. */
    const val STAGING_ISSUER = "https://hub.stg.thoryn.org"
}
