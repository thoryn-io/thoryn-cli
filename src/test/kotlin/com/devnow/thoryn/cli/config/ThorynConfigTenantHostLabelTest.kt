package com.devnow.thoryn.cli.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3296 (epic SSO-3289, ADR `2026-09-22-public-issuer-host-auth-subdomain.md`) — the public
 * authentication host moves from `{slug}.hub.<domain>` to `{slug}.auth.<domain>`.
 *
 * The contract these tests pin: **the CLI never assumes the host word.** Every composed host reuses
 * the label already present in the base issuer it was pointed at, so ONE binary is correct on both
 * sides of the SSO-3297 staging cutover — which is what lets this land while staging still serves
 * `hub.stg.thoryn.org`, with no discovery probe and no re-release.
 */
class ThorynConfigTenantHostLabelTest {

    private val none: (String) -> String? = { null }

    // ---- workspace issuer composition --------------------------------------

    @Test
    fun `a workspace issuer is composed on whichever label the base issuer carries`() {
        // Today's staging (pre-cutover).
        assertThat(ThorynConfig.tenantIssuer("https://hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.hub.stg.thoryn.org")
        // Post-cutover staging, and production.
        assertThat(ThorynConfig.tenantIssuer("https://auth.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.auth.stg.thoryn.org")
        assertThat(ThorynConfig.tenantIssuer("https://auth.thoryn.io", "acme"))
            .isEqualTo("https://acme.auth.thoryn.io")
    }

    @Test
    fun `a base issuer with no recognised label is returned unchanged, never guessed at`() {
        assertThat(ThorynConfig.tenantIssuer("http://localhost:54702", "acme")).isEqualTo("http://localhost:54702")
        assertThat(ThorynConfig.tenantIssuer("https://idp.example.com", "acme")).isEqualTo("https://idp.example.com")
    }

    /**
     * A CUSTOM DOMAIN (ADR §5, epic SSO-3290) is indistinguishable by string shape from a platform
     * base host: `auth.acme.com` reads as "label `auth`, apex `acme.com`". Pinned as a KNOWN LIMIT
     * rather than a bug — it is pre-existing (`hub.acme.com` composed the same way before SSO-3296),
     * and it is not reachable today because custom domains are not built. When SSO-3290 lands, a
     * custom-domain issuer is used VERBATIM as the workspace issuer (the tenant registry, not a
     * pattern, is what makes it trusted), so it must never be fed to [ThorynConfig.tenantIssuer] as a
     * base in the first place.
     */
    @Test
    fun `a custom-domain host cannot be told from a base host by shape alone`() {
        assertThat(ThorynConfig.tenantIssuer("https://auth.acme.com/", "acme"))
            .isEqualTo("https://acme.auth.acme.com")
        // It does at least name no workspace and is already its own base, so a session recorded on a
        // custom domain round-trips unharmed.
        assertThat(ThorynConfig.workspaceOfIssuer("https://auth.acme.com")).isNull()
        assertThat(ThorynConfig.baseHubOf("https://auth.acme.com")).isEqualTo("https://auth.acme.com")
    }

    @Test
    fun `the sandbox issuer keeps its path form on top of the workspace issuer`() {
        // ADR §3 — only the HOST word moves; `/{env}` is byte-unchanged. Composed by the caller.
        val workspace = ThorynConfig.tenantIssuer("https://auth.stg.thoryn.org", "acme")
        assertThat("$workspace/dev").isEqualTo("https://acme.auth.stg.thoryn.org/dev")
    }

    // ---- the inverse: base + slug read back out of a workspace issuer -------

    @Test
    fun `the base issuer and the workspace slug are read back on either label`() {
        for (label in listOf("auth", "hub")) {
            assertThat(ThorynConfig.baseHubOf("https://acme.$label.stg.thoryn.org"))
                .isEqualTo("https://$label.stg.thoryn.org")
            assertThat(ThorynConfig.workspaceOfIssuer("https://acme.$label.stg.thoryn.org")).isEqualTo("acme")
            // A BASE issuer is already a base, and names no workspace.
            assertThat(ThorynConfig.baseHubOf("https://$label.stg.thoryn.org/"))
                .isEqualTo("https://$label.stg.thoryn.org")
            assertThat(ThorynConfig.workspaceOfIssuer("https://$label.stg.thoryn.org")).isNull()
        }
    }

    @Test
    fun `a host carrying no recognised label names no workspace`() {
        assertThat(ThorynConfig.workspaceOfIssuer("https://auth.acme.com")).isNull()
        assertThat(ThorynConfig.baseHubOf("https://auth.acme.com")).isEqualTo("https://auth.acme.com")
        assertThat(ThorynConfig.workspaceOfIssuer("http://localhost:54702")).isNull()
    }

    // ---- the directory (identity-service) host -----------------------------

    @Test
    fun `the directory host is a separate host on hub, and same-origin under slash id on auth`() {
        // Pre-cutover (SSO-1920): identity is its own host.
        assertThat(ThorynConfig.tenantIdentityHost("https://hub.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.identity.stg.thoryn.org")
        // Post-cutover (ADR §2): identity mounts under the reserved `/id` context path on the
        // workspace's OWN host — one origin, one cookie jar, no cross-origin hop mid sign-in.
        assertThat(ThorynConfig.tenantIdentityHost("https://auth.stg.thoryn.org", "acme"))
            .isEqualTo("https://acme.auth.stg.thoryn.org/id")
        assertThat(ThorynConfig.tenantIdentityHost("https://auth.thoryn.io", "acme"))
            .isEqualTo("https://acme.auth.thoryn.io/id")
    }

    @Test
    fun `an unrecognised base has no derivable directory host`() {
        assertThat(ThorynConfig.tenantIdentityHost("http://localhost:54702", "acme"))
            .isEqualTo(ThorynConfig.DEFAULT_IDENTITY)
    }

    @Test
    fun `the identity context path cannot collide with a workspace or environment slug`() {
        // `TrustedTenantIssuers.SLUG_PATTERN` has a three-character floor; `/id` is two.
        assertThat(ThorynConfig.IDENTITY_CONTEXT_PATH).isEqualTo("/id")
        assertThat(ThorynConfig.IDENTITY_CONTEXT_PATH.removePrefix("/")).hasSizeLessThan(3)
    }

    // ---- the escape hatch --------------------------------------------------

    @Test
    fun `the label override recognises a bespoke host word without a CLI release`() {
        val env: (String) -> String? = { if (it == ThorynConfig.TENANT_HOST_LABEL_ENV) "sso" else null }
        val labels = ThorynConfig.tenantHostLabels(env)

        assertThat(labels).startsWith("sso")
        assertThat(ThorynConfig.labelIndex("sso.example.org", labels)).isEqualTo(0)
        assertThat(ThorynConfig.labelIndex("acme.sso.example.org", labels)).isEqualTo(1)
        // The built-ins stay recognised alongside the override.
        assertThat(labels).contains("auth", "hub")
    }

    @Test
    fun `with no override the built-in labels are auth then hub`() {
        assertThat(ThorynConfig.tenantHostLabels(none)).containsExactly("auth", "hub")
    }

    // ---- label indexing edge cases -----------------------------------------

    @Test
    fun `only the first and second host components can be the platform label`() {
        val labels = ThorynConfig.DEFAULT_TENANT_HOST_LABELS
        assertThat(ThorynConfig.labelIndex("auth.stg.thoryn.org", labels)).isEqualTo(0)
        assertThat(ThorynConfig.labelIndex("acme.auth.stg.thoryn.org", labels)).isEqualTo(1)
        // A label appearing DEEPER is part of the apex, not our separator — and must not be read as one.
        assertThat(ThorynConfig.labelIndex("portal.sso.auth.example.com", labels)).isEqualTo(-1)
        assertThat(ThorynConfig.labelIndex("localhost", labels)).isEqualTo(-1)
        assertThat(ThorynConfig.labelIndex("127.0.0.1", labels)).isEqualTo(-1)
        // Case is not significant in a hostname.
        assertThat(ThorynConfig.labelIndex("ACME.AUTH.STG.THORYN.ORG", labels)).isEqualTo(1)
    }

    // ---- the env-var rename ------------------------------------------------

    @Test
    fun `THORYN_ISSUER is the documented env var and THORYN_HUB stays an accepted alias`() {
        assertThat(ThorynConfig.ISSUER_ENV).isEqualTo("THORYN_ISSUER")
        assertThat(ThorynConfig.HUB_ENV).isEqualTo("THORYN_HUB")
        assertThat(ThorynConfig.ISSUER_ENV_NAMES).containsExactly("THORYN_ISSUER", "THORYN_HUB")

        val both: (String) -> String? = { name ->
            when (name) {
                ThorynConfig.ISSUER_ENV -> "https://auth.stg.thoryn.org"
                ThorynConfig.HUB_ENV -> "https://hub.stg.thoryn.org"
                else -> null
            }
        }
        // The documented name wins when both are exported.
        assertThat(ThorynConfig.resolveHubBase(null, null, both, null))
            .isEqualTo(ThorynConfig.HubBase("https://auth.stg.thoryn.org", ThorynConfig.HubSource.ENV))

        // The alias alone still resolves — a pre-rename CI job keeps working.
        val aliasOnly: (String) -> String? = { if (it == ThorynConfig.HUB_ENV) "https://hub.stg.thoryn.org" else null }
        assertThat(ThorynConfig.resolveHubBase(null, null, aliasOnly, null))
            .isEqualTo(ThorynConfig.HubBase("https://hub.stg.thoryn.org", ThorynConfig.HubSource.ENV))

        // `--issuer` still beats both.
        assertThat(ThorynConfig.resolveHubBase("https://auth.other.org", null, both, null))
            .isEqualTo(ThorynConfig.HubBase("https://auth.other.org", ThorynConfig.HubSource.FLAG))
    }

    /**
     * SSO-3297 hand-off: the ONE line the cutover moves in this repo. Until it flips, the released CLI
     * and every help string still name today's staging host, so nothing scheduled against staging breaks.
     */
    @Test
    fun `the staging convenience constant still names the pre-cutover host`() {
        assertThat(ThorynConfig.STAGING_ISSUER).isEqualTo("https://hub.stg.thoryn.org")
        assertThat(ThorynConfig.gatewayForIssuer(ThorynConfig.STAGING_ISSUER)).isEqualTo(ThorynConfig.STAGING_GATEWAY)
    }
}
