package com.devnow.thoryn.provision

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.File
import java.security.MessageDigest

/** Thrown on any provisioning-file load / parse / validation failure, or a refused plan/apply/destroy. */
open class ProvisionException(message: String) : RuntimeException(message)

/**
 * SSO-3088 (epic SSO-3087) — one declared resource of a provisioning file: its `kind` (closed
 * allowlist), stable `name` (the converge key), the environment it lives in (an `environment`
 * resource's name in the same file, an existing slug, or `null` ⇒ the production plane), and its
 * kind-specific `spec` (forwarded to the product API).
 */
data class ProvisionResource(
    val kind: String,
    val name: String,
    val environment: String?,
    val spec: Map<String, Any?>,
    /**
     * SSO-3113 — the least-privilege access grants declared ON this resource, converged with it (see
     * [ProvisionGrant]). `null` ⇒ the file does not manage this object's grants (nothing is read or
     * written); an empty list ⇒ the file declares NONE (every revocable grant on the object is revoked).
     */
    val grants: List<ProvisionGrant>? = null,
    /**
     * SSO-3659 (ADR 2026-10-13 §1) — "this repository depends on it and does not own it". A read-only
     * reference is looked up live and must MATCH: any field difference is the plan error
     * `access_read_only`, it is never created or removed, and it may be declared with only `viewer`
     * reach (an owned resource needs `manager`).
     */
    val readOnly: Boolean = false,
    /**
     * SSO-3715 (ADR 2026-10-15 platform-is-the-ledger §1) — "mine, keep": the file converges and owns the resource,
     * but `destroy` / `--prune` never remove it (the destroy plan shows it as retained). Terraform's
     * `prevent_destroy`; the declared replacement for the receipt-era adopted bit — intent in the reviewed file
     * instead of history in a ledger. Refused together with [readOnly] (a reference is never removed anyway).
     */
    val retain: Boolean = false,
    /**
     * SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) — where `apply`
     * PUBLISHES this resource's id once it is converged (see [PublishTarget]). `application` only: the
     * clientId is the one output a resource has, and it is public by construction. Empty ⇒ nothing is
     * published. Refused together with [readOnly] (a reference publishes nothing — the owner publishes).
     */
    val publishTo: List<PublishTarget> = emptyList(),
    /**
     * SSO-3659 (ADR 2026-10-13 converge §5; production-clients ADR §3 tier 3) — WHERE `apply` DELIVERS the
     * one-time `client_secret` a confidential `application` is minted with (see [SecretTarget]): the moment the
     * client is converged and recorded, into the place that consumes it — never a CI secret store, never the
     * console. `null` ⇒ the host's generic channel (the CLI's `--secret-file` / guarded TTY). Refused on a
     * public client (nothing is minted), on any other kind, and together with [readOnly]. SSO-3954 (oauthy ADR 2026-10-14
     * amended 2026-10-25, SSO-3951) — `null` ⇒ **the customer manages the secret** ([effectiveSecretSink] is
     * [SecretTarget.CUSTOMER_MANAGED]): the create's one-time value is discarded, a person mints one with
     * `thoryn clients rotate-secret` and stores it in the customer's own secret infrastructure. SSO-3921 — `workloadPull`
     * (DEPRECATED, SSO-3951 / SSO-3953) names the Kubernetes workload identity that mints its own at start ([SecretTarget]).
     */
    val secretSink: SecretTarget? = null,
) {
    val isSingleton: Boolean get() = kind in ProvisionFile.SINGLETON_KINDS
    val key: String get() = "$kind/$name"

    /**
     * SSO-3954 — the sink `apply` acts on: the declared one, or — for a confidential application that MINTS a secret on
     * create and declares none — [SecretTarget.CUSTOMER_MANAGED], the default. Null when nothing is minted (a public or
     * secret-less client, a read-only reference, another kind): there is nothing to deliver or discard.
     */
    val effectiveSecretSink: SecretTarget?
        get() = secretSink ?: SecretTarget.CUSTOMER_MANAGED.takeIf { kind == ProvisionFile.KIND_APPLICATION && !readOnly && ProvisionFile.mintsSecret(spec) }
}

/**
 * SSO-3668 — one OUTPUT target of an `application` resource: after `apply` has converged the client (so
 * its id is known), the clientId is upserted into [repository]'s GitHub environment [environment] as the
 * Actions **variable** [name] — never a secret; the value is a client id, public by construction. Done on
 * EVERY apply, so a re-created client propagates without a second step. Today's only [kind] is
 * [ProvisionFile.PUBLISH_KIND_GITHUB_ACTIONS_VARIABLE]. The engine hands it to its
 * [ProvisionEngine.OutputSink]; the CLI's sink is `gh variable set`, the GitHub App's is its own gateway.
 */
data class PublishTarget(val kind: String, val repository: String, val environment: String, val name: String) {
    /** `<kind> <owner/name> (environment <env>) <NAME>` — the display form in plans, receipts and errors. */
    val label: String get() = "$kind $repository (environment $environment) $name"

    /** The one command a human runs when the target could not be reached — with the id from the receipt. */
    fun byHand(value: String): String = "gh variable set $name --body $value --repo $repository --env $environment"
}

/**
 * SSO-3659 (ADR 2026-10-13 converge §5 "secrets are delivered where they are consumed, never into a CI secret
 * store"; production-clients ADR §3 tier 3) — the declared DELIVERY TARGET of a confidential application's
 * server-minted `client_secret`. Three kinds today:
 *
 *  - [ProvisionFile.SECRET_SINK_KIND_KUBERNETES_SECRET] — `data.<key>` of the Kubernetes Secret
 *    `<namespace>/<name>`, written by the host through the operator's own `kubectl` (`create secret generic …
 *    --from-file=<key>=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -`, the `install-forge` pattern:
 *    the value rides on stdin, never on argv). The namespace must already exist — it is never created.
 *  - [ProvisionFile.SECRET_SINK_KIND_FILE] — an owner-only (`0600`) file at [path], never overwritten unless
 *    the host is told to.
 *  - [ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED] (SSO-3954; oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951:
 *    "Thoryn owns the secret lifecycle, the customer owns delivery") — **the default** for a confidential application
 *    that declares no sink ([ProvisionResource.effectiveSecretSink]). Delivered NOWHERE by `apply`: the one-time value
 *    the create returns is discarded (never printed, written, logged or handed to a sink), no grant is made to anyone,
 *    and the plan names the runbook — a PERSON mints the secret (`thoryn clients rotate-secret <clientId> --secret-file
 *    <path>`, [ProvisionFile.CUSTOMER_MANAGED_RUNBOOK]) and stores it in the customer's own secret infrastructure (a
 *    secret manager, an operator-created Kubernetes Secret). Nothing is undelivered, so a CI apply with no secret
 *    channel creates the application and stays green.
 *  - [ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL] (SSO-3921; oauthy ADR 2026-10-14 credential ladder, rung 3 "runtime
 *    pull") — **DEPRECATED** (SSO-3951; removed by SSO-3953; still converged). Delivered NOWHERE: `apply` discards the
 *    one-time value the create returns and converges `manager` on the application for the `wi_` workload client of the
 *    `kubernetes` workload-identity [trust] named here, so the workload's init container signs in with its projected
 *    ServiceAccount token and mints its own (`thoryn clients rotate-secret`). Nothing is undelivered.
 *
 * The engine hands the minted value to its [ProvisionEngine.DeclaredSecretSink] right after the client is
 * converged and recorded; the value itself never enters the file, the plan, the receipt, a log or argv. A
 * target the host cannot reach is `undelivered_secrets`: the client exists, the receipt records it, and the
 * recovery is `thoryn clients rotate-secret <clientId> --secret-file <path>`.
 */
data class SecretTarget(
    val kind: String,
    val namespace: String? = null,
    val name: String? = null,
    val key: String? = null,
    val path: String? = null,
    /** SSO-3921 — `workloadPull`: the NAME of the `workloadIdentityTrust` whose workload pulls the secret at runtime. */
    val trust: String? = null,
) {
    /** SSO-3921 — nothing is delivered: the named trust's workload mints its own secret when it starts. DEPRECATED (SSO-3951). */
    val runtimePull: Boolean get() = kind == ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL

    /** SSO-3954 — nothing is delivered and nothing is granted: a person mints the secret and the customer stores it. */
    val customerManaged: Boolean get() = kind == ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED

    /** SSO-3954 — the engine DISCARDS the create's one-time value for this target (it reaches no sink and no channel). */
    val discardsMintedSecret: Boolean get() = runtimePull || customerManaged

    /** `kubernetesSecret <ns>/<name> key <key>` | `file <path>` | `workloadPull by trust <name>` | `customerManaged` — the display form in plans and messages. */
    val label: String get() = when (kind) {
        ProvisionFile.SECRET_SINK_KIND_KUBERNETES_SECRET -> "$kind $namespace/$name key $key"
        ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL -> "$kind by trust $trust"
        ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED -> kind
        else -> "$kind $path"
    }

    companion object {
        /** SSO-3954 — the one `customerManaged` target (it has no members): the default of a confidential application. */
        val CUSTOMER_MANAGED: SecretTarget = SecretTarget(kind = ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED)
    }

    /** The target as a plan's `--output json` renders it — the declaration only, never a value. */
    fun toStructured(): Map<String, String> = buildMap {
        put("kind", kind)
        namespace?.let { put("namespace", it) }
        name?.let { put("name", it) }
        key?.let { put("key", it) }
        path?.let { put("path", it) }
        trust?.let { put("trust", it) }
    }
}

/**
 * SSO-3113 (epic SSO-3108) — one grant on a resource: `subject` (`member:<sub>` / `client:<clientId>`)
 * holds `relation` (`manager` / `viewer`) on the resource. The OBJECT half is not written in the file —
 * it derives from the receipt id the resource resolves to (`environment:<id>`, `application:<clientId>`,
 * `user:<id>`, `federation_member:<id>`, `<singleton>:<envSlug>`), so a grant can never point at an
 * object the file does not own.
 */
data class ProvisionGrant(val subject: String, val relation: String) {
    /** `<subject> <relation>` — the display / set-comparison form. */
    val label: String get() = "$subject $relation"
}

/**
 * SSO-3962 (epic SSO-3960; oauthy ADR `2026-10-25-provisioning-is-tenant-and-applications`) — the PART of provisioning
 * a file belongs to, declared by its `apiVersion`. Thoryn's scope is two halves that are not symmetric: a workspace
 * CONFIGURES ITS TENANT (who can sign in, where users come from, how sign-in looks and behaves, which policies apply)
 * and lets APPLICATIONS USE that tenant through standard OAuth 2.0 / OIDC. An application is a USER of the tenant: it
 * references the tenant's roles and environments by name and defines nothing about them. So a project belongs to
 * exactly one part — ONE config project per workspace writes tenant files, MANY app projects write application files —
 * and the engine refuses a kind from the other part before any call is made.
 *
 *  - [TENANT] — `thoryn.io/tenant/v1`: [TENANT_KINDS] (environments, identity sources, users — sandbox test users
 *    included —, login methods / flows / theme, email provider, custom domain, roles, and the workload identity trusts
 *    of the workspace's app projects: a repository never describes its own authority).
 *  - [APPLICATION] — `thoryn.io/application/v1`: [APPLICATION_KINDS] (`application`, with its `tokenClaims` and
 *    `roleMapping` and the settings the applications API carries). Its identity is confined to
 *    [ScopeRequirements.APPLICATION_FILE_SCOPES].
 *  - [MIXED] — `thoryn.io/provision/v1`: the one format that existed before the parts (SSO-3088), accepted for ONE more
 *    release with a warning that names the part the file should declare and which resources would have to move
 *    ([ProvisionFile.warnings]); `thoryn provision split` writes the two files.
 */
enum class ProvisionPart(val apiVersion: String, val label: String, val kinds: Set<String>) {
    TENANT(ProvisionFile.API_VERSION_TENANT, "tenant", ProvisionFile.TENANT_KINDS),
    APPLICATION(ProvisionFile.API_VERSION_APPLICATION, "application", ProvisionFile.APPLICATION_KINDS),
    MIXED(ProvisionFile.API_VERSION, "mixed", ProvisionFile.KINDS),
    ;

    /** `thoryn.io/<part>/v1` as it is written in a file. */
    override fun toString(): String = apiVersion

    /** Which project kind owns the file: the workspace's one config project, or an application's own project. */
    val owner: String get() = when (this) {
        TENANT -> "the workspace's config project"
        APPLICATION -> "the application's own project"
        MIXED -> "a project of either part"
    }

    companion object {
        /** The part a file declaring [apiVersion] belongs to, or null for a string that is none of the three. */
        fun of(apiVersion: String?): ProvisionPart? = entries.firstOrNull { it.apiVersion == apiVersion }

        /** The part a KIND is provisioning of (never [MIXED]), or null for a kind outside the allowlist. */
        fun ofKind(kind: String): ProvisionPart? = when (kind) {
            in ProvisionFile.TENANT_KINDS -> TENANT
            in ProvisionFile.APPLICATION_KINDS -> APPLICATION
            else -> null
        }
    }
}

/**
 * SSO-3088 (epic SSO-3087) — a parsed **provisioning file** (`.thoryn/provision.yaml`): the DESIRED
 * STATE of a repository's Thoryn resources, the "what I own" half of the `.thoryn/` folder next to
 * `connection.json` ("who I am", SSO-2948). DATA, not code, validated against the bundled
 * `provision.schema.json` with the same hand-rolled, message-bearing approach [Connection] uses.
 *
 * Secrets NEVER enter the file: a `spec` key that carries a secret VALUE (`password`, `smtpPassword`,
 * `clientSecret`, …) is rejected; the file names the ENV VAR instead (`passwordEnv: SMTP_PASSWORD`),
 * which the engine resolves at apply time and never records.
 *
 * SSO-3962 — a file belongs to one [ProvisionPart], declared by its `apiVersion` ([part]); a kind from the other part is
 * a validation violation. [warnings] carries what is accepted today and refused in a later release.
 */
class ProvisionFile private constructor(
    /** Where the file was read from (error messages, the plan header). */
    val source: String,
    /** `sha256:<hex>` over the raw bytes — shown in the plan header so a reader knows which file was planned. */
    val digest: String,
    val resources: List<ProvisionResource>,
    /** SSO-3962 — the part the file's `apiVersion` declares (see [ProvisionPart]). */
    val part: ProvisionPart = ProvisionPart.MIXED,
    /**
     * SSO-3962 — deprecations the file carries, each one sentence a host prints (the CLI: `Warning: …` on stderr before a
     * plan / apply): the mixed `thoryn.io/provision/v1` format (names the part the file should declare, or that it must be
     * split), and `publishTo:` (ADR 2026-10-13 §2, superseded). Empty for a file nothing is deprecated in.
     */
    val warnings: List<String> = emptyList(),
) {
    /** The `environment` resource declared under [name], if any. */
    fun environmentResource(name: String): ProvisionResource? =
        resources.firstOrNull { it.kind == KIND_ENVIRONMENT && it.name == name }

    companion object {
        /**
         * SSO-3088 — the ORIGINAL, mixed format: every kind. SSO-3962 deprecates it (accepted for one more release with a
         * warning, see [ProvisionPart.MIXED]); a new file declares [API_VERSION_TENANT] or [API_VERSION_APPLICATION].
         */
        const val API_VERSION = "thoryn.io/provision/v1"
        /** SSO-3962 — a TENANT file (the workspace's config project): [TENANT_KINDS]. */
        const val API_VERSION_TENANT = "thoryn.io/tenant/v1"
        /** SSO-3962 — an APPLICATION file (an app project): [APPLICATION_KINDS]. */
        const val API_VERSION_APPLICATION = "thoryn.io/application/v1"
        /** Every `apiVersion` the loader accepts — must equal the schema's `apiVersion` enum (asserted by the conformance test). */
        val API_VERSIONS: List<String> = listOf(API_VERSION_TENANT, API_VERSION_APPLICATION, API_VERSION)

        /** Bundled schema resource — the documented contract this loader validates against. */
        const val SCHEMA_RESOURCE = "/provision/provision.schema.json"

        /** The conventional folder + the default file names probed in order by `thoryn provision`. */
        const val DEFAULT_DIR = ".thoryn"
        val DEFAULT_FILES: List<String> = listOf("provision.yaml", "provision.yml", "provision.json")

        const val KIND_ENVIRONMENT = "environment"
        const val KIND_APPLICATION = "application"
        const val KIND_EMAIL_PROVIDER = "emailProvider"
        /**
         * The per-environment hosted-login branding (`/api/v1/login-experience/branding`). SSO-4041 — the spec IS the record:
         * the PUT replaces it whole, so the plan diffs every field ([LOGIN_THEME_SPEC_KEYS]) and a stored field the file does
         * not declare is shown as cleared; the value grammar is identity's, mirrored in [validateLoginTheme].
         */
        const val KIND_LOGIN_THEME = "loginTheme"
        const val KIND_LOGIN_FLOW = "loginFlow"
        /** SSO-3100 — the per-environment sign-in METHOD allow-list (`/api/v1/login-methods`). */
        const val KIND_LOGIN_METHODS = "loginMethods"
        const val KIND_FEDERATION_MEMBER = "federationMember"
        const val KIND_USER = "user"
        /**
         * SSO-3413 — the workspace's ONE custom domain (`/api/v1/custom-domain`): WORKSPACE-level (never an
         * `environment`), a singleton, converged by claim + verify. See [ProvisionEngine] for the semantics.
         */
        const val KIND_CUSTOM_DOMAIN = "customDomain"
        /**
         * SSO-4042 — ONE transactional email template override, per (type, locale) of the resource's environment:
         * `/api/v1/login-experience/email-templates/{type}?locale=` (product-api `LoginExperienceController`, identity-service
         * `EmailTemplateService`). SSO-4054 (oauthy SSO-4043, identity V131) — PER ENVIRONMENT, like `loginTheme`: `environment`
         * names the plane (omitted ⇒ production) and every call carries it as `X-Thoryn-Environment`. A sandbox that declares no
         * copy of a cell sends production's (identity's send-path fallback) — that is not drift, and nothing is planned for it.
         * Converged by (environment, `spec.type`, `spec.locale`): a GET that answers `404 template_not_customized` (exact per
         * environment — the plane's own row, never the inherited one) is a create, a stored cell is diffed on `subject` and the body (line endings
         * and trailing whitespace normalised), `apply` PUTs `{ subject, bodyHtml }`, a removal is the `DELETE` (back to the
         * built-in default). The body is `spec.body` inline or `spec.bodyFile`, a path relative to the provisioning file read when
         * the file is loaded ([parse] with its directory). See [ProvisionEngine].
         */
        const val KIND_EMAIL_TEMPLATE = "emailTemplate"
        /**
         * SSO-4057 (oauthy SSO-4047, identity V132) — the TENANT-LEVEL Terms of Use or Privacy Policy of the resource's
         * environment, hosted by identity-service: `/api/v1/login-experience/legal-documents/{terms-of-use|privacy-policy}`
         * (product-api `TenantLegalDocumentsController`, identity `TenantLegalDocumentService`). One per (environment,
         * `spec.type`); `environment` names the plane (omitted ⇒ production) and every call carries it as
         * `X-Thoryn-Environment`. There is NO fallback between environments: identity resolves a sign-in's document as the
         * application's own active one, else the tenant's active one for THAT environment, else none
         * (`TouCheckService.resolveActiveDocument`), so a sandbox without a document of its own has none.
         *
         * Documents are VERSIONED and a published version never changes (users accepted that text; a version with
         * acceptances cannot even be deleted, GDPR Art. 7). So the declaration is "the ACTIVE version is `spec.version`, with
         * this title, format and body": the active version with that label and that content ⇒ no change; no version with that
         * label ⇒ publish it (a POST that activates the new version and deactivates the previous one — users accept it at
         * their next sign-in); a stored, inactive version with that label and that content ⇒ re-activate it; a stored
         * version with that label and OTHER content ⇒ refused at plan time ([ProvisionEngine]: give the new text a new
         * `spec.version`). The body is `spec.body` inline or `spec.bodyFile`, a path relative to the provisioning file read
         * when the file is loaded, exactly as for [KIND_EMAIL_TEMPLATE].
         *
         * Not a platform access object: product-api gates the surface on `tenant:legal-documents.read` / `.write` alone (no
         * `PlatformSingletonGate`), so — like [KIND_ROLE] — there is no ownership check and no `grants:` ([SCOPE_ONLY_KINDS]).
         */
        const val KIND_LEGAL_DOCUMENT = "legalDocument"
        /**
         * SSO-3689 (ADR 2026-10-14 credential ladder, rungs 1–3) — a workload-identity TRUST of the resource's
         * environment (`/api/v1/workload-identity/trusts`): the platform identity a CI job or a pod presents
         * instead of a stored secret, by `provider` with that provider's immutable pins. Converged by `name`;
         * an `application` binds one by NAME through `spec.federatedTrust`. See [ProvisionEngine].
         */
        const val KIND_WORKLOAD_IDENTITY_TRUST = "workloadIdentityTrust"
        /**
         * SSO-3941 — an RBAC ROLE of the resource's environment (`/api/v1/roles`, product-api SSO-1891): its `name` IS the
         * role's name (the converge key), `spec.permissions` the FULL set of permission strings it grants (converged as a set;
         * a missing workspace permission is created), `spec.description` optional. Not a platform access object — product-api
         * gates it on `tenant:roles.*` alone — so there is no ownership verdict and it cannot carry `grants:`. See [ProvisionEngine].
         */
        const val KIND_ROLE = "role"

        /**
         * SSO-3962 — TENANT provisioning: what defines the tenant. Every kind added later (SSO-3965: directories / SCIM,
         * organizations, security policies, hooks, …) joins this set unless it describes one client's connection. Includes
         * `user` (a sandbox test user is a fact about who may sign in — the tenant's decision, visible to every application
         * of the environment) and `workloadIdentityTrust` (the config project declares the trusts of the workspace's app
         * projects; a repository never declares its own authority). Must equal the schema's tenant `kind` enum.
         */
        val TENANT_KINDS: Set<String> = setOf(
            KIND_ENVIRONMENT, KIND_FEDERATION_MEMBER, KIND_USER, KIND_LOGIN_METHODS, KIND_LOGIN_FLOW, KIND_LOGIN_THEME,
            KIND_EMAIL_PROVIDER, KIND_CUSTOM_DOMAIN, KIND_ROLE, KIND_WORKLOAD_IDENTITY_TRUST, KIND_EMAIL_TEMPLATE,
            KIND_LEGAL_DOCUMENT,
        )

        /**
         * SSO-3962 — APPLICATION provisioning: how ONE client connects — its OAuth client with `tokenClaims` / `roleMapping`
         * (role NAMES the tenant defines) and the settings the applications API carries. Must equal the schema's application
         * `kind` enum.
         */
        val APPLICATION_KINDS: Set<String> = setOf(KIND_APPLICATION)

        /** The CLOSED kind allowlist — must equal the schema's `kind` enum (asserted by the conformance test); the union of the two parts. */
        val KINDS: Set<String> = TENANT_KINDS + APPLICATION_KINDS

        /**
         * One-per-environment kinds — and, SSO-3413, the one-per-WORKSPACE [KIND_CUSTOM_DOMAIN]: `name` is
         * optional (defaults to the kind) and their API is a PUT.
         */
        val SINGLETON_KINDS: Set<String> = setOf(KIND_EMAIL_PROVIDER, KIND_LOGIN_THEME, KIND_LOGIN_FLOW, KIND_LOGIN_METHODS, KIND_CUSTOM_DOMAIN)

        /**
         * SSO-3413 — kinds that live on the WORKSPACE, not in an environment: `environment` is refused on them. (SSO-4054 — an
         * `emailTemplate` left this set when identity re-keyed templates per environment, oauthy SSO-4043.)
         */
        val WORKSPACE_KINDS: Set<String> = setOf(KIND_CUSTOM_DOMAIN)

        /**
         * SSO-3941 / SSO-4057 — kinds that are NOT objects of the platform authorization graph: product-api gates them on their
         * `tenant:` scope alone (a role on `tenant:roles.*`, a tenant-level legal document on `tenant:legal-documents.*`). The engine
         * asks no ownership check for them (so they need no `tenant:access.read`), and they cannot carry `grants:`.
         */
        val SCOPE_ONLY_KINDS: Set<String> = setOf(KIND_ROLE, KIND_LEGAL_DOCUMENT)

        /** SSO-4057 — the kinds whose body may live in a file next to the provisioning file (`spec.bodyFile`, read when the file is loaded). */
        val BODY_FILE_KINDS: Set<String> = setOf(KIND_EMAIL_TEMPLATE, KIND_LEGAL_DOCUMENT)

        // ── SSO-4042 — `emailTemplate`: identity-service's `EmailTemplateType` / `EmailTemplateService` rules, mirrored ──

        /** `spec.type`: identity's `EmailTemplateType.wireValue`s (oauthy, read 2026-10-28). Must equal the schema's `type` enum. */
        val EMAIL_TEMPLATE_TYPES: List<String> = listOf(
            "magic_link", "invitation", "password_reset", "security_alert", "account_unlock", "email_verification", "organization_invitation", "co_admin_invitation",
        )

        /** The `spec` members an `emailTemplate` accepts (the schema's `additionalProperties: false`). */
        val EMAIL_TEMPLATE_SPEC_KEYS: Set<String> = setOf("type", "locale", "subject", "body", "bodyFile")

        /**
         * `spec.locale`: the API's storage grammar — a 2–3 letter ISO 639 language code (`en`, `nl`; case-insensitive, stored
         * lower-case). Omitted ⇒ the BASE, locale-independent template (`*` on the wire). A region subtag (`en-GB`) is refused
         * by product-api (`400 invalid_template_locale`), so it is refused here. Must equal the schema's `locale` pattern.
         */
        val EMAIL_TEMPLATE_LOCALE_PATTERN = Regex("^[A-Za-z]{2,3}$")

        /** The base, locale-independent template as the API renders its locale. */
        const val EMAIL_TEMPLATE_BASE_LOCALE = "*"

        /** `spec.subject`: at most this many characters (identity's `EmailTemplateProperties.maxSubjectChars`; `413 template_subject_too_large`). */
        const val EMAIL_TEMPLATE_MAX_SUBJECT_CHARS = 998

        /** The body: at most this many UTF-8 bytes (identity's `maxBodyBytes`, 64 KiB; `413 template_body_too_large`). */
        const val EMAIL_TEMPLATE_MAX_BODY_BYTES = 64 * 1024

        const val ERR_EMAIL_TEMPLATE_BODY_REQUIRED = "email_template_body_required"
        const val ERR_EMAIL_TEMPLATE_BODY_AMBIGUOUS = "email_template_body_ambiguous"

        // ── SSO-4057 — `legalDocument`: identity-service's `TenantLegalDocumentRules` (oauthy #4290, read 2026-10-29), mirrored ──
        // product-api applies the same rules before forwarding (its own `TenantLegalDocumentRules`); identity is authoritative.

        /** `spec.type`: the API's path segment (`{docType:terms-of-use|privacy-policy}`). Must equal the schema's `type` enum. */
        val LEGAL_DOCUMENT_TYPES: List<String> = listOf("terms-of-use", "privacy-policy")

        /** The `spec` members a `legalDocument` accepts (the schema's `additionalProperties: false`). */
        val LEGAL_DOCUMENT_SPEC_KEYS: Set<String> = setOf("type", "version", "title", "format", "body", "bodyFile")

        /** `spec.format`: identity's `TermsOfUseEntity.BODY_FORMAT_*`; omitted ⇒ [LEGAL_DOCUMENT_DEFAULT_FORMAT]. Must equal the schema's `format` enum. */
        val LEGAL_DOCUMENT_FORMATS: List<String> = listOf("markdown", "text")
        const val LEGAL_DOCUMENT_DEFAULT_FORMAT = "markdown"

        /** `spec.version`: plain text of at most this many characters after trimming (identity's `MAX_VERSION_CHARS`; `400 invalid_version`). */
        const val LEGAL_DOCUMENT_MAX_VERSION_CHARS = 64

        /** `spec.title`: plain text of at most this many characters after trimming (identity's `MAX_TITLE_CHARS`; `400 invalid_title`). */
        const val LEGAL_DOCUMENT_MAX_TITLE_CHARS = 200

        /** The body: at most this many UTF-8 bytes (identity's `MAX_BODY_BYTES`, 128 KiB; `400 body_too_large`). */
        const val LEGAL_DOCUMENT_MAX_BODY_BYTES = 131_072

        /**
         * HTML in a body, as identity detects it (`TenantLegalDocumentRules.HTML_MARKUP`): `<` followed by a letter, `/`, `!` or
         * `?` — a start or end tag, a comment, a doctype, a processing instruction. Refused (`400 html_not_allowed`), never
         * sanitised; a `<` in prose (`a < b`) is fine. Must equal the schema's body `not.pattern`.
         */
        val LEGAL_DOCUMENT_HTML_MARKUP = Regex("<[A-Za-z/!?]")

        const val ERR_LEGAL_DOCUMENT_BODY_REQUIRED = "legal_document_body_required"
        const val ERR_LEGAL_DOCUMENT_BODY_AMBIGUOUS = "legal_document_body_ambiguous"
        /** identity's (and product-api's) error code for a body that carries HTML, used verbatim so a reader can search for it. */
        const val ERR_HTML_NOT_ALLOWED = "html_not_allowed"

        /** SSO-3413 — the `spec` members a `customDomain` accepts (the schema's `additionalProperties: false`). */
        val CUSTOM_DOMAIN_SPEC_KEYS: Set<String> = setOf("host", "acceptReSignIn")

        // ── SSO-4041 — `loginTheme`: the WHOLE branding record, with identity-service's write rules mirrored client-side ──
        //
        // `PUT /api/v1/login-experience/branding` REPLACES the stored record (identity's `LoginBrandingAdminService.upsert`:
        // every field is written from the request, an omitted or `null` field CLEARS the stored value, and `cssVariables` is
        // replaced as ONE map — `null` clears every token). So the file is the record: what it declares is set, what it
        // does not declare is cleared, and the plan says so field by field. The grammar below is identity's
        // (`LoginBrandingService.HEX_COLOR`, `MAX_BORDER_RADIUS_PX`, `LoginBranding.Theme`, `MAX_LOGO_URL_CHARS`,
        // `BrandingCssVariables.ALLOWED` + `FONT_STACK`), so a typo (`primaryColour`) or a bad value is refused before any
        // call instead of being dropped by the API's lenient JSON binding and silently clearing the field it was meant to set.

        /** The `spec` members a `loginTheme` accepts — the whole record the PUT replaces (the schema's `additionalProperties: false`). */
        val LOGIN_THEME_SPEC_KEYS: Set<String> = setOf(
            "logoUrl", "primaryColor", "backgroundColor", "borderRadiusPx", "theme", "cssVariables",
            // SSO-4048 (oauthy SSO-4044) — the tenant's name, the browser title, the favicon and the footer links.
            "displayName", "pageTitle", "faviconUrl", "supportUrl", "termsUrl", "privacyUrl",
        )

        /** `spec.theme`: identity's `LoginBranding.Theme` values. Must equal the schema's `theme` enum. */
        val LOGIN_THEME_THEMES: List<String> = listOf("light", "dark", "auto")

        /** A CSS hex colour as identity accepts it: `#rgb`, `#rrggbb` or `#rrggbbaa`. Must equal the schema's colour `pattern`. */
        val HEX_COLOR_PATTERN = Regex("^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")

        /** `spec.logoUrl`: an `https://` URL of at most this many characters (identity's `MAX_LOGO_URL_CHARS`). */
        const val LOGIN_THEME_MAX_LOGO_URL_CHARS = 2000

        /** `spec.borderRadiusPx`: `0..64` (identity's `MAX_BORDER_RADIUS_PX`). */
        const val LOGIN_THEME_MAX_BORDER_RADIUS_PX = 64

        const val CSS_VARIABLE_KIND_COLOR = "color"
        const val CSS_VARIABLE_KIND_FONT = "font"

        /**
         * The CLOSED allowlist of `spec.cssVariables` tokens (identity's `BrandingCssVariables.ALLOWED`): token → value kind
         * ([CSS_VARIABLE_KIND_COLOR] is a hex colour, [CSS_VARIABLE_KIND_FONT] a plain font-family stack). Must equal the
         * schema's `cssVariables.properties`.
         */
        val LOGIN_THEME_CSS_VARIABLES: Map<String, String> = linkedMapOf(
            "--thoryn-accent" to CSS_VARIABLE_KIND_COLOR,
            "--thoryn-text" to CSS_VARIABLE_KIND_COLOR,
            "--thoryn-muted" to CSS_VARIABLE_KIND_COLOR,
            "--thoryn-font-family" to CSS_VARIABLE_KIND_FONT,
        )

        /** A font-family stack as identity accepts it (letters, digits, spaces, commas, quotes, `-` and `_`; 1–120 chars). */
        val LOGIN_THEME_FONT_STACK_PATTERN = Regex("^[A-Za-z0-9 ,_'\"-]{1,120}$")

        // ── SSO-4048 — name, title, favicon, footer links (oauthy SSO-4044; identity's `LoginBrandingService.sanitisePlainText`,
        // `sanitiseHttpsUrl`, `sanitiseSupportUrl`, `MAX_DISPLAY_NAME_CHARS`, `MAX_PAGE_TITLE_CHARS`, `MAX_URL_CHARS`). Every one is
        // trimmed first, and a blank value is "unset" (the PUT clears it), exactly as identity treats it.

        /** `spec.displayName`: plain text of at most this many characters (identity's `MAX_DISPLAY_NAME_CHARS`). */
        const val LOGIN_THEME_MAX_DISPLAY_NAME_CHARS = 80

        /** `spec.pageTitle`: plain text of at most this many characters (identity's `MAX_PAGE_TITLE_CHARS`). */
        const val LOGIN_THEME_MAX_PAGE_TITLE_CHARS = 120

        /** The plain-text fields → their character limit. Must equal the schema's `maxLength` for each. */
        val LOGIN_THEME_TEXT_FIELDS: Map<String, Int> = linkedMapOf(
            "displayName" to LOGIN_THEME_MAX_DISPLAY_NAME_CHARS,
            "pageTitle" to LOGIN_THEME_MAX_PAGE_TITLE_CHARS,
        )

        /** `spec.faviconUrl` / `supportUrl` / `termsUrl` / `privacyUrl`: at most this many characters (identity's `MAX_URL_CHARS`). */
        const val LOGIN_THEME_MAX_LINK_CHARS = 2000

        /**
         * The link fields → the schemes each accepts (matched case-insensitively, as identity does; a bare scheme is not a
         * destination). Only the support link may be a `mailto:` address.
         */
        val LOGIN_THEME_LINK_FIELDS: Map<String, List<String>> = linkedMapOf(
            "faviconUrl" to listOf("https://"),
            "supportUrl" to listOf("https://", "mailto:"),
            "termsUrl" to listOf("https://"),
            "privacyUrl" to listOf("https://"),
        )

        /**
         * Plain text as identity accepts it: no `<`, `>` and no ISO control character (`Char.isISOControl`: U+0000–U+001F,
         * U+007F–U+009F). Empty matches (a blank value clears). Must equal the schema's `pattern` for each plain-text field.
         */
        val LOGIN_THEME_PLAIN_TEXT_PATTERN = Regex("^[^<>\\u0000-\\u001F\\u007F-\\u009F]*$")

        /**
         * One character that is neither whitespace nor an ISO control character in Kotlin's sense (`Char.isWhitespace` ||
         * `Char.isISOControl`), spelled out so the JSON Schema (ECMA-262) and the JVM read it the same way — `\s` differs between them.
         */
        private const val LINK_CHAR = "[^\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]"

        /** An `https://` link (any case) with a destination after the scheme and no whitespace / control character; or empty. */
        val LOGIN_THEME_HTTPS_LINK_PATTERN = Regex("^(?:[Hh][Tt][Tt][Pp][Ss]://$LINK_CHAR+)?$")

        /** As [LOGIN_THEME_HTTPS_LINK_PATTERN], or a `mailto:` address (any case) — the support link only. */
        val LOGIN_THEME_SUPPORT_LINK_PATTERN = Regex("^(?:(?:[Hh][Tt][Tt][Pp][Ss]://|[Mm][Aa][Ii][Ll][Tt][Oo]:)$LINK_CHAR+)?$")

        /** Required `spec` members per kind — mirrors the schema's per-kind `then.required`. */
        val REQUIRED_SPEC: Map<String, Set<String>> = mapOf(
            KIND_ENVIRONMENT to setOf("slug"),
            KIND_APPLICATION to setOf("displayName"),
            KIND_USER to setOf("email"),
            KIND_FEDERATION_MEMBER to setOf("providerType"),
            KIND_EMAIL_PROVIDER to setOf("smtpHost"),
            KIND_LOGIN_FLOW to setOf("templateId"),
            // SSO-4041 — every field optional: the spec IS the record (an empty one declares the platform defaults); see [validateLoginTheme].
            KIND_LOGIN_THEME to emptySet(),
            KIND_LOGIN_METHODS to setOf("methods"),
            KIND_CUSTOM_DOMAIN to setOf("host"),
            // SSO-4042 — and exactly one of `body` / `bodyFile`, checked by [validateEmailTemplate].
            KIND_EMAIL_TEMPLATE to setOf("type", "subject"),
            // SSO-4057 — and exactly one of `body` / `bodyFile`, checked by [validateLegalDocument].
            KIND_LEGAL_DOCUMENT to setOf("type", "version", "title"),
            KIND_WORKLOAD_IDENTITY_TRUST to setOf("provider", "scopes"),
            // `permissions` is required too, but `[]` (a role that grants nothing) is legal — checked by [validateRole].
            KIND_ROLE to emptySet(),
        )

        // ── SSO-3941 — `role` and an application's `tokenClaims` ──

        const val ROLE_PERMISSIONS = "permissions"
        const val ROLE_DESCRIPTION = "description"
        /** The `spec` members a role accepts (the schema's `additionalProperties: false`). */
        val ROLE_SPEC_KEYS: Set<String> = setOf(ROLE_PERMISSIONS, ROLE_DESCRIPTION)
        /**
         * product-api's `RbacService.RESERVED_PREFIX`: a permission whose first `:`-segment is `tenant`, `admin` or `holder`
         * (case-insensitive) would be confusable with a platform scope, and is refused `400 permission_name_reserved`.
         */
        val RESERVED_PERMISSION_PREFIX = Regex("^(tenant|admin|holder):.*", RegexOption.IGNORE_CASE)
        const val ERR_PERMISSION_NAME_RESERVED = "permission_name_reserved"

        /** An application's claims-in-token toggle (`/api/v1/applications/{clientId}/token-claims`). */
        const val SPEC_TOKEN_CLAIMS = "tokenClaims"
        const val TOKEN_CLAIMS_SOURCES = "sources"
        const val TOKEN_CLAIMS_ENABLED = "enabled"
        /**
         * SSO-3945 (oauthy SSO-3943) — the optional role mapping: Thoryn role name → the value the application receives in its
         * `roles` claim. `PUT …/token-claims` REPLACES the configuration, so the engine sends it with every PUT and an omitted
         * one means "no mapping" (a live mapping is then removed — the plan says so).
         */
        const val TOKEN_CLAIMS_ROLE_MAPPING = "roleMapping"
        val TOKEN_CLAIMS_KEYS: Set<String> = setOf(TOKEN_CLAIMS_SOURCES, TOKEN_CLAIMS_ENABLED, TOKEN_CLAIMS_ROLE_MAPPING)
        /** The claim source a `roleMapping` translates; product-api refuses a mapping without it (`invalid_role_mapping`). */
        const val TOKEN_CLAIMS_ROLES_SOURCE = "roles"
        // product-api's `RoleMappingRules` (SSO-3943), mirrored exactly — no stricter: the server refuses the same with
        // `400 invalid_role_mapping`, this only says so before any call, naming the field.
        const val ROLE_MAPPING_MAX_ENTRIES = 100
        const val ROLE_MAPPING_MAX_ROLE_NAME_LENGTH = 200
        val ROLE_MAPPING_VALUE_GRAMMAR = Regex("^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
        /** `\p{Cntrl}` as product-api reads it (java.util.regex: ASCII control characters, U+0000–U+001F and U+007F). */
        private val ROLE_MAPPING_CONTROL_CHARS = Regex("\\p{Cntrl}")
        /**
         * product-api's default when `sources` is omitted. The source NAMES are deliberately not validated here: the file
         * passes them through and product-api decides (`400 unsupported_claim_source`), so a source the server gains later
         * (SSO-3943's `roles`) is declarable the day the server accepts it, without a CLI release.
         */
        val DEFAULT_TOKEN_CLAIM_SOURCES: List<String> = listOf("permissions")

        // ── SSO-3689 — secret-less clients: `clientAuthenticationMethods` / `jwksUri` / `jwks` / `federatedTrust` ──

        const val SPEC_CLIENT_AUTHENTICATION_METHODS = "clientAuthenticationMethods"
        const val SPEC_JWKS_URI = "jwksUri"
        const val SPEC_JWKS = "jwks"
        /** The NAME of a [KIND_WORKLOAD_IDENTITY_TRUST] in the same environment; the engine resolves it to the id the API takes. */
        const val SPEC_FEDERATED_TRUST = "federatedTrust"
        const val SPEC_CLIENT_TYPE = "clientType"
        const val SPEC_GRANT_TYPES = "grantTypes"
        const val SPEC_REQUIRE_PROOF_KEY = "requireProofKey"

        /** Rung 1 — the application's own key pair; its public half at `jwksUri` or inline in `jwks`. */
        const val METHOD_PRIVATE_KEY_JWT = "private_key_jwt"
        /** Rung 2 — the workload's platform identity token IS the client assertion (ADR 2026-10-14 federated client authentication). */
        const val METHOD_FEDERATED_ASSERTION = "federated_assertion"
        /** A Thoryn-minted secret presented in the `Authorization: Basic` header — the one method a `secretSink:` delivers for. */
        const val METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"
        /** A public client (PKCE, no credential). */
        const val METHOD_NONE = "none"
        /** NOT declarable: a secret in the request body is the courier rung; product-api accepts it, a provisioning file does not. */
        const val METHOD_CLIENT_SECRET_POST = "client_secret_post"

        /** The CLOSED method allowlist — must equal the schema's `clientAuthenticationMethods.items.enum`. */
        val CLIENT_AUTHENTICATION_METHODS: Set<String> = setOf(METHOD_PRIVATE_KEY_JWT, METHOD_FEDERATED_ASSERTION, METHOD_CLIENT_SECRET_BASIC, METHOD_NONE)
        /** The methods a Thoryn-minted secret exists for: a `secretSink:` is legal only when the declared methods include one. */
        val SECRET_BEARING_METHODS: Set<String> = setOf(METHOD_CLIENT_SECRET_BASIC)

        /** product-api's `clientType` defaults to `confidential`; only an explicit `public` client is secret-less. */
        fun isConfidential(spec: Map<String, Any?>): Boolean =
            !spec[SPEC_CLIENT_TYPE]?.toString()?.trim().equals(CLIENT_TYPE_PUBLIC, ignoreCase = true)

        /**
         * SSO-3689 — whether creating an application with [spec] MINTS a client secret: a confidential client whose declared
         * methods include a secret-bearing one (or declare none — product-api then defaults to `client_secret_basic`). A
         * `private_key_jwt` or `federated_assertion` client is confidential and minted nothing (`clientSecret: null`).
         */
        fun mintsSecret(spec: Map<String, Any?>): Boolean {
            if (!isConfidential(spec)) return false
            val methods = (spec[SPEC_CLIENT_AUTHENTICATION_METHODS] as? List<*>)?.map { it.toString().trim() } ?: return true
            return methods.any { it in SECRET_BEARING_METHODS }
        }
        /** The grants a federated login client may register (ADR 2026-10-14 §2) — never `client_credentials`. */
        val FEDERATED_GRANT_TYPES: Set<String> = setOf("authorization_code", "refresh_token")
        /** JWK members that carry PRIVATE key material (RFC 7518 §6.2.2 / §6.3.2 / §6.4) — refused in any inline `jwks`. */
        val JWK_PRIVATE_MEMBERS: Set<String> = setOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")
        /** The key types an inline JWK Set may carry (what the hub validates assertions with). */
        val JWK_KEY_TYPES: Set<String> = setOf("RSA", "EC")

        // The codes the hub's `FederatedLoginClientBinder` and product-api's `FederatedAssertionBindingValidator` answer
        // with — mirrored so a file is refused with the same vocabulary whichever side refuses.
        const val ERR_FEDERATED_ONLY_METHOD = "federated_assertion_only_method"
        const val ERR_FEDERATED_GRANT_NOT_ALLOWED = "federated_assertion_grant_not_allowed"
        const val ERR_FEDERATED_PKCE_REQUIRED = "federated_assertion_pkce_required"
        const val ERR_FEDERATED_NO_SECRET_OR_KEY = "federated_assertion_no_secret_or_key"
        const val ERR_FEDERATED_TRUST_REQUIRED = "federated_trust_required"
        const val ERR_FEDERATED_TRUST_WITHOUT_METHOD = "federated_trust_without_method"
        /** product-api's code for a method outside its allowlist; here also the file's answer to `client_secret_post`. */
        const val ERR_INVALID_CLIENT_AUTHENTICATION_METHOD = "invalid_client_authentication_method"
        const val ERR_INCOHERENT_CLIENT_AUTHENTICATION_METHODS = "incoherent_client_authentication_methods"
        // The file's own codes (no API counterpart: the API would accept the shape, the ladder does not).
        const val ERR_PRIVATE_KEY_JWT_KEY_REQUIRED = "private_key_jwt_key_required"
        const val ERR_JWKS_XOR_JWKS_URI = "jwks_or_jwks_uri"
        const val ERR_SECRET_SINK_WITHOUT_SECRET = "secret_sink_without_secret_method"
        const val ERR_INVALID_JWKS = "invalid_jwks"

        // ── SSO-3766 / SSO-3767 / SSO-3770 — application settings the applications API took on (oauthy SSO-3758 / 3759 / 3762) ──

        /** SSO-3767 — RFC 8693 token exchange for this application (product-api `allowTokenExchange`, default `false`). */
        const val SPEC_ALLOW_TOKEN_EXCHANGE = "allowTokenExchange"
        /** SSO-3766 — the RFC 9396 `authorization_details` types the application may send (default `[]`; PATCH replaces, `[]` clears). */
        const val SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES = "allowedAuthorizationDetailTypes"
        /** SSO-3770 — cap the session at [SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS] counted from sign-in (default `false`). */
        const val SPEC_REFRESH_TOKEN_SLIDING_WINDOW = "refreshTokenSlidingWindow"
        /** SSO-3770 — the absolute session lifetime in seconds (default 7 776 000 = 90 d); needs the sliding window. */
        const val SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS = "refreshTokenAbsoluteMaxTtlSeconds"
        /** The sliding refresh-token TTL the absolute lifetime must not undercut (sent on create; not converged today). */
        const val SPEC_REFRESH_TOKEN_TTL_SECONDS = "refreshTokenTtlSeconds"
        /** SSO-3810 — the application may call RFC 7662 introspection at its workspace (product-api `allowTokenIntrospection`, default `false`). */
        const val SPEC_ALLOW_TOKEN_INTROSPECTION = "allowTokenIntrospection"
        /** SSO-3807 — the access-token format the application receives: `self-contained` (a JWT, the default) or `reference` (opaque). */
        const val SPEC_ACCESS_TOKEN_FORMAT = "accessTokenFormat"
        /** SSO-3811 — DPoP (RFC 9449) opt-in: a proof that arrives binds the access token (product-api `dpopAllowed`, default `false`). */
        const val SPEC_DPOP_ALLOWED = "dpopAllowed"
        /** SSO-3811 — every token request must carry a DPoP proof (product-api `dpopRequired`, default `false`). */
        const val SPEC_DPOP_REQUIRED = "dpopRequired"
        /** product-api's `accessTokenFormat` values (the hub's `OAuth2TokenFormat` values, exact spelling). */
        val ACCESS_TOKEN_FORMATS: Set<String> = setOf("self-contained", "reference")
        /** The settings, in the order a plan lists them — each converged on UPDATE, an omitted one keeps the live value. */
        val APPLICATION_SETTING_FIELDS: List<String> = listOf(
            SPEC_ALLOW_TOKEN_EXCHANGE, SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES, SPEC_REFRESH_TOKEN_SLIDING_WINDOW, SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS,
            SPEC_ALLOW_TOKEN_INTROSPECTION, SPEC_ACCESS_TOKEN_FORMAT, SPEC_DPOP_ALLOWED, SPEC_DPOP_REQUIRED,
        )
        /** The RFC 8693 grant an application must register to hold [SPEC_ALLOW_TOKEN_EXCHANGE]. */
        const val GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
        /** product-api's absolute-session bounds (`AdvancedClientSettingsValidator.ABSOLUTE_SESSION_MIN/MAX_SECONDS`): 1 h – 90 d. */
        const val ABSOLUTE_SESSION_MIN_SECONDS = 3_600L
        const val ABSOLUTE_SESSION_MAX_SECONDS = 7_776_000L
        /** The hub's own RFC 9396 type — permitted only for applications of the platform HOME workspace (`thoryn`). */
        const val AUTHORIZATION_DETAILS_TYPE_ACCESS_GRANT = "thoryn_access_grant"
        /** One RFC 9396 type per entry: a non-empty token without whitespace (the server decides which are supported). */
        val AUTHORIZATION_DETAILS_TYPE_PATTERN = Regex("^\\S+$")
        // product-api's codes for these settings, mirrored so a file is refused with the vocabulary the API answers with.
        const val ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT = "token_exchange_requires_confidential_client"
        const val ERR_TOKEN_EXCHANGE_GRANT_REQUIRED = "token_exchange_grant_required"
        /** API-only (403): turning the setting ON needs `manager` on the application's environment — the plan gate predicts it. */
        const val ERR_TOKEN_EXCHANGE_NOT_GRANTABLE = "token_exchange_not_grantable"
        /** SSO-3810 — `allowTokenIntrospection: true` on a public client (product-api / hub `400`). */
        const val ERR_TOKEN_INTROSPECTION_REQUIRES_CONFIDENTIAL_CLIENT = "token_introspection_requires_confidential_client"
        /** SSO-3810 — API-only (403): turning introspection ON needs `manager` on the application's environment — the plan gate predicts it. */
        const val ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE = "token_introspection_not_grantable"
        /** SSO-3807 — `accessTokenFormat` is not exactly `self-contained` or `reference`. */
        const val ERR_INVALID_ACCESS_TOKEN_FORMAT = "invalid_access_token_format"
        /** API-only (400): a type the authorization server does not support (its discovery list, plus [AUTHORIZATION_DETAILS_TYPE_ACCESS_GRANT]). */
        const val ERR_UNSUPPORTED_AUTHORIZATION_DETAILS_TYPE = "unsupported_authorization_details_type"
        /** API-only (403): [AUTHORIZATION_DETAILS_TYPE_ACCESS_GRANT] outside the platform home workspace. */
        const val ERR_AUTHORIZATION_DETAILS_TYPE_NOT_PERMITTED = "authorization_details_type_not_permitted"
        const val ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW = "session_lifetime_requires_sliding_window"
        const val ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL = "session_lifetime_below_refresh_ttl"
        const val ERR_TOKEN_TTL_OUT_OF_RANGE = "token_ttl_out_of_range"
        /** API-only (400): longer than the environment authentication policy's `refreshClipSeconds` (the cap rides in `max`). */
        const val ERR_SESSION_EXCEEDS_TENANT_POLICY = "session_exceeds_tenant_policy"

        // ── SSO-3689 — `workloadIdentityTrust` ──

        const val PROVIDER_GITHUB_ACTIONS = "github_actions"
        const val PROVIDER_FORGEJO = "forgejo"
        const val PROVIDER_KUBERNETES = "kubernetes"
        /** The CLOSED provider allowlist — must equal the schema's `provider` enum; each maps to its pin block. */
        val TRUST_PIN_BLOCKS: Map<String, String> = linkedMapOf(PROVIDER_GITHUB_ACTIONS to "github", PROVIDER_FORGEJO to "forgejo", PROVIDER_KUBERNETES to "kubernetes")
        val TRUST_PROVIDERS: Set<String> get() = TRUST_PIN_BLOCKS.keys
        const val TRUST_SCOPES = "scopes"
        const val TRUST_CONFIRM_PRODUCTION = "confirmProduction"
        /**
         * SSO-3702 (SSO-3699 option B) — a `github_actions` trust's optional PLAN profile `{ environment, scopes? }`: a
         * second GitHub environment whose jobs the hub mints read-only scopes only (the `.read` members of `spec.scopes`
         * when `scopes` is omitted — derived by the hub). Sent on create; on a live trust WITHOUT a profile it is converged
         * by the one additive `set plan profile` call; a live profile that differs is `workload_identity_trust_immutable`.
         */
        const val TRUST_PLAN = "plan"
        val TRUST_PLAN_KEYS: Set<String> = setOf("environment", TRUST_SCOPES)
        /** The `spec` members a trust accepts (the schema's `additionalProperties: false`). */
        val TRUST_SPEC_KEYS: Set<String> = setOf("provider", TRUST_SCOPES, TRUST_CONFIRM_PRODUCTION, TRUST_PLAN) + TRUST_PIN_BLOCKS.values
        val GITHUB_PIN_KEYS: Set<String> = setOf("repository", "ownerId", "repositoryId", "environment", "ref", "githubHostedRunnersOnly")
        val FORGEJO_PIN_KEYS: Set<String> = setOf("instanceUrl", "owner", "ownerId", "repository", "repositoryId", "ref")
        val KUBERNETES_PIN_KEYS: Set<String> = setOf("issuer", "namespace", "serviceAccount", "jwks")
        /** A trust carries workspace (`tenant:<area>.<action>`) scopes only — the hub's `invalid_scope` otherwise. */
        val TENANT_SCOPE_PATTERN = Regex("^tenant:[a-z-]+\\.[a-z-]+$")
        /** A Forgejo instance origin: `https`, host (and port), no path. */
        val FORGEJO_INSTANCE_PATTERN = Regex("^https://[^/?#]+$")
        val GIT_REF_PATTERN = Regex("^refs/.+")
        // The trust service's codes (product-api `WorkloadIdentityTrustService`), mirrored for the file's own refusals.
        const val ERR_UNSUPPORTED_PROVIDER = "unsupported_provider"
        const val ERR_INVALID_SCOPE = "invalid_scope"
        const val ERR_PRODUCTION_CONFIRMATION_REQUIRED = "production_confirmation_required"
        const val ERR_PRODUCTION_REQUIRES_ENVIRONMENT = "production_requires_environment"
        const val ERR_PRODUCTION_REQUIRES_REF = "production_requires_ref"
        const val ERR_PRODUCTION_REQUIRES_SERVICE_ACCOUNT = "production_requires_service_account"
        const val ERR_INVALID_GITHUB_IDS = "invalid_github_ids"
        const val ERR_INVALID_FORGEJO_IDS = "invalid_forgejo_ids"
        const val ERR_INVALID_FORGEJO_INSTANCE = "invalid_forgejo_instance"
        const val ERR_INVALID_KUBERNETES_ISSUER = "invalid_kubernetes_issuer"
        const val ERR_INVALID_KUBERNETES_NAMESPACE = "invalid_kubernetes_namespace"
        const val ERR_INVALID_KUBERNETES_SERVICE_ACCOUNT = "invalid_kubernetes_service_account"
        const val ERR_INVALID_KUBERNETES_JWKS = "invalid_kubernetes_jwks"
        // SSO-3702 — the plan profile's codes (product-api SSO-3701 / hub SSO-3700), mirrored for the file's own refusals.
        const val ERR_PLAN_PROFILE_UNSUPPORTED = "plan_profile_unsupported"
        const val ERR_PLAN_PROFILE_REQUIRES_ENVIRONMENT = "plan_profile_requires_environment"
        const val ERR_INVALID_PLAN_ENVIRONMENT = "invalid_plan_environment"
        const val ERR_PLAN_ENVIRONMENT_EQUALS_APPLY = "plan_environment_equals_apply"
        const val ERR_PLAN_SCOPES_EMPTY = "plan_scopes_empty"
        const val ERR_PLAN_SCOPE_NOT_READ_ONLY = "plan_scope_not_read_only"
        const val ERR_PLAN_SCOPE_NOT_SUBSET = "plan_scope_not_subset"

        /** SSO-3702 — a read-only workspace scope (`tenant:<area>.read`), the only kind a plan profile may carry. */
        val READ_SCOPE_PATTERN = Regex("^tenant:[a-z-]+\\.read$")

        /**
         * SSO-3856 — the operator-plane scope namespaces. A `platform:` scope on a client is put there (and taken away)
         * only by an operator (`thoryn operator platform-scopes`, oathy ADR `2026-10-19-operator-grants-platform-client-
         * scopes.md`); an `admin:` scope only ever sits on the operator client. Neither can be granted from a provisioning
         * file — the hub refuses both on every customer-plane path — and the hub KEEPS a client's `platform:` scopes when a
         * provisioning update replaces its scope list. So the engine neither declares nor compares them: a declared one is
         * refused here ([ERR_RESERVED_SCOPE]), and a live one is left out of the diff, or every plan of a client an
         * operator has granted one to would show a change that applying can never make.
         */
        val RESERVED_OPERATOR_PLANE_SCOPE_PREFIXES: List<String> = listOf("platform:", "admin:")
        const val ERR_RESERVED_SCOPE = "reserved_scope"

        fun isReservedOperatorPlaneScope(scope: String): Boolean =
            RESERVED_OPERATOR_PLANE_SCOPE_PREFIXES.any { scope.trim().startsWith(it) }

        /** The production plane: no `environment`, or the `production` slug (mirrors [ProvisionEngine.PRODUCTION_ENV_SLUG]). */
        fun isProductionPlane(environment: String?): Boolean = environment == null || environment == ProvisionEngine.PRODUCTION_ENV_SLUG

        val NAME_PATTERN = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        /** A `spec` property name that would carry a secret VALUE — rejected; use `<key>Env`. */
        val SECRET_KEY_PATTERN = Regex("([Pp]assword|[Ss]ecret|[Tt]oken)$")

        /**
         * SSO-3113 — the relations a `grants:` entry may carry (the SSO-3112 contract; equals the schema enum).
         * SSO-3673 — deliberately WITHOUT [AccessRefs.RELATION_OWNER]: a repository cannot claim ownership by
         * writing YAML; a workspace admin grants `owner` with `thoryn access grant` (see [GRANT_OWNER_REFUSED]).
         */
        val GRANT_RELATIONS: Set<String> = setOf(AccessRefs.RELATION_MANAGER, AccessRefs.RELATION_VIEWER)

        /** SSO-3673 — the violation text for `relation: owner` in a `grants:` entry; names the fix. */
        const val GRANT_OWNER_REFUSED: String =
            "relation 'owner' cannot be declared in a provisioning file — a repository cannot claim ownership by writing YAML; " +
                "a workspace admin grants it with `thoryn access grant <subject> owner <object>`"

        /** SSO-3659 — the resource-level `readOnly` flag (ADR 2026-10-13 §1): a dependency, not an owned resource. */
        const val READ_ONLY = "readOnly"
        /** SSO-3715 — the resource-level `retain` flag (ADR 2026-10-15 §1): owned and converged, never removed by destroy / --prune. */
        const val RETAIN = "retain"

        // ── SSO-3668 — `publishTo:` (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) ──

        /** The resource-level output declaration: where `apply` publishes the converged id ([PublishTarget]). */
        const val PUBLISH_TO = "publishTo"
        /** A GitHub Actions VARIABLE on a repository's environment (`gh variable set … --env`). Never a secret. */
        const val PUBLISH_KIND_GITHUB_ACTIONS_VARIABLE = "githubActionsVariable"
        /** The CLOSED publish-target kind allowlist — must equal the schema's `publishTo.items.kind` enum. */
        val PUBLISH_KINDS: Set<String> = setOf(PUBLISH_KIND_GITHUB_ACTIONS_VARIABLE)
        /** The kinds a `publishTo:` may sit on: an application's clientId is the one output a resource has. */
        val PUBLISHABLE_KINDS: Set<String> = setOf(KIND_APPLICATION)
        /** The members of one target — exactly these four (the schema's `additionalProperties: false`). */
        val PUBLISH_TARGET_KEYS: Set<String> = setOf("kind", "repository", "environment", "name")
        /** `owner/name` — a GitHub owner (no leading / trailing hyphen, ≤ 39) and a repository name (≤ 100). */
        val REPOSITORY_PATTERN = Regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}$")
        /** An Actions variable name: upper-case, digits and underscores, not starting with a digit. */
        val VARIABLE_NAME_PATTERN = Regex("^[A-Z_][A-Z0-9_]*$")
        /** GitHub reserves the `GITHUB_` prefix for its own variables; such a name is refused at publish time. */
        const val RESERVED_VARIABLE_PREFIX = "GITHUB_"

        // ── SSO-3659 — `secretSink:` (ADR 2026-10-13 converge §5; production-clients ADR §3 tier 3) ──

        /** The resource-level delivery declaration: where `apply` hands a minted client secret ([SecretTarget]). */
        const val SECRET_SINK = "secretSink"
        /** `data.<key>` of an EXISTING namespace's Kubernetes Secret, through the operator's own `kubectl` (value on stdin). */
        const val SECRET_SINK_KIND_KUBERNETES_SECRET = "kubernetesSecret"
        /** An owner-only (`0600`) file; never overwritten unless the host is told to. */
        const val SECRET_SINK_KIND_FILE = "file"
        /**
         * SSO-3921 (oauthy ADR 2026-10-14 credential ladder, rung 3) — delivered nowhere: the minted value is discarded and the
         * named `kubernetes` trust's workload client is converged `manager` on the application, so the pod mints its own.
         */
        const val SECRET_SINK_KIND_WORKLOAD_PULL = "workloadPull"
        /**
         * SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951) — THE DEFAULT: the customer manages the secret. `apply`
         * discards the create's one-time value, grants nothing, and the plan names the runbook ([CUSTOMER_MANAGED_RUNBOOK]).
         */
        const val SECRET_SINK_KIND_CUSTOMER_MANAGED = "customerManaged"
        /** SSO-3954 — the person's step a `customerManaged` secret takes: minted by Thoryn, stored by the customer. */
        const val CUSTOMER_MANAGED_RUNBOOK = "a person mints it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and stores it in your secret manager (or an operator-created Kubernetes Secret)"
        /** SSO-3954 — the deprecation every `workloadPull` sink is reported with (plan, apply, `provision workflow check`). */
        const val WORKLOAD_PULL_DEPRECATION = "secretSink workloadPull is DEPRECATED (product-owner decision SSO-3951, 2026-10-25: Thoryn owns the secret lifecycle, the customer owns delivery; SSO-3953 removes it) — drop the sink (the default is $SECRET_SINK_KIND_CUSTOMER_MANAGED), then revoke the pod trust's manager grant and delete the trust by hand"
        /** The CLOSED sink kind allowlist — must equal the schema's `secretSink.oneOf[*].kind` consts. */
        val SECRET_SINK_KINDS: Set<String> = setOf(SECRET_SINK_KIND_KUBERNETES_SECRET, SECRET_SINK_KIND_FILE, SECRET_SINK_KIND_WORKLOAD_PULL, SECRET_SINK_KIND_CUSTOMER_MANAGED)
        /** SSO-3954 — the members of a `customerManaged` target — the kind alone. */
        val SECRET_SINK_CUSTOMER_MANAGED_KEYS: Set<String> = setOf("kind")
        /** The kinds a `secretSink:` may sit on: only a (confidential) application is minted a secret. */
        val SECRET_SINK_KINDS_ALLOWED_ON: Set<String> = setOf(KIND_APPLICATION)
        /** The members of a `kubernetesSecret` target — exactly these four (the schema's `additionalProperties: false`). */
        val SECRET_SINK_KUBERNETES_KEYS: Set<String> = setOf("kind", "namespace", "name", "key")
        /** The members of a `file` target — exactly these two. */
        val SECRET_SINK_FILE_KEYS: Set<String> = setOf("kind", "path")
        /** SSO-3921 — the members of a `workloadPull` target — exactly these two. */
        val SECRET_SINK_WORKLOAD_PULL_KEYS: Set<String> = setOf("kind", "trust")
        /** SSO-3921 — the provider a runtime-pull trust must have: rung 3 is a POD minting its own secret at start. */
        const val WORKLOAD_PULL_PROVIDER = PROVIDER_KUBERNETES
        /**
         * SSO-3921 — the scope the pod's `thoryn clients rotate-secret` needs (product-api's `POST /api/v1/applications/{id}/
         * secret/rotate`; oauthy ADR 2026-10-14 rung 3: "a workload client holding `tenant:applications.write` on the
         * application may call it"). The trust's scope ceiling must carry it, or the pod's rotation is a `403`.
         */
        const val ROTATE_SECRET_SCOPE = "tenant:applications.write"
        // SSO-3921 — the file's (and the plan's) refusals of a `workloadPull` sink.
        /** The named trust exists neither in the file nor live (in the application's plane). */
        const val ERR_WORKLOAD_PULL_TRUST_NOT_FOUND = "workload_pull_trust_not_found"
        /** The named trust lives on another plane than the application: its workload client could not rotate it. */
        const val ERR_WORKLOAD_PULL_TRUST_OTHER_PLANE = "workload_pull_trust_other_plane"
        /** The named trust is not a `kubernetes` trust: runtime pull is a pod's, never a CI job's (that would be the courier). */
        const val ERR_WORKLOAD_PULL_TRUST_PROVIDER = "workload_pull_trust_not_kubernetes"
        /** The named trust's scopes do not carry [ROTATE_SECRET_SCOPE]. */
        const val ERR_WORKLOAD_PULL_SCOPE_MISSING = "workload_pull_scope_missing"
        /** A Kubernetes namespace: an RFC 1123 DNS label (lower-case alphanumerics and `-`, ≤ 63). */
        val K8S_NAMESPACE_PATTERN = Regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
        /** A Kubernetes Secret name: an RFC 1123 DNS subdomain (lower-case labels joined by `.`, ≤ 253 in total). */
        val K8S_SECRET_NAME_PATTERN = Regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
        const val K8S_SECRET_NAME_MAX = 253
        /** A Secret `data` key: alphanumerics, `-`, `_`, `.` (≤ 253), the grammar `kubectl create secret` accepts. */
        val K8S_SECRET_KEY_PATTERN = Regex("^[-._a-zA-Z0-9]+$")
        const val K8S_SECRET_KEY_MAX = 253
        /** `clientType: public` — the one spec value that means no secret is minted (product-api defaults to confidential). */
        const val CLIENT_TYPE_PUBLIC = "public"

        private val jsonMapper = JsonMapper.builder().addModule(kotlinModule()).build()
        private val yamlMapper = YAMLMapper.builder().addModule(kotlinModule()).build()

        /** The default file under [dir]/.thoryn, probing [DEFAULT_FILES] in order; null when none exists. */
        fun resolveDefault(dir: File = File(".")): File? =
            DEFAULT_FILES.map { File(dir, "$DEFAULT_DIR/$it") }.firstOrNull { it.isFile }

        /** Read, parse and validate a provisioning file; throws [ProvisionException] on any problem. */
        fun load(file: File, env: (String) -> String? = { System.getenv(it) }): ProvisionFile {
            if (!file.isFile) throw ProvisionException("provisioning file not found: ${file.path}")
            val bytes = try {
                file.readBytes()
            } catch (e: Exception) {
                throw ProvisionException("could not read provisioning file '${file.path}': ${e.message}")
            }
            val yaml = !file.name.endsWith(".json", ignoreCase = true)
            return parse(bytes, file.path, yaml, env, baseDir = file.absoluteFile.parentFile)
        }

        /**
         * Parse and validate [bytes] (YAML unless [yaml] is false); [source] is used only in messages.
         *
         * SSO-3430 — a resource's `environment` may carry `{{env.NAME}}` placeholders (the grammar `spec`
         * already uses), resolved here from [env]: a repository that is not rendered names its sandbox
         * through a CI variable (`environment: "{{env.THORYN_ENVIRONMENT}}"`). The field is ADDRESSING,
         * not a write-only secret, so an unset or empty variable fails closed for plan and apply alike —
         * never a silent fallback to the production plane. [env] `null` leaves `environment` as written (a
         * bundled recipe resolves its own params later); `thoryn provision` ([load]) reads the process env.
         *
         * SSO-4042 — an `emailTemplate`'s `spec.bodyFile` is resolved against [baseDir] (the provisioning file's own directory,
         * as [load] passes it), read here and checked against the body caps; the resource then carries the HTML as `spec.body`
         * (and keeps `bodyFile` so a plan can name the file). A file parsed from bytes with no [baseDir] cannot declare one.
         * SSO-4057 — the same for a `legalDocument`'s body ([BODY_FILE_KINDS]), held to the legal-document body rules.
         */
        fun parse(
            bytes: ByteArray,
            source: String = "<provision>",
            yaml: Boolean = true,
            env: ((String) -> String?)? = null,
            baseDir: File? = null,
        ): ProvisionFile {
            val root = try {
                if (yaml) yamlMapper.readTree(bytes) else jsonMapper.readTree(bytes)
            } catch (e: Exception) {
                throw ProvisionException("provisioning file '$source' is not valid ${if (yaml) "YAML" else "JSON"}: ${e.message}")
            }
            val violations = validate(root)
            if (violations.isNotEmpty()) {
                throw ProvisionException("invalid provisioning file '$source':\n  - " + violations.joinToString("\n  - "))
            }
            val unresolved = mutableListOf<String>()
            val resources = root["resources"].toList().mapIndexed { i, r ->
                val kind = r["kind"].asString()
                @Suppress("UNCHECKED_CAST")
                val declaredSpec = jsonMapper.convertValue(r["spec"], Map::class.java) as Map<String, Any?>
                val spec = if (kind in BODY_FILE_KINDS) readBodyFile(kind, declaredSpec, baseDir, "resources[$i]", unresolved) else declaredSpec
                ProvisionResource(
                    kind = kind,
                    name = r["name"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() } ?: kind,
                    environment = r["environment"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() }
                        ?.let { raw -> env?.let { resolveEnvironment(raw, "resources[$i]", it, unresolved) } ?: raw },
                    spec = spec,
                    grants = r["grants"]?.takeIf { it.isArray() }?.toList()?.map { g ->
                        ProvisionGrant(subject = g["subject"].asString().trim(), relation = g["relation"].asString().trim())
                    },
                    readOnly = r[READ_ONLY]?.takeIf { it.isBoolean() }?.asBoolean() ?: false,
                    retain = r[RETAIN]?.takeIf { it.isBoolean() }?.asBoolean() ?: false,
                    publishTo = r[PUBLISH_TO]?.takeIf { it.isArray() }?.toList()?.map { t ->
                        PublishTarget(
                            kind = t["kind"].asString().trim(),
                            repository = t["repository"].asString().trim(),
                            environment = t["environment"].asString().trim(),
                            name = t["name"].asString().trim(),
                        )
                    } ?: emptyList(),
                    secretSink = r[SECRET_SINK]?.takeIf { it.isObject() }?.let { t ->
                        fun text(field: String): String? = t[field]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
                        SecretTarget(kind = text("kind") ?: "", namespace = text("namespace"), name = text("name"), key = text("key"), path = text("path"), trust = text("trust"))
                    },
                )
            }
            if (unresolved.isNotEmpty()) {
                throw ProvisionException("invalid provisioning file '$source':\n  - " + unresolved.joinToString("\n  - "))
            }
            val part = ProvisionPart.of(root["apiVersion"].asString()) ?: ProvisionPart.MIXED
            return ProvisionFile(source = source, digest = sha256(bytes), resources = resources, part = part, warnings = warnings(part, resources))
        }

        /**
         * SSO-4042 — resolve `spec.bodyFile` into `spec.body`: the path is relative to [baseDir] and must stay inside it (the
         * grammar check in [validateEmailTemplate] / [validateLegalDocument] refused `..` and absolute paths; this is the
         * resolved-path check), the file must exist and read as UTF-8, and its content is held to the same rules as an inline
         * body of the [kind] (SSO-4057 — a legal document's: 128 KiB, no control character, no HTML). Problems land on
         * [problems] (the file fails to load — a body that cannot be read must never plan as "create with an empty body").
         */
        private fun readBodyFile(kind: String, spec: Map<String, Any?>, baseDir: File?, where: String, problems: MutableList<String>): Map<String, Any?> {
            val path = spec["bodyFile"]?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return spec
            if (baseDir == null) {
                problems += "$where ($kind) spec.bodyFile '$path' cannot be resolved: this provisioning document was not read from a file, so there is no directory to resolve it against — use spec.body"
                return spec
            }
            val root = baseDir.absoluteFile.normalize()
            val file = File(root, path).absoluteFile.normalize()
            if (!file.path.startsWith(root.path + File.separator)) {
                problems += "$where ($kind) spec.bodyFile '$path' resolves outside the provisioning file's directory"
                return spec
            }
            if (!file.isFile) {
                problems += "$where ($kind) spec.bodyFile '$path' not found (${file.path})"
                return spec
            }
            val text = try {
                file.readText(Charsets.UTF_8)
            } catch (e: Exception) {
                problems += "$where ($kind) spec.bodyFile '$path' could not be read: ${e.message}"
                return spec
            }
            if (kind == KIND_LEGAL_DOCUMENT) {
                legalDocumentBodyProblem(text)?.let { problems += "$where ($kind) spec.bodyFile '$path' $it" }
            } else {
                val bytes = text.toByteArray(Charsets.UTF_8).size
                when {
                    text.isBlank() -> problems += "$where ($kind) spec.bodyFile '$path' is blank"
                    bytes > EMAIL_TEMPLATE_MAX_BODY_BYTES -> problems += "$where ($kind) spec.bodyFile '$path' is $bytes bytes, over the $EMAIL_TEMPLATE_MAX_BODY_BYTES-byte limit"
                }
            }
            return spec + ("body" to text)
        }

        // ── SSO-3962 — what is accepted today and refused in a later release ──

        /** The release line a deprecation names: the mixed format and `publishTo` are accepted through it and refused after. */
        const val DEPRECATION_WINDOW: String = "accepted for one more release"

        /**
         * The deprecations [resources] under [part] carry, each one sentence (see [ProvisionFile.warnings]):
         *  - a [ProvisionPart.MIXED] file: which part it should declare — tenant when it declares only tenant kinds,
         *    application when only application kinds, and when it declares both, that it is two files (the tenant
         *    resources belong in the workspace's config project, the application resources in the app project —
         *    `thoryn provision split` writes them);
         *  - `publishTo:` (SSO-3668, ADR 2026-10-13 §2 — superseded by ADR 2026-10-25 decision 1): the app project owns its
         *    production client in every environment, created under a consent-approved creation slot, so no variable sink is
         *    needed; the targets still publish today.
         */
        fun warnings(part: ProvisionPart, resources: List<ProvisionResource>): List<String> {
            val w = mutableListOf<String>()
            if (part == ProvisionPart.MIXED) {
                val tenant = resources.filter { it.kind in TENANT_KINDS }
                val application = resources.filter { it.kind in APPLICATION_KINDS }
                val head = "apiVersion $API_VERSION is deprecated ($DEPRECATION_WINDOW; SSO-3962, oauthy ADR 2026-10-25 provisioning-is-tenant-and-applications): " +
                    "a file is tenant provisioning (${ProvisionPart.TENANT.apiVersion}, the workspace's ONE config project) or application provisioning " +
                    "(${ProvisionPart.APPLICATION.apiVersion}, an app project). "
                w += when {
                    application.isEmpty() -> head + "This file declares only tenant kinds — declare `apiVersion: ${ProvisionPart.TENANT.apiVersion}`."
                    tenant.isEmpty() -> head + "This file declares only application kinds — declare `apiVersion: ${ProvisionPart.APPLICATION.apiVersion}`."
                    else -> head + "This file declares BOTH: ${tenant.joinToString(", ") { it.key }} are tenant provisioning (the config project) and " +
                        "${application.joinToString(", ") { it.key }} are application provisioning (the app project) — split it into two files " +
                        "(`thoryn provision split`), each converged by its own project's identity."
                }
            }
            resources.filter { it.publishTo.isNotEmpty() }.takeIf { it.isNotEmpty() }?.let { publishing ->
                w += "$PUBLISH_TO is deprecated ($DEPRECATION_WINDOW; SSO-3962 — oauthy ADR 2026-10-25 supersedes ADR 2026-10-13 §1–§2): the application project " +
                    "owns its production client in every environment, created under a consent-approved creation slot (`thoryn access reserve` / " +
                    "`thoryn access approve`), and its deploy reads the client id from its own apply (`apply --output json`, `thoryn clients list`) — " +
                    "no variable another repository publishes. Declared on: ${publishing.joinToString(", ") { it.key }}. The targets are still published today; " +
                    "move the client to the app project's ${ProvisionPart.APPLICATION.apiVersion} file and drop the block."
            }
            return w
        }

        /**
         * SSO-3430 — substitute `{{env.NAME}}` in a resource's `environment`. A value without a placeholder
         * is returned unchanged; an unset / empty variable, or a result that is not an environment name or
         * slug, is recorded in [problems] (and the raw value returned so parsing can report every problem).
         */
        private fun resolveEnvironment(raw: String, where: String, env: (String) -> String?, problems: MutableList<String>): String {
            if (!ProvisionEngine.ENV_PLACEHOLDER.containsMatchIn(raw)) return raw
            var missing = false
            val resolved = ProvisionEngine.ENV_PLACEHOLDER.replace(raw) { m ->
                val name = m.groupValues[1]
                env(name)?.trim()?.takeIf { it.isNotEmpty() } ?: run {
                    problems += "$where environment '$raw' references env var '$name', which is not set"
                    missing = true
                    m.value
                }
            }
            if (missing) return raw
            if (!NAME_PATTERN.matches(resolved)) {
                problems += "$where environment '$raw' resolves to '$resolved', which is not an environment slug (${NAME_PATTERN.pattern})"
                return raw
            }
            return resolved
        }

        /**
         * Structural validation mirroring `provision.schema.json`: the `apiVersion` const, unknown
         * properties, the closed `kind` allowlist, `name` grammar + uniqueness, per-kind required `spec`
         * members, the secret-key rejection, and that an `environment` resource carries no
         * `environment`. Returns human-readable violations (empty ⇒ conformant).
         */
        fun validate(root: JsonNode): List<String> {
            val v = mutableListOf<String>()
            if (!root.isObject()) return listOf("provisioning file must be an object")
            rejectUnknownKeys(root, setOf("apiVersion", "resources"), "(root)", v)
            // SSO-3962 — the part the file declares; an unknown string names the two parts (and the deprecated mixed one) it may be.
            val declared = root["apiVersion"]?.takeIf { it.isTextual() }?.asString()
            val part = ProvisionPart.of(declared)
            if (part == null) {
                v += "apiVersion must be '$API_VERSION_TENANT' (tenant provisioning: the workspace's config project) or '$API_VERSION_APPLICATION' " +
                    "(application provisioning: an app project); '$API_VERSION' is accepted for one more release" + (declared?.let { " (was '$it')" } ?: "")
            }

            val resources = root["resources"]
            if (resources == null || !resources.isArray()) {
                v += "resources array is required"
                return v
            }
            if (resources.isEmpty()) v += "resources must be non-empty"
            val keys = mutableListOf<String>()
            resources.toList().forEachIndexed { i, r ->
                val where = "resources[$i]"
                if (!r.isObject()) {
                    v += "$where must be an object"
                    return@forEachIndexed
                }
                rejectUnknownKeys(r, setOf("kind", "name", "environment", "spec", "grants", READ_ONLY, RETAIN, PUBLISH_TO, SECRET_SINK), where, v)
                // SSO-3659 — `readOnly: true` declares a dependency, not ownership: a boolean, and never with `grants`
                // (a grant is a write on the object; a reference writes nothing).
                r[READ_ONLY]?.takeIf { !it.isNull }?.let { ro ->
                    if (!ro.isBoolean()) v += "$where $READ_ONLY must be true or false"
                    else if (ro.asBoolean() && r["grants"]?.takeIf { !it.isNull } != null) v += "$where a read-only reference cannot carry 'grants' — this repository does not own it"
                }
                // SSO-3715 — `retain: true` is "mine, keep": a boolean, meaningless on a reference (never removed anyway).
                r[RETAIN]?.takeIf { !it.isNull }?.let { keep ->
                    if (!keep.isBoolean()) v += "$where $RETAIN must be true or false"
                    else if (keep.asBoolean() && r[READ_ONLY]?.takeIf { it.isBoolean() }?.asBoolean() == true) v += "$where a read-only reference cannot carry '$RETAIN' — it is never removed; `$RETAIN` is for a resource this file owns"
                }
                val kind = r["kind"]?.takeIf { !it.isNull }?.asString()
                if (kind == null || kind !in KINDS) {
                    v += "$where kind '$kind' not in the allowlist $KINDS"
                    return@forEachIndexed
                }
                // SSO-3962 — a kind from the OTHER part is refused before any call: the message names the file's part, the
                // kind's part, and the project the declaration belongs in.
                if (part != null && part != ProvisionPart.MIXED && kind !in part.kinds) {
                    v += "$where ${crossPartRefusal(kind, part)}"
                    return@forEachIndexed
                }
                val name = r["name"]?.takeIf { !it.isNull }?.asString()
                when {
                    name.isNullOrBlank() && kind !in SINGLETON_KINDS -> v += "$where ($kind) requires a name"
                    !name.isNullOrBlank() && !NAME_PATTERN.matches(name) -> v += "$where name '$name' must match ${NAME_PATTERN.pattern}"
                }
                keys += "$kind/${name?.takeIf { it.isNotBlank() } ?: kind}"
                r["environment"]?.takeIf { !it.isNull }?.let { env ->
                    if (env.asString().isBlank()) v += "$where environment must be non-empty when present"
                    if (kind == KIND_ENVIRONMENT) v += "$where an environment resource cannot itself carry 'environment'"
                    if (kind in WORKSPACE_KINDS) v += "$where a $kind belongs to the workspace, not an environment — remove 'environment'"
                }
                val spec = r["spec"]
                if (spec == null || !spec.isObject()) {
                    v += "$where spec object is required"
                    return@forEachIndexed
                }
                spec.properties().forEach { entry ->
                    if (SECRET_KEY_PATTERN.containsMatchIn(entry.key)) {
                        v += "$where spec.${entry.key} would carry a secret value — name the env var instead: '${entry.key}Env'"
                    }
                }
                REQUIRED_SPEC.getValue(kind).forEach { req ->
                    if (isMissing(spec[req])) v += "$where ($kind) spec.$req is required"
                }
                // SSO-3113 — `grants`: an array of { subject: <member|client>:<id>, relation: manager|viewer }, no duplicates.
                r["grants"]?.takeIf { !it.isNull }?.let { grants ->
                    if (!grants.isArray()) {
                        v += "$where grants must be an array of { subject, relation }"
                    } else {
                        val seen = mutableSetOf<String>()
                        grants.toList().forEachIndexed { gi, g ->
                            val gw = "$where grants[$gi]"
                            if (!g.isObject()) { v += "$gw must be an object { subject, relation }"; return@forEachIndexed }
                            rejectUnknownKeys(g, setOf("subject", "relation"), gw, v)
                            val subject = g["subject"]?.takeIf { it.isTextual() }?.asString()?.trim()
                            val relation = g["relation"]?.takeIf { it.isTextual() }?.asString()?.trim()
                            if (subject.isNullOrEmpty()) v += "$gw subject is required (member:<sub> | client:<clientId>)"
                            else AccessRefs.validateSubject(subject)?.let { v += "$gw $it" }
                            if (relation.isNullOrEmpty()) v += "$gw relation is required (${GRANT_RELATIONS.joinToString(" | ")})"
                            // SSO-3673 — `owner` is a real platform relation, so it gets its own answer: not "unknown", but "not from a file".
                            else if (relation == AccessRefs.RELATION_OWNER) v += "$gw $GRANT_OWNER_REFUSED"
                            else if (relation !in GRANT_RELATIONS) v += "$gw relation '$relation' must be one of ${GRANT_RELATIONS.joinToString(", ")}"
                            if (subject != null && relation != null && !seen.add("$subject $relation")) v += "$gw duplicates grant '$subject $relation'"
                        }
                    }
                }
                // SSO-3668 — `publishTo`: on an application only, never on a read-only reference, each target
                // exactly { kind, repository, environment, name } with a closed kind, GitHub grammar, no duplicates.
                r[PUBLISH_TO]?.takeIf { !it.isNull }?.let { targets -> validatePublishTo(targets, kind, r, where, v) }
                // SSO-3659 — `secretSink`: on a CONFIDENTIAL application only (nothing is minted for a public client), never on
                // a read-only reference, exactly { kind: kubernetesSecret, namespace, name, key } or { kind: file, path }.
                r[SECRET_SINK]?.takeIf { !it.isNull }?.let { target -> validateSecretSink(target, kind, r, spec, where, v) }
                // SSO-3413 — `customDomain`: exactly { host, acceptReSignIn? }.
                if (kind == KIND_CUSTOM_DOMAIN) {
                    rejectUnknownKeys(spec, CUSTOM_DOMAIN_SPEC_KEYS, "$where spec", v)
                    spec["host"]?.takeIf { !it.isNull && !it.isTextual() }?.let { v += "$where (customDomain) spec.host must be a host name" }
                    spec["acceptReSignIn"]?.takeIf { !it.isNull && !it.isBoolean() }?.let { v += "$where (customDomain) spec.acceptReSignIn must be true or false" }
                }
                // SSO-4042 — `emailTemplate`: the closed record, the type enum, the locale grammar, exactly one body source, the caps.
                if (kind == KIND_EMAIL_TEMPLATE) validateEmailTemplate(spec, r, where, v)
                // SSO-4057 — `legalDocument`: the closed record, the type enum, the plain-text version / title, the format, one body source, the body rules.
                if (kind == KIND_LEGAL_DOCUMENT) validateLegalDocument(spec, r, where, v)

                // SSO-4041 — `loginTheme`: the closed record and identity's value grammar, checked before any call.
                if (kind == KIND_LOGIN_THEME) validateLoginTheme(spec, where, v)
                // SSO-3100 — `loginMethods.methods` is the FULL allow-list: a non-empty array of method tokens.
                if (kind == KIND_LOGIN_METHODS) spec["methods"]?.takeIf { it.isArray() }?.let { methods ->
                    if (methods.toList().any { !it.isTextual() || it.asString().isBlank() }) v += "$where (loginMethods) spec.methods must be a list of non-empty method names"
                }
                // SSO-3689 — how an application authenticates: the credential ladder's rungs, mirrored client-side.
                if (kind == KIND_APPLICATION) validateApplicationAuth(spec, r, where, v)
                // SSO-3766 / SSO-3767 / SSO-3770 — token exchange, authorization detail types, session lifetime.
                if (kind == KIND_APPLICATION) validateApplicationSettings(spec, where, v)
                // SSO-3856 — an application cannot declare an operator-plane (`platform:` / `admin:`) scope.
                if (kind == KIND_APPLICATION) spec["scopes"]?.takeIf { it.isArray() }?.toList()
                    ?.mapNotNull { n -> n.takeIf { it.isTextual() }?.asString()?.trim() }
                    ?.filter { isReservedOperatorPlaneScope(it) }?.distinct()
                    ?.forEach { v += "$where spec.scopes: $ERR_RESERVED_SCOPE — '$it' is an operator-plane scope; a provisioning file cannot grant it (the hub refuses it). A platform: scope is declared in .thoryn/platform-scopes.yaml and applied by an operator with `thoryn operator platform-scopes apply`" }
                // SSO-3689 — a workload-identity trust: the provider's pins, the scope grammar, the production rules.
                if (kind == KIND_WORKLOAD_IDENTITY_TRUST) validateWorkloadIdentityTrust(spec, r, where, v)
                // SSO-3941 — a role: its permission strings; an application's claims-in-token toggle.
                if (kind == KIND_ROLE) validateRole(spec, r, where, v)
                if (kind == KIND_APPLICATION) spec[SPEC_TOKEN_CLAIMS]?.takeIf { !it.isNull }?.let { validateTokenClaims(it, where, v) }
            }
            keys.groupBy { it }.filterValues { it.size > 1 }.keys.forEach { v += "duplicate resource '$it' — kind + name must be unique" }
            validateWorkloadPullTrusts(resources.toList(), v)
            validateEmailTemplateCells(resources.toList(), v)
            validateLegalDocumentCells(resources.toList(), v)
            return v
        }

        /**
         * SSO-3921 — the cross-resource rules of a `secretSink: { kind: workloadPull, trust }` whose trust is DECLARED in the
         * same file (a trust that is only live is checked by the plan, against its live view): it lives on the application's
         * plane ([ERR_WORKLOAD_PULL_TRUST_OTHER_PLANE] — the hub replaces an in-flight secret only for a workload client of the
         * application's own environment, and product-api resolves the rotation in that plane), it is a `kubernetes` trust
         * ([ERR_WORKLOAD_PULL_TRUST_PROVIDER] — rung 3 is a pod minting its own; a CI job pulling a secret is the courier
         * again), and its scopes carry [ROTATE_SECRET_SCOPE] ([ERR_WORKLOAD_PULL_SCOPE_MISSING]).
         */
        private fun validateWorkloadPullTrusts(resources: List<JsonNode>, v: MutableList<String>) {
            fun env(n: JsonNode): String? = n["environment"]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            fun plane(e: String?): String = e?.let { "environment '$it'" } ?: "the production plane"
            resources.forEachIndexed { i, r ->
                if (!r.isObject() || r["kind"]?.takeIf { it.isTextual() }?.asString() != KIND_APPLICATION) return@forEachIndexed
                val sink = r[SECRET_SINK]?.takeIf { it.isObject() } ?: return@forEachIndexed
                if (sink["kind"]?.takeIf { it.isTextual() }?.asString()?.trim() != SECRET_SINK_KIND_WORKLOAD_PULL) return@forEachIndexed
                val name = sink["trust"]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() } ?: return@forEachIndexed
                val trust = resources.firstOrNull { t ->
                    t.isObject() && t["kind"]?.takeIf { it.isTextual() }?.asString() == KIND_WORKLOAD_IDENTITY_TRUST && t["name"]?.takeIf { it.isTextual() }?.asString() == name
                } ?: return@forEachIndexed
                val where = "resources[$i] $SECRET_SINK"
                if (env(trust) != env(r)) {
                    v += "$where: $ERR_WORKLOAD_PULL_TRUST_OTHER_PLANE — trust '$name' is declared for ${plane(env(trust))} while the application lives in ${plane(env(r))}; " +
                        "the workload that pulls the secret must be a trust of the application's OWN environment"
                }
                val spec = trust["spec"]?.takeIf { it.isObject() } ?: return@forEachIndexed
                val provider = spec["provider"]?.takeIf { it.isTextual() }?.asString()?.trim()
                if (provider != null && provider != WORKLOAD_PULL_PROVIDER) {
                    v += "$where: $ERR_WORKLOAD_PULL_TRUST_PROVIDER — trust '$name' is a '$provider' trust; a runtime pull is a POD minting its own secret at start " +
                        "(provider: $WORKLOAD_PULL_PROVIDER). A CI job that fetches a secret to hand on is the courier the credential ladder rules out"
                }
                val scopes = spec[TRUST_SCOPES]?.takeIf { it.isArray() }?.toList()?.mapNotNull { s -> s.takeIf { it.isTextual() }?.asString()?.trim() }.orEmpty()
                if (ROTATE_SECRET_SCOPE !in scopes) {
                    v += "$where: $ERR_WORKLOAD_PULL_SCOPE_MISSING — trust '$name' must carry $ROTATE_SECRET_SCOPE in spec.$TRUST_SCOPES: " +
                        "its pods mint the secret with `thoryn clients rotate-secret`, which product-api refuses without one"
                }
            }
        }

        /**
         * SSO-3668 — the `publishTo:` rules the schema also pins: only an `application` has an output to
         * publish (its clientId); a `readOnly` reference publishes nothing (the owning repository does); a
         * target is exactly `{ kind, repository, environment, name }` with a closed `kind`, an `owner/name`
         * repository, a non-empty GitHub environment name and an `[A-Z_][A-Z0-9_]*` variable name outside
         * GitHub's reserved `GITHUB_` prefix; no two targets name the same variable.
         */
        private fun validatePublishTo(targets: JsonNode, kind: String, r: JsonNode, where: String, v: MutableList<String>) {
            if (kind !in PUBLISHABLE_KINDS) {
                v += "$where $PUBLISH_TO is only supported on kind ${PUBLISHABLE_KINDS.joinToString(" | ")} — an application's clientId is the one output a resource publishes"
            }
            if (r[READ_ONLY]?.takeIf { it.isBoolean() }?.asBoolean() == true) {
                v += "$where a read-only reference cannot carry '$PUBLISH_TO' — it publishes nothing; the repository that owns the resource publishes its id"
            }
            if (!targets.isArray()) {
                v += "$where $PUBLISH_TO must be an array of { kind, repository, environment, name }"
                return
            }
            if (targets.isEmpty()) v += "$where $PUBLISH_TO must name at least one target (or be omitted)"
            val seen = mutableSetOf<String>()
            targets.toList().forEachIndexed { ti, t ->
                val tw = "$where $PUBLISH_TO[$ti]"
                if (!t.isObject()) { v += "$tw must be an object { kind, repository, environment, name }"; return@forEachIndexed }
                rejectUnknownKeys(t, PUBLISH_TARGET_KEYS, tw, v)
                fun text(field: String): String? = t[field]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
                val tKind = text("kind")
                val repository = text("repository")
                val environment = text("environment")
                val name = text("name")
                when {
                    tKind == null -> v += "$tw kind is required (${PUBLISH_KINDS.joinToString(" | ")})"
                    tKind !in PUBLISH_KINDS -> v += "$tw kind '$tKind' must be one of ${PUBLISH_KINDS.joinToString(", ")}"
                }
                when {
                    repository == null -> v += "$tw repository is required (owner/name)"
                    !REPOSITORY_PATTERN.matches(repository) -> v += "$tw repository '$repository' must be a GitHub owner/name (${REPOSITORY_PATTERN.pattern})"
                }
                if (environment == null) v += "$tw environment is required (the target repository's GitHub environment, e.g. production)"
                when {
                    name == null -> v += "$tw name is required (the Actions variable, e.g. THORYN_PRODUCTION_CLIENT_ID)"
                    !VARIABLE_NAME_PATTERN.matches(name) -> v += "$tw name '$name' must be an Actions variable name (${VARIABLE_NAME_PATTERN.pattern})"
                    name.startsWith(RESERVED_VARIABLE_PREFIX) -> v += "$tw name '$name' is reserved — GitHub refuses variables starting with $RESERVED_VARIABLE_PREFIX"
                }
                if (tKind != null && repository != null && environment != null && name != null && !seen.add("$tKind $repository $environment $name")) {
                    v += "$tw duplicates target '$tKind $repository (environment $environment) $name'"
                }
            }
        }

        /**
         * SSO-3659 — the `secretSink:` rules the schema also pins: only an `application` is minted a secret, and only a
         * confidential one (`clientType: public` has nothing to deliver); a `readOnly` reference is minted nothing (the
         * owning repository delivers); the target is exactly `{ kind: kubernetesSecret, namespace, name, key }` with the
         * Kubernetes name grammars (namespace: DNS label; name: DNS subdomain; key: `[-._a-zA-Z0-9]+`) or
         * `{ kind: file, path }` with a non-empty path.
         */
        private fun validateSecretSink(target: JsonNode, kind: String, r: JsonNode, spec: JsonNode, where: String, v: MutableList<String>) {
            if (kind !in SECRET_SINK_KINDS_ALLOWED_ON) {
                v += "$where $SECRET_SINK is only supported on kind ${SECRET_SINK_KINDS_ALLOWED_ON.joinToString(" | ")} — only a confidential application is minted a secret"
            } else if (spec["clientType"]?.takeIf { it.isTextual() }?.asString()?.trim().equals(CLIENT_TYPE_PUBLIC, ignoreCase = true)) {
                v += "$where $SECRET_SINK on a public client — a public client (clientType: $CLIENT_TYPE_PUBLIC) is minted no secret, so there is nothing to deliver"
            }
            if (r[READ_ONLY]?.takeIf { it.isBoolean() }?.asBoolean() == true) {
                v += "$where a read-only reference cannot carry '$SECRET_SINK' — nothing is minted for it; the repository that owns the application delivers its secret"
            }
            if (!target.isObject()) {
                v += "$where $SECRET_SINK must be an object { kind: $SECRET_SINK_KIND_CUSTOMER_MANAGED }, { kind: $SECRET_SINK_KIND_KUBERNETES_SECRET, namespace, name, key }, { kind: $SECRET_SINK_KIND_FILE, path } or { kind: $SECRET_SINK_KIND_WORKLOAD_PULL, trust }"
                return
            }
            fun text(field: String): String? = target[field]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            val tw = "$where $SECRET_SINK"
            when (val tKind = text("kind")) {
                null -> v += "$tw kind is required (${SECRET_SINK_KINDS.joinToString(" | ")})"
                SECRET_SINK_KIND_KUBERNETES_SECRET -> {
                    rejectUnknownKeys(target, SECRET_SINK_KUBERNETES_KEYS, tw, v)
                    val namespace = text("namespace")
                    val name = text("name")
                    val key = text("key")
                    when {
                        namespace == null -> v += "$tw namespace is required (an EXISTING Kubernetes namespace — thoryn never creates one)"
                        !K8S_NAMESPACE_PATTERN.matches(namespace) -> v += "$tw namespace '$namespace' must be a Kubernetes namespace name (${K8S_NAMESPACE_PATTERN.pattern})"
                    }
                    when {
                        name == null -> v += "$tw name is required (the Kubernetes Secret to write)"
                        name.length > K8S_SECRET_NAME_MAX || !K8S_SECRET_NAME_PATTERN.matches(name) -> v += "$tw name '$name' must be a Kubernetes Secret name (RFC 1123 subdomain, ≤ $K8S_SECRET_NAME_MAX)"
                    }
                    when {
                        key == null -> v += "$tw key is required (the Secret's data key, e.g. client-secret)"
                        key.length > K8S_SECRET_KEY_MAX || !K8S_SECRET_KEY_PATTERN.matches(key) -> v += "$tw key '$key' must be a Secret data key (${K8S_SECRET_KEY_PATTERN.pattern}, ≤ $K8S_SECRET_KEY_MAX)"
                    }
                }
                SECRET_SINK_KIND_FILE -> {
                    rejectUnknownKeys(target, SECRET_SINK_FILE_KEYS, tw, v)
                    if (text("path") == null) v += "$tw path is required (the owner-only file the secret is written to)"
                }
                // SSO-3954 — `customerManaged` is the kind alone: there is nowhere to name, a person delivers.
                SECRET_SINK_KIND_CUSTOMER_MANAGED -> rejectUnknownKeys(target, SECRET_SINK_CUSTOMER_MANAGED_KEYS, tw, v)
                SECRET_SINK_KIND_WORKLOAD_PULL -> {
                    rejectUnknownKeys(target, SECRET_SINK_WORKLOAD_PULL_KEYS, tw, v)
                    val trust = text("trust")
                    when {
                        trust == null -> v += "$tw trust is required (the NAME of the $PROVIDER_KUBERNETES $KIND_WORKLOAD_IDENTITY_TRUST whose pods mint the secret at start)"
                        !NAME_PATTERN.matches(trust) -> v += "$tw trust '$trust' must be the NAME of a $KIND_WORKLOAD_IDENTITY_TRUST (${NAME_PATTERN.pattern})"
                    }
                }
                else -> v += "$tw kind '$tKind' must be one of ${SECRET_SINK_KINDS.joinToString(", ")}"
            }
        }

        /**
         * SSO-3689 (ADR 2026-10-14 credential ladder; ADR 2026-10-14 federated client authentication §6 / §11) — the
         * client-authentication rules the schema also pins, with the HUB's own codes so a file is refused with the
         * vocabulary the API would answer: the closed method allowlist (`client_secret_post` is not declarable — the
         * courier rung); `jwksUri` XOR `jwks`, REQUIRED for `private_key_jwt`; a `federated_assertion` client is that
         * method alone, never `clientType: public`, only `authorization_code` / `refresh_token`, PKCE kept, no key, no
         * secret, and names its `federatedTrust`; `federatedTrust` without the method is refused; a `secretSink:` is
         * legal only when a secret-bearing method is among the declared ones. An inline `jwks` holds PUBLIC keys only.
         */
        private fun validateApplicationAuth(spec: JsonNode, r: JsonNode, where: String, v: MutableList<String>) {
            val methodsNode = spec[SPEC_CLIENT_AUTHENTICATION_METHODS]?.takeIf { !it.isNull }
            var methods: List<String>? = null
            if (methodsNode != null) {
                if (!methodsNode.isArray() || methodsNode.isEmpty()) {
                    v += "$where spec.$SPEC_CLIENT_AUTHENTICATION_METHODS must be a non-empty list of ${CLIENT_AUTHENTICATION_METHODS.joinToString(" | ")}"
                } else {
                    val raw = methodsNode.toList().map { if (it.isTextual()) it.asString().trim() else it.toString() }
                    raw.filter { it !in CLIENT_AUTHENTICATION_METHODS }.distinct().forEach { m ->
                        v += if (m == METHOD_CLIENT_SECRET_POST) {
                            "$where spec.$SPEC_CLIENT_AUTHENTICATION_METHODS: $ERR_INVALID_CLIENT_AUTHENTICATION_METHOD — '$METHOD_CLIENT_SECRET_POST' is not declarable: a secret in the request body is the courier rung of the credential ladder; use $METHOD_CLIENT_SECRET_BASIC (or climb to $METHOD_PRIVATE_KEY_JWT / $METHOD_FEDERATED_ASSERTION)"
                        } else {
                            "$where spec.$SPEC_CLIENT_AUTHENTICATION_METHODS: $ERR_INVALID_CLIENT_AUTHENTICATION_METHOD — '$m' must be one of ${CLIENT_AUTHENTICATION_METHODS.joinToString(", ")}"
                        }
                    }
                    if (raw.size != raw.distinct().size) v += "$where spec.$SPEC_CLIENT_AUTHENTICATION_METHODS lists a method twice"
                    methods = raw.filter { it in CLIENT_AUTHENTICATION_METHODS }
                    if (METHOD_NONE in methods && methods.size > 1) v += "$where spec.$SPEC_CLIENT_AUTHENTICATION_METHODS: $ERR_INCOHERENT_CLIENT_AUTHENTICATION_METHODS — a public client ('$METHOD_NONE') combines with no other method"
                }
            }
            val jwksUri = spec[SPEC_JWKS_URI]?.takeIf { !it.isNull }
            val jwks = spec[SPEC_JWKS]?.takeIf { !it.isNull }
            if (jwksUri != null && (!jwksUri.isTextual() || !jwksUri.asString().trim().startsWith("https://"))) {
                v += "$where spec.$SPEC_JWKS_URI must be an https:// URL (where the client's PUBLIC keys are fetched)"
            }
            if (jwks != null) validateJwks(jwks, "$where spec.$SPEC_JWKS", ERR_INVALID_JWKS, v)
            if (jwksUri != null && jwks != null) v += "$where $ERR_JWKS_XOR_JWKS_URI — give exactly one of spec.$SPEC_JWKS_URI and spec.$SPEC_JWKS"
            val hasKey = jwksUri != null || jwks != null
            val trust = spec[SPEC_FEDERATED_TRUST]?.takeIf { !it.isNull }
            val trustName = trust?.takeIf { it.isTextual() }?.asString()?.trim()
            if (trust != null && (trustName.isNullOrEmpty() || !NAME_PATTERN.matches(trustName))) {
                v += "$where spec.$SPEC_FEDERATED_TRUST must be the NAME of a $KIND_WORKLOAD_IDENTITY_TRUST resource (${NAME_PATTERN.pattern}) — the engine resolves it to the trust id"
            }
            val federated = methods?.contains(METHOD_FEDERATED_ASSERTION) == true
            if (methods != null && METHOD_PRIVATE_KEY_JWT in methods && !hasKey) {
                v += "$where $ERR_PRIVATE_KEY_JWT_KEY_REQUIRED — $METHOD_PRIVATE_KEY_JWT needs the client's PUBLIC key: spec.$SPEC_JWKS_URI or spec.$SPEC_JWKS"
            }
            if (trust != null && !federated) {
                v += "$where $ERR_FEDERATED_TRUST_WITHOUT_METHOD — spec.$SPEC_FEDERATED_TRUST is only valid when spec.$SPEC_CLIENT_AUTHENTICATION_METHODS is ['$METHOD_FEDERATED_ASSERTION']"
            }
            val sink = r[SECRET_SINK]?.takeIf { !it.isNull }
            if (sink != null && methods != null && methods.none { it in SECRET_BEARING_METHODS }) {
                v += "$where $ERR_SECRET_SINK_WITHOUT_SECRET — a $SECRET_SINK delivers a Thoryn-minted secret, and none exists for ${methods.joinToString(", ")}; drop the sink or declare $METHOD_CLIENT_SECRET_BASIC"
            }
            if (!federated) return
            if (methods!!.size != 1) {
                v += "$where $ERR_FEDERATED_ONLY_METHOD — spec.$SPEC_CLIENT_AUTHENTICATION_METHODS must be exactly ['$METHOD_FEDERATED_ASSERTION'] for a federated login client"
            }
            if (spec[SPEC_CLIENT_TYPE]?.takeIf { it.isTextual() }?.asString()?.trim().equals(CLIENT_TYPE_PUBLIC, ignoreCase = true)) {
                v += "$where $ERR_FEDERATED_ONLY_METHOD — a public client (clientType: $CLIENT_TYPE_PUBLIC) authenticates with '$METHOD_NONE'; a federated login client is confidential — its platform token is the credential"
            }
            // SSO-3767 (oauthy 2026-10-16 amendment of decision 2) — plus the token-exchange grant when `allowTokenExchange: true`.
            val exchanging = spec[SPEC_ALLOW_TOKEN_EXCHANGE]?.takeIf { it.isBoolean() }?.asBoolean() == true
            val allowedGrants = if (exchanging) FEDERATED_GRANT_TYPES + GRANT_TOKEN_EXCHANGE else FEDERATED_GRANT_TYPES
            spec[SPEC_GRANT_TYPES]?.takeIf { it.isArray() }?.toList()?.map { it.asString().trim() }?.filter { it.isNotEmpty() && it !in allowedGrants }?.takeIf { it.isNotEmpty() }?.let { bad ->
                v += if (bad == listOf(GRANT_TOKEN_EXCHANGE)) {
                    "$where $ERR_FEDERATED_GRANT_NOT_ALLOWED — a federated login client registers the token-exchange grant only together with $SPEC_ALLOW_TOKEN_EXCHANGE: true; declare both, or drop the grant"
                } else {
                    "$where $ERR_FEDERATED_GRANT_NOT_ALLOWED — a federated login client may register only ${allowedGrants.joinToString(", ")} (not ${bad.joinToString(", ")}); for client_credentials use the trust's own wi_ workload client"
                }
            }
            if (spec[SPEC_REQUIRE_PROOF_KEY]?.takeIf { it.isBoolean() }?.asBoolean() == false) {
                v += "$where $ERR_FEDERATED_PKCE_REQUIRED — $SPEC_REQUIRE_PROOF_KEY cannot be false for a federated login client; PKCE (RFC 7636) stays mandatory"
            }
            if (hasKey) v += "$where $ERR_FEDERATED_NO_SECRET_OR_KEY — a federated login client registers no $SPEC_JWKS / $SPEC_JWKS_URI; its platform token is the credential"
            if (trust == null) v += "$where $ERR_FEDERATED_TRUST_REQUIRED — spec.$SPEC_FEDERATED_TRUST (the NAME of a $KIND_WORKLOAD_IDENTITY_TRUST in the same environment) is required for a federated login client"
        }

        /**
         * SSO-3766 / SSO-3767 / SSO-3770 — the application settings the schema also pins, with product-api's own codes (the
         * ones a file alone can decide; the rest are the API's, mapped at apply):
         *  - `allowTokenExchange` (boolean): when `true`, the client authenticates (never `clientType: public` / method
         *    `none` — [ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT]) and declares the token-exchange grant in `grantTypes`
         *    ([ERR_TOKEN_EXCHANGE_GRANT_REQUIRED]). WHO may turn it on (`manager` on the environment) is the plan gate's.
         *  - `allowedAuthorizationDetailTypes` (list): distinct, one type per entry; `[]` is legal (it clears). Which types
         *    are SUPPORTED, and `thoryn_access_grant`'s home-workspace rule, are the server's.
         *  - `refreshTokenSlidingWindow` (boolean) / `refreshTokenAbsoluteMaxTtlSeconds` (integer 3 600 – 7 776 000,
         *    [ERR_TOKEN_TTL_OUT_OF_RANGE]): the absolute lifetime is declared WITH `refreshTokenSlidingWindow: true`
         *    ([ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW] — a file says what the session is, it does not lean on the live
         *    window) and is at least a declared `refreshTokenTtlSeconds` ([ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL]).
         *  - SSO-3810 `allowTokenIntrospection` (boolean): when `true`, the client authenticates
         *    ([ERR_TOKEN_INTROSPECTION_REQUIRES_CONFIDENTIAL_CLIENT]). WHO may turn it on (`manager` on the environment) is
         *    the plan gate's.
         *  - SSO-3807 `accessTokenFormat`: exactly `self-contained` or `reference` ([ERR_INVALID_ACCESS_TOKEN_FORMAT]).
         */
        private fun validateApplicationSettings(spec: JsonNode, where: String, v: MutableList<String>) {
            fun present(field: String): JsonNode? = spec[field]?.takeIf { !it.isNull }
            listOf(SPEC_ALLOW_TOKEN_EXCHANGE, SPEC_REFRESH_TOKEN_SLIDING_WINDOW, SPEC_ALLOW_TOKEN_INTROSPECTION, SPEC_DPOP_ALLOWED, SPEC_DPOP_REQUIRED).forEach { f ->
                present(f)?.takeIf { !it.isBoolean() }?.let { v += "$where spec.$f must be true or false" }
            }
            present(SPEC_ACCESS_TOKEN_FORMAT)?.let { f ->
                if (!f.isTextual() || f.asString() !in ACCESS_TOKEN_FORMATS) {
                    v += "$where spec.$SPEC_ACCESS_TOKEN_FORMAT: $ERR_INVALID_ACCESS_TOKEN_FORMAT — must be ${ACCESS_TOKEN_FORMATS.joinToString(" or ") { "'$it'" }}"
                }
            }
            val publicClient = spec[SPEC_CLIENT_TYPE]?.takeIf { it.isTextual() }?.asString()?.trim().equals(CLIENT_TYPE_PUBLIC, ignoreCase = true) ||
                present(SPEC_CLIENT_AUTHENTICATION_METHODS)?.takeIf { it.isArray() }?.toList()?.any { it.asString().trim() == METHOD_NONE } == true
            if (present(SPEC_ALLOW_TOKEN_INTROSPECTION)?.takeIf { it.isBoolean() }?.asBoolean() == true && publicClient) {
                v += "$where $ERR_TOKEN_INTROSPECTION_REQUIRES_CONFIDENTIAL_CLIENT — $SPEC_ALLOW_TOKEN_INTROSPECTION: true needs a client that authenticates ($METHOD_CLIENT_SECRET_BASIC, $METHOD_PRIVATE_KEY_JWT or $METHOD_FEDERATED_ASSERTION); a public client ('$METHOD_NONE') cannot hold it"
            }
            present(SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES)?.let { types ->
                if (!types.isArray()) {
                    v += "$where spec.$SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES must be a list of RFC 9396 types ([] clears it; omit it to keep the live list)"
                } else {
                    val raw = types.toList()
                    raw.forEachIndexed { i, t ->
                        if (!t.isTextual() || !AUTHORIZATION_DETAILS_TYPE_PATTERN.matches(t.asString())) {
                            v += "$where spec.$SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES[$i] must be ONE authorization-details type (a non-empty name without spaces, e.g. openid_credential)"
                        }
                    }
                    val names = raw.filter { it.isTextual() }.map { it.asString() }
                    if (names.size != names.distinct().size) v += "$where spec.$SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES lists a type twice"
                }
            }
            val sliding = present(SPEC_REFRESH_TOKEN_SLIDING_WINDOW)?.takeIf { it.isBoolean() }?.asBoolean()
            present(SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS)?.let { abs ->
                if (!abs.isIntegralNumber()) {
                    v += "$where spec.$SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS must be a whole number of seconds"
                    return@let
                }
                val seconds = abs.asLong()
                if (seconds !in ABSOLUTE_SESSION_MIN_SECONDS..ABSOLUTE_SESSION_MAX_SECONDS) {
                    v += "$where spec.$SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS: $ERR_TOKEN_TTL_OUT_OF_RANGE — $seconds is outside $ABSOLUTE_SESSION_MIN_SECONDS – $ABSOLUTE_SESSION_MAX_SECONDS (1 h – 90 d)"
                }
                if (sliding != true) {
                    v += "$where $ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW — spec.$SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS applies only with spec.$SPEC_REFRESH_TOKEN_SLIDING_WINDOW: true; declare the window with it"
                }
                present(SPEC_REFRESH_TOKEN_TTL_SECONDS)?.takeIf { it.isIntegralNumber() }?.asLong()?.takeIf { seconds < it }?.let { ttl ->
                    v += "$where $ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL — spec.$SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS ($seconds) is shorter than spec.$SPEC_REFRESH_TOKEN_TTL_SECONDS ($ttl): the first refresh token would outlive the session"
                }
            }
            if (present(SPEC_ALLOW_TOKEN_EXCHANGE)?.takeIf { it.isBoolean() }?.asBoolean() != true) return
            val methods = present(SPEC_CLIENT_AUTHENTICATION_METHODS)?.takeIf { it.isArray() }?.toList()?.map { it.asString().trim() }
            val public = spec[SPEC_CLIENT_TYPE]?.takeIf { it.isTextual() }?.asString()?.trim().equals(CLIENT_TYPE_PUBLIC, ignoreCase = true)
            if (public || methods?.contains(METHOD_NONE) == true) {
                v += "$where $ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT — $SPEC_ALLOW_TOKEN_EXCHANGE: true needs a client that authenticates ($METHOD_CLIENT_SECRET_BASIC, $METHOD_PRIVATE_KEY_JWT or $METHOD_FEDERATED_ASSERTION); a public client ('$METHOD_NONE') cannot hold it"
            }
            val grants = present(SPEC_GRANT_TYPES)?.takeIf { it.isArray() }?.toList()?.map { it.asString().trim() }
            if (grants == null || GRANT_TOKEN_EXCHANGE !in grants) {
                v += "$where $ERR_TOKEN_EXCHANGE_GRANT_REQUIRED — $SPEC_ALLOW_TOKEN_EXCHANGE: true needs '$GRANT_TOKEN_EXCHANGE' among spec.$SPEC_GRANT_TYPES"
            }
        }

        /**
         * SSO-3689 — an inline JWK Set is PUBLIC key material only: `{ keys: [ … ] }`, each key an RSA / EC public key
         * with a `kid` and NO private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`). A private key in a
         * provisioning file is a secret in the repository — exactly what the file exists to make impossible.
         */
        fun validateJwks(jwks: JsonNode, where: String, code: String, v: MutableList<String>) {
            val keys = jwks.takeIf { it.isObject() }?.get("keys")
            if (keys == null || !keys.isArray() || keys.isEmpty()) {
                v += "$where: $code — must be a JWK Set object { keys: [ … ] } with at least one PUBLIC key"
                return
            }
            keys.toList().forEachIndexed { i, k ->
                val kw = "$where.keys[$i]"
                if (!k.isObject()) { v += "$kw: $code — a key must be a JWK object"; return@forEachIndexed }
                val kty = k["kty"]?.takeIf { it.isTextual() }?.asString()
                if (kty == null || kty !in JWK_KEY_TYPES) v += "$kw: $code — kty must be one of ${JWK_KEY_TYPES.joinToString(", ")} (was '${kty ?: ""}')"
                if (k["kid"]?.takeIf { it.isTextual() }?.asString()?.isNotBlank() != true) v += "$kw: $code — every key needs a kid"
                k.properties().map { it.key }.filter { it in JWK_PRIVATE_MEMBERS }.takeIf { it.isNotEmpty() }?.let { priv ->
                    v += "$kw: $code — carries PRIVATE key material (${priv.joinToString(", ")}); a provisioning file holds public keys only — strip the private members"
                }
                when (kty) {
                    "RSA" -> if (k["n"]?.isTextual() != true || k["e"]?.isTextual() != true) v += "$kw: $code — an RSA public key needs n and e"
                    "EC" -> if (k["crv"]?.isTextual() != true || k["x"]?.isTextual() != true || k["y"]?.isTextual() != true) v += "$kw: $code — an EC public key needs crv, x and y"
                }
            }
        }

        /**
         * SSO-3689 — the trust rules the schema also pins, with the trust service's codes: a closed `provider`, exactly
         * that provider's pin block, `tenant:` scopes only (a CEILING the hub caps at the applying identity's own —
         * `scope_not_grantable` at apply), and the production rules (`confirmProduction: true`; GitHub pins an
         * environment, Forgejo a ref, Kubernetes a namespace + service account). A trust has no access object of its
         * own (it is the environment's), so it carries no `grants:`.
         */
        private fun validateWorkloadIdentityTrust(spec: JsonNode, r: JsonNode, where: String, v: MutableList<String>) {
            rejectUnknownKeys(spec, TRUST_SPEC_KEYS, "$where spec", v)
            if (r["grants"]?.takeIf { !it.isNull } != null) v += "$where a $KIND_WORKLOAD_IDENTITY_TRUST's grants are not converged from a file — it cannot carry 'grants' (SSO-3774: its `owner` is a workspace admin's grant, `thoryn access grant <subject> owner trust:<id>`; manager / viewer are delegated with `thoryn access grant`)"
            val provider = spec["provider"]?.takeIf { it.isTextual() }?.asString()?.trim()
            if (provider != null && provider !in TRUST_PROVIDERS) v += "$where spec.provider: $ERR_UNSUPPORTED_PROVIDER — '$provider' must be one of ${TRUST_PROVIDERS.joinToString(", ")}"
            spec[TRUST_SCOPES]?.takeIf { it.isArray() }?.toList()?.let { scopes ->
                val raw = scopes.map { if (it.isTextual()) it.asString().trim() else it.toString() }
                raw.filter { !TENANT_SCOPE_PATTERN.matches(it) }.distinct().forEach { v += "$where spec.$TRUST_SCOPES: $ERR_INVALID_SCOPE — '$it' is not a workspace scope (tenant:<area>.<action>); a trust can carry only tenant: scopes" }
                if (raw.size != raw.distinct().size) v += "$where spec.$TRUST_SCOPES lists a scope twice"
            }
            spec[TRUST_CONFIRM_PRODUCTION]?.takeIf { !it.isNull && !it.isBoolean() }?.let { v += "$where spec.$TRUST_CONFIRM_PRODUCTION must be true or false" }
            val production = isProductionPlane(r["environment"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() })
            if (production && spec[TRUST_CONFIRM_PRODUCTION]?.takeIf { it.isBoolean() }?.asBoolean() != true) {
                v += "$where $ERR_PRODUCTION_CONFIRMATION_REQUIRED — this trust is on the PRODUCTION plane (its jobs / pods act on production); declare spec.$TRUST_CONFIRM_PRODUCTION: true"
            }
            if (provider == null || provider !in TRUST_PROVIDERS) return
            val block = TRUST_PIN_BLOCKS.getValue(provider)
            TRUST_PIN_BLOCKS.values.filter { it != block && spec[it]?.takeIf { n -> !n.isNull } != null }.forEach { other ->
                v += "$where spec.$other does not belong to provider '$provider' — only spec.$block does"
            }
            // SSO-3702 — the plan profile: github_actions only, keyed on a DIFFERENT GitHub environment, read-only scopes
            // that are a subset of spec.scopes (omitted ⇒ derived by the hub from the .read members of spec.scopes).
            spec[TRUST_PLAN]?.takeIf { !it.isNull }?.let { plan ->
                val pw = "$where spec.$TRUST_PLAN"
                if (provider != PROVIDER_GITHUB_ACTIONS) {
                    v += "$where $ERR_PLAN_PROFILE_UNSUPPORTED — only a github_actions trust carries a plan profile (the job's GitHub environment claim selects it); a '$provider' trust has none"
                    return@let
                }
                if (!plan.isObject()) {
                    v += "$pw must be an object { environment, scopes? }"
                    return@let
                }
                rejectUnknownKeys(plan, TRUST_PLAN_KEYS, pw, v)
                val environment = plan["environment"]?.takeIf { !it.isNull }
                when {
                    environment == null -> v += "$where $ERR_PLAN_PROFILE_REQUIRES_ENVIRONMENT — spec.$TRUST_PLAN.environment (the GitHub environment the plan jobs run in) is required"
                    !environment.isTextual() || environment.asString().isBlank() -> v += "$where $ERR_INVALID_PLAN_ENVIRONMENT — spec.$TRUST_PLAN.environment must be a non-empty GitHub environment name"
                    environment.asString().trim() == spec[block]?.get("environment")?.takeIf { it.isTextual() }?.asString()?.trim() ->
                        v += "$where $ERR_PLAN_ENVIRONMENT_EQUALS_APPLY — spec.$TRUST_PLAN.environment '${environment.asString().trim()}' must differ from spec.$block.environment: the GitHub environment is what separates \"may read\" from \"may write\""
                }
                plan[TRUST_SCOPES]?.takeIf { !it.isNull }?.let { scopes ->
                    if (!scopes.isArray()) {
                        v += "$pw.$TRUST_SCOPES must be an array of tenant:<area>.read scopes"
                        return@let
                    }
                    val raw = scopes.toList().map { if (it.isTextual()) it.asString().trim() else it.toString() }
                    if (raw.isEmpty()) v += "$where $ERR_PLAN_SCOPES_EMPTY — spec.$TRUST_PLAN.$TRUST_SCOPES must list at least one scope, or be omitted to derive the .read members of spec.$TRUST_SCOPES"
                    raw.filter { !READ_SCOPE_PATTERN.matches(it) }.distinct().forEach { v += "$where $ERR_PLAN_SCOPE_NOT_READ_ONLY — '$it' is not a tenant:<area>.read scope; a plan profile is read-only by construction" }
                    val apply = spec[TRUST_SCOPES]?.takeIf { it.isArray() }?.toList()?.map { if (it.isTextual()) it.asString().trim() else it.toString() }.orEmpty()
                    raw.filter { READ_SCOPE_PATTERN.matches(it) && it !in apply }.distinct().forEach { v += "$where $ERR_PLAN_SCOPE_NOT_SUBSET — plan scope '$it' is not among spec.$TRUST_SCOPES" }
                    if (raw.size != raw.distinct().size) v += "$pw.$TRUST_SCOPES lists a scope twice"
                }
            }
            val pins = spec[block]?.takeIf { !it.isNull }
            if (pins == null || !pins.isObject()) {
                v += "$where spec.$block is required for provider '$provider' (the provider's pins)"
                return
            }
            val pw = "$where spec.$block"
            fun text(field: String): String? = pins[field]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            fun integral(field: String): Boolean? = pins[field]?.takeIf { !it.isNull }?.let { it.isIntegralNumber && it.asLong() > 0 }
            when (provider) {
                PROVIDER_GITHUB_ACTIONS -> {
                    rejectUnknownKeys(pins, GITHUB_PIN_KEYS, pw, v)
                    val repository = text("repository")
                    when {
                        repository == null -> v += "$pw.repository is required (owner/name)"
                        !REPOSITORY_PATTERN.matches(repository) -> v += "$pw.repository '$repository' must be a GitHub owner/name"
                    }
                    val ownerId = integral("ownerId"); val repositoryId = integral("repositoryId")
                    if (ownerId == false || repositoryId == false) v += "$pw: $ERR_INVALID_GITHUB_IDS — ownerId and repositoryId are GitHub's positive integer ids"
                    if ((ownerId == null) != (repositoryId == null)) v += "$pw: $ERR_INVALID_GITHUB_IDS — ownerId and repositoryId go together: give both (a private repository), or neither (looked up once for a public one)"
                    pins["environment"]?.takeIf { !it.isNull && (!it.isTextual() || it.asString().isBlank()) }?.let { v += "$pw.environment must be a non-empty GitHub environment name" }
                    text("ref")?.let { if (!GIT_REF_PATTERN.matches(it)) v += "$pw.ref '$it' must be a full ref, e.g. refs/heads/main" }
                    pins["githubHostedRunnersOnly"]?.takeIf { !it.isNull && !it.isBoolean() }?.let { v += "$pw.githubHostedRunnersOnly must be true or false" }
                    if (production && text("environment") == null) v += "$where $ERR_PRODUCTION_REQUIRES_ENVIRONMENT — a production trust must pin a GitHub environment (spec.$block.environment), the one with the reviewers"
                }
                PROVIDER_FORGEJO -> {
                    rejectUnknownKeys(pins, FORGEJO_PIN_KEYS, pw, v)
                    val instance = text("instanceUrl")
                    when {
                        instance == null -> v += "$pw.instanceUrl is required (the Forgejo instance origin, https://host)"
                        !FORGEJO_INSTANCE_PATTERN.matches(instance) -> v += "$pw: $ERR_INVALID_FORGEJO_INSTANCE — instanceUrl '$instance' must be an https origin with no path"
                    }
                    if (text("owner") == null) v += "$pw.owner is required"
                    if (text("repository") == null) v += "$pw.repository is required"
                    if (integral("ownerId") != true || integral("repositoryId") != true) v += "$pw: $ERR_INVALID_FORGEJO_IDS — ownerId and repositoryId (the instance's immutable ids, GET /api/v1/repos/{owner}/{repo}) are required positive integers"
                    text("ref")?.let { if (!GIT_REF_PATTERN.matches(it)) v += "$pw.ref '$it' must be a full ref, e.g. refs/heads/main" }
                    if (production && text("ref") == null) v += "$where $ERR_PRODUCTION_REQUIRES_REF — a production Forgejo trust must pin a ref (spec.$block.ref); Forgejo has no environments"
                }
                PROVIDER_KUBERNETES -> {
                    rejectUnknownKeys(pins, KUBERNETES_PIN_KEYS, pw, v)
                    val issuer = text("issuer")
                    when {
                        issuer == null -> v += "$pw.issuer is required (the cluster's exact OIDC issuer)"
                        !issuer.startsWith("https://") -> v += "$pw: $ERR_INVALID_KUBERNETES_ISSUER — issuer '$issuer' must be an https:// URL"
                    }
                    val namespace = text("namespace"); val sa = text("serviceAccount")
                    if (namespace != null && !K8S_NAMESPACE_PATTERN.matches(namespace)) v += "$pw: $ERR_INVALID_KUBERNETES_NAMESPACE — namespace '$namespace' must be an RFC 1123 label"
                    if (sa != null && !K8S_NAMESPACE_PATTERN.matches(sa)) v += "$pw: $ERR_INVALID_KUBERNETES_SERVICE_ACCOUNT — serviceAccount '$sa' must be an RFC 1123 label"
                    if (sa != null && namespace == null) v += "$pw.serviceAccount needs namespace"
                    pins["jwks"]?.takeIf { !it.isNull }?.let { validateJwks(it, "$pw.jwks", ERR_INVALID_KUBERNETES_JWKS, v) }
                    if (production && (namespace == null || sa == null)) v += "$where $ERR_PRODUCTION_REQUIRES_SERVICE_ACCOUNT — a production Kubernetes trust must pin spec.$block.namespace and spec.$block.serviceAccount"
                }
            }
        }

        /**
         * SSO-4042 — an `emailTemplate`: exactly `{ type, locale?, subject, body | bodyFile }` ([EMAIL_TEMPLATE_SPEC_KEYS]); `type` one
         * of [EMAIL_TEMPLATE_TYPES]; `locale` in the API's grammar ([EMAIL_TEMPLATE_LOCALE_PATTERN]); `subject` non-blank and at most
         * [EMAIL_TEMPLATE_MAX_SUBJECT_CHARS] characters; EXACTLY ONE of `body` (inline HTML, non-blank, at most
         * [EMAIL_TEMPLATE_MAX_BODY_BYTES] UTF-8 bytes) and `bodyFile` (a relative path inside the provisioning file's directory —
         * no absolute path, no `..`; read and checked against the same caps when the file is loaded, see [parse]). It carries no
         * `grants:` — product-api gates every login-experience call on its environment's `login_theme` object, so there is
         * no access object of its own to grant on. The `{{variable}}` allowlist stays the API's (`400 unknown_template_variable`
         * at apply): it is per type and may grow, and the refusal names the allowed set.
         */
        private fun validateEmailTemplate(spec: JsonNode, r: JsonNode, where: String, v: MutableList<String>) {
            rejectUnknownKeys(spec, EMAIL_TEMPLATE_SPEC_KEYS, "$where spec", v)
            if (r["grants"]?.takeIf { !it.isNull } != null) {
                v += "$where an emailTemplate cannot carry 'grants' — it has no access object of its own (product-api gates email templates with the login experience of their environment, login_theme:<environment>); grant on the loginTheme instead"
            }
            spec["type"]?.takeIf { !it.isNull }?.let { t ->
                val type = t.takeIf { it.isTextual() }?.asString()?.trim()
                if (type == null || type !in EMAIL_TEMPLATE_TYPES) v += "$where (emailTemplate) spec.type '${t.asString()}' must be one of ${EMAIL_TEMPLATE_TYPES.joinToString(", ")}"
            }
            spec["locale"]?.takeIf { !it.isNull }?.let { l ->
                val locale = l.takeIf { it.isTextual() }?.asString()?.trim()
                if (locale == null || !EMAIL_TEMPLATE_LOCALE_PATTERN.matches(locale)) {
                    v += "$where (emailTemplate) spec.locale '${l.asString()}' must be a 2-3 letter ISO 639 language code (e.g. en, nl) — the API stores no region subtag; omit it for the base template"
                }
            }
            spec["subject"]?.takeIf { !it.isNull }?.let { s ->
                val subject = s.takeIf { it.isTextual() }?.asString()
                when {
                    subject == null -> v += "$where (emailTemplate) spec.subject must be a string"
                    subject.isBlank() -> v += "$where (emailTemplate) spec.subject must not be blank"
                    subject.length > EMAIL_TEMPLATE_MAX_SUBJECT_CHARS -> v += "$where (emailTemplate) spec.subject is ${subject.length} characters, over the $EMAIL_TEMPLATE_MAX_SUBJECT_CHARS-character limit"
                }
            }
            val body = spec["body"]?.takeIf { !it.isNull }
            val bodyFile = spec["bodyFile"]?.takeIf { !it.isNull }
            when {
                body == null && bodyFile == null -> v += "$where (emailTemplate) $ERR_EMAIL_TEMPLATE_BODY_REQUIRED — spec.body (inline HTML) or spec.bodyFile (a path relative to this file) is required"
                body != null && bodyFile != null -> v += "$where (emailTemplate) $ERR_EMAIL_TEMPLATE_BODY_AMBIGUOUS — declare spec.body OR spec.bodyFile, not both"
            }
            body?.let { b ->
                val html = b.takeIf { it.isTextual() }?.asString()
                when {
                    html == null -> v += "$where (emailTemplate) spec.body must be a string of HTML"
                    html.isBlank() -> v += "$where (emailTemplate) spec.body must not be blank"
                    html.toByteArray(Charsets.UTF_8).size > EMAIL_TEMPLATE_MAX_BODY_BYTES ->
                        v += "$where (emailTemplate) spec.body is ${html.toByteArray(Charsets.UTF_8).size} bytes, over the $EMAIL_TEMPLATE_MAX_BODY_BYTES-byte limit"
                }
            }
            bodyFile?.let { f ->
                val path = f.takeIf { it.isTextual() }?.asString()?.trim()
                when {
                    path.isNullOrEmpty() -> v += "$where (emailTemplate) spec.bodyFile must be a path relative to the provisioning file"
                    File(path).isAbsolute || path.startsWith("/") || path.startsWith("\\") -> v += "$where (emailTemplate) spec.bodyFile '$path' must be relative to the provisioning file, not absolute"
                    path.split('/', '\\').any { it == ".." } -> v += "$where (emailTemplate) spec.bodyFile '$path' must stay inside the provisioning file's directory (no '..')"
                }
            }
        }

        /**
         * SSO-4057 — a `legalDocument`: exactly `{ type, version, title, format?, body | bodyFile }` ([LEGAL_DOCUMENT_SPEC_KEYS]);
         * `type` one of [LEGAL_DOCUMENT_TYPES]; `version` / `title` plain text as identity accepts it (trimmed, non-empty, at most
         * [LEGAL_DOCUMENT_MAX_VERSION_CHARS] / [LEGAL_DOCUMENT_MAX_TITLE_CHARS] characters, no `<`, `>` or control character);
         * `format` one of [LEGAL_DOCUMENT_FORMATS]; EXACTLY ONE of `body` (inline, see [legalDocumentBodyProblem]) and `bodyFile`
         * (a relative path inside the provisioning file's directory, read and held to the same rules when the file is loaded).
         * No `grants:` — it is not a platform access object ([SCOPE_ONLY_KINDS]).
         */
        private fun validateLegalDocument(spec: JsonNode, r: JsonNode, where: String, v: MutableList<String>) {
            rejectUnknownKeys(spec, LEGAL_DOCUMENT_SPEC_KEYS, "$where spec", v)
            if (r["grants"]?.takeIf { !it.isNull } != null) {
                v += "$where a $KIND_LEGAL_DOCUMENT cannot carry 'grants' — it is not a platform access object (product-api gates legal documents on tenant:legal-documents.* alone)"
            }
            spec["type"]?.takeIf { !it.isNull }?.let { t ->
                val type = t.takeIf { it.isTextual() }?.asString()?.trim()
                if (type == null || type !in LEGAL_DOCUMENT_TYPES) v += "$where ($KIND_LEGAL_DOCUMENT) spec.type '${t.asString()}' must be one of ${LEGAL_DOCUMENT_TYPES.joinToString(", ")}"
            }
            mapOf("version" to LEGAL_DOCUMENT_MAX_VERSION_CHARS, "title" to LEGAL_DOCUMENT_MAX_TITLE_CHARS).forEach { (field, max) ->
                spec[field]?.takeIf { !it.isNull }?.let { n ->
                    val text = n.takeIf { it.isTextual() }?.asString()?.trim()
                    when {
                        text == null -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.$field must be a string"
                        text.isEmpty() -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.$field must not be blank"
                        text.length > max -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.$field is ${text.length} characters, over the $max-character limit"
                        text.any { it == '<' || it == '>' || it.isISOControl() } -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.$field must be plain text (no '<', '>' or control character)"
                    }
                }
            }
            spec["format"]?.takeIf { !it.isNull }?.let { f ->
                val format = f.takeIf { it.isTextual() }?.asString()
                if (format == null || format !in LEGAL_DOCUMENT_FORMATS) v += "$where ($KIND_LEGAL_DOCUMENT) spec.format '${f.asString()}' must be one of ${LEGAL_DOCUMENT_FORMATS.joinToString(", ")}"
            }
            val body = spec["body"]?.takeIf { !it.isNull }
            val bodyFile = spec["bodyFile"]?.takeIf { !it.isNull }
            when {
                body == null && bodyFile == null -> v += "$where ($KIND_LEGAL_DOCUMENT) $ERR_LEGAL_DOCUMENT_BODY_REQUIRED — spec.body (inline Markdown or text) or spec.bodyFile (a path relative to this file) is required"
                body != null && bodyFile != null -> v += "$where ($KIND_LEGAL_DOCUMENT) $ERR_LEGAL_DOCUMENT_BODY_AMBIGUOUS — declare spec.body OR spec.bodyFile, not both"
            }
            body?.let { b ->
                val text = b.takeIf { it.isTextual() }?.asString()
                if (text == null) v += "$where ($KIND_LEGAL_DOCUMENT) spec.body must be a string of Markdown or plain text"
                else legalDocumentBodyProblem(text)?.let { v += "$where ($KIND_LEGAL_DOCUMENT) spec.body $it" }
            }
            bodyFile?.let { f ->
                val path = f.takeIf { it.isTextual() }?.asString()?.trim()
                when {
                    path.isNullOrEmpty() -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.bodyFile must be a path relative to the provisioning file"
                    File(path).isAbsolute || path.startsWith("/") || path.startsWith("\\") -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.bodyFile '$path' must be relative to the provisioning file, not absolute"
                    path.split('/', '\\').any { it == ".." } -> v += "$where ($KIND_LEGAL_DOCUMENT) spec.bodyFile '$path' must stay inside the provisioning file's directory (no '..')"
                }
            }
        }

        /**
         * SSO-4057 — what is wrong with a legal document's body, in identity's order (`TenantLegalDocumentRules.validate`): blank
         * (`invalid_body`), over [LEGAL_DOCUMENT_MAX_BODY_BYTES] UTF-8 bytes (`body_too_large`), a control character other than
         * newline, carriage return or tab (`invalid_body`), HTML ([LEGAL_DOCUMENT_HTML_MARKUP], `html_not_allowed`). Null when it
         * is acceptable. The phrase completes "spec.body …" / "spec.bodyFile '<path>' …".
         */
        fun legalDocumentBodyProblem(body: String): String? {
            if (body.isBlank()) return "is blank"
            val bytes = body.toByteArray(Charsets.UTF_8).size
            if (bytes > LEGAL_DOCUMENT_MAX_BODY_BYTES) return "is $bytes bytes, over the $LEGAL_DOCUMENT_MAX_BODY_BYTES-byte limit"
            if (body.any { it.isISOControl() && it != '\n' && it != '\r' && it != '\t' }) return "contains a control character (only newline, carriage return and tab are allowed)"
            LEGAL_DOCUMENT_HTML_MARKUP.find(body)?.let { m ->
                val line = body.substring(0, m.range.first).count { it == '\n' } + 1
                return "$ERR_HTML_NOT_ALLOWED — it contains HTML ('${m.value}…' on line $line): write Markdown or plain text; the platform refuses HTML rather than sanitising it"
            }
            return null
        }

        /**
         * SSO-4041 — a `loginTheme`: exactly the record `PUT /api/v1/login-experience/branding` replaces ([LOGIN_THEME_SPEC_KEYS];
         * an unknown key names the record, because the API's lenient binding would DROP it and the PUT would then clear the
         * field the author meant to set), every declared value in identity's own grammar: `logoUrl` an `https://` URL of at most
         * [LOGIN_THEME_MAX_LOGO_URL_CHARS] characters, `primaryColor` / `backgroundColor` a hex colour ([HEX_COLOR_PATTERN]),
         * `borderRadiusPx` an integer `0..`[LOGIN_THEME_MAX_BORDER_RADIUS_PX], `theme` one of [LOGIN_THEME_THEMES], and
         * `cssVariables` an object whose keys are the closed `--thoryn-*` allowlist ([LOGIN_THEME_CSS_VARIABLES]) with a hex colour
         * or a plain font stack ([LOGIN_THEME_FONT_STACK_PATTERN]) as values; SSO-4048 — `displayName` / `pageTitle` plain text
         * ([LOGIN_THEME_TEXT_FIELDS]: at most 80 / 120 characters, no `<`, `>` or control character) and `faviconUrl` / `termsUrl` /
         * `privacyUrl` `https://` links, `supportUrl` `https://` or `mailto:` ([LOGIN_THEME_LINK_FIELDS]: at most
         * [LOGIN_THEME_MAX_LINK_CHARS] characters, no whitespace). A value carrying a `{{env.NAME}}` placeholder is
         * left to the API (it is resolved at plan / apply). An EMPTY spec is legal: it declares the platform defaults, and the plan
         * shows every stored field as cleared. The WCAG contrast floor stays identity's (`400 insufficient_contrast` at apply).
         */
        private fun validateLoginTheme(spec: JsonNode, where: String, v: MutableList<String>) {
            spec.properties().forEach { entry ->
                if (entry.key !in LOGIN_THEME_SPEC_KEYS) {
                    v += "$where (loginTheme) spec.${entry.key} is not a branding field — the record is exactly ${LOGIN_THEME_SPEC_KEYS.joinToString(", ")}; " +
                        "the API would drop an unknown key, and the PUT replaces the whole record, so a typo here clears the field it was meant to set"
                }
            }
            fun placeholder(n: JsonNode): Boolean = n.isTextual() && ProvisionEngine.ENV_PLACEHOLDER.containsMatchIn(n.asString())
            fun text(field: String): String? {
                val n = spec[field]?.takeIf { !it.isNull } ?: return null
                if (!n.isTextual()) { v += "$where (loginTheme) spec.$field must be a string"; return null }
                if (placeholder(n)) return null
                return n.asString().trim()
            }
            text("logoUrl")?.takeIf { it.isNotEmpty() }?.let { url ->
                if (!url.startsWith("https://")) v += "$where (loginTheme) spec.logoUrl must be an https:// URL (was '$url')"
                if (url.length > LOGIN_THEME_MAX_LOGO_URL_CHARS) v += "$where (loginTheme) spec.logoUrl exceeds the $LOGIN_THEME_MAX_LOGO_URL_CHARS-character limit"
            }
            listOf("primaryColor", "backgroundColor").forEach { field ->
                text(field)?.takeIf { it.isNotEmpty() }?.let { colour ->
                    if (!HEX_COLOR_PATTERN.matches(colour)) v += "$where (loginTheme) spec.$field '$colour' is not a CSS hex colour — use #rgb, #rrggbb or #rrggbbaa"
                }
            }
            text("theme")?.takeIf { it.isNotEmpty() }?.let { theme ->
                if (theme !in LOGIN_THEME_THEMES) v += "$where (loginTheme) spec.theme '$theme' must be one of ${LOGIN_THEME_THEMES.joinToString(", ")}"
            }
            spec["borderRadiusPx"]?.takeIf { !it.isNull }?.let { px ->
                when {
                    placeholder(px) -> Unit
                    !px.isIntegralNumber() -> v += "$where (loginTheme) spec.borderRadiusPx must be an integer between 0 and $LOGIN_THEME_MAX_BORDER_RADIUS_PX"
                    px.asInt() !in 0..LOGIN_THEME_MAX_BORDER_RADIUS_PX -> v += "$where (loginTheme) spec.borderRadiusPx ${px.asInt()} must be between 0 and $LOGIN_THEME_MAX_BORDER_RADIUS_PX"
                }
            }
            // SSO-4048 — the name / title (plain text) and the favicon / footer links, in identity's grammar (trimmed; blank clears).
            LOGIN_THEME_TEXT_FIELDS.forEach { (field, max) ->
                text(field)?.takeIf { it.isNotEmpty() }?.let { value ->
                    when {
                        value.length > max -> v += "$where (loginTheme) spec.$field exceeds the $max-character limit"
                        value.any { it == '<' || it == '>' || it.isISOControl() } -> v += "$where (loginTheme) spec.$field must be plain text: no '<', '>' or control characters"
                    }
                }
            }
            LOGIN_THEME_LINK_FIELDS.forEach { (field, schemes) ->
                text(field)?.takeIf { it.isNotEmpty() }?.let { url ->
                    when {
                        url.length > LOGIN_THEME_MAX_LINK_CHARS -> v += "$where (loginTheme) spec.$field exceeds the $LOGIN_THEME_MAX_LINK_CHARS-character limit"
                        url.any { it.isWhitespace() || it.isISOControl() } ||
                            schemes.none { url.startsWith(it, ignoreCase = true) && url.length > it.length } ->
                            v += "$where (loginTheme) spec.$field must be ${schemes.joinToString(" or ") { if (it == "mailto:") "a mailto: address" else "an https:// URL" }} without whitespace (was '$url')"
                    }
                }
            }
            spec["cssVariables"]?.takeIf { !it.isNull }?.let { css ->
                if (!css.isObject()) { v += "$where (loginTheme) spec.cssVariables must be an object of --thoryn-* token → value"; return }
                css.properties().forEach { (token, value) ->
                    val kind = LOGIN_THEME_CSS_VARIABLES[token]
                    if (kind == null) {
                        v += "$where (loginTheme) spec.cssVariables.$token is not a supported CSS variable — allowed: ${LOGIN_THEME_CSS_VARIABLES.keys.joinToString(", ")}"
                        return@forEach
                    }
                    if (value.isNull) return@forEach
                    if (!value.isTextual()) { v += "$where (loginTheme) spec.cssVariables.$token must be a string"; return@forEach }
                    if (placeholder(value)) return@forEach
                    val text = value.asString().trim()
                    if (text.isEmpty()) return@forEach
                    when (kind) {
                        CSS_VARIABLE_KIND_COLOR -> if (!HEX_COLOR_PATTERN.matches(text)) v += "$where (loginTheme) spec.cssVariables.$token '$text' is not a CSS hex colour — use #rgb, #rrggbb or #rrggbbaa"
                        CSS_VARIABLE_KIND_FONT -> if (!LOGIN_THEME_FONT_STACK_PATTERN.matches(text)) v += "$where (loginTheme) spec.cssVariables.$token '$text' is not a plain font-family stack (letters, digits, spaces, commas, quotes; at most 120 characters)"
                    }
                }
            }
        }

        /**
         * SSO-4042 — one resource per (type, locale) cell: the API addresses one record by them, so two declarations would fight over
         * it. SSO-4054 — per ENVIRONMENT: the same cell in production and in a sandbox are two records (an omitted `environment`
         * and `environment: production` are the same plane).
         */
        private fun validateEmailTemplateCells(resources: List<JsonNode>, v: MutableList<String>) {
            resources.filter { it.isObject() && it["kind"]?.asString() == KIND_EMAIL_TEMPLATE && it["spec"]?.isObject() == true }
                .groupBy { r ->
                    val env = r["environment"]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() && !isProductionPlane(it) }
                    val cell = emailTemplateCell(r["spec"]["type"]?.takeIf { it.isTextual() }?.asString(), r["spec"]["locale"]?.takeIf { it.isTextual() }?.asString())
                    if (env == null) cell else "$cell in environment $env"
                }
                .filterValues { it.size > 1 }
                .forEach { (cell, dups) -> v += "duplicate emailTemplate for $cell — declared ${dups.size} times (${dups.joinToString(", ") { "'" + (it["name"]?.asString() ?: KIND_EMAIL_TEMPLATE) + "'" }}); one resource per (environment, type, locale)" }
        }

        /** SSO-4057 — one `legalDocument` per (environment, type): the API keeps one active document of each type per environment. */
        private fun validateLegalDocumentCells(resources: List<JsonNode>, v: MutableList<String>) {
            resources.filter { it.isObject() && it["kind"]?.asString() == KIND_LEGAL_DOCUMENT && it["spec"]?.isObject() == true }
                .groupBy { r ->
                    val env = r["environment"]?.takeIf { it.isTextual() }?.asString()?.trim()?.takeIf { it.isNotEmpty() && !isProductionPlane(it) }
                    val type = r["spec"]["type"]?.takeIf { it.isTextual() }?.asString()?.trim() ?: "?"
                    if (env == null) type else "$type in environment $env"
                }
                .filterValues { it.size > 1 }
                .forEach { (cell, dups) -> v += "duplicate $KIND_LEGAL_DOCUMENT for $cell — declared ${dups.size} times (${dups.joinToString(", ") { "'" + (it["name"]?.asString() ?: KIND_LEGAL_DOCUMENT) + "'" }}); one resource per (environment, type)" }
        }

        /** The (type, locale) a template addresses, as `type <t> locale <l>` — the base locale rendered as [EMAIL_TEMPLATE_BASE_LOCALE]. */
        fun emailTemplateCell(type: String?, locale: String?): String = "type ${type?.trim() ?: "?"} locale ${emailTemplateLocale(locale)}"

        /** A declared `spec.locale` in its storage form: trimmed, lower-cased; absent / blank / `*` ⇒ [EMAIL_TEMPLATE_BASE_LOCALE]. */
        fun emailTemplateLocale(locale: Any?): String = locale?.toString()?.trim()?.lowercase()?.takeIf { it.isNotEmpty() && it != EMAIL_TEMPLATE_BASE_LOCALE } ?: EMAIL_TEMPLATE_BASE_LOCALE

        /**
         * SSO-3941 — a `role`: exactly `{ permissions, description? }`. `permissions` is required (an empty list is a role that
         * grants nothing) and lists permission strings — product-api's rules, mirrored: non-blank, not a reserved platform-scope
         * namespace (`tenant:` / `admin:` / `holder:`, [ERR_PERMISSION_NAME_RESERVED]); no duplicates. A role is not a platform
         * access object, so it cannot carry `grants:`.
         */
        private fun validateRole(spec: JsonNode, r: JsonNode, where: String, v: MutableList<String>) {
            rejectUnknownKeys(spec, ROLE_SPEC_KEYS, "$where spec", v)
            if (r["grants"]?.takeIf { !it.isNull } != null) {
                v += "$where a $KIND_ROLE cannot carry 'grants' — a role is not a platform access object (product-api gates it on tenant:roles.* alone); assign it to people with `thoryn users roles add`"
            }
            spec[ROLE_DESCRIPTION]?.takeIf { !it.isNull && !it.isTextual() }?.let { v += "$where ($KIND_ROLE) spec.$ROLE_DESCRIPTION must be a string" }
            val permissions = spec[ROLE_PERMISSIONS]?.takeIf { !it.isNull }
            when {
                permissions == null -> v += "$where ($KIND_ROLE) spec.$ROLE_PERMISSIONS is required — the FULL list of permissions the role grants ([] for none)"
                !permissions.isArray() -> v += "$where ($KIND_ROLE) spec.$ROLE_PERMISSIONS must be a list of permission names"
                else -> {
                    val names = mutableListOf<String>()
                    permissions.toList().forEachIndexed { i, p ->
                        val name = p.takeIf { it.isTextual() }?.asString()?.trim()
                        when {
                            name.isNullOrEmpty() -> v += "$where ($KIND_ROLE) spec.$ROLE_PERMISSIONS[$i] must be a non-empty permission name (e.g. invoices:read)"
                            RESERVED_PERMISSION_PREFIX.matches(name) -> v += "$where ($KIND_ROLE) spec.$ROLE_PERMISSIONS[$i]: $ERR_PERMISSION_NAME_RESERVED — '$name' begins with a reserved platform-scope namespace (tenant:, admin:, holder:)"
                            else -> names += name
                        }
                    }
                    names.groupBy { it }.filterValues { it.size > 1 }.keys.forEach { v += "$where ($KIND_ROLE) spec.$ROLE_PERMISSIONS lists '$it' twice" }
                }
            }
        }

        /**
         * SSO-3941 — an application's `tokenClaims`: exactly `{ sources?, enabled?, roleMapping? }` (SSO-3945 — see [validateRoleMapping]). `sources` (default `[permissions]`, the
         * server's) is a non-empty list of non-empty source names, passed through as written — WHICH names exist is
         * product-api's call ([DEFAULT_TOKEN_CLAIM_SOURCES]); `enabled: false` turns claims-in-token OFF and takes no `sources`.
         */
        private fun validateTokenClaims(node: JsonNode, where: String, v: MutableList<String>) {
            val w = "$where spec.$SPEC_TOKEN_CLAIMS"
            if (!node.isObject()) {
                v += "$w must be an object { sources: [ … ] } (or { enabled: false } to turn claims in the token off)"
                return
            }
            rejectUnknownKeys(node, TOKEN_CLAIMS_KEYS, w, v)
            val enabled = node[TOKEN_CLAIMS_ENABLED]?.takeIf { !it.isNull }
            if (enabled != null && !enabled.isBoolean()) v += "$w.$TOKEN_CLAIMS_ENABLED must be true or false"
            val roleMapping = node[TOKEN_CLAIMS_ROLE_MAPPING]?.takeIf { !it.isNull }
            if (enabled?.takeIf { it.isBoolean() }?.asBoolean() == false && roleMapping != null) {
                v += "$w: `$TOKEN_CLAIMS_ENABLED: false` turns claims in the token off — it takes no $TOKEN_CLAIMS_ROLE_MAPPING"
                return
            }
            val sources = node[TOKEN_CLAIMS_SOURCES]?.takeIf { !it.isNull }
            if (sources == null) {
                roleMapping?.let { validateRoleMapping(it, DEFAULT_TOKEN_CLAIM_SOURCES, w, v) }
                return
            }
            if (enabled?.takeIf { it.isBoolean() }?.asBoolean() == false) {
                v += "$w: `$TOKEN_CLAIMS_ENABLED: false` turns claims in the token off — it takes no $TOKEN_CLAIMS_SOURCES"
                return
            }
            if (!sources.isArray() || sources.isEmpty()) {
                v += "$w.$TOKEN_CLAIMS_SOURCES must be a non-empty list of claim source names (e.g. [permissions])"
                return
            }
            val names = sources.toList().map { it.takeIf { n -> n.isTextual() }?.asString()?.trim() ?: "" }
            names.forEachIndexed { i, n -> if (n.isEmpty()) v += "$w.$TOKEN_CLAIMS_SOURCES[$i] must be a non-empty source name" }
            names.filter { it.isNotEmpty() }.groupBy { it }.filterValues { it.size > 1 }.keys.forEach { v += "$w.$TOKEN_CLAIMS_SOURCES lists '$it' twice" }
            roleMapping?.let { validateRoleMapping(it, names, w, v) }
        }

        /**
         * SSO-3945 — `tokenClaims.roleMapping`: an object of role name → value, refused here on exactly what product-api's
         * `RoleMappingRules.validate` refuses (`400 invalid_role_mapping`) and nothing more — at most
         * [ROLE_MAPPING_MAX_ENTRIES] entries; a key 1..[ROLE_MAPPING_MAX_ROLE_NAME_LENGTH] characters, not blank, without
         * control characters; a value matching [ROLE_MAPPING_VALUE_GRAMMAR] and not under a reserved platform-scope namespace
         * (`tenant:` / `admin:` / `holder:`, any case); and the `roles` source among [sources] (default `[permissions]`). A
         * YAML value must be a STRING: an unquoted `1.10` or `0123` would reach the server as something else, so it is
         * refused with "quote it" rather than converted.
         */
        private fun validateRoleMapping(mapping: JsonNode, sources: List<String>, w: String, v: MutableList<String>) {
            val f = "$w.$TOKEN_CLAIMS_ROLE_MAPPING"
            if (!mapping.isObject()) {
                v += "$f must be an object of role name → the value the application receives in its `roles` claim (e.g. { forge-maintainer: Maintainers })"
                return
            }
            if (TOKEN_CLAIMS_ROLES_SOURCE !in sources) {
                v += "$f requires the '$TOKEN_CLAIMS_ROLES_SOURCE' claim source — add it to $w.$TOKEN_CLAIMS_SOURCES (invalid_role_mapping)"
            }
            if (mapping.size() > ROLE_MAPPING_MAX_ENTRIES) {
                v += "$f holds ${mapping.size()} entries; at most $ROLE_MAPPING_MAX_ENTRIES are allowed (invalid_role_mapping)"
            }
            mapping.properties().forEach { (role, value) ->
                if (role.isBlank() || role.length > ROLE_MAPPING_MAX_ROLE_NAME_LENGTH || ROLE_MAPPING_CONTROL_CHARS.containsMatchIn(role)) {
                    v += "$f: every key must be a role name of 1 to $ROLE_MAPPING_MAX_ROLE_NAME_LENGTH characters, not blank, without control characters (invalid_role_mapping)"
                    return@forEach
                }
                when {
                    !value.isTextual() ->
                        v += "$f['$role'] must be a string — quote it (e.g. \"$role\": \"Maintainers\")"
                    !ROLE_MAPPING_VALUE_GRAMMAR.matches(value.asString()) ->
                        v += "$f['$role']: a value must be 1 to 128 characters, start with a letter or digit, and contain only letters, digits and . _ - : @ / (invalid_role_mapping)"
                    RESERVED_PERMISSION_PREFIX.matches(value.asString()) ->
                        v += "$f['$role']: a value may not start with a reserved platform scope prefix (tenant:, admin:, holder:) (invalid_role_mapping)"
                }
            }
        }

        /**
         * SSO-3962 — the violation text for a [kind] declared in a file of [part] (never [ProvisionPart.MIXED]): e.g.
         * "`role` is tenant provisioning; this is an application file (thoryn.io/application/v1). Declare it in the
         * workspace's config project." — the kind's part, the file's part, the project it belongs in.
         */
        fun crossPartRefusal(kind: String, part: ProvisionPart): String {
            val kindPart = ProvisionPart.ofKind(kind) ?: return "kind '$kind' not in the allowlist $KINDS"
            val relation = when (kindPart) {
                ProvisionPart.TENANT -> "it defines the tenant, and an application is a user of the tenant"
                else -> "it is how one client uses the tenant, which the tenant's config project does not decide"
            }
            return "`$kind` is ${kindPart.label} provisioning; this is ${article(part.label)} ${part.label} file (${part.apiVersion}). " +
                "Declare it in ${kindPart.owner} ($relation)."
        }

        private fun article(word: String): String = if (word.first() in "aeiou") "an" else "a"

        /** A required spec member is missing when absent, null, a blank scalar, or an empty array. */
        private fun isMissing(node: JsonNode?): Boolean = when {
            node == null || node.isNull -> true
            node.isArray() -> node.isEmpty()
            node.isObject() -> false
            else -> node.asString().isBlank()
        }

        private fun rejectUnknownKeys(node: JsonNode, allowed: Set<String>, where: String, into: MutableList<String>) {
            node.properties().forEach { entry ->
                if (entry.key !in allowed) into += "$where has unknown property '${entry.key}' (additionalProperties:false)"
            }
        }

        private fun sha256(bytes: ByteArray): String =
            "sha256:" + MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
