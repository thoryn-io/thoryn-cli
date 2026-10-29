package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.VersionProvider
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig
import com.devnow.thoryn.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3435 — the two `.thoryn/` files `thoryn project init` SEEDS into a repository so it is in the
 * provisioning-as-code converge loop from its first commit (oauthy ADR
 * `2026-10-13-provisioning-as-code-converge-github-app-and-fga-ownership`, §3 "the App seeds `.thoryn/` into
 * every repository it generates" and §6 "bootstrap once, by a human; then the file is in control"):
 *
 *  - **`connection.json`** — "who I am": a `workload_identity` connection contract
 *    (`src/main/resources/examples/connection.schema.json`) for the trust the run just created or adopted, so a
 *    job signs in with `thoryn login --connection <file>` and no secret. It is DERIVED from the trust, so a
 *    re-run re-renders it (a different client id after the trust was recreated is corrected, an identical one is
 *    left alone).
 *  - **`provision.yaml`** — "what I own": a STARTER declaration in the shapes the existing `.thoryn/provision.yaml`
 *    files use. For a config project the production section declares the workspace's own resource it owns — the
 *    sandbox environment — and the sandbox section anchors on that sandbox (slug only: its trust holds
 *    `tenant:environments.read`, so nothing it declares can need a write); for an app project it declares the
 *    app's OAuth client in its sandbox. Seeded only when ABSENT and never overwritten afterwards: from then on the
 *    file is in control (`plan` on a pull request, `apply` on the default branch).
 *
 * A config project also gets its provisioning WORKFLOW (SSO-3971, thoryn-cli contract v1): the App-dispatched stub
 * [WORKFLOW_PATH] calling the reusable workflow at this CLI's release, and its run-time configuration
 * [WORKFLOW_CONFIG_PATH] — the shape oauthy ADR 2026-10-25 (provisioning is tenant and applications) and
 * thoryn-io/thoryn-tenant use. Seeded like `provision.yaml`: only when absent.
 *
 * Both live next to the connection's `provisionFile` from `.thoryn/template.json`: an app template's
 * `.thoryn/provision.yaml` gets `.thoryn/connection.json` beside it; a config template's
 * `.thoryn/environments/<connection>/provision.yaml` gets `.thoryn/environments/<connection>/connection.json`.
 */
internal object ProjectSeeds {

    const val CONNECTION_FILE: String = "connection.json"

    /** The deterministic branch a config project's seeds are proposed on once the approval ruleset protects the default branch. */
    const val PROVISIONING_BRANCH: String = "thoryn/provisioning"
    const val PROVISIONING_MESSAGE: String = "Thoryn project: the connection contracts and the starter provisioning files"

    private val json: JsonMapper = JsonMapper.builder().build()

    /** `<dir of provisionFile>/connection.json`. */
    fun connectionPath(provisionFile: String): String = provisionFile.substringBeforeLast('/') + "/" + CONNECTION_FILE

    /** One seeded file: its repository-relative path and content. */
    class Seed(val path: String, val content: String, val kind: String)

    const val KIND_CONNECTION: String = "connection"
    const val KIND_PROVISION: String = "provision"

    /**
     * The `workload_identity` connection contract for [trust] (the product-api trust record): the trust's
     * `clientId`, `audience` and (when not the default) `tokenEndpoint`, its scopes, and its GitHub pins — the
     * pins grant nothing; the CLI uses them only to explain a refused sign-in. Validates against the bundled schema
     * ([Connection.validate]) before it is returned, so a seed can never be a file `thoryn login` would refuse.
     */
    fun connectionJson(workspaceSlug: String, trust: JsonNode, envSlug: String, production: Boolean): String {
        val github = trust["github"]
        val pins = linkedMapOf<String, Any?>()
        text(github, "owner")?.let { pins["owner"] = it }
        text(github, "repository")?.let { pins["repository"] = it }
        github?.get("ownerId")?.takeIf { it.isIntegralNumber && it.asLong() > 0 }?.let { pins["ownerId"] = it.asLong() }
        github?.get("repositoryId")?.takeIf { it.isIntegralNumber && it.asLong() > 0 }?.let { pins["repositoryId"] = it.asLong() }
        text(github, "environment")?.let { pins["environment"] = it }
        text(github, "ref")?.let { pins["ref"] = it }
        val audience = text(trust, "audience")?.trimEnd('/')
        val tokenEndpoint = text(trust, "tokenEndpoint")?.takeIf { audience != null && it != WorkloadIdentityFlow.tokenEndpointFor(audience, null) }
        val scopes = trust["scopes"]?.takeIf { it.isArray }?.toList()?.mapNotNull { it.asString() }.orEmpty()
        val auth = linkedMapOf<String, Any?>(
            "method" to Connection.AUTH_METHOD_WORKLOAD_IDENTITY,
            "provider" to Connection.PROVIDER_GITHUB_ACTIONS,
            "clientId" to text(trust, "clientId"),
        )
        if (audience != null) auth["audience"] = audience else if (!production) auth["environment"] = envSlug
        if (tokenEndpoint != null) auth["tokenEndpoint"] = tokenEndpoint
        auth["scopes"] = scopes
        if (pins.isNotEmpty()) auth["github"] = pins
        val document = linkedMapOf<String, Any?>(
            "apiVersion" to Connection.API_VERSION,
            "workspace" to linkedMapOf("slug" to workspaceSlug),
            "auth" to auth,
        )
        val tree = json.valueToTree<JsonNode>(document)
        val violations = Connection.validate(tree)
        check(violations.isEmpty()) { "the seeded connection would not validate: $violations" }
        return json.writerWithDefaultPrettyPrinter().writeValueAsString(tree) + "\n"
    }

    /** True when [content] is a `workload_identity` connection pinning [repositoryId] — one this command wrote (and may rewrite). */
    fun isOurConnection(content: ByteArray, repositoryId: Long): Boolean = runCatching {
        val c = Connection.parse(content, "<existing>")
        c.isWorkloadIdentity && c.github?.repositoryId == repositoryId
    }.getOrDefault(false)

    /** The app project's starter: its OAuth client in the sandbox the repository's trust is bound to. */
    fun appProvisionYaml(repository: GhRepository, stack: String, sandboxSlug: String, clientId: String): String {
        val name = resourceName(repository.name, "app")
        val redirect = REDIRECT_URIS[stack] ?: "http://localhost:3000/callback"
        return """
            |# Seeded by `thoryn project init app` (SSO-3435) for ${repository.fullName} — the "what I own" half of .thoryn/,
            |# next to connection.json ("who I am"). The repository converges this file: `thoryn provision plan` on a pull
            |# request, `thoryn provision apply` on ${repository.defaultBranch} (oauthy ADR 2026-10-13, provisioning-as-code converge).
            |# From here on this file is in control — edit it freely; `thoryn project init` never overwrites it.
            |#
            |# APPLICATION provisioning (SSO-3962, oauthy ADR 2026-10-25): this file declares how THIS application uses the
            |# tenant — its OAuth client (and its `tokenClaims` / `roleMapping`, naming roles the tenant defines). It defines
            |# nothing about the tenant: environments, users (test users included), sign-in configuration, roles and this
            |# repository's own workload identity trust are declared in the workspace's CONFIG project (a thoryn.io/tenant/v1 file).
            |apiVersion: ${ProvisionFile.API_VERSION_APPLICATION}
            |resources:
            |  # The application's OAuth client in sandbox `$sandboxSlug`: the sandbox this repository's workload identity
            |  # ($clientId) is trusted in and manages. A public client with PKCE needs no secret; adjust the redirect
            |  # URIs to where the app runs (the same sandbox slug can also be read from CI as "{{env.THORYN_ENVIRONMENT}}").
            |  # Its PRODUCTION client is declared HERE too, without `environment:` — created once a workspace admin approves a
            |  # creation slot for this repository's identity (`thoryn access reserve client:$clientId application:<clientId>`).
            |  - kind: application
            |    name: $name
            |    environment: $sandboxSlug
            |    spec:
            |      displayName: "${repository.fullName}"
            |      clientType: public
            |      grantTypes: [authorization_code, refresh_token]
            |      redirectUris: ["$redirect"]
            |      scopes: [openid, profile, email]
            |
        """.trimMargin()
    }

    /** The config project's PRODUCTION section: the workspace's own resource this repository owns — its sandbox. */
    fun configProductionProvisionYaml(repository: GhRepository, sandboxSlug: String, sandboxName: String, clientId: String, githubEnvironment: String): String = """
        |# Seeded by `thoryn project init config` (SSO-3435) for ${repository.fullName} — the PRODUCTION section: the
        |# workspace's own resources this repository owns, converged by the production connection ($clientId, which signs
        |# in only from the GitHub environment `$githubEnvironment` on ${repository.defaultBranch}). `thoryn provision plan` on a
        |# pull request, `thoryn provision apply` on ${repository.defaultBranch} (oauthy ADR 2026-10-13, provisioning-as-code converge).
        |# From here on this file is in control — edit it freely; `thoryn project init` never overwrites it.
        |#
        |# TENANT provisioning (SSO-3962, oauthy ADR 2026-10-25): the config project is the ONE place that defines what the tenant
        |# IS — its environments, identity sources (federationMember), users, sign-in (loginMethods, loginFlow, loginTheme),
        |# email provider, email templates (emailTemplate — one per environment, type and locale), custom domain,
        |# roles, and the workload identity trusts of the workspace's APP projects (one
        |# `kind: workloadIdentityTrust` per app repository: a repository never declares its own authority). Applications are
        |# USERS of the tenant: each app project declares its own OAuth client in its own thoryn.io/application/v1 file,
        |# production client included (created under a creation slot a workspace admin approves) — never here.
        |apiVersion: ${ProvisionFile.API_VERSION_TENANT}
        |resources:
        |  # The workspace's sandbox, adopted by its slug (created by `thoryn project init`, or already there). Declare further
        |  # sandboxes here; each gets its own section under .thoryn/environments/<name>/ with its own connection.
        |  - kind: environment
        |    name: ${resourceName(sandboxSlug, "sandbox")}
        |    spec:
        |      slug: $sandboxSlug
        |      displayName: "${sandboxName.replace("\"", "'")}"
        |
    """.trimMargin()

    // ── SSO-3971 — the App-dispatched workflow stub and its run-time configuration (thoryn-cli contract v1) ──────────

    /** The stub the Thoryn GitHub App dispatches — the ONE path it looks for. */
    const val WORKFLOW_PATH: String = ProvisioningWorkflowContract.WORKFLOW_PATH

    /** The reusable workflow's run-time configuration the stub's default `with.config` names. */
    const val WORKFLOW_CONFIG_PATH: String = WorkflowConfig.DEFAULT_PATH

    const val KIND_WORKFLOW: String = "workflow"

    /**
     * The release a stub pins when this CLI is not a release build (a local or SNAPSHOT build has no tag of its own): the
     * first release whose engine reads `thoryn.io/tenant/v1` (SSO-3962). A release build pins ITSELF ([stubRelease]).
     */
    const val FALLBACK_STUB_RELEASE: String = "cli-v0.49.0"

    private val RELEASE_VERSION = Regex("^\\d+\\.\\d+\\.\\d+$")
    private val HTTPS_ORIGIN = Regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")

    /**
     * The `cli-v*` tag the seeded stub calls the reusable workflow at — and so, through `job.workflow_ref`, the CLI its jobs
     * run: this CLI's own release (`cli-v0.50.0` for a 0.50.0 build, whose tag exists because the release is cut from it),
     * else [FALLBACK_STUB_RELEASE].
     */
    fun stubRelease(version: String = VersionProvider.readVersion()): String =
        if (RELEASE_VERSION.matches(version)) "cli-v$version" else FALLBACK_STUB_RELEASE

    /** The unprotected GitHub environment a config project's plan job runs in: the production trust's plan profile is keyed on it. */
    fun planEnvironment(applyEnvironment: String): String = "$applyEnvironment-plan"

    /**
     * The config project's provisioning STUB (contract v1 §2): the App's four `workflow_dispatch` inputs, `check-run:` in
     * the `run-name`, `permissions: {}`, per-mode concurrency, and ONE job — under the apply marker — that calls the
     * reusable workflow at [release] with `id-token: write`, `checks: write`, `contents: read`: the plan job in
     * [planEnvironment] (unprotected; the production trust's plan profile mints it read-only scopes), the apply job in
     * [applyEnvironment] (the reviewed production environment the trust pins). [issuer] is passed only when it is an
     * `https://` origin the contract accepts (the reusable workflow's default is production's).
     */
    fun configStubYaml(repository: GhRepository, issuer: String, planEnvironment: String, applyEnvironment: String, release: String = stubRelease()): String {
        val issuerLine = issuer.trim().trimEnd('/').takeIf { HTTPS_ORIGIN.matches(it) }?.let { "\n|      issuer: $it" } ?: ""
        return """
            |# Thoryn provisioning — the STUB the Thoryn GitHub App dispatches (seeded by `thoryn project init config`, SSO-3971).
            |# It only forwards the App's inputs to the reusable workflow ${ProvisioningWorkflowContract.REUSABLE_WORKFLOW}:
            |# $WORKFLOW_CONFIG_PATH holds the run-time configuration (files, fixRequest, consentUrl, apply toggles), the `with:` block
            |# the job shape. Configure, never edit the job; lint both with `thoryn provision workflow check`.
            |#
            |# This repository is the workspace's CONFIG PROJECT — TENANT provisioning (thoryn.io/tenant/v1; oauthy ADR
            |# 2026-10-25-provisioning-is-tenant-and-applications). The App never holds a credential to your workspace: each called
            |# job signs in as THIS repository's own workload identity (.thoryn/environments/<connection>/connection.json, no
            |# secret) — in `$planEnvironment` (unprotected) for a read-only plan on every pull request, in `$applyEnvironment` (deploys
            |# from ${repository.defaultBranch} only, reviewed) for the apply. One trust, two profiles: the hub mints write scopes only to a job in
            |# `$applyEnvironment`. Removals are never automated, and nothing is written back: the platform is the ledger.
            |name: Thoryn provisioning
            |run-name: "Thoryn provisioning ${'$'}{{ inputs.mode }} ${'$'}{{ inputs.head_sha }} check-run:${'$'}{{ inputs.check_run_id }}"
            |
            |on:
            |  workflow_dispatch:
            |    inputs:
            |      mode:
            |        description: "plan (pull request, read-only) or apply (default branch, reviewed)"
            |        required: true
            |        type: choice
            |        options: [plan, apply]
            |      head_sha:
            |        description: "The commit to plan or apply"
            |        required: true
            |        type: string
            |      check_run_id:
            |        description: "The Thoryn GitHub App check run this run reports to"
            |        required: true
            |        type: string
            |      pr_number:
            |        description: "The pull request (plan only)"
            |        required: false
            |        type: string
            |        default: ""
            |
            |concurrency:
            |  group: thoryn-provisioning-${'$'}{{ inputs.mode }}
            |  cancel-in-progress: false
            |
            |permissions: {}
            |
            |jobs:
            |  ${ProvisioningWorkflowContract.APPLY_JOB_MARKER}
            |  provisioning:
            |    uses: ${ProvisioningWorkflowContract.REUSABLE_WORKFLOW}@$release
            |    permissions:
            |      id-token: write
            |      checks: write
            |      contents: read
            |    with:
            |      mode: ${'$'}{{ inputs.mode }}
            |      head_sha: ${'$'}{{ inputs.head_sha }}
            |      check_run_id: ${'$'}{{ inputs.check_run_id }}
            |      pr_number: ${'$'}{{ inputs.pr_number }}
            |      plan-environment: $planEnvironment
            |      apply-environment: $applyEnvironment$issuerLine
            |
        """.trimMargin()
    }

    /**
     * The config project's `.thoryn/workflow.yaml` (contract v1 §5): every section's tenant file with the connection beside
     * it, production first (it declares the sandboxes the other sections configure); `fixRequest: true`; removals off. No
     * `env`: the seeded files are literal. No `consentUrl`: this command knows no App consent page (a red job then prints
     * the CLI commands alone) — set it when the Thoryn GitHub App is installed.
     */
    fun configWorkflowYaml(repository: GhRepository, files: List<Pair<String, String>>): String = buildString {
        append(
            """
            |# Thoryn provisioning — the run-time configuration of the reusable workflow the stub ($WORKFLOW_PATH) calls.
            |# Seeded by `thoryn project init config` (SSO-3971) for ${repository.fullName}. Schema: thoryn-cli examples/workflow.schema.json;
            |# lint: `thoryn provision workflow check`. Unknown keys are refused — a knob that is not here is a product gap to report,
            |# not a script to write.
            |apiVersion: thoryn.io/workflow/v1
            |# One tenant file per section, planned on every pull request and applied on ${repository.defaultBranch}, in this order — each signed in
            |# with its own connection (this repository's workload identity for that plane).
            |files:
            |""".trimMargin(),
        )
        append('\n')
        files.forEach { (file, connection) ->
            append("  - file: $file\n")
            append("    connection: $connection\n")
        }
        append(
            """
            |# Upload the fix request when a job is red on a missing right, so the App names the fix on its check run.
            |fixRequest: true
            |# Set `consentUrl` to the Thoryn GitHub App's browser consent base URL (an https:// origin) and a red job also prints
            |# a link to approve the missing right in the browser. Unset: the job prints the CLI commands alone.
            |# Removals are never automated: retiring a tenant resource is a reviewed act by a person.
            |apply:
            |  prune: false
            |  destroy: false
            |""".trimMargin(),
        )
        append('\n')
    }

    /** The config project's SANDBOX section: anchored on the sandbox it configures (slug only — this connection reads environments, it does not rename them). */
    fun configSandboxProvisionYaml(repository: GhRepository, sandboxSlug: String, clientId: String): String = """
        |# Seeded by `thoryn project init config` (SSO-3435) for ${repository.fullName} — the SANDBOX section: what the sandbox
        |# connection ($clientId, manager of sandbox `$sandboxSlug`) configures inside that sandbox. `thoryn provision plan`
        |# on a pull request, `thoryn provision apply` on ${repository.defaultBranch} (oauthy ADR 2026-10-13, provisioning-as-code converge).
        |# From here on this file is in control — edit it freely; `thoryn project init` never overwrites it.
        |#
        |# TENANT provisioning (SSO-3962, oauthy ADR 2026-10-25): what the sandbox IS — its sign-in configuration, its test
        |# users, its roles, and the workload identity trusts of the app projects bound to it. The applications that USE the
        |# sandbox declare their own OAuth clients in their own thoryn.io/application/v1 files, never here.
        |apiVersion: ${ProvisionFile.API_VERSION_TENANT}
        |resources:
        |  # The sandbox itself — the anchor its configuration hangs off. `readOnly: true`: a dependency, not this section's
        |  # (the production section declares it), so plan reads it and apply never writes it, and this connection needs no
        |  # tenant:environments.write (SSO-3971; the Thoryn GitHub App's seed does the same). Add the sandbox's
        |  # configuration below, each with `environment: ${resourceName(sandboxSlug, "sandbox")}`: loginMethods, federationMember,
        |  # emailProvider, loginTheme, loginFlow, role, emailTemplate (a cell this sandbox does not declare sends production's copy);
        |  # `kind: user` for the sandbox's TEST USERS (an app project references
        |  # one by email in its test configuration, it never creates one); and `kind: workloadIdentityTrust` for each app
        |  # project's CI identity (its scopes: tenant:applications.read tenant:applications.write tenant:access.read — plus
        |  # tenant:environments.read for a sandbox client — and nothing wider).
        |  - kind: environment
        |    name: ${resourceName(sandboxSlug, "sandbox")}
        |    readOnly: true
        |    spec:
        |      slug: $sandboxSlug
        |
    """.trimMargin()

    // ── SSO-3669 — the app's PRODUCTION client, declared in the CONFIG repository (ADR 2026-10-13 production-clients §1) ──

    /** The config project's production section — where every application's production client is declared. */
    const val CONFIG_PRODUCTION_PROVISION_FILE: String = ".thoryn/environments/production/provision.yaml"

    /** The app repository's GitHub environment the id is published to, and the variable its production deploy reads (ADR §2). */
    const val PRODUCTION_GITHUB_ENVIRONMENT: String = "production"
    const val PRODUCTION_CLIENT_ID_VARIABLE: String = "THORYN_PRODUCTION_CLIENT_ID"

    /**
     * The paths the application starters' shared `.thoryn/provision.yaml` (thoryn-starters `shared/thoryn/`) registers
     * for every stack — the sign-in callback and the post-logout landing. `.thoryn/template.json` (v2) does not declare
     * them, so they are this convention, appended to `--production-url`.
     */
    const val CALLBACK_PATH: String = "/callback"
    const val SIGNED_OUT_PATH: String = "/signed-out"

    /** `thoryn/app-<app repository name>` — the deterministic branch the entry is proposed on (a re-run reuses it, SSO-3436). */
    fun productionClientBranch(appRepositoryName: String): String = "thoryn/app-$appRepositoryName"

    /** The provisioning `name` (the converge key) of the app's production client: the app repository's name (`owner/name` → `name`). */
    fun productionClientName(appRepository: String): String = resourceName(appRepository.substringAfter('/'), "app")

    /**
     * The `application` entry for [appRepository]'s production client, exactly the ADR §1 shape: no `environment` (the
     * production plane), a PUBLIC client (PKCE proves it; nothing is minted, nothing is delivered), `authorization_code`
     * with `openid profile email`, the redirect URIs under [productionUrl] ([CALLBACK_PATH] / [SIGNED_OUT_PATH]), and a
     * `publishTo` target that lands the id in the app repository's `production` GitHub environment as
     * [PRODUCTION_CLIENT_ID_VARIABLE] on every production apply (§2). Built as a tree, so it is COMPARED structurally
     * with what the config repository already declares (converged by `name`).
     */
    fun productionClientEntry(appRepository: String, productionUrl: String, name: String = productionClientName(appRepository)): JsonNode {
        val base = productionUrl.trimEnd('/')
        return json.valueToTree(
            linkedMapOf(
                "kind" to "application",
                "name" to name,
                "spec" to linkedMapOf(
                    "displayName" to appRepository,
                    "clientType" to "public",
                    "grantTypes" to listOf("authorization_code"),
                    "scopes" to listOf("openid", "profile", "email"),
                    "redirectUris" to listOf(base + CALLBACK_PATH),
                    "postLogoutRedirectUris" to listOf(base + SIGNED_OUT_PATH),
                ),
                "publishTo" to listOf(
                    linkedMapOf(
                        "kind" to "githubActionsVariable",
                        "repository" to appRepository,
                        "environment" to PRODUCTION_GITHUB_ENVIRONMENT,
                        "name" to PRODUCTION_CLIENT_ID_VARIABLE,
                    ),
                ),
            ),
        )
    }

    /** True when [resource] (a `resources[]` item of the config file) is the production client of [appRepository] (`owner/name`). */
    fun isProductionClientOf(resource: JsonNode, appRepository: String): Boolean =
        resource.isObject && text(resource, "kind") == "application" && text(resource, "name") == productionClientName(appRepository)

    /** The comment lines written above an APPENDED production-client entry (a human reads the config file; the tree comparison ignores them). */
    fun productionClientHeader(appRepository: String): String = """
        |
        |  # Production OAuth client of the application repository $appRepository (proposed by `thoryn project init app`).
        |  # DEPRECATED SHAPE (SSO-3962, oauthy ADR 2026-10-25 supersedes ADR 2026-10-13 §1–§2): the app project owns its production
        |  # client in its own thoryn.io/application/v1 file, created under a creation slot a workspace admin approves
        |  # (`thoryn access reserve`); `publishTo` is accepted for one more release. Move this entry there and drop it here.
        |  # Owned by this repository: changing a redirect URI is a reviewed pull request here plus an approved production run.
        |  # A public client with PKCE — no secret exists anywhere. Its id is published to $appRepository's GitHub
        |  # environment `$PRODUCTION_GITHUB_ENVIRONMENT` as the Actions variable $PRODUCTION_CLIENT_ID_VARIABLE on every production apply.
        |
    """.trimMargin()

    /** A provisioning `name` (the converge key) from a repository or environment name: lower-case slug, or [fallback]. */
    fun resourceName(raw: String, fallback: String): String {
        val slug = raw.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(63).trimEnd('-')
        return if (slug.isEmpty() || !NAME.matches(slug)) fallback else slug
    }

    private val NAME = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

    /** Each stack's framework-default redirect URI — a starter value the application's owner adjusts. */
    private val REDIRECT_URIS: Map<String, String> = mapOf(
        "express" to "http://localhost:3000/callback",
        "spring-boot" to "http://localhost:8080/login/oauth2/code/thoryn",
        "aspnet-core" to "https://localhost:5001/signin-oidc",
    )

    private fun text(node: JsonNode?, field: String): String? =
        node?.get(field)?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
}
