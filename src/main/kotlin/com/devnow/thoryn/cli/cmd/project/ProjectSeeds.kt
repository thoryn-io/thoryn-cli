package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import com.devnow.thoryn.cli.cmd.connection.Connection
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
            |apiVersion: thoryn.io/provision/v1
            |resources:
            |  # The application's OAuth client in sandbox `$sandboxSlug`: the sandbox this repository's workload identity
            |  # ($clientId) is trusted in and manages. A public client with PKCE needs no secret; adjust the redirect
            |  # URIs to where the app runs (the same sandbox slug can also be read from CI as "{{env.THORYN_ENVIRONMENT}}").
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
        |apiVersion: thoryn.io/provision/v1
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

    /** The config project's SANDBOX section: anchored on the sandbox it configures (slug only — this connection reads environments, it does not rename them). */
    fun configSandboxProvisionYaml(repository: GhRepository, sandboxSlug: String, clientId: String): String = """
        |# Seeded by `thoryn project init config` (SSO-3435) for ${repository.fullName} — the SANDBOX section: what the sandbox
        |# connection ($clientId, manager of sandbox `$sandboxSlug`) configures inside that sandbox. `thoryn provision plan`
        |# on a pull request, `thoryn provision apply` on ${repository.defaultBranch} (oauthy ADR 2026-10-13, provisioning-as-code converge).
        |# From here on this file is in control — edit it freely; `thoryn project init` never overwrites it.
        |apiVersion: thoryn.io/provision/v1
        |resources:
        |  # The sandbox itself, adopted by slug — the anchor its configuration hangs off. This connection holds
        |  # tenant:environments.read, so only the slug is declared (nothing here can need a write). Add the sandbox's
        |  # sign-in configuration below: loginMethods, federationMember, emailProvider, loginTheme, loginFlow — each with
        |  # `environment: ${resourceName(sandboxSlug, "sandbox")}`.
        |  - kind: environment
        |    name: ${resourceName(sandboxSlug, "sandbox")}
        |    spec:
        |      slug: $sandboxSlug
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
