package com.devnow.thoryn.cli.cmd.connection

import com.devnow.thoryn.cli.auth.TrustPins
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.File

/**
 * SSO-2948 (epic SSO-2947) — a parsed **connection contract**.
 *
 * A connection is a schema-backed JSON file (`connection.schema.json`, bundled beside the recipe
 * schema) describing HOW the CLI signs into a given workspace/identity: the workspace slug (which
 * derives the per-tenant hub issuer + gateway), and the machine client + the *name* of the env var
 * that carries its secret. It is a real end-user feature — a person keeps as many connection files
 * as they have use cases — that the CLI's own CI merely dogfoods (see the ADR
 * `2026-09-09-thoryn-cli-as-code-ci-connection-contract.md`).
 *
 * Two auth methods, one per client (ADR D10):
 *  - `client_credentials` — an API key: the client id + the NAME of the env var carrying its secret.
 *  - `workload_identity` (SSO-3308) — a GitHub Actions workload identity trust: the trust's `wi_…`
 *    client id and audience (derived from the workspace + `environment` when omitted). No secret at all —
 *    the job's own OIDC token is exchanged, so the file names no env var. Optional `auth.github` pins
 *    mirror the trust's, so a refused sign-in can name the field that differs.
 *
 * DATA, not code: the secret is NEVER in the file, only the [secretEnv] name. This class parses and
 * structurally validates against the bundled schema's contract (no third-party JSON-Schema engine —
 * the same hand-rolled, message-bearing approach the recipe suite uses); [load]/[parse] throw
 * [ConnectionException] with a clear, aggregated message on any violation.
 */
internal class Connection private constructor(
    /** Workspace slug — derives `https://<slug>.hub.<env>` and the matching gateway. */
    val slug: String,
    /**
     * NAME of the env var holding the platform BASE ISSUER (default [DEFAULT_HUB_BASE_URL_ENV]).
     * SSO-3296 — the default name additionally accepts the documented `THORYN_ISSUER` spelling; a name
     * given EXPLICITLY here is read verbatim, so the confinement it expresses is never widened.
     */
    val hubBaseUrlEnv: String,
    /** How the client authenticates: [AUTH_METHOD_CLIENT_CREDENTIALS] or [AUTH_METHOD_WORKLOAD_IDENTITY]. */
    val method: String,
    /** OAuth client id of the machine client (public). */
    val clientId: String,
    /** NAME of the env var holding the client secret (never the value) — `client_credentials` only. */
    val secretEnvOrNull: String?,
    /** The EXACT scope set to request — ceiling and floor. */
    val scopes: List<String>,
    /** SSO-3308 — the trust's audience, when the file names it (else derived; `workload_identity` only). */
    val audience: String? = null,
    /** SSO-3308 — the sandbox environment slug the derived audience carries as `/{environment}`. */
    val environment: String? = null,
    /** SSO-3308 — an explicit token endpoint (same origin as the audience), else `{audience}/oauth2/token`. */
    val tokenEndpoint: String? = null,
    /** SSO-3308 — the trust's GitHub pins as the file states them, for local diagnostics only. */
    val github: TrustPins? = null,
) {

    /** True for a `workload_identity` connection (no secret; the GitHub Actions job token is the credential). */
    val isWorkloadIdentity: Boolean get() = method == AUTH_METHOD_WORKLOAD_IDENTITY

    /** NAME of the env var holding the client secret — a `client_credentials` connection always has one. */
    val secretEnv: String
        get() = secretEnvOrNull ?: error("a '$method' connection names no secret env var")

    companion object {
        const val API_VERSION = "thoryn.io/connection/v1"
        const val AUTH_METHOD_CLIENT_CREDENTIALS = "client_credentials"

        /** SSO-3308 — a GitHub Actions workload identity trust: no secret, the job token is exchanged. */
        const val AUTH_METHOD_WORKLOAD_IDENTITY = "workload_identity"

        /** The auth methods a connection may name. */
        val AUTH_METHODS: List<String> = listOf(AUTH_METHOD_CLIENT_CREDENTIALS, AUTH_METHOD_WORKLOAD_IDENTITY)

        /** SSO-3308 — the only workload identity provider in v1 (the trust API's `provider`). */
        const val PROVIDER_GITHUB_ACTIONS = "github_actions"

        /** SSO-3308 — `auth.*` members only a `workload_identity` connection may carry. */
        private val WORKLOAD_ONLY_KEYS = listOf("provider", "audience", "environment", "tokenEndpoint", "github")

        /** SSO-3308 — `auth.github` members (the trust API's GitHub pin, same names). */
        private val GITHUB_KEYS = setOf("owner", "repository", "ownerId", "repositoryId", "environment", "ref", "githubHostedRunnersOnly")

        /**
         * Default env var naming the platform base issuer when `workspace.hubBaseUrlEnv` is omitted.
         * SSO-3296 — kept at the pre-rename `THORYN_HUB` so existing contracts resolve unchanged;
         * `ThorynConfig.ISSUER_ENV` (`THORYN_ISSUER`) is the documented spelling and is tried first
         * when the contract leaves this field at its default.
         */
        const val DEFAULT_HUB_BASE_URL_ENV = "THORYN_HUB"

        /** Bundled schema resource — the documented contract this loader validates against. */
        const val SCHEMA_RESOURCE = "/examples/connection.schema.json"

        /** Workspace slug grammar — same as the recipe workspace-slug / recipe-id pattern. */
        val SLUG_PATTERN = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        /** POSIX-ish environment-variable name grammar. */
        val ENV_NAME_PATTERN = Regex("^[A-Za-z_][A-Za-z0-9_]*$")

        /** A `tenant:<resource>.<verb>` scope — the recipe schema's scope grammar. */
        val SCOPE_PATTERN = Regex("^tenant:[a-z-]+\\.[a-z-]+$")

        private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

        /** Read, parse and validate a connection file; throws [ConnectionException] on any problem. */
        fun load(file: File): Connection {
            if (!file.isFile) throw ConnectionException("connection file not found: ${file.path}")
            val bytes = try {
                file.readBytes()
            } catch (e: Exception) {
                throw ConnectionException("could not read connection file '${file.path}': ${e.message}")
            }
            return parse(bytes, file.path)
        }

        /** Parse and validate connection [bytes]; [source] is used only in error messages. */
        fun parse(bytes: ByteArray, source: String = "<connection>"): Connection {
            val root = try {
                mapper.readTree(bytes)
            } catch (e: Exception) {
                throw ConnectionException("connection '$source' is not valid JSON: ${e.message}")
            }
            val violations = validate(root)
            if (violations.isNotEmpty()) {
                throw ConnectionException(
                    "invalid connection '$source':\n  - " + violations.joinToString("\n  - "),
                )
            }
            val workspace = root["workspace"]
            val auth = root["auth"]
            val hubEnv = workspace["hubBaseUrlEnv"]
                ?.takeIf { !it.isNull }
                ?.asString()
                ?.takeIf { it.isNotBlank() }
                ?: DEFAULT_HUB_BASE_URL_ENV
            fun text(node: JsonNode?, name: String): String? =
                node?.get(name)?.takeIf { !it.isNull }?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            val github = auth["github"]?.takeIf { it.isObject() }?.let { g ->
                TrustPins(
                    owner = text(g, "owner"),
                    repository = text(g, "repository"),
                    ownerId = g["ownerId"]?.takeIf { it.isIntegralNumber() }?.asLong(),
                    repositoryId = g["repositoryId"]?.takeIf { it.isIntegralNumber() }?.asLong(),
                    environment = text(g, "environment"),
                    ref = text(g, "ref"),
                    githubHostedRunnersOnly = g["githubHostedRunnersOnly"]?.takeIf { it.isBoolean() }?.asBoolean(),
                )
            }
            return Connection(
                slug = workspace["slug"].asString(),
                hubBaseUrlEnv = hubEnv,
                method = auth["method"].asString(),
                clientId = auth["clientId"].asString(),
                secretEnvOrNull = text(auth, "secretEnv"),
                scopes = auth["scopes"].toList().map { it.asString() },
                audience = text(auth, "audience")?.trimEnd('/'),
                environment = text(auth, "environment"),
                tokenEndpoint = text(auth, "tokenEndpoint"),
                github = github,
            )
        }

        /**
         * Structural validation mirroring `connection.schema.json` (draft 2020-12): the `const`
         * fields, `additionalProperties:false` on each object, required members, the slug / env-name /
         * scope patterns, and the non-empty unique scope array. Returns human-readable violations
         * (empty ⇒ conformant) so callers and the conformance test can assert on WHY a document is
         * rejected.
         */
        fun validate(root: JsonNode): List<String> {
            val v = mutableListOf<String>()
            if (!root.isObject()) return listOf("connection must be a JSON object")

            rejectUnknownKeys(root, setOf("apiVersion", "workspace", "auth"), "(root)", v)

            if (root["apiVersion"]?.asString() != API_VERSION) {
                v += "apiVersion must be '$API_VERSION'"
            }

            val workspace = root["workspace"]
            if (workspace == null || !workspace.isObject()) {
                v += "workspace object is required"
            } else {
                rejectUnknownKeys(workspace, setOf("slug", "hubBaseUrlEnv"), "workspace", v)
                val slug = workspace["slug"]?.takeIf { !it.isNull }?.asString()
                when {
                    slug.isNullOrBlank() -> v += "workspace.slug is required"
                    !SLUG_PATTERN.matches(slug) -> v += "workspace.slug '$slug' must match ${SLUG_PATTERN.pattern}"
                }
                workspace["hubBaseUrlEnv"]?.takeIf { !it.isNull }?.asString()?.let { env ->
                    if (!ENV_NAME_PATTERN.matches(env)) {
                        v += "workspace.hubBaseUrlEnv '$env' must match ${ENV_NAME_PATTERN.pattern}"
                    }
                }
            }

            val auth = root["auth"]
            if (auth == null || !auth.isObject()) {
                v += "auth object is required"
            } else {
                rejectUnknownKeys(
                    auth,
                    setOf("method", "clientId", "secretEnv", "scopes") + WORKLOAD_ONLY_KEYS,
                    "auth",
                    v,
                )
                val method = auth["method"]?.takeIf { !it.isNull }?.asString()
                if (method !in AUTH_METHODS) {
                    v += "auth.method must be one of ${AUTH_METHODS.joinToString(" | ")}"
                }
                if (auth["clientId"]?.takeIf { !it.isNull }?.asString().isNullOrBlank()) {
                    v += "auth.clientId is required"
                }
                val secretEnv = auth["secretEnv"]?.takeIf { !it.isNull }?.asString()
                when (method) {
                    AUTH_METHOD_CLIENT_CREDENTIALS -> {
                        when {
                            secretEnv.isNullOrBlank() -> v += "auth.secretEnv is required"
                            !ENV_NAME_PATTERN.matches(secretEnv) -> v += "auth.secretEnv '$secretEnv' must match ${ENV_NAME_PATTERN.pattern}"
                        }
                        WORKLOAD_ONLY_KEYS.filter { auth.has(it) }.forEach { k ->
                            v += "auth.$k applies to the '$AUTH_METHOD_WORKLOAD_IDENTITY' method only"
                        }
                    }
                    AUTH_METHOD_WORKLOAD_IDENTITY -> {
                        if (auth.has("secretEnv")) {
                            v += "auth.secretEnv must not be set for '$AUTH_METHOD_WORKLOAD_IDENTITY' — a workload identity " +
                                "sign-in uses no secret (the GitHub Actions job token is the credential)"
                        }
                        validateWorkloadIdentity(auth, v)
                    }
                }
                val scopesNode = auth["scopes"]
                if (scopesNode == null || !scopesNode.isArray()) {
                    v += "auth.scopes array is required"
                } else {
                    val scopes = scopesNode.toList().map { it.asString() }
                    if (scopes.isEmpty()) v += "auth.scopes must be non-empty"
                    if (scopes.size != scopes.toSet().size) v += "auth.scopes must be unique: $scopes"
                    scopes.forEach { s ->
                        if (!SCOPE_PATTERN.matches(s)) v += "auth.scopes entry '$s' must match ${SCOPE_PATTERN.pattern}"
                    }
                }
            }
            return v
        }

        /** SSO-3308 — the `workload_identity`-only members: provider, audience, environment, tokenEndpoint, github. */
        private fun validateWorkloadIdentity(auth: JsonNode, v: MutableList<String>) {
            auth["provider"]?.takeIf { !it.isNull }?.asString()?.let { p ->
                if (p != PROVIDER_GITHUB_ACTIONS) v += "auth.provider must be '$PROVIDER_GITHUB_ACTIONS'"
            }
            val audience = auth["audience"]?.takeIf { !it.isNull }?.asString()
            audience?.let { a ->
                if (!HTTP_URL_PATTERN.matches(a)) v += "auth.audience '$a' must be an absolute http(s) URL"
            }
            auth["environment"]?.takeIf { !it.isNull }?.asString()?.let { e ->
                if (!SLUG_PATTERN.matches(e)) v += "auth.environment '$e' must match ${SLUG_PATTERN.pattern}"
                if (audience != null) v += "auth.environment only derives the audience; omit it when auth.audience is set"
            }
            auth["tokenEndpoint"]?.takeIf { !it.isNull }?.asString()?.let { t ->
                if (!HTTP_URL_PATTERN.matches(t)) v += "auth.tokenEndpoint '$t' must be an absolute http(s) URL"
            }
            val github = auth["github"] ?: return
            if (!github.isObject()) {
                v += "auth.github must be an object"
                return
            }
            rejectUnknownKeys(github, GITHUB_KEYS, "auth.github", v)
            listOf("owner", "repository", "environment", "ref").forEach { k ->
                github[k]?.let { n -> if (!n.isString() || n.asString().isBlank()) v += "auth.github.$k must be a non-empty string" }
            }
            listOf("ownerId", "repositoryId").forEach { k ->
                github[k]?.let { n -> if (!n.isIntegralNumber() || n.asLong() <= 0) v += "auth.github.$k must be a positive integer" }
            }
            github["githubHostedRunnersOnly"]?.let { n -> if (!n.isBoolean()) v += "auth.github.githubHostedRunnersOnly must be a boolean" }
        }

        /** An absolute http(s) URL (the loader's check; the sign-in re-validates the issuer rules). */
        private val HTTP_URL_PATTERN = Regex("^https?://[^\\s/?#]+(/[^\\s?#]*)?$")

        private fun rejectUnknownKeys(node: JsonNode, allowed: Set<String>, where: String, into: MutableList<String>) {
            node.properties().forEach { entry ->
                if (entry.key !in allowed) into += "$where has unknown property '${entry.key}' (additionalProperties:false)"
            }
        }

        /**
         * The confinement primitive behind the ADR's "scope ceiling" layer: true iff every
         * [requested] scope is present in [granted] (i.e. `requested ⊆ granted`). SSO-2951's
         * repo-level test asserts `connection.scopes ⊆ the client's granted set` with this.
         */
        fun scopesWithinGrant(requested: Set<String>, granted: Set<String>): Boolean =
            granted.containsAll(requested)
    }
}

/** Thrown on any connection load / parse / validation failure. */
internal class ConnectionException(message: String) : RuntimeException(message)
