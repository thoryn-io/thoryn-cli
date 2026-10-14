package com.devnow.thoryn.cli.cmd.connection

import com.devnow.thoryn.cli.auth.KubernetesPins
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
 *    SSO-3684 — the same method under a `kubernetes` trust (oathy SSO-3678): `auth.provider: kubernetes`,
 *    and the identity token comes from a FILE — `auth.tokenSource: {kind: file, path: …}`, the pod's
 *    projected ServiceAccount token — instead of the GitHub Actions runner. Optional `auth.kubernetes`
 *    pins (issuer, namespace, serviceAccount) play the role `auth.github` plays for GitHub.
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
    /** SSO-3684 — the trust's provider (`github_actions` default, or `kubernetes`); `workload_identity` only. */
    val provider: String? = null,
    /**
     * SSO-3684 — the FILE the identity token is read from (`auth.tokenSource.kind: file`), else null: the
     * GitHub Actions runner variables are the source. A path, never a token.
     */
    val tokenFile: String? = null,
    /** SSO-3684 — a `kubernetes` trust's pins as the file states them, for local diagnostics only. */
    val kubernetes: KubernetesPins? = null,
) {

    /** True for a `workload_identity` connection (no secret; the GitHub Actions job token is the credential). */
    val isWorkloadIdentity: Boolean get() = method == AUTH_METHOD_WORKLOAD_IDENTITY

    /** SSO-3684 — the provider a `workload_identity` connection binds to; GitHub Actions when the file names none. */
    val effectiveProvider: String get() = provider ?: PROVIDER_GITHUB_ACTIONS

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

        /** SSO-3308 — the default workload identity provider (the trust API's `provider`): a GitHub Actions job. */
        const val PROVIDER_GITHUB_ACTIONS = "github_actions"

        /** SSO-3684 — a pod in a Kubernetes cluster, authenticating with its projected ServiceAccount token. */
        const val PROVIDER_KUBERNETES = "kubernetes"

        /** The workload identity providers a connection may name. */
        val PROVIDERS: List<String> = listOf(PROVIDER_GITHUB_ACTIONS, PROVIDER_KUBERNETES)

        /** SSO-3684 — `auth.tokenSource.kind`: the GitHub Actions runner's job-token endpoint (the default when absent). */
        const val TOKEN_SOURCE_GITHUB_ACTIONS = "github_actions"

        /** SSO-3684 — `auth.tokenSource.kind`: a file on disk, read on every exchange (a projected ServiceAccount token). */
        const val TOKEN_SOURCE_FILE = "file"

        /** The token-source kinds a connection may name. */
        val TOKEN_SOURCE_KINDS: List<String> = listOf(TOKEN_SOURCE_GITHUB_ACTIONS, TOKEN_SOURCE_FILE)

        /** SSO-3308 — `auth.*` members only a `workload_identity` connection may carry. */
        private val WORKLOAD_ONLY_KEYS = listOf("provider", "audience", "environment", "tokenEndpoint", "github", "tokenSource", "kubernetes")

        /** SSO-3308 — `auth.github` members (the trust API's GitHub pin, same names). */
        private val GITHUB_KEYS = setOf("owner", "repository", "ownerId", "repositoryId", "environment", "ref", "githubHostedRunnersOnly")

        /** SSO-3684 — `auth.kubernetes` members (the trust API's Kubernetes pin, same names; never the key set). */
        private val KUBERNETES_KEYS = setOf("issuer", "namespace", "serviceAccount")

        /** SSO-3684 — `auth.tokenSource` members. */
        private val TOKEN_SOURCE_KEYS = setOf("kind", "path")

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
            val kubernetes = auth["kubernetes"]?.takeIf { it.isObject() }?.let { k ->
                KubernetesPins(
                    issuer = text(k, "issuer")?.trimEnd('/'),
                    namespace = text(k, "namespace"),
                    serviceAccount = text(k, "serviceAccount"),
                )
            }
            val tokenSource = auth["tokenSource"]?.takeIf { it.isObject() }
            val tokenFile = tokenSource?.takeIf { text(it, "kind") == TOKEN_SOURCE_FILE }?.let { text(it, "path") }
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
                provider = text(auth, "provider"),
                tokenFile = tokenFile,
                kubernetes = kubernetes,
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

        /**
         * SSO-3308 — the `workload_identity`-only members: provider, audience, environment, tokenEndpoint, github;
         * SSO-3684 — tokenSource and kubernetes. A `kubernetes` provider's token can only come from a file
         * (the projected ServiceAccount token), and a `github_actions` one carries no `kubernetes` pins; each
         * provider's pin block belongs to it alone.
         */
        private fun validateWorkloadIdentity(auth: JsonNode, v: MutableList<String>) {
            val provider = auth["provider"]?.takeIf { !it.isNull }?.asString()
            provider?.let { p ->
                if (p !in PROVIDERS) v += "auth.provider must be one of ${PROVIDERS.joinToString(" | ")}"
            }
            val tokenSourceKind = validateTokenSource(auth, v)
            if (provider == PROVIDER_KUBERNETES) {
                if (tokenSourceKind != TOKEN_SOURCE_FILE) {
                    v += "auth.tokenSource of kind '$TOKEN_SOURCE_FILE' is required for provider '$PROVIDER_KUBERNETES' — a pod's " +
                        "identity token is its projected ServiceAccount token on disk (e.g. " +
                        "{\"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\"})"
                }
                if (auth.has("github")) v += "auth.github applies to provider '$PROVIDER_GITHUB_ACTIONS' only"
            } else {
                if (auth.has("kubernetes")) v += "auth.kubernetes applies to provider '$PROVIDER_KUBERNETES' only"
            }
            validateKubernetesPins(auth, v)
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

        /** SSO-3684 — `auth.tokenSource`: `{kind}` with a non-empty `path` for `file`; returns the kind (null when absent). */
        private fun validateTokenSource(auth: JsonNode, v: MutableList<String>): String? {
            val source = auth["tokenSource"] ?: return null
            if (!source.isObject()) {
                v += "auth.tokenSource must be an object"
                return null
            }
            rejectUnknownKeys(source, TOKEN_SOURCE_KEYS, "auth.tokenSource", v)
            val kind = source["kind"]?.takeIf { !it.isNull }?.asString()
            when {
                kind.isNullOrBlank() -> v += "auth.tokenSource.kind is required (one of ${TOKEN_SOURCE_KINDS.joinToString(" | ")})"
                kind !in TOKEN_SOURCE_KINDS -> v += "auth.tokenSource.kind must be one of ${TOKEN_SOURCE_KINDS.joinToString(" | ")}"
            }
            val path = source["path"]?.takeIf { !it.isNull }
            when (kind) {
                TOKEN_SOURCE_FILE -> if (path == null || !path.isString() || path.asString().isBlank()) {
                    v += "auth.tokenSource.path is required for kind '$TOKEN_SOURCE_FILE' (the file holding the identity token)"
                }
                TOKEN_SOURCE_GITHUB_ACTIONS -> if (path != null) v += "auth.tokenSource.path applies to kind '$TOKEN_SOURCE_FILE' only"
            }
            return kind
        }

        /** SSO-3684 — `auth.kubernetes`: the trust's pins, each a non-empty string; the issuer an absolute https URL. */
        private fun validateKubernetesPins(auth: JsonNode, v: MutableList<String>) {
            val k = auth["kubernetes"] ?: return
            if (!k.isObject()) {
                v += "auth.kubernetes must be an object"
                return
            }
            rejectUnknownKeys(k, KUBERNETES_KEYS, "auth.kubernetes", v)
            KUBERNETES_KEYS.forEach { key ->
                k[key]?.let { n -> if (!n.isString() || n.asString().isBlank()) v += "auth.kubernetes.$key must be a non-empty string" }
            }
            k["issuer"]?.takeIf { it.isString() }?.asString()?.let { iss ->
                if (!HTTPS_URL_PATTERN.matches(iss)) v += "auth.kubernetes.issuer '$iss' must be an absolute https URL"
            }
        }

        /** An absolute http(s) URL (the loader's check; the sign-in re-validates the issuer rules). */
        private val HTTP_URL_PATTERN = Regex("^https?://[^\\s/?#]+(/[^\\s?#]*)?$")

        /** SSO-3684 — an absolute https URL (a cluster's OIDC issuer is always https). */
        private val HTTPS_URL_PATTERN = Regex("^https://[^\\s/?#]+(/[^\\s?#]*)?$")

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
