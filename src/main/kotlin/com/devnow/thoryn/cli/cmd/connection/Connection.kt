package com.devnow.thoryn.cli.cmd.connection

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
 * DATA, not code: the secret is NEVER in the file, only the [secretEnv] name. This class parses and
 * structurally validates against the bundled schema's contract (no third-party JSON-Schema engine —
 * the same hand-rolled, message-bearing approach the recipe suite uses); [load]/[parse] throw
 * [ConnectionException] with a clear, aggregated message on any violation.
 */
internal class Connection private constructor(
    /** Workspace slug — derives `https://<slug>.hub.<env>` and the matching gateway. */
    val slug: String,
    /** NAME of the env var holding the hub base URL (default [DEFAULT_HUB_BASE_URL_ENV]). */
    val hubBaseUrlEnv: String,
    /** OAuth client id of the machine client (public). */
    val clientId: String,
    /** NAME of the env var holding the client secret (never the value). */
    val secretEnv: String,
    /** The EXACT scope set to request — ceiling and floor. */
    val scopes: List<String>,
) {

    companion object {
        const val API_VERSION = "thoryn.io/connection/v1"
        const val AUTH_METHOD_CLIENT_CREDENTIALS = "client_credentials"

        /** Default env var naming the hub base URL when `workspace.hubBaseUrlEnv` is omitted. */
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
            return Connection(
                slug = workspace["slug"].asString(),
                hubBaseUrlEnv = hubEnv,
                clientId = auth["clientId"].asString(),
                secretEnv = auth["secretEnv"].asString(),
                scopes = auth["scopes"].toList().map { it.asString() },
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
                rejectUnknownKeys(auth, setOf("method", "clientId", "secretEnv", "scopes"), "auth", v)
                if (auth["method"]?.asString() != AUTH_METHOD_CLIENT_CREDENTIALS) {
                    v += "auth.method must be '$AUTH_METHOD_CLIENT_CREDENTIALS'"
                }
                if (auth["clientId"]?.takeIf { !it.isNull }?.asString().isNullOrBlank()) {
                    v += "auth.clientId is required"
                }
                val secretEnv = auth["secretEnv"]?.takeIf { !it.isNull }?.asString()
                when {
                    secretEnv.isNullOrBlank() -> v += "auth.secretEnv is required"
                    !ENV_NAME_PATTERN.matches(secretEnv) -> v += "auth.secretEnv '$secretEnv' must match ${ENV_NAME_PATTERN.pattern}"
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
