package com.devnow.thoryn.cli.cmd.operator

import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3856 — a **platform-scopes declaration** (`.thoryn/platform-scopes.yaml`): the `platform:` scopes each
 * named machine client of the platform HOME workspace's production plane should hold, applied by an operator with
 * `thoryn operator platform-scopes apply -f <file>`.
 *
 * oathy ADR `2026-10-19-operator-grants-platform-client-scopes.md` §4: the grants a platform workload needs are
 * declared in git, in the repository that owns the workload, and reviewed like any other change; an operator
 * converges the file (read each client's scopes, add what is missing, remove what is extra). The declaration is the
 * reproducible record and the hub calls are idempotent, so a from-scratch environment converges by applying it once.
 *
 * ```yaml
 * apiVersion: thoryn.io/platform-scopes/v1
 * ticket: SSO-3857                      # optional; lands on every audit row (≤ 64 chars)
 * reason: "the provisioning service"    # optional; lands on every audit row (≤ 500 chars)
 * clients:
 *   - clientId: provisioning-m2m        # a client_credentials client of the home's production plane
 *     scopes:                           # EXACTLY the platform: scopes it should hold; [] removes every one
 *       - platform:trusted-issuers.read
 *       - platform:audit-events.append
 *     ticket: SSO-3857                  # optional per-client override of ticket / reason
 * ```
 *
 * What a file can say is deliberately narrow:
 *  - only `platform:` scopes. A client's `tenant:` and OIDC scopes belong to the customer plane (a provisioning
 *    file / the client API) and this capability never changes them; the hub refuses anything else with
 *    `400 not_a_platform_scope` anyway.
 *  - no workspace and no environment: the hub surface has no workspace segment, so the target is always the home's
 *    production plane — a file cannot name another one.
 *  - clients NOT listed are left alone. The hub offers no "list every client with a platform: scope" read, so the
 *    file converges exactly the clients it names; removing a client's grants is `scopes: []`, not deleting its entry.
 */
data class PlatformScopesFile(
    val clients: List<Client>,
    val reason: String? = null,
    val ticket: String? = null,
) {

    /** One client and the exact set of `platform:` scopes it should hold. */
    data class Client(
        val clientId: String,
        val scopes: List<String>,
        val reason: String? = null,
        val ticket: String? = null,
    )

    /** A file that cannot be applied, with every reason at once (not just the first). */
    class InvalidException(val source: String, val violations: List<String>) :
        RuntimeException("$source: ${violations.joinToString("; ")}")

    companion object {
        const val API_VERSION: String = "thoryn.io/platform-scopes/v1"

        /** Where the declaration lives in the repository that owns the workload (thoryn-provisioning, SSO-3857). */
        const val DEFAULT_PATH: String = ".thoryn/platform-scopes.yaml"

        const val NAMESPACE: String = "platform:"

        /** The hub's limits on the audit-row fields (oathy `PlatformClientScopeService`). */
        const val MAX_REASON: Int = 500
        const val MAX_TICKET: Int = 64

        /** `platform:<area>.<action>` — the shape every platform scope has. */
        private val PLATFORM_SCOPE = Regex("^platform:[a-z0-9-]+\\.[a-z0-9-]+$")

        private val ROOT_KEYS = setOf("apiVersion", "reason", "ticket", "clients")
        private val CLIENT_KEYS = setOf("clientId", "scopes", "reason", "ticket")

        private val yaml = YAMLMapper.builder().build()

        fun load(path: Path): PlatformScopesFile {
            if (!Files.isRegularFile(path)) throw InvalidException(path.toString(), listOf("no such file"))
            return parse(Files.readString(path), path.toString())
        }

        /** Parse and validate [text] (YAML, so JSON too); [source] appears only in messages. */
        fun parse(text: String, source: String = "<input>"): PlatformScopesFile {
            val root: JsonNode = try {
                yaml.readTree(text)
            } catch (e: Exception) {
                throw InvalidException(source, listOf("not valid YAML: ${e.message?.lineSequence()?.firstOrNull()}"))
            }
            if (root.isMissingNode || root.isNull) throw InvalidException(source, listOf("the file is empty"))
            if (!root.isObject) throw InvalidException(source, listOf("the file must be a mapping with apiVersion and clients"))

            val v = mutableListOf<String>()
            unknownKeys(root, ROOT_KEYS, "", v)
            val apiVersion = text(root, "apiVersion")
            if (apiVersion != API_VERSION) v += "apiVersion must be '$API_VERSION' (was ${apiVersion?.let { "'$it'" } ?: "missing"})"
            val reason = auditField(root, "reason", MAX_REASON, "", v)
            val ticket = auditField(root, "ticket", MAX_TICKET, "", v)

            val clientsNode = root["clients"]
            val clients = mutableListOf<Client>()
            when {
                clientsNode == null || clientsNode.isNull -> v += "clients is required: a list of { clientId, scopes }"
                !clientsNode.isArray -> v += "clients must be a list of { clientId, scopes }"
                clientsNode.isEmpty -> v += "clients must name at least one client"
                else -> {
                    val seen = mutableSetOf<String>()
                    clientsNode.toList().forEachIndexed { i, c ->
                        val where = "clients[$i]"
                        if (!c.isObject) { v += "$where must be a mapping { clientId, scopes }"; return@forEachIndexed }
                        unknownKeys(c, CLIENT_KEYS, "$where.", v)
                        val clientId = text(c, "clientId")
                        if (clientId == null) v += "$where.clientId is required"
                        else if (!seen.add(clientId)) v += "$where.clientId '$clientId' is declared twice"
                        val scopes = scopes(c["scopes"], "$where.scopes", v)
                        val r = auditField(c, "reason", MAX_REASON, "$where.", v)
                        val t = auditField(c, "ticket", MAX_TICKET, "$where.", v)
                        if (clientId != null && scopes != null) clients += Client(clientId, scopes, r, t)
                    }
                }
            }
            if (v.isNotEmpty()) throw InvalidException(source, v)
            return PlatformScopesFile(clients, reason, ticket)
        }

        private fun scopes(node: JsonNode?, where: String, v: MutableList<String>): List<String>? {
            if (node == null || node.isNull) {
                v += "$where is required — the exact platform: scopes the client should hold ([] to hold none)"
                return null
            }
            if (!node.isArray) { v += "$where must be a list of platform: scopes"; return null }
            val out = mutableListOf<String>()
            node.toList().forEach { s ->
                val scope = if (s.isString) s.asString().trim() else null
                when {
                    scope.isNullOrEmpty() -> v += "$where must contain only scope names"
                    !scope.startsWith(NAMESPACE) ->
                        v += "$where: '$scope' is not a platform: scope — this file manages platform: scopes only; " +
                            "a client's tenant: and OIDC scopes are declared in its provisioning file"
                    !PLATFORM_SCOPE.matches(scope) -> v += "$where: '$scope' is not a valid scope name (platform:<area>.<action>)"
                    scope in out -> v += "$where lists '$scope' twice"
                    else -> out += scope
                }
            }
            return out
        }

        private fun auditField(node: JsonNode, field: String, max: Int, prefix: String, v: MutableList<String>): String? {
            val n = node[field] ?: return null
            if (n.isNull) return null
            if (!n.isString) { v += "$prefix$field must be text"; return null }
            val value = n.asString().trim()
            if (value.length > max) v += "$prefix$field is ${value.length} characters; the hub accepts at most $max"
            return value.ifEmpty { null }
        }

        private fun text(node: JsonNode, field: String): String? =
            node[field]?.takeIf { it.isString }?.asString()?.trim()?.takeIf { it.isNotEmpty() }

        private fun unknownKeys(node: JsonNode, allowed: Set<String>, prefix: String, v: MutableList<String>) {
            node.properties().map { it.key }.filter { it !in allowed }.forEach {
                v += "$prefix$it is not a known field (allowed: ${allowed.joinToString(", ")})"
            }
        }
    }
}

/**
 * SSO-3856 — what converging one declared client means: the scopes to add, to remove, and those already right.
 * Pure — [of] compares the declaration with the hub's answer and makes no call — so the plan an operator reads is
 * exactly what `apply` then does.
 */
data class PlatformScopesPlan(
    val clientId: String,
    val live: List<String>,
    val grant: List<String>,
    val revoke: List<String>,
    val unchanged: List<String>,
) {
    val changes: Boolean get() = grant.isNotEmpty() || revoke.isNotEmpty()

    companion object {
        fun of(desired: PlatformScopesFile.Client, live: List<String>): PlatformScopesPlan {
            val liveSet = live.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
            return PlatformScopesPlan(
                clientId = desired.clientId,
                live = liveSet,
                grant = desired.scopes.filter { it !in liveSet },
                revoke = liveSet.filter { it !in desired.scopes },
                unchanged = desired.scopes.filter { it in liveSet },
            )
        }
    }
}
