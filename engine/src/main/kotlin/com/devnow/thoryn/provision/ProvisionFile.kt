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
     * `access_read_only`, it is never created, adopted, recorded in the receipt, or removed, and it may
     * be declared with only `viewer` reach (an owned resource needs `manager`).
     */
    val readOnly: Boolean = false,
    /**
     * SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) — where `apply`
     * PUBLISHES this resource's id once it is converged (see [PublishTarget]). `application` only: the
     * clientId is the one output a resource has, and it is public by construction. Empty ⇒ nothing is
     * published. Refused together with [readOnly] (a reference publishes nothing — the owner publishes).
     */
    val publishTo: List<PublishTarget> = emptyList(),
) {
    val isSingleton: Boolean get() = kind in ProvisionFile.SINGLETON_KINDS
    val key: String get() = "$kind/$name"
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
 * SSO-3088 (epic SSO-3087) — a parsed **provisioning file** (`.thoryn/provision.yaml`): the DESIRED
 * STATE of a repository's Thoryn resources, the "what I own" half of the `.thoryn/` folder next to
 * `connection.json` ("who I am", SSO-2948). DATA, not code, validated against the bundled
 * `provision.schema.json` with the same hand-rolled, message-bearing approach [Connection] uses.
 *
 * Secrets NEVER enter the file: a `spec` key that carries a secret VALUE (`password`, `smtpPassword`,
 * `clientSecret`, …) is rejected; the file names the ENV VAR instead (`passwordEnv: SMTP_PASSWORD`),
 * which the engine resolves at apply time and never records.
 */
class ProvisionFile private constructor(
    /** Where the file was read from (error messages + the receipt). */
    val source: String,
    /** `sha256:<hex>` over the raw bytes — recorded on the receipt so drift between file and receipt is visible. */
    val digest: String,
    val resources: List<ProvisionResource>,
) {
    /** The `environment` resource declared under [name], if any. */
    fun environmentResource(name: String): ProvisionResource? =
        resources.firstOrNull { it.kind == KIND_ENVIRONMENT && it.name == name }

    companion object {
        const val API_VERSION = "thoryn.io/provision/v1"

        /** Bundled schema resource — the documented contract this loader validates against. */
        const val SCHEMA_RESOURCE = "/provision/provision.schema.json"

        /** The conventional folder + the default file names probed in order by `thoryn provision`. */
        const val DEFAULT_DIR = ".thoryn"
        val DEFAULT_FILES: List<String> = listOf("provision.yaml", "provision.yml", "provision.json")

        const val KIND_ENVIRONMENT = "environment"
        const val KIND_APPLICATION = "application"
        const val KIND_EMAIL_PROVIDER = "emailProvider"
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

        /** The CLOSED kind allowlist — must equal the schema's `kind` enum (asserted by the conformance test). */
        val KINDS: Set<String> = setOf(
            KIND_ENVIRONMENT, KIND_APPLICATION, KIND_EMAIL_PROVIDER, KIND_LOGIN_THEME,
            KIND_LOGIN_FLOW, KIND_LOGIN_METHODS, KIND_FEDERATION_MEMBER, KIND_USER, KIND_CUSTOM_DOMAIN,
        )

        /**
         * One-per-environment kinds — and, SSO-3413, the one-per-WORKSPACE [KIND_CUSTOM_DOMAIN]: `name` is
         * optional (defaults to the kind) and their API is a PUT.
         */
        val SINGLETON_KINDS: Set<String> = setOf(KIND_EMAIL_PROVIDER, KIND_LOGIN_THEME, KIND_LOGIN_FLOW, KIND_LOGIN_METHODS, KIND_CUSTOM_DOMAIN)

        /** SSO-3413 — kinds that live on the WORKSPACE, not in an environment: `environment` is refused on them. */
        val WORKSPACE_KINDS: Set<String> = setOf(KIND_CUSTOM_DOMAIN)

        /** SSO-3413 — the `spec` members a `customDomain` accepts (the schema's `additionalProperties: false`). */
        val CUSTOM_DOMAIN_SPEC_KEYS: Set<String> = setOf("host", "acceptReSignIn")

        /** Required `spec` members per kind — mirrors the schema's per-kind `then.required`. */
        val REQUIRED_SPEC: Map<String, Set<String>> = mapOf(
            KIND_ENVIRONMENT to setOf("slug"),
            KIND_APPLICATION to setOf("displayName"),
            KIND_USER to setOf("email"),
            KIND_FEDERATION_MEMBER to setOf("providerType"),
            KIND_EMAIL_PROVIDER to setOf("smtpHost"),
            KIND_LOGIN_FLOW to setOf("templateId"),
            KIND_LOGIN_THEME to emptySet(),
            KIND_LOGIN_METHODS to setOf("methods"),
            KIND_CUSTOM_DOMAIN to setOf("host"),
        )

        val NAME_PATTERN = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        /** A `spec` property name that would carry a secret VALUE — rejected; use `<key>Env`. */
        val SECRET_KEY_PATTERN = Regex("([Pp]assword|[Ss]ecret|[Tt]oken)$")

        /** SSO-3113 — the relations a `grants:` entry may carry (the SSO-3112 contract; equals the schema enum). */
        val GRANT_RELATIONS: Set<String> = AccessRefs.RELATIONS

        /** SSO-3659 — the resource-level `readOnly` flag (ADR 2026-10-13 §1): a dependency, not an owned resource. */
        const val READ_ONLY = "readOnly"

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
            return parse(bytes, file.path, yaml, env)
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
         */
        fun parse(
            bytes: ByteArray,
            source: String = "<provision>",
            yaml: Boolean = true,
            env: ((String) -> String?)? = null,
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
                val spec = jsonMapper.convertValue(r["spec"], Map::class.java) as Map<String, Any?>
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
                    publishTo = r[PUBLISH_TO]?.takeIf { it.isArray() }?.toList()?.map { t ->
                        PublishTarget(
                            kind = t["kind"].asString().trim(),
                            repository = t["repository"].asString().trim(),
                            environment = t["environment"].asString().trim(),
                            name = t["name"].asString().trim(),
                        )
                    } ?: emptyList(),
                )
            }
            if (unresolved.isNotEmpty()) {
                throw ProvisionException("invalid provisioning file '$source':\n  - " + unresolved.joinToString("\n  - "))
            }
            return ProvisionFile(source = source, digest = sha256(bytes), resources = resources)
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
            if (root["apiVersion"]?.asString() != API_VERSION) v += "apiVersion must be '$API_VERSION'"

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
                rejectUnknownKeys(r, setOf("kind", "name", "environment", "spec", "grants", READ_ONLY, PUBLISH_TO), where, v)
                // SSO-3659 — `readOnly: true` declares a dependency, not ownership: a boolean, and never with `grants`
                // (a grant is a write on the object; a reference writes nothing).
                r[READ_ONLY]?.takeIf { !it.isNull }?.let { ro ->
                    if (!ro.isBoolean()) v += "$where $READ_ONLY must be true or false"
                    else if (ro.asBoolean() && r["grants"]?.takeIf { !it.isNull } != null) v += "$where a read-only reference cannot carry 'grants' — this repository does not own it"
                }
                val kind = r["kind"]?.takeIf { !it.isNull }?.asString()
                if (kind == null || kind !in KINDS) {
                    v += "$where kind '$kind' not in the allowlist $KINDS"
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
                            else if (relation !in GRANT_RELATIONS) v += "$gw relation '$relation' must be one of ${GRANT_RELATIONS.joinToString(", ")}"
                            if (subject != null && relation != null && !seen.add("$subject $relation")) v += "$gw duplicates grant '$subject $relation'"
                        }
                    }
                }
                // SSO-3668 — `publishTo`: on an application only, never on a read-only reference, each target
                // exactly { kind, repository, environment, name } with a closed kind, GitHub grammar, no duplicates.
                r[PUBLISH_TO]?.takeIf { !it.isNull }?.let { targets -> validatePublishTo(targets, kind, r, where, v) }
                // SSO-3413 — `customDomain`: exactly { host, acceptReSignIn? }.
                if (kind == KIND_CUSTOM_DOMAIN) {
                    rejectUnknownKeys(spec, CUSTOM_DOMAIN_SPEC_KEYS, "$where spec", v)
                    spec["host"]?.takeIf { !it.isNull && !it.isTextual() }?.let { v += "$where (customDomain) spec.host must be a host name" }
                    spec["acceptReSignIn"]?.takeIf { !it.isNull && !it.isBoolean() }?.let { v += "$where (customDomain) spec.acceptReSignIn must be true or false" }
                }
                // SSO-3100 — `loginMethods.methods` is the FULL allow-list: a non-empty array of method tokens.
                if (kind == KIND_LOGIN_METHODS) spec["methods"]?.takeIf { it.isArray() }?.let { methods ->
                    if (methods.toList().any { !it.isTextual() || it.asString().isBlank() }) v += "$where (loginMethods) spec.methods must be a list of non-empty method names"
                }
            }
            keys.groupBy { it }.filterValues { it.size > 1 }.keys.forEach { v += "duplicate resource '$it' — kind + name must be unique" }
            return v
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
