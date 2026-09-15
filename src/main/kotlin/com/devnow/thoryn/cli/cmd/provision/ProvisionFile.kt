package com.devnow.thoryn.cli.cmd.provision

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.File
import java.security.MessageDigest

/** Thrown on any provisioning-file load / parse / validation failure, or a refused plan/apply/destroy. */
internal class ProvisionException(message: String) : RuntimeException(message)

/**
 * SSO-3088 (epic SSO-3087) — one declared resource of a provisioning file: its `kind` (closed
 * allowlist), stable `name` (the converge key), the environment it lives in (an `environment`
 * resource's name in the same file, an existing slug, or `null` ⇒ the production plane), and its
 * kind-specific `spec` (forwarded to the product API).
 */
internal data class ProvisionResource(
    val kind: String,
    val name: String,
    val environment: String?,
    val spec: Map<String, Any?>,
) {
    val isSingleton: Boolean get() = kind in ProvisionFile.SINGLETON_KINDS
    val key: String get() = "$kind/$name"
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
internal class ProvisionFile private constructor(
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

        /** The CLOSED kind allowlist — must equal the schema's `kind` enum (asserted by the conformance test). */
        val KINDS: Set<String> = setOf(
            KIND_ENVIRONMENT, KIND_APPLICATION, KIND_EMAIL_PROVIDER, KIND_LOGIN_THEME,
            KIND_LOGIN_FLOW, KIND_LOGIN_METHODS, KIND_FEDERATION_MEMBER, KIND_USER,
        )

        /** One-per-environment kinds: `name` is optional (defaults to the kind) and their API is a PUT. */
        val SINGLETON_KINDS: Set<String> = setOf(KIND_EMAIL_PROVIDER, KIND_LOGIN_THEME, KIND_LOGIN_FLOW, KIND_LOGIN_METHODS)

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
        )

        val NAME_PATTERN = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        /** A `spec` property name that would carry a secret VALUE — rejected; use `<key>Env`. */
        val SECRET_KEY_PATTERN = Regex("([Pp]assword|[Ss]ecret|[Tt]oken)$")

        private val jsonMapper = JsonMapper.builder().addModule(kotlinModule()).build()
        private val yamlMapper = YAMLMapper.builder().addModule(kotlinModule()).build()

        /** The default file under [dir]/.thoryn, probing [DEFAULT_FILES] in order; null when none exists. */
        fun resolveDefault(dir: File = File(".")): File? =
            DEFAULT_FILES.map { File(dir, "$DEFAULT_DIR/$it") }.firstOrNull { it.isFile }

        /** Read, parse and validate a provisioning file; throws [ProvisionException] on any problem. */
        fun load(file: File): ProvisionFile {
            if (!file.isFile) throw ProvisionException("provisioning file not found: ${file.path}")
            val bytes = try {
                file.readBytes()
            } catch (e: Exception) {
                throw ProvisionException("could not read provisioning file '${file.path}': ${e.message}")
            }
            val yaml = !file.name.endsWith(".json", ignoreCase = true)
            return parse(bytes, file.path, yaml)
        }

        /** Parse and validate [bytes] (YAML unless [yaml] is false); [source] is used only in messages. */
        fun parse(bytes: ByteArray, source: String = "<provision>", yaml: Boolean = true): ProvisionFile {
            val root = try {
                if (yaml) yamlMapper.readTree(bytes) else jsonMapper.readTree(bytes)
            } catch (e: Exception) {
                throw ProvisionException("provisioning file '$source' is not valid ${if (yaml) "YAML" else "JSON"}: ${e.message}")
            }
            val violations = validate(root)
            if (violations.isNotEmpty()) {
                throw ProvisionException("invalid provisioning file '$source':\n  - " + violations.joinToString("\n  - "))
            }
            val resources = root["resources"].toList().map { r ->
                val kind = r["kind"].asString()
                @Suppress("UNCHECKED_CAST")
                val spec = jsonMapper.convertValue(r["spec"], Map::class.java) as Map<String, Any?>
                ProvisionResource(
                    kind = kind,
                    name = r["name"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() } ?: kind,
                    environment = r["environment"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() },
                    spec = spec,
                )
            }
            return ProvisionFile(source = source, digest = sha256(bytes), resources = resources)
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
                rejectUnknownKeys(r, setOf("kind", "name", "environment", "spec"), where, v)
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
                // SSO-3100 — `loginMethods.methods` is the FULL allow-list: a non-empty array of method tokens.
                if (kind == KIND_LOGIN_METHODS) spec["methods"]?.takeIf { it.isArray() }?.let { methods ->
                    if (methods.toList().any { !it.isTextual() || it.asString().isBlank() }) v += "$where (loginMethods) spec.methods must be a list of non-empty method names"
                }
            }
            keys.groupBy { it }.filterValues { it.size > 1 }.keys.forEach { v += "duplicate resource '$it' — kind + name must be unique" }
            return v
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
