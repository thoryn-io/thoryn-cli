package com.devnow.thoryn.cli.cmd.provision.workflow

import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File

/**
 * SSO-3719 — `.thoryn/workflow.yaml`: the RUN-TIME configuration of the reusable provisioning workflow. Committed, DATA,
 * schema-documented (`examples/workflow.schema.json`), validated here with the same hand-rolled, message-bearing
 * validation the connection contract uses (no JSON-Schema engine). The reusable workflow reads it through
 * `thoryn provision workflow check --output json` and acts on the `config` object it prints: which provisioning files
 * to plan/apply with which connection, the CLI's environment variables, whether to upload the fix request, and the
 * apply-time toggles.
 *
 * Everything a repository legitimately varies is a key here or an input of the reusable workflow (the stub's `with:`);
 * nothing is a script. Unknown keys are refused — a key that is not here is a product gap to record, not a hole to
 * write shell into.
 *
 *  - `files` — one or MANY `{file, connection}` pairs (a production file + sandbox files; a connection defaults to the
 *    `connection.json` beside its file, the layout the Thoryn GitHub App seeds). Planned and applied in order.
 *  - `env` — extra environment variables for the CLI: ALLOW-LISTED NAMES ONLY (`THORYN_*`, not one the workflow itself
 *    sets, never credential-shaped — this file is committed plaintext). Serves `{{env.NAME}}` placeholders in a
 *    provisioning file (SSO-3430) and the CLI's own documented variables. Values are exported, never evaluated.
 *  - `fixRequest` — upload the SSO-3710 fix request on a red job (default true).
 *  - `consentUrl` — SSO-3723: the base URL of the Thoryn GitHub App's browser consent, so a red job's "To fix — Option 2,
 *    in the browser" is a link resolvable by run (`<consentUrl>/github/consent/run/<owner>/<repo>/<run_id>`). Exported to
 *    the CLI as `THORYN_CONSENT_URL` when the reusable workflow's `consent-url` input is empty. Configuration — the CLI
 *    never guesses it from the issuer. Absent ⇒ Option 1 alone.
 *  - `apply.prune` / `apply.destroy` / `apply.confirm` — removals, NEVER on by default: `prune` passes `--prune` to the
 *    apply; `destroy` runs `provision destroy` after a successful apply (an ephemeral fixture); `confirm` is the workspace
 *    slug a production-plane removal needs (the SSO-2413 gate).
 *  - `provider` — the forge the identity token comes from. `github_actions` only: a Forgejo trust exists on the hub
 *    (oauthy ADR Amendment 3) but `thoryn login --connection` cannot exchange a Forgejo job token yet — a recorded gap.
 */
class WorkflowConfig private constructor(
    val provider: String,
    val files: List<FileEntry>,
    val env: Map<String, String>,
    val fixRequest: Boolean,
    /** SSO-3723 — the consent base URL (`THORYN_CONSENT_URL` for the CLI), or null. */
    val consentUrl: String?,
    val prune: Boolean,
    val destroy: Boolean,
    val confirm: String?,
    /** Where it was read from, or null for the built-in default. */
    val source: String?,
) {
    data class FileEntry(val file: String, val connection: String)

    /** The `config` object the reusable workflow consumes. */
    fun toStructured(): Map<String, Any?> = linkedMapOf(
        "apiVersion" to API_VERSION,
        "source" to source,
        "provider" to provider,
        "files" to files.map { linkedMapOf("file" to it.file, "connection" to it.connection) },
        "env" to env,
        "fixRequest" to fixRequest,
        "consentUrl" to (consentUrl ?: ""),
        "apply" to linkedMapOf("prune" to prune, "destroy" to destroy, "confirm" to (confirm ?: "")),
    )

    companion object {
        const val API_VERSION = "thoryn.io/workflow/v1"
        const val DEFAULT_PATH = ".thoryn/workflow.yaml"
        const val DEFAULT_FILE = ".thoryn/provision.yaml"
        const val DEFAULT_CONNECTION = ".thoryn/connection.json"
        const val SCHEMA_RESOURCE = "/examples/workflow.schema.json"
        const val PROVIDER_GITHUB_ACTIONS = "github_actions"
        val PROVIDERS: List<String> = listOf(PROVIDER_GITHUB_ACTIONS)

        /** A relative path inside the repository: no leading `/`, no `..` segment, no whitespace, no expression. */
        val PATH_GRAMMAR = Regex("^(?!/)(?!.*(^|/)\\.\\.(/|$))[A-Za-z0-9_./@-]{1,512}$")
        val ENV_NAME_GRAMMAR = Regex("^THORYN_[A-Z0-9_]{1,120}$")
        /** A committed value must never be a credential. */
        val CREDENTIAL_SHAPED_NAME = Regex("(_SECRET|_PASSWORD|_TOKEN|_KEY|_API_KEY)$")
        val WORKSPACE_SLUG_GRAMMAR = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
        const val MAX_ENV_VALUE_LENGTH = 1024

        /** Variables the reusable workflow sets itself (from its inputs and its own steps) — a config may not shadow them. */
        val WORKFLOW_OWNED_ENV: Set<String> = setOf("THORYN_ISSUER", "THORYN_HUB", "THORYN_FIX_REQUEST", "THORYN_CONSENT_URL", "THORYN_CI_PLAINTEXT_TOKENS")

        /** SSO-3723 — an absolute https URL without query or fragment (an origin, or an origin plus a path). */
        val CONSENT_URL_GRAMMAR = Regex("^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")

        private val TOP_KEYS = setOf("apiVersion", "provider", "files", "env", "fixRequest", "consentUrl", "apply")
        private val FILE_KEYS = setOf("file", "connection")
        private val APPLY_KEYS = setOf("prune", "destroy", "confirm")

        private val yaml = YAMLMapper.builder().build()

        /** The configuration a repository without a `.thoryn/workflow.yaml` runs with. */
        fun defaults(): WorkflowConfig = WorkflowConfig(
            provider = PROVIDER_GITHUB_ACTIONS,
            files = listOf(FileEntry(DEFAULT_FILE, DEFAULT_CONNECTION)),
            env = emptyMap(),
            fixRequest = true,
            consentUrl = null,
            prune = false,
            destroy = false,
            confirm = null,
            source = null,
        )

        /** Parse a document; the first problem is a [WorkflowConfigException] naming the key and its fix. */
        fun parse(text: String, source: String? = null): WorkflowConfig {
            val root = try { yaml.readTree(text) } catch (ex: Exception) {
                throw WorkflowConfigException("$source is not valid YAML: ${ex.message?.lineSequence()?.first()}")
            }
            val errors = validate(root)
            if (errors.isNotEmpty()) throw WorkflowConfigException("${source ?: "workflow config"}: " + errors.joinToString("; "))
            val files: List<FileEntry> = root["files"]?.toList()?.map { FileEntry(it["file"].asString(), it["connection"]?.asString() ?: connectionBeside(it["file"].asString())) }
                ?: listOf(FileEntry(DEFAULT_FILE, DEFAULT_CONNECTION))
            val env = root["env"]?.properties()?.associate { it.key to it.value.asString() } ?: emptyMap()
            val apply = root["apply"]
            return WorkflowConfig(
                provider = root["provider"]?.asString() ?: PROVIDER_GITHUB_ACTIONS,
                files = files,
                env = env,
                fixRequest = root["fixRequest"]?.asBoolean() ?: true,
                consentUrl = root["consentUrl"]?.asString()?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() },
                prune = apply?.get("prune")?.asBoolean() ?: false,
                destroy = apply?.get("destroy")?.asBoolean() ?: false,
                confirm = apply?.get("confirm")?.asString()?.takeIf { it.isNotEmpty() },
                source = source,
            )
        }

        /** [parse] the file (reported as [display]), or [defaults] when it does not exist. */
        fun load(file: File, display: String = file.path): WorkflowConfig = if (file.isFile) parse(file.readText(), display) else defaults()

        /** The App's layout: `connection.json` beside the provisioning file. */
        fun connectionBeside(file: String): String {
            val dir = file.substringBeforeLast('/', missingDelimiterValue = "")
            return if (dir.isEmpty()) "connection.json" else "$dir/connection.json"
        }

        /**
         * Every problem in [root], each naming its key and the fix — the schema's constraints, enforced. Unknown keys are
         * refused at every level: a key that is not in the contract is a gap to record, not a shell to write.
         */
        fun validate(root: JsonNode?): List<String> {
            val errors = mutableListOf<String>()
            if (root == null || !root.isObject) return listOf("the document must be a YAML mapping with apiVersion: $API_VERSION")
            root.propertyNames().filter { it !in TOP_KEYS }.forEach { errors += "unknown key '$it' — allowed: ${TOP_KEYS.sorted().joinToString(", ")} (a knob that is not here is a product gap to report, not a script to write)" }
            when (val v = root["apiVersion"]) {
                null -> errors += "apiVersion is required: $API_VERSION"
                else -> if (v.asString() != API_VERSION) errors += "apiVersion must be $API_VERSION (was ${v.asString()})"
            }
            root["provider"]?.let { p ->
                if (!p.isString || p.asString() !in PROVIDERS) {
                    errors += "provider must be one of ${PROVIDERS.joinToString(", ")} (was ${p.asString()})" +
                        if (p.asString() == "forgejo") " — a Forgejo job token cannot be exchanged by `thoryn login --connection` yet; recorded as a product gap (SSO-3719)" else ""
                }
            }
            root["files"]?.let { files ->
                if (!files.isArray || files.isEmpty) errors += "files must be a non-empty list of { file, connection } entries"
                else files.toList().forEachIndexed { i, entry ->
                    if (!entry.isObject) { errors += "files[$i] must be a mapping { file, connection }"; return@forEachIndexed }
                    entry.propertyNames().filter { it !in FILE_KEYS }.forEach { errors += "files[$i]: unknown key '$it' — allowed: file, connection" }
                    val file = entry["file"]
                    if (file == null || !file.isString || !PATH_GRAMMAR.matches(file.asString())) errors += "files[$i].file must be a relative path inside the repository (no leading /, no ..)"
                    entry["connection"]?.let { c -> if (!c.isString || !PATH_GRAMMAR.matches(c.asString())) errors += "files[$i].connection must be a relative path inside the repository (no leading /, no ..)" }
                }
                val paths = files.toList().mapNotNull { it["file"]?.asString() }
                paths.groupBy { it }.filter { it.value.size > 1 }.keys.forEach { errors += "files: '$it' is listed more than once" }
            }
            root["env"]?.let { env ->
                if (!env.isObject) errors += "env must be a mapping of THORYN_* variable names to string values"
                else env.properties().forEach { (name, value) ->
                    when {
                        !ENV_NAME_GRAMMAR.matches(name) -> errors += "env.$name: only THORYN_* names (upper case, digits, _) are allowed — the CLI's own variables and the {{env.NAME}} placeholders a provisioning file reads"
                        name in WORKFLOW_OWNED_ENV -> errors += "env.$name is set by the reusable workflow itself (from its inputs) and cannot be overridden here — use the stub's `with:`"
                        CREDENTIAL_SHAPED_NAME.containsMatchIn(name) -> errors += "env.$name looks like a credential — this file is committed plaintext; a secret is never configuration (the identity is the job's own OIDC token)"
                    }
                    if (!value.isString && !value.isNumber && !value.isBoolean) errors += "env.$name must be a scalar"
                    else if (value.asString().contains('\n') || value.asString().length > MAX_ENV_VALUE_LENGTH) errors += "env.$name must be a single line of at most $MAX_ENV_VALUE_LENGTH characters"
                }
            }
            root["fixRequest"]?.let { if (!it.isBoolean) errors += "fixRequest must be true or false" }
            root["consentUrl"]?.let { if (!it.isString || (it.asString().isNotEmpty() && !CONSENT_URL_GRAMMAR.matches(it.asString().trimEnd('/')))) errors += "consentUrl must be an https:// base URL of the Thoryn GitHub App's consent page (no query or fragment), or empty" }
            root["apply"]?.let { apply ->
                if (!apply.isObject) errors += "apply must be a mapping { prune, destroy, confirm }"
                else {
                    apply.propertyNames().filter { it !in APPLY_KEYS }.forEach { errors += "apply: unknown key '$it' — allowed: prune, destroy, confirm" }
                    apply["prune"]?.let { if (!it.isBoolean) errors += "apply.prune must be true or false" }
                    apply["destroy"]?.let { if (!it.isBoolean) errors += "apply.destroy must be true or false" }
                    apply["confirm"]?.let { if (!it.isString || (it.asString().isNotEmpty() && !WORKSPACE_SLUG_GRAMMAR.matches(it.asString()))) errors += "apply.confirm must be the workspace slug (lower-case letters, digits, -) or empty" }
                }
            }
            return errors
        }
    }
}

class WorkflowConfigException(message: String) : RuntimeException(message)
