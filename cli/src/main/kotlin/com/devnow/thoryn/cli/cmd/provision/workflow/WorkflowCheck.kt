package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.APPLY_JOB_MARKER
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.CONCURRENCY_MODE_FRAGMENT
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.DISPATCH_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.ALLOWED_MODE_OPTIONS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FIX_REQUEST_ARTIFACT
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.IMPORT_ARTIFACT
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.IMPORT_MODE
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.JOB_PERMISSIONS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.MINIMUM_RELEASE
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.REUSABLE_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.REUSABLE_WORKFLOW
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.RUN_NAME_MARKER
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.STUB_REQUIRED_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.forwarded
import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.connection.ConnectionException
import com.devnow.thoryn.cli.cmd.provision.TrustScopes
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File

/**
 * SSO-3719 — the RULE ENGINE behind `thoryn provision workflow check` and the dogfood conformance tests: evaluates a
 * workflow file against [ProvisioningWorkflowContract], rule by rule, each verdict carrying the exact fix.
 *
 * Three shapes, detected from the document:
 *  - [Shape.STUB] — the SUPPORTED shape: `workflow_dispatch` with the App's inputs and one job that `uses:` the reusable
 *    workflow at a release. Rules: the dispatch contract (`dispatch.*`), the stub (`stub.*`), the config (`config.*`).
 *  - [Shape.REUSABLE] — the reusable workflow itself (`on: workflow_call`), evaluated as the CALLED side of the contract
 *    (`reusable.*`): how `provisioning.yml` is held to what the stub relies on.
 *  - [Shape.CUSTOM] — a hand-written workflow with its own jobs: NOT the supported shape. The check reports only what the
 *    App needs to dispatch it (`dispatch.*`, `custom.*`) and says so; it is documented as unsupported, not promoted.
 *  A `uses:` of a workflow that is not ours is [Shape.FOREIGN_STUB]: nothing can be verified about the called side.
 *
 * Contract v2 (SSO-3991): a stub's `mode` may also offer `import`. `dispatch.import-capable` says whether the App may
 * dispatch `import` to the file ([Report.importCapable]) — and FAILS a file that offers `import` but could not honour it,
 * because an import dispatched to a reusable workflow without the `import` job runs zero jobs and reports green.
 */
object WorkflowCheck {

    enum class Shape(val label: String, val supported: Boolean) {
        STUB("stub calling the reusable workflow", true),
        REUSABLE("the reusable workflow (called side)", true),
        CUSTOM("hand-written workflow — not the supported shape", false),
        FOREIGN_STUB("stub calling a workflow that is not thoryn-io/thoryn-cli's", false),
    }

    enum class Status { PASS, FAIL, UNVERIFIABLE }

    data class RuleResult(
        val id: String,
        val title: String,
        val status: Status,
        val detail: String,
        val fix: String? = null,
        /** `dispatch.import-capable` / `reusable.import-job` only: the file offers (or carries) `import`. */
        val offersImport: Boolean = false,
    ) {
        val failed: Boolean get() = status != Status.PASS
    }

    class Report(
        val file: String,
        val shape: Shape,
        val rules: List<RuleResult>,
        /** The stub's `with:` values, effective (defaults filled in) — null for the other shapes. */
        val inputs: Map<String, String>?,
        val config: WorkflowConfig?,
        val configError: String?,
    ) {
        val ok: Boolean get() = rules.none { it.failed } && configError == null
        val supported: Boolean get() = shape.supported

        /**
         * SSO-3991 (contract v2 §1) — may the App dispatch `mode: import` to this file? Only when it offers `import` (a
         * dispatched workflow) or carries the `import` job (the reusable workflow) AND the rule that pins it passes. A v1
         * stub is never import-capable; the App relies on this ("dispatch import only to a stub that offers it").
         */
        val importCapable: Boolean
            get() = rules.any { (it.id == IMPORT_CAPABLE_RULE || it.id == IMPORT_JOB_RULE) && it.status == Status.PASS && it.offersImport }

        fun toStructured(): Map<String, Any?> = linkedMapOf(
            "contractVersion" to ProvisioningWorkflowContract.CONTRACT_VERSION,
            "file" to file,
            "shape" to shape.name.lowercase(),
            "supported" to supported,
            "ok" to ok,
            "importCapable" to importCapable,
            "rules" to rules.map { r -> linkedMapOf("id" to r.id, "title" to r.title, "status" to r.status.name, "detail" to r.detail, "fix" to r.fix) },
            "inputs" to inputs,
            "config" to config?.toStructured(),
            "configError" to configError,
        )
    }

    private val yaml = YAMLMapper.builder().build()

    /** SSO-3991 — the rule that says whether the App may dispatch `import` to a dispatched workflow. */
    const val IMPORT_CAPABLE_RULE: String = "dispatch.import-capable"

    /** SSO-3991 — the rule that pins the reusable workflow's `import` job. */
    const val IMPORT_JOB_RULE: String = "reusable.import-job"

    /**
     * Evaluate [text] (the workflow at [path]). [configFile] is the run-time configuration a stub / the reusable workflow
     * reads (absent ⇒ defaults); [root] lets the check confirm the configured files exist (null ⇒ not checked).
     */
    fun evaluate(text: String, path: String, configFile: File? = null, root: File? = null): Report {
        val doc: JsonNode = try { yaml.readTree(text) } catch (ex: Exception) {
            return Report(path, Shape.CUSTOM, listOf(RuleResult("workflow.yaml", "the file is YAML", Status.FAIL, "not valid YAML: ${ex.message?.lineSequence()?.first()}", "fix the YAML syntax")), null, null, null)
        }
        if (doc == null || !doc.isObject) {
            return Report(path, Shape.CUSTOM, listOf(RuleResult("workflow.yaml", "the file is a workflow", Status.FAIL, "the document is not a mapping", "a GitHub Actions workflow is a YAML mapping with on:, jobs:")), null, null, null)
        }
        val shape = shapeOf(doc)
        val rules = mutableListOf<RuleResult>()
        var inputs: Map<String, String>? = null
        var config: WorkflowConfig? = null
        var configError: String? = null
        when (shape) {
            Shape.REUSABLE -> {
                rules += reusableRules(doc, text)
                rules += commonRules(doc, text)
            }
            Shape.STUB -> {
                rules += dispatchRules(doc, text)
                val (stubRules, effective) = stubRules(doc)
                rules += stubImportCapableRule(doc, effective)
                rules += stubRules
                inputs = effective
                rules += commonRules(doc, text)
            }
            Shape.FOREIGN_STUB -> {
                rules += dispatchRules(doc, text)
                rules += if (IMPORT_MODE in offeredModes(doc)) {
                    RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.UNVERIFIABLE, "the stub offers `import`, but the workflow it calls is not $REUSABLE_WORKFLOW — nothing says it has an `import` job", "call $REUSABLE_WORKFLOW@$IMPORT_MINIMUM_RELEASE (or newer), or drop `import` from `mode`'s options", offersImport = true)
                } else {
                    notOffered()
                }
                val job = singleUsesJob(doc)!!
                rules += RuleResult(
                    "stub.uses", "the stub calls the reusable workflow", Status.UNVERIFIABLE,
                    "cannot verify a called workflow: `${job["uses"].asString()}` is not $REUSABLE_WORKFLOW — run the check on that file.",
                    "use: $REUSABLE_WORKFLOW@$MINIMUM_RELEASE (or newer) — the supported shape; a foreign reusable workflow is hand-written code the App cannot vouch for.",
                )
                rules += commonRules(doc, text)
            }
            Shape.CUSTOM -> {
                rules += dispatchRules(doc, text)
                rules += customImportCapableRule(doc)
                rules += customRules(doc)
                rules += commonRules(doc, text)
            }
        }
        if (shape == Shape.STUB || shape == Shape.REUSABLE) {
            val configRelative = inputs?.get("config") ?: WorkflowConfig.DEFAULT_PATH
            val configPath = configFile ?: (if (root != null) File(root, configRelative) else File(configRelative))
            val configDisplay = configFile?.let { f -> root?.let { r -> f.absoluteFile.normalize().relativeToOrNull(r.absoluteFile.normalize())?.path } ?: f.path } ?: configRelative
            try {
                config = WorkflowConfig.load(configPath, configDisplay)
                val configured = if (root != null) ConfiguredFiles.load(config, root) else null
                rules += configValidRule(config, configured)
                if (configured != null && config.files.isNotEmpty()) {
                    rules += secretDeliveryRule(config, configured)
                    rules += trustScopesRule(config, configured)
                }
            } catch (ex: WorkflowConfigException) {
                configError = ex.message
                rules += RuleResult("config.valid", "the run-time configuration is valid", Status.FAIL, ex.message ?: "invalid", "fix $configDisplay — schema: examples/workflow.schema.json (unknown keys are refused: a knob that is not there is a product gap to report)")
            }
        }
        return Report(path, shape, rules, inputs, config, configError)
    }

    /**
     * SSO-3970 — every file `.thoryn/workflow.yaml` lists (each `files[].file` and its `files[].connection`), loaded ONCE
     * with the same loaders `thoryn provision plan` and `thoryn login --connection` use. A file that is missing or does not
     * load is recorded with the loader's reason; the rules below never skip it silently. [files] / [connections] hold what
     * loaded, keyed by the configured path.
     */
    internal class ConfiguredFiles private constructor(
        val files: Map<String, ProvisionFile>,
        val connections: Map<String, Connection>,
        /** Configured paths that are not in the repository. */
        val missing: List<String>,
        /** Configured paths that exist but do not load, each with the loader's reason. */
        val unloadable: Map<String, String>,
    ) {
        /** Configured paths that could not be read, for any reason. */
        val notLoaded: List<String> get() = missing + unloadable.keys

        companion object {
            fun load(config: WorkflowConfig, root: File): ConfiguredFiles {
                val files = linkedMapOf<String, ProvisionFile>()
                val connections = linkedMapOf<String, Connection>()
                val missing = mutableListOf<String>()
                val unloadable = linkedMapOf<String, String>()
                config.files.map { it.file }.distinct().forEach { path ->
                    val f = File(root, path)
                    if (!f.isFile) { missing += path; return@forEach }
                    try {
                        files[path] = ProvisionFile.parse(f.readBytes(), path, yaml = !f.name.endsWith(".json", ignoreCase = true))
                    } catch (ex: ProvisionException) {
                        unloadable[path] = oneLine(ex.message ?: "does not load")
                    }
                }
                config.files.map { it.connection }.distinct().forEach { path ->
                    val c = File(root, path)
                    if (!c.isFile) { if (path !in missing) missing += path; return@forEach }
                    try {
                        connections[path] = Connection.parse(c.readBytes(), path)
                    } catch (ex: ConnectionException) {
                        unloadable[path] = oneLine(ex.message ?: "does not load")
                    }
                }
                return ConfiguredFiles(files, connections, missing, unloadable)
            }

            /** A loader's message (a header line, then `  - violation` lines) as one line: `header violation; violation`. */
            private fun oneLine(message: String): String {
                val lines = message.lines().map { it.trim() }.filter { it.isNotEmpty() }
                val head = lines.firstOrNull() ?: return message
                val rest = lines.drop(1).map { it.removePrefix("- ") }
                return if (rest.isEmpty()) head else "$head ${rest.joinToString("; ")}"
            }
        }
    }

    private const val CONFIG_VALID_TITLE = "the run-time configuration is valid"

    /**
     * `config.valid` — the configuration parsed (a [WorkflowConfigException] is reported by the caller) AND every file it
     * lists is in the repository and loads. SSO-3970: a configured file that does not load used to pass here and silently
     * drop the rules that read it, so a broken project printed "OK". Now each one fails this rule, named with the loader's
     * reason. A configuration listing no file says so in the detail. [configured] null ⇒ no repository root to resolve
     * the files against (the rule engine's unit tests): only the configuration itself is judged.
     */
    private fun configValidRule(config: WorkflowConfig, configured: ConfiguredFiles?): RuleResult {
        val summary = (config.source ?: "no ${WorkflowConfig.DEFAULT_PATH} — built-in defaults") +
            ": ${config.files.size} file(s), ${config.env.size} env var(s), fixRequest=${config.fixRequest}, prune=${config.prune}, destroy=${config.destroy}"
        if (config.files.isEmpty()) return RuleResult("config.valid", CONFIG_VALID_TITLE, Status.PASS, "$summary — no provisioning files configured, so there is nothing to plan or apply")
        if (configured == null || configured.notLoaded.isEmpty()) {
            return RuleResult("config.valid", CONFIG_VALID_TITLE, Status.PASS, summary + if (configured != null) " — every configured file loads" else "")
        }
        val source = config.source ?: WorkflowConfig.DEFAULT_PATH
        val problems = mutableListOf<String>()
        val fixes = mutableListOf<String>()
        if (configured.missing.isNotEmpty()) {
            problems += "configured file(s) not found in the repository: ${configured.missing.joinToString(", ")}"
            fixes += "commit them, or point `files[].file` / `files[].connection` in $source at the committed paths"
        }
        configured.unloadable.forEach { (path, reason) -> problems += "$path does not load: $reason" }
        if (configured.unloadable.isNotEmpty()) {
            fixes += "correct ${configured.unloadable.keys.joinToString(", ")} — `thoryn provision plan --file <file>` and `thoryn login --connection <connection>` report the same problems"
        }
        val loadedCount = configured.files.size
        val head = if (loadedCount == 0) "no configured provisioning file loads, so nothing can be planned or applied" else "$loadedCount of ${config.files.map { it.file }.distinct().size} configured provisioning file(s) load"
        return RuleResult("config.valid", CONFIG_VALID_TITLE, Status.FAIL, "$head; " + problems.joinToString("; "), fixes.joinToString("; "))
    }

    /** The detail suffix a file-reading rule carries when some configured file could not be read. */
    private fun notChecked(paths: List<String>): String = "not checked: ${paths.joinToString(", ")} could not be loaded (see config.valid)"

    /**
     * SSO-3921 / SSO-3954 — `config.secret-delivery`: the reusable workflow's apply job runs on a hosted runner with no
     * kubeconfig, no `--secret-file` and no TTY. A confidential application that MINTS a secret on create (`client_secret_basic`,
     * or no declared method) is created green there because, since SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25,
     * SSO-3951), **the customer manages its secret by default**: with no `secretSink` — or `secretSink: { kind:
     * customerManaged }` — `apply` discards the create's one-time value, grants nothing, and a person mints the secret the
     * runtime gets (`thoryn clients rotate-secret <clientId> --secret-file …`) and stores it in the customer's own secret
     * infrastructure. The rule PASSES such a file and says so (the notice is where the semantics are explained). Still red:
     * a `kubernetesSecret` sink has no cluster to reach on that runner, and a `file` sink writes onto a runner that is gone
     * when the job ends — green, and the secret lost all the same. A `workloadPull` sink (SSO-3921, rung 3) passes but is
     * reported DEPRECATED (SSO-3951 / SSO-3953). A `readOnly` reference, a public client and a secret-less one
     * (`private_key_jwt`, `federated_assertion`) mint nothing and pass.
     *
     * SSO-3970: a configured file that does not load cannot be checked, so this rule FAILS naming it (the reason is on
     * `config.valid`) — it never passes on the files that did load, and never disappears.
     */
    private fun secretDeliveryRule(config: WorkflowConfig, configured: ConfiguredFiles): RuleResult {
        val title = "a CI apply can create every declared application"
        val problems = mutableListOf<String>()
        val notices = mutableListOf<String>()
        val blocked = mutableListOf<String>()
        config.files.map { it.file }.distinct().forEach { path ->
            val file = configured.files[path] ?: run { blocked += path; return@forEach }
            file.resources.filter { it.kind == ProvisionFile.KIND_APPLICATION && !it.readOnly && mintsSecret(it.spec) }.forEach { r ->
                val sink = r.effectiveSecretSink ?: return@forEach
                when (sink.kind) {
                    ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED -> notices += "$path application ${r.name}: its client secret is managed by the customer" +
                        (if (r.secretSink == null) " (no secretSink — the default)" else " (secretSink customerManaged)") +
                        " — apply discards the create's value; ${ProvisionFile.CUSTOMER_MANAGED_RUNBOOK}"
                    ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL -> notices += "$path application ${r.name}: ${ProvisionFile.WORKLOAD_PULL_DEPRECATION}"
                    ProvisionFile.SECRET_SINK_KIND_KUBERNETES_SECRET -> problems += "$path application ${r.name} delivers its secret to ${sink.label} — the apply job's runner has no kubeconfig, so it cannot reach a cluster (undelivered_secrets, exit 65)"
                    else -> problems += "$path application ${r.name} delivers its secret to ${sink.label} — the file lands on the runner and is gone when the job ends: green, and the secret lost"
                }
            }
        }
        if (blocked.isNotEmpty()) {
            return RuleResult(
                "config.secret-delivery", title, Status.FAIL, (listOf(notChecked(blocked)) + problems + notices).joinToString("; "),
                "make config.valid pass, then run the check again" + if (problems.isNotEmpty()) "; and drop the `secretSink:` of the applications named above" else "",
            )
        }
        return if (problems.isEmpty()) {
            RuleResult(
                "config.secret-delivery", title, Status.PASS,
                if (notices.isEmpty()) "no application in the configured file(s) is minted a secret the job would have to deliver" else notices.joinToString("; "),
            )
        } else {
            RuleResult(
                "config.secret-delivery", title, Status.FAIL, (problems + notices).joinToString("; "),
                "drop the `secretSink:` — the default is `${ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED}` (apply discards the create's value; ${ProvisionFile.CUSTOMER_MANAGED_RUNBOOK}) — " +
                    "or authenticate without a minted secret (clientAuthenticationMethods: [private_key_jwt]); a kubernetesSecret or file sink is for an operator's own apply with the cluster or disk at hand",
            )
        }
    }

    /**
     * SSO-3926 — `config.trust-scopes`: every configured provisioning file against the connection it is planned and applied
     * with. The scopes a file needs are derived from what it declares ([com.devnow.thoryn.provision.ScopeRequirements] — each
     * kind's read and write scope as product-api gates them, `tenant:access.*` for the ownership check, `grants:` blocks and a
     * `workloadPull` sink's grant, `tenant:workload-identity.read` for a trust a binding or sink names, a declared trust's
     * scope ceiling) and held against `auth.scopes`, and — the plan scopes — against the trust's plan profile as the
     * connection implies it ([TrustScopes.evaluate]). A missing one fails here, naming the scope and the profile, instead
     * of as a `403 access_denied` in the middle of the plan job (thoryn-cicd run 39917407017).
     *
     * SSO-3970: a pair whose file or connection does not load cannot be checked, so this rule FAILS naming it (the reason
     * is on `config.valid`) — it never passes on the pairs that did load, and never disappears.
     */
    private fun trustScopesRule(config: WorkflowConfig, configured: ConfiguredFiles): RuleResult {
        val title = "the identity carries every scope the provisioning files need"
        val problems = mutableListOf<String>()
        val satisfied = mutableListOf<String>()
        val blocked = mutableListOf<String>()
        config.files.forEach { entry ->
            val file = configured.files[entry.file]
            val connection = configured.connections[entry.connection]
            if (file == null || connection == null) {
                if (file == null && entry.file !in blocked) blocked += entry.file
                if (connection == null && entry.connection !in blocked) blocked += entry.connection
                return@forEach
            }
            val verdict = TrustScopes.evaluate(file, entry.file, connection, entry.connection, config.prune)
            problems += verdict.problems
            if (verdict.problems.isEmpty()) satisfied += verdict.satisfied
        }
        if (blocked.isNotEmpty()) {
            return RuleResult(
                TrustScopes.RULE_ID, title, Status.FAIL, (listOf(notChecked(blocked)) + problems + satisfied).joinToString("; "),
                "make config.valid pass, then run the check again" + if (problems.isNotEmpty()) "; and ${TrustScopes.FIX}" else "",
            )
        }
        return if (problems.isEmpty()) {
            RuleResult(TrustScopes.RULE_ID, title, Status.PASS, satisfied.joinToString("; "))
        } else {
            RuleResult(TrustScopes.RULE_ID, title, Status.FAIL, problems.joinToString("; "), TrustScopes.FIX)
        }
    }

    /** Whether creating [spec]'s application mints a secret ([ProvisionFile.mintsSecret]: confidential, and a secret-bearing method declared or none). */
    private fun mintsSecret(spec: Map<String, Any?>): Boolean = ProvisionFile.mintsSecret(spec)

    // ── shape ───────────────────────────────────────────────────────────────────────────────────────────────────

    private fun shapeOf(doc: JsonNode): Shape {
        if (doc["on"]?.has("workflow_call") == true) return Shape.REUSABLE
        val job = singleUsesJob(doc) ?: return Shape.CUSTOM
        return if (job["uses"].asString().startsWith("$REUSABLE_WORKFLOW@")) Shape.STUB else Shape.FOREIGN_STUB
    }

    /** The one `uses:` job of a stub-shaped workflow, or null when the jobs run their own steps. */
    private fun singleUsesJob(doc: JsonNode): JsonNode? {
        val jobs = doc["jobs"]?.takeIf { it.isObject } ?: return null
        val uses = jobs.properties().map { it.value }.filter { it.has("uses") && it["uses"].isString }
        return uses.singleOrNull()?.takeIf { jobs.size() == 1 }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────

    private fun JsonNode?.keys(): List<String> = this?.takeIf { it.isObject }?.propertyNames()?.toList() ?: emptyList()
    private fun JsonNode?.str(): String? = this?.takeIf { it.isValueNode }?.asString()
    private fun JsonNode?.steps(): List<JsonNode> = this?.get("steps")?.takeIf { it.isArray }?.toList() ?: emptyList()
    private fun JsonNode?.permissions(): Map<String, String>? = this?.get("permissions")?.takeIf { it.isObject }?.properties()?.associate { it.key to it.value.asString() }
    private fun JsonNode.runs(): List<String> = (this["jobs"].keys()).flatMap { this["jobs"][it].steps() }.mapNotNull { it["run"].str() }
    private fun pass(id: String, title: String, detail: String) = RuleResult(id, title, Status.PASS, detail)
    private fun fail(id: String, title: String, detail: String, fix: String) = RuleResult(id, title, Status.FAIL, detail, fix)
    private fun markerPresent(text: String) = Regex("(?m)^\\s*${Regex.escape(APPLY_JOB_MARKER)}\\s*$").containsMatchIn(text)

    // ── dispatch.* — what the App sends and looks for (stub and custom) ─────────────────────────────────────────

    internal fun dispatchRules(doc: JsonNode, text: String): List<RuleResult> {
        val out = mutableListOf<RuleResult>()
        val on = doc["on"]
        val problems = mutableListOf<String>()
        if (on.keys() != listOf("workflow_dispatch")) problems += "`on:` must be exactly `workflow_dispatch` (was ${on.keys().ifEmpty { listOf("none") }.joinToString(", ")})"
        val inputs = on?.get("workflow_dispatch")?.get("inputs")
        val names = inputs.keys()
        if (names.toSet() != DISPATCH_INPUTS.keys) problems += "inputs must be exactly ${DISPATCH_INPUTS.keys.joinToString(", ")} (was ${names.ifEmpty { listOf("none") }.joinToString(", ")})"
        DISPATCH_INPUTS.forEach { (name, spec) ->
            val node = inputs?.get(name) ?: return@forEach
            if ((node["required"]?.asBoolean() ?: false) != spec.required) problems += "input `$name` must be required: ${spec.required}"
            if (node["type"].str() != spec.type) problems += "input `$name` must be type: ${spec.type}"
            // SSO-3991 — `mode` offers v1's [plan, apply] or v2's [plan, apply, import]; nothing else (ALLOWED_MODE_OPTIONS).
            if (spec.options != null) {
                val declared = node["options"]?.toList()?.map { it.asString() }
                val allowed = if (name == "mode") ALLOWED_MODE_OPTIONS else listOf(spec.options)
                if (declared !in allowed) problems += "input `$name` options must be ${allowed.joinToString(" or ") { "[${it.joinToString(", ")}]" }}"
            }
        }
        out += if (problems.isEmpty()) pass("dispatch.inputs", "workflow_dispatch with the App's four inputs", "mode (choice: ${offeredModes(doc).joinToString(", ")}), head_sha, check_run_id required; pr_number optional")
        else fail("dispatch.inputs", "workflow_dispatch with the App's four inputs", problems.joinToString("; "), "declare `on.workflow_dispatch.inputs` exactly as the stub does: mode {required, type: choice, options: [plan, apply] — or [plan, apply, import] to receive the configuration import}, head_sha {required, type: string}, check_run_id {required, type: string}, pr_number {required: false, type: string, default: \"\"}")

        val runName = doc["run-name"].str() ?: ""
        out += if (runName.contains(RUN_NAME_MARKER)) pass("dispatch.run-name", "the run-name carries the check-run id", "`$RUN_NAME_MARKER` present — how the App finds the run to complete its check")
        else fail("dispatch.run-name", "the run-name carries the check-run id", "run-name is `${runName.ifEmpty { "(none)" }}`", "set `run-name: \"Thoryn provisioning \${{ inputs.mode }} \${{ inputs.head_sha }} $RUN_NAME_MARKER\"`")

        val perms = doc["permissions"]
        out += if (perms != null && perms.isObject && perms.isEmpty) pass("dispatch.permissions", "top-level permissions are {}", "every job declares its own")
        else fail("dispatch.permissions", "top-level permissions are {}", if (perms == null) "no top-level `permissions:`" else "top-level permissions grant ${perms.keys().joinToString(", ").ifEmpty { "(non-empty)" }}", "set `permissions: {}` at the top; grant `id-token: write`, `checks: write`, `contents: read` on the job")

        val conc = doc["concurrency"]
        val group = conc?.get("group").str() ?: ""
        val cancel = conc?.get("cancel-in-progress")?.asBoolean() ?: true
        out += if (group.contains(CONCURRENCY_MODE_FRAGMENT) && !cancel) pass("dispatch.concurrency", "concurrency is per mode and never cancels", "group `$group`, cancel-in-progress: false")
        else fail("dispatch.concurrency", "concurrency is per mode and never cancels", if (conc == null) "no `concurrency:`" else "group `$group`, cancel-in-progress: $cancel", "set `concurrency: { group: thoryn-provisioning-$CONCURRENCY_MODE_FRAGMENT, cancel-in-progress: false }` — a plan never waits on an apply, two applies never race, a held apply is never cancelled")

        out += if (markerPresent(text)) pass("dispatch.apply-job-marker", "the apply-job marker is present", "`$APPLY_JOB_MARKER` — the App dispatches `apply` only when it sees this line")
        else fail("dispatch.apply-job-marker", "the apply-job marker is present", "no line `$APPLY_JOB_MARKER`", "add the comment line `$APPLY_JOB_MARKER` above the job that applies (in a stub: above the `uses:` job — the reusable workflow carries the apply job)")
        return out
    }

    // ── dispatch.import-capable — may the App dispatch `import` (contract v2, SSO-3991) ─────────────────────────

    private const val IMPORT_CAPABLE_TITLE = "the App may dispatch import only if the workflow can run it"

    /** The `mode` options a dispatched workflow declares (empty when there are none). */
    internal fun offeredModes(doc: JsonNode): List<String> =
        doc["on"]?.get("workflow_dispatch")?.get("inputs")?.get("mode")?.get("options")?.takeIf { it.isArray }?.toList()?.map { it.asString() } ?: emptyList()

    private fun notOffered() = RuleResult(
        IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.PASS,
        "`mode` does not offer `import` (contract v1): the App never dispatches the configuration import to this file — to receive it, add `import` to `mode`'s options and call $REUSABLE_WORKFLOW@$IMPORT_MINIMUM_RELEASE or newer",
    )

    /**
     * A stub that offers `import` must call a reusable workflow that has the `import` job — [IMPORT_MINIMUM_RELEASE] or newer —
     * and must not override `cli-version` to a CLI older than that. Otherwise an import dispatch runs zero jobs (no job of the
     * called workflow is gated on `import`) and the run reports green with nothing imported. A commit SHA or a branch cannot be
     * dated, so it is UNVERIFIABLE rather than a pass. A stub that does not offer `import` passes: the App never sends it one.
     */
    private fun stubImportCapableRule(doc: JsonNode, effective: Map<String, String>): RuleResult {
        if (IMPORT_MODE !in offeredModes(doc)) return notOffered()
        val ref = singleUsesJob(doc)!!["uses"].asString().substringAfter('@', "")
        val fix = "call $REUSABLE_WORKFLOW@$IMPORT_MINIMUM_RELEASE or newer (the first release whose reusable workflow has the `import` job), or drop `import` from `mode`'s options until you do"
        if (ProvisioningWorkflowContract.releaseVersion(ref) == null) {
            return RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.UNVERIFIABLE, "the stub offers `import`, but `@$ref` is not a cli-v* release, so the check cannot tell whether the called workflow has the `import` job", fix, offersImport = true)
        }
        if (!ProvisioningWorkflowContract.shipsImportJob(ref)) {
            return RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.FAIL, "the stub offers `import`, but the reusable workflow at `@$ref` has no `import` job: an import dispatch would run zero jobs and report green with nothing imported", fix, offersImport = true)
        }
        effective["cli-version"]?.takeIf { it.isNotEmpty() && ProvisioningWorkflowContract.releaseVersion(it) != null && !ProvisioningWorkflowContract.shipsImportJob(it) }?.let { v ->
            return RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.FAIL, "the stub offers `import`, but `with.cli-version: $v` runs a CLI without `provision import --for-workflow`", "set `with.cli-version` to $IMPORT_MINIMUM_RELEASE or newer, or omit it (the called release's own CLI is used)", offersImport = true)
        }
        return RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.PASS, "`mode` offers `import` and the reusable workflow at `@$ref` has the `import` job: the App may dispatch the configuration import (contract v2)", offersImport = true)
    }

    /** A hand-written workflow that offers `import` must carry a job gated on it, in a plan environment, uploading [IMPORT_ARTIFACT]. */
    private fun customImportCapableRule(doc: JsonNode): RuleResult {
        if (IMPORT_MODE !in offeredModes(doc)) return notOffered()
        val jobs = doc["jobs"]
        fun gated(mode: String) = jobs.keys().filter { jobs[it]["if"].str()?.replace(" ", "") == "inputs.mode=='$mode'" }
        fun envOf(name: String) = jobs[name]["environment"].str() ?: jobs[name]["environment"]?.get("name").str()
        val importJobs = gated(IMPORT_MODE)
        val applyEnvs = gated("apply").mapNotNull { envOf(it) }.toSet()
        val planEnvs = gated("plan").mapNotNull { envOf(it) }.toSet()
        val problems = mutableListOf<String>()
        if (importJobs.isEmpty()) problems += "no job gated `if: inputs.mode == '$IMPORT_MODE'` — an import dispatch would run zero jobs and report green"
        importJobs.forEach { name ->
            val env = envOf(name)
            if (env == null || env !in planEnvs) problems += "job `$name` must run in the plan job's environment (the trust's read-only plan profile)"
            if (env != null && env in applyEnvs) problems += "job `$name` runs in the apply environment — the import must never be minted write scopes"
            if (jobs[name].steps().none { it["uses"].str()?.startsWith("actions/upload-artifact@") == true && it["with"]?.get("name").str() == IMPORT_ARTIFACT }) problems += "job `$name` uploads no `$IMPORT_ARTIFACT` artifact"
        }
        return if (problems.isEmpty()) RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.PASS, "`mode` offers `import`; job(s) ${importJobs.joinToString()} run it in the plan environment and upload `$IMPORT_ARTIFACT`", offersImport = true)
        else RuleResult(IMPORT_CAPABLE_RULE, IMPORT_CAPABLE_TITLE, Status.FAIL, problems.joinToString("; "), "the supported shape is a stub calling $REUSABLE_WORKFLOW@$IMPORT_MINIMUM_RELEASE; or drop `import` from `mode`'s options", offersImport = true)
    }

    // ── stub.* — the supported shape ────────────────────────────────────────────────────────────────────────────

    internal fun stubRules(doc: JsonNode): Pair<List<RuleResult>, Map<String, String>> {
        val out = mutableListOf<RuleResult>()
        val jobs = doc["jobs"]
        val jobName = jobs.keys().single()
        val job = jobs[jobName]
        val stray = job.keys().filter { it !in setOf("uses", "with", "permissions", "name", "if", "needs") }
        out += if (stray.isEmpty()) pass("stub.job", "one job, which only calls the reusable workflow", "job `$jobName`: uses + with + permissions")
        else fail("stub.job", "one job, which only calls the reusable workflow", "job `$jobName` declares ${stray.joinToString(", ")}", "remove ${stray.joinToString(", ")} from the `uses:` job — runs-on, timeout and the environments are INPUTS of the reusable workflow (`with:`); steps and secrets have no place in a stub")

        val uses = job["uses"].asString()
        val ref = uses.substringAfter('@', "")
        out += when {
            ProvisioningWorkflowContract.COMMIT_SHA_GRAMMAR.matches(ref) -> pass("stub.uses", "the reusable workflow is pinned to a release", "$REUSABLE_WORKFLOW@$ref (a commit)")
            ProvisioningWorkflowContract.releaseVersion(ref) == null -> fail("stub.uses", "the reusable workflow is pinned to a release", "`@$ref` is a branch, not a release", "pin `uses: $REUSABLE_WORKFLOW@$MINIMUM_RELEASE` (or a newer cli-v* tag, or a full commit SHA) — a branch moves under you")
            !ProvisioningWorkflowContract.isAtLeastMinimumRelease(ref) -> fail("stub.uses", "the reusable workflow is pinned to a release", "`@$ref` predates the reusable workflow", "pin `uses: $REUSABLE_WORKFLOW@$MINIMUM_RELEASE` or newer")
            else -> pass("stub.uses", "the reusable workflow is pinned to a release", "$REUSABLE_WORKFLOW@$ref")
        }

        val with = job["with"]
        val given = with.keys()
        val problems = mutableListOf<String>()
        val fixes = mutableListOf<String>()
        given.filter { it !in REUSABLE_INPUTS }.forEach {
            problems += "`with.$it` is not an input of the reusable workflow"
            fixes += "remove `with.$it` — the inputs are ${REUSABLE_INPUTS.keys.joinToString(", ")}; a knob that is not one of them is a product gap to report, not a job to edit"
        }
        STUB_REQUIRED_INPUTS.filter { it !in given }.forEach {
            problems += "`with.$it` is missing"
            fixes += if (REUSABLE_INPUTS[it]!!.forwardedDispatchInput) "add `with.$it: ${forwarded(it)}`" else "add `with.$it: <${REUSABLE_INPUTS[it]!!.grammarHint}>`"
        }
        val effective = linkedMapOf<String, String>()
        REUSABLE_INPUTS.forEach { (name, spec) ->
            val value = with?.get(name)?.let { if (it.isValueNode) it.asString() else it.toString() }
            if (value == null) { spec.default?.let { effective[name] = it }; return@forEach }
            effective[name] = value
            if (spec.forwardedDispatchInput) {
                if (value != forwarded(name)) { problems += "`with.$name` must forward the dispatch input verbatim (was `$value`)"; fixes += "set `with.$name: ${forwarded(name)}`" }
            } else {
                if (value.contains("\${{")) { problems += "`with.$name` is an expression (`$value`)"; fixes += "give `with.$name` a literal value — ${spec.grammarHint}" }
                else if (spec.grammar != null && value.isNotEmpty() && !spec.grammar.matches(value)) { problems += "`with.$name: $value` is not ${spec.grammarHint}"; fixes += "set `with.$name` to ${spec.grammarHint}" }
                else if (value.isEmpty() && spec.required) { problems += "`with.$name` is empty"; fixes += "set `with.$name` to ${spec.grammarHint}" }
            }
        }
        val plan = effective["plan-environment"]
        val apply = effective["apply-environment"]
        if (plan != null && apply != null && plan == apply) {
            problems += "plan-environment and apply-environment are both `$plan`"
            fixes += "use two GitHub environments: an UNPROTECTED one for plan (the trust's plan profile is keyed on it) and a REVIEWED one for apply (required reviewers; the trust pins it) — the environment is the only pin separating read from write"
        }
        effective["cli-version"]?.takeIf { it.isNotEmpty() }?.let { v -> if (ProvisioningWorkflowContract.releaseVersion(v) != null && !ProvisioningWorkflowContract.isAtLeastMinimumRelease(v)) { problems += "`with.cli-version: $v` predates the reusable workflow"; fixes += "set `with.cli-version` to $MINIMUM_RELEASE or newer, or omit it (the called release's own tag is used)" } }
        out += if (problems.isEmpty()) pass("stub.with", "the with: block passes the reusable workflow's inputs", "plan-environment `$plan`, apply-environment `$apply`" + (effective["issuer"]?.let { ", issuer $it" } ?: ""))
        else fail("stub.with", "the with: block passes the reusable workflow's inputs", problems.joinToString("; "), fixes.joinToString("; "))

        val perms = job.permissions()
        out += if (perms == JOB_PERMISSIONS) pass("stub.permissions", "the job grants id-token: write, checks: write, contents: read", "exactly — the called jobs declare the same")
        else fail("stub.permissions", "the job grants id-token: write, checks: write, contents: read", "job permissions are ${perms?.entries?.joinToString(", ") { "${it.key}: ${it.value}" } ?: "(none)"}", "set `permissions: { id-token: write, checks: write, contents: read }` on the `uses:` job — id-token mints the identity, checks completes the App's check run, contents reads the checkout; nothing writes back (the platform is the ledger)")

        out += if (!job.has("secrets")) pass("stub.secrets", "the stub passes no secret", "the identity is the job's own OIDC token")
        else fail("stub.secrets", "the stub passes no secret", "the job declares `secrets:`", "remove `secrets:` — the reusable workflow takes none; a credential is never configuration")
        return out to effective
    }

    // ── custom.* — what the App needs from a hand-written workflow ──────────────────────────────────────────────

    internal fun customRules(doc: JsonNode): List<RuleResult> {
        val out = mutableListOf<RuleResult>()
        val jobs = doc["jobs"]
        val planJobs = jobs.keys().filter { jobs[it]["if"].str()?.replace(" ", "") == "inputs.mode=='plan'" }
        val applyJobs = jobs.keys().filter { jobs[it]["if"].str()?.replace(" ", "") == "inputs.mode=='apply'" }
        val problems = mutableListOf<String>()
        if (planJobs.isEmpty()) problems += "no job gated `if: inputs.mode == 'plan'`"
        if (applyJobs.isEmpty()) problems += "no job gated `if: inputs.mode == 'apply'`"
        val planEnvs = planJobs.mapNotNull { jobs[it]["environment"].str() ?: jobs[it]["environment"]?.get("name").str() }
        val applyEnvs = applyJobs.mapNotNull { jobs[it]["environment"].str() ?: jobs[it]["environment"]?.get("name").str() }
        if (planJobs.isNotEmpty() && planEnvs.isEmpty()) problems += "the plan job declares no GitHub environment"
        if (applyJobs.isNotEmpty() && applyEnvs.isEmpty()) problems += "the apply job declares no GitHub environment"
        if (planEnvs.intersect(applyEnvs.toSet()).isNotEmpty()) problems += "plan and apply share a GitHub environment (${planEnvs.intersect(applyEnvs.toSet()).joinToString()})"
        (planJobs + applyJobs).forEach { name ->
            val p = jobs[name].permissions() ?: emptyMap()
            if (p["id-token"] != "write") problems += "job `$name` lacks `id-token: write`"
            if (p["checks"] != "write") problems += "job `$name` lacks `checks: write`"
            val first = jobs[name].steps().firstOrNull()
            if (first?.get("uses").str()?.startsWith("actions/checkout@") != true || first?.get("with")?.get("ref").str() != forwarded("head_sha")) problems += "job `$name` does not check out `${forwarded("head_sha")}` first"
            val upload = jobs[name].steps().any { it["uses"].str()?.startsWith("actions/upload-artifact@") == true && it["with"]?.get("name").str() == FIX_REQUEST_ARTIFACT && (it["if"].str()?.contains("failure()") == true) }
            if (!upload) problems += "job `$name` uploads no `$FIX_REQUEST_ARTIFACT` artifact on failure"
        }
        out += if (problems.isEmpty()) pass("custom.jobs", "a plan job and an apply job the App can drive", "plan in ${planEnvs.joinToString()}, apply in ${applyEnvs.joinToString()}; id-token + checks write; checkout at head_sha; fix request uploaded on failure")
        else fail("custom.jobs", "a plan job and an apply job the App can drive", problems.joinToString("; "), "the supported shape is a stub calling $REUSABLE_WORKFLOW@$MINIMUM_RELEASE — every knob is a `with:` input or a key of ${WorkflowConfig.DEFAULT_PATH}; a hand-written workflow must itself: gate two jobs on inputs.mode, run them in two different GitHub environments, grant id-token: write + checks: write, check out \${{ inputs.head_sha }}, and upload `$FIX_REQUEST_ARTIFACT` with `if: failure()`")
        return out
    }

    // ── reusable.* — the called side ────────────────────────────────────────────────────────────────────────────

    internal fun reusableRules(doc: JsonNode, text: String): List<RuleResult> {
        val out = mutableListOf<RuleResult>()
        val inputs = doc["on"]["workflow_call"]?.get("inputs")
        val problems = mutableListOf<String>()
        if (inputs.keys().toSet() != REUSABLE_INPUTS.keys) problems += "inputs are ${inputs.keys().joinToString(", ")}; the contract lists ${REUSABLE_INPUTS.keys.joinToString(", ")}"
        REUSABLE_INPUTS.forEach { (name, spec) ->
            val node = inputs?.get(name) ?: return@forEach
            if ((node["required"]?.asBoolean() ?: false) != spec.required) problems += "input `$name` required must be ${spec.required}"
            if ((node["type"].str() ?: "string") != spec.type) problems += "input `$name` type must be ${spec.type}"
            if (spec.default != null && node["default"].str() != spec.default) problems += "input `$name` default must be `${spec.default}` (was `${node["default"].str()}`)"
        }
        out += if (problems.isEmpty()) pass("reusable.inputs", "workflow_call declares the contract's inputs", REUSABLE_INPUTS.keys.joinToString(", "))
        else fail("reusable.inputs", "workflow_call declares the contract's inputs", problems.joinToString("; "), "align `on.workflow_call.inputs` with ProvisioningWorkflowContract.REUSABLE_INPUTS (one source: change both, bump the contract version)")

        val jobs = doc["jobs"]
        val jp = mutableListOf<String>()
        // Contract v2 (SSO-3991): a third job, `import`, in the PLAN environment (never apply-environment).
        if (jobs.keys() != listOf("plan", "apply", IMPORT_MODE)) jp += "jobs must be exactly plan, apply, $IMPORT_MODE (was ${jobs.keys().joinToString(", ")})"
        val plan = jobs["plan"]; val apply = jobs["apply"]; val import = jobs[IMPORT_MODE]
        val environments = mapOf("plan" to "plan-environment", "apply" to "apply-environment", IMPORT_MODE to "plan-environment")
        environments.forEach { (name, env) ->
            if (jobs[name]?.get("if").str()?.replace(" ", "") != "inputs.mode=='$name'") jp += "$name must be gated `if: inputs.mode == '$name'`"
            if (jobs[name]?.get("environment").str() != forwarded(env)) jp += "$name must run in `environment: ${forwarded(env)}`"
        }
        listOf("plan" to plan, "apply" to apply, IMPORT_MODE to import).forEach { (name, job) ->
            if (job?.get("runs-on").str()?.contains("inputs.runs-on") != true) jp += "$name must take its runner from `inputs.runs-on`"
            if (job?.get("timeout-minutes").str()?.contains("inputs.timeout-minutes") != true) jp += "$name must take `timeout-minutes` from `inputs.timeout-minutes`"
            if (job.permissions() != JOB_PERMISSIONS) jp += "$name permissions must be exactly ${JOB_PERMISSIONS.entries.joinToString(", ") { "${it.key}: ${it.value}" }}"
            val first = job.steps().firstOrNull()
            if (first?.get("uses").str()?.startsWith("actions/checkout@") != true || first?.get("with")?.get("ref").str() != forwarded("head_sha")) jp += "$name must check out `${forwarded("head_sha")}` first"
            val upload = job.steps().filter { it["uses"].str()?.startsWith("actions/upload-artifact@") == true }
            if (upload.none { it["with"]?.get("name").str() == FIX_REQUEST_ARTIFACT && it["if"].str()?.contains("failure()") == true && it["with"]?.get("if-no-files-found").str() == "ignore" && Regex("@[0-9a-f]{40}").containsMatchIn(it["uses"].asString()) }) jp += "$name must upload `$FIX_REQUEST_ARTIFACT` (actions/upload-artifact pinned to a commit, if: failure(), if-no-files-found: ignore)"
            if (job.steps().none { it["env"]?.has(FixRequest.ENV) == true && it["run"].str()?.contains("login --connection") == true }) jp += "$name's sign-in step must set ${FixRequest.ENV}"
            if (job.steps().none { it["run"].str()?.contains("provision workflow check") == true && it["run"].str()?.contains("--output json") == true }) jp += "$name must read ${WorkflowConfig.DEFAULT_PATH} through `thoryn provision workflow check --output json` (the CLI validates it; no hand parsing)"
        }
        val topPerms = doc["permissions"]
        if (topPerms != null && !(topPerms.isObject && topPerms.isEmpty)) jp += "top-level permissions must be absent or {}"
        if (!markerPresent(text)) jp += "the apply job must carry `$APPLY_JOB_MARKER`"
        out += if (jp.isEmpty()) pass("reusable.jobs", "plan, apply and import jobs as the contract pins them", "gated on inputs.mode; environments (import in the plan one), runner and timeout from inputs; permissions exact; checkout at head_sha; fix request uploaded; config read through the CLI; apply-job marker")
        else fail("reusable.jobs", "plan, apply and import jobs as the contract pins them", jp.joinToString("; "), "shape the jobs as docs/provisioning-workflow-contract.md §reusable describes")

        out += importJobRule(import)

        val writes = jobs.keys().filter { (jobs[it].permissions() ?: emptyMap()).let { p -> p["contents"] == "write" || p.containsKey("pull-requests") } }
        val pushes = doc.runs().filter { it.contains("gh pr create") || it.contains("git push") || it.contains("git commit") }
        out += if (writes.isEmpty() && pushes.isEmpty()) pass("reusable.no-write-back", "nothing is written back to the repository", "no contents: write, no pull-requests, no git push / gh pr create — the platform is the ledger (ADR 2026-10-15)")
        else fail("reusable.no-write-back", "nothing is written back to the repository", (writes.map { "job `$it` may write to the repository" } + pushes.map { "a run block pushes or opens a pull request" }).joinToString("; "), "drop contents: write / pull-requests: write and the receipt step — ownership is the platform's `owner` relation, not a committed file (SSO-3708 / SSO-3717)")
        return out
    }

    /**
     * SSO-3991 (contract v2 §3) — `reusable.import-job`: what the App relies on from the `import` job beyond the per-job
     * shape `reusable.jobs` pins. It imports each configured file with `provision import --for-workflow` into a copy (never
     * the checkout — `--write` without `--file` would edit the working tree), previews it with `provision plan`, writes the
     * summary through `provision workflow import-summary` (the CLI's allow-listed field list, the size bound), never applies
     * or destroys, and uploads [IMPORT_ARTIFACT] (pinned to a commit, hidden `.thoryn/` paths included, missing files an
     * error, kept 7 days) — on success only, never on failure.
     */
    private fun importJobRule(job: JsonNode?): RuleResult {
        val title = "the import job imports read-only and hands the files over as the $IMPORT_ARTIFACT artifact"
        if (job == null) return fail(IMPORT_JOB_RULE, title, "no `$IMPORT_MODE` job", "add the `$IMPORT_MODE` job of docs/provisioning-workflow-contract.md §3 (contract v2)").copy(offersImport = true)
        val runs = job.steps().mapNotNull { it["run"].str() }
        // Commands, not comments: each non-comment line of every run block.
        val lines = runs.flatMap { it.lines() }.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        val problems = mutableListOf<String>()
        val importRun = lines.firstOrNull { it.contains("thoryn.jar provision import ") }
        if (importRun == null) problems += "no step runs `thoryn provision import`"
        else {
            if (!importRun.contains("--for-workflow")) problems += "`provision import` must run with `--for-workflow <file>` (the connection's scopes, plane routing, own trusts excluded)"
            if (!importRun.contains("--file \"\$out/")) problems += "`provision import` must write a copy under the artifact directory (`--file \"\$out/<file>\"`), never the checkout"
            if (!importRun.contains("--write")) problems += "`provision import` must `--write` the copy"
        }
        if (lines.none { it.contains("thoryn.jar provision plan ") && it.contains("--file \"\$out/") && it.contains("--output json") }) problems += "no `provision plan --file \"\$out/<file>\" --output json` preview of the imported copy"
        if (lines.none { it.contains("thoryn.jar provision workflow import-summary ") && it.contains("--artifact") }) problems += "no step writes ${ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE} through `thoryn provision workflow import-summary`"
        if (lines.any { it.contains("provision apply") || it.contains("provision destroy") }) problems += "the import job must never apply or destroy"
        val uploads = job.steps().filter { it["uses"].str()?.startsWith("actions/upload-artifact@") == true && it["with"]?.get("name").str() == IMPORT_ARTIFACT }
        val upload = uploads.singleOrNull()
        if (upload == null) problems += "the job must upload exactly one `$IMPORT_ARTIFACT` artifact"
        else {
            val with = upload["with"]
            if (!Regex("@[0-9a-f]{40}").containsMatchIn(upload["uses"].asString())) problems += "`$IMPORT_ARTIFACT` must be uploaded with actions/upload-artifact pinned to a commit"
            if (upload["if"].str()?.contains("failure()") == true || upload["if"].str()?.contains("always()") == true) problems += "`$IMPORT_ARTIFACT` must be uploaded only by a successful job"
            if (with?.get("retention-days").str() != "7") problems += "`$IMPORT_ARTIFACT` must set `retention-days: 7`"
            if (with?.get("include-hidden-files").str() != "true") problems += "`$IMPORT_ARTIFACT` must set `include-hidden-files: true` (the files live under `.thoryn/`, which upload-artifact v4.4+ leaves out by default)"
            if (with?.get("if-no-files-found").str() != "error") problems += "`$IMPORT_ARTIFACT` must set `if-no-files-found: error`"
        }
        return if (problems.isEmpty()) {
            RuleResult(IMPORT_JOB_RULE, title, Status.PASS, "imports each configured file with --for-workflow into a copy, previews it with plan, writes the summary through the CLI, applies nothing, uploads $IMPORT_ARTIFACT (pinned, hidden files included, 7 days)", offersImport = true)
        } else {
            RuleResult(IMPORT_JOB_RULE, title, Status.FAIL, problems.joinToString("; "), "shape the `$IMPORT_MODE` job as docs/provisioning-workflow-contract.md §3 describes (contract v2)", offersImport = true)
        }
    }

    // ── common.* — every shape ──────────────────────────────────────────────────────────────────────────────────

    internal fun commonRules(doc: JsonNode, text: String): List<RuleResult> {
        val out = mutableListOf<RuleResult>()
        val secretRefs = text.contains("secrets.") || doc["jobs"].keys().any { doc["jobs"][it].has("secrets") }
        out += if (!secretRefs) pass("common.no-secrets", "no secret is referenced", "the identity is the job's own OIDC token, exchanged under the workspace's trust")
        else fail("common.no-secrets", "no secret is referenced", "the workflow references `secrets`", "remove every `secrets.*` / `secrets:` — a workload-identity connection needs none, and a credential is never configuration")
        val leaking = doc.runs().filter { it.contains("\${{") }
        out += if (leaking.isEmpty()) pass("common.no-expression-in-run", "no `\${{ }}` inside a run: block", "every value reaches a shell through env: (the template-injection rule, oauthy SSO-3635)")
        else fail("common.no-expression-in-run", "no `\${{ }}` inside a run: block", "${leaking.size} run block(s) interpolate an expression into the shell's source: ${leaking.first().lineSequence().first { it.contains("\${{") }.trim()}", "put the value in the step's `env:` and read `\"\$VAR\"` in the script")
        return out
    }
}
