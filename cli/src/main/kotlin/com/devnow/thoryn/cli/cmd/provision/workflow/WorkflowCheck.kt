package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.APPLY_JOB_MARKER
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.CONCURRENCY_MODE_FRAGMENT
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.DISPATCH_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FIX_REQUEST_ARTIFACT
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.JOB_PERMISSIONS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.MINIMUM_RELEASE
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.REUSABLE_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.REUSABLE_WORKFLOW
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.RUN_NAME_MARKER
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.STUB_REQUIRED_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.forwarded
import com.devnow.thoryn.provision.FixRequest
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
 */
object WorkflowCheck {

    enum class Shape(val label: String, val supported: Boolean) {
        STUB("stub calling the reusable workflow", true),
        REUSABLE("the reusable workflow (called side)", true),
        CUSTOM("hand-written workflow — not the supported shape", false),
        FOREIGN_STUB("stub calling a workflow that is not thoryn-io/thoryn-cli's", false),
    }

    enum class Status { PASS, FAIL, UNVERIFIABLE }

    data class RuleResult(val id: String, val title: String, val status: Status, val detail: String, val fix: String? = null) {
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

        fun toStructured(): Map<String, Any?> = linkedMapOf(
            "contractVersion" to ProvisioningWorkflowContract.CONTRACT_VERSION,
            "file" to file,
            "shape" to shape.name.lowercase(),
            "supported" to supported,
            "ok" to ok,
            "rules" to rules.map { r -> linkedMapOf("id" to r.id, "title" to r.title, "status" to r.status.name, "detail" to r.detail, "fix" to r.fix) },
            "inputs" to inputs,
            "config" to config?.toStructured(),
            "configError" to configError,
        )
    }

    private val yaml = YAMLMapper.builder().build()

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
                rules += stubRules
                inputs = effective
                rules += commonRules(doc, text)
            }
            Shape.FOREIGN_STUB -> {
                rules += dispatchRules(doc, text)
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
                val missing = if (root != null) config.files.flatMap { listOf(it.file, it.connection) }.filterNot { File(root, it).isFile } else emptyList()
                rules += if (missing.isEmpty()) {
                    RuleResult("config.valid", "the run-time configuration is valid", Status.PASS, (config.source?.let { "$it" } ?: "no ${WorkflowConfig.DEFAULT_PATH} — built-in defaults") + ": ${config.files.size} file(s), ${config.env.size} env var(s), fixRequest=${config.fixRequest}, prune=${config.prune}, destroy=${config.destroy}")
                } else {
                    RuleResult("config.valid", "the run-time configuration is valid", Status.FAIL, "configured file(s) not found in the repository: ${missing.joinToString(", ")}", "commit them, or point `files[].file` / `files[].connection` in ${config.source ?: WorkflowConfig.DEFAULT_PATH} at the committed paths")
                }
            } catch (ex: WorkflowConfigException) {
                configError = ex.message
                rules += RuleResult("config.valid", "the run-time configuration is valid", Status.FAIL, ex.message ?: "invalid", "fix $configDisplay — schema: examples/workflow.schema.json (unknown keys are refused: a knob that is not there is a product gap to report)")
            }
        }
        return Report(path, shape, rules, inputs, config, configError)
    }

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
            spec.options?.let { opts -> if (node["options"]?.toList()?.map { it.asString() } != opts) problems += "input `$name` options must be [${opts.joinToString(", ")}]" }
        }
        out += if (problems.isEmpty()) pass("dispatch.inputs", "workflow_dispatch with the App's four inputs", "mode (choice: plan, apply), head_sha, check_run_id required; pr_number optional")
        else fail("dispatch.inputs", "workflow_dispatch with the App's four inputs", problems.joinToString("; "), "declare `on.workflow_dispatch.inputs` exactly as the stub does: mode {required, type: choice, options: [plan, apply]}, head_sha {required, type: string}, check_run_id {required, type: string}, pr_number {required: false, type: string, default: \"\"}")

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
        if (jobs.keys() != listOf("plan", "apply")) jp += "jobs must be exactly plan, apply (was ${jobs.keys().joinToString(", ")})"
        val plan = jobs["plan"]; val apply = jobs["apply"]
        if (plan?.get("if").str()?.replace(" ", "") != "inputs.mode=='plan'") jp += "plan must be gated `if: inputs.mode == 'plan'`"
        if (apply?.get("if").str()?.replace(" ", "") != "inputs.mode=='apply'") jp += "apply must be gated `if: inputs.mode == 'apply'`"
        if (plan?.get("environment").str() != forwarded("plan-environment")) jp += "plan must run in `environment: ${forwarded("plan-environment")}`"
        if (apply?.get("environment").str() != forwarded("apply-environment")) jp += "apply must run in `environment: ${forwarded("apply-environment")}`"
        listOf("plan" to plan, "apply" to apply).forEach { (name, job) ->
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
        out += if (jp.isEmpty()) pass("reusable.jobs", "plan and apply jobs as the contract pins them", "gated on inputs.mode; environments, runner and timeout from inputs; permissions exact; checkout at head_sha; fix request uploaded; config read through the CLI; apply-job marker")
        else fail("reusable.jobs", "plan and apply jobs as the contract pins them", jp.joinToString("; "), "shape the jobs as docs/provisioning-workflow-contract.md §reusable describes")

        val writes = jobs.keys().filter { (jobs[it].permissions() ?: emptyMap()).let { p -> p["contents"] == "write" || p.containsKey("pull-requests") } }
        val pushes = doc.runs().filter { it.contains("gh pr create") || it.contains("git push") || it.contains("git commit") }
        out += if (writes.isEmpty() && pushes.isEmpty()) pass("reusable.no-write-back", "nothing is written back to the repository", "no contents: write, no pull-requests, no git push / gh pr create — the platform is the ledger (ADR 2026-10-15)")
        else fail("reusable.no-write-back", "nothing is written back to the repository", (writes.map { "job `$it` may write to the repository" } + pushes.map { "a run block pushes or opens a pull request" }).joinToString("; "), "drop contents: write / pull-requests: write and the receipt step — ownership is the platform's `owner` relation, not a committed file (SSO-3708 / SSO-3717)")
        return out
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
