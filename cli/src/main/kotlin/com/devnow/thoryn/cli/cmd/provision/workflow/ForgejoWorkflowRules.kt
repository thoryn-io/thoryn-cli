package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.COMMIT_SHA_GRAMMAR
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_ACTION
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_ACTION_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_ACTION_NAME
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_ALLOWED_TRIGGERS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_CHECKOUT_FORBIDDEN_INPUTS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_JOB_KEYS
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_MINIMUM_RELEASE
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract.FORGEJO_REQUIRED_TRIGGERS
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.RuleResult
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck.Status
import tools.jackson.databind.JsonNode

/**
 * SSO-4474 — the `forgejo.*` and `action.*` rules of `thoryn provision workflow check`: a Forgejo Actions stub calling
 * thoryn-cli's provisioning ACTION ([WorkflowCheck.Shape.FORGEJO_STUB]) and the action itself
 * ([WorkflowCheck.Shape.FORGEJO_ACTION], the called side). docs/provisioning-workflow-contract.md §8.
 *
 * The rule they hold a stub to is the hub's (thoryn-architecture ADR 2026-10-14, Amendment 2026-11-23, C5–C7): a plan on
 * a same-repository pull request into the default branch and on a push to it, an apply ONLY on an operator's
 * `workflow_dispatch` of it. The hub enforces it on the job token; the action refuses early; this check refuses a stub that
 * could apply any other way — its own `run:` step, a checkout of other code, an `env:` over the job's context, a dispatch
 * input, a `workflow_call` or `pull_request_target` trigger — before it is ever merged.
 */
internal object ForgejoWorkflowRules {

    private fun JsonNode?.keys(): List<String> = this?.takeIf { it.isObject }?.propertyNames()?.toList() ?: emptyList()
    private fun JsonNode?.str(): String? = this?.takeIf { it.isValueNode }?.asString()
    private fun JsonNode?.steps(): List<JsonNode> = this?.get("steps")?.takeIf { it.isArray }?.toList() ?: emptyList()
    private fun pass(id: String, title: String, detail: String) = RuleResult(id, title, Status.PASS, detail)
    private fun fail(id: String, title: String, problems: List<String>, fix: String) = RuleResult(id, title, Status.FAIL, problems.joinToString("; "), fix)

    /** A step that names the Thoryn action, on any host or none: what makes a workflow a Forgejo stub. */
    private fun isActionStep(step: JsonNode): Boolean = step["uses"].str()?.let { it.substringBefore('@').endsWith(FORGEJO_ACTION_NAME) && it.contains('@') } == true

    /** A checkout action's step (`actions/checkout@…` on any host). */
    private fun isCheckoutStep(step: JsonNode): Boolean = step["uses"].str()?.let { Regex("(^|/)checkout@").containsMatchIn(it) } == true

    private fun jobs(doc: JsonNode): List<Pair<String, JsonNode>> = doc["jobs"]?.takeIf { it.isObject }?.properties()?.map { it.key to it.value } ?: emptyList()

    /** Does [doc] call the Thoryn Forgejo action from a job's steps? */
    fun callsAction(doc: JsonNode): Boolean = jobs(doc).any { (_, job) -> job.steps().any(::isActionStep) }

    /** Is [doc] an action's metadata (`runs.using`), not a workflow? */
    fun isAction(doc: JsonNode): Boolean = doc["runs"]?.get("using") != null && doc["jobs"] == null

    /** The events [doc] runs on, each with its filter node (null for a bare `push:` / `on: push` / `on: [push]`). */
    fun triggers(doc: JsonNode): Map<String, JsonNode?> {
        val on = doc["on"] ?: return emptyMap()
        return when {
            on.isString -> mapOf(on.asString() to null)
            on.isArray -> on.toList().associate { it.asString() to null }
            on.isObject -> on.properties().associate { it.key to it.value.takeUnless { v -> v.isNull } }
            else -> emptyMap()
        }
    }

    // ── forgejo.* — the stub ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Every `forgejo.*` rule of the stub, and the action's effective `with:` (defaults filled in), and the branch the stub
     * filters on (null when it does not name exactly one).
     */
    fun stubRules(doc: JsonNode): Triple<List<RuleResult>, Map<String, String>, String?> {
        val out = mutableListOf<RuleResult>()
        out += triggersRule(doc)
        val (branchRule, branch) = branchesRule(doc)
        out += branchRule
        out += jobRule(doc)
        out += applyGateRule(doc)
        val step = jobs(doc).flatMap { it.second.steps() }.first(::isActionStep)
        val (usesRule, ref) = usesRule(step)
        out += usesRule
        val (withRule, effective) = withRule(step, ref)
        out += withRule
        return Triple(out, effective, branch)
    }

    private const val TRIGGERS_TITLE = "runs on a pull request, a push and a dispatch of the default branch only"

    private fun triggersRule(doc: JsonNode): RuleResult {
        val on = triggers(doc).keys
        val problems = mutableListOf<String>()
        if ("workflow_call" in on) problems += "`workflow_call`: inside a reusable workflow every job's token says workflow_call, whatever started the run, and the platform refuses it on every plane (C6) — call the action from this workflow's own job"
        if ("pull_request_target" in on) problems += "`pull_request_target` runs this repository's code for a request that may come from a fork, and the platform refuses its token on every plane (C6) — use pull_request"
        (on - FORGEJO_ALLOWED_TRIGGERS.toSet() - setOf("workflow_call", "pull_request_target")).forEach { problems += "`$it` does not start Thoryn provisioning" }
        FORGEJO_REQUIRED_TRIGGERS.filter { it !in on }.forEach {
            problems += "no `$it` — " + when (it) {
                "pull_request" -> "pull requests get no plan"
                "push" -> "a merge into the default branch gets no plan"
                else -> "nothing can ever apply (an operator's dispatch is the only apply)"
            }
        }
        return if (problems.isEmpty()) {
            pass("forgejo.triggers", TRIGGERS_TITLE, "on: ${on.joinToString(", ")} — plan on a pull request and a push, apply only on a workflow_dispatch")
        } else {
            fail("forgejo.triggers", TRIGGERS_TITLE, problems, "set `on:` to pull_request and push (each `branches: [<default branch>]`) and workflow_dispatch (no inputs); `schedule` may be added for a drift plan")
        }
    }

    private const val BRANCHES_TITLE = "pull requests and pushes are filtered to the default branch"
    private val LITERAL_BRANCH = Regex("^[A-Za-z0-9._/-]{1,255}$")

    private fun branchesRule(doc: JsonNode): Pair<RuleResult, String?> {
        val on = triggers(doc)
        val problems = mutableListOf<String>()
        val named = linkedMapOf<String, String>()
        listOf("pull_request", "push").filter { it in on }.forEach { event ->
            val node = on[event]
            if (node == null || !node.isObject) { problems += "`$event` has no branch filter, so it runs for every branch and the platform refuses all but the default one"; return@forEach }
            val allowed = if (event == "pull_request") setOf("branches", "types") else setOf("branches")
            node.keys().filter { it !in allowed }.forEach { problems += "`$event.$it` is not supported — filter on `branches` only" }
            val branches = node["branches"]?.let { b -> if (b.isArray) b.toList().map { it.asString() } else listOfNotNull(b.str()) } ?: emptyList()
            when {
                branches.size != 1 -> problems += "`$event.branches` must name exactly one branch, the default branch (was ${branches.ifEmpty { listOf("none") }.joinToString(", ")})"
                !LITERAL_BRANCH.matches(branches.single()) || branches.single().startsWith("refs/") -> problems += "`$event.branches: ${branches.single()}` must be the default branch's plain name (no pattern, no refs/heads/)"
                else -> named[event] = branches.single()
            }
        }
        if (named.values.distinct().size > 1) problems += "pull_request filters `${named["pull_request"]}` and push `${named["push"]}` — both must name the default branch"
        val branch = named.values.distinct().singleOrNull()?.takeIf { problems.isEmpty() }
        val rule = if (problems.isEmpty()) {
            pass("forgejo.branches", BRANCHES_TITLE, branch?.let { "pull_request and push on `$it`" } ?: "no pull_request or push to filter (see forgejo.triggers)")
        } else {
            fail("forgejo.branches", BRANCHES_TITLE, problems, "set `pull_request: { branches: [main] }` and `push: { branches: [main] }`, with the default branch's name — the branch the trust pins")
        }
        return rule to branch
    }

    private const val JOB_TITLE = "one job: a checkout, then the Thoryn action, with an ID token"

    private fun jobRule(doc: JsonNode): RuleResult {
        val all = jobs(doc)
        val problems = mutableListOf<String>()
        if (all.size != 1) problems += "the stub must have exactly one job (has ${all.joinToString(", ") { it.first }.ifEmpty { "none" }})"
        val (name, job) = all.firstOrNull { (_, j) -> j.steps().any(::isActionStep) } ?: all.first()
        job.keys().filter { it !in FORGEJO_JOB_KEYS }.forEach { problems += "job `$name` declares `$it`" }
        val oidc = job["enable-openid-connect"]
        if (oidc == null || oidc.asString() != "true") problems += "job `$name` does not set `enable-openid-connect: true`, so Forgejo issues it no ID token and nothing can sign in"
        val steps = job.steps()
        val actionAt = steps.indexOfFirst(::isActionStep)
        if (steps.count(::isActionStep) != 1) problems += "job `$name` must call the action exactly once"
        if (actionAt >= 0 && steps.take(actionAt).none(::isCheckoutStep)) problems += "job `$name` does not check the repository out before the action"
        if (actionAt >= 0) steps[actionAt].keys().filter { it !in setOf("name", "id", "uses", "with") }.forEach { problems += "the action's step declares `$it`" }
        return if (problems.isEmpty()) {
            pass("forgejo.job", JOB_TITLE, "job `$name`: enable-openid-connect: true; a checkout, then the action")
        } else {
            fail("forgejo.job", JOB_TITLE, problems, "one job with only ${FORGEJO_JOB_KEYS.sorted().joinToString(", ")}; `enable-openid-connect: true`; steps: a checkout (e.g. `uses: https://code.forgejo.org/actions/checkout@v4`), then `uses: $FORGEJO_ACTION@$FORGEJO_MINIMUM_RELEASE` — the runner and timeout are the job's, everything else is .thoryn/workflow.yaml")
        }
    }

    private const val APPLY_GATE_TITLE = "the stub can apply only on a workflow_dispatch of the default branch"

    /**
     * What would let a stub apply outside a default-branch dispatch, or widen what a dispatch applies: a step running its own
     * commands or another action (an own `thoryn provision apply` runs on every trigger), a checkout of another ref or
     * repository (an apply of code nobody merged), an `env:` over the job's context, or a dispatch input.
     */
    private fun applyGateRule(doc: JsonNode): RuleResult {
        val problems = mutableListOf<String>()
        jobs(doc).forEach { (name, job) ->
            job.steps().forEachIndexed { i, step ->
                val label = step["name"].str()?.let { "`$it`" } ?: "#${i + 1}"
                when {
                    isActionStep(step) -> Unit
                    step.has("run") -> problems += "job `$name` step $label runs its own commands — a `thoryn provision apply` there would apply on every trigger the job runs on"
                    isCheckoutStep(step) -> step["with"].keys().filter { it in FORGEJO_CHECKOUT_FORBIDDEN_INPUTS }.forEach {
                        problems += "the checkout sets `with.$it` — an apply must converge the dispatched commit of this repository, at the workspace root"
                    }
                    else -> problems += "job `$name` step $label calls `${step["uses"].str() ?: "(nothing)"}` — only a checkout runs before the action"
                }
                if (step.has("env")) problems += "job `$name` step $label sets `env:`"
            }
            if (job.has("env")) problems += "job `$name` sets `env:`"
        }
        if (doc.has("env")) problems += "the workflow sets `env:`"
        val dispatch = triggers(doc)["workflow_dispatch"]
        val inputs = dispatch?.get("inputs").keys()
        if (inputs.isNotEmpty()) problems += "workflow_dispatch takes input(s) ${inputs.joinToString(", ")} — a dispatch is not review, so it takes nothing that could change what an apply does"
        return if (problems.isEmpty()) {
            pass("forgejo.apply-gate", APPLY_GATE_TITLE, "no step but the checkout and the action, no env:, a dispatch without inputs — the action applies only on a workflow_dispatch of the default branch, and the platform mints apply scopes to nothing else")
        } else {
            fail("forgejo.apply-gate", APPLY_GATE_TITLE, problems, "remove every other step, every `env:` (THORYN_* variables go in .thoryn/workflow.yaml `env`), the checkout's ${FORGEJO_CHECKOUT_FORBIDDEN_INPUTS.joinToString("/")} inputs and the dispatch's inputs")
        }
    }

    private const val USES_TITLE = "the action is called by its full URL, pinned to a release"

    /** `forgejo.uses`, and the ref the action is pinned at (null when it is not the Thoryn action on github.com). */
    private fun usesRule(step: JsonNode): Pair<RuleResult, String?> {
        val uses = step["uses"].asString()
        val ref = uses.substringAfter('@', "")
        val fix = "use `uses: $FORGEJO_ACTION@$FORGEJO_MINIMUM_RELEASE` (or a newer cli-v* tag, or a full commit SHA with `with.cli-version`)"
        if (!uses.startsWith("$FORGEJO_ACTION@")) {
            return if (uses.startsWith("$FORGEJO_ACTION_NAME@")) {
                fail("forgejo.uses", USES_TITLE, listOf("`$uses` has no host: Forgejo resolves it against the instance's DEFAULT_ACTIONS_URL (data.forgejo.org on most instances), not github.com, where thoryn-cli lives"), fix) to null
            } else {
                RuleResult("forgejo.uses", USES_TITLE, Status.UNVERIFIABLE, "`$uses` is not $FORGEJO_ACTION — a copy on another host cannot be verified as thoryn-cli's", fix) to null
            }
        }
        val rule = when {
            COMMIT_SHA_GRAMMAR.matches(ref) -> pass("forgejo.uses", USES_TITLE, "$FORGEJO_ACTION@$ref (a commit)")
            ProvisioningWorkflowContract.releaseVersion(ref) == null -> fail("forgejo.uses", USES_TITLE, listOf("`@$ref` is a branch, not a release"), "$fix — a branch moves under you")
            !ProvisioningWorkflowContract.shipsForgejoAction(ref) -> fail("forgejo.uses", USES_TITLE, listOf("`@$ref` predates the Forgejo action ($FORGEJO_MINIMUM_RELEASE)"), fix)
            else -> pass("forgejo.uses", USES_TITLE, "$FORGEJO_ACTION@$ref")
        }
        return rule to ref
    }

    private const val WITH_TITLE = "the with: block passes only the action's inputs, as literals"

    private fun withRule(step: JsonNode, ref: String?): Pair<RuleResult, Map<String, String>> {
        val with = step["with"]
        val problems = mutableListOf<String>()
        val fixes = mutableListOf<String>()
        with.keys().filter { it !in FORGEJO_ACTION_INPUTS }.forEach {
            problems += "`with.$it` is not an input of the action" + if (it in setOf("mode", "apply", "plan")) " — no input selects plan or apply: the job's own trigger does" else ""
            fixes += "remove `with.$it` — the inputs are ${FORGEJO_ACTION_INPUTS.keys.joinToString(", ")}"
        }
        val effective = linkedMapOf<String, String>()
        FORGEJO_ACTION_INPUTS.forEach { (name, spec) ->
            val value = with?.get(name)?.let { if (it.isValueNode) it.asString() else it.toString() }
            if (value == null) { effective[name] = spec.default ?: ""; return@forEach }
            effective[name] = value
            when {
                value.contains("\${{") -> { problems += "`with.$name` is an expression (`$value`)"; fixes += "give `with.$name` a literal value — ${spec.grammarHint}" }
                spec.grammar != null && value.isNotEmpty() && !spec.grammar.matches(value) -> { problems += "`with.$name: $value` is not ${spec.grammarHint}"; fixes += "set `with.$name` to ${spec.grammarHint}" }
            }
        }
        effective["cli-version"]?.takeIf { ProvisioningWorkflowContract.releaseVersion(it) != null && !ProvisioningWorkflowContract.shipsForgejoAction(it) }?.let {
            problems += "`with.cli-version: $it` predates the Forgejo action"
            fixes += "set `with.cli-version` to $FORGEJO_MINIMUM_RELEASE or newer, or omit it (the called release's own CLI runs)"
        }
        if (ref != null && COMMIT_SHA_GRAMMAR.matches(ref) && effective["cli-version"].isNullOrEmpty()) {
            problems += "the action is pinned to a commit and `with.cli-version` is empty, so it cannot tell which CLI release to run"
            fixes += "set `with.cli-version` to the cli-v* release that commit is tagged with"
        }
        val rule = if (problems.isEmpty()) {
            pass("forgejo.with", WITH_TITLE, "issuer ${effective["issuer"]}" + (effective["id-token-origin"]?.takeIf { it.isNotEmpty() }?.let { ", id-token-origin $it" } ?: ""))
        } else {
            fail("forgejo.with", WITH_TITLE, problems, fixes.joinToString("; "))
        }
        return rule to effective
    }

    private const val CONFIG_TITLE = "the configuration and its connections sign in as this Forgejo repository"

    /**
     * `forgejo.config` — `.thoryn/workflow.yaml` says `provider: forgejo`, and (with a repository root) every configured
     * connection signs in as a Forgejo job: `auth.provider: forgejo`, its ref pin on the branch the stub filters, a plan
     * profile mirrored on a production trust (a pull request and a push plan with it, and are refused without one), and
     * `auth.audience` when the job hands it the token as a file (the action requests the token for that audience).
     */
    fun configRule(config: WorkflowConfig, connections: Map<String, Connection>?, branch: String?, effective: Map<String, String>): RuleResult {
        val problems = mutableListOf<String>()
        val source = config.source ?: "the built-in defaults (no ${WorkflowConfig.DEFAULT_PATH})"
        if (config.provider != WorkflowConfig.PROVIDER_FORGEJO) problems += "$source has provider `${config.provider}` — a Forgejo stub needs `provider: forgejo`"
        val fileSourced = mutableListOf<String>()
        connections?.forEach { (path, c) ->
            if (c.effectiveProvider != Connection.PROVIDER_FORGEJO) { problems += "$path signs in as `${c.effectiveProvider}` — a Forgejo job needs `auth.provider: forgejo` (`thoryn workload-identity trusts get <id> --connection` prints it)"; return@forEach }
            if (c.tokenFile != null) {
                fileSourced += path
                if (c.audience == null) problems += "$path reads its token from a file and names no `auth.audience` — the action requests the job token for exactly that audience"
            }
            val pin = c.forgejo?.ref
            if (branch != null && pin != null && pin != "refs/heads/$branch") problems += "$path pins `$pin`, and the stub filters on `$branch` — the platform plans and applies only on the trust's pinned branch"
            if (c.environment == null && c.planScopes == null) problems += "$path mirrors no plan profile (`auth.plan`): on a production trust every pull-request and push plan is refused without one — add it (`thoryn workload-identity trusts set-plan-profile <id>`) and print the connection again"
        }
        if (connections != null && effective["id-token-origin"].orEmpty().isNotEmpty() && fileSourced.isEmpty()) {
            problems += "`with.id-token-origin` is set, and no configured connection reads its token from a file (`auth.tokenSource: {kind: file, path}`), so it does nothing"
        }
        return if (problems.isEmpty()) {
            pass(
                "forgejo.config", CONFIG_TITLE,
                "provider forgejo" + (connections?.let { ", ${it.size} connection(s) on auth.provider forgejo" } ?: "") +
                    (if (fileSourced.isNotEmpty()) "; ${fileSourced.joinToString(", ")} get a fresh job token as a file before each sign-in" else ""),
            )
        } else {
            fail("forgejo.config", CONFIG_TITLE, problems, "set `provider: forgejo` in ${WorkflowConfig.DEFAULT_PATH} and use each forgejo trust's connection as `thoryn workload-identity trusts get <id> --connection` prints it")
        }
    }

    // ── action.* — the called side ──────────────────────────────────────────────────────────────────────────────

    /** The action's own rules: its inputs are the contract's, it is a bash composite, it reads the config through the CLI, it writes nothing back, and no expression reaches a shell. */
    fun actionRules(doc: JsonNode, text: String): List<RuleResult> {
        val out = mutableListOf<RuleResult>()
        val inputs = doc["inputs"]
        val ip = mutableListOf<String>()
        if (inputs.keys() != FORGEJO_ACTION_INPUTS.keys.toList()) ip += "inputs are ${inputs.keys().joinToString(", ")}; the contract lists ${FORGEJO_ACTION_INPUTS.keys.joinToString(", ")}"
        FORGEJO_ACTION_INPUTS.forEach { (name, spec) ->
            val node = inputs?.get(name) ?: return@forEach
            if ((node["required"]?.asBoolean() ?: false) != spec.required) ip += "input `$name` required must be ${spec.required}"
            if ((node["default"].str() ?: "") != (spec.default ?: "")) ip += "input `$name` default must be `${spec.default}` (was `${node["default"].str()}`)"
        }
        out += if (ip.isEmpty()) pass("action.inputs", "the action declares the contract's inputs", FORGEJO_ACTION_INPUTS.keys.joinToString(", "))
        else fail("action.inputs", "the action declares the contract's inputs", ip, "align `inputs` with ProvisioningWorkflowContract.FORGEJO_ACTION_INPUTS (one source: change both)")

        val steps = doc["runs"].steps()
        val runs = steps.mapNotNull { it["run"].str() }
        val rp = mutableListOf<String>()
        if (doc["runs"]?.get("using").str() != "composite") rp += "runs.using must be composite"
        steps.filter { it.has("run") && it["shell"].str() != "bash" }.forEach { rp += "step `${it["name"].str()}` must declare `shell: bash`" }
        if (runs.none { it.contains("provision workflow check") && it.contains("--output json") }) rp += "a step must read ${WorkflowConfig.DEFAULT_PATH} through `thoryn provision workflow check --output json`"
        if (runs.none { it.contains("workflow_dispatch)") && it.contains("mode=apply") }) rp += "the mode step must map only a workflow_dispatch to apply"
        if (runs.any { it.contains("git push") || it.contains("git commit") || it.contains("gh pr create") }) rp += "a run block writes back to the repository"
        if (text.contains("secrets.")) rp += "the action references `secrets`"
        val leaking = runs.filter { it.contains("\${{") }
        if (leaking.isNotEmpty()) rp += "${leaking.size} run block(s) interpolate an expression into the shell's source"
        out += if (rp.isEmpty()) pass("action.steps", "a bash composite that reads the config through the CLI and writes nothing back", "${steps.size} steps; every value reaches a shell through env:")
        else fail("action.steps", "a bash composite that reads the config through the CLI and writes nothing back", rp, "shape the action as docs/provisioning-workflow-contract.md §8 describes")
        return out
    }
}
