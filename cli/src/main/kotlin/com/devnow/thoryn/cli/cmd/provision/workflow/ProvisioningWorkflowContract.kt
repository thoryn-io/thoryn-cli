package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.provision.FixRequest

/**
 * SSO-3719 (epic SSO-3304) — the PROVISIONING WORKFLOW CONTRACT, version [CONTRACT_VERSION]: what the Thoryn GitHub
 * App dispatches (oauthy converge ADR 2026-10-13 Amendments 1, 5–7; the orchestrator's `ThorynFiles.kt`) and what the
 * reusable workflow `thoryn-io/thoryn-cli/.github/workflows/provisioning.yml` satisfies. One source for three readers:
 * the reusable workflow (holds to it), the stub every repository keeps (`thoryn provision workflow check` lints it),
 * and the dogfood conformance tests (hold THIS repository's files to it).
 *
 * This is an INTERNAL contract between the App and the reusable workflow, not a customer authoring surface (product
 * owner, 2026-10-15): a customer's power comes from CONFIGURATION — the stub's `with:` block ([REUSABLE_INPUTS]) and the
 * committed `.thoryn/workflow.yaml` ([WorkflowConfig]) — never from a hand-edited job. A hand-written workflow is
 * "not the supported shape"; the check still says what the App would need from it.
 *
 * WHY A WORKFLOW FILE STAYS AT ALL: the job's GitHub OIDC token IS the repository's identity, and the job's GitHub
 * environment is the review gate the hub pins (Amendment 5). Neither can move into the App, which never holds a Thoryn
 * credential. Everything else moves out, into the reusable workflow.
 */
object ProvisioningWorkflowContract {

    /** Bump when a rule changes what a valid stub or reusable workflow looks like. */
    const val CONTRACT_VERSION: Int = 1

    /** Where the App dispatches: the ONE path it looks for (`ThorynFiles.WORKFLOW_PATH`). */
    const val WORKFLOW_PATH: String = ".github/workflows/thoryn-provisioning.yml"

    /** The reusable workflow a stub calls, without its `@<ref>`. */
    const val REUSABLE_WORKFLOW: String = "thoryn-io/thoryn-cli/.github/workflows/provisioning.yml"

    /** The reusable workflow's own path in this repository. */
    const val REUSABLE_WORKFLOW_PATH: String = ".github/workflows/provisioning.yml"

    /** The first thoryn-cli release that ships the reusable workflow and `thoryn provision workflow check`. */
    const val MINIMUM_RELEASE: String = "cli-v0.36.0"

    /** Present in the dispatched workflow iff it carries an apply job — what the App checks before dispatching `apply`. */
    const val APPLY_JOB_MARKER: String = "# thoryn-provisioning: apply-job"

    /** The `run-name` fragment the App finds the dispatched run by, to complete its check run. */
    const val RUN_NAME_MARKER: String = "check-run:\${{ inputs.check_run_id }}"

    /** `concurrency.group` must be per mode: a plan and an apply never wait on each other, two applies never race. */
    const val CONCURRENCY_MODE_FRAGMENT: String = "\${{ inputs.mode }}"

    val MODES: List<String> = listOf("plan", "apply")

    /** The run artifact the App reads a red job's fix request from (SSO-3710). */
    const val FIX_REQUEST_ARTIFACT: String = FixRequest.ARTIFACT_NAME

    /** A `workflow_dispatch` input the App sends. */
    data class DispatchInput(val required: Boolean, val type: String, val options: List<String>? = null)

    /** The App dispatches with exactly these (`ThorynFiles.workflowYaml`). */
    val DISPATCH_INPUTS: Map<String, DispatchInput> = linkedMapOf(
        "mode" to DispatchInput(required = true, type = "choice", options = MODES),
        "head_sha" to DispatchInput(required = true, type = "string"),
        "check_run_id" to DispatchInput(required = true, type = "string"),
        "pr_number" to DispatchInput(required = false, type = "string"),
    )

    /** What a stub's `uses:` job grants the called jobs — and exactly what each called job declares. */
    val JOB_PERMISSIONS: Map<String, String> = linkedMapOf("id-token" to "write", "checks" to "write", "contents" to "read")

    /** How a stub forwards a dispatch input: `${{ inputs.<name> }}`, verbatim. */
    fun forwarded(input: String): String = "\${{ inputs.$input }}"

    /**
     * An input of the reusable workflow. [grammar] validates a LITERAL value in a stub's `with:`; [forwardedDispatchInput]
     * marks the four the stub must forward as [forwarded] expressions instead.
     */
    data class ReusableInput(
        val description: String,
        val type: String = "string",
        val required: Boolean = false,
        val default: String? = null,
        val grammar: Regex? = null,
        val grammarHint: String? = null,
        val forwardedDispatchInput: Boolean = false,
    )

    /** A GitHub environment name: GitHub allows letters, digits, `_`, `-`, `.` and spaces (no `${{`). */
    val GITHUB_ENVIRONMENT_GRAMMAR = Regex("^[A-Za-z0-9][A-Za-z0-9_. -]{0,254}$")
    val HTTPS_URL_GRAMMAR = Regex("^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$")
    val RELEASE_TAG_GRAMMAR = Regex("^cli-v[0-9]+\\.[0-9]+\\.[0-9]+$")
    val COMMIT_SHA_GRAMMAR = Regex("^[0-9a-f]{40}$")
    /** A runner label, or a JSON array of labels (`["self-hosted", "linux"]`). */
    val RUNS_ON_GRAMMAR = Regex("^([A-Za-z0-9][A-Za-z0-9_.-]{0,99}|\\[\\s*\"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\"(\\s*,\\s*\"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\")*\\s*\\])$")
    val POSITIVE_INT_GRAMMAR = Regex("^[1-9][0-9]{0,3}$")

    /**
     * The reusable workflow's `on.workflow_call.inputs`, in order — the stub's `with:` surface. The reusable workflow file
     * is held to this map by the conformance test; `thoryn provision workflow check` refuses a `with:` key not in it.
     */
    val REUSABLE_INPUTS: Map<String, ReusableInput> = linkedMapOf(
        "mode" to ReusableInput("plan or apply — forwarded from the App's dispatch input.", required = true, forwardedDispatchInput = true),
        "head_sha" to ReusableInput("The commit to plan or apply — forwarded.", required = true, forwardedDispatchInput = true),
        "check_run_id" to ReusableInput("The App's check run — forwarded.", required = true, forwardedDispatchInput = true),
        "pr_number" to ReusableInput("The pull request (plan only) — forwarded.", default = "", forwardedDispatchInput = true),
        "plan-environment" to ReusableInput(
            "The UNPROTECTED GitHub environment the plan job runs in (the trust's plan profile is keyed on it).",
            required = true, grammar = GITHUB_ENVIRONMENT_GRAMMAR, grammarHint = "a GitHub environment name",
        ),
        "apply-environment" to ReusableInput(
            "The REVIEWED GitHub environment the apply job runs in (required reviewers; the trust pins it).",
            required = true, grammar = GITHUB_ENVIRONMENT_GRAMMAR, grammarHint = "a GitHub environment name",
        ),
        "issuer" to ReusableInput(
            "Platform base issuer (THORYN_ISSUER / THORYN_HUB for the CLI), e.g. https://auth.thoryn.io.",
            default = "https://auth.thoryn.io", grammar = HTTPS_URL_GRAMMAR, grammarHint = "an https:// origin",
        ),
        "cli-version" to ReusableInput(
            "A cli-v* release to run. Empty: the release tagged at the called workflow's own commit (github.job_workflow_sha), else the latest.",
            default = "", grammar = RELEASE_TAG_GRAMMAR, grammarHint = "a cli-v<major>.<minor>.<patch> tag",
        ),
        "runs-on" to ReusableInput(
            "Runner label, or a JSON array of labels for a self-hosted pool (needs gh, jq, bash; Java is set up).",
            default = "ubuntu-latest", grammar = RUNS_ON_GRAMMAR, grammarHint = "a label, or a JSON array of labels",
        ),
        "timeout-minutes" to ReusableInput(
            "Job timeout in minutes, each job.",
            type = "number", default = "30", grammar = POSITIVE_INT_GRAMMAR, grammarHint = "a positive whole number of minutes",
        ),
        "config" to ReusableInput(
            "Path of the committed run-time configuration the reusable workflow reads (files, env, fixRequest, consentUrl, apply).",
            default = WorkflowConfig.DEFAULT_PATH, grammar = WorkflowConfig.PATH_GRAMMAR, grammarHint = "a relative path inside the repository",
        ),
        "consent-url" to ReusableInput(
            "SSO-3723 — base URL of the Thoryn GitHub App's browser consent (THORYN_CONSENT_URL for the CLI): a red job prints `To fix — Option 2, in the browser: <url>/github/consent/run/<owner>/<repo>/<run_id>`. Empty: .thoryn/workflow.yaml consentUrl, else Option 1 alone.",
            default = "", grammar = WorkflowConfig.CONSENT_URL_GRAMMAR, grammarHint = "an https:// base URL (no query or fragment)",
        ),
    )

    /** The inputs a stub MUST pass (the forwarded four and the two environments). */
    val STUB_REQUIRED_INPUTS: List<String> = REUSABLE_INPUTS.filter { it.value.required }.keys.toList()

    /** `<major>.<minor>.<patch>` of a `cli-v*` tag as a comparable list; null for anything else. */
    fun releaseVersion(tag: String): List<Int>? =
        RELEASE_TAG_GRAMMAR.matchEntire(tag)?.let { tag.removePrefix("cli-v").split('.').map(String::toInt) }

    /** Is [tag] at least [MINIMUM_RELEASE]? */
    fun isAtLeastMinimumRelease(tag: String): Boolean {
        val v = releaseVersion(tag) ?: return false
        val min = releaseVersion(MINIMUM_RELEASE)!!
        for (i in 0..2) {
            if (v[i] != min[i]) return v[i] > min[i]
        }
        return true
    }
}
