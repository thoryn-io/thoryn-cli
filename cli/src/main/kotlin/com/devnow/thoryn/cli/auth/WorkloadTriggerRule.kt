package com.devnow.thoryn.cli.auth

/**
 * SSO-4472 — the CLI's copy of the provider-neutral profile rule for a CI provider WITHOUT reviewer-protected
 * environments (thoryn-architecture ADR `2026-10-14-plan-identity-and-resource-ownership`, Amendment 2026-11-23,
 * C5–C7; the hub's evaluator is oauthy SSO-4471). Forgejo follows it first; a GitHub trust keeps its environment
 * selector ([WorkloadProfile.select]).
 *
 * The HUB decides; this copy only lets `thoryn login --connection` decide whether to send `scope` (the connection's
 * scopes for an expected APPLY, none otherwise — so the hub mints the matched profile, never a write scope to a plan
 * job), and lets a refusal be explained with the job's own trigger class.
 */
enum class TriggerClass(val wire: String) {
    /** A person, by hand, on a chosen ref (Forgejo `workflow_dispatch`). */
    DISPATCH("dispatch"),

    /** Commits pushed to a ref (`push`). */
    PUSH("push"),

    /** The provider's scheduler (`schedule`). */
    SCHEDULE("schedule"),

    /** A same-repository pull request whose code the job runs (`pull_request`; the target branch in `base_ref`). */
    CHANGE_REQUEST("change-request"),

    /** The base repository's workflow, run for a request that may come from a fork (`pull_request_target`). */
    BASE_CODE_CHANGE_INPUT("base-code-change-input"),

    /** The token does not say what started the run (`workflow_call`: a reusable workflow's job). */
    HIDDEN_TRIGGER("hidden-trigger"),

    /** Any other event (releases, comments, …), or none at all. */
    OTHER("other"),
}

/** SSO-4472 — Forgejo's mapping of a job token to a [TriggerClass] (the amendment's rule 1 table, Forgejo v17.0.1). */
object ForgejoTriggerMapping {
    fun classify(eventName: String?): TriggerClass = when (eventName) {
        "workflow_dispatch" -> TriggerClass.DISPATCH
        "push" -> TriggerClass.PUSH
        "schedule" -> TriggerClass.SCHEDULE
        "pull_request" -> TriggerClass.CHANGE_REQUEST
        "pull_request_target" -> TriggerClass.BASE_CODE_CHANGE_INPUT
        "workflow_call" -> TriggerClass.HIDDEN_TRIGGER
        else -> TriggerClass.OTHER
    }
}

/**
 * SSO-4472 — what the hub is expected to answer for one job, by the amendment's rules 2–5, as far as the CLI can tell
 * from the connection: [Mint] a profile, [Refused] with the hub's audited reason, or [Unknown] (the connection does not
 * name the production pin, or a sandbox event the rule leaves "as today").
 */
sealed interface TriggerExpectation {
    data class Mint(val minted: WorkloadProfile) : TriggerExpectation

    /** [reason] is the hub's audited `errorReason` (`event_not_allowed`, `ref_mismatch`, `base_ref_mismatch`). */
    data class Refused(val reason: String, val explanation: String) : TriggerExpectation

    data object Unknown : TriggerExpectation

    /** The profile expected to be minted, or null (refused, or the CLI cannot tell). */
    val profile: WorkloadProfile? get() = (this as? Mint)?.minted
}

object TriggerProfileRule {
    const val EVENT_NOT_ALLOWED = "event_not_allowed"
    const val REF_MISMATCH = "ref_mismatch"
    const val BASE_REF_MISMATCH = "base_ref_mismatch"

    private const val BRANCH_PREFIX = "refs/heads/"

    /**
     * The expectation for a job of class [trigger] on [ref] (target branch [baseRef] for a change request) under a trust
     * pinned to [pinnedRef] on the [production] plane. [hasPlanProfile] is whether the connection mirrors a plan profile
     * (`auth.plan`); a push, schedule or change request that would get the plan profile is refused without one.
     */
    fun expect(
        trigger: TriggerClass,
        ref: String?,
        baseRef: String?,
        pinnedRef: String?,
        production: Boolean,
        hasPlanProfile: Boolean,
    ): TriggerExpectation {
        // Rule 4 — refused on every plane, sandbox included.
        when (trigger) {
            TriggerClass.BASE_CODE_CHANGE_INPUT -> return TriggerExpectation.Refused(
                EVENT_NOT_ALLOWED,
                "pull_request_target jobs are always refused (they run the base repository's code with a fork's input).",
            )
            TriggerClass.HIDDEN_TRIGGER -> return TriggerExpectation.Refused(
                EVENT_NOT_ALLOWED,
                "workflow_call jobs are always refused: a reusable workflow's job hides what started the run. Run `thoryn login` " +
                    "in the job's own steps (an action), never inside a reusable workflow.",
            )
            else -> Unit
        }
        val pin = pinnedRef?.trim()?.takeIf { it.isNotEmpty() }
        if (!production) {
            // Rule 5 — a sandbox trust keeps D8's sandbox column: the accepted classes get APPLY.
            if (trigger == TriggerClass.OTHER) return TriggerExpectation.Unknown
            if (pin != null && trigger != TriggerClass.CHANGE_REQUEST && ref != null && ref != pin) {
                return TriggerExpectation.Refused(REF_MISMATCH, "the trust pins ref '$pin'; this job runs on '$ref'.")
            }
            return TriggerExpectation.Mint(WorkloadProfile.APPLY)
        }
        // Rule 2 — a production trust pins one branch ref P; without it (a connection that does not mirror it) the CLI cannot tell.
        if (pin == null) return TriggerExpectation.Unknown
        val branch = pin.removePrefix(BRANCH_PREFIX)
        fun plan(what: String): TriggerExpectation =
            if (hasPlanProfile) {
                TriggerExpectation.Mint(WorkloadProfile.PLAN)
            } else {
                TriggerExpectation.Refused(
                    EVENT_NOT_ALLOWED,
                    "$what gets the trust's PLAN profile, and the connection names none (no auth.plan): the trust must carry a plan " +
                        "profile — or apply from a workflow_dispatch on '$pin'.",
                )
            }
        return when (trigger) {
            TriggerClass.DISPATCH ->
                if (ref == pin) {
                    TriggerExpectation.Mint(WorkloadProfile.APPLY)
                } else {
                    TriggerExpectation.Refused(REF_MISMATCH, "a dispatch applies only on the pinned ref '$pin'; this one runs on '${ref ?: "(none)"}'.")
                }
            TriggerClass.PUSH, TriggerClass.SCHEDULE ->
                if (ref == pin) {
                    plan("a ${trigger.wire} on '$pin'")
                } else {
                    TriggerExpectation.Refused(
                        REF_MISMATCH,
                        "a ${trigger.wire} gets a plan only on the pinned ref '$pin'; this one runs on '${ref ?: "(none)"}' (open a pull request into '$branch' to get a plan).",
                    )
                }
            TriggerClass.CHANGE_REQUEST -> when {
                // MEASURE-ON-FORGE (SSO-4474): `base_ref` is the short branch name; the full ref is accepted locally too.
                baseRef == null -> TriggerExpectation.Unknown
                baseRef == branch || baseRef == pin -> plan("a pull request into '$branch'")
                else -> TriggerExpectation.Refused(BASE_REF_MISMATCH, "a pull request gets a plan only into '$branch'; this one targets '$baseRef'.")
            }
            else -> TriggerExpectation.Refused(
                EVENT_NOT_ALLOWED,
                "a production trust mints only to a workflow_dispatch, a push or schedule, or a pull request; this job was started by none of them.",
            )
        }
    }
}
