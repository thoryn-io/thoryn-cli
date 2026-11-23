package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-4472 — the CLI's copy of the provider-neutral profile rule (ADR 2026-10-14 Amendment 2026-11-23, rules 1–5) and
 * Forgejo's mapping of `event_name` to a trigger class. One assertion group per rule, so reverting any branch of
 * [TriggerProfileRule.expect] or [ForgejoTriggerMapping.classify] fails a test here.
 */
class WorkloadTriggerRuleTest {

    private val pin = "refs/heads/main"

    private fun production(trigger: TriggerClass, ref: String? = pin, baseRef: String? = null, plan: Boolean = true) =
        TriggerProfileRule.expect(trigger, ref, baseRef, pin, production = true, hasPlanProfile = plan)

    @Test
    fun `rule 1 — Forgejo's events map to exactly one trigger class`() {
        assertThat(ForgejoTriggerMapping.classify("workflow_dispatch")).isEqualTo(TriggerClass.DISPATCH)
        assertThat(ForgejoTriggerMapping.classify("push")).isEqualTo(TriggerClass.PUSH)
        assertThat(ForgejoTriggerMapping.classify("schedule")).isEqualTo(TriggerClass.SCHEDULE)
        assertThat(ForgejoTriggerMapping.classify("pull_request")).isEqualTo(TriggerClass.CHANGE_REQUEST)
        assertThat(ForgejoTriggerMapping.classify("pull_request_target")).isEqualTo(TriggerClass.BASE_CODE_CHANGE_INPUT)
        assertThat(ForgejoTriggerMapping.classify("workflow_call")).isEqualTo(TriggerClass.HIDDEN_TRIGGER)
        assertThat(ForgejoTriggerMapping.classify("release")).isEqualTo(TriggerClass.OTHER)
        assertThat(ForgejoTriggerMapping.classify(null)).isEqualTo(TriggerClass.OTHER)
    }

    @Test
    fun `rule 2 — a dispatch on the pinned ref gets APPLY, a dispatch elsewhere is a ref mismatch`() {
        assertThat(production(TriggerClass.DISPATCH).profile).isEqualTo(WorkloadProfile.APPLY)
        val elsewhere = production(TriggerClass.DISPATCH, ref = "refs/heads/feature") as TriggerExpectation.Refused
        assertThat(elsewhere.reason).isEqualTo(TriggerProfileRule.REF_MISMATCH)
    }

    @Test
    fun `rule 2 — a push or schedule on the pinned ref gets PLAN with a plan profile and is refused without one`() {
        assertThat(production(TriggerClass.PUSH).profile).isEqualTo(WorkloadProfile.PLAN)
        assertThat(production(TriggerClass.SCHEDULE).profile).isEqualTo(WorkloadProfile.PLAN)
        val noPlan = production(TriggerClass.PUSH, plan = false) as TriggerExpectation.Refused
        assertThat(noPlan.reason).isEqualTo(TriggerProfileRule.EVENT_NOT_ALLOWED)
        assertThat(noPlan.explanation).contains("plan profile").contains("workflow_dispatch on 'refs/heads/main'")
    }

    @Test
    fun `rule 2 — a push to another branch is refused (a pull request gets the plan)`() {
        val other = production(TriggerClass.PUSH, ref = "refs/heads/feature") as TriggerExpectation.Refused
        assertThat(other.reason).isEqualTo(TriggerProfileRule.REF_MISMATCH)
        assertThat(other.explanation).contains("open a pull request into 'main'")
    }

    @Test
    fun `rule 2 — a same-repository pull request into the pinned branch plans, into another branch it is refused`() {
        assertThat(production(TriggerClass.CHANGE_REQUEST, ref = "refs/pull/9/head", baseRef = "main").profile).isEqualTo(WorkloadProfile.PLAN)
        val other = production(TriggerClass.CHANGE_REQUEST, ref = "refs/pull/9/head", baseRef = "release") as TriggerExpectation.Refused
        assertThat(other.reason).isEqualTo(TriggerProfileRule.BASE_REF_MISMATCH)
        assertThat(production(TriggerClass.CHANGE_REQUEST, ref = "refs/pull/9/head", baseRef = null)).isEqualTo(TriggerExpectation.Unknown)
    }

    @Test
    fun `rule 2 — any other event is refused on production, and an unknown pin leaves the decision to the hub`() {
        assertThat((production(TriggerClass.OTHER) as TriggerExpectation.Refused).reason).isEqualTo(TriggerProfileRule.EVENT_NOT_ALLOWED)
        assertThat(TriggerProfileRule.expect(TriggerClass.DISPATCH, pin, null, pinnedRef = null, production = true, hasPlanProfile = true))
            .isEqualTo(TriggerExpectation.Unknown)
    }

    @Test
    fun `rule 4 — pull_request_target and workflow_call are refused on every plane`() {
        for (production in listOf(true, false)) {
            for (trigger in listOf(TriggerClass.BASE_CODE_CHANGE_INPUT, TriggerClass.HIDDEN_TRIGGER)) {
                val e = TriggerProfileRule.expect(trigger, pin, null, pin, production, hasPlanProfile = true)
                assertThat(e).isInstanceOf(TriggerExpectation.Refused::class.java)
                assertThat((e as TriggerExpectation.Refused).reason).isEqualTo(TriggerProfileRule.EVENT_NOT_ALLOWED)
            }
        }
        val hidden = TriggerProfileRule.expect(TriggerClass.HIDDEN_TRIGGER, pin, null, null, false, false) as TriggerExpectation.Refused
        assertThat(hidden.explanation).contains("reusable workflow")
    }

    @Test
    fun `rule 5 — a sandbox trust gives every accepted class APPLY`() {
        for (trigger in listOf(TriggerClass.DISPATCH, TriggerClass.PUSH, TriggerClass.SCHEDULE, TriggerClass.CHANGE_REQUEST)) {
            assertThat(TriggerProfileRule.expect(trigger, "refs/heads/any", "main", pinnedRef = null, production = false, hasPlanProfile = false).profile)
                .isEqualTo(WorkloadProfile.APPLY)
        }
        assertThat(TriggerProfileRule.expect(TriggerClass.OTHER, pin, null, null, production = false, hasPlanProfile = false)).isEqualTo(TriggerExpectation.Unknown)
    }

    @Test
    fun `the seam reads the job token's own claims — event_name, ref and base_ref`() {
        val pr = JobIdentity.of(FakeJobTokens.forgejoToken("https://acme.auth.example", eventName = "pull_request", ref = "refs/pull/9/head", baseRef = "main"))
        assertThat(pr.baseRef).isEqualTo("main")
        assertThat(WorkloadProfile.forgejoExpectation(pr, pin, production = true, hasPlanProfile = true).profile).isEqualTo(WorkloadProfile.PLAN)
        val dispatch = JobIdentity.of(FakeJobTokens.forgejoToken("https://acme.auth.example", eventName = "workflow_dispatch"))
        assertThat(dispatch.baseRef).isNull() // Forgejo writes "" for a missing context value: treated as absent
        assertThat(WorkloadProfile.forgejoExpectation(dispatch, pin, production = true, hasPlanProfile = false).profile).isEqualTo(WorkloadProfile.APPLY)
    }
}
