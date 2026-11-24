package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.ForgejoFixtures.STUB
import com.devnow.thoryn.cli.cmd.provision.workflow.ForgejoFixtures.connection
import com.devnow.thoryn.cli.cmd.provision.workflow.ForgejoFixtures.evaluate
import com.devnow.thoryn.cli.cmd.provision.workflow.ForgejoFixtures.stubWith
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * SSO-4474 — `thoryn provision workflow check` over a Forgejo stub: the example stub passes every rule, and each way a
 * stub could apply outside a workflow_dispatch of the default branch (or widen what a dispatch applies) is refused by the
 * rule that names it.
 */
class ForgejoWorkflowCheckTest {

    @TempDir
    lateinit var dir: File

    private fun rule(report: WorkflowCheck.Report, id: String) = report.rules.single { it.id == id }

    @Test
    fun `the example stub with a forgejo configuration is the supported Forgejo shape and passes every rule`() {
        val report = evaluate(dir)
        assertThat(report.shape).isEqualTo(WorkflowCheck.Shape.FORGEJO_STUB)
        assertThat(report.supported).isTrue()
        assertThat(report.rules.filter { it.failed }).withFailMessage("%s", report.rules.filter { it.failed }).isEmpty()
        assertThat(report.rules.map { it.id }).contains(
            "forgejo.triggers", "forgejo.branches", "forgejo.job", "forgejo.apply-gate", "forgejo.uses", "forgejo.with",
            "config.valid", "forgejo.config", "config.secret-delivery", "config.trust-scopes", "common.no-secrets", "common.no-expression-in-run",
        )
        // No GitHub App contract on Forgejo: nothing dispatches mode / head_sha / check_run_id.
        assertThat(report.rules.map { it.id }).noneMatch { it.startsWith("dispatch.") || it.startsWith("stub.") }
        assertThat(report.inputs).containsEntry("issuer", "https://auth.thoryn.io").containsEntry("cli-version", "").containsEntry("id-token-origin", "")
        assertThat(report.toStructured()["shape"]).isEqualTo("forgejo_stub")
    }

    /** Each mutation of the example stub that would apply outside a default-branch dispatch, and the rule that refuses it. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("applyEscapes")
    fun `a stub that could apply outside a workflow_dispatch of the default branch is refused`(case: String, stub: String, ruleId: String, says: String) {
        val report = evaluate(dir, stub = stub)
        assertThat(report.ok).isFalse()
        val r = rule(report, ruleId)
        assertThat(r.status).withFailMessage("%s should not pass: %s", ruleId, r.detail).isNotEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains(says)
        assertThat(r.fix).isNotBlank()
    }

    @Test
    fun `a stub without an ID token, a checkout or the action's full URL is refused`() {
        assertThat(rule(evaluate(dir, stub = stubWith("    enable-openid-connect: true\n", "")), "forgejo.job").detail)
            .contains("does not set `enable-openid-connect: true`")
        assertThat(rule(evaluate(dir, stub = stubWith("      - uses: https://code.forgejo.org/actions/checkout@v4\n", "")), "forgejo.job").detail)
            .contains("does not check the repository out before the action")
        val bare = rule(evaluate(dir, stub = stubWith("https://github.com/thoryn-io/thoryn-cli/forgejo/provisioning@", "thoryn-io/thoryn-cli/forgejo/provisioning@")), "forgejo.uses")
        assertThat(bare.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(bare.detail).contains("DEFAULT_ACTIONS_URL")
        val mirror = rule(evaluate(dir, stub = stubWith("https://github.com/thoryn-io/", "https://codeberg.org/thoryn-io/")), "forgejo.uses")
        assertThat(mirror.status).isEqualTo(WorkflowCheck.Status.UNVERIFIABLE)
    }

    @Test
    fun `the action must be pinned to a release that ships it, and a commit pin names the CLI release`() {
        assertThat(rule(evaluate(dir, stub = stubWith("@cli-v0.61.0", "@cli-v0.60.2")), "forgejo.uses").detail).contains("predates the Forgejo action")
        assertThat(rule(evaluate(dir, stub = stubWith("@cli-v0.61.0", "@main")), "forgejo.uses").detail).contains("is a branch, not a release")
        val sha = "0123456789abcdef0123456789abcdef01234567"
        val pinned = evaluate(dir, stub = stubWith("@cli-v0.61.0", "@$sha"))
        assertThat(rule(pinned, "forgejo.uses").status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(rule(pinned, "forgejo.with").detail).contains("pinned to a commit and `with.cli-version` is empty")
        val named = evaluate(dir, stub = stubWith("@cli-v0.61.0", "@$sha").replace("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n          cli-version: cli-v0.61.0"))
        assertThat(rule(named, "forgejo.with").status).isEqualTo(WorkflowCheck.Status.PASS)
    }

    @Test
    fun `the configuration and its connections must sign in as this Forgejo repository`() {
        assertThat(rule(evaluate(dir, config = "apiVersion: thoryn.io/workflow/v1\n"), "forgejo.config").detail)
            .contains("has provider `github_actions` — a Forgejo stub needs `provider: forgejo`")
        assertThat(rule(evaluate(dir, connection = connection(provider = "github_actions", plan = "")), "forgejo.config").detail)
            .contains("signs in as `github_actions`")
        assertThat(rule(evaluate(dir, connection = connection(ref = "refs/heads/develop")), "forgejo.config").detail)
            .contains("pins `refs/heads/develop`, and the stub filters on `main`")
        assertThat(rule(evaluate(dir, connection = connection(plan = "")), "forgejo.config").detail)
            .contains("mirrors no plan profile (`auth.plan`)")
    }

    @Test
    fun `behind an authenticating proxy the file-sourced connection names its audience, and id-token-origin needs one`() {
        val fileSourced = connection(auth = "\"tokenSource\": { \"kind\": \"file\", \"path\": \"/tmp/thoryn/job-token\" },")
        val withOrigin = stubWith("issuer: https://auth.thoryn.io", "issuer: https://auth.thoryn.io\n          id-token-origin: http://forgejo-http.forge.svc:3000")
        val ok = evaluate(dir, stub = withOrigin, connection = fileSourced)
        assertThat(rule(ok, "forgejo.config").status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(rule(ok, "forgejo.config").detail).contains("get a fresh job token as a file before each sign-in")
        assertThat(rule(ok, "forgejo.with").detail).contains("id-token-origin http://forgejo-http.forge.svc:3000")

        val noAudience = fileSourced.replace("\"audience\": \"https://acme.auth.thoryn.io\",", "")
        assertThat(rule(evaluate(dir, stub = withOrigin, connection = noAudience), "forgejo.config").detail)
            .contains("reads its token from a file and names no `auth.audience`")
        assertThat(rule(evaluate(dir, stub = withOrigin), "forgejo.config").detail)
            .contains("`with.id-token-origin` is set, and no configured connection reads its token from a file")
        assertThat(rule(evaluate(dir, stub = withOrigin.replace("http://forgejo-http.forge.svc:3000", "http://forge.internal/api")), "forgejo.with").detail)
            .contains("is not an http(s):// origin (no path)")
    }

    @Test
    fun `a plan profile with listed scopes must carry every scope the file needs to plan`() {
        val listed = connection(plan = "\"plan\": { \"scopes\": [\"tenant:access.read\"] },")
        val r = rule(evaluate(dir, connection = listed), "config.trust-scopes")
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).contains("needs tenant:roles.read to PLAN").contains("(auth.plan.scopes) does not list it")
        val complete = connection(plan = "\"plan\": { \"scopes\": [\"tenant:roles.read\", \"tenant:access.read\"] },")
        assertThat(rule(evaluate(dir, connection = complete), "config.trust-scopes").status).isEqualTo(WorkflowCheck.Status.PASS)
    }

    @Test
    fun `the released action passes its own rules, and a mode input or an expression in a run block fails them`() {
        val action = ForgejoFixtures.ACTION
        val report = WorkflowCheck.evaluate(action, ProvisioningWorkflowContract.FORGEJO_ACTION_PATH)
        assertThat(report.shape).isEqualTo(WorkflowCheck.Shape.FORGEJO_ACTION)
        assertThat(report.rules.filter { it.id.startsWith("action.") && it.failed }).withFailMessage("%s", report.rules).isEmpty()
        val withMode = action.replace("inputs:\n  issuer:", "inputs:\n  mode:\n    description: plan or apply\n    default: plan\n  issuer:")
        assertThat(rule(WorkflowCheck.evaluate(withMode, "action.yml"), "action.inputs").status).isEqualTo(WorkflowCheck.Status.FAIL)
        val leaking = action.replace("echo \"mode=\$mode\" >> \"\$GITHUB_OUTPUT\"", "echo \"mode=\${{ github.event_name }}\" >> \"\$GITHUB_OUTPUT\"")
        check(leaking != action)
        assertThat(rule(WorkflowCheck.evaluate(leaking, "action.yml"), "action.steps").detail).contains("interpolate an expression")
    }

    companion object {
        private const val ACTION_LINE = "      - uses: https://github.com/thoryn-io/thoryn-cli/forgejo/provisioning@cli-v0.61.0\n"

        @JvmStatic
        fun applyEscapes(): List<Arguments> = listOf(
            Arguments.of(
                "its own apply step",
                STUB.replace(ACTION_LINE, ACTION_LINE.replace("      - uses", "      - run: thoryn provision apply --file .thoryn/provision.yaml --yes\n      - uses")),
                "forgejo.apply-gate", "runs its own commands",
            ),
            Arguments.of("a reusable workflow (workflow_call)", stubWith("  workflow_dispatch:\n", "  workflow_dispatch:\n  workflow_call:\n"), "forgejo.triggers", "`workflow_call`"),
            Arguments.of("pull_request_target", stubWith("  pull_request:\n", "  pull_request_target:\n"), "forgejo.triggers", "`pull_request_target`"),
            Arguments.of(
                "a checkout of another ref",
                stubWith("      - uses: https://code.forgejo.org/actions/checkout@v4\n", "      - uses: https://code.forgejo.org/actions/checkout@v4\n        with:\n          ref: feature\n"),
                "forgejo.apply-gate", "the checkout sets `with.ref`",
            ),
            Arguments.of("an env: over the job's context", stubWith("    timeout-minutes: 30\n", "    timeout-minutes: 30\n    env:\n      GITHUB_EVENT_NAME: workflow_dispatch\n"), "forgejo.apply-gate", "sets `env:`"),
            Arguments.of(
                "a dispatch input",
                stubWith("  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs:\n      prune:\n        type: boolean\n"),
                "forgejo.apply-gate", "workflow_dispatch takes input(s) prune",
            ),
            Arguments.of("a mode input", stubWith("          issuer: https://auth.thoryn.io", "          issuer: https://auth.thoryn.io\n          mode: apply"), "forgejo.with", "no input selects plan or apply"),
            Arguments.of(
                "another action before it",
                stubWith(ACTION_LINE, "      - uses: https://example.org/acme/deploy@v1\n$ACTION_LINE"),
                "forgejo.apply-gate", "calls `https://example.org/acme/deploy@v1`",
            ),
            Arguments.of("a push to every branch", stubWith("  push:\n    branches: [main]\n", "  push:\n"), "forgejo.branches", "`push` has no branch filter"),
            Arguments.of("a push to a branch pattern", stubWith("  push:\n    branches: [main]\n", "  push:\n    branches: ['release/*']\n"), "forgejo.branches", "plain name (no pattern"),
            Arguments.of("no dispatch at all", stubWith("  workflow_dispatch:\n", ""), "forgejo.triggers", "nothing can ever apply"),
        )
    }
}
