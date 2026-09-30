package com.devnow.thoryn.cli.cmd.project

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * SSO-3435 — a config project's production approval per GitHub plan (product-owner settlement 2026-09-30,
 * revised): the `thoryn-production-approval` ruleset on the default branch + the reviewers' CODEOWNERS always;
 * environment reviewers when the plan offers them (Enterprise, or any public repository); a private repository on
 * GitHub Free — no rulesets — is refused before any Thoryn write.
 */
class ProjectInitApprovalTest : ProjectTestBase() {

    private val base = arrayOf("project", "init", "config", "--reviewer", "alice", "--reviewer", "bob", "--confirm-production")

    @Suppress("UNCHECKED_CAST")
    private fun approval(out: String) = parseJson(out)["productionApproval"] as Map<String, Any?>

    @Test
    fun `GitHub Team private — the environment reviewers are refused for the plan, the ruleset carries the approval, and the run succeeds`() {
        gh.plan = "team"

        val (exit, out, err) = runCli(*base, "--repo", "acme/platform", "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(approval(out)["mechanisms"]).isEqualTo(listOf("pull_request_ruleset"))
        @Suppress("UNCHECKED_CAST")
        assertThat(approval(out)["environmentReviewers"] as Map<String, Any?>).containsEntry("active", false)
        // The reviewers PUT was refused (billing plan), then the environment was set up branch-only.
        val envPuts = gh.calls.filter { it.args.contains("repos/acme/platform/environments/thoryn-production") && it.args.contains("PUT") }
        assertThat(envPuts).hasSize(2)
        assertThat(parseJson(envPuts[1].stdin!!)).doesNotContainKey("reviewers")
        assertThat(gh.environments.getValue("acme/platform/thoryn-production").custom).isTrue()
        assertThat(gh.rulesets.getValue("acme/platform").values.single()["enforcement"]).isEqualTo("active")
        assertThat(gh.variables).containsKey("acme/platform@thoryn-production:THORYN_PRODUCTION_WIF_CLIENT_ID")
        assertThat(api.trusts).hasSize(2)

        val table = runCli(*base, "--repo", "acme/platform")
        assertThat(table.out).contains("required reviewers not offered by this GitHub plan (the ruleset carries the approval)")
            .contains("Environment reviewers are not offered by this GitHub plan")
    }

    @Test
    fun `a public repository gets both the ruleset and the environment reviewers, whatever the plan`() {
        gh.plan = "free"

        val (exit, out, err) = runCli(*base, "--repo", "acme/platform", "--public", "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(approval(out)["mechanisms"]).isEqualTo(listOf("pull_request_ruleset", "environment_reviewers"))
        assertThat(gh.environments.getValue("acme/platform/thoryn-production").reviewers).containsExactly(501L, 502L)
    }

    @Test
    fun `GitHub Free private is refused before any Thoryn write, and the repository this run created is named and kept`() {
        gh.plan = "free"

        val (exit, out, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_GH) // the run created the repository
        assertThat(err).contains(
            "Production approval needs a reviewed pull request on the default branch, which GitHub Free does not support for private " +
                "repositories. Use GitHub Pro, Team or Enterprise, or a public repository.",
        ).contains("What remains: the repository acme/platform, which this run created").contains("Nothing was created in Thoryn")
            .doesNotContain("GitHub Team or Enterprise for a private repository")
        assertThat(out).isEmpty()
        assertThat(gh.repos).containsKey("acme/platform") // kept, never deleted
        assertThat(gh.files.getValue("acme/platform")).doesNotContainKey(".github/CODEOWNERS") // no commit before the refusal
        assertThat(gh.environments).isEmpty()
        assertThat(api.writes).isEmpty()
        assertThat(gh.variables).isEmpty()

        val again = runCli(*base, "--repo", "acme/platform", "--json")
        assertThat(again.exit).isEqualTo(ProjectInit.EXIT_CHECK) // nothing changed this time
        assertThat(parseJson(again.out)).containsEntry("error", "github_plan_required").containsEntry("changed", false)
            .containsEntry("repositoryCreated", false)
    }

    @Test
    fun `a re-run adopts and updates the ruleset instead of creating a second one`() {
        assertThat(runCli(*base, "--repo", "acme/platform").exit).isEqualTo(0)
        val id = gh.rulesets.getValue("acme/platform").keys.single()
        // Someone weakened it in between.
        gh.rulesets.getValue("acme/platform")[id] = mapOf("name" to "thoryn-production-approval", "enforcement" to "evaluate", "rules" to listOf<Any>())
        val calls = gh.calls.size

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.rulesets.getValue("acme/platform").keys).containsExactly(id)
        val rerun = gh.invocations.drop(calls)
        assertThat(rerun).contains("gh api --method PUT repos/acme/platform/rulesets/$id --input -")
            .noneMatch { it.contains("--method POST repos/acme/platform/rulesets") }
            .noneMatch { it.contains("--method PUT repos/acme/platform/contents") } // CODEOWNERS unchanged
        @Suppress("UNCHECKED_CAST")
        val rules = gh.rulesets.getValue("acme/platform").getValue(id)["rules"] as List<Map<String, Any?>>
        assertThat(gh.rulesets.getValue("acme/platform").getValue(id)["enforcement"]).isEqualTo("active")
        assertThat(gh.rulesets.getValue("acme/platform").getValue(id)["bypass_actors"]).isEqualTo(listOf<Any>())
        assertThat(rules.map { it["type"] }).containsExactly("pull_request", "non_fast_forward", "deletion")
        @Suppress("UNCHECKED_CAST")
        assertThat(rules.first()["parameters"] as Map<String, Any?>).containsEntry("required_approving_review_count", 1)
            .containsEntry("require_code_owner_review", true).containsEntry("dismiss_stale_reviews_on_push", true)
    }

    @Test
    fun `an existing repository's different CODEOWNERS stops before any change, and --force replaces it past the ruleset`() {
        gh.seedRepo("acme/platform")
        gh.files["acme/platform"] = mutableMapOf(".github/CODEOWNERS" to "* @someone-else\n")

        val (exit, _, err) = runCli(*base, "--repo", "acme/platform")
        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("already has a different .github/CODEOWNERS. Nothing was changed").contains("--force")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()

        // With an active ruleset from an earlier run, --force disables it for the one commit, then enforces it again.
        gh.rulesets["acme/platform"] = linkedMapOf(4100L to mapOf("name" to "thoryn-production-approval", "enforcement" to "active"))
        val forced = runCli(*base, "--repo", "acme/platform", "--force")
        assertThat(forced.exit).describedAs(forced.err).isEqualTo(0)
        assertThat(gh.files.getValue("acme/platform")[".github/CODEOWNERS"]).contains("/.thoryn/environments/production/ @alice @bob")
        assertThat(gh.mutations.filter { it.contains("rulesets") || it.contains("contents") }).containsExactly(
            "gh api --method PUT repos/acme/platform/rulesets/4100 --input -",
            "gh api --method PUT repos/acme/platform/contents/.github/CODEOWNERS --input -",
            "gh api --method PUT repos/acme/platform/rulesets/4100 --input -",
        )
        assertThat(gh.rulesets.getValue("acme/platform").getValue(4100L)["enforcement"]).isEqualTo("active")
    }

    @Test
    fun `in an existing clone CODEOWNERS is written to the working tree, and a different one is a conflict`() {
        val dir = clone("acme/platform", existing = mapOf(".github/CODEOWNERS" to "* @someone-else\n"))

        val (exit, _, err) = runCli(*base, "--dir", dir.toString())
        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("These files already exist with different content: .github/CODEOWNERS")
        assertThat(gh.mutations).isEmpty()

        val forced = runCli(*base, "--dir", dir.toString(), "--force")
        assertThat(forced.exit).describedAs(forced.err).isEqualTo(0)
        assertThat(Files.readString(dir.resolve(".github/CODEOWNERS"))).isEqualTo(ProjectInit.codeownersFor(listOf("alice", "bob")))
        assertThat(forced.out).contains("codeowners").contains("pending").contains("lands with your pull request")
    }

    @Test
    fun `other GitHub refusals of the protection are not relabelled as a plan limit`() {
        gh.failProtectionWith = "gh: Validation Failed: branch name is invalid (HTTP 422)"
        val otherValidation = runCli(*base, "--repo", "acme/platform")
        assertThat(otherValidation.exit).isEqualTo(ProjectInit.EXIT_GH)
        assertThat(otherValidation.err).contains("the protection step failed — gh: gh: Validation Failed").doesNotContain("GitHub Free")

        gh.failProtectionWith = "gh: Must have admin rights to Repository. (HTTP 403)"
        val forbidden = runCli(*base, "--repo", "acme/platform")
        assertThat(forbidden.exit).isEqualTo(ProjectInit.EXIT_GH)
        assertThat(forbidden.err).contains("admin rights").doesNotContain("GitHub Free")
        assertThat(api.writes).isEmpty()
    }
}
