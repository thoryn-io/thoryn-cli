package com.devnow.thoryn.cli.cmd.project

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Path
import java.util.Base64

/** A GitHub repository as the project flow needs it: its immutable ids and default branch. */
data class GhRepository(
    val id: Long,
    val ownerId: Long,
    val ownerLogin: String,
    val name: String,
    val defaultBranch: String,
    val htmlUrl: String?,
    val private: Boolean,
) {
    val fullName: String get() = "$ownerLogin/$name"
}

/**
 * SSO-3435 — the typed `gh` calls `thoryn project init` makes. Every GitHub operation is one of these, so
 * the exact invocations are few, reviewable and asserted by the tests:
 *
 * | purpose | invocation |
 * |---|---|
 * | installed? | `gh --version` |
 * | signed in? | `gh auth status` (output discarded — never shown, never parsed) |
 * | the clone's repository | `gh repo view --json nameWithOwner` (in the clone) |
 * | a repository's ids | `gh api repos/<owner>/<repo>` |
 * | a user's / owner's id | `gh api users/<login>` |
 * | the template declaration | `gh api repos/<template>/contents/.thoryn/template.json` |
 * | the template's files | `gh api repos/<template>/tarball` |
 * | create the repository | `gh api --method POST repos/<template>/generate -f owner=… -f name=… -F private=… -f description=…` |
 * | (config) CODEOWNERS | `gh api repos/<o>/<r>/contents/.github/CODEOWNERS`, `gh api --method PUT … --input -` (with `--repo`); `gh api repos/<o>/<r>/branches/<default>` while a new repository is generated |
 * | (config) approval ruleset | `gh api repos/<o>/<r>/rulesets`, `gh api --method POST repos/<o>/<r>/rulesets --input -`, `gh api --method PUT repos/<o>/<r>/rulesets/<id> --input -`, `gh api repos/<o>/<r>/rulesets/<id>` |
 * | protect the production environment | `gh api --method PUT repos/<o>/<r>/environments/<env> --input -` (again without reviewers on a billing-plan 422) |
 * | its branch policies | `gh api repos/<o>/<r>/environments/<env>/deployment-branch-policies`, `… --method POST … -f name=<branch> -f type=branch`, `… --method DELETE …/<id>` |
 * | verify the protection | `gh api repos/<o>/<r>/environments/<env>` |
 * | a variable (upsert) | `gh variable set <NAME> --body <value> --repo <o>/<r> [--env <env>]` |
 */
class GitHubCli(
    private val gh: GhRunner,
    /** Waits between polls for a generating repository's branch; tests pass a no-op. */
    private val sleeper: (Long) -> Unit = { Thread.sleep(it) },
) {

    private val json = JsonMapper.builder().build()

    sealed interface Availability {
        data object Ready : Availability
        data object NotInstalled : Availability
        data object NotSignedIn : Availability
    }

    fun availability(): Availability = try {
        if (!gh.run(listOf("--version")).ok) {
            Availability.NotInstalled
        } else if (!gh.run(listOf("auth", "status")).ok) {
            Availability.NotSignedIn
        } else {
            Availability.Ready
        }
    } catch (ex: GhNotInstalledException) {
        Availability.NotInstalled
    }

    /** The repository, or null when GitHub answers 404 (absent, or invisible to the signed-in gh user). */
    fun repository(owner: String, name: String, step: String): GhRepository? {
        val r = gh.run(listOf("api", "repos/$owner/$name"))
        if (r.ok) return parseRepository(r.text, step, r)
        if (r.httpStatus() == 404) return null
        throw GhCommandException(step, r)
    }

    /** `owner/name` of the clone in [dir], per `gh`'s own resolution of its remotes. */
    fun repositoryOfClone(dir: Path, step: String): String {
        val r = gh.run(listOf("repo", "view", "--json", "nameWithOwner"), dir = dir)
        if (!r.ok) throw GhCommandException(step, r, "Run this inside a clone of a GitHub repository, or pass --repo <owner>/<name>.")
        return node(r, step).path("nameWithOwner").asString("").takeIf { it.contains('/') }
            ?: throw GhCommandException(step, r, "gh could not name the repository of this clone.")
    }

    /** A user's (or organization's) numeric id, or null when it does not exist. */
    fun accountId(login: String, step: String): Long? {
        val r = gh.run(listOf("api", "users/$login"))
        if (r.ok) return node(r, step).path("id").asLong(0).takeIf { it > 0 }
        if (r.httpStatus() == 404) return null
        throw GhCommandException(step, r)
    }

    /** True when [path] exists in the repository's default branch. */
    fun fileExists(repository: String, path: String, step: String): Boolean {
        val r = gh.run(listOf("api", "repos/$repository/contents/$path"))
        if (r.ok) return true
        if (r.httpStatus() == 404) return false
        throw GhCommandException(step, r)
    }

    /**
     * The template's `.thoryn/template.json` from its default branch, or null when the template repository or
     * the file does not exist (an empty, not yet published template repository answers 404 too).
     */
    fun templateDeclaration(template: String, step: String): String? {
        val r = gh.run(listOf("api", "repos/$template/contents/${StarterTemplateManifest.PATH}"))
        if (!r.ok) {
            if (r.httpStatus() == 404) return null
            throw GhCommandException(step, r)
        }
        val n = node(r, step)
        if (n.path("type").asString("") != "file") return null
        val encoded = n.path("content").asString("").filterNot { it.isWhitespace() }
        return runCatching { String(Base64.getDecoder().decode(encoded), Charsets.UTF_8) }.getOrNull()
    }

    /** The template's default-branch tarball (gzip'd tar). */
    fun templateTarball(template: String, step: String): ByteArray {
        val r = gh.run(listOf("api", "repos/$template/tarball"))
        if (!r.ok) throw GhCommandException(step, r)
        return r.stdout
    }

    /** Create [owner]/[name] from the template repository (GitHub's "use this template"). */
    fun generate(template: String, owner: String, name: String, private: Boolean, description: String, step: String): GhRepository {
        val r = gh.run(
            listOf(
                "api", "--method", "POST", "repos/$template/generate",
                "-f", "owner=$owner", "-f", "name=$name", "-F", "private=$private", "-f", "description=$description",
            ),
        )
        if (!r.ok) throw GhCommandException(step, r)
        return parseRepository(r.text, step, r)
    }

    /**
     * Bring the GitHub [environment] to the required shape: a deployment branch policy admitting only [branch], and
     * [reviewerIds] as required reviewers WHEN the plan offers them. GitHub offers environment reviewers on a private
     * repository only on GitHub Enterprise; on another plan it answers the reviewers PUT with a `422` naming the
     * billing plan, and the environment is then set up without them (the approval is carried by the default-branch
     * ruleset instead). Returns whether the reviewers are active. Idempotent: a re-run converges an existing environment.
     */
    fun protectEnvironment(repository: GhRepository, environment: String, reviewerIds: List<Long>, branch: String, step: String): Boolean {
        val path = "repos/${repository.fullName}/environments/$environment"
        val branchOnly = linkedMapOf("protected_branches" to false, "custom_branch_policies" to true)
        val withReviewers = linkedMapOf(
            "reviewers" to reviewerIds.map { linkedMapOf("type" to "User", "id" to it) },
            "prevent_self_review" to false,
            "deployment_branch_policy" to branchOnly,
        )
        var reviewersActive = true
        val put = gh.run(listOf("api", "--method", "PUT", path, "--input", "-"), stdin = json.writeValueAsBytes(withReviewers))
        if (!put.ok) {
            if (!environmentReviewersNeedPlan(put)) {
                throw GhCommandException(step, put, "GitHub refused to protect the environment; you need admin rights on the repository.")
            }
            reviewersActive = false
            val retry = gh.run(
                listOf("api", "--method", "PUT", path, "--input", "-"),
                stdin = json.writeValueAsBytes(linkedMapOf("deployment_branch_policy" to branchOnly)),
            )
            if (!retry.ok) throw GhCommandException(step, retry, "GitHub refused to create the environment; you need admin rights on the repository.")
        }
        val list = gh.run(listOf("api", "$path/deployment-branch-policies"))
        if (!list.ok) throw GhCommandException(step, list)
        val policies = node(list, step).path("branch_policies")
        var present = false
        (0 until policies.size()).map { policies.get(it) }.forEach { p ->
            val policyName = p.path("name").asString("")
            val type = p.path("type").asString("branch")
            if (policyName == branch && type == "branch") {
                present = true
            } else {
                val id = p.path("id").asLong(0)
                val del = gh.run(listOf("api", "--method", "DELETE", "$path/deployment-branch-policies/$id"))
                if (!del.ok) throw GhCommandException(step, del)
            }
        }
        if (!present) {
            val add = gh.run(listOf("api", "--method", "POST", "$path/deployment-branch-policies", "-f", "name=$branch", "-f", "type=branch"))
            if (!add.ok) throw GhCommandException(step, add)
        }
        return reviewersActive
    }

    /**
     * Read the environment back: true when it has a custom deployment branch policy and — when [reviewerIds] is not
     * empty — all of them as required reviewers. Checked before any production variable is set.
     */
    fun environmentProtected(repository: GhRepository, environment: String, reviewerIds: List<Long>, step: String): Boolean {
        val r = gh.run(listOf("api", "repos/${repository.fullName}/environments/$environment"))
        if (!r.ok) {
            if (r.httpStatus() == 404) return false
            throw GhCommandException(step, r)
        }
        val n = node(r, step)
        val rules = n.path("protection_rules")
        val reviewers = (0 until rules.size()).map { rules.get(it) }
            .filter { it.path("type").asString("") == "required_reviewers" }
            .flatMap { rule -> rule.path("reviewers").let { rs -> (0 until rs.size()).map { rs.get(it).path("reviewer").path("id").asLong(0) } } }
            .toSet()
        val customBranches = n.path("deployment_branch_policy").path("custom_branch_policies").asBoolean(false)
        return reviewers.containsAll(reviewerIds) && customBranches
    }

    /**
     * GitHub's refusal of environment reviewers for the account's billing plan: a `422` whose message names the
     * billing plan ("Failed to create the environment protection rule. Please ensure the billing plan supports the
     * required reviewers protection rule." / the older "… please ensure billing plan include protected branch gate.").
     * Any other `422` (an invalid name, a conflicting policy) is not this.
     */
    internal fun environmentReviewersNeedPlan(put: GhResult): Boolean =
        put.httpStatus() == 422 && (put.stderr + "\n" + put.text).contains("billing plan", ignoreCase = true)

    /**
     * GitHub's refusal of a repository ruleset on a PRIVATE repository under GitHub Free: a `403` "Upgrade to GitHub
     * Pro or make this repository public to enable this feature." Nothing else (a `403` for missing admin rights, a
     * `422` for an invalid rule) is treated as a plan limit.
     */
    internal fun rulesetsNeedPlan(repository: GhRepository, r: GhResult): Boolean =
        repository.private && r.httpStatus() == 403 &&
            (r.stderr + "\n" + r.text).contains("Upgrade to GitHub Pro or make this repository public", ignoreCase = true)

    // ── The default-branch approval ruleset + CODEOWNERS ────────────────────────────────────────

    /** A file on the default branch: its text and blob sha. */
    data class RepoFile(val content: String, val sha: String)

    /** [path] on the default branch, or null when it does not exist. */
    fun readFile(repository: GhRepository, path: String, step: String): RepoFile? {
        val r = gh.run(listOf("api", "repos/${repository.fullName}/contents/$path"))
        if (!r.ok) {
            if (r.httpStatus() == 404) return null
            throw GhCommandException(step, r)
        }
        val n = node(r, step)
        if (n.path("type").asString("") != "file") return null
        val content = runCatching {
            String(Base64.getDecoder().decode(n.path("content").asString("").filterNot { it.isWhitespace() }), Charsets.UTF_8)
        }.getOrDefault("")
        return RepoFile(content, n.path("sha").asString(""))
    }

    /** Create or replace [path] on the default branch with one commit (`sha` = the blob it replaces). */
    fun writeFile(repository: GhRepository, path: String, content: String, sha: String?, message: String, step: String) {
        val body = linkedMapOf<String, Any?>(
            "message" to message,
            "content" to Base64.getEncoder().encodeToString(content.toByteArray()),
            "branch" to repository.defaultBranch,
        )
        if (sha != null) body["sha"] = sha
        val r = gh.run(listOf("api", "--method", "PUT", "repos/${repository.fullName}/contents/$path", "--input", "-"), stdin = json.writeValueAsBytes(body))
        if (!r.ok) throw GhCommandException(step, r)
    }

    /**
     * A repository GitHub is still generating from its template has no default branch yet: wait (bounded) until it
     * has, before committing to it.
     */
    fun awaitDefaultBranch(repository: GhRepository, step: String) {
        var last: GhResult? = null
        repeat(BRANCH_ATTEMPTS) { attempt ->
            val r = gh.run(listOf("api", "repos/${repository.fullName}/branches/${repository.defaultBranch}"))
            if (r.ok) return
            if (r.httpStatus() != 404) throw GhCommandException(step, r)
            last = r
            if (attempt < BRANCH_ATTEMPTS - 1) sleeper(BRANCH_WAIT_MILLIS)
        }
        throw GhCommandException(step, last!!, "GitHub had not finished creating the repository's ${repository.defaultBranch} branch; re-run in a minute.")
    }

    /** The id of the repository's ruleset named [name], or null. */
    fun rulesetId(repository: GhRepository, name: String, step: String): Long? {
        val r = gh.run(listOf("api", "repos/${repository.fullName}/rulesets"))
        if (!r.ok) {
            if (rulesetsNeedPlan(repository, r)) throw GhPlanLimitException(step, r)
            throw GhCommandException(step, r)
        }
        val list = node(r, step)
        return (0 until list.size()).map { list.get(it) }.firstOrNull { it.path("name").asString("") == name }?.path("id")?.asLong(0)?.takeIf { it > 0 }
    }

    /** Create the approval ruleset ([enforcement] `active` or `disabled`); returns its id. */
    fun createRuleset(repository: GhRepository, enforcement: String, step: String): Long {
        val r = gh.run(listOf("api", "--method", "POST", "repos/${repository.fullName}/rulesets", "--input", "-"), stdin = json.writeValueAsBytes(approvalRuleset(enforcement)))
        if (!r.ok) {
            if (rulesetsNeedPlan(repository, r)) throw GhPlanLimitException(step, r)
            throw GhCommandException(step, r, "GitHub refused the ruleset; you need admin rights on the repository.")
        }
        return node(r, step).path("id").asLong(0).takeIf { it > 0 }
            ?: throw GhCommandException(step, GhResult(1, ByteArray(0), "GitHub returned a ruleset without an id"))
    }

    /** Replace ruleset [id] with the required shape at [enforcement] (adopt and update). */
    fun updateRuleset(repository: GhRepository, id: Long, enforcement: String, step: String) {
        val r = gh.run(listOf("api", "--method", "PUT", "repos/${repository.fullName}/rulesets/$id", "--input", "-"), stdin = json.writeValueAsBytes(approvalRuleset(enforcement)))
        if (!r.ok) {
            if (rulesetsNeedPlan(repository, r)) throw GhPlanLimitException(step, r)
            throw GhCommandException(step, r, "GitHub refused the ruleset; you need admin rights on the repository.")
        }
    }

    /** True when ruleset [id] is active on the default branch with its pull-request rule. Checked before the production variable. */
    fun rulesetActive(repository: GhRepository, id: Long, step: String): Boolean {
        val r = gh.run(listOf("api", "repos/${repository.fullName}/rulesets/$id"))
        if (!r.ok) {
            if (r.httpStatus() == 404) return false
            throw GhCommandException(step, r)
        }
        val n = node(r, step)
        val rules = n.path("rules")
        val pr = (0 until rules.size()).map { rules.get(it) }.firstOrNull { it.path("type").asString("") == "pull_request" }
        return n.path("enforcement").asString("") == "active" &&
            pr != null && pr.path("parameters").path("required_approving_review_count").asInt(0) >= 1 &&
            pr.path("parameters").path("require_code_owner_review").asBoolean(false)
    }

    /**
     * The production-approval ruleset (product-owner settlement 2026-09-30, revised): on the default branch, a pull
     * request with at least one approving review, code-owner review required, stale approvals dismissed on push,
     * force-pushes and deletion blocked, and NO bypass actors.
     */
    fun approvalRuleset(enforcement: String): Map<String, Any?> = linkedMapOf(
        "name" to RULESET_NAME,
        "target" to "branch",
        "enforcement" to enforcement,
        "bypass_actors" to listOf<Any>(),
        "conditions" to linkedMapOf("ref_name" to linkedMapOf("include" to listOf("~DEFAULT_BRANCH"), "exclude" to listOf<String>())),
        "rules" to listOf(
            linkedMapOf(
                "type" to "pull_request",
                "parameters" to linkedMapOf(
                    "required_approving_review_count" to 1,
                    "require_code_owner_review" to true,
                    "dismiss_stale_reviews_on_push" to true,
                    "require_last_push_approval" to false,
                    "required_review_thread_resolution" to false,
                ),
            ),
            linkedMapOf("type" to "non_fast_forward"),
            linkedMapOf("type" to "deletion"),
        ),
    )

    /** Create or update one Actions variable (never a secret) at repository level, or in [environment]. */
    fun setVariable(repository: GhRepository, name: String, value: String, environment: String?, step: String) {
        val args = mutableListOf("variable", "set", name, "--body", value, "--repo", repository.fullName)
        if (environment != null) args += listOf("--env", environment)
        val r = gh.run(args)
        if (!r.ok) throw GhCommandException(step, r)
    }

    companion object {
        /** The deterministic name of the production-approval ruleset (adopted and updated on a re-run). */
        const val RULESET_NAME: String = "thoryn-production-approval"
        const val ENFORCEMENT_ACTIVE: String = "active"
        const val ENFORCEMENT_DISABLED: String = "disabled"
        private const val BRANCH_ATTEMPTS = 10
        private const val BRANCH_WAIT_MILLIS = 1500L
    }

    private fun node(r: GhResult, step: String): JsonNode = try {
        json.readTree(r.text)
    } catch (ex: Exception) {
        throw GhCommandException(step, GhResult(1, ByteArray(0), "gh returned output thoryn could not read"))
    }

    private fun parseRepository(text: String, step: String, r: GhResult): GhRepository {
        val n = try {
            json.readTree(text)
        } catch (ex: Exception) {
            throw GhCommandException(step, GhResult(1, ByteArray(0), "gh returned output thoryn could not read"))
        }
        val id = n.path("id").asLong(0)
        val owner = n.path("owner")
        val ownerId = owner.path("id").asLong(0)
        if (id <= 0 || ownerId <= 0) throw GhCommandException(step, GhResult(1, ByteArray(0), "GitHub returned a repository without ids"))
        return GhRepository(
            id = id,
            ownerId = ownerId,
            ownerLogin = owner.path("login").asString(""),
            name = n.path("name").asString(""),
            defaultBranch = n.path("default_branch").asString("").ifBlank { "main" },
            htmlUrl = n.path("html_url").asString(null),
            private = n.path("private").asBoolean(true),
        )
    }
}
