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
 * | protect the production environment | `gh api --method PUT repos/<o>/<r>/environments/<env> --input -` |
 * | its branch policies | `gh api repos/<o>/<r>/environments/<env>/deployment-branch-policies`, `… --method POST … -f name=<branch> -f type=branch`, `… --method DELETE …/<id>` |
 * | verify the protection | `gh api repos/<o>/<r>/environments/<env>` |
 * | a variable (upsert) | `gh variable set <NAME> --body <value> --repo <o>/<r> [--env <env>]` |
 */
class GitHubCli(private val gh: GhRunner) {

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
     * Bring the GitHub [environment] to the required shape: exactly [reviewerIds] as required reviewers and a
     * deployment branch policy admitting only [branch]. Idempotent: a re-run converges an existing environment.
     */
    fun protectEnvironment(repository: GhRepository, environment: String, reviewerIds: List<Long>, branch: String, step: String) {
        val path = "repos/${repository.fullName}/environments/$environment"
        val body = linkedMapOf(
            "reviewers" to reviewerIds.map { linkedMapOf("type" to "User", "id" to it) },
            "prevent_self_review" to false,
            "deployment_branch_policy" to linkedMapOf("protected_branches" to false, "custom_branch_policies" to true),
        )
        val put = gh.run(listOf("api", "--method", "PUT", path, "--input", "-"), stdin = json.writeValueAsBytes(body))
        if (!put.ok) {
            if (reviewersNeedPaidPlan(repository, put)) throw GhPlanLimitException(step, put)
            throw GhCommandException(step, put, "GitHub refused to protect the environment; you need admin rights on the repository.")
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
    }

    /**
     * Read the environment back: true when it has required reviewers (all of [reviewerIds]) and a custom
     * deployment branch policy. Checked before any production variable is set.
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
        return reviewerIds.isNotEmpty() && reviewers.containsAll(reviewerIds) && customBranches
    }

    /**
     * True when GitHub refused the environment's required reviewers because the repository is PRIVATE on a plan
     * without them (GitHub Free / Pro for a private repository): a 422 whose message names reviewers or the plan.
     * Any other refusal — another 422, a 403 for missing admin rights — is not relabelled.
     */
    internal fun reviewersNeedPaidPlan(repository: GhRepository, put: GhResult): Boolean =
        repository.private && put.httpStatus() == 422 && PLAN_LIMIT.containsMatchIn(put.stderr + "\n" + put.text)

    /** Create or update one Actions variable (never a secret) at repository level, or in [environment]. */
    fun setVariable(repository: GhRepository, name: String, value: String, environment: String?, step: String) {
        val args = mutableListOf("variable", "set", name, "--body", value, "--repo", repository.fullName)
        if (environment != null) args += listOf("--env", environment)
        val r = gh.run(args)
        if (!r.ok) throw GhCommandException(step, r)
    }

    companion object {
        /** GitHub's wording when a plan lacks environment protection rules for a private repository. */
        private val PLAN_LIMIT = Regex(
            "(?i)(required reviewers|reviewers? (are|is) not available|protection rules? (are|is) not available|" +
                "upgrade to github|github (team|enterprise|pro)\\b|your (current )?plan|not available for (this|private) repositor)",
        )
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
