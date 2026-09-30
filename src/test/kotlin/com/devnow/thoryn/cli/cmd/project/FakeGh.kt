package com.devnow.thoryn.cli.cmd.project

import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.nio.file.Path
import java.util.Base64

/**
 * SSO-3435 — a fake `gh`: an in-memory GitHub reached only through the invocations `thoryn project init` makes.
 * It RECORDS every invocation (arguments, stdin, directory) so a test can assert the exact `gh` calls, and it
 * answers anything it does not model with a failure, so an unexpected call fails the test. Never calls GitHub.
 */
internal class FakeGh : GhRunner {

    data class Call(val args: List<String>, val stdin: String?, val dir: Path?) {
        override fun toString(): String = "gh " + args.joinToString(" ")
    }

    class Env(var reviewers: List<Long> = emptyList(), var custom: Boolean = false, val policies: MutableList<Pair<Long, String>> = mutableListOf())

    private val json = JsonMapper.builder().addModule(kotlinModule()).build()

    val calls = mutableListOf<Call>()
    var installed = true
    var signedIn = true
    val users = mutableMapOf("alice" to 501L, "bob" to 502L, "acme" to 900L)
    /** fullName → repository record. */
    val repos = linkedMapOf<String, MutableMap<String, Any?>>()
    /** fullName → path → content on the default branch (the contents API). */
    val files = mutableMapOf<String, MutableMap<String, String>>()
    /** The account's GitHub plan: `free` (no rulesets / env reviewers on private repositories), `team` (no env reviewers there), `enterprise`. */
    var plan = "enterprise"
    /** fullName → ruleset id → ruleset body. */
    val rulesets = mutableMapOf<String, MutableMap<Long, Map<String, Any?>>>()
    private var nextRulesetId = 4200L
    /** "fullName@branch" → the files of a non-default branch (branches thoryn creates through git/refs). */
    val branches = mutableMapOf<String, MutableMap<String, String>>()
    /** Open pull requests: fullName → (head branch → html_url). */
    val pulls = mutableMapOf<String, MutableMap<String, String>>()
    /** template fullName → its declaration (null ⇒ the template repository is empty). */
    val declarations = mutableMapOf<String, String?>()
    val tarballs = mutableMapOf<String, ByteArray>()
    /** clone directory → fullName (what `gh repo view` answers there). */
    val clones = mutableMapOf<Path, String>()
    /** "fullName/envName" → environment state. */
    val environments = linkedMapOf<String, Env>()
    /** "fullName[@env]:NAME" → value. */
    val variables = linkedMapOf<String, String>()
    var failProtectionWith: String? = null
    /** When set, `gh variable set` fails with this stderr (e.g. one carrying a token-like string). */
    var failVariablesWith: String? = null
    private var nextRepoId = 1044556600L
    private var nextPolicyId = 70L

    fun seedRepo(fullName: String, defaultBranch: String = "main", private: Boolean = true): MutableMap<String, Any?> {
        val (owner, name) = fullName.split('/')
        val repo = linkedMapOf<String, Any?>(
            "id" to nextRepoId++, "name" to name, "owner" to mapOf("login" to owner, "id" to (users[owner] ?: 900L)),
            "default_branch" to defaultBranch, "html_url" to "https://github.com/$fullName", "private" to private,
        )
        repos[fullName] = repo
        return repo
    }

    fun repoId(fullName: String): Long = repos.getValue(fullName)["id"] as Long

    val invocations: List<String> get() = calls.map { it.toString() }

    /** Calls that change GitHub (everything that is not a read). */
    val mutations: List<String>
        get() = calls.filter { c ->
            c.args.firstOrNull() == "variable" || (c.args.firstOrNull() == "api" && c.args.getOrNull(1) == "--method")
        }.map { it.toString() }

    override fun run(args: List<String>, stdin: ByteArray?, dir: Path?): GhResult {
        calls += Call(args, stdin?.toString(Charsets.UTF_8), dir)
        if (!installed) throw GhNotInstalledException("the GitHub CLI (gh) is not installed or not on PATH")
        return when {
            args == listOf("--version") -> ok("gh version 2.100.0 (fake)")
            args == listOf("auth", "status") -> if (signedIn) {
                ok("github.com\n  ✓ Logged in to github.com account alice\n  - Token: gho_************************************")
            } else {
                GhResult(1, ByteArray(0), "You are not logged into any GitHub hosts. To log in, run: gh auth login")
            }
            args == listOf("repo", "view", "--json", "nameWithOwner") ->
                clones[dir?.toAbsolutePath()?.normalize()]?.let { okJson(mapOf("nameWithOwner" to it)) }
                    ?: GhResult(1, ByteArray(0), "no git remotes found")
            args.firstOrNull() == "variable" -> variable(args)
            args.firstOrNull() == "api" -> api(args.drop(1), stdin)
            else -> unexpected(args)
        }
    }

    private fun api(a: List<String>, stdin: ByteArray?): GhResult {
        val method = if (a.firstOrNull() == "--method") a[1] else "GET"
        val rest = if (a.firstOrNull() == "--method") a.drop(2) else a
        val path = rest.first()
        val fields = rest.drop(1).chunked(2).filter { it.size == 2 && (it[0] == "-f" || it[0] == "-F") }
            .associate { it[1].substringBefore('=') to it[1].substringAfter('=') }
        val seg = path.substringBefore('?').split('/')
        return when {
            method == "GET" && seg[0] == "users" && seg.size == 2 -> users[seg[1]]?.let { okJson(mapOf("id" to it, "login" to seg[1])) } ?: notFound()
            method == "GET" && seg[0] == "repos" && seg.size == 3 -> repos["${seg[1]}/${seg[2]}"]?.let { okJson(it) } ?: notFound()
            method == "GET" && seg[0] == "repos" && seg.size >= 4 && seg[3] == "contents" && path.contains("?ref=") -> {
                val file = seg.drop(4).joinToString("/").substringBefore('?')
                val content = branches["${seg[1]}/${seg[2]}@${path.substringAfter("?ref=")}"]?.get(file) ?: return notFound()
                okJson(mapOf("type" to "file", "sha" to "sha-${content.hashCode()}", "content" to Base64.getMimeEncoder().encodeToString(content.toByteArray())))
            }
            method == "GET" && seg[0] == "repos" && seg.size >= 4 && seg[3] == "contents" -> contents("${seg[1]}/${seg[2]}", seg.drop(4).joinToString("/"))
            method == "GET" && seg[0] == "repos" && seg.size >= 6 && seg[3] == "git" && seg[4] == "ref" -> {
                val full = "${seg[1]}/${seg[2]}"
                val branch = seg.drop(6).joinToString("/")
                if (full !in repos) return notFound()
                val known = branch == repos.getValue(full)["default_branch"] || "$full@$branch" in branches
                if (known) okJson(mapOf("ref" to "refs/heads/$branch", "object" to mapOf("sha" to "commit-$branch"))) else notFound()
            }
            method == "POST" && seg[0] == "repos" && seg.size == 5 && seg[3] == "git" && seg[4] == "refs" -> {
                val full = "${seg[1]}/${seg[2]}"
                val branch = fields.getValue("ref").removePrefix("refs/heads/")
                branches["$full@$branch"] = files[full].orEmpty().toMutableMap()
                okJson(mapOf("ref" to fields["ref"]))
            }
            seg[0] == "repos" && seg.size == 4 && seg[3] == "pulls" -> {
                val full = "${seg[1]}/${seg[2]}"
                val open = pulls.getOrPut(full) { linkedMapOf() }
                if (method == "GET") {
                    val head = path.substringAfter("head=").substringBefore('&').substringAfter(':')
                    okJson(open.filterKeys { it == head }.values.map { mapOf("html_url" to it) })
                } else {
                    val url = "https://github.com/$full/pull/${open.size + 1}"
                    open[fields.getValue("head")] = url
                    okJson(mapOf("html_url" to url, "number" to open.size))
                }
            }
            method == "PUT" && seg[0] == "repos" && seg.size >= 4 && seg[3] == "contents" -> putContents("${seg[1]}/${seg[2]}", seg.drop(4).joinToString("/"), stdin)
            method == "GET" && seg[0] == "repos" && seg.size == 5 && seg[3] == "branches" -> if ("${seg[1]}/${seg[2]}" in repos) okJson(mapOf("name" to seg[4])) else notFound()
            seg[0] == "repos" && seg.size >= 4 && seg[3] == "rulesets" -> ruleset("${seg[1]}/${seg[2]}", seg.getOrNull(4)?.toLong(), method, stdin)
            method == "GET" && seg[0] == "repos" && seg.size == 4 && seg[3] == "tarball" -> tarballs["${seg[1]}/${seg[2]}"]?.let { GhResult(0, it, "") } ?: notFound()
            method == "POST" && seg[0] == "repos" && seg.size == 4 && seg[3] == "generate" -> generate("${seg[1]}/${seg[2]}", fields)
            seg[0] == "repos" && seg.size >= 5 && seg[3] == "environments" -> environment("${seg[1]}/${seg[2]}", seg[4], seg.drop(5), method, fields, stdin)
            else -> unexpected(listOf("api") + a)
        }
    }

    private fun contents(fullName: String, path: String): GhResult {
        if (fullName in declarations) {
            val raw = declarations[fullName] ?: return GhResult(1, "{\"message\":\"This repository is empty.\"}".toByteArray(), "gh: This repository is empty. (HTTP 404)")
            return if (path == StarterTemplateManifest.PATH) {
                okJson(mapOf("type" to "file", "content" to Base64.getMimeEncoder().encodeToString(raw.toByteArray())))
            } else {
                notFound()
            }
        }
        val content = files[fullName]?.get(path) ?: return notFound()
        return okJson(mapOf("type" to "file", "sha" to "sha-${content.hashCode()}", "content" to Base64.getMimeEncoder().encodeToString(content.toByteArray())))
    }

    private fun generate(template: String, fields: Map<String, String>): GhResult {
        if (template !in tarballs && declarations[template] == null) return notFound()
        val fullName = "${fields["owner"]}/${fields["name"]}"
        if (fullName in repos) return GhResult(1, ByteArray(0), "gh: Name already exists on this account (HTTP 422)")
        val repo = seedRepo(fullName, private = fields["private"] == "true")
        repo["template_repository"] = mapOf("full_name" to template)
        files[fullName] = mutableMapOf(StarterTemplateManifest.PATH to (declarations[template] ?: ""))
        return okJson(repo)
    }

    private fun isPrivate(fullName: String) = repos[fullName]?.get("private") == true

    private fun putContents(fullName: String, path: String, stdin: ByteArray?): GhResult {
        if (fullName !in repos) return notFound()
        @Suppress("UNCHECKED_CAST")
        val body = json.readValue(stdin, Map::class.java) as Map<String, Any?>
        val branch = body["branch"] as String? ?: repos.getValue(fullName)["default_branch"] as String
        if (branch != repos.getValue(fullName)["default_branch"]) {
            val files = branches["$fullName@$branch"] ?: return notFound()
            val existing = files[path]
            if (existing != null && body["sha"] != "sha-${existing.hashCode()}") return GhResult(1, ByteArray(0), "gh: sha wasn't supplied (HTTP 422)")
            files[path] = String(Base64.getDecoder().decode(body["content"] as String))
            return okJson(mapOf("content" to mapOf("path" to path)))
        }
        if (rulesets[fullName].orEmpty().values.any { it["enforcement"] == "active" }) {
            return GhResult(1, ByteArray(0), "gh: Repository rule violations found (HTTP 409)")
        }
        val existing = files[fullName]?.get(path)
        if (existing != null && body["sha"] != "sha-${existing.hashCode()}") return GhResult(1, ByteArray(0), "gh: sha wasn't supplied (HTTP 422)")
        files.getOrPut(fullName) { mutableMapOf() }[path] = String(Base64.getDecoder().decode(body["content"] as String))
        return okJson(mapOf("content" to mapOf("path" to path)))
    }

    private fun ruleset(fullName: String, id: Long?, method: String, stdin: ByteArray?): GhResult {
        if (fullName !in repos) return notFound()
        val mine = rulesets.getOrPut(fullName) { linkedMapOf() }
        @Suppress("UNCHECKED_CAST")
        fun body() = json.readValue(stdin, Map::class.java) as Map<String, Any?>
        return when {
            id == null && method == "GET" -> okJson(mine.map { (k, v) -> mapOf("id" to k, "name" to v["name"], "enforcement" to v["enforcement"]) })
            id == null && method == "POST" -> {
                if (plan == "free" && isPrivate(fullName)) {
                    return GhResult(1, "{\"message\":\"Upgrade to GitHub Pro or make this repository public to enable this feature.\"}".toByteArray(), "gh: Upgrade to GitHub Pro or make this repository public to enable this feature. (HTTP 403)")
                }
                val newId = nextRulesetId++
                mine[newId] = body()
                okJson(body() + ("id" to newId))
            }
            id != null && method == "PUT" -> mine[id]?.let { mine[id] = body(); okJson(body() + ("id" to id)) } ?: notFound()
            id != null && method == "GET" -> mine[id]?.let { okJson(it + ("id" to id)) } ?: notFound()
            else -> unexpected(listOf(method, fullName, "rulesets"))
        }
    }

    private fun environment(fullName: String, name: String, tail: List<String>, method: String, fields: Map<String, String>, stdin: ByteArray?): GhResult {
        if (fullName !in repos) return notFound()
        val key = "$fullName/$name"
        return when {
            tail.isEmpty() && method == "PUT" -> {
                failProtectionWith?.let { return GhResult(1, ByteArray(0), it) }
                @Suppress("UNCHECKED_CAST")
                val body = json.readValue(stdin, Map::class.java) as Map<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val reviewers = (body["reviewers"] as List<Map<String, Any?>>?).orEmpty().map { (it["id"] as Number).toLong() }
                if (reviewers.isNotEmpty() && isPrivate(fullName) && plan != "enterprise") {
                    return GhResult(
                        1, ByteArray(0),
                        "gh: Failed to create the environment protection rule. Please ensure the billing plan supports the required reviewers protection rule. (HTTP 422)",
                    )
                }
                val env = environments.getOrPut(key) { Env() }
                env.reviewers = reviewers
                @Suppress("UNCHECKED_CAST")
                env.custom = (body["deployment_branch_policy"] as Map<String, Any?>)["custom_branch_policies"] == true
                okJson(mapOf("name" to name))
            }
            tail.isEmpty() && method == "GET" -> {
                val env = environments[key] ?: return notFound()
                val rules = if (env.reviewers.isEmpty()) {
                    emptyList()
                } else {
                    listOf(mapOf("type" to "required_reviewers", "reviewers" to env.reviewers.map { mapOf("type" to "User", "reviewer" to mapOf("id" to it)) }))
                }
                okJson(mapOf("name" to name, "protection_rules" to rules, "deployment_branch_policy" to mapOf("protected_branches" to false, "custom_branch_policies" to env.custom)))
            }
            tail == listOf("deployment-branch-policies") && method == "GET" -> {
                val env = environments[key] ?: return notFound()
                okJson(mapOf("total_count" to env.policies.size, "branch_policies" to env.policies.map { mapOf("id" to it.first, "name" to it.second, "type" to "branch") }))
            }
            tail == listOf("deployment-branch-policies") && method == "POST" -> {
                val env = environments[key] ?: return notFound()
                env.policies += nextPolicyId++ to fields.getValue("name")
                okJson(mapOf("name" to fields["name"]))
            }
            tail.size == 2 && tail[0] == "deployment-branch-policies" && method == "DELETE" -> {
                val env = environments[key] ?: return notFound()
                env.policies.removeIf { it.first == tail[1].toLong() }
                GhResult(0, ByteArray(0), "")
            }
            else -> unexpected(listOf(method, fullName, name) + tail)
        }
    }

    private fun variable(args: List<String>): GhResult {
        // variable set NAME --body VALUE --repo O/N [--env E]
        failVariablesWith?.let { return GhResult(1, ByteArray(0), it) }
        if (args.getOrNull(1) != "set") return unexpected(args)
        val name = args[2]
        val opts = args.drop(3).chunked(2).associate { it[0] to it.getOrNull(1) }
        val repo = opts["--repo"] ?: return unexpected(args)
        if (repo !in repos) return notFound()
        val env = opts["--env"]
        variables[if (env == null) "$repo:$name" else "$repo@$env:$name"] = opts.getValue("--body")!!
        return GhResult(0, ByteArray(0), "")
    }

    private fun ok(text: String) = GhResult(0, text.toByteArray(), "")
    private fun okJson(value: Any?) = GhResult(0, json.writeValueAsBytes(value), "")
    private fun notFound() = GhResult(1, "{\"message\":\"Not Found\"}".toByteArray(), "gh: Not Found (HTTP 404)")
    private fun unexpected(args: List<String>) = GhResult(99, ByteArray(0), "FakeGh: unexpected invocation ${args.joinToString(" ")}")
}
