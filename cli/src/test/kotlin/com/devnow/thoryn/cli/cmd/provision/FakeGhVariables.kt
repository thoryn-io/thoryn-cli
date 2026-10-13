package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.project.GhResult
import com.devnow.thoryn.cli.cmd.project.GhRunner
import java.nio.file.Path

/**
 * SSO-3668 — a fake `gh` for the `publishTo:` publisher: exactly the invocations
 * [GitHubActionsVariablePublisher] makes (version / auth status, the repository, the environment GET + bare
 * PUT, `variable set`), recorded so a test asserts them, and nothing else — an unexpected call fails loud.
 * Never calls GitHub.
 */
internal class FakeGhVariables : GhRunner {

    val calls = mutableListOf<List<String>>()
    var signedIn = true
    val repos = mutableSetOf("acme/billing-web")
    /** `owner/name/env` — the environments that exist. */
    val environments = mutableSetOf<String>()
    /** `owner/name@env:NAME` → value. */
    val variables = linkedMapOf<String, String>()
    /** When set, `gh variable set` fails with this stderr. */
    var failVariablesWith: String? = null

    val invocations: List<String> get() = calls.map { "gh " + it.joinToString(" ") }

    override fun run(args: List<String>, stdin: ByteArray?, dir: Path?): GhResult {
        calls += args
        return when {
            args == listOf("--version") -> ok("gh version 2.100.0 (fake)")
            args == listOf("auth", "status") -> if (signedIn) ok("Logged in to github.com") else GhResult(1, ByteArray(0), "You are not logged into any GitHub hosts. To log in, run: gh auth login")
            args.firstOrNull() == "api" -> api(args.drop(1))
            args.firstOrNull() == "variable" && args.getOrNull(1) == "set" -> {
                failVariablesWith?.let { return GhResult(1, ByteArray(0), it) }
                val repo = args[args.indexOf("--repo") + 1]
                if (repo !in repos) return notFound()
                val env = args.indexOf("--env").takeIf { it >= 0 }?.let { args[it + 1] }
                if (env != null && "$repo/$env" !in environments) return notFound()
                variables[if (env == null) "$repo:${args[2]}" else "$repo@$env:${args[2]}"] = args[args.indexOf("--body") + 1]
                GhResult(0, ByteArray(0), "")
            }
            else -> unexpected(args)
        }
    }

    private fun api(a: List<String>): GhResult {
        val method = if (a.firstOrNull() == "--method") a[1] else "GET"
        val path = if (a.firstOrNull() == "--method") a[2] else a[0]
        val seg = path.split('/')
        if (seg.size < 3 || seg[0] != "repos") return unexpected(listOf("api") + a)
        val repo = "${seg[1]}/${seg[2]}"
        if (repo !in repos) return notFound()
        return when {
            seg.size == 3 && method == "GET" ->
                ok("""{"id":1044556600,"name":"${seg[2]}","owner":{"login":"${seg[1]}","id":900},"default_branch":"main","html_url":"https://github.com/$repo","private":true}""")
            seg.size == 5 && seg[3] == "environments" && method == "GET" ->
                if ("$repo/${seg[4]}" in environments) ok("""{"name":"${seg[4]}","protection_rules":[],"deployment_branch_policy":null}""") else notFound()
            seg.size == 5 && seg[3] == "environments" && method == "PUT" && a.size == 3 -> {
                environments += "$repo/${seg[4]}"
                ok("""{"name":"${seg[4]}"}""")
            }
            else -> unexpected(listOf("api") + a)
        }
    }

    private fun ok(text: String) = GhResult(0, text.toByteArray(), "")
    private fun notFound() = GhResult(1, "{\"message\":\"Not Found\"}".toByteArray(), "gh: Not Found (HTTP 404)")
    private fun unexpected(args: List<String>) = GhResult(99, ByteArray(0), "FakeGhVariables: unexpected invocation ${args.joinToString(" ")}")
}
