package com.devnow.thoryn.cli.cmd.provision.workflow

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * SSO-4474 — the Forgejo action's own bash, run as the runner would run it (each step's `run:` with its `env:` values),
 * against a fake `thoryn` and a MockWebServer for the instance: the trigger gate (only a workflow_dispatch of the default
 * branch applies; a fork's pull request is skipped), the plan / apply loop, and the token handed over as a file behind an
 * authenticating proxy. Needs bash, jq, git and curl on PATH (any CI runner, a developer machine); SKIPPED and reported so
 * otherwise, never green by omission.
 */
class ForgejoActionScriptTest {

    @TempDir
    lateinit var dir: File

    private val action = YAMLMapper.builder().build().readTree(ForgejoFixtures.ACTION)
    private val runnerTemp get() = File(dir, "runner-temp").also { it.mkdirs() }
    private val workspace get() = File(dir, "workspace").also { it.mkdirs() }
    private val cliDir get() = File(runnerTemp, "thoryn-provisioning").also { it.mkdirs() }
    private val calls get() = File(dir, "calls.log")

    @BeforeEach
    fun tools() {
        listOf("bash", "jq", "git", "curl").forEach { tool ->
            assumeTrue(System.getenv("PATH").split(File.pathSeparator).any { File(it, tool).canExecute() }, "$tool is not on PATH — skipped")
        }
    }

    private fun script(id: String): String = action["runs"]["steps"].toList().first { it["name"].asString().startsWith(id) }["run"].asString()

    data class Run(val exit: Int, val out: String, val outputs: String)

    private fun run(script: String, env: Map<String, String>, cwd: File = workspace): Run {
        val output = File(dir, "github-output").apply { writeText("") }
        val pb = ProcessBuilder("bash", "-c", script).directory(cwd).redirectErrorStream(true)
        pb.environment().keys.retainAll(setOf("PATH", "HOME"))
        pb.environment() += mapOf("RUNNER_TEMP" to runnerTemp.path, "GITHUB_OUTPUT" to output.path, "GITHUB_STEP_SUMMARY" to File(dir, "summary.md").path) + env
        val p = pb.start()
        val out = p.inputStream.bufferedReader().readText()
        assertThat(p.waitFor(60, TimeUnit.SECONDS)).isTrue()
        return Run(p.exitValue(), out, output.readText())
    }

    // ── the trigger gate ───────────────────────────────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0} on {1} (base {2}, head repo {4}) -> {5}")
    @CsvSource(
        "pull_request,        refs/pull/3/head,   main,    main, acme/infra, plan",
        "pull_request,        refs/pull/3/head,   main,    main, '',         plan",
        "pull_request,        refs/pull/3/head,   main,    main, fork/infra, skip",
        "pull_request,        refs/pull/3/head,   develop, main, acme/infra, FAIL:targets 'develop'",
        "push,                refs/heads/main,    '',      main, '',         plan",
        "push,                refs/heads/feature, '',      main, '',         FAIL:a push plans only on the default branch",
        "schedule,            refs/heads/main,    '',      main, '',         plan",
        "workflow_dispatch,   refs/heads/main,    '',      main, '',         apply",
        "workflow_dispatch,   refs/heads/feature, '',      main, '',         FAIL:this dispatch chose 'refs/heads/feature'",
        "workflow_dispatch,   refs/tags/v1,       '',      main, '',         FAIL:an apply runs only on a workflow_dispatch of the default branch",
        "workflow_call,       refs/heads/main,    '',      main, '',         FAIL:event workflow_call",
        "pull_request_target, refs/heads/main,    main,    main, fork/infra, FAIL:pull_request_target",
        "release,             refs/tags/v1,       '',      main, '',         FAIL:does not start Thoryn provisioning",
        "workflow_dispatch,   refs/heads/main,    '',      '',   '',         FAIL:names no default branch",
    )
    fun `only a workflow_dispatch of the default branch applies, and a fork's pull request is skipped`(event: String, ref: String, base: String, default: String, head: String, expected: String) {
        val r = run(
            script("Decide what this run does"),
            mapOf("EVENT_NAME" to event, "REF" to ref, "BASE_REF" to base, "DEFAULT_BRANCH" to default, "REPOSITORY" to "acme/infra", "HEAD_REPOSITORY" to head),
        )
        if (expected.startsWith("FAIL:")) {
            assertThat(r.exit).withFailMessage("expected a red step, got:\n%s", r.out).isNotEqualTo(0)
            assertThat(r.out).contains("::error::").contains(expected.removePrefix("FAIL:"))
            assertThat(r.outputs).doesNotContain("mode=")
        } else {
            assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(0)
            assertThat(r.outputs.trim()).isEqualTo("mode=$expected")
        }
        if (expected == "skip") {
            assertThat(r.out).contains("::notice::No plan for this pull request: its code is in the fork fork/infra")
            assertThat(File(dir, "summary.md").readText()).contains("Thoryn provisioning: skipped")
        }
    }

    @Test
    fun `the CLI release is the action's own cli-v tag, never a branch, and never one that predates the action`() {
        val download = script("Download the released thoryn CLI")
        val branch = run(download, mapOf("CLI_VERSION" to "", "ACTION_REF" to "main"))
        assertThat(branch.exit).isNotEqualTo(0)
        assertThat(branch.out).contains("which is not a cli-v* release tag")
        val old = run(download, mapOf("CLI_VERSION" to "", "ACTION_REF" to "cli-v0.60.2"))
        assertThat(old.exit).isNotEqualTo(0)
        assertThat(old.out).contains("predates Forgejo provisioning: set cli-version to ${ProvisioningWorkflowContract.FORGEJO_MINIMUM_RELEASE}")
    }

    // ── plan / apply ───────────────────────────────────────────────────────────────────────────────────────────

    /** A fake CLI: records each call (and, at login, the token file it finds, its mode and content) — never prints them. */
    private fun fakeCli(tokenFile: File? = null) {
        val seen = File(dir, "seen-token")
        val record = tokenFile?.let { "if [ \"\$1\" = login ]; then cp '${it.path}' '${seen.path}'; ls -l '${it.path}' | cut -c1-10 > '${seen.path}.mode'; fi" } ?: ""
        File(cliDir, "thoryn").apply {
            writeText("#!/usr/bin/env bash\necho \"\$*\" >> '${calls.path}'\n$record\necho \"thoryn \$1 ok\"\n")
            setExecutable(true)
        }
    }

    private fun report(prune: Boolean = false, confirm: String = "", destroy: Boolean = false) = File(cliDir, "workflow.json").writeText(
        """{"config":{"files":[{"file":".thoryn/provision.yaml","connection":".thoryn/connection.json"}],"env":{"THORYN_ENVIRONMENT":"sandbox"},"apply":{"prune":$prune,"confirm":"$confirm","destroy":$destroy}}}""",
    )

    private fun connection(text: String = ForgejoFixtures.connection()) = File(workspace, ".thoryn/connection.json").also { it.parentFile.mkdirs(); it.writeText(text) }

    private fun commit(): String {
        fun git(vararg args: String) = ProcessBuilder(listOf("git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false") + args)
            .directory(workspace).redirectErrorStream(true).start().also { it.waitFor(30, TimeUnit.SECONDS) }.inputStream.bufferedReader().readText().trim()
        git("init", "-q")
        git("commit", "-q", "--allow-empty", "-m", "x")
        return git("rev-parse", "HEAD")
    }

    private fun planApply(mode: String, sha: String = "", extra: Map<String, String> = emptyMap()) =
        run(script("Plan or apply every configured file"), mapOf("MODE" to mode, "SHA" to sha, "ID_TOKEN_ORIGIN" to "", "THORYN_ISSUER" to "https://auth.thoryn.io", "THORYN_HUB" to "https://auth.thoryn.io", "THORYN_CI_PLAINTEXT_TOKENS" to "1") + extra)

    @Test
    fun `a plan signs in and plans every configured file, and never applies`() {
        fakeCli(); report(prune = true); connection()
        val r = planApply("plan")
        assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(0)
        assertThat(calls.readLines()).containsExactly("login --connection .thoryn/connection.json", "provision plan --file .thoryn/provision.yaml")
    }

    @Test
    fun `an apply converges the dispatched commit, with the configured removals`() {
        fakeCli(); report(prune = true, confirm = "acme"); connection()
        val r = planApply("apply", sha = commit())
        assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(0)
        assertThat(calls.readLines()).containsExactly("login --connection .thoryn/connection.json", "provision apply --file .thoryn/provision.yaml --yes --prune --confirm acme")
        assertThat(r.out).contains("from a workflow_dispatch of the default branch")
    }

    @Test
    fun `an apply at any other commit than the dispatched one stops before it signs in`() {
        fakeCli(); report(); connection(); commit()
        val r = planApply("apply", sha = "0123456789abcdef0123456789abcdef01234567")
        assertThat(r.exit).isNotEqualTo(0)
        assertThat(r.out).contains("an apply runs only at the dispatched commit 0123456789abcdef0123456789abcdef01234567")
        assertThat(calls).doesNotExist()
    }

    // ── behind an authenticating proxy: the token as a file ────────────────────────────────────────────────────

    @Test
    fun `behind a proxy each sign-in gets a fresh job token from id-token-origin, written 0600, never printed, removed after`() {
        val token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOmFjbWUifQ.c2lnbmF0dXJl"
        val requestToken = "runtime-request-token-4711"
        val tokenFile = File(dir, "tokens/job-token")
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(200).setBody("""{"value":"$token"}"""))
            server.start()
            fakeCli(tokenFile); report()
            connection(ForgejoFixtures.connection(auth = "\"tokenSource\": { \"kind\": \"file\", \"path\": \"${tokenFile.path}\" },"))
            val r = planApply(
                "plan",
                extra = mapOf(
                    "ID_TOKEN_ORIGIN" to server.url("/").toString().trimEnd('/'),
                    "ACTIONS_ID_TOKEN_REQUEST_URL" to "https://forge.example.invalid/api/actions/_apis/pipelines/workflows/7/idtoken?api-version=2.0",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN" to requestToken,
                ),
            )
            assertThat(r.exit).withFailMessage("%s", r.out).isEqualTo(0)
            val request = server.takeRequest(5, TimeUnit.SECONDS)!!
            // The same route under the other origin, for the connection's audience, authorised by the runner's request token.
            assertThat(request.path).isEqualTo("/api/actions/_apis/pipelines/workflows/7/idtoken?api-version=2.0&audience=https%3A%2F%2Facme.auth.thoryn.io")
            assertThat(request.getHeader("Authorization")).isEqualTo("Bearer $requestToken")
            assertThat(File(dir, "seen-token").readText().trim()).isEqualTo(token)
            assertThat(File(dir, "seen-token.mode").readText().trim()).isEqualTo("-rw-------")
            assertThat(r.out).doesNotContain(token).doesNotContain(requestToken)
            assertThat(tokenFile).doesNotExist()
            assertThat(calls.readLines()).containsExactly("login --connection .thoryn/connection.json", "provision plan --file .thoryn/provision.yaml")
        }
    }

    @Test
    fun `a proxy's redirect to its login page is red before any sign-in, naming id-token-origin`() {
        val tokenFile = File(dir, "tokens/job-token")
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "/oauth2/sign_in"))
            server.start()
            fakeCli(tokenFile); report()
            connection(ForgejoFixtures.connection(auth = "\"tokenSource\": { \"kind\": \"file\", \"path\": \"${tokenFile.path}\" },"))
            val r = planApply(
                "plan",
                extra = mapOf(
                    "ACTIONS_ID_TOKEN_REQUEST_URL" to server.url("/api/actions/_apis/pipelines/workflows/7/idtoken?api-version=2.0").toString(),
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN" to "runtime-request-token-4711",
                ),
            )
            assertThat(r.exit).isNotEqualTo(0)
            assertThat(r.out).contains("answered HTTP 302 to the ID token request").contains("set id-token-origin")
            assertThat(calls).doesNotExist()
        }
    }
}
