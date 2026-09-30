package com.devnow.thoryn.cli.cmd.project

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * SSO-3435 — how `thoryn project init` reaches GitHub: ONLY through the customer's own `gh` CLI, as a child
 * process. Behind an interface so tests substitute a fake `gh` and assert the exact invocations.
 *
 * **Thoryn never handles a GitHub credential.** It does not read, print, log or store a GitHub token; no
 * token is ever placed in an argument or in an environment variable thoryn sets ([ProcessGhRunner.EXTRA_ENV]
 * carries only `GH_PROMPT_DISABLED`). `gh` authenticates with whatever the user signed it in with.
 */
interface GhRunner {
    /**
     * Run `gh <args>` in [dir] (the current directory when null), feeding [stdin] when given.
     * Throws [GhNotInstalledException] when there is no `gh` executable.
     */
    fun run(args: List<String>, stdin: ByteArray? = null, dir: Path? = null): GhResult
}

/** One `gh` invocation's outcome. Nothing from [stderr] is shown except through [reason], which redacts. */
class GhResult(val exitCode: Int, val stdout: ByteArray, val stderr: String) {
    val ok: Boolean get() = exitCode == 0
    val text: String get() = stdout.toString(Charsets.UTF_8)

    /** `gh api` reports an HTTP failure on stderr as `… (HTTP 404)`. */
    fun httpStatus(): Int? = Regex("\\(HTTP (\\d{3})\\)").find(stderr)?.groupValues?.get(1)?.toIntOrNull()

    /** The first meaningful line of stderr, for an error message — redacted. */
    fun reason(): String =
        GhRedaction.redact(stderr.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } ?: "exit code $exitCode")
}

class GhNotInstalledException(message: String) : RuntimeException(message)

/** A `gh` step failed; [result] carries the (redacted) reason. */
class GhCommandException(val step: String, val result: GhResult, val hint: String? = null) :
    RuntimeException("gh failed during $step: ${result.reason()}")

/** Redaction applied to anything `gh` wrote before thoryn may show it (defence in depth — gh does not print tokens). */
object GhRedaction {
    private val TOKEN = Regex("\\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\\b")

    fun redact(text: String): String = TOKEN.replace(text, "[redacted]")
}

/** The real runner: `ProcessBuilder("gh", …)` — GraalVM native-image safe (no reflection, no JNI). */
class ProcessGhRunner(
    private val executable: String = "gh",
    private val timeoutSeconds: Long = 180,
) : GhRunner {

    override fun run(args: List<String>, stdin: ByteArray?, dir: Path?): GhResult {
        val builder = ProcessBuilder(listOf(executable) + args)
        dir?.let { builder.directory(it.toFile()) }
        builder.environment().putAll(EXTRA_ENV)
        val process = try {
            builder.start()
        } catch (ex: IOException) {
            throw GhNotInstalledException("the GitHub CLI (gh) is not installed or not on PATH")
        }
        // Drain stderr on its own thread so a chatty gh never blocks on a full pipe.
        val errBuffer = ByteArrayOutputStream()
        val errReader = Thread { runCatching { process.errorStream.copyTo(errBuffer) } }.apply { isDaemon = true; start() }
        // gh may exit before reading its input (an early error): a broken pipe here is not our failure.
        runCatching { process.outputStream.use { input -> if (stdin != null) input.write(stdin) } }
        val out = process.inputStream.readBytes()
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return GhResult(124, out, "gh did not finish within $timeoutSeconds seconds")
        }
        errReader.join(TimeUnit.SECONDS.toMillis(5))
        return GhResult(process.exitValue(), out, GhRedaction.redact(errBuffer.toString(Charsets.UTF_8)))
    }

    companion object {
        /** The ONLY environment thoryn adds to a `gh` process: never a credential. */
        val EXTRA_ENV: Map<String, String> = mapOf("GH_PROMPT_DISABLED" to "1")
    }
}
