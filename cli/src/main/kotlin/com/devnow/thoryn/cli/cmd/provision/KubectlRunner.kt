package com.devnow.thoryn.cli.cmd.provision

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * SSO-3659 (ADR 2026-10-13 §5) — how a `secretSink: { kind: kubernetesSecret }` reaches a cluster: ONLY through
 * the operator's own `kubectl`, as a child process, with whatever context and credentials it is already
 * configured with. Behind an interface (the shape of `GhRunner`) so tests substitute a fake and assert the exact
 * invocations — in particular that a secret value is only ever on **stdin**, never on argv.
 *
 * **Thoryn never handles a cluster credential.** It reads no kubeconfig, sets no token, and adds nothing to the
 * process environment.
 */
interface KubectlRunner {
    /**
     * Run `kubectl <args>`, feeding [stdin] when given. Throws [KubectlNotInstalledException] when there is no
     * `kubectl` executable.
     */
    fun run(args: List<String>, stdin: ByteArray? = null): KubectlResult
}

/** One `kubectl` invocation's outcome. [stdout] may carry a rendered Secret manifest — it is never shown. */
class KubectlResult(val exitCode: Int, val stdout: ByteArray, val stderr: String) {
    val ok: Boolean get() = exitCode == 0

    /** The first meaningful line of stderr, for an error message (the caller redacts the secret value from it). */
    fun reason(): String = stderr.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } ?: "exit code $exitCode"
}

class KubectlNotInstalledException(message: String) : RuntimeException(message)

/** The real runner: `ProcessBuilder("kubectl", …)` — GraalVM native-image safe (no reflection, no JNI). */
class ProcessKubectlRunner(
    private val executable: String = "kubectl",
    private val timeoutSeconds: Long = 120,
) : KubectlRunner {

    override fun run(args: List<String>, stdin: ByteArray?): KubectlResult {
        val process = try {
            ProcessBuilder(listOf(executable) + args).start()
        } catch (ex: IOException) {
            throw KubectlNotInstalledException("kubectl is not installed or not on PATH")
        }
        // Drain stderr on its own thread so a chatty kubectl never blocks on a full pipe.
        val errBuffer = ByteArrayOutputStream()
        val errReader = Thread { runCatching { process.errorStream.copyTo(errBuffer) } }.apply { isDaemon = true; start() }
        // kubectl may exit before reading its input (an early error): a broken pipe here is not our failure.
        runCatching { process.outputStream.use { input -> if (stdin != null) input.write(stdin) } }
        val out = process.inputStream.readBytes()
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return KubectlResult(124, out, "kubectl did not finish within $timeoutSeconds seconds")
        }
        errReader.join(TimeUnit.SECONDS.toMillis(5))
        return KubectlResult(process.exitValue(), out, errBuffer.toString(Charsets.UTF_8))
    }
}
