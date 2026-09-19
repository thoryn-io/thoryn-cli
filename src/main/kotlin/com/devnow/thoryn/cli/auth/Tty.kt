package com.devnow.thoryn.cli.auth

import com.sun.jna.Library
import com.sun.jna.Native

/**
 * SSO-3227 — **is a human actually watching this invocation?**
 *
 * The CLI must never raise a biometric / platform-authentication prompt in a context where nobody can
 * answer it: a CI runner, a pipeline stage, a cron job. There the hardware key is unusable by
 * definition and the right move is to degrade to the software key with a one-line notice, not to hang
 * for 30 seconds on a dialog no one will see.
 *
 * ## Why not `System.console() != null`
 *
 * Since **JDK 19** ([JDK-8295803](https://bugs.openjdk.org/browse/JDK-8295803)) `System.console()`
 * returns a non-null `Console` even when stdin/stdout are pipes — it hands back a `ProxyingConsole`
 * over the redirected streams. So the idiom every older CLI uses answers "yes, interactive" inside a
 * pipeline, which is exactly backwards for a presence prompt. `Console.isTerminal()` is the correct
 * JDK API and would answer this precisely — but it arrived in **JDK 22**, and this project compiles
 * and ships on **JDK 21** (`maven.compiler.release=21`; `release.yml` builds every native image with
 * GraalVM 21). It is therefore not available to us.
 *
 * So we ask the C library the same question the JDK does: `isatty(2)`. JNA is already on the classpath
 * and already initialised in the native image (the OS keychain backend uses it), so this costs no new
 * dependency and no new native-image machinery beyond one reflection entry.
 *
 * ## Fail-safe direction
 *
 * Any failure — JNA unavailable, symbol missing, an exotic platform — answers **not interactive**.
 * That is the safe direction: the CLI degrades to the software key and keeps working, rather than
 * attempting a prompt it cannot service.
 */
internal object Tty {

    /** Test seam — force the answer without a real terminal. */
    internal var override: Boolean? = null

    /**
     * Environment variables that assert "no human here" regardless of what `isatty` says. `CI` is the
     * de-facto standard every major CI provider sets; `THORYN_NON_INTERACTIVE` is the explicit opt-out
     * for a wrapper script that owns a TTY but must not be interrupted.
     */
    internal var environment: (String) -> String? = { System.getenv(it) }

    const val NON_INTERACTIVE_ENV_VAR: String = "THORYN_NON_INTERACTIVE"

    private interface LibC : Library {
        fun isatty(fd: Int): Int
    }

    private val libc: LibC? by lazy {
        runCatching {
            val library = if (System.getProperty("os.name").orEmpty().startsWith("Windows")) "msvcrt" else "c"
            Native.load(library, LibC::class.java)
        }.getOrNull()
    }

    /**
     * True when this invocation can service an interactive prompt: no CI / opt-out marker is set, and
     * **stdin and stderr are both real terminals**. stderr rather than stdout deliberately — `thoryn
     * whoami --output json | jq` redirects stdout while a human is still very much present, and stdin
     * because a prompt with no keyboard behind it cannot be answered.
     */
    fun interactive(): Boolean {
        override?.let { return it }
        if (!environment("CI").isNullOrBlank()) return false
        if (!environment(NON_INTERACTIVE_ENV_VAR).isNullOrBlank()) return false
        val c = libc ?: return false
        return runCatching { c.isatty(STDIN) == 1 && c.isatty(STDERR) == 1 }.getOrDefault(false)
    }

    /** Test seam — drop the forced answer and the environment override. */
    internal fun resetForTest() {
        override = null
        environment = { System.getenv(it) }
    }

    private const val STDIN = 0
    private const val STDERR = 2
}
