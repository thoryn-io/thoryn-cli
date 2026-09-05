package com.devnow.thoryn.cli.cmd.examples

/**
 * SSO-2876 — minimal interactive prompting for the guided `examples apply`. Version-agnostic: with no
 * console (piped/CI) or on EOF, [ask] falls back to the default and [confirm] returns false — so a
 * non-interactive run proceeds only via `--set`/`--yes`, never blocking. Avoids `Console.isTerminal()`
 * (JDK 22) since the CLI targets JDK 21.
 */
internal object Prompt {

    /** Prompt for a value, returning the trimmed input or [default] on empty/EOF/no-console. */
    fun ask(message: String, default: String?): String {
        val console = System.console()
        val suffix = if (!default.isNullOrEmpty()) " [$default]" else ""
        val line = console?.readLine("%s%s: ", message, suffix)?.trim()
        return if (line.isNullOrEmpty()) (default ?: "") else line
    }

    /** Yes/no confirmation; defaults to NO (also when there is no console / on EOF). */
    fun confirm(message: String): Boolean {
        val line = System.console()?.readLine("%s [y/N]: ", message)?.trim()?.lowercase()
        return line == "y" || line == "yes"
    }
}
