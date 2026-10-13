package com.devnow.thoryn.cli.cmd.examples

/**
 * SSO-2876 — minimal interactive prompting for the guided `examples apply`. Version-agnostic: with no
 * console (piped/CI) or on EOF, [ask] falls back to the default and [confirm] returns false — so a
 * non-interactive run proceeds only via `--set`/`--yes`, never blocking. Avoids `Console.isTerminal()`
 * (JDK 22) since the CLI targets JDK 21.
 */
internal object Prompt {

    /** True when an interactive console is attached (prompts will actually be shown). */
    fun interactive(): Boolean = System.console() != null

    /** Prompt for a value, returning the trimmed input or [default] on empty/EOF/no-console. */
    fun ask(message: String, default: String?): String {
        val console = System.console()
        val suffix = if (!default.isNullOrEmpty()) " [$default]" else ""
        val line = console?.readLine("%s%s: ", message, suffix)?.trim()
        return if (line.isNullOrEmpty()) (default ?: "") else line
    }

    /**
     * SSO-3102 — prompt for a `secret: true` param WITHOUT echo. Returns the trimmed input, or "" on
     * empty/EOF/no-console (the caller then applies the recipe default). The default is never shown:
     * when one exists the prompt says Enter generates a value that is revealed once after apply.
     */
    fun askSecret(message: String, hasDefault: Boolean): String {
        val console = System.console() ?: return ""
        val suffix = if (hasDefault) " [Enter = generate one, shown once after apply]" else ""
        val chars = console.readPassword("%s%s: ", message, suffix) ?: return ""
        return String(chars).trim().also { chars.fill('\u0000') }
    }

    /** Yes/no confirmation; defaults to NO (also when there is no console / on EOF). */
    fun confirm(message: String): Boolean {
        val line = System.console()?.readLine("%s [y/N]: ", message)?.trim()?.lowercase()
        return line == "y" || line == "yes"
    }

    /**
     * SSO-2880 — block until the user presses Enter. Returns immediately when there is no interactive
     * console (piped / CI / EOF) so a non-interactive run tears down cleanly rather than hanging.
     */
    fun awaitEnter() {
        val console = System.console() ?: return
        runCatching { console.readLine() }
    }
}

/**
 * SSO-3102 — the process environment a recipe param is overridable from (the env var of the param's own
 * name; what CI exports, and the only secret-safe channel besides an interactive prompt). One seam for the
 * guided `examples apply` and the interpreter so tests can drive it.
 */
internal object RecipeParamEnv {
    var lookup: (String) -> String? = { System.getenv(it) }
}
