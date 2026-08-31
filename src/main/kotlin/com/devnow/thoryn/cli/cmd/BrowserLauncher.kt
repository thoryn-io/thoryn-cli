package com.devnow.thoryn.cli.cmd

import java.awt.Desktop
import java.net.URI
import java.util.Locale

/**
 * SSO-2820 — best-effort "open this URL in the user's default browser" for the interactive
 * `thoryn login` loopback flow.
 *
 * Opening the browser is a convenience, never a requirement: the CLI always prints the authorize URL
 * first, so a failure here is non-fatal (headless box, no `DISPLAY`, locked-down desktop). [open]
 * returns `true` when a launcher was invoked without throwing, `false` otherwise — the caller has
 * already told the user they can paste the URL manually.
 *
 * Strategy: prefer `java.awt.Desktop.browse` when supported, else fall back to the platform opener
 * (`open` on macOS, `xdg-open` on Linux/BSD, `rundll32 url.dll,FileProtocolHandler` on Windows). The
 * URL is one the CLI itself built (the hub authorize endpoint), not attacker-controlled input.
 *
 * Set `THORYN_NO_BROWSER` (truthy) to skip the auto-open entirely and rely on the printed URL — for
 * SSH sessions, CI, scripting, and the CLI e2e (where Playwright, not a real browser, drives the
 * authorize URL).
 */
object BrowserLauncher {

    fun open(url: String): Boolean {
        if (noBrowserRequested()) return false
        if (tryDesktop(url)) return true
        return tryPlatformOpener(url)
    }

    /** True when `THORYN_NO_BROWSER` (env or `-D`) is set to a truthy value (`1`/`true`/`yes`, case-insensitive). */
    private fun noBrowserRequested(): Boolean {
        val raw = System.getProperty("THORYN_NO_BROWSER")?.takeIf { it.isNotBlank() }
            ?: System.getenv("THORYN_NO_BROWSER")?.takeIf { it.isNotBlank() }
            ?: return false
        return raw.lowercase(Locale.ROOT) in setOf("1", "true", "yes", "on")
    }

    private fun tryDesktop(url: String): Boolean = try {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(URI.create(url))
            true
        } else {
            false
        }
    } catch (_: Exception) {
        false
    }

    private fun tryPlatformOpener(url: String): Boolean {
        val os = System.getProperty("os.name").lowercase(Locale.ROOT)
        val command: List<String> = when {
            os.contains("mac") -> listOf("open", url)
            os.contains("win") -> listOf("rundll32", "url.dll,FileProtocolHandler", url)
            else -> listOf("xdg-open", url) // Linux / BSD / other X11-ish
        }
        return try {
            ProcessBuilder(command).inheritIO().start()
            true
        } catch (_: Exception) {
            false
        }
    }
}
