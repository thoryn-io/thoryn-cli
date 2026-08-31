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
 */
object BrowserLauncher {

    fun open(url: String): Boolean {
        if (tryDesktop(url)) return true
        return tryPlatformOpener(url)
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
