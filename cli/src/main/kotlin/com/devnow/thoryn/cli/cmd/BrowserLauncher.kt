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
 * SSO-2954 — native-image safety. On the GraalVM native binary AWT is not present, so the very first
 * touch of [Desktop] (`Desktop.isDesktopSupported()`) throws `java.lang.UnsatisfiedLinkError`
 * ("No awt in java.library.path"). That is an [Error], not an [Exception], so the old
 * `catch (_: Exception)` let it escape — crashing the whole `thoryn login` process (and with it the
 * loopback callback server, so the browser redirect then 404s). Two defences, both applied here:
 *   1. The desktop attempt is skipped entirely in the native image (see [inNativeImage]), so AWT is
 *      never touched on the binary and the working [tryPlatformOpener] path is used directly.
 *   2. [tryDesktop] catches [Throwable] (not just [Exception]), so any AWT class-init/link failure on
 *      a non-native JVM is still swallowed and control falls through to the platform opener.
 * [open] therefore can never throw — it is best-effort by contract.
 *
 * Set `THORYN_NO_BROWSER` (truthy) to skip the auto-open entirely and rely on the printed URL — for
 * SSH sessions, CI, scripting, and the CLI e2e (where Playwright, not a real browser, drives the
 * authorize URL). It is also the interim workaround if auto-open ever misbehaves on a given host.
 */
object BrowserLauncher {

    /**
     * Best-effort open [url] in the default browser. Never throws — returns `true` if a launcher was
     * invoked, `false` otherwise (the caller has already printed the URL for manual paste).
     */
    fun open(url: String): Boolean = open(
        url = url,
        noBrowser = ::noBrowserRequested,
        inNativeImage = ::inNativeImage,
        desktopOpen = ::tryDesktop,
        platformOpen = ::tryPlatformOpener,
    )

    /**
     * Internal seam so the desktop attempt and the platform opener can be driven independently in
     * tests without launching a real browser or process. Production wires the real implementations
     * via the public [open] above; the public `open(url): Boolean` signature is unchanged.
     */
    internal fun open(
        url: String,
        noBrowser: () -> Boolean,
        inNativeImage: () -> Boolean,
        desktopOpen: (String) -> Boolean,
        platformOpen: (String) -> Boolean,
    ): Boolean {
        if (noBrowser()) return false
        // Only consult AWT Desktop on a real JVM. In the native image AWT is absent and touching it
        // throws UnsatisfiedLinkError (SSO-2954), so go straight to the platform opener there. The
        // desktop attempt is wrapped here too — not just inside tryDesktop — so open() can never throw
        // regardless of the desktop impl: a Throwable simply falls through to the platform opener.
        if (!inNativeImage()) {
            val opened = try {
                desktopOpen(url)
            } catch (_: Throwable) {
                false
            }
            if (opened) return true
        }
        return platformOpen(url)
    }

    /** True when `THORYN_NO_BROWSER` (env or `-D`) is set to a truthy value (`1`/`true`/`yes`, case-insensitive). */
    private fun noBrowserRequested(): Boolean {
        val raw = System.getProperty("THORYN_NO_BROWSER")?.takeIf { it.isNotBlank() }
            ?: System.getenv("THORYN_NO_BROWSER")?.takeIf { it.isNotBlank() }
            ?: return false
        return raw.lowercase(Locale.ROOT) in setOf("1", "true", "yes", "on")
    }

    /**
     * True when running as a GraalVM native image. Reads the `org.graalvm.nativeimage.imagecode`
     * system property — the same signal `org.graalvm.nativeimage.ImageInfo.inImageCode()` reads
     * internally (set to `buildtime`/`runtime` in an image, unset on a stock JVM). Using the property
     * rather than the `ImageInfo` class keeps this dependency-free (the GraalVM SDK is not on the
     * runtime classpath) and, crucially, avoids loading any AWT/native class on the binary. Guarded so
     * any lookup failure is treated as "not native" and the JVM path still runs.
     */
    private fun inNativeImage(): Boolean = try {
        System.getProperty("org.graalvm.nativeimage.imagecode") != null
    } catch (_: Throwable) {
        false
    }

    private fun tryDesktop(url: String): Boolean = try {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(URI.create(url))
            true
        } else {
            false
        }
    } catch (_: Throwable) {
        // Throwable, not Exception: AWT's absence surfaces as UnsatisfiedLinkError (an Error) — see the
        // class KDoc (SSO-2954). Swallow it so control falls through to the platform opener.
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
        } catch (_: Throwable) {
            false
        }
    }
}
