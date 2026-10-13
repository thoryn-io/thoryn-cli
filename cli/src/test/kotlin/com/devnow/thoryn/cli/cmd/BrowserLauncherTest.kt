package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-2954 — the interactive `thoryn login` browser auto-open must never crash the process.
 *
 * On the GraalVM native binary the first touch of `java.awt.Desktop` throws `UnsatisfiedLinkError`
 * ("No awt in java.library.path") — an [Error], not an [Exception]. These tests drive the internal
 * seam of [BrowserLauncher.open] with stubbed desktop/platform openers (no real browser or process
 * is ever launched) to pin: a `Throwable` from the desktop attempt is non-fatal and the platform
 * opener fallback is taken; the native-image gate skips AWT entirely; and `THORYN_NO_BROWSER` still
 * short-circuits before any opener runs.
 */
class BrowserLauncherTest {

    @Test
    fun `a Throwable from the desktop attempt is non-fatal and falls back to the platform opener`() {
        var platformOpenerCalledWith: String? = null

        val result = BrowserLauncher.open(
            url = "https://hub.example.test/oauth2/authorize?x=1",
            noBrowser = { false },
            inNativeImage = { false }, // JVM path: desktop is attempted...
            desktopOpen = { throw java.lang.UnsatisfiedLinkError("No awt in java.library.path") },
            platformOpen = { url -> platformOpenerCalledWith = url; true },
        )

        // open() returned without propagating the Error, and the platform opener took over.
        assertThat(result).isTrue()
        assertThat(platformOpenerCalledWith).isEqualTo("https://hub.example.test/oauth2/authorize?x=1")
    }

    @Test
    fun `a plain Error from the desktop attempt does not escape open`() {
        // Guards the general contract, not just UnsatisfiedLinkError: any Error/class-init failure is
        // swallowed. If open() rethrew, this test would error rather than assert.
        val result = BrowserLauncher.open(
            url = "https://hub.example.test/authorize",
            noBrowser = { false },
            inNativeImage = { false },
            desktopOpen = { throw NoClassDefFoundError("java/awt/Desktop") },
            platformOpen = { true },
        )

        assertThat(result).isTrue()
    }

    @Test
    fun `in the native image the desktop attempt is skipped and the platform opener is used`() {
        var desktopAttempted = false
        var platformOpenerCalled = false

        val result = BrowserLauncher.open(
            url = "https://hub.example.test/authorize",
            noBrowser = { false },
            inNativeImage = { true }, // native binary: AWT must never be touched
            desktopOpen = { desktopAttempted = true; true },
            platformOpen = { platformOpenerCalled = true; true },
        )

        assertThat(desktopAttempted).isFalse()
        assertThat(platformOpenerCalled).isTrue()
        assertThat(result).isTrue()
    }

    @Test
    fun `desktop success short-circuits before the platform opener on a JVM`() {
        var platformOpenerCalled = false

        val result = BrowserLauncher.open(
            url = "https://hub.example.test/authorize",
            noBrowser = { false },
            inNativeImage = { false },
            desktopOpen = { true },
            platformOpen = { platformOpenerCalled = true; true },
        )

        assertThat(result).isTrue()
        assertThat(platformOpenerCalled).isFalse()
    }

    @Test
    fun `THORYN_NO_BROWSER short-circuits returning false with no opener invoked`() {
        var desktopAttempted = false
        var platformOpenerCalled = false

        val result = BrowserLauncher.open(
            url = "https://hub.example.test/authorize",
            noBrowser = { true }, // THORYN_NO_BROWSER is set
            inNativeImage = { false },
            desktopOpen = { desktopAttempted = true; true },
            platformOpen = { platformOpenerCalled = true; true },
        )

        assertThat(result).isFalse()
        assertThat(desktopAttempted).isFalse()
        assertThat(platformOpenerCalled).isFalse()
    }

    @Test
    fun `open returns false when both the desktop attempt and the platform opener fail`() {
        val result = BrowserLauncher.open(
            url = "https://hub.example.test/authorize",
            noBrowser = { false },
            inNativeImage = { false },
            desktopOpen = { false },
            platformOpen = { false },
        )

        assertThat(result).isFalse()
    }
}
