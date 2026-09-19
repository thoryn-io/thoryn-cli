package com.devnow.thoryn.cli.auth

import java.io.IOException
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.time.Duration
import java.time.Instant
import kotlin.io.path.Path
import kotlin.io.path.exists

/**
 * SSO-3227 — **how often the user is asked to prove presence for the hardware DPoP key.**
 *
 * The requirement is "once per session start, and again after N minutes idle (default 15) — not per
 * request". Two things have to be true for that to hold, and they are enforced in different places:
 *
 * 1. **Not per request.** [Dpop] caches the loaded [DpopKey] for the life of the process, and the
 *    secure-element signer holds one OS key handle. A command that mints five proofs (a token
 *    request plus four API calls) asks the OS to authorize signing with the same handle — it never
 *    re-opens the key per proof. This part is fully in the CLI's hands.
 *
 * 2. **Once per session start / per idle lapse.** This gate: a timestamp of the last successful
 *    presence-backed signature, kept in a 0600 state file beside the token store, and an idle window
 *    ([IDLE_MINUTES_ENV_VAR], default [DEFAULT_IDLE_MINUTES] minutes). Within the window the CLI
 *    stays silent; once it lapses the CLI prints one line telling the user why their laptop is about
 *    to ask for a fingerprint, so an unexplained biometric dialog never appears mid-script.
 *
 * ## The honest boundary
 *
 * The CLI does not — and cannot — decide whether the OS shows the dialog. A key created with
 * `kSecAccessControlUserPresence` is authorized by LocalAuthentication, and macOS alone decides when
 * a fresh authorization is required. Because every `thoryn` invocation is a **separate short-lived
 * process**, an `LAContext` (the only supported way to widen OS-side authorization reuse) cannot
 * outlive one command either. So what this gate guarantees is: *the CLI asks the OS to sign with the
 * presence-bound key at most once per process, and it tells the user before the first such request
 * once the idle window has lapsed.* Making the cadence hold **across** processes needs a resident
 * agent holding the `LAContext` — filed as a follow-up under SSO-3227, not faked here.
 *
 * The timestamp file holds an epoch second and nothing else. It is not a credential, it is not a
 * capability, and forging it grants nothing: the OS still enforces presence on the signature itself.
 */
internal object UserPresence {

    /** Default idle window before the CLI announces a fresh presence check. */
    const val DEFAULT_IDLE_MINUTES: Long = 15

    /** Override the idle window, in minutes. `0` announces on every invocation. */
    const val IDLE_MINUTES_ENV_VAR: String = "THORYN_DPOP_PRESENCE_IDLE_MINUTES"

    /** Explicit path override for the presence timestamp (tests / CI sandboxes). */
    const val STATE_FILE_ENV_VAR: String = "THORYN_DPOP_PRESENCE_FILE"

    /** Test seams. */
    internal var clock: () -> Instant = { Instant.now() }
    internal var environment: (String) -> String? = { System.getenv(it) }

    /** Whether this process has already passed the gate — the "not per request" half. */
    @Volatile
    private var announcedThisProcess: Boolean = false

    /**
     * The configured idle window. A malformed or negative value falls back to the default rather than
     * failing a command over a typo in an env var.
     */
    fun idleWindow(): Duration {
        val raw = environment(IDLE_MINUTES_ENV_VAR)?.trim()?.takeIf { it.isNotEmpty() }
            ?: return Duration.ofMinutes(DEFAULT_IDLE_MINUTES)
        val minutes = raw.toLongOrNull()?.takeIf { it >= 0 } ?: return Duration.ofMinutes(DEFAULT_IDLE_MINUTES)
        return Duration.ofMinutes(minutes)
    }

    /** True when the last recorded presence is still inside the idle window. */
    fun withinIdleWindow(): Boolean {
        val last = lastVerifiedAt() ?: return false
        val window = idleWindow()
        if (window.isZero) return false
        val elapsed = Duration.between(last, clock())
        // A clock that moved backwards (NTP step, VM restore) must not be read as "still fresh".
        return !elapsed.isNegative && elapsed < window
    }

    /**
     * Called **once per process**, immediately before the first presence-backed signature. Prints a
     * single explanatory line when the idle window has lapsed, so the platform dialog that follows is
     * never unexplained. Returns without printing when presence is still fresh, and never prints twice.
     */
    fun announceIfDue(err: PrintStream = System.err) {
        if (announcedThisProcess) return
        announcedThisProcess = true
        if (withinIdleWindow()) return
        err.println(
            "Confirm your presence to sign in with this machine's hardware-bound key " +
                "(asked once per session, and again after ${idleWindow().toMinutes()} minutes idle).",
        )
    }

    /** Record a successful presence-backed signature as "now". Best effort — never fails a command. */
    fun recordVerified() {
        val path = stateFile()
        runCatching {
            path.parent?.let { Files.createDirectories(it) }
            Files.writeString(
                path,
                clock().epochSecond.toString(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            )
            if (path.fileSystem.supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(
                    path,
                    setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                )
            }
        }
    }

    /** Forget the recorded presence — part of `thoryn logout --rotate-key`. */
    fun clear() {
        runCatching { Files.deleteIfExists(stateFile()) }
    }

    private fun lastVerifiedAt(): Instant? {
        val path = stateFile()
        if (!path.exists()) return null
        return try {
            Files.readString(path).trim().toLongOrNull()?.let { Instant.ofEpochSecond(it) }
        } catch (_: IOException) {
            null
        }
    }

    /** Beside the DPoP key file, so a sandboxed `THORYN_TOKEN_FILE` carries the whole set together. */
    internal fun stateFile(): Path {
        environment(STATE_FILE_ENV_VAR)?.takeIf { it.isNotBlank() }?.let { return Path(it) }
        return FileDpopKeyStore.defaultPath().resolveSibling("dpop-presence")
    }

    /** Test seam — drop the per-process latch and the injected clock/environment. */
    internal fun resetForTest() {
        announcedThisProcess = false
        clock = { Instant.now() }
        environment = { System.getenv(it) }
    }
}
