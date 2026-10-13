package com.devnow.thoryn.cli.auth

/**
 * SSO-3282 — the one place the CLI recognises "the hub refused this key because its device was
 * revoked", and the one place it says what to do about it.
 *
 * ## The dead end this exists to end
 *
 * A revoked device's key is refused on every grant (SSO-3228), and the refusal is `invalid_grant` —
 * the same code the hub returns for a replayed authorization code, a spent refresh token and a
 * redirect-URI mismatch. So the CLI could see only "invalid_grant" and had nothing to act on. The
 * product owner revoked the machine they were sitting at and every `thoryn login` afterwards failed
 * `400 invalid_grant`, with the revoke's own output cheerfully promising that signing in again
 * would register a new device — which it could not, because the key on disk had not changed.
 *
 * The hub now attaches a stable [ERROR_DESCRIPTION] to exactly that refusal (SSO-3282, hub half).
 * That string is a WIRE CONTRACT between the two repos: it is matched here EXACTLY, so that the CLI
 * branches on a revoked device and on nothing else.
 *
 * ## Why the match is on the description alone
 *
 * Deliberately deterministic. The tempting alternative — on any `invalid_grant`, go and ask the hub
 * whether this key's device is revoked — turns a clean signal into a guess plus a round trip, and
 * the lookup itself needs the very session the refusal just proved is unusable. A refusal that does
 * NOT carry this description is left exactly as it was: reported, not retried.
 */
internal object RevokedDevice {

    /**
     * The hub's `error_description` on a revoked-device refusal — `DpopDeviceGuard
     * .REVOKED_ERROR_DESCRIPTION` in `thoryn-io/oauthy`. Do not loosen this to a `contains`: the
     * exactness is what keeps "rotate my key and retry" from firing on an unrelated failure.
     */
    const val ERROR_DESCRIPTION: String = "dpop_device_revoked"

    /** Did the hub refuse this grant because the key's device is revoked? */
    fun refused(errorDescription: String?): Boolean = errorDescription?.trim() == ERROR_DESCRIPTION

    /**
     * What a person is told when their key is refused and the CLI is about to fix it for them.
     * One sentence, in the order the events happen.
     */
    const val ROTATING_NOTICE: String =
        "This machine's device was revoked, so its key is no longer accepted. " +
            "Generating a new key and signing in again — this machine will register as a new device."

    /**
     * What a person is told when the CLI is NOT going to fix it for them — a renewal, where the
     * remedy is a command they run rather than something that can happen mid-call.
     */
    const val RENEWAL_GUIDANCE: String =
        "This machine's device was revoked, so its key is no longer accepted and this session cannot " +
            "be renewed. Run `thoryn logout --rotate-key` to generate a new key, then `thoryn login`."
}
