package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.Tokens

/**
 * SSO-3270 — the other end of [DeviceRegistrar]: when this installation **discards its DPoP key**,
 * revoke the device that key was registered as.
 *
 * ## Why discarding the key is not enough
 *
 * [DeviceRegistrar] registers the key a login bound its token to, and the hub keeps a `dpop_device`
 * row naming that key's `jkt`. `thoryn logout --rotate-key` used to delete the key and stop there,
 * on the argument that the hub needed no cleanup — a `jkt` only ever *binds* a token, and the tokens
 * were being discarded in the same breath. That is true of the security question and wrong about
 * every other one: the row survives, so `thoryn devices list` and the account page go on showing a
 * machine that can no longer sign anything, and the SSO-3229 activity view attributes a key nobody
 * holds. A device list is a list a person makes decisions from, so a row in it has to be real.
 *
 * ## Why the order is revoke → discard → clear
 *
 * The revoke is `POST /account/devices/{id}/revoke` on the hub, and the hub authenticates it from
 * the session AND a fresh DPoP proof (RFC 9449) signed by the key the request is about. Both of the
 * things `logout` is about to destroy are therefore what the call needs: run it after
 * [com.devnow.thoryn.cli.auth.Dpop.rotate] and there is no key left to sign the proof; run it after
 * the token store is cleared and there is no session to authenticate with. So it goes first, and
 * `logout` prints its outcome alongside the rest.
 *
 * ## Why nothing here can fail a logout
 *
 * Signing out is a local act that must always succeed — a user reaching for `--rotate-key` on a
 * machine they are handing on cannot be left holding a live key because the hub was unreachable.
 * Every failure is therefore a one-line note and a continue, and each one says what to do instead:
 * the device id is printed so the same revoke can be run from another machine. The failures are all
 * ordinary — a session whose refresh token already lapsed (401), a device someone already revoked
 * from the console (404), an aeroplane (network).
 */
internal object DeviceRetirement {

    /** The `reason` recorded on the hub's audit row, so the log distinguishes this from a theft. */
    const val REASON_KEY_ROTATED: String = "key_rotated"

    /** Test seam — substitutes the hub client without a network call. */
    internal var clientFactory: (String, Tokens) -> ProductApiClient = { hub, tokens ->
        CommandSupport.client(hub, tokens)
    }

    /**
     * Revoke the device registered for the key this installation is about to discard.
     *
     * **Call before the key is rotated and before the token store is cleared** — see the class doc.
     *
     * @return a line for the user, or null when there was nothing to revoke: no session, no hub
     *   recorded at login, or no device id (a session that predates device registration, or one
     *   whose registration the hub declined — there is no row to strand in either case).
     */
    fun revokeRetiredDevice(tokens: Tokens?, reason: String = REASON_KEY_ROTATED): String? {
        val session = tokens ?: return null
        val deviceId = session.deviceId?.takeIf { it.isNotBlank() } ?: return null
        val hub = session.issuer?.takeIf { it.isNotBlank() } ?: return null

        return try {
            val body = clientFactory(hub, session).revokeDevice(deviceId, reason)
            val name = body["name"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotEmpty() }
                ?: session.deviceName?.takeIf { it.isNotBlank() }
                ?: deviceId
            // An already-revoked device answers 200 with `revokedSessions: 0` rather than an error,
            // so the count is the only thing that varies between "we ended sessions" and "it was
            // already gone" — and neither is worth a second sentence.
            val ended = body["revokedSessions"]?.takeIf { !it.isNull }?.asInt() ?: 0
            if (ended > 0) {
                "Device '$name' revoked at the hub ($ended ${if (ended == 1) "session" else "sessions"} ended)."
            } else {
                "Device '$name' revoked at the hub."
            }
        } catch (ex: ProductApiException) {
            when (ex.httpStatus) {
                // The hub has no such device: already revoked from elsewhere, or a row this account
                // no longer owns. Either way the thing this exists to prevent has not happened.
                404 -> "Note: the hub has no device '$deviceId' to revoke — it was already removed."
                401, 403 -> unrevoked(deviceId, "your session had already ended at the hub")
                else -> unrevoked(deviceId, ex.errorCode ?: "HTTP ${ex.httpStatus}")
            }
        } catch (ex: Exception) {
            unrevoked(deviceId, CommandSupport.describeThrowable(ex))
        }
    }

    /** The one shape every failure takes: what went wrong, and the command that finishes the job. */
    private fun unrevoked(deviceId: String, why: String): String =
        "Note: this device could not be revoked at the hub ($why). It still appears in " +
            "`thoryn devices list`; run `thoryn devices revoke $deviceId` from another machine."

    /** Test seam — restore the real collaborator. */
    internal fun resetForTest() {
        clientFactory = { hub, tokens -> CommandSupport.client(hub, tokens) }
    }
}
