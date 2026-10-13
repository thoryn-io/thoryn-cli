package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.Tokens
import java.io.PrintStream
import java.net.InetAddress

/**
 * SSO-3228 — registers this installation's DPoP key as a named **device** on the hub, the first time
 * a login produces a token bound to it.
 *
 * ## Why registration happens at login and nowhere else
 *
 * `POST /account/devices` requires the caller to prove possession of the key being registered, and
 * the hub takes that proof from the request itself: the token must carry `cnf.jkt` and be presented
 * under the DPoP scheme with a fresh proof from the same key. A login is exactly the moment all
 * three hold — the CLI has just minted a bound token with the key it is about to register. Doing it
 * lazily on some later command would work identically but would surprise the user by making an
 * unrelated command register something.
 *
 * ## Why it never fails the login
 *
 * A device record is a revocation convenience, not a credential. A hub that does not have the
 * endpoint yet (an older platform), a network blip, or a refusal must not turn a successful sign-in
 * into a failed one — the session is valid and every command works without a device record. So
 * [register] swallows everything, notes it on stderr once, and returns the tokens unchanged.
 *
 * ## Why the token is the gate
 *
 * A token with no `cnf.jkt` is not sender-constrained, so there is nothing to register and the hub
 * would refuse anyway (`dpop_binding_required`). Reading the claim rather than "did we send a
 * proof?" is the same gate the hub uses, so the two agree by construction.
 */
object DeviceRegistrar {

    /** Test seam — substitutes the hub client without a network call. */
    internal var clientFactory: (String, Tokens) -> ProductApiClient = { hub, tokens ->
        CommandSupport.client(hub, tokens)
    }

    /** Test seam — the hostname used as the default device name. */
    internal var hostname: () -> String? = { runCatching { InetAddress.getLocalHost().hostName }.getOrNull() }

    /**
     * Register the key [tokens] is bound to, returning [tokens] stamped with the device id and name
     * — or unchanged when there is nothing to register or the hub declined.
     *
     * @param explicitName `--device-name`, when the user named the machine themselves.
     */
    fun register(
        tokens: Tokens,
        explicitName: String? = null,
        err: PrintStream = System.err,
    ): Tokens {
        val hub = tokens.issuer?.takeIf { it.isNotBlank() } ?: return tokens
        // Not sender-constrained ⇒ nothing to register. The same gate the hub applies.
        val boundThumbprint = JwtClaims.of(tokens.accessToken)["cnf"]?.get("jkt")?.asString()
            ?.takeIf { it.isNotBlank() }
            ?: return tokens
        val session = runCatching { Dpop.session(err) }.getOrNull() ?: return tokens
        // A token bound to a key this installation does not hold cannot be used to register that
        // key, and registering a DIFFERENT one is exactly what the hub refuses. Leave it alone.
        if (session.thumbprint != boundThumbprint) return tokens

        val name = explicitName?.trim()?.takeIf { it.isNotEmpty() } ?: defaultName()

        return try {
            val response = clientFactory(hub, tokens).registerDevice(
                mapOf(
                    "jwk" to session.key.publicJwkJson,
                    "name" to name,
                    "osHint" to osHint(),
                    "hostHint" to hostname(),
                ),
            )
            val id = response["id"]?.asString()
            val registeredName = response["name"]?.asString() ?: name
            tokens.copy(deviceId = id, deviceName = registeredName)
        } catch (e: Exception) {
            // Never fail a sign-in over this — see the class docs. One line, so a user who expected
            // `thoryn devices list` to show this machine knows why it does not.
            err.println(
                "Note: this device could not be registered (${e.message ?: e.javaClass.simpleName}). " +
                    "You are signed in; run `thoryn login` again later to register it.",
            )
            tokens
        }
    }

    /** The machine's hostname, else a stable fallback — never blank, since the hub requires a name. */
    private fun defaultName(): String =
        hostname()?.trim()?.takeIf { it.isNotEmpty() } ?: "${osName()} device"

    /** `darwin 25.5.0 arm64` — a display aid the hub stores verbatim and decides nothing from. */
    private fun osHint(): String = listOf(
        System.getProperty("os.name"),
        System.getProperty("os.version"),
        System.getProperty("os.arch"),
    ).filter { !it.isNullOrBlank() }.joinToString(" ")

    private fun osName(): String = System.getProperty("os.name")?.takeIf { it.isNotBlank() } ?: "unknown"

    /** Test seam — restore the real collaborators. */
    internal fun resetForTest() {
        clientFactory = { hub, tokens -> CommandSupport.client(hub, tokens) }
        hostname = { runCatching { InetAddress.getLocalHost().hostName }.getOrNull() }
    }
}
