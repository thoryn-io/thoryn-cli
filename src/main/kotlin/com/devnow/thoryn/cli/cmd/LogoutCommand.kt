package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.TokenStore
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn logout` — clear the locally stored tokens.
 *
 * Hub-side revocation (RFC 7009) lands as a follow-up; for the scaffold we
 * just delete the token file. After this command the user is "signed out"
 * from this machine; tokens elsewhere (other devices, other CLI installs)
 * remain valid until they expire.
 *
 * **DPoP key (SSO-3199).** The installation's DPoP key (RFC 9449) is deliberately NOT deleted by
 * default: it is a machine identity, not a session artefact, and on its own it authorises nothing — a
 * proof key is only usable together with an access token bound to it, and those are being discarded
 * here. Keeping it means the next `thoryn login` re-binds to the same `jkt`. `--rotate-key` discards it
 * instead (the right move when handing the machine on, or when the key may have leaked); every token
 * bound to the old thumbprint becomes unusable at that moment. Only the PUBLIC thumbprint is ever
 * printed — the private key never leaves the secure store.
 */
@Command(
    name = "logout",
    description = ["Clear locally stored tokens. Does not yet revoke at the hub."],
    mixinStandardHelpOptions = true,
)
class LogoutCommand : Callable<Int> {

    @Option(
        names = ["--rotate-key"],
        description = [
            "Also discard this installation's DPoP key (RFC 9449) so the next login generates a new " +
                "one. Any access token still bound to the old key thumbprint stops working.",
        ],
    )
    var rotateKey: Boolean = false

    /** Test seam — where the command writes its confirmation lines. */
    internal var out: PrintStream = System.out

    private val tokenStore: TokenStore = TokenStoreFactory.default()

    override fun call(): Int {
        tokenStore.delete()
        out.println("Signed out (local tokens cleared).")

        if (rotateKey) {
            val had = Dpop.rotate()
            out.println(
                if (had) "DPoP key discarded — the next `thoryn login` generates a new one."
                else "No DPoP key was stored; the next `thoryn login` generates one.",
            )
        } else {
            val session = runCatching { Dpop.session() }.getOrNull()
            if (session != null) {
                // SSO-3227 — name the protection class too: "kept" means something different for a
                // non-exportable hardware key than for a software one, and this is the last line the
                // user sees before handing the machine on.
                out.println(
                    "DPoP key kept (jkt ${session.thumbprint}, ${session.key.keyClass.wireValue}). " +
                        "Use `--rotate-key` to generate a new one.",
                )
            }
        }
        return 0
    }
}
