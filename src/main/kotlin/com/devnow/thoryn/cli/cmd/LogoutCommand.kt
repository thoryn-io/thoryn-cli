package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.TokenStore
import picocli.CommandLine.Command
import java.util.concurrent.Callable

/**
 * `thoryn logout` — clear the locally stored tokens.
 *
 * Hub-side revocation (RFC 7009) lands as a follow-up; for the scaffold we
 * just delete the token file. After this command the user is "signed out"
 * from this machine; tokens elsewhere (other devices, other CLI installs)
 * remain valid until they expire.
 */
@Command(
    name = "logout",
    description = ["Clear locally stored tokens. Does not yet revoke at the hub."],
    mixinStandardHelpOptions = true,
)
class LogoutCommand : Callable<Int> {

    private val tokenStore: TokenStore = FileTokenStore()

    override fun call(): Int {
        tokenStore.delete()
        println("Signed out (local tokens cleared).")
        return 0
    }
}
