package com.devnow.oathy.cli

import com.devnow.oathy.cli.cmd.ClientsCommand
import com.devnow.oathy.cli.cmd.LoginCommand
import com.devnow.oathy.cli.cmd.LogoutCommand
import picocli.CommandLine
import picocli.CommandLine.Command
import kotlin.system.exitProcess

/**
 * `oathy` — the Thoryn customer-plane CLI.
 *
 * See ADR `2026-04-25-customer-plane-product-api` (§4 and §8). Authorization
 * Code + PKCE with loopback redirect per RFC 8252 §7.3. Native-image build and
 * OS-package distribution land in SSO-733 / SSO-734.
 */
@Command(
    name = "oathy",
    description = ["Thoryn customer-plane CLI."],
    version = ["oathy 0.0.1-SNAPSHOT"],
    mixinStandardHelpOptions = true,
    subcommands = [
        LoginCommand::class,
        LogoutCommand::class,
        ClientsCommand::class,
    ],
)
class OathyMain : Runnable {
    override fun run() {
        // Top-level invocation with no subcommand — print usage.
        CommandLine.usage(this, System.out)
    }
}

fun main(args: Array<String>) {
    val exitCode = CommandLine(OathyMain()).execute(*args)
    exitProcess(exitCode)
}
