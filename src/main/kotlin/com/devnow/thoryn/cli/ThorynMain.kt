package com.devnow.thoryn.cli

import com.devnow.thoryn.cli.cmd.AuditCommand
import com.devnow.thoryn.cli.cmd.AuditReplayCommand
import com.devnow.thoryn.cli.cmd.ClientsCommand
import com.devnow.thoryn.cli.cmd.FederationCommand
import com.devnow.thoryn.cli.cmd.LoginCommand
import com.devnow.thoryn.cli.cmd.LogoutCommand
import com.devnow.thoryn.cli.cmd.TenantCommand
import com.devnow.thoryn.cli.cmd.WorkspaceCommand
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
    name = "thoryn",
    description = ["Thoryn customer-plane CLI."],
    version = ["thoryn 0.0.1-SNAPSHOT"],
    mixinStandardHelpOptions = true,
    subcommands = [
        LoginCommand::class,
        LogoutCommand::class,
        ClientsCommand::class,
        FederationCommand::class,
        WorkspaceCommand::class,
        TenantCommand::class,
        AuditCommand::class,
        AuditReplayCommand::class,
    ],
)
class ThorynMain : Runnable {
    override fun run() {
        // Top-level invocation with no subcommand — print usage.
        CommandLine.usage(this, System.out)
    }
}

fun main(args: Array<String>) {
    val exitCode = CommandLine(ThorynMain()).execute(*args)
    exitProcess(exitCode)
}
