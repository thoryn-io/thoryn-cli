package com.devnow.thoryn.cli

import com.devnow.thoryn.cli.cmd.AccessCommand
import com.devnow.thoryn.cli.cmd.AuditCommand
import com.devnow.thoryn.cli.cmd.AuditReplayCommand
import com.devnow.thoryn.cli.cmd.BrandingCommand
import com.devnow.thoryn.cli.cmd.LoginFlowCommand
import com.devnow.thoryn.cli.cmd.LoginMethodsCommand
import com.devnow.thoryn.cli.cmd.ClientsCommand
import com.devnow.thoryn.cli.cmd.DevicesCommand
import com.devnow.thoryn.cli.cmd.DiagCommand
import com.devnow.thoryn.cli.cmd.DomainCommand
import com.devnow.thoryn.cli.cmd.KeysCommand
import com.devnow.thoryn.cli.cmd.EnvironmentCommand
import com.devnow.thoryn.cli.cmd.FederationCommand
import com.devnow.thoryn.cli.cmd.LoginCommand
import com.devnow.thoryn.cli.cmd.LogoutCommand
import com.devnow.thoryn.cli.cmd.StatusCommand
import com.devnow.thoryn.cli.cmd.TenantCommand
import com.devnow.thoryn.cli.cmd.UsersCommand
import com.devnow.thoryn.cli.cmd.WhoamiCommand
import com.devnow.thoryn.cli.cmd.WorkspaceCommand
import com.devnow.thoryn.cli.cmd.examples.ExamplesCommand
import com.devnow.thoryn.cli.cmd.provision.ProvisionCommand
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
    // SSO-2953: version is build-stamped via VersionProvider (reads the filtered
    // version.properties resource), not a hardcoded literal — so a release binary
    // reports its release version instead of 0.0.1-SNAPSHOT.
    versionProvider = VersionProvider::class,
    mixinStandardHelpOptions = true,
    subcommands = [
        LoginCommand::class,
        LogoutCommand::class,
        WhoamiCommand::class,
        StatusCommand::class,
        // SSO-3228 — the machines signed in to your account (DPoP keys as named devices).
        DevicesCommand::class,
        ClientsCommand::class,
        FederationCommand::class,
        WorkspaceCommand::class,
        EnvironmentCommand::class,
        // SSO-3113 — least-privilege access grants (`thoryn access grant|revoke|list|mine`).
        AccessCommand::class,
        // SSO-3303 — the workspace's custom domain (`thoryn domain add|status|verify|remove`).
        DomainCommand::class,
        // SSO-3369 — on-demand signing-key rotation (`thoryn keys rotate | rotations`).
        KeysCommand::class,
        BrandingCommand::class,
        LoginFlowCommand::class,
        LoginMethodsCommand::class,
        TenantCommand::class,
        UsersCommand::class,
        AuditCommand::class,
        AuditReplayCommand::class,
        ExamplesCommand::class,
        ProvisionCommand::class,
        // SSO-2956 — hidden internal diagnostics (native-image token round-trip check).
        DiagCommand::class,
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
