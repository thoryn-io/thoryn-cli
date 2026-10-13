package com.devnow.thoryn.cli.cmd.operator

import com.devnow.thoryn.cli.cmd.CommandSupport
import picocli.CommandLine.Command
import java.util.concurrent.Callable

/**
 * `thoryn operator …` (SSO-3356) — the Thoryn operator plane: cross-workspace operations a customer
 * cannot perform for themselves (oathy ADR `2026-09-18-operator-workspace-ownership-transfer.md`,
 * docs `operate/operator-plane/`).
 *
 * Not part of the customer product. An operator is an identity in the platform home workspace
 * (`thoryn`) that holds the explicit `platform:thoryn#operator` grant; the session is a PASSKEY
 * sign-in with the operator client, kept apart from the `thoryn login` session; and the hub serves
 * `/admin` only on its private address, reached with `kubectl port-forward`.
 */
@Command(
    name = "operator",
    description = [
        "Thoryn operator plane (Thoryn staff / self-managed platform operators): passkey sign-in on the",
        "platform home and workspace operations over a kubectl port-forward to the hub.",
    ],
    mixinStandardHelpOptions = true,
    subcommands = [
        OperatorLoginCommand::class,
        OperatorLogoutCommand::class,
        OperatorCustomDomainCommand::class,
    ],
)
class OperatorCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn operator <subcommand>")
        System.err.println("Subcommands: login | logout | custom-domain")
        System.err.println()
        System.err.println("  1. thoryn operator login --issuer <platform issuer>      # passkey sign-in on 'thoryn'")
        System.err.println("  2. ${OperatorSession.PORT_FORWARD_COMMAND}   # in another terminal")
        System.err.println("  3. thoryn operator custom-domain entitle <workspace>")
        return CommandSupport.EXIT_USAGE
    }
}

/** `thoryn operator logout` — forget the operator session. The customer `thoryn login` session is untouched. */
@Command(
    name = "logout",
    description = ["Forget the operator session on this machine. Your `thoryn login` session is left untouched."],
    mixinStandardHelpOptions = true,
)
class OperatorLogoutCommand : Callable<Int> {
    override fun call(): Int {
        runCatching { OperatorSession.store().delete() }
        println("Operator session cleared. (Your `thoryn login` session is unchanged.)")
        return CommandSupport.EXIT_OK
    }
}
