package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.SecretIo
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.util.concurrent.Callable

/**
 * `thoryn provision ...` — SSO-2952 (epic SSO-2947).
 *
 * **Operator provisioning**, distinct from the customer-facing `examples` surface. The CI-identity
 * bootstrap is an operator concern (a founder mints the CI's own machine credential once), not an
 * example a customer would run — so it lives here as a dedicated command rather than as an
 * example recipe. Per ADR `2026-09-09-thoryn-cli-as-code-ci-connection-contract.md`, the identity it
 * provisions is the one the CLI's connection contract (`thoryn login --connection`) binds to on every
 * CI run.
 *
 * Subcommands:
 *  - `ci-identity` — mint the confidential `client_credentials` machine client (secret via [SecretIo]).
 */
@Command(
    name = "provision",
    description = ["Operator provisioning (bootstrap the CI machine identity)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ProvisionCommand.CiIdentitySubcommand::class,
    ],
)
class ProvisionCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn provision <subcommand>")
        System.err.println("Subcommands: ci-identity")
        return CommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn provision ci-identity [--secret-file <path>] [--force-stdout]`
     *
     * Mint the CI's confidential `client_credentials` machine client from the bundled declarative spec
     * (`/provision/ci-identity.json`) — the same product-api `POST /api/v1/applications` call
     * `thoryn clients create` makes. The one-shot `client_secret` is emitted through [SecretIo]: written
     * to `--secret-file`, or printed to an interactive TTY with a WARN; a non-interactive stdout is
     * refused unless `--force-stdout`. The secret never touches argv or a log.
     *
     * A founder runs this ONCE, signed into the `thoryn` workspace (browser OIDC + `workspace switch`),
     * so the client is minted under that workspace's `tnt`.
     */
    @Command(
        name = "ci-identity",
        description = ["Mint the CI's confidential client_credentials machine client. The secret is shown once."],
        mixinStandardHelpOptions = true,
    )
    class CiIdentitySubcommand : Callable<Int> {

        @Option(names = ["--secret-file"], description = ["Write the minted client secret to this file (owner-only) instead of a TTY/pipe."])
        var secretFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing the secret to a non-interactive stdout (pipe/redirect). Off by default."])
        var forceStdout: Boolean = false

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            // Honour an active `workspace switch` so the client is minted under the founder's selected
            // workspace (the `thoryn` tenant), exactly as `thoryn clients create` does.
            val client = CommandSupport.gatewayClient(gateway, tokens)
            val spec = try {
                MachineClientSpec.ciIdentity()
            } catch (ex: MachineClientProvisionException) {
                System.err.println("Could not load the ci-identity provisioning spec: ${ex.message}")
                return CommandSupport.EXIT_IO_ERROR
            }
            val provisioner = MachineClientProvisioner(
                client,
                MachineClientProvisioner.SecretSink.toSecretIo(secretFile, forceStdout),
            )
            return try {
                val result = provisioner.provision(spec)
                println("Machine client provisioned:")
                println("  clientId: ${result.clientId}")
                println("  scopes:   ${result.grantedScopes.joinToString(", ")}")
                if (!result.secretDelivered) {
                    System.err.println(
                        "The machine client '${result.clientId}' was created but its secret could not be delivered — " +
                            "re-run with --secret-file <path> (or --force-stdout).",
                    )
                    return SecretIo.EXIT_NO_SECRET
                }
                println()
                println("Next: paste the clientId into .thoryn/connection.json (auth.clientId), and the secret into the")
                println("THORYN_CLI_CI_CLIENT_SECRET GitHub secret, then shred the secret file. See .thoryn/README.md.")
                CommandSupport.EXIT_OK
            } catch (ex: MachineClientProvisionException) {
                System.err.println("Could not provision the CI machine client: ${ex.message}")
                CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(OutputFormat.TABLE, ex, requiredScope = "tenant:applications.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }
}
