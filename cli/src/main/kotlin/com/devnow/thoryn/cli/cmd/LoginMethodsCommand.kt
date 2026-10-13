package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn login-methods ...` (SSO-3075, epic SSO-2871) — read + set the allow-list of sign-in methods
 * the hosted login offers for the selected environment.
 *
 * Thin wrapper over product-api's `/api/v1/login-methods` surface (SSO-1307). The policy is
 * per-(tenant, ENVIRONMENT) — the slug rides on `X-Thoryn-Environment` (from `env use` or the
 * `--environment` flag) — so a sandbox and production can offer different methods (SSO-3073 makes the
 * login page actually enforce the per-environment policy).
 *
 * This is the surface a headless recipe needs to enable an OPT-IN method (`magic_code`, `sms`, …) that
 * is not in the default set — e.g. the magic-code example turns on `magic_code` for its sandbox so the
 * hosted login renders the "email me a code" affordance. A raw product-api call in an example is a gap
 * signal (this command closes it, mirroring `thoryn login-flow`, SSO-3065).
 *
 * Subcommands:
 *  - `show`  — GET /api/v1/login-methods (stored + effective + supported)
 *  - `set`   — PUT /api/v1/login-methods from repeated `--method` flags (the FULL allow-list)
 *  - `reset` — DELETE /api/v1/login-methods (back to the default: every method offered)
 *
 * Scopes: `show` → `tenant:idp.read`; `set` / `reset` → `tenant:idp.write`.
 */
@Command(
    name = "login-methods",
    description = ["Show / set which sign-in methods the hosted login offers for the selected environment."],
    mixinStandardHelpOptions = true,
    subcommands = [
        LoginMethodsCommand.ShowSubcommand::class,
        LoginMethodsCommand.SetSubcommand::class,
        LoginMethodsCommand.ResetSubcommand::class,
    ],
)
class LoginMethodsCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn login-methods <subcommand>")
        System.err.println("Subcommands: show | set | reset")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn login-methods show` — the methods the selected environment offers. */
    @Command(name = "show", description = ["Show the login methods for the selected environment."], mixinStandardHelpOptions = true)
    class ShowSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [LoginFlowCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = LoginFlowCommand.resolveClient(gateway, tokens, environment)
            return try {
                CommandSupport.emitRecord(format, client.getLoginMethods(), ::loginMethodsRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn login-methods set --method password --method magic_link --method magic_code`
     *
     * PUTs the FULL allow-list (replace, not merge — pass every method you want offered). Order is
     * preserved as the login-method order. The server rejects an empty or unknown-token list
     * (`400 invalid_login_method`); to reset to the default use `reset`, not an empty `set`.
     */
    @Command(name = "set", description = ["Set the FULL login-method allow-list from repeated --method flags."], mixinStandardHelpOptions = true)
    class SetSubcommand : Callable<Int> {

        @Option(
            names = ["--method"],
            description = [
                "A login method to offer (repeatable; the full allow-list, in order). " +
                    "e.g. password | magic_link | magic_code | passkey | totp | sms. " +
                    "--method password --method magic_link --method magic_code",
            ],
            required = true,
        )
        var methods: MutableList<String> = mutableListOf()

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [LoginFlowCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val normalised = methods.map { it.trim().lowercase() }.filter { it.isNotEmpty() }
            if (normalised.isEmpty()) {
                System.err.println("login-methods set: at least one --method is required.")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = LoginFlowCommand.resolveClient(gateway, tokens, environment)
            return try {
                CommandSupport.emitRecord(format, client.putLoginMethods(normalised), ::loginMethodsRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn login-methods reset` — reset to the default (every method offered). */
    @Command(name = "reset", description = ["Reset the login-method policy to the default (offer every method)."], mixinStandardHelpOptions = true)
    class ResetSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [LoginFlowCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = LoginFlowCommand.resolveClient(gateway, tokens, environment)
            return try {
                client.resetLoginMethods()
                CommandSupport.emitRecord(format, client.getLoginMethods(), ::loginMethodsRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        /** Render fields for the login-methods view: stored / effective / supported (comma-joined). */
        internal fun loginMethodsRecordFields(node: JsonNode): List<Pair<String, Any?>> {
            fun list(field: String): String =
                node[field]?.takeUnless { it.isNull }?.mapNotNull { it.asString() }?.joinToString(", ")
                    ?: "(none)"
            return listOf(
                "stored" to (node["stored"]?.takeIf { !it.isNull }?.let { list("stored") } ?: "(default)"),
                "effective" to list("effective"),
                "supported" to list("supported"),
                "updatedAt" to (node["updatedAt"]?.takeUnless { it.isNull }?.asString()),
            )
        }
    }
}
