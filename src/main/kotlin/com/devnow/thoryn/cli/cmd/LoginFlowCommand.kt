package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn login-flow ...` (SSO-3065, epic SSO-2871) — author + activate the MULTI-STEP login journey
 * (which authenticator stages a sign-in walks) for the selected environment.
 *
 * Thin wrapper over product-api's `/api/v1/login-flows` surface (SSO-2345) reached through the
 * api-gateway. The flow is per-(tenant, ENVIRONMENT): it applies to the environment you've selected
 * with `thoryn env use` (the slug rides on `X-Thoryn-Environment`), so a sandbox and production can
 * carry different journeys. identity-service runs the flow in ENFORCE mode (LoginFlowEnforceDriver):
 * a REQUIRED stage the user can satisfy is challenged on every sign-in.
 *
 * This is the one surface a headless recipe needed and no other CLI command exposed — e.g. the
 * passkey second-factor example (SSO-3045) activates a `password REQUIRED + passkey REQUIRED` flow so
 * an enrolled passkey is challenged (passkey, unlike TOTP, has no enrolment-driven MFA path).
 *
 * Subcommands:
 *  - `show`           — GET /api/v1/login-flows/active (the flow the environment enforces today)
 *  - `set`            — PUT /api/v1/login-flows/draft from `--stage id:TYPE:REQUIREMENT` flags,
 *                       optionally `--activate` it in the same call
 *  - `activate`       — POST /api/v1/login-flows/activate <version>
 *  - `apply-template` — POST /api/v1/login-flows/templates/<id>/apply (creates a draft from a starter
 *                       template: password-only | mfa-always | passwordless-preferred | risk-based-step-up),
 *                       optionally `--activate`
 *
 * Scopes: `show` → `tenant:idp.read`; `set` / `activate` / `apply-template` → `tenant:idp.write`
 * (granted to `thoryn-cli`). Request them with `thoryn login --scope all-tenant-config`.
 */
@Command(
    name = "login-flow",
    description = ["Author + activate the login journey (authenticator stages) for the selected environment."],
    mixinStandardHelpOptions = true,
    subcommands = [
        LoginFlowCommand.ShowSubcommand::class,
        LoginFlowCommand.SetSubcommand::class,
        LoginFlowCommand.ActivateSubcommand::class,
        LoginFlowCommand.ApplyTemplateSubcommand::class,
    ],
)
class LoginFlowCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn login-flow <subcommand>")
        System.err.println("Subcommands: show | set | activate | apply-template")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn login-flow show` — the active flow the selected environment enforces. */
    @Command(name = "show", description = ["Show the ACTIVE login flow for the selected environment."], mixinStandardHelpOptions = true)
    class ShowSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = resolveClient(gateway, tokens, environment)
            return try {
                CommandSupport.emitRecord(format, client.getActiveLoginFlow(), ::loginFlowRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn login-flow set --stage password:PASSWORD:REQUIRED --stage passkey:PASSKEY:REQUIRED [--activate]`
     *
     * Each `--stage` is `id:TYPE:REQUIREMENT` (repeatable, render order preserved):
     *  - TYPE        — PASSWORD | PASSKEY | MAGIC_LINK | TOTP | SMS | STEP_UP (authenticator capability)
     *  - REQUIREMENT — REQUIRED | ALTERNATIVE | CONDITIONAL | DISABLED
     * Saves the draft; with `--activate` it activates the new version in the same call.
     */
    @Command(name = "set", description = ["Author the login flow from --stage id:TYPE:REQUIREMENT flags (optionally --activate)."], mixinStandardHelpOptions = true)
    class SetSubcommand : Callable<Int> {

        @Option(
            names = ["--stage"],
            description = [
                "A stage as id:TYPE:REQUIREMENT (repeatable, in render order). " +
                    "TYPE=PASSWORD|PASSKEY|MAGIC_LINK|TOTP|SMS|STEP_UP; REQUIREMENT=REQUIRED|ALTERNATIVE|CONDITIONAL|DISABLED. " +
                    "e.g. --stage password:PASSWORD:REQUIRED --stage passkey:PASSKEY:REQUIRED",
            ],
            required = true,
        )
        var stages: MutableList<String> = mutableListOf()

        @Option(names = ["--activate"], description = ["Activate the saved draft immediately."])
        var activate: Boolean = false

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val parsed = parseStages(stages) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = resolveClient(gateway, tokens, environment)
            val definition = mapOf(
                "version" to 1, // the store assigns the real next version; this satisfies the parse.
                "status" to "DRAFT",
                "stages" to parsed,
            )
            return try {
                val draft = client.putLoginFlowDraft(definition)
                if (!activate) {
                    CommandSupport.emitRecord(format, draft, ::loginFlowRecordFields)
                    return CommandSupport.EXIT_OK
                }
                val version = draft["version"]?.takeUnless { it.isNull }?.asInt()
                    ?: run {
                        System.err.println("login-flow set --activate: draft response carried no version to activate.")
                        return CommandSupport.EXIT_HTTP_ERROR
                    }
                CommandSupport.emitRecord(format, client.activateLoginFlow(version), ::loginFlowRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn login-flow activate <version>` — activate a stored draft version. */
    @Command(name = "activate", description = ["Activate a stored login-flow draft VERSION."], mixinStandardHelpOptions = true)
    class ActivateSubcommand : Callable<Int> {

        @Parameters(index = "0", paramLabel = "VERSION", description = ["The draft version number to activate."])
        var version: Int = 0

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = resolveClient(gateway, tokens, environment)
            return try {
                CommandSupport.emitRecord(format, client.activateLoginFlow(version), ::loginFlowRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn login-flow apply-template <id> [--activate]` — create a draft from a starter template. */
    @Command(name = "apply-template", description = ["Create a draft from a starter template (optionally --activate)."], mixinStandardHelpOptions = true)
    class ApplyTemplateSubcommand : Callable<Int> {

        @Parameters(
            index = "0",
            paramLabel = "TEMPLATE_ID",
            description = ["password-only | mfa-always | passwordless-preferred | risk-based-step-up."],
        )
        var templateId: String = ""

        @Option(names = ["--activate"], description = ["Activate the created draft immediately."])
        var activate: Boolean = false

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        @Option(names = ["--environment"], description = [ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = resolveClient(gateway, tokens, environment)
            return try {
                val draft = client.applyLoginFlowTemplate(templateId)
                if (!activate) {
                    CommandSupport.emitRecord(format, draft, ::loginFlowRecordFields)
                    return CommandSupport.EXIT_OK
                }
                val version = draft["version"]?.takeUnless { it.isNull }?.asInt()
                    ?: run {
                        System.err.println("login-flow apply-template --activate: draft carried no version.")
                        return CommandSupport.EXIT_HTTP_ERROR
                    }
                CommandSupport.emitRecord(format, client.activateLoginFlow(version), ::loginFlowRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        private val VALID_REQUIREMENTS = setOf("REQUIRED", "ALTERNATIVE", "CONDITIONAL", "DISABLED")

        internal const val ENVIRONMENT_OPTION_DESC =
            "Target environment slug (rides X-Thoryn-Environment). Use for a client-credentials/CI " +
                "session that hasn't run `workspace switch` + `env use`. Omit to use the environment " +
                "selected by `env use`."

        /**
         * SSO-3068 — pick the gateway client for a login-flow call. With `--environment <slug>` the
         * environment rides directly as `X-Thoryn-Environment` on a base (e.g. client-credentials/CI)
         * token, so an API-key session that never ran `workspace switch` + `env use` can still target a
         * specific environment — mirroring `thoryn examples --environment`. Without it, behaviour is
         * unchanged: honour an active `workspace switch` and the environment selected by `env use`.
         */
        internal fun resolveClient(gateway: String, tokens: com.devnow.thoryn.cli.auth.Tokens, environment: String?) =
            if (!environment.isNullOrBlank()) {
                CommandSupport.client(gateway, tokens, environmentSlug = environment)
            } else {
                CommandSupport.gatewayClient(gateway, tokens)
            }

        /**
         * Parse `--stage id:TYPE:REQUIREMENT` entries into login-flow stage maps. Returns null (and
         * prints usage) on a malformed entry — the caller returns [CommandSupport.EXIT_USAGE].
         */
        internal fun parseStages(raw: List<String>): List<Map<String, Any?>>? {
            val out = mutableListOf<Map<String, Any?>>()
            for (entry in raw) {
                val parts = entry.split(":")
                if (parts.size != 3 || parts.any { it.isBlank() }) {
                    System.err.println("login-flow: bad --stage '$entry' — expected id:TYPE:REQUIREMENT.")
                    return null
                }
                val (id, type, requirement) = parts
                val req = requirement.uppercase()
                if (req !in VALID_REQUIREMENTS) {
                    System.err.println("login-flow: bad requirement '$requirement' in '$entry' — one of $VALID_REQUIREMENTS.")
                    return null
                }
                out.add(
                    mapOf(
                        "id" to id,
                        "authenticators" to listOf(mapOf("type" to type.uppercase())),
                        "requirement" to req,
                    ),
                )
            }
            return out
        }

        /** Render fields for `show` / `set` / `activate` output: version, status, and a stage summary. */
        internal fun loginFlowRecordFields(node: JsonNode): List<Pair<String, Any?>> {
            val stages = node["stages"]?.takeUnless { it.isNull }?.mapNotNull { st ->
                val id = st["id"]?.asString() ?: return@mapNotNull null
                val types = st["authenticators"]?.mapNotNull { it["type"]?.asString() }?.joinToString("+") ?: ""
                val req = st["requirement"]?.asString() ?: ""
                "$id[$types]=$req"
            }?.joinToString(", ") ?: "(none)"
            return listOf(
                "version" to (node["version"]?.takeUnless { it.isNull }?.asInt()),
                "status" to (node["status"]?.takeUnless { it.isNull }?.asString()),
                "stages" to stages,
            )
        }
    }
}
