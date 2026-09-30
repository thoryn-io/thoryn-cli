package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.SelectedWorkspaceStore
import com.devnow.thoryn.cli.cmd.WorkloadIdentityCommand
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.Callable

/**
 * `thoryn project init config|app` (SSO-3435, epic SSO-3304) — set up, from the CLI and with NO GitHub App, a
 * GitHub repository that manages your own Thoryn workspace (a **config project**) or connects one application
 * (an **app project**). GitHub goes through your own `gh`; Thoryn through the public customer-plane API with
 * your own `thoryn login` session. See [ProjectInit] for the steps, the checks and the re-run guarantees.
 *
 *  - `project init config [--repo owner/name] [--sandbox <slug>] --reviewer <login>… --confirm-production`
 *  - `project init app --stack express|spring-boot|aspnet-core --environment <sandbox> [--repo owner/name]`
 *
 * Without `--repo` it works on the clone in the current directory (or `--dir`): it adds the template's files
 * (never overwriting one unless `--force`) and commits nothing.
 *
 * Exit codes: `0` done · `1` not signed in · `2` product-api refused a call · `3` a `gh` step failed ·
 * `4` a pre-flight check refused (nothing changed) · `64` invalid flags.
 */
@Command(
    name = "project",
    description = ["Set up a GitHub repository for your workspace's configuration or for an application (uses your own gh)."],
    mixinStandardHelpOptions = true,
    subcommands = [ProjectCommand.InitCommand::class],
)
class ProjectCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn project init config|app …")
        return CommandSupport.EXIT_USAGE
    }

    @Command(
        name = "init",
        description = [
            "Create or connect a repository: `config` manages your workspace, `app` connects one application.",
            "GitHub steps run through your own gh CLI; no GitHub App and no stored secret.",
        ],
        mixinStandardHelpOptions = true,
        subcommands = [InitConfigCommand::class, InitAppCommand::class],
    )
    class InitCommand : Callable<Int> {
        override fun call(): Int {
            System.err.println("Usage: thoryn project init config|app …")
            System.err.println("  config  a repository that manages your Thoryn workspace (production + a sandbox)")
            System.err.println("  app     a repository that connects one application to a sandbox")
            return CommandSupport.EXIT_USAGE
        }
    }

    /** Options both kinds share. */
    abstract class InitBase : Callable<Int> {
        @Option(
            names = ["--repo"],
            paramLabel = "<owner/name>",
            description = [
                "The GitHub repository. Created from the template when it does not exist (private unless --public);",
                "used as is when it does. Omit to work on the git clone in the current directory (or --dir).",
            ],
        )
        var repo: String? = null

        @Option(names = ["--public"], description = ["Create the repository public (with --repo, when it is created). Default: private."])
        var public: Boolean = false

        @Option(names = ["--dir"], paramLabel = "<path>", description = ["The root of the existing clone (without --repo). Default: the current directory."])
        var dir: String? = null

        @Option(names = ["--force"], description = ["In an existing clone, overwrite files that differ from the template's (default: stop and list them)."])
        var force: Boolean = false

        @Option(
            names = ["--template"],
            paramLabel = "<owner/repo>",
            description = ["The template repository to start from (e.g. a mirror). Default: thoryn-io/starter-<stack>."],
        )
        var template: String? = null

        @Option(
            names = ["--gateway"],
            description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."],
            defaultValue = ThorynConfig.DEFAULT_GATEWAY,
        )
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        @Option(names = ["--json"], description = ["Machine-readable output; shorthand for --output json."])
        var json: Boolean = false

        internal abstract val kind: ProjectInit.Kind
        abstract val stack: String

        /** Kind-specific flag validation; a message means usage error. */
        abstract fun validateKind(): String?

        abstract fun sandbox(): String?
        abstract fun reviewers(): List<String>
        abstract fun confirmProduction(): Boolean
        abstract fun kindArgs(): List<String>

        override fun call(): Int {
            if (json && outputRaw != null && !outputRaw.equals("json", ignoreCase = true)) {
                System.err.println("Error: --json cannot be combined with --output $outputRaw.")
                return CommandSupport.EXIT_USAGE
            }
            val format = CommandSupport.parseFormat(if (json) "json" else outputRaw) ?: return CommandSupport.EXIT_USAGE
            (validateCommon() ?: validateKind())?.let { message ->
                return renderStop(format, ProjectInit.Stop(ProjectInit.EXIT_USAGE, usageCode(message), message.substringAfter("|")), null)
            }

            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val selected = runCatching { SelectedWorkspaceStore().read() }.getOrNull()
            val session = ProjectInit.Session(
                workspaceSlug = selected?.slug ?: tokens.workspace?.takeIf { it.isNotBlank() } ?: ThorynConfig.workspaceOfIssuer(tokens.issuer),
                tenantId = selected?.tenantId ?: JwtClaims.of(tokens.accessToken)["tnt"]?.takeUnless { it.isNull }?.asString(),
                issuer = CommandSupport.resolvePlatformIssuer(ThorynConfig.DEFAULT_HUB, tokens),
                authMode = tokens.authMode,
            )
            val gw = gateway
            val api = object : ProjectInit.ThorynApi {
                override val workspace: ProductApiClient by lazy { CommandSupport.gatewayClient(gw, tokens, applyEnvironment = false) }
                private val perEnvironment = mutableMapOf<String, ProductApiClient>()
                override fun inEnvironment(slug: String): ProductApiClient =
                    perEnvironment.getOrPut(slug) { CommandSupport.gatewayClient(gw, tokens, environmentOverride = slug) }
            }
            val request = ProjectInit.Request(
                kind = kind,
                stack = stack,
                template = template?.trim() ?: "$TEMPLATE_OWNER/starter-$stack",
                repo = repo?.trim(),
                public = public,
                dir = dir?.let { Path.of(it) } ?: Path.of(System.getProperty("user.dir")),
                force = force,
                sandbox = sandbox(),
                reviewers = reviewers(),
                confirmProduction = confirmProduction(),
                commandLine = commandLine(),
            )
            val init = ProjectInit(request, GitHubCli(ghRunner()), api, session)
            return try {
                val report = init.execute()
                render(format, init, report)
                CommandSupport.EXIT_OK
            } catch (stop: ProjectInit.Stop) {
                renderStop(format, stop, init)
            } catch (ex: GhCommandException) {
                renderGhFailure(format, ex, init)
            } catch (ex: GhNotInstalledException) {
                renderGhFailure(format, GhCommandException(init.currentStep, GhResult(127, ByteArray(0), ex.message ?: "gh not found")), init)
            } catch (ex: ProductApiException) {
                renderApiFailure(format, ex, init)
            } catch (ex: Exception) {
                printProgress(init, System.err)
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        private fun validateCommon(): String? {
            repo?.trim()?.let {
                if (!REPO.matches(it)) return "invalid_repo|--repo must be <owner>/<name> (was '$it')."
                if (dir != null || force) return "invalid_request|--dir and --force apply to an existing clone; drop them with --repo."
            }
            if (repo == null && public) return "invalid_request|--public applies when --repo creates a repository."
            template?.trim()?.let { if (!REPO.matches(it)) return "invalid_template|--template must be <owner>/<repo> (was '$it')." }
            return null
        }

        private fun usageCode(message: String): String = message.substringBefore("|", "invalid_request")

        private fun commandLine(): String = buildList {
            add("thoryn project init ${kind.label}")
            addAll(kindArgs())
            repo?.let { add("--repo ${it.trim()}") }
            if (public) add("--public")
            dir?.let { add("--dir $it") }
            if (force) add("--force")
            template?.let { add("--template ${it.trim()}") }
        }.joinToString(" ")
    }

    /** `thoryn project init config` — the workspace's config project. */
    @Command(
        name = "config",
        description = [
            "Set up the repository that manages your workspace: a production connection (behind required reviewers)",
            "and a sandbox connection, each a secret-less workload identity trust.",
        ],
        mixinStandardHelpOptions = true,
    )
    class InitConfigCommand : InitBase() {
        @Option(
            names = ["--sandbox"],
            paramLabel = "<slug>",
            description = ["The sandbox the project configures; created when it does not exist. Default: the only sandbox, else 'sandbox'."],
        )
        var sandboxSlug: String? = null

        @Option(
            names = ["--reviewer"],
            paramLabel = "<github-login>",
            description = ["A GitHub user who must approve every production run (repeatable, 1-6). Required."],
        )
        var reviewerArgs: List<String> = mutableListOf()

        @Option(
            names = ["--confirm-production"],
            description = ["Required: the project gets a PRODUCTION workload identity that manages the workspace."],
        )
        var confirm: Boolean = false

        override val kind: ProjectInit.Kind = ProjectInit.Kind.CONFIG
        override val stack: String = CONFIG_STACK

        private val reviewerList: List<String>
            get() = reviewerArgs.flatMap { it.split(',', ' ') }.map { it.trim().removePrefix("@") }.filter { it.isNotEmpty() }

        override fun validateKind(): String? {
            val r = reviewerList
            if (r.isEmpty()) return "invalid_production_reviewers|Name at least one --reviewer <github-login>: every production run waits for a reviewer's approval."
            if (r.size > MAX_REVIEWERS) return "invalid_production_reviewers|At most $MAX_REVIEWERS --reviewer (GitHub's limit for an environment)."
            r.firstOrNull { !LOGIN.matches(it) }?.let { return "invalid_production_reviewers|'$it' is not a GitHub login." }
            if (r.map { it.lowercase() }.distinct().size != r.size) return "invalid_production_reviewers|A --reviewer is listed twice."
            if (!confirm) {
                return "production_confirmation_required|A config project creates a PRODUCTION workload identity trust that manages the workspace. " +
                    "Re-run with --confirm-production."
            }
            sandboxSlug?.trim()?.let {
                if (!SLUG.matches(it)) return "invalid_environment|--sandbox must be an environment slug (was '$it')."
                if (it == PRODUCTION) return "sandbox_required|--sandbox names a sandbox, not production."
            }
            return null
        }

        override fun sandbox(): String? = sandboxSlug?.trim()
        override fun reviewers(): List<String> = reviewerList
        override fun confirmProduction(): Boolean = confirm
        override fun kindArgs(): List<String> = buildList {
            sandboxSlug?.let { add("--sandbox ${it.trim()}") }
            reviewerList.forEach { add("--reviewer $it") }
            add("--confirm-production")
        }
    }

    /** `thoryn project init app` — one application's project, connected to one existing sandbox. */
    @Command(
        name = "app",
        description = [
            "Set up a repository that connects one application to an existing SANDBOX (never production):",
            "a secret-less workload identity trust its CI signs in with.",
        ],
        mixinStandardHelpOptions = true,
    )
    class InitAppCommand : InitBase() {
        @Option(names = ["--stack"], required = true, paramLabel = "<stack>", description = ["The application stack: express | spring-boot | aspnet-core."])
        var stackArg: String = ""

        @Option(names = ["--environment"], required = true, paramLabel = "<sandbox>", description = ["The existing sandbox the application connects to (its slug)."])
        var environment: String = ""

        override val kind: ProjectInit.Kind = ProjectInit.Kind.APP
        override val stack: String get() = stackArg.trim()

        override fun validateKind(): String? {
            if (stack !in APP_STACKS) return "invalid_stack|--stack must be one of ${APP_STACKS.joinToString(" | ")} (was '$stack')."
            val env = environment.trim()
            if (env == PRODUCTION) {
                return "production_refused|An app project connects to an existing SANDBOX; it never gets a production trust. " +
                    "Name a sandbox with --environment <slug> (thoryn env list)."
            }
            if (!SLUG.matches(env)) return "invalid_environment|--environment must be a sandbox slug (was '$env')."
            return null
        }

        override fun sandbox(): String = environment.trim()
        override fun reviewers(): List<String> = emptyList()
        override fun confirmProduction(): Boolean = false
        override fun kindArgs(): List<String> = listOf("--stack $stack", "--environment ${environment.trim()}")
    }

    companion object {
        const val TEMPLATE_OWNER: String = "thoryn-io"
        const val CONFIG_STACK: String = "config"
        const val PRODUCTION: String = "production"
        val APP_STACKS: List<String> = listOf("express", "spring-boot", "aspnet-core")
        private const val MAX_REVIEWERS = 6

        private val REPO = Regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/(?!\\.\\.?$)[A-Za-z0-9._-]{1,100}$")
        private val LOGIN = Regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
        private val SLUG = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

        /** Test seam: how `gh` is run. Production spawns the real `gh`. */
        @Volatile
        internal var ghRunner: () -> GhRunner = { ProcessGhRunner() }

        internal fun resetForTest() {
            ghRunner = { ProcessGhRunner() }
        }

        // ── Rendering ────────────────────────────────────────────────────────────────────────────

        private fun render(format: OutputFormat, init: ProjectInit, report: Map<String, Any?>) {
            when (format) {
                OutputFormat.JSON -> Printers.json(report, System.out)
                OutputFormat.YAML -> Printers.yaml(report, System.out)
                OutputFormat.TABLE -> {
                    val out = System.out
                    @Suppress("UNCHECKED_CAST")
                    val repository = (report["repository"] as? Map<String, Any?>)?.get("fullName")
                    out.println("${if (init.steps.any { it.status in CHANGED }) "Set up" else "Checked"} the ${report["kind"]} project $repository for workspace ${report["workspace"]}.")
                    out.println()
                    printSteps(init.steps, out)
                    out.println()
                    out.println("Next steps:")
                    @Suppress("UNCHECKED_CAST")
                    (report["nextSteps"] as List<String>).forEachIndexed { i, s -> out.println("  ${i + 1}. $s") }
                }
            }
        }

        private val CHANGED = setOf("created", "set", "granted", "written")

        private fun printSteps(steps: List<ProjectInit.Step>, out: PrintStream) {
            val nameWidth = steps.maxOfOrNull { it.name.length } ?: 0
            val statusWidth = steps.maxOfOrNull { it.status.length } ?: 0
            steps.forEach { out.println("  ${it.name.padEnd(nameWidth)}  ${it.status.padEnd(statusWidth)}  ${it.detail}") }
        }

        private fun printProgress(init: ProjectInit?, err: PrintStream) {
            if (init == null || init.steps.isEmpty()) return
            err.println()
            err.println("Done before this stop (kept; each step is safe to repeat):")
            printSteps(init.steps, err)
            err.println("Re-run the same command to continue where it stopped.")
        }

        private fun structured(code: String, description: String?, hint: String?, init: ProjectInit?, extra: Map<String, Any?>): Map<String, Any?> =
            linkedMapOf<String, Any?>(
                "error" to code,
                "errorDescription" to description,
                "hint" to hint,
                "changed" to (init?.steps?.isNotEmpty() ?: false),
                "completedSteps" to init?.steps.orEmpty().map { linkedMapOf("step" to it.name, "status" to it.status, "detail" to it.detail) },
            ).apply { putAll(extra) }

        internal fun renderStop(format: OutputFormat, stop: ProjectInit.Stop, init: ProjectInit?): Int {
            when (format) {
                OutputFormat.JSON -> Printers.json(structured(stop.code, stop.description, stop.hint, init, stop.extra), System.out)
                OutputFormat.YAML -> Printers.yaml(structured(stop.code, stop.description, stop.hint, init, stop.extra), System.out)
                OutputFormat.TABLE -> {
                    val err = System.err
                    err.println("Error: ${stop.description}")
                    stop.hint?.let { err.println(it) }
                    @Suppress("UNCHECKED_CAST")
                    (stop.extra["manualSteps"] as? List<String>)?.let { steps ->
                        err.println()
                        err.println("Or do it by hand — these are the steps it takes, with your values filled in:")
                        steps.forEach { err.println("  $it") }
                    }
                    printProgress(init, err)
                }
            }
            return stop.exit
        }

        private fun renderGhFailure(format: OutputFormat, ex: GhCommandException, init: ProjectInit): Int {
            val reason = ex.result.reason()
            when (format) {
                OutputFormat.JSON, OutputFormat.YAML -> {
                    val body = structured("gh_failed", reason, ex.hint, init, mapOf("step" to ex.step))
                    if (format == OutputFormat.JSON) Printers.json(body, System.out) else Printers.yaml(body, System.out)
                }
                OutputFormat.TABLE -> {
                    System.err.println("Error: the ${ex.step} step failed — gh: $reason")
                    ex.hint?.let { System.err.println(it) }
                    printProgress(init, System.err)
                }
            }
            return ProjectInit.EXIT_GH
        }

        private fun renderApiFailure(format: OutputFormat, ex: ProductApiException, init: ProjectInit): Int {
            val scope = when (init.currentStep) {
                ProjectInit.STEP_ENVIRONMENTS -> "tenant:environments.write"
                ProjectInit.STEP_TRUSTS -> WorkloadIdentityCommand.SCOPE_WRITE
                ProjectInit.STEP_ACCESS -> "tenant:access.write"
                else -> null
            }
            val exit = if (init.currentStep == ProjectInit.STEP_TRUSTS) {
                WorkloadIdentityCommand.renderTrustError(format, ex, scope!!)
            } else {
                CommandSupport.renderError(format, ex, requiredScope = scope)
            }
            if (format == OutputFormat.TABLE) {
                System.err.println("(during the ${init.currentStep} step)")
                printProgress(init, System.err)
            }
            return exit
        }
    }
}
