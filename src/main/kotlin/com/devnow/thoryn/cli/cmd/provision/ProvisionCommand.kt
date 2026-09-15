package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.VersionProvider
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.SecretIo
import com.devnow.thoryn.cli.cmd.SelectedWorkspaceStore
import com.devnow.thoryn.cli.cmd.examples.Prompt
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
 *  - `plan` / `apply` / `destroy` — SSO-3088 (epic SSO-3087): provisioning-as-code over the
 *    `.thoryn/provision.yaml` desired-state file (see [ProvisionEngine]). `plan` shows what `apply`
 *    would do; `apply` converges (a second run is a no-op; `--prune` removes what the file dropped);
 *    `destroy` removes everything the file's receipt owns, child-first. Production-plane removals are
 *    confirmation-gated with `--confirm <workspace-slug>`, like `env delete` / `clients delete`.
 */
@Command(
    name = "provision",
    description = ["Provisioning-as-code: plan / apply / destroy a .thoryn/provision.yaml; bootstrap the CI machine identity."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ProvisionCommand.CiIdentitySubcommand::class,
        ProvisionCommand.PlanSubcommand::class,
        ProvisionCommand.ApplySubcommand::class,
        ProvisionCommand.DestroySubcommand::class,
    ],
)
class ProvisionCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn provision <subcommand>")
        System.err.println("Subcommands: plan, apply, destroy, ci-identity")
        return CommandSupport.EXIT_USAGE
    }

    // ── SSO-3088: plan / apply / destroy over .thoryn/provision.yaml ────────────────────────────

    /** Options every provisioning verb shares: the file, its receipt, the gateway, the output format. */
    internal open class FileOptions {
        @Option(names = ["--file", "-f"], description = ["Provisioning file (default: .thoryn/provision.yaml, .yml or .json)."])
        var file: File? = null

        @Option(names = ["--receipt"], description = ["Receipt path (default: next to the file as <name>.receipt.json)."])
        var receipt: File? = null

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        /** Resolve + load the file (or fail with a usage error) and locate its receipt. */
        fun open(): Session? {
            val target = file ?: ProvisionFile.resolveDefault() ?: run {
                System.err.println("No provisioning file found — expected ${ProvisionFile.DEFAULT_DIR}/${ProvisionFile.DEFAULT_FILES.first()} (or pass --file).")
                return null
            }
            val parsed = ProvisionFile.load(target)
            val store = ProvisionReceiptStore()
            val receiptPath = receipt ?: store.defaultPathFor(target)
            return Session(parsed, store, receiptPath, store.read(receiptPath))
        }

        /** Locate the receipt only (destroy does not need a valid file, just its receipt). */
        fun openReceipt(): Pair<File, ProvisionReceipt?>? {
            val store = ProvisionReceiptStore()
            val path = receipt ?: (file ?: ProvisionFile.resolveDefault())?.let { store.defaultPathFor(it) } ?: run {
                System.err.println("No provisioning file or receipt found — pass --file or --receipt.")
                return null
            }
            return path to store.read(path)
        }
    }

    internal class Session(
        val file: ProvisionFile,
        val store: ProvisionReceiptStore,
        val receiptPath: File,
        val receipt: ProvisionReceipt?,
    )

    internal companion object {
        /** An engine whose clients target the file's per-resource environment on the caller's session. */
        fun engine(gateway: String, tokens: com.devnow.thoryn.cli.auth.Tokens): ProvisionEngine = ProvisionEngine(
            clients = { slug -> CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false, environmentOverride = slug ?: "") },
            cliVersion = runCatching { VersionProvider.readVersion() }.getOrNull(),
        )

        fun workspaceSlug(): String? = runCatching { SelectedWorkspaceStore().read()?.slug }.getOrNull()

        fun printPlan(plan: ProvisionPlan, file: ProvisionFile) {
            println("Plan — ${file.source} (${file.digest.take(19)}…)")
            val w1 = (plan.changes.map { it.kind.length } + 4).max()
            val w2 = (plan.changes.map { it.name.length } + 4).max()
            println("  ${"KIND".padEnd(w1)}  ${"NAME".padEnd(w2)}  ACTION  REASON")
            plan.changes.forEach { c ->
                println("  ${c.kind.padEnd(w1)}  ${c.name.padEnd(w2)}  ${c.action.name.lowercase().padEnd(6)}  ${c.reason}")
            }
            plan.changes.filter { it.diff.isNotEmpty() }.forEach { c ->
                c.diff.forEach { (field, change) -> println("      ${c.kind} ${c.name}: $field: $change") }
            }
            println(
                "  ${plan.creates.size} to create, ${plan.updates.size} to update, ${plan.adopts.size} to adopt, " +
                    "${plan.removes.size} to remove, ${plan.changes.count { it.action == ChangeAction.NOOP }} unchanged.",
            )
        }

        fun fail(ex: Exception, gateway: String, format: OutputFormat): Int = when (ex) {
            is ProvisionException -> { System.err.println("Error: ${ex.message}"); CommandSupport.EXIT_HTTP_ERROR }
            is ProductApiException -> CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
            else -> CommandSupport.renderRequestFailure(ex, gateway)
        }
    }

    /**
     * `thoryn provision plan [--file] [--prune]` — read-only: what `apply` would do. SSO-3089 — reads the
     * LIVE state of every declared resource by its converge key (so it needs a session), and reports
     * create / update (with the changed fields) / adopt / no-op / remove.
     */
    @Command(name = "plan", description = ["Show what `apply` would create / update / adopt / remove for the provisioning file (read-only)."], mixinStandardHelpOptions = true)
    internal class PlanSubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--prune"], description = ["Also plan removal of owned resources the file no longer declares."])
        var prune: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            return try {
                val plan = engine(gateway, tokens).plan(s.file, s.receipt, prune)
                if (format == OutputFormat.TABLE) printPlan(plan, s.file) else CommandSupport.emitValue(format, plan.toStructured(), "")
                CommandSupport.EXIT_OK
            } catch (ex: Exception) {
                fail(ex, gateway, format)
            }
        }
    }

    /** `thoryn provision apply [--file] [--prune] [--confirm <ws>] [--yes]` — converge the file. */
    @Command(name = "apply", description = ["Converge the account to the provisioning file (a second run is a no-op)."], mixinStandardHelpOptions = true)
    internal class ApplySubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--prune"], description = ["Remove owned resources the file no longer declares."])
        var prune: Boolean = false

        @Option(names = ["--confirm"], description = ["Workspace slug confirming production-plane removals (--prune)."])
        var confirm: String? = null

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val engine = engine(gateway, tokens)
            val plan = engine.plan(s.file, s.receipt, prune)
            if (format == OutputFormat.TABLE) printPlan(plan, s.file)
            if (!plan.hasChanges) {
                if (format == OutputFormat.TABLE) println("No changes.") else CommandSupport.emitValue(format, plan.toStructured(), "")
                return CommandSupport.EXIT_OK
            }
            if (plan.removesOnProductionPlane && confirm.isNullOrBlank()) {
                System.err.println("--prune would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            if (!yes && !Prompt.confirm("Apply these changes now?")) {
                println("Aborted — nothing was changed.")
                return CommandSupport.EXIT_OK
            }
            return try {
                val result = engine.apply(s.file, s.receipt, plan, workspaceSlug(), confirm) { s.store.write(s.receiptPath, it) }
                if (format == OutputFormat.TABLE) {
                    println("Applied. ${result.resources.size} resource(s) owned. Receipt: ${s.receiptPath.path}")
                } else {
                    CommandSupport.emitValue(format, result, "")
                }
                CommandSupport.EXIT_OK
            } catch (ex: Exception) {
                System.err.println("Apply stopped; the receipt at ${s.receiptPath.path} records what succeeded — fix the cause and re-run.")
                fail(ex, gateway, format)
            }
        }
    }

    /** `thoryn provision destroy [--file|--receipt] [--confirm <ws>] [--yes]` — remove everything owned. */
    @Command(name = "destroy", description = ["Remove every resource the provisioning file's receipt owns (child-first)."], mixinStandardHelpOptions = true)
    internal class DestroySubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--confirm"], description = ["Workspace slug confirming production-plane removals."])
        var confirm: String? = null

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val (receiptPath, receipt) = try { openReceipt() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            if (receipt == null || receipt.resources.isEmpty()) {
                println("Nothing to destroy — no receipt at ${receiptPath.path} (or it owns no resources).")
                return CommandSupport.EXIT_OK
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val engine = engine(gateway, tokens)
            val production = receipt.resources.any { ProvisionEngine.removable(it) && ProvisionEngine.onProductionPlane(it) }
            if (production && confirm.isNullOrBlank()) {
                System.err.println("destroy would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            println("Destroy — ${receipt.resources.size} owned resource(s) from ${receipt.file.path}:")
            receipt.resources.forEach { println("  ${it.kind} ${it.name} (id ${it.id}${it.environment?.let { e -> ", env $e" } ?: ""})") }
            if (!yes && !Prompt.confirm("Remove these resources now? This is irreversible.")) {
                println("Aborted — nothing was removed.")
                return CommandSupport.EXIT_OK
            }
            return try {
                val store = ProvisionReceiptStore()
                val outcome = engine.destroy(receipt, confirm) { store.write(receiptPath, it) }
                if (outcome.remaining.resources.isEmpty()) store.delete(receiptPath)
                if (outcome.failures.isEmpty()) {
                    if (format == OutputFormat.TABLE) println("Destroyed. Nothing is owned any more.") else CommandSupport.emitValue(format, mapOf("destroyed" to true), "")
                    CommandSupport.EXIT_OK
                } else {
                    System.err.println("${outcome.failures.size} resource(s) could not be removed and stay in the receipt: re-run to retry.")
                    CommandSupport.EXIT_HTTP_ERROR
                }
            } catch (ex: Exception) {
                fail(ex, gateway, format)
            }
        }
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
