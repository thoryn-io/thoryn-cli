package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ImportedResource
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionFileRef
import com.devnow.thoryn.provision.ProvisionPlan
import com.devnow.thoryn.provision.ProvisionReceipt
import com.devnow.thoryn.provision.ProvisionReceiptStore
import com.devnow.thoryn.cli.VersionProvider
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CustomDomainView
import com.devnow.thoryn.cli.cmd.DomainCommand
import com.devnow.thoryn.cli.cmd.DomainWaiter
import com.devnow.thoryn.cli.cmd.SecretIo
import com.devnow.thoryn.cli.cmd.SelectedWorkspaceStore
import com.devnow.thoryn.cli.cmd.examples.Prompt
import com.devnow.thoryn.cli.cmd.project.GhRunner
import com.devnow.thoryn.cli.cmd.project.ProcessGhRunner
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
 *  - `plan` / `apply` / `destroy` — SSO-3088 (epic SSO-3087): provisioning-as-code over the
 *    `.thoryn/provision.yaml` desired-state file (see [ProvisionEngine]). `plan` shows what `apply`
 *    would do; `apply` converges (a second run is a no-op; `--prune` removes what the file dropped);
 *    `destroy` removes everything the file's receipt owns, child-first. Production-plane removals are
 *    confirmation-gated with `--confirm <workspace-slug>`, like `env delete` / `clients delete`.
 *    SSO-3113: `apply --secret-file <path>` / `--force-stdout` deliver a confidential application's
 *    one-time client secret through [SecretIo] (exactly as `clients create`); an undeliverable secret
 *    still records the resource and exits [SecretIo.EXIT_NO_SECRET]. A resource's `grants:` block is
 *    converged with it (`thoryn access` is the imperative twin).
 *  - SSO-3659 (ADR 2026-10-13 §1/§2): ownership is decided by the signed-in identity's platform reach —
 *    `plan` and `apply` gate every declared resource (`manager` ⇒ converge; `viewer` ⇒ only a matching
 *    `readOnly: true` reference; none ⇒ `access_not_owned`); a failed gate is a red plan (exit
 *    [CommandSupport.EXIT_HTTP_ERROR]) and `apply` refuses before writing. SSO-3673: the gate asks the
 *    platform PER OBJECT (`POST /api/v1/access/check`), and "owned elsewhere" (`access_owned_elsewhere`) is
 *    the platform's `owner` relation on the resource — the former `--peer-receipt` flag (other repositories'
 *    receipts as the marker) is REMOVED; nothing else consumed it.
 *    `import [--write]` renders what the identity may reach as `provision.yaml` entries (`manager` ⇒ owned,
 *    recorded `adopted: true`; `viewer` ⇒ `readOnly: true`, as is an object another repository owns); without
 *    `--write` it only prints them.
 *  - SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2): an `application`'s
 *    `publishTo:` targets receive its clientId after `apply` converged it — through [GitHubActionsVariablePublisher]
 *    (`gh variable set … --env`, the customer's own `gh` login) on every apply. `plan` prints the pending publish
 *    as a line and writes nothing. An unreachable target is `publish_target_unreachable` AFTER the client exists
 *    and is in the receipt: exit [CommandSupport.EXIT_HTTP_ERROR], naming the `gh variable set` to run by hand.
 */
@Command(
    name = "provision",
    description = ["Provisioning-as-code: plan / apply / import / destroy a .thoryn/provision.yaml."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ProvisionCommand.PlanSubcommand::class,
        ProvisionCommand.ApplySubcommand::class,
        ProvisionCommand.ImportSubcommand::class,
        ProvisionCommand.DestroySubcommand::class,
    ],
)
class ProvisionCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn provision <subcommand>")
        System.err.println("Subcommands: plan, apply, import, destroy")
        return CommandSupport.EXIT_USAGE
    }

    // ── SSO-3088: plan / apply / destroy over .thoryn/provision.yaml ────────────────────────────

    /** Options every provisioning verb shares: the file, its receipt, the gateway, the output format. */
    internal open class FileOptions {
        @Option(names = ["--file", "-f"], description = ["Provisioning file (default: .thoryn/provision.yaml, .yml or .json)."])
        var file: File? = null

        @Option(names = ["--receipt"], description = ["Receipt path (default: next to the file as <name>.receipt.json)."])
        var receipt: File? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
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
        fun engine(
            gateway: String,
            tokens: com.devnow.thoryn.cli.auth.Tokens,
            secretSink: ProvisionEngine.SecretSink = ProvisionEngine.SecretSink.undeliverable(),
            format: OutputFormat = OutputFormat.TABLE,
            /** SSO-3668 — `apply` passes the `gh variable set` publisher; the read-only verbs reach nothing. */
            outputSink: ProvisionEngine.OutputSink = ProvisionEngine.OutputSink.unavailable(),
        ): ProvisionEngine = ProvisionEngine(
            clients = { slug -> CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false, environmentOverride = slug ?: "") },
            // SSO-3414 — with --output json|yaml stdout carries ONE document; the per-resource progress goes to stderr.
            out = if (format == OutputFormat.TABLE) System.out else System.err,
            cliVersion = runCatching { VersionProvider.readVersion() }.getOrNull(),
            secretSink = secretSink,
            // SSO-3413 — the workspace id (`tnt`) names the workspace-level custom domain's access object.
            workspaceId = runCatching { JwtClaims.of(tokens.accessToken)["tnt"]?.asString() }.getOrNull()?.takeIf { it.isNotBlank() },
            // SSO-3659 — who applied, on the receipt (display / audit; SSO-3673: the owner marker is the platform's).
            subject = subjectOf(tokens),
            outputSink = outputSink,
        )

        /** SSO-3668 — test seam: how `gh` is run for `publishTo:`. Production spawns the customer's real `gh`. */
        @Volatile
        internal var ghRunner: () -> GhRunner = { ProcessGhRunner() }

        internal fun resetForTest() {
            ghRunner = { ProcessGhRunner() }
        }

        /**
         * SSO-3659 — the signed-in identity's PLATFORM SUBJECT, derived from the access token exactly as
         * product-api's `PlatformSubjects.fromJwt` derives the caller (ADR 2026-09-15 §4): `client:<client_id>`
         * when the token has no `sub` or its `sub` IS the client (a `client_credentials` / workload-identity
         * machine identity — Spring AS names the principal after the client), else `member:<sub>`; `azp` is the
         * fallback spelling of `client_id`. Null for an opaque token — the engine then records no marker.
         */
        fun subjectOf(tokens: Tokens): String? {
            val claims = runCatching { JwtClaims.of(tokens.accessToken) }.getOrNull() ?: return null
            fun claim(name: String): String? = claims[name]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            val clientId = claim("client_id") ?: claim("azp") ?: tokens.clientId?.takeIf { tokens.authMode != null }
            val sub = claim("sub")
            return when {
                clientId != null && (sub == null || sub == clientId) -> "client:$clientId"
                sub != null -> "member:$sub"
                else -> null
            }
        }

        fun workspaceSlug(): String? = runCatching { SelectedWorkspaceStore().read()?.slug }.getOrNull()

        /** SSO-3659 — the red half of a plan: one line per resource that failed the ownership gate, on stderr. */
        fun printPlanErrors(plan: ProvisionPlan) {
            if (!plan.hasErrors) return
            System.err.println("${plan.errors.size} resource(s) failed the ownership check — apply would refuse this plan:")
            plan.errors.forEach { c -> System.err.println("  ! ${c.kind} ${c.name}: ${c.reason}") }
        }

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
            // SSO-3113 — grant changes per object (a no-op resource can still carry them).
            plan.changes.filter { it.hasGrantChanges }.forEach { c ->
                c.grantAdds.forEach { println("      ${c.kind} ${c.name}: grant + $it") }
                c.grantRemoves.forEach { println("      ${c.kind} ${c.name}: grant - $it") }
            }
            // SSO-3668 — where apply will publish the id (a line, never a write: plan reaches no target).
            plan.changes.filter { it.publishTo.isNotEmpty() }.forEach { c ->
                c.publishTo.forEach { t -> println("      ${c.kind} ${c.name}: publish clientId → ${t.label}") }
            }
            // SSO-3413 / SSO-3414 — a customDomain's state, the issuer in use and the DNS records to publish.
            plan.changes.forEach { c ->
                val d = c.customDomain ?: return@forEach
                println("      ${c.kind} ${c.name}: ${d["desiredHost"]} — state ${d["state"]}, entitled ${d["entitled"]}, issuer ${d["issuer"] ?: "(unknown)"}")
                @Suppress("UNCHECKED_CAST")
                val records = (d["records"] as? List<Map<String, Any?>>).orEmpty()
                if (records.isNotEmpty()) println("      DNS records to publish (machine-readable: --output json → changes[].customDomain.records):")
                records.forEach { r -> println("        ${r["type"]}  ${r["name"]}  ${r["value"]}  ttl=${r["ttl"]}") }
                if (d["state"] == CustomDomainView.NONE) println("        (the TXT ownership record is issued when apply claims the domain)")
            }
            println(
                "  ${plan.creates.size} to create, ${plan.updates.size} to update, ${plan.adopts.size} to adopt, " +
                    "${plan.removes.size} to remove, ${plan.changes.count { it.action == ChangeAction.NOOP }} unchanged" +
                    (if (plan.grantChanges > 0) ", ${plan.grantChanges} grant change(s)" else "") +
                    (if (plan.publishes > 0) ", ${plan.publishes} output(s) to publish" else "") +
                    (if (plan.hasErrors) ", ${plan.errors.size} ownership error(s)." else "."),
            )
        }

        /**
         * SSO-3659 — render a plan in the requested format and answer the exit code: a plan with an ownership
         * error is RED ([CommandSupport.EXIT_HTTP_ERROR]) whatever else it says, so a pull-request dry run fails
         * on a resource the repository does not own.
         */
        fun renderPlan(plan: ProvisionPlan, file: ProvisionFile, format: OutputFormat): Int {
            if (format == OutputFormat.TABLE) printPlan(plan, file) else CommandSupport.emitValue(format, plan.toStructured(), "")
            printPlanErrors(plan)
            return if (plan.hasErrors) CommandSupport.EXIT_HTTP_ERROR else CommandSupport.EXIT_OK
        }

        /**
         * SSO-3568 — a session this process has already reported as unrenewable takes precedence over
         * every other rendering. [com.devnow.thoryn.cli.cmd.provision.ProvisionEngine] wraps a refused
         * read into a `ProvisionException` naming the resource, which is right for a real API failure
         * and wrong here: it produced the reported
         * `Error: application/forge-oauth2-proxy: could not read live state (HTTP 401: invalid_token -
         * DPoP proof has already been used.)` AFTER the correct "sign in again" line, and that is the
         * line the reader keeps. Returning quietly leaves the sign-in instruction as the final word.
         */
        fun fail(ex: Exception, gateway: String, format: OutputFormat): Int {
            CommandSupport.unrenewableSessionGuidance()?.let { return CommandSupport.renderUnrenewableSession(format, it) }
            return when (ex) {
                is ProvisionException -> { System.err.println("Error: ${ex.message}"); CommandSupport.EXIT_HTTP_ERROR }
                is ProductApiException -> CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
                else -> CommandSupport.renderRequestFailure(ex, gateway)
            }
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
                val plan = engine(gateway, tokens, format = format).plan(s.file, s.receipt, prune)
                renderPlan(plan, s.file, format)
            } catch (ex: Exception) {
                fail(ex, gateway, format)
            }
        }
    }

    /**
     * `thoryn provision apply [--file] [--prune] [--confirm <ws>] [--yes] [--secret-file <path>] [--force-stdout]`
     * — converge the file. SSO-3113: a confidential `application` the apply CREATES is minted a one-time
     * client secret, delivered through [SecretIo] like `thoryn clients create` — written to
     * `--secret-file` (owner-only; a second one in the same apply lands at `<path>.<clientId>`), or
     * printed to an interactive TTY with a WARN; a non-interactive stdout is refused unless
     * `--force-stdout`. The secret never enters the receipt, the plan, or a log. When it cannot be
     * delivered the resource is still recorded and the command exits [SecretIo.EXIT_NO_SECRET],
     * naming `thoryn clients rotate-secret`.
     */
    @Command(name = "apply", description = ["Converge the account to the provisioning file (a second run is a no-op)."], mixinStandardHelpOptions = true)
    internal class ApplySubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--prune"], description = ["Remove owned resources the file no longer declares."])
        var prune: Boolean = false

        @Option(names = ["--confirm"], description = ["Workspace slug confirming production-plane removals (--prune)."])
        var confirm: String? = null

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        @Option(names = ["--secret-file"], description = ["Write a created confidential application's one-time client secret to this file (owner-only) instead of a TTY/pipe."])
        var secretFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing a minted client secret to a non-interactive stdout (pipe/redirect). Off by default."])
        var forceStdout: Boolean = false

        @Option(names = ["--wait"], description = ["SSO-3414 — after applying, block until the file's customDomain is --wait-until (default ACTIVE), verifying it each round; bounded by --wait-timeout."])
        var wait: Boolean = false

        @Option(names = ["--wait-until"], description = ["With --wait: ACTIVE (default) or VERIFIED."])
        var waitUntil: String = CustomDomainView.ACTIVE

        @Option(names = ["--wait-timeout"], description = ["With --wait: give up after this long, e.g. 15m (default 15m)."])
        var waitTimeout: String? = null

        @Option(names = ["--wait-interval"], description = ["With --wait: time between checks, e.g. 20s (default 20s)."])
        var waitInterval: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val s = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            waitUsageError(s.file)?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val engine = try {
                engine(
                    gateway, tokens, CliSecretSink.toSecretIo(secretFile, forceStdout), format,
                    // SSO-3668 — the only verb that publishes; the publisher touches gh only when a target is reached for.
                    outputSink = GitHubActionsVariablePublisher(ghRunner()),
                )
            } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val plan = try {
                engine.plan(s.file, s.receipt, prune)
            } catch (ex: Exception) {
                return fail(ex, gateway, format)
            }
            if (format == OutputFormat.TABLE) printPlan(plan, s.file)
            // SSO-3659 — a plan with an ownership error is refused WHOLE, before anything is written or asked.
            if (plan.hasErrors) {
                if (format != OutputFormat.TABLE) CommandSupport.emitValue(format, plan.toStructured(), "")
                printPlanErrors(plan)
                System.err.println("Nothing was changed.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            if (!plan.hasChanges) {
                if (wait) return awaitDomain(gateway, tokens, format, plan.toStructured())
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
                } else if (!wait) {
                    CommandSupport.emitValue(format, result, "")
                }
                // SSO-3113 — the resources exist and are owned, but a minted client secret was not surfaced.
                val lost = engine.undeliveredSecrets
                if (lost.isNotEmpty()) {
                    System.err.println(
                        "The client secret of ${lost.size} created application(s) could not be delivered (${lost.joinToString(", ")}). " +
                            "Re-run with --secret-file <path> (or --force-stdout) next time; for these, mint a new secret now with " +
                            lost.joinToString("; ") { "`thoryn clients rotate-secret $it --secret-file <path>`" } + ".",
                    )
                    return SecretIo.EXIT_NO_SECRET
                }
                if (wait) awaitDomain(gateway, tokens, format, result) else CommandSupport.EXIT_OK
            } catch (ex: ProvisionEngine.PublishTargetUnreachableException) {
                // SSO-3668 — NOT a stopped apply: every resource was converged and is in the receipt; only the publish
                // of an id did not land. The receipt is the source of the id for the by-hand command the error names.
                if (format == OutputFormat.TABLE) {
                    println("Applied. ${ex.receipt.resources.size} resource(s) owned. Receipt: ${s.receiptPath.path}")
                } else {
                    CommandSupport.emitValue(format, ex.receipt, "")
                }
                System.err.println("Error: ${ex.message}")
                CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: Exception) {
                System.err.println("Apply stopped; the receipt at ${s.receiptPath.path} records what succeeded — fix the cause and re-run.")
                fail(ex, gateway, format)
            }
        }

        /** `--wait*` validation: the flags go together, and there must be a customDomain to wait for. */
        private fun waitUsageError(file: ProvisionFile): String? {
            if (!wait) {
                return if (waitTimeout != null || waitInterval != null || waitUntil != CustomDomainView.ACTIVE) {
                    "--wait-until, --wait-timeout and --wait-interval apply to --wait only."
                } else {
                    null
                }
            }
            if (file.resources.none { it.kind == ProvisionFile.KIND_CUSTOM_DOMAIN }) {
                return "--wait waits for the file's customDomain, and ${file.source} declares none."
            }
            waitUntil = waitUntil.trim().uppercase()
            if (waitUntil !in DomainWaiter.TARGETS) return "--wait-until must be ACTIVE or VERIFIED (was '$waitUntil')."
            if (waitTimeout != null && DomainWaiter.parseDuration(waitTimeout) == null) return "--wait-timeout must be a positive duration such as 15m (was '$waitTimeout')."
            if (waitInterval != null && DomainWaiter.parseDuration(waitInterval) == null) return "--wait-interval must be a positive duration such as 20s (was '$waitInterval')."
            return null
        }

        /**
         * SSO-3414 — block until the workspace's custom domain reaches [waitUntil], verifying it every round.
         * With `--output json|yaml` the ONE document printed is `{ "apply": <receipt or plan>, "customDomain": <status> }`.
         */
        private fun awaitDomain(gateway: String, tokens: Tokens, format: OutputFormat, applied: Any?): Int {
            val timeout = DomainWaiter.parseDuration(waitTimeout) ?: DomainWaiter.DEFAULT_TIMEOUT
            val outcome = DomainWaiter(
                client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false, environmentOverride = ""),
                until = waitUntil,
                timeout = timeout,
                interval = DomainWaiter.parseDuration(waitInterval) ?: DomainWaiter.DEFAULT_INTERVAL,
                drive = true,
                clock = DomainCommand.waitClock,
                sleeper = DomainCommand.waitSleeper,
            ).await()
            if (format != OutputFormat.TABLE) {
                CommandSupport.emitValue(
                    format,
                    mapOf("apply" to applied, "customDomain" to outcome.body?.let { CustomDomainView.normalized(it) }),
                    "",
                )
                return DomainCommand.renderWaitOutcome(outcome, format, waitUntil, timeout, emitBody = false)
            }
            return DomainCommand.renderWaitOutcome(outcome, format, waitUntil, timeout)
        }
    }

    /**
     * `thoryn provision import [--file] [--write]` — SSO-3659 (ADR 2026-10-13 §2): the inverse of `plan`,
     * bounded by the same relations. Lists what the signed-in identity may reach (`GET /api/v1/access/mine`,
     * `manager` then `viewer`) and renders each live resource the file does not yet declare as a `provision.yaml`
     * entry — `manager` objects as OWNED (recorded `adopted: true` in the receipt, never deleted by destroy),
     * `viewer` objects (and, SSO-3673, objects the platform says another repository OWNS) as `readOnly: true`.
     * Nothing the identity has no relation to is listed, so nothing it has no relation to can be imported — the
     * hub's rows stay the authority; `import` only writes the file and the receipt. Without `--write` it prints
     * the entries it would add (stdout; notes and skipped objects on stderr) and changes nothing.
     */
    @Command(name = "import", description = ["Render the live resources this identity may reach as provisioning-file entries; --write appends them and records the owned ones in the receipt."], mixinStandardHelpOptions = true)
    internal class ImportSubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--write"], description = ["Append the entries to the provisioning file (created when absent) and record the owned ones in its receipt. Default: print only."])
        var write: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val target = file ?: ProvisionFile.resolveDefault() ?: File(ProvisionFile.DEFAULT_DIR, ProvisionFile.DEFAULT_FILES.first())
            val existing = try {
                if (target.isFile) ProvisionFile.load(target) else null
            } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            if (write && target.name.endsWith(".json", ignoreCase = true)) {
                System.err.println("Error: --write appends YAML; ${target.path} is a JSON file — run without --write and add the entries by hand.")
                return CommandSupport.EXIT_USAGE
            }
            val store = ProvisionReceiptStore()
            val receiptPath = receipt ?: store.defaultPathFor(target)
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            return try {
                val current = store.read(receiptPath)
                val engine = engine(gateway, tokens, format = format)
                val result = engine.import(existing, current)
                val yaml = renderEntries(result.resources)
                if (format == OutputFormat.TABLE) {
                    if (result.resources.isEmpty()) println("Nothing to import — every resource this identity may reach is already declared in ${target.path}.") else print(yaml)
                } else {
                    CommandSupport.emitValue(
                        format,
                        mapOf("file" to target.path, "written" to (write && result.resources.isNotEmpty()), "resources" to result.resources.map { it.toStructured() }, "skipped" to result.skipped),
                        "",
                    )
                }
                result.resources.filter { it.note != null }.forEach { System.err.println("  note ${it.resource.kind} ${it.resource.name}: ${it.note}") }
                result.skipped.forEach { System.err.println("  skipped $it") }
                if (!write || result.resources.isEmpty()) {
                    if (!write && result.resources.isNotEmpty()) System.err.println("Printed ${result.resources.size} entry(ies) — nothing was written; re-run with --write to append them to ${target.path}.")
                    return CommandSupport.EXIT_OK
                }
                appendEntries(target, yaml, existing)
                val owned = result.resources.mapNotNull { it.owned }
                val reloaded = ProvisionFile.load(target)
                store.write(
                    receiptPath,
                    ProvisionReceipt(
                        file = ProvisionFileRef(reloaded.source, reloaded.digest),
                        appliedAt = java.time.Instant.now().toString(),
                        cliVersion = runCatching { VersionProvider.readVersion() }.getOrNull(),
                        workspace = workspaceSlug() ?: current?.workspace,
                        subject = subjectOf(tokens) ?: current?.subject,
                        resources = current?.resources.orEmpty().filter { o -> owned.none { it.key == o.key } } + owned,
                    ),
                )
                if (format == OutputFormat.TABLE) {
                    println("Imported ${result.resources.size} entry(ies) into ${target.path}: ${owned.size} owned (adopted — never deleted by destroy), ${result.resources.size - owned.size} read-only. Receipt: ${receiptPath.path}")
                }
                CommandSupport.EXIT_OK
            } catch (ex: Exception) {
                fail(ex, gateway, format)
            }
        }

        /** The entries as a `resources:` list fragment, indented for the file (two spaces, as the schema examples are written). */
        private fun renderEntries(entries: List<ImportedResource>): String {
            if (entries.isEmpty()) return ""
            val node = tools.jackson.databind.json.JsonMapper.builder().build().valueToTree<tools.jackson.databind.JsonNode>(entries.map { it.toEntry() })
            return ProvisionYamlEdit.fragment(node)
        }

        /**
         * Append under the file's `resources:` list — only when that list is the LAST top-level key (otherwise the
         * appended entries would not belong to it); a fresh file is created with the header. The result is re-loaded
         * through [ProvisionFile] and the original bytes restored when it does not validate, so `--write` can never
         * leave an invalid file behind.
         */
        private fun appendEntries(target: File, fragment: String, existing: ProvisionFile?) {
            if (existing == null) {
                target.absoluteFile.parentFile?.mkdirs()
                target.writeText(ProvisionYamlEdit.fresh(fragment))
            } else {
                val original = target.readBytes()
                // The shared edit rule (ProvisionYamlEdit): append under `resources:` only when it is the last top-level key.
                target.writeText(ProvisionYamlEdit.append(original.toString(Charsets.UTF_8), fragment, target.path))
                try {
                    ProvisionFile.load(target)
                } catch (ex: ProvisionException) {
                    target.writeBytes(original)
                    throw ProvisionException("the appended entries did not validate (${ex.message}); ${target.path} was left unchanged")
                }
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

}
