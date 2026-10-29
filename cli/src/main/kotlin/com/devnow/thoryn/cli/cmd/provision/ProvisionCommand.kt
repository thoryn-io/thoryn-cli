package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ImportOptions
import com.devnow.thoryn.provision.ImportedResource
import com.devnow.thoryn.provision.MissingScopeException
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import com.devnow.thoryn.provision.ProvisionPlan
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.TokenStoreFactory
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
 *    would do; `apply` converges (a second run is a no-op; `--prune` removes what this identity OWNS and
 *    the file no longer declares, and revokes undeclared grants on the objects it may delete);
 *    `destroy` removes what the file declares and this identity may remove, child-first. Production-plane
 *    removals are confirmation-gated with `--confirm <workspace-slug>`, like `env delete` / `clients delete`.
 *    **SSO-3715 (ADR 2026-10-15 platform-is-the-ledger): there is NO receipt.** Every verb reads live state
 *    only; `apply --output json` / `plan --output json` carry the resolved ids (`resources[]`:
 *    `{kind, name, id, environment, action}`) a workflow used to read from the receipt. What `destroy` /
 *    `--prune` may remove is the platform's `owner` relation: a `client:` identity removes only what it owns
 *    (manager alone never suffices for automation), a person removes what they manage and nobody owns,
 *    non-ownable kinds go with their sandbox and never on the production plane; `retain: true` keeps a
 *    resource regardless. Every refusal is a `skip` row with the reason and the command a human runs.
 *    SSO-3113: `apply --secret-file <path>` / `--force-stdout` are the fallback channel ([SecretIo], exactly as
 *    `clients create`) for a declared `kubernetesSecret` / `file` sink that cannot be reached; an undeliverable secret
 *    still leaves the resource in place and exits [SecretIo.EXIT_NO_SECRET]. A resource's `grants:` block is
 *    converged with it (`thoryn access` is the imperative twin).
 *  - SSO-3659 (ADR 2026-10-13 §1/§2): ownership is decided by the signed-in identity's platform reach —
 *    `plan` and `apply` gate every declared resource (`manager` ⇒ converge; `viewer` ⇒ only a matching
 *    `readOnly: true` reference; none ⇒ `access_not_owned`); a failed gate is a red plan (exit
 *    [CommandSupport.EXIT_HTTP_ERROR]) and `apply` refuses before writing. SSO-3673: the gate asks the
 *    platform PER OBJECT (`POST /api/v1/access/check`), and "owned elsewhere" (`access_owned_elsewhere`) is
 *    the platform's `owner` relation on the resource — the former `--peer-receipt` flag (other repositories'
 *    receipts as the marker) is REMOVED; nothing else consumed it.
 *    `import [--write]` renders what the identity may reach as `provision.yaml` entries (`manager` ⇒ an entry
 *    the file converges; `viewer` ⇒ `readOnly: true`, as is an object another repository owns); without
 *    `--write` it only prints them. SSO-3715 — `import` writes the file only. SSO-3990 — part- and scope-aware, and with
 *    `--for-workflow <file>` bounded by that configured file's connection and routed by plane (see [ImportSubcommand]).
 *  - SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2): an `application`'s
 *    `publishTo:` targets receive its clientId after `apply` converged it — through [GitHubActionsVariablePublisher]
 *    (`gh variable set … --env`, the customer's own `gh` login) on every apply. `plan` prints the pending publish
 *    as a line and writes nothing. An unreachable target is `publish_target_unreachable` AFTER the client exists:
 *    exit [CommandSupport.EXIT_HTTP_ERROR], naming the `gh variable set` to run by hand.
 *  - **SSO-3659 (ADR 2026-10-13 converge §5)** — a confidential application's `secretSink:` receives its minted
 *    secret through [CliDeclaredSecretSink] right after `apply` converged the client: `kubernetesSecret`
 *    via the operator's own `kubectl` (value on stdin, never argv; the namespace is never created), `file` via the
 *    owner-only writer (no overwrite unless `--force`). A sink that cannot be reached falls back to `--secret-file` /
 *    the TTY; when nothing reaches, the client stays and `apply` exits [SecretIo.EXIT_NO_SECRET] with
 *    `undelivered_secrets`, naming the resource and `thoryn clients rotate-secret <clientId> --secret-file <path>`.
 *    `plan` prints the intended delivery as a line and mints nothing.
 *  - **SSO-3921 (oauthy ADR 2026-10-14 credential ladder, rung 3)** — `secretSink: { kind: workloadPull, trust }`:
 *    nothing is delivered. `apply` discards the minted value and converges `manager` on the application for the named
 *    `kubernetes` trust's workload client; the pod's init container mints its own secret at start. No channel is
 *    needed, so a CI apply with no kubeconfig creates the application and exits 0. `plan` prints who pulls it.
 *    **DEPRECATED** since SSO-3951 (removed by SSO-3953): still converged, with a warning on every plan and apply.
 *  - **SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951 — Thoryn owns the secret lifecycle, the customer owns
 *    delivery)** — `secretSink: { kind: customerManaged }`, THE DEFAULT for a confidential application without a sink:
 *    `apply` discards the create's one-time value (never shown, written or handed anywhere), grants nothing, and exits 0
 *    with no channel at all; `plan` prints the runbook — a person mints the secret with `thoryn clients rotate-secret
 *    <clientId> --secret-file <path>` and stores it in the customer's secret manager or an operator-created Secret.
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
        // SSO-3962 — `thoryn provision split`: a mixed thoryn.io/provision/v1 file into its tenant and application files.
        ProvisionCommand.SplitSubcommand::class,
        // SSO-3719 — `thoryn provision workflow check`: the stub + .thoryn/workflow.yaml against the workflow contract.
        com.devnow.thoryn.cli.cmd.provision.workflow.ProvisionWorkflowCommand::class,
    ],
)
class ProvisionCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn provision <subcommand>")
        System.err.println("Subcommands: plan, apply, import, destroy, split, workflow")
        return CommandSupport.EXIT_USAGE
    }

    // ── SSO-3088: plan / apply / destroy over .thoryn/provision.yaml ────────────────────────────

    /** Options every provisioning verb shares: the file, the gateway, the output format. */
    internal open class FileOptions {
        @Option(names = ["--file", "-f"], description = ["Provisioning file (default: .thoryn/provision.yaml, .yml or .json)."])
        var file: File? = null

        @Option(names = ["--gateway"], description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        /**
         * SSO-3710 — where a RED plan writes its fix request (`thoryn-provision-request.json`): every `access_*` row that
         * is a missing right, with the exact command a workspace admin runs; file-fix rows as notes. Opt-in; the env var
         * `THORYN_FIX_REQUEST` is the same switch. Exit codes are unchanged — the request describes the failure, it is not one.
         */
        @Option(
            names = ["--fix-request"],
            description = ["SSO-3710 — write the fix request (missing rights + the exact `thoryn access grant` commands, schema fix-request.schema.json) to this file when the plan has an ownership error; a workflow uploads it as the `thoryn-provision-request` artifact. Env: THORYN_FIX_REQUEST."],
        )
        var fixRequest: File? = null

        /** SSO-3710 — the fix-request file to write, from the flag or `THORYN_FIX_REQUEST`; null ⇒ none. */
        fun fixRequestTarget(): java.nio.file.Path? = FixRequests.target(fixRequest)

        /** Resolve + load the file (or fail with a usage error). SSO-3715 — the file is the only input; nothing sits beside it. */
        fun open(): ProvisionFile? {
            val target = file ?: ProvisionFile.resolveDefault() ?: run {
                System.err.println("No provisioning file found — expected ${ProvisionFile.DEFAULT_DIR}/${ProvisionFile.DEFAULT_FILES.first()} (or pass --file).")
                return null
            }
            return ProvisionFile.load(target).also { printWarnings(it) }
        }
    }

    internal companion object {
        /**
         * SSO-3962 — what the file carries that is accepted today and refused in a later release ([ProvisionFile.warnings]: the
         * mixed `thoryn.io/provision/v1` format, `publishTo:`), one `Warning:` line each on stderr before the work — never on
         * stdout, which `--output json|yaml` reserves for the one document.
         */
        fun printWarnings(file: ProvisionFile) {
            file.warnings.forEach { System.err.println("Warning: ${file.source}: $it") }
        }

        /** An engine whose clients target the file's per-resource environment on the caller's session. */
        fun engine(
            gateway: String,
            tokens: com.devnow.thoryn.cli.auth.Tokens,
            secretSink: ProvisionEngine.SecretSink = ProvisionEngine.SecretSink.undeliverable(),
            format: OutputFormat = OutputFormat.TABLE,
            /** SSO-3668 — `apply` passes the `gh variable set` publisher; the read-only verbs reach nothing. */
            outputSink: ProvisionEngine.OutputSink = ProvisionEngine.OutputSink.unavailable(),
            /** SSO-3659 — `apply` passes the kubectl / file delivery; the read-only verbs reach nothing. */
            declaredSecretSink: ProvisionEngine.DeclaredSecretSink = ProvisionEngine.DeclaredSecretSink.unavailable(),
        ): ProvisionEngine = ProvisionEngine(
            clients = { slug -> CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false, environmentOverride = slug ?: "") },
            // SSO-3414 — with --output json|yaml stdout carries ONE document; the per-resource progress goes to stderr.
            out = if (format == OutputFormat.TABLE) System.out else System.err,
            secretSink = secretSink,
            // SSO-3413 — the workspace id (`tnt`) names the workspace-level custom domain's access object.
            workspaceId = runCatching { JwtClaims.of(tokens.accessToken)["tnt"]?.asString() }.getOrNull()?.takeIf { it.isNotBlank() },
            // SSO-3659 / SSO-3715 — the caller's subject: the SHAPE of the deletion authority (owner for a client:, unowned-manager for a member:).
            subject = subjectOf(tokens),
            outputSink = outputSink,
            declaredSecretSink = declaredSecretSink,
            // SSO-3689 — the session's scopes: a workloadIdentityTrust may carry only scopes this identity holds (the hub's
            // ceiling); known here, the plan refuses an overreaching trust up front with the hub's own code.
            callerScopes = callerScopesOf(tokens),
        )

        /**
         * SSO-3689 — the scopes the session's token carries: the JWT `scope` claim (space-separated, as the hub mints
         * it), else what the token response said. Null for an opaque token without a recorded scope — the engine then
         * states the ceiling and leaves the refusal to the hub.
         */
        fun callerScopesOf(tokens: Tokens): Set<String>? {
            val claim = runCatching { JwtClaims.of(tokens.accessToken)["scope"]?.takeIf { !it.isNull }?.asString() }.getOrNull()
            return (claim ?: tokens.scope)?.split(' ')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()?.takeIf { it.isNotEmpty() }
        }

        /** SSO-3926 — the stored session, as far as naming a profile goes (an unreadable store names none). */
        private fun storedSession(): TrustScopes.Session =
            runCatching { TokenStoreFactory.default().read() }.getOrNull()?.let { TrustScopes.Session.of(it) } ?: TrustScopes.Session(null, null, null, null)

        /**
         * SSO-3926 — `config.trust-scopes` before the work: the scopes [file] needs to plan (or, with [plan], the writes that
         * plan makes) against the session's token. Prints the message and answers true when one is missing.
         */
        fun scopesMissing(file: ProvisionFile, prune: Boolean, tokens: Tokens, plan: ProvisionPlan? = null): Boolean {
            val message = TrustScopes.preflight(file, prune, callerScopesOf(tokens), TrustScopes.Session.of(tokens), plan) ?: return false
            System.err.println(message)
            return true
        }

        /** SSO-3668 — test seam: how `gh` is run for `publishTo:`. Production spawns the customer's real `gh`. */
        @Volatile
        internal var ghRunner: () -> GhRunner = { ProcessGhRunner() }

        /** SSO-3659 — test seam: how `kubectl` is run for a `kubernetesSecret` sink. Production spawns the operator's real `kubectl`. */
        @Volatile
        internal var kubectlRunner: () -> KubectlRunner = { ProcessKubectlRunner() }

        internal fun resetForTest() {
            ghRunner = { ProcessGhRunner() }
            kubectlRunner = { ProcessKubectlRunner() }
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
            // SSO-3710 / SSO-3722 — the fix behind those rows, as ONE "To fix" block in two options: the SAME items (and the
            // same `cli` strings) and the same notes a `--fix-request` file carries, rendered by the one function the request
            // is rendered with; the browser option is the run's consent link when the workflow configured one (SSO-3723).
            // SSO-3738 — with a consent, Option 1 is `thoryn access approve` and no row prints a raw grant line.
            val (items, notes) = FixRequest.fromPlan(plan)
            val consentUrl = FixRequests.consentUrl()
            val approving = FixRequest.approveRun(items, consentUrl) != null
            plan.errors.forEach { c -> System.err.println("  ! ${c.kind} ${c.name}: ${FixRequest.reasonForDisplay(c.reason, c.fix, approving)}") }
            FixRequest.render(items, notes, consentUrl).takeIf { it.isNotEmpty() }?.let { System.err.println(it) }
        }

        /**
         * SSO-3710 — write the plan's fix request when the caller asked for one ([FileOptions.fixRequestTarget]) and the
         * plan is red. Never changes the exit code.
         */
        fun writeFixRequest(target: java.nio.file.Path?, plan: ProvisionPlan, file: ProvisionFile, tokens: Tokens, gateway: String) {
            val path = target ?: return
            val request = FixRequests.forPlan(plan, file, tokens, gateway) ?: return
            FixRequests.write(request, path)
        }

        fun printPlan(plan: ProvisionPlan, file: ProvisionFile) {
            println("Plan — ${file.source} (${file.digest.take(19)}…)")
            val w1 = (plan.changes.map { it.kind.length } + 4).max()
            val w2 = (plan.changes.map { it.name.length } + 4).max()
            println("  ${"KIND".padEnd(w1)}  ${"NAME".padEnd(w2)}  ACTION  REASON")
            // SSO-3738 — with a consent for this run, a refused row's inline grant command reads "approve it" instead.
            val approving = plan.hasErrors && FixRequest.approveRun(FixRequest.fromPlan(plan).first, FixRequests.consentUrl()) != null
            plan.changes.forEach { c ->
                println("  ${c.kind.padEnd(w1)}  ${c.name.padEnd(w2)}  ${c.action.name.lowercase().padEnd(6)}  ${FixRequest.reasonForDisplay(c.reason, c.fix, approving)}")
            }
            // SSO-3715 — a refused / deferred removal names the command a person runs instead.
            plan.changes.filter { it.byHand != null }.forEach { c -> println("      ${c.kind} ${c.name}: by hand: ${c.byHand}") }
            plan.changes.filter { it.diff.isNotEmpty() }.forEach { c ->
                c.diff.forEach { (field, change) -> println("      ${c.kind} ${c.name}: $field: $change") }
            }
            // SSO-3113 — grant changes per object (a no-op resource can still carry them); SSO-3715 — undeclared live grants are shown, not red.
            plan.changes.filter { it.hasGrantChanges || it.grantUndeclared.isNotEmpty() }.forEach { c ->
                c.grantAdds.forEach { println("      ${c.kind} ${c.name}: grant + $it") }
                c.grantRemoves.forEach { println("      ${c.kind} ${c.name}: grant - $it (not declared; --prune)") }
                c.grantUndeclared.forEach { println("      ${c.kind} ${c.name}: grant   $it (present, not declared)") }
            }
            // SSO-3668 — where apply will publish the id (a line, never a write: plan reaches no target).
            plan.changes.filter { it.publishTo.isNotEmpty() }.forEach { c ->
                c.publishTo.forEach { t -> println("      ${c.kind} ${c.name}: publish clientId → ${t.label}") }
            }
            // SSO-3659 — where apply will deliver the minted client secret (a line; no secret exists at plan time).
            plan.changes.forEach { c ->
                c.secretSink?.let { t ->
                    when {
                        // SSO-3921 — a runtime pull delivers nothing: the line says WHO mints the secret, and with which workload client.
                        t.runtimePull -> println("      ${c.kind} ${c.name}: secret: pulled at runtime by trust ${t.trust} (workload client ${c.pullClientId ?: "created by this apply"}; apply discards the minted value) — DEPRECATED, SSO-3951")
                        // SSO-3954 — the customer manages the secret (the default): apply discards the create's value; a person mints the real one.
                        t.customerManaged -> println("      ${c.kind} ${c.name}: secret: managed by the customer (apply discards the minted value; ${ProvisionFile.CUSTOMER_MANAGED_RUNBOOK})")
                        else -> println("      ${c.kind} ${c.name}: deliver client secret → ${t.label}")
                    }
                }
            }
            // SSO-3689 — a live trust's workload client and audience (what its consumer's connection.json names; apply prints that document).
            plan.changes.forEach { c ->
                c.trust?.let { t ->
                    // SSO-3702 — a trust's plan profile, when it carries one (the same connection.json serves both profiles).
                    val planProfile = (t["plan"] as? Map<*, *>)?.let { p -> " plan-profile ${p["environment"]} [${(p["scopes"] as? List<*>)?.joinToString(" ") ?: ""}]" } ?: ""
                    println("      ${c.kind} ${c.name}: clientId ${t["clientId"]} audience ${t["audience"]}$planProfile (connection.json is printed by apply, never written)")
                }
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
                "  ${plan.creates.size} to create, ${plan.updates.size} to update, " +
                    "${plan.removes.size} to remove, ${plan.changes.count { it.action == ChangeAction.NOOP }} unchanged" +
                    (if (plan.skips.isNotEmpty()) ", ${plan.skips.size} skipped" else "") +
                    (if (plan.grantChanges > 0) ", ${plan.grantChanges} grant change(s)" else "") +
                    (if (plan.publishes > 0) ", ${plan.publishes} output(s) to publish" else "") +
                    (if (plan.deliveries > 0) ", ${plan.deliveries} client secret(s) to deliver" else "") +
                    (if (plan.runtimePulls > 0) ", ${plan.runtimePulls} client secret(s) pulled at runtime" else "") +
                    (if (plan.customerManaged > 0) ", ${plan.customerManaged} client secret(s) managed by the customer" else "") +
                    (if (plan.hasErrors) ", ${plan.errors.size} ownership error(s)." else "."),
            )
        }

        /**
         * SSO-3659 — render a plan in the requested format and answer the exit code: a plan with an ownership
         * error is RED ([CommandSupport.EXIT_HTTP_ERROR]) whatever else it says, so a pull-request dry run fails
         * on a resource the repository does not own.
         */
        fun renderPlan(
            plan: ProvisionPlan,
            file: ProvisionFile,
            format: OutputFormat,
            /** SSO-3710 — the fix-request file to write on a red plan, with the session + gateway that resolve its trust. */
            fixRequest: java.nio.file.Path? = null,
            tokens: Tokens? = null,
            gateway: String? = null,
        ): Int {
            if (format == OutputFormat.TABLE) printPlan(plan, file) else CommandSupport.emitValue(format, plan.toStructured(), "")
            printPlanErrors(plan)
            if (tokens != null && gateway != null) writeFixRequest(fixRequest, plan, file, tokens, gateway)
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
                // SSO-3926 — a scope 403 names the scope AND the profile to add it to (config.trust-scopes), for this session.
                is MissingScopeException -> { System.err.println(TrustScopes.render(ex, storedSession())); CommandSupport.EXIT_HTTP_ERROR }
                is ProvisionException -> { System.err.println("Error: ${ex.message}"); CommandSupport.EXIT_HTTP_ERROR }
                is ProductApiException -> CommandSupport.renderError(format, ex, requiredScope = "tenant:applications.write")
                else -> CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn provision plan [--file] [--prune]` — read-only: what `apply` would do. SSO-3089 — reads the
     * LIVE state of every declared resource by its converge key (so it needs a session), and reports
     * create / update (with the changed fields) / no-op / remove. `--output json` carries `resources[]`
     * (`{kind, name, id, environment, action}`), the ids a workflow reads (SSO-3715).
     */
    @Command(name = "plan", description = ["Show what `apply` would create / update / remove for the provisioning file (read-only)."], mixinStandardHelpOptions = true)
    internal class PlanSubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--prune"], description = ["Also plan the removal of resources this identity OWNS that the file no longer declares, and of undeclared grants on the declared objects it may delete."])
        var prune: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val file = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            if (scopesMissing(file, prune, tokens)) return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val plan = engine(gateway, tokens, format = format).plan(file, prune)
                renderPlan(plan, file, format, fixRequestTarget(), tokens, gateway)
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
     * `--force-stdout`. The secret never enters the plan or a log. When it cannot be delivered the
     * resource stays in place and the command exits [SecretIo.EXIT_NO_SECRET], naming
     * `thoryn clients rotate-secret`. SSO-3715 — `--output json` prints the applied resources with their
     * ids (`resources[]`: `{kind, name, id, environment, action}`); table output stays the default.
     */
    @Command(name = "apply", description = ["Converge the account to the provisioning file (a second run is a no-op)."], mixinStandardHelpOptions = true)
    internal class ApplySubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--prune"], description = ["Remove the resources this identity OWNS that the file no longer declares, and revoke undeclared grants on the declared objects it may delete (never the owner tuple, a workspace userset or this identity itself)."])
        var prune: Boolean = false

        @Option(names = ["--confirm"], description = ["Workspace slug confirming production-plane removals (--prune)."])
        var confirm: String? = null

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        @Option(names = ["--secret-file"], description = ["SSO-3659 — the fallback for a `secretSink: { kind: kubernetesSecret | file }` that cannot be reached: write the created application's one-time client secret to this file (owner-only) instead of a TTY/pipe. An application without a sink is `customerManaged` (SSO-3954): apply discards the value; mint one with `thoryn clients rotate-secret`."])
        var secretFile: File? = null

        @Option(names = ["--force-stdout"], description = ["Allow printing a minted client secret to a non-interactive stdout (pipe/redirect) when a declared kubernetesSecret / file sink cannot be reached. Off by default."])
        var forceStdout: Boolean = false

        @Option(names = ["--force"], description = ["SSO-3659 — overwrite an existing file named by a resource's `secretSink: { kind: file, path }`. Off by default."])
        var force: Boolean = false

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
            val file = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            waitUsageError(file)?.let { System.err.println("Error: $it"); return CommandSupport.EXIT_USAGE }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val engine = try {
                engine(
                    gateway, tokens, CliSecretSink.toSecretIo(secretFile, forceStdout), format,
                    // SSO-3668 — the only verb that publishes; the publisher touches gh only when a target is reached for.
                    outputSink = GitHubActionsVariablePublisher(ghRunner()),
                    // SSO-3659 — the only verb that mints; the delivery touches kubectl / a file only when a sink is declared.
                    declaredSecretSink = CliDeclaredSecretSink(kubectlRunner(), overwriteFiles = force),
                )
            } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            if (scopesMissing(file, prune, tokens)) return CommandSupport.EXIT_HTTP_ERROR
            val plan = try {
                engine.plan(file, prune)
            } catch (ex: Exception) {
                return fail(ex, gateway, format)
            }
            if (format == OutputFormat.TABLE) printPlan(plan, file)
            // SSO-3659 — a plan with an ownership error is refused WHOLE, before anything is written or asked.
            if (plan.hasErrors) {
                if (format != OutputFormat.TABLE) CommandSupport.emitValue(format, plan.toStructured(), "")
                printPlanErrors(plan)
                // SSO-3710 — the apply job's red check names its fix the same way the plan job's does.
                writeFixRequest(fixRequestTarget(), plan, file, tokens, gateway)
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
            // SSO-3926 — the writes this plan makes, against the token: a missing write scope is named before the first write.
            if (scopesMissing(file, prune, tokens, plan)) return CommandSupport.EXIT_HTTP_ERROR
            if (!yes && !Prompt.confirm("Apply these changes now?")) {
                println("Aborted — nothing was changed.")
                return CommandSupport.EXIT_OK
            }
            return try {
                val result = engine.apply(file, plan, workspaceSlug(), confirm)
                if (format == OutputFormat.TABLE) {
                    println("Applied. ${result.resources.size} resource(s) converged (${result.resources.count { it.action == ChangeAction.CREATE }} created, ${result.resources.count { it.action == ChangeAction.UPDATE }} updated); ids: --output json.")
                } else if (!wait) {
                    CommandSupport.emitValue(format, result.toStructured(), "")
                }
                // SSO-3113 — the resources exist, but a minted client secret was not surfaced.
                // SSO-3659 — `undelivered_secrets`: raised AFTER everything is converged; names each resource and its recovery.
                val lost = engine.undeliveredSecretDetails
                if (lost.isNotEmpty()) {
                    System.err.println(
                        "Error: ${ProvisionEngine.ERROR_UNDELIVERED_SECRETS} — every resource was converged, but " +
                            "the client secret of ${lost.size} created application(s) could not be delivered:\n  " +
                            lost.joinToString("\n  ") { u ->
                                "${u.resourceKey} (clientId ${u.clientId})" +
                                    (u.target?.let { " → ${it.label}" } ?: "") + ": ${u.reason}\n    mint a new secret by hand: ${u.recovery}"
                            } + "\n" +
                            (if (lost.any { it.target == null }) "Re-run with --secret-file <path> (or --force-stdout) next time, or declare a `secretSink:` on the resource." else "Fix the sink and run the recovery command; the next apply mints nothing for an existing client."),
                    )
                    return SecretIo.EXIT_NO_SECRET
                }
                if (wait) awaitDomain(gateway, tokens, format, result.toStructured()) else CommandSupport.EXIT_OK
            } catch (ex: ProvisionEngine.PublishTargetUnreachableException) {
                // SSO-3668 — NOT a stopped apply: every resource was converged; only the publish of an id did not land.
                // The apply output is the source of the id for the by-hand command the error names.
                if (format == OutputFormat.TABLE) {
                    println("Applied. ${ex.result.resources.size} resource(s) converged; ids: --output json.")
                } else {
                    CommandSupport.emitValue(format, ex.result.toStructured(), "")
                }
                System.err.println("Error: ${ex.message}")
                CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: Exception) {
                System.err.println("Apply stopped; what succeeded is live on the platform (the ledger) — fix the cause and re-run, the next plan reads it.")
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
         * With `--output json|yaml` the ONE document printed is `{ "apply": <apply result or plan>, "customDomain": <status> }`.
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
     * `thoryn provision import [--file] [--write] [--for-workflow <file> [--root] [--config]] [--part]` — SSO-3659 (ADR
     * 2026-10-13 §2): the inverse of `plan`, bounded by the same relations. Lists what the signed-in identity may reach
     * (`GET /api/v1/access/mine`, `manager` then `viewer`) and renders each live resource the file does not yet declare as a
     * `provision.yaml` entry — `manager` objects as entries the file converges, `viewer` objects (and, SSO-3673, objects the
     * platform says another repository OWNS) as `readOnly: true`. Nothing the identity has no relation to is listed, so
     * nothing it has no relation to can be imported — the hub's rows stay the authority; SSO-3715 — `import` writes the FILE
     * only. Without `--write` it prints the entries it would add (stdout; notes and skipped objects on stderr) and changes
     * nothing.
     *
     * SSO-3990 (thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13) — what it writes plans as all `noop`:
     *  - **part-aware** — a `thoryn.io/tenant/v1` file never receives `kind: application`, an application file never a tenant
     *    kind; each object left out is listed with the reason. A file that does not exist yet takes `--part`.
     *  - **scope-aware** — a kind the session cannot read is listed as not imported, naming the scope (no `403` aborts the
     *    run); an entry whose write scope is missing is rendered `readOnly: true`. With `--for-workflow` the scopes are the
     *    configured file's connection's (`auth.scopes`, narrowed by the token to plan), so the file passes `provision workflow
     *    check`'s `config.trust-scopes` with that connection; without it, the token's.
     *  - `emailProvider` / `federationMember` are always `readOnly` (write-only secrets); production-plane users are never
     *    imported, sandbox test users are; the repository's own trusts are never imported; with `--for-workflow`, each object
     *    goes to exactly one configured file by plane.
     */
    @Command(name = "import", description = ["Render the live resources this identity may reach as provisioning-file entries; --write appends them to the file."], mixinStandardHelpOptions = true)
    internal class ImportSubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--write"], description = ["Append the entries to the provisioning file (created when absent). Default: print only."])
        var write: Boolean = false

        @Option(
            names = ["--for-workflow"],
            paramLabel = "<file>",
            description = [
                "SSO-3990 — import for this configured provisioning file of .thoryn/workflow.yaml (its path as listed there): its connection's auth.scopes " +
                    "decide what is read (narrowed by the token) and what is written as readOnly, every object goes to one configured file by plane, and the " +
                    "configured connections' own trusts are left out. --file defaults to <root>/<file>; pass --file to write a copy instead.",
            ],
        )
        var forWorkflow: String? = null

        @Option(names = ["--root"], description = ["With --for-workflow: the repository root the configured paths are resolved against (default: the current directory)."])
        var root: File? = null

        @Option(names = ["--config"], description = ["With --for-workflow: the run-time configuration (default: <root>/${com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig.DEFAULT_PATH}; absent ⇒ the built-in default)."])
        var config: File? = null

        @Option(names = ["--part"], description = ["SSO-3990 — the part of a file that does not exist yet: tenant (thoryn.io/tenant/v1) or application (thoryn.io/application/v1). An existing file's own apiVersion decides; default for a new file: whatever the imported kinds make it."])
        var partRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val repoRoot = root ?: File(".")
            if (forWorkflow == null && (root != null || config != null)) {
                System.err.println("Error: --root and --config only apply with --for-workflow <file>.")
                return CommandSupport.EXIT_USAGE
            }
            val workflowTarget = forWorkflow?.let { configured ->
                val configFile = config ?: File(repoRoot, com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig.DEFAULT_PATH)
                try {
                    WorkflowImportTarget.resolve(repoRoot, configFile, config?.path ?: com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig.DEFAULT_PATH, configured)
                } catch (ex: WorkflowImportException) {
                    System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
                }
            }
            val target = file ?: workflowTarget?.let { File(repoRoot, it.file) } ?: ProvisionFile.resolveDefault() ?: File(ProvisionFile.DEFAULT_DIR, ProvisionFile.DEFAULT_FILES.first())
            // SSO-4042 — the import job imports into a COPY of the committed file (`--file <copy>`); a `bodyFile` the committed
            // file names is relative to it, so the copy loads only when those files sit beside it too. Stage them (never
            // overwriting a different file); the artifact then carries the files a configured file references.
            workflowTarget?.let { w ->
                try {
                    stageBodyFiles(File(repoRoot, w.file), target)
                } catch (ex: ProvisionException) {
                    System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
                }
            }
            val existing = try {
                if (target.isFile) ProvisionFile.load(target).also { printWarnings(it) } else null
            } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val requestedPart = when (partRaw?.trim()?.lowercase()) {
                null -> null
                ProvisionPart.TENANT.label -> ProvisionPart.TENANT
                ProvisionPart.APPLICATION.label -> ProvisionPart.APPLICATION
                else -> { System.err.println("Error: --part must be tenant or application (was $partRaw)."); return CommandSupport.EXIT_USAGE }
            }
            if (existing != null && requestedPart != null && existing.part != requestedPart) {
                System.err.println("Error: --part $partRaw, but ${target.path} declares ${existing.part.apiVersion} — the file's own apiVersion decides; drop --part.")
                return CommandSupport.EXIT_USAGE
            }
            val part = existing?.part ?: requestedPart ?: ProvisionPart.MIXED
            if (write && target.name.endsWith(".json", ignoreCase = true)) {
                System.err.println("Error: --write appends YAML; ${target.path} is a JSON file — run without --write and add the entries by hand.")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val tokenScopes = callerScopesOf(tokens)
            val options = workflowTarget?.options(part, tokenScopes) ?: ImportOptions(part = part, planScopes = tokenScopes, applyScopes = tokenScopes)
            workflowTarget?.let { w ->
                val session = subjectOf(tokens)
                if (session != "client:${w.connection.clientId}") {
                    System.err.println(
                        "Warning: signed in as ${session ?: "an identity this CLI cannot name"}, not as ${w.connectionPath}'s client ${w.connection.clientId} — " +
                            "the scopes are that connection's, but what is read-only because it is only viewed or owned elsewhere follows the signed-in identity.",
                    )
                }
            }
            return try {
                val engine = engine(gateway, tokens, format = format)
                val result = engine.import(existing, options)
                val yaml = renderEntries(result.resources)
                if (format == OutputFormat.TABLE) {
                    if (result.resources.isEmpty()) println("Nothing to import — every resource this identity may reach is already declared in ${target.path}.") else print(yaml)
                } else {
                    CommandSupport.emitValue(
                        format,
                        mapOf(
                            "file" to target.path, "part" to part.label, "written" to (write && result.resources.isNotEmpty()),
                            "resources" to result.resources.map { it.toStructured() }, "skipped" to result.skipped,
                        ),
                        "",
                    )
                }
                result.resources.filter { it.note != null }.forEach { System.err.println("  note ${it.resource.kind} ${it.resource.name}: ${it.note}") }
                result.skipped.forEach { System.err.println("  skipped $it") }
                // SSO-4042 — the files the entries refer to (an emailTemplate's or, SSO-4057, a legalDocument's body as `bodyFile`), written next to the file.
                val files = result.resources.flatMap { it.files.entries }.associate { it.key to it.value }
                if (!write || result.resources.isEmpty()) {
                    if (!write && result.resources.isNotEmpty()) {
                        if (files.isNotEmpty()) System.err.println("  ${files.size} file(s) would be written next to ${target.path}: ${files.keys.sorted().joinToString(", ")}")
                        System.err.println("Printed ${result.resources.size} entry(ies) — nothing was written; re-run with --write to append them to ${target.path}.")
                    }
                    return CommandSupport.EXIT_OK
                }
                appendEntries(target, yaml, existing, if (part == ProvisionPart.MIXED) ProvisionYamlEdit.apiVersionFor(result.resources.map { it.resource.kind }) else part.apiVersion, files)
                val readOnly = result.resources.count { it.resource.readOnly }
                if (format == OutputFormat.TABLE) {
                    val wrote = if (files.isEmpty()) "Nothing else was written" else "${files.size} file(s) written beside it (${files.keys.sorted().joinToString(", ")}); nothing else was written"
                    println("Imported ${result.resources.size} entry(ies) into ${target.path}: ${result.resources.size - readOnly} to converge, $readOnly read-only. $wrote — the platform is the ledger.")
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
        private fun appendEntries(target: File, fragment: String, existing: ProvisionFile?, apiVersion: String, files: Map<String, String> = emptyMap()) {
            target.absoluteFile.parentFile?.mkdirs()
            // SSO-4042 — the referenced files first (the re-load below resolves `bodyFile` against the target's directory); a file
            // that already exists with OTHER content is refused before anything is written — an import never clobbers a body.
            val written = writeReferencedFiles(target, files)
            fun undoFiles() = written.forEach { it.delete() }
            if (existing == null) {
                // SSO-3962 — a fresh file declares the part its entries belong to (both parts ⇒ the mixed format, which warns to
                // split); SSO-3990 — or the part `--part` named, whose kinds alone the import rendered.
                target.writeText(ProvisionYamlEdit.fresh(fragment, apiVersion))
                try {
                    ProvisionFile.load(target)
                } catch (ex: ProvisionException) {
                    target.delete(); undoFiles()
                    throw ProvisionException("the imported entries did not validate (${ex.message}); ${target.path} was not written")
                }
            } else {
                val original = target.readBytes()
                // The shared edit rule (ProvisionYamlEdit): append under `resources:` only when it is the last top-level key.
                target.writeText(ProvisionYamlEdit.append(original.toString(Charsets.UTF_8), fragment, target.path))
                try {
                    ProvisionFile.load(target)
                } catch (ex: ProvisionException) {
                    target.writeBytes(original); undoFiles()
                    throw ProvisionException("the appended entries did not validate (${ex.message}); ${target.path} was left unchanged")
                }
            }
        }

        /**
         * SSO-4042 — write each `path → content` of [files] relative to [target]'s directory. Returns the files this call CREATED
         * (an identical existing file is left as it is and not returned; a different one is refused before any write).
         */
        private fun writeReferencedFiles(target: File, files: Map<String, String>): List<File> {
            val dir = target.absoluteFile.parentFile ?: File(".")
            val resolved = files.mapKeys { (path, _) -> File(dir, path) }
            resolved.forEach { (f, content) ->
                if (f.exists() && f.readText(Charsets.UTF_8) != content) {
                    throw ProvisionException("${f.path} already exists with different content; the import does not overwrite a template body or a legal document's body — move it aside or declare that resource by hand")
                }
            }
            return resolved.mapNotNull { (f, content) ->
                if (f.exists()) null else { f.parentFile?.mkdirs(); f.writeText(content, Charsets.UTF_8); f }
            }
        }

        /**
         * SSO-4042 — `--for-workflow` with `--file <copy>`: the files the COMMITTED file names as `bodyFile` are copied beside the
         * copy (same relative paths) so the copy loads, plans and re-loads; an existing different file at the destination is refused.
         * A no-op when the copy is the committed file itself or the committed file names no `bodyFile`.
         */
        private fun stageBodyFiles(committed: File, target: File) {
            if (!committed.isFile || committed.absoluteFile.normalize() == target.absoluteFile.normalize()) return
            val paths = ProvisionFile.load(committed).resources.filter { it.kind in ProvisionFile.BODY_FILE_KINDS }.mapNotNull { it.spec["bodyFile"]?.toString()?.trim()?.takeIf { p -> p.isNotEmpty() } }.distinct()
            if (paths.isEmpty()) return
            val from = committed.absoluteFile.parentFile
            writeReferencedFiles(target, paths.associateWith { File(from, it).readText(Charsets.UTF_8) })
        }
    }

    /**
     * SSO-3962 — `thoryn provision split [--file] [--tenant-file <path>] [--application-file <path>] [--force]`: the one-time
     * move from the mixed `thoryn.io/provision/v1` format to the two parts ([ProvisionSplit]). Reads the mixed file,
     * writes `.thoryn/tenant.provision.yaml` (every tenant kind — for the workspace's config project) and
     * `.thoryn/application.provision.yaml` (every `application` — for the app project) next to it, each re-loaded through
     * the loader before it is written, and prints which resource went where. The source file is never modified; the
     * outputs are re-rendered, so its comments are not carried over (the output says so). No session is needed.
     */
    @Command(name = "split", description = ["SSO-3962 — write a mixed thoryn.io/provision/v1 file as a tenant file (thoryn.io/tenant/v1) and an application file (thoryn.io/application/v1); the source is left as it is."], mixinStandardHelpOptions = true)
    internal class SplitSubcommand : Callable<Int> {
        @Option(names = ["--file", "-f"], description = ["The mixed provisioning file to split (default: .thoryn/provision.yaml, .yml or .json)."])
        var file: File? = null

        @Option(names = ["--tenant-file"], description = ["Where the tenant file is written (default: <dir of the source>/tenant.provision.yaml). Not written when the source declares no tenant kind."])
        var tenantFile: File? = null

        @Option(names = ["--application-file"], description = ["Where the application file is written (default: <dir of the source>/application.provision.yaml). Not written when the source declares no application."])
        var applicationFile: File? = null

        @Option(names = ["--force"], description = ["Overwrite an output file that already exists. Off by default."])
        var force: Boolean = false

        override fun call(): Int {
            val source = file ?: ProvisionFile.resolveDefault() ?: run {
                System.err.println("No provisioning file found — expected ${ProvisionFile.DEFAULT_DIR}/${ProvisionFile.DEFAULT_FILES.first()} (or pass --file).")
                return CommandSupport.EXIT_USAGE
            }
            val dir = source.absoluteFile.parentFile
            val outputs = try {
                ProvisionSplit.split(source, tenantFile ?: File(dir, "tenant.provision.yaml"), applicationFile ?: File(dir, "application.provision.yaml"), force)
            } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            println("Split ${source.path} (${ProvisionFile.API_VERSION}) into its two parts:")
            outputs.forEach { o ->
                if (o.written) {
                    println("  ${o.part.label.padEnd(11)}  ${o.file.path}  (${o.part.apiVersion}): ${o.resources.joinToString(", ")}")
                } else {
                    println("  ${o.part.label.padEnd(11)}  not written — the source declares no ${o.part.label} kind")
                }
            }
            println("${source.path} was not changed; the outputs are re-rendered, so its comments are not carried over.")
            println("Next: the tenant file belongs in the workspace's config project, the application file in the app project — each converged by its own identity (`thoryn provision plan --file <path>` is the check).")
            return CommandSupport.EXIT_OK
        }
    }

    /**
     * `thoryn provision destroy [--file] [--confirm <ws>] [--yes]` — SSO-3715: remove what the file declares AND this
     * identity may remove (the platform's `owner` relation decides; see [ProvisionEngine.planDestroy]), child-first.
     * The destroy plan is printed first — `remove` rows, and `skip` rows (retained, not owned, left to a person,
     * removed with their sandbox) each with the reason and the command a human would run.
     */
    @Command(name = "destroy", description = ["Remove the resources the provisioning file declares that this identity may remove (owner-gated; child-first; `retain: true` keeps one)."], mixinStandardHelpOptions = true)
    internal class DestroySubcommand : FileOptions(), Callable<Int> {
        @Option(names = ["--confirm"], description = ["Workspace slug confirming production-plane removals."])
        var confirm: String? = null

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val file = try { open() ?: return CommandSupport.EXIT_USAGE } catch (ex: ProvisionException) {
                System.err.println("Error: ${ex.message}"); return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val engine = engine(gateway, tokens, format = format)
            val plan = try {
                engine.planDestroy(file)
            } catch (ex: Exception) {
                return fail(ex, gateway, format)
            }
            if (format == OutputFormat.TABLE) {
                println("Destroy — ${file.source} (${file.digest.take(19)}…)")
                val w1 = (plan.changes.map { it.kind.length } + 4).max()
                val w2 = (plan.changes.map { it.name.length } + 4).max()
                println("  ${"KIND".padEnd(w1)}  ${"NAME".padEnd(w2)}  ACTION  REASON")
                plan.changes.forEach { c -> println("  ${c.kind.padEnd(w1)}  ${c.name.padEnd(w2)}  ${c.action.name.lowercase().padEnd(6)}  ${c.reason}${c.liveId?.let { " (id $it)" } ?: ""}") }
                plan.changes.filter { it.byHand != null }.forEach { c -> println("      ${c.kind} ${c.name}: by hand: ${c.byHand}") }
                println("  ${plan.removes.size} to remove, ${plan.skips.size} left in place" + (if (plan.hasErrors) ", ${plan.errors.size} error(s)." else "."))
            }
            if (plan.hasErrors) {
                if (format != OutputFormat.TABLE) CommandSupport.emitValue(format, plan.toStructured(), "")
                printPlanErrors(plan)
                System.err.println("Nothing was removed.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            if (plan.removes.isEmpty()) {
                if (format == OutputFormat.TABLE) println("Nothing to destroy — this identity may remove none of the declared resources (see the rows above).") else CommandSupport.emitValue(format, plan.toStructured(), "")
                return CommandSupport.EXIT_OK
            }
            if (plan.removesOnProductionPlane && confirm.isNullOrBlank()) {
                System.err.println("destroy would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
                return CommandSupport.EXIT_HTTP_ERROR
            }
            if (!yes && !Prompt.confirm("Remove these ${plan.removes.size} resource(s) now? This is irreversible.")) {
                println("Aborted — nothing was removed.")
                return CommandSupport.EXIT_OK
            }
            return try {
                val outcome = engine.destroy(plan, confirm)
                if (outcome.failures.isEmpty()) {
                    if (format == OutputFormat.TABLE) {
                        println("Destroyed ${outcome.removed.size} resource(s)." + (if (plan.skips.isNotEmpty()) " ${plan.skips.size} left in place (see the plan above)." else ""))
                    } else {
                        CommandSupport.emitValue(format, mapOf("destroyed" to true, "removed" to outcome.removed.map { it.toStructured() }, "skipped" to plan.skips.map { it.toStructured() }), "")
                    }
                    CommandSupport.EXIT_OK
                } else {
                    if (format != OutputFormat.TABLE) CommandSupport.emitValue(format, mapOf("destroyed" to false, "removed" to outcome.removed.map { it.toStructured() }, "failures" to outcome.failures), "")
                    System.err.println("${outcome.failures.size} resource(s) could not be removed and stay live: re-run to retry.")
                    CommandSupport.EXIT_HTTP_ERROR
                }
            } catch (ex: Exception) {
                fail(ex, gateway, format)
            }
        }
    }

}
