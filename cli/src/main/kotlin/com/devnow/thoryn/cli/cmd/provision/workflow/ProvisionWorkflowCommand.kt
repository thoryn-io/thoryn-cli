package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.util.concurrent.Callable

/**
 * `thoryn provision workflow check [--file <stub>] [--config <workflow.yaml>] [--output json]` — SSO-3719 (epic SSO-3304).
 *
 * Lints the repository's provisioning workflow STUB (`.github/workflows/thoryn-provisioning.yml`, the one path the Thoryn
 * GitHub App dispatches) and its run-time configuration (`.thoryn/workflow.yaml`) against [ProvisioningWorkflowContract]:
 * every rule PASS / FAIL with the exact fix, the EFFECTIVE configuration (the stub's `with:` inputs with defaults filled
 * in, the config's files / env / toggles), exit [CommandSupport.EXIT_OK] or [CommandSupport.EXIT_CHECK_FAILED].
 *
 * The reusable workflow runs this very command with `--output json` and acts on the `config` object it prints — so the
 * file a customer commits is validated by the same code on a laptop and in the job, and a red check names its fix.
 *
 * A hand-written workflow (own jobs, own steps) is reported as NOT the supported shape: the rules still say what the App
 * would need from it, but it is unsupported, not promoted. A `uses:` of a workflow that is not thoryn-cli's cannot be
 * verified at all ("run the check on that file").
 *
 * `thoryn provision workflow import-summary` (SSO-3991, contract v2) is the reusable workflow's own step: it writes the
 * `import-summary.json` of the `import` job's artifact ([ImportSummary]). It is not a customer command.
 */
@Command(
    name = "workflow",
    description = ["The provisioning workflow stub and its .thoryn/workflow.yaml: check them against the contract."],
    mixinStandardHelpOptions = true,
    subcommands = [ProvisionWorkflowCommand.CheckSubcommand::class, ProvisionWorkflowCommand.ImportSummarySubcommand::class],
)
class ProvisionWorkflowCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn provision workflow check [--file <workflow>] [--config <workflow.yaml>] [--output json]")
        return CommandSupport.EXIT_USAGE
    }

    @Command(
        name = "check",
        description = ["Lint the provisioning workflow stub (default .github/workflows/thoryn-provisioning.yml) and .thoryn/workflow.yaml against contract v${ProvisioningWorkflowContract.CONTRACT_VERSION}; print each rule PASS/FAIL with its fix and the effective configuration. Exit 0 when every rule passes, 4 otherwise."],
        mixinStandardHelpOptions = true,
    )
    internal class CheckSubcommand : Callable<Int> {
        @Option(names = ["--file", "-f"], description = ["The workflow to check (default: ${ProvisioningWorkflowContract.WORKFLOW_PATH}). The reusable workflow itself (on: workflow_call) is checked as the called side."])
        var file: File? = null

        @Option(names = ["--config"], description = ["The run-time configuration (default: the stub's `with.config`, else ${WorkflowConfig.DEFAULT_PATH}; absent ⇒ built-in defaults)."])
        var config: File? = null

        @Option(names = ["--root"], description = ["Repository root the configured files are resolved against (default: the current directory)."])
        var root: File? = null

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val repoRoot = (root ?: File(".")).absoluteFile
            val target = file ?: File(repoRoot, ProvisioningWorkflowContract.WORKFLOW_PATH)
            if (!target.isFile) {
                System.err.println("Error: no workflow at ${target.path} — the Thoryn GitHub App dispatches ${ProvisioningWorkflowContract.WORKFLOW_PATH}; commit the stub (see README \"Configure the provisioning workflow\") or pass --file.")
                return CommandSupport.EXIT_USAGE
            }
            val display = target.absoluteFile.normalize().relativeToOrNull(repoRoot.normalize())?.path ?: target.path
            val report = WorkflowCheck.evaluate(target.readText(), display, configFile = config, root = repoRoot)
            if (format == OutputFormat.TABLE) print(report) else CommandSupport.emitValue(format, report.toStructured(), "")
            return if (report.ok) CommandSupport.EXIT_OK else CommandSupport.EXIT_CHECK_FAILED
        }

        private fun print(report: WorkflowCheck.Report) {
            println("Thoryn provisioning workflow check — contract v${ProvisioningWorkflowContract.CONTRACT_VERSION}")
            println("  file   ${report.file}")
            println("  shape  ${report.shape.label}" + if (!report.supported) "  (UNSUPPORTED — the supported shape is a stub calling ${ProvisioningWorkflowContract.REUSABLE_WORKFLOW}@${ProvisioningWorkflowContract.MINIMUM_RELEASE}; below is what the App would need from this one)" else "")
            println()
            val w = report.rules.maxOf { it.id.length }
            report.rules.forEach { r ->
                val status = when (r.status) { WorkflowCheck.Status.PASS -> "PASS"; WorkflowCheck.Status.FAIL -> "FAIL"; WorkflowCheck.Status.UNVERIFIABLE -> "????" }
                println("  $status  ${r.id.padEnd(w)}  ${r.title}")
                println("        ${"".padEnd(w)}  ${r.detail}")
                if (r.failed && r.fix != null) println("        ${"".padEnd(w)}  fix: ${r.fix}")
            }
            report.inputs?.let { inputs ->
                println()
                println("Effective inputs (the stub's with:, defaults filled in)")
                inputs.forEach { (k, v) -> println("  ${k.padEnd(18)} ${v.ifEmpty { "(empty)" }}") }
            }
            report.config?.let { c ->
                println()
                println("Effective configuration (${c.source ?: "no ${WorkflowConfig.DEFAULT_PATH} — built-in defaults"})")
                println("  ${"provider".padEnd(18)} ${c.provider}")
                if (c.files.isEmpty()) println("  ${"files".padEnd(18)} (none — no provisioning files configured)")
                c.files.forEachIndexed { i, f -> println("  ${(if (i == 0) "files" else "").padEnd(18)} ${f.file}  (connection ${f.connection})") }
                println("  ${"env".padEnd(18)} ${if (c.env.isEmpty()) "(none)" else c.env.entries.joinToString(" ") { "${it.key}=${it.value}" }}")
                println("  ${"fixRequest".padEnd(18)} ${c.fixRequest}")
                println("  ${"apply".padEnd(18)} prune=${c.prune} destroy=${c.destroy} confirm=${c.confirm ?: "(none)"}")
            }
            println()
            val failed = report.rules.filter { it.failed }
            println(if (report.ok) "OK — ${report.rules.size} rule(s) pass." else "FAILED — ${failed.size} of ${report.rules.size} rule(s): ${failed.joinToString(", ") { it.id }}.")
        }
    }

    /**
     * `thoryn provision workflow import-summary --artifact <dir> --work <dir> --head-sha <sha> [--config] [--root]` — SSO-3991.
     * The reusable workflow's `import` job runs this after importing every configured file: it checks the artifact directory
     * holds exactly the configured files, each loading and within the size bound, and writes `import-summary.json` beside
     * them ([ImportSummary]: a fixed field list, never a value of the configuration). Exit 0 written,
     * [CommandSupport.EXIT_CHECK_FAILED] when the artifact would be refused (nothing written).
     */
    @Command(
        name = "import-summary",
        description = ["Used by the reusable workflow's import job (contract v2): check the imported files and write ${ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE} beside them. Exit 0 written, 4 refused."],
        mixinStandardHelpOptions = true,
    )
    internal class ImportSummarySubcommand : Callable<Int> {
        @Option(names = ["--artifact"], required = true, description = ["The artifact directory: each configured file imported at its repository path."])
        lateinit var artifact: File

        @Option(names = ["--work"], required = true, description = ["Where the job wrote <i>.import.json, <i>.plan.json and <i>.plan.exit for the i-th configured file."])
        lateinit var work: File

        @Option(names = ["--head-sha"], required = true, description = ["The commit the import ran at (the dispatch's head_sha)."])
        lateinit var headSha: String

        @Option(names = ["--config"], description = ["The run-time configuration (default: <root>/${WorkflowConfig.DEFAULT_PATH}; absent ⇒ built-in defaults)."])
        var config: File? = null

        @Option(names = ["--root"], description = ["Repository root (default: the current directory)."])
        var root: File? = null

        override fun call(): Int {
            val repoRoot = root ?: File(".")
            val configFile = config ?: File(repoRoot, WorkflowConfig.DEFAULT_PATH)
            return try {
                val workflow = WorkflowConfig.load(configFile, config?.path ?: WorkflowConfig.DEFAULT_PATH)
                val summary = ImportSummary.build(headSha.trim(), workflow, artifact, work)
                ImportSummary.write(summary, artifact)
                print(ImportSummary.render(summary))
                CommandSupport.EXIT_OK
            } catch (ex: WorkflowConfigException) {
                System.err.println("Error: ${ex.message}"); CommandSupport.EXIT_USAGE
            } catch (ex: ImportSummary.ImportSummaryException) {
                System.err.println("Error: ${ex.message} — nothing is handed to the Thoryn GitHub App."); CommandSupport.EXIT_CHECK_FAILED
            }
        }
    }
}
