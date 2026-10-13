package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.PublishTarget
import com.devnow.thoryn.cli.cmd.project.GhCommandException
import com.devnow.thoryn.cli.cmd.project.GhNotInstalledException
import com.devnow.thoryn.cli.cmd.project.GhRunner
import com.devnow.thoryn.cli.cmd.project.GitHubCli

/**
 * SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) — the CLI's
 * [ProvisionEngine.OutputSink]: an application's clientId lands in the target repository's GitHub
 * environment as an Actions VARIABLE, through the customer's own `gh` login (never a token thoryn
 * handles — [GhRunner]). CLI side, not engine side: it runs a process.
 *
 * The invocations, in order, all through [GitHubCli]:
 *
 * | purpose | invocation |
 * |---|---|
 * | reachable? (once per apply) | `gh --version`, `gh auth status` |
 * | the target repository | `gh api repos/<owner>/<name>` |
 * | does the environment exist? | `gh api repos/<owner>/<name>/environments/<env>` |
 * | create it when absent | `gh api --method PUT repos/<owner>/<name>/environments/<env>` — no body: no protection rules are set, and an EXISTING environment is never written (its reviewers and branch policy are the app repository's to decide) |
 * | the variable (upsert) | `gh variable set <NAME> --body <clientId> --repo <owner>/<name> --env <env>` |
 *
 * Every failure is answered as a REASON (the engine turns it into `publish_target_unreachable` after
 * the resource is converged and recorded), never thrown past the engine: an unreachable target must not
 * cost the client its receipt entry.
 */
internal class GitHubActionsVariablePublisher(
    private val gh: GhRunner,
    private val cli: GitHubCli = GitHubCli(gh),
) : ProvisionEngine.OutputSink {

    /** `null` ⇒ gh is installed and signed in; else the reason it is not (checked once per publisher). */
    private var unavailable: String? = null
    private var checked = false

    override fun publish(target: PublishTarget, value: String): String? {
        if (target.kind != ProvisionFile.PUBLISH_KIND_GITHUB_ACTIONS_VARIABLE) return "unsupported publish target kind '${target.kind}'"
        availability()?.let { return it }
        return try {
            val (owner, name) = target.repository.split('/', limit = 2)
            val repository = cli.repository(owner, name, STEP)
                ?: return "repository ${target.repository} was not found, or is not visible to the signed-in gh account"
            if (cli.environmentState(repository, target.environment, STEP) == null) {
                // Absent: create it bare. Present: never touched — protection stays what the repository's admins set.
                val created = gh.run(listOf("api", "--method", "PUT", "repos/${repository.fullName}/environments/${target.environment}"))
                if (!created.ok) return "could not create the GitHub environment '${target.environment}' on ${target.repository} (${created.reason()}); you need admin rights on the repository"
            }
            cli.setVariable(repository, target.name, value, target.environment, STEP)
            null
        } catch (ex: GhCommandException) {
            ex.result.reason()
        } catch (ex: GhNotInstalledException) {
            ex.message
        }
    }

    private fun availability(): String? {
        if (!checked) {
            checked = true
            unavailable = when (cli.availability()) {
                GitHubCli.Availability.Ready -> null
                GitHubCli.Availability.NotInstalled -> "the GitHub CLI (gh) is not installed or not on PATH"
                GitHubCli.Availability.NotSignedIn -> "gh is not signed in to GitHub (run `gh auth login`)"
            }
        }
        return unavailable
    }

    companion object {
        /** The step name on a `gh` failure's message. */
        const val STEP = "publishTo"
    }
}
