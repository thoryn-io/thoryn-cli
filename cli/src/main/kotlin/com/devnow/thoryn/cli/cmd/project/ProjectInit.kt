package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.provision.ProvisionYamlEdit
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import tools.jackson.databind.JsonNode
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-3435 (epic SSO-3304) — the work behind `thoryn project init config|app`: set up a GitHub repository that
 * manages the caller's own Thoryn workspace (a CONFIG project) or connects one application (an APP project),
 * with no GitHub App — GitHub through the customer's own `gh` ([GitHubCli]), Thoryn through the public
 * product-api surface with the customer's own `thoryn login` session ([ThorynApi]).
 *
 * It mirrors oauthy's server-side starter orchestrator (SSO-3310, ADR 2026-09-30-starter-orchestrator-service):
 * the same template contract ([StarterTemplateManifest]), the same steps and rules — one production connection,
 * reviewers required and confirmed, the production trust pinned to the repository ids + the GitHub environment
 * + the default branch, trusts carrying exactly the template's scopes, grants per the template, protection
 * BEFORE any production variable — and the same refusals.
 *
 * **Nothing is half-done by a refusal.** Every check — flags, the Thoryn session and the caller's reach, `gh`
 * installed and signed in, the template (v2, valid), the scope ceiling, the repository (resolvable or
 * creatable), the reviewers, file conflicts in a clone, conflicting trusts — runs BEFORE the first change, on
 * either side. When `gh` is missing or signed out, it prints what it would run (with the Thoryn values filled
 * in) and stops without having changed anything.
 *
 * **Safe to re-run.** A step that fails part-way (a GitHub or product-api error that no pre-flight could see)
 * leaves only completed, idempotent steps behind, and running the same command again converges: the
 * repository is reused, the environment protection re-applied to the required shape, trusts adopted (by
 * their deterministic name, or — for one the orchestrator created — by their pins), grants are idempotent,
 * variables upserted, identical files skipped.
 *
 * **The app's PRODUCTION client (SSO-3669, ADR 2026-10-13 production-clients-declared-in-the-config-project §1).**
 * An app repository is sandbox-only; with `--config-repo` + `--production-url`, the run ends by proposing the app's
 * production client ON THE CONFIG REPOSITORY: a pull request from the deterministic branch `thoryn/app-<app repo>`
 * (reused on a re-run — never a second one) adding an `application` entry to its production section, converged by
 * `name` (added when absent, replaced when different, nothing proposed when identical), with the `publishTo` block
 * that lands the id in the app repository's `production` GitHub environment. The config repository is resolved and
 * the file computed at pre-flight (a missing repository stops the run before any write, with the by-hand steps; it is
 * never created); the default branch is never written; the command never merges.
 */
internal class ProjectInit(
    private val request: Request,
    private val github: GitHubCli,
    private val thoryn: ThorynApi,
    private val session: Session,
) {

    enum class Kind(val templateKind: String, val label: String) {
        CONFIG(StarterTemplateManifest.KIND_CONFIG, "config"),
        APP(StarterTemplateManifest.KIND_APPLICATION, "app"),
    }

    data class Request(
        val kind: Kind,
        /** `config` for a config project; the application stack otherwise. */
        val stack: String,
        /** `owner/repo` of the public template repository. */
        val template: String,
        /** `owner/name` given with `--repo`; null ⇒ the existing clone in [dir]. */
        val repo: String?,
        val public: Boolean,
        val dir: Path,
        val force: Boolean,
        /** The app project's sandbox, or the config project's sandbox (null ⇒ choose). */
        val sandbox: String?,
        val reviewers: List<String>,
        val confirmProduction: Boolean,
        /** The command line to repeat, for the hints. */
        val commandLine: String,
        /** SSO-3669 (app) — `owner/name` of the workspace's config repository the production client is proposed on; null ⇒ no proposal. */
        val configRepo: String? = null,
        /** SSO-3669 (app) — where the app runs in production; the redirect URIs hang off it. Set together with [configRepo]. */
        val productionUrl: String? = null,
    )

    /** The Thoryn session facts the project needs, from the current login / workspace selection. */
    data class Session(
        val workspaceSlug: String?,
        val tenantId: String?,
        val issuer: String,
        /** `client_credentials` / `workload_identity` for a machine session; null for a person. */
        val authMode: String?,
    )

    /** The product-api calls, per environment (the `X-Thoryn-Environment` header), and the workspace-level ones. */
    interface ThorynApi {
        val workspace: ProductApiClient
        fun inEnvironment(slug: String): ProductApiClient
    }

    /** A refusal or a failed step, rendered by [ProjectCommand]; [steps] says what was done before it. */
    class Stop(
        val exit: Int,
        val code: String,
        val description: String,
        val hint: String? = null,
        val extra: Map<String, Any?> = emptyMap(),
    ) : RuntimeException(code)

    data class Step(val name: String, val status: String, val detail: String)

    /** Filled as the run advances; the report (success or failure) is rendered from it. */
    val steps: MutableList<Step> = mutableListOf()

    /** The step in progress — names a product-api error's context ([STEP_PREFLIGHT] until the first change). */
    var currentStep: String = STEP_PREFLIGHT
        private set
    val report: LinkedHashMap<String, Any?> = linkedMapOf()

    private data class Env(val id: String, val slug: String, val name: String?, val production: Boolean, val suspended: Boolean)

    private data class Target(
        val connection: String,
        val spec: StarterTemplateManifest.Connection,
        val envSlug: String,
        var envId: String?,
        val githubEnvironment: String?,
        /** The trust this connection uses, once [ensureTrust] ran. */
        var trust: JsonNode? = null,
    ) {
        /** Where this connection's `connection.json` is seeded: beside its `provisionFile`. */
        val connectionPath: String get() = ProjectSeeds.connectionPath(spec.provisionFile)
    }

    private enum class FileAction { WRITE, OVERWRITE, SAME }

    private class PlannedFile(val entry: TemplateArchive.Entry, val target: Path, val action: FileAction)

    /** SSO-3669 — the config repository and the production-section file as it must read after this app's production client is converged into it. */
    private class ConfigProject(
        val repository: GhRepository,
        val appRepository: String,
        val entry: JsonNode,
        val converged: ProvisionYamlEdit.Converged,
    ) {
        val branch: String get() = ProjectSeeds.productionClientBranch(appRepository.substringAfter('/'))
        val name: String get() = ProjectSeeds.productionClientName(appRepository)
    }

    // ── Entry point ──────────────────────────────────────────────────────────────────────────────

    /** Run the whole flow. Throws [Stop] (a refusal, or a failed step) and [ProductApiException]. */
    fun execute(): Map<String, Any?> {
        val config = request.kind == Kind.CONFIG
        report["kind"] = request.kind.label
        report["template"] = request.template

        // ── Pre-flight: Thoryn (reads only) ──────────────────────────────────────────────────────
        if (config && session.authMode != null) {
            throw Stop(
                EXIT_CHECK, "person_required",
                "A config project delegates workspace-wide management to its production workload identity; only a person may grant that.",
                "Sign in as yourself (thoryn login) rather than with a machine identity, and re-run.",
            )
        }
        val environments = environments()
        val workspaceSlug = session.workspaceSlug
            ?: throw Stop(EXIT_CHECK, "workspace_unknown", "This session names no workspace.", "Run `thoryn workspace switch <slug>` (or `thoryn login --workspace <slug>`) and re-run.")
        report["workspace"] = workspaceSlug
        report["issuer"] = session.issuer

        val production = environments.firstOrNull { it.production }
        val sandbox: Env?
        val sandboxSlug: String
        var tenantId = session.tenantId
        if (config) {
            // The workspace this session acts on must be one the caller manages (managers delegate). With no
            // tenant id on the session, the one workspace the caller's reach names is it.
            val managed = mine("workspace")
            val own = session.tenantId
            tenantId = when {
                own != null -> own.takeIf { "workspace:${encodeId(it)}" in managed }
                else -> managed.singleOrNull()?.removePrefix("workspace:")
            }
            if (tenantId == null) {
                throw Stop(
                    EXIT_CHECK, "workspace_manager_required",
                    "A config project needs you to manage the workspace ($workspaceSlug): its production connection is made manager of it.",
                    "Ask a workspace admin to run it, or to grant you: thoryn access grant member:<you> manager workspace:<id>.",
                )
            }
            production ?: throw Stop(EXIT_CHECK, "environment_not_found", "The workspace has no production environment.")
            val chosen = chooseSandbox(environments)
            sandbox = chosen.first
            sandboxSlug = chosen.second
        } else {
            sandboxSlug = request.sandbox!!
            val env = environments.firstOrNull { it.slug == sandboxSlug }
                ?: throw Stop(EXIT_CHECK, "environment_not_found", "No sandbox '$sandboxSlug' in workspace $workspaceSlug (or you cannot see it).", "List them with `thoryn env list`; create one with `thoryn env create`.")
            if (env.production) throw productionRefused()
            if (env.suspended) throw Stop(EXIT_CHECK, "environment_suspended", "Sandbox '$sandboxSlug' is suspended.", "Reactivate it with `thoryn env reactivate ${env.id}`, or choose another.")
            if (!mine("environment").contains("environment:${env.id}")) {
                throw Stop(
                    EXIT_CHECK, "environment_manager_required",
                    "You do not manage sandbox '$sandboxSlug'; the project's workload identity is made manager of it, and managers delegate.",
                    "Ask a workspace admin for: thoryn access grant member:<you> manager environment:${env.id}",
                )
            }
            sandbox = env
        }

        // ── Pre-flight: GitHub (reads only) ──────────────────────────────────────────────────────
        when (github.availability()) {
            GitHubCli.Availability.Ready -> Unit
            GitHubCli.Availability.NotInstalled -> throw ghUnavailable(false, workspaceSlug, sandboxSlug, sandbox, production, tenantId)
            GitHubCli.Availability.NotSignedIn -> throw ghUnavailable(true, workspaceSlug, sandboxSlug, sandbox, production, tenantId)
        }
        val manifest = readTemplate()
        checkScopeCeiling(manifest, config && sandbox == null)

        val repoOwner: String
        val repoName: String
        var repository: GhRepository?
        if (request.repo != null) {
            repoOwner = request.repo.substringBefore('/')
            repoName = request.repo.substringAfter('/')
            repository = github.repository(repoOwner, repoName, STEP_PREFLIGHT)
            if (repository == null && github.accountId(repoOwner, STEP_PREFLIGHT) == null) {
                throw Stop(EXIT_CHECK, "github_owner_not_found", "GitHub has no user or organization '$repoOwner' (visible to your gh sign-in).")
            }
        } else {
            if (!Files.isDirectory(request.dir.resolve(".git"))) {
                throw Stop(
                    EXIT_CHECK, "not_a_clone", "${request.dir.toAbsolutePath().normalize()} is not the root of a git clone.",
                    "Run it at the root of a clone of your GitHub repository (or pass --dir), or pass --repo <owner>/<name> to create one.",
                )
            }
            val fullName = github.repositoryOfClone(request.dir, STEP_PREFLIGHT)
            repoOwner = fullName.substringBefore('/')
            repoName = fullName.substringAfter('/')
            repository = github.repository(repoOwner, repoName, STEP_PREFLIGHT)
                ?: throw Stop(EXIT_CHECK, "github_repository_not_found", "gh names this clone's repository $fullName, but GitHub does not show it to your gh sign-in.")
        }
        val reviewerIds = if (config) {
            val ids = request.reviewers.associateWith { github.accountId(it, STEP_PREFLIGHT) }
            val missing = ids.filterValues { it == null }.keys
            if (missing.isNotEmpty()) {
                throw Stop(EXIT_CHECK, "github_reviewer_not_found", "Not a GitHub user: ${missing.joinToString(", ")}.", "Every --reviewer must be an existing GitHub login.")
            }
            ids.values.map { it!! }
        } else {
            emptyList()
        }
        val codeowners = if (config) codeownersFor(request.reviewers) else null
        // --repo on an existing repository: its CODEOWNERS is committed through the API; a different one is a conflict.
        val remoteCodeowners = if (config && request.repo != null && repository != null) {
            github.readFile(repository, CODEOWNERS_PATH, STEP_PREFLIGHT).also { existing ->
                if (existing != null && existing.content != codeowners && !request.force) {
                    throw Stop(
                        EXIT_CHECK, "file_conflicts",
                        "${repository.fullName} already has a different $CODEOWNERS_PATH. Nothing was changed.",
                        "The config project's reviewers must own /.thoryn/environments/production/, /.github/workflows/ and /.github/CODEOWNERS. " +
                            "Merge those two lines into it yourself and re-run, or re-run with --force to replace it.",
                        mapOf("conflicts" to listOf(CODEOWNERS_PATH)),
                    )
                }
            }
        } else {
            null
        }
        val files = if (request.repo == null) planFiles(codeowners, manifest, repository!!) else emptyList()

        val targets = buildList {
            val (sandboxName, sandboxSpec) = manifest.sandboxConnection
            add(Target(sandboxName, sandboxSpec, sandboxSlug, sandbox?.id, null))
            manifest.productionConnection?.let { (name, spec) ->
                add(Target(name, spec, production!!.slug, production.id, manifest.productionGithubEnvironment))
            }
        }
        // An existing repository may already carry trusts: refuse up front when one of ours conflicts.
        repository?.let { repo -> targets.filter { it.envId != null }.forEach { findTrust(it, repo) } }
        // SSO-3669 — the config repository must be reachable, and its production file editable, BEFORE the first change.
        val configProject = request.configRepo?.let { preflightConfigProject(it, "$repoOwner/$repoName") }

        // ── The run ──────────────────────────────────────────────────────────────────────────────
        report["repository"] = linkedMapOf("fullName" to "$repoOwner/$repoName")
        currentStep = STEP_REPOSITORY
        if (repository == null) {
            repository = github.generate(
                request.template, repoOwner, repoName, private = !request.public,
                description = if (config) "Thoryn config project: workspace $workspaceSlug" else "Thoryn application project",
                step = STEP_REPOSITORY,
            )
            step(STEP_REPOSITORY, "created", "${repository.fullName} (${visibility(repository)}) from ${request.template}")
        } else {
            step(STEP_REPOSITORY, "existing", "${repository.fullName} (${visibility(repository)})")
        }
        val repo = repository
        report["repository"] = linkedMapOf(
            "fullName" to repo.fullName, "id" to repo.id, "ownerId" to repo.ownerId, "defaultBranch" to repo.defaultBranch,
            "url" to repo.htmlUrl, "private" to repo.private, "created" to (steps.last().status == "created"),
        )

        val productionGithubEnvironment = manifest.productionGithubEnvironment
        var rulesetId: Long? = null
        var environmentReviewers = false
        if (config) {
            // Production approval, all BEFORE any Thoryn write (a plan refusal leaves nothing in the workspace).
            currentStep = STEP_APPROVAL
            rulesetId = try {
                approvalRuleset(repo, codeowners!!, remoteCodeowners)
            } catch (ex: GhPlanLimitException) {
                throw planLimitRefusal(repo)
            }
            currentStep = STEP_PROTECTION
            val protection = github.protectEnvironment(repo, productionGithubEnvironment!!, reviewerIds, repo.defaultBranch, STEP_PROTECTION)
            environmentReviewers = protection.reviewersActive
            step(
                STEP_PROTECTION, if (protection.changed) "set" else "in place",
                "GitHub environment $productionGithubEnvironment: deploys from ${repo.defaultBranch} only; " +
                    if (environmentReviewers) "required reviewers ${request.reviewers.joinToString(", ")}" else "required reviewers not offered by this GitHub plan (the ruleset carries the approval)",
            )
            report["productionApproval"] = linkedMapOf(
                "mechanisms" to buildList {
                    add("pull_request_ruleset")
                    if (environmentReviewers) add("environment_reviewers")
                },
                "ruleset" to linkedMapOf(
                    "name" to GitHubCli.RULESET_NAME, "id" to rulesetId, "enforcement" to GitHubCli.ENFORCEMENT_ACTIVE, "branch" to repo.defaultBranch,
                    "requiredApprovingReviews" to 1, "codeOwnerReview" to true, "dismissStaleReviews" to true,
                    "blocksForcePush" to true, "blocksDeletion" to true, "bypassActors" to listOf<String>(),
                ),
                "codeowners" to linkedMapOf("path" to CODEOWNERS_PATH, "owners" to request.reviewers, "paths" to CODEOWNED_PATHS),
                "environmentReviewers" to linkedMapOf(
                    "active" to environmentReviewers, "reviewers" to request.reviewers,
                    "note" to if (environmentReviewers) null else "GitHub offers environment reviewers on a private repository only on GitHub Enterprise.",
                ),
                "githubEnvironment" to productionGithubEnvironment,
                "deploymentBranch" to repo.defaultBranch,
            )
        }

        currentStep = STEP_ENVIRONMENTS
        var sandboxName = sandbox?.name ?: "Sandbox $sandboxSlug"
        if (config) {
            val sandboxTarget = targets.first { !it.spec.production }
            if (sandboxTarget.envId == null) {
                sandboxTarget.envId = ensureSandbox(sandboxSlug)
                sandboxName = "Sandbox $sandboxSlug"
                step(STEP_ENVIRONMENTS, "created", "sandbox $sandboxSlug")
            } else {
                step(STEP_ENVIRONMENTS, "existing", "sandbox $sandboxSlug; production ${production!!.slug}")
            }
        } else {
            step(STEP_ENVIRONMENTS, "existing", "sandbox $sandboxSlug")
        }

        currentStep = STEP_TRUSTS
        val connections = mutableListOf<Map<String, Any?>>()
        val clientIds = linkedMapOf<String, String>()
        targets.forEach { t ->
            val (trust, adopted) = ensureTrust(t, repo)
            val clientId = text(trust, "clientId") ?: throw Stop(EXIT_HTTP, "invalid_response", "product-api returned a trust without a clientId.")
            clientIds[t.connection] = clientId
            t.trust = trust
            step(
                STEP_TRUSTS, if (adopted) "adopted" else "created",
                "${t.connection}: ${text(trust, "name")} → $clientId (in ${t.envSlug}${t.githubEnvironment?.let { ", GitHub environment $it" } ?: ""})",
            )
            connections += linkedMapOf(
                "connection" to t.connection, "environment" to t.envSlug, "production" to t.spec.production,
                "githubEnvironment" to t.githubEnvironment, "scopes" to t.spec.scopes,
                "trustId" to text(trust, "id"), "trustName" to text(trust, "name"), "clientId" to clientId, "adopted" to adopted,
            )
        }
        report["connections"] = connections

        currentStep = STEP_ACCESS
        val grants = mutableListOf<Map<String, Any?>>()
        targets.forEach { t ->
            val subject = "client:" + encodeId(clientIds.getValue(t.connection))
            val objectRef = if (t.spec.grant.on == StarterTemplateManifest.GRANT_ON_WORKSPACE) "workspace:${encodeId(tenantId!!)}" else "environment:${t.envId}"
            // An existing grant is left alone — read first, so a re-run writes nothing here.
            if (grantExists(subject, t.spec.grant.relation, objectRef)) {
                step(STEP_ACCESS, "existing", "$subject ${t.spec.grant.relation} $objectRef")
                grants += linkedMapOf("subject" to subject, "relation" to t.spec.grant.relation, "object" to objectRef, "existing" to true)
                return@forEach
            }
            try {
                thoryn.workspace.createGrant(subject, t.spec.grant.relation, objectRef)
            } catch (ex: ProductApiException) {
                if (t.spec.grant.on == StarterTemplateManifest.GRANT_ON_WORKSPACE && ex.httpStatus == 404) {
                    throw Stop(
                        EXIT_HTTP, "workspace_grant_unavailable",
                        "This platform cannot yet grant a machine client workspace-wide management (manager on workspace:<id>) through its access-grants API.",
                        "Everything before this step is set up; nothing was set on GitHub's variables yet. Re-run the same command once the platform supports it.",
                    )
                }
                throw ex
            }
            step(STEP_ACCESS, "granted", "$subject ${t.spec.grant.relation} $objectRef")
            grants += linkedMapOf("subject" to subject, "relation" to t.spec.grant.relation, "object" to objectRef, "existing" to false)
        }
        report["grants"] = grants

        val values = linkedMapOf(
            StarterTemplateManifest.THORYN_ISSUER to session.issuer,
            StarterTemplateManifest.THORYN_WORKSPACE to workspaceSlug,
        )
        targets.forEach { t ->
            values[t.spec.clientIdVariable] = clientIds.getValue(t.connection)
            t.spec.environmentVariable?.let { values[it] = t.envSlug }
        }
        currentStep = STEP_VARIABLES
        val variables = mutableListOf<Map<String, Any?>>()
        // Read before write: a variable already at its value is not set again (a re-run makes no writes).
        val current = mutableMapOf<String?, Map<String, String>?>()
        fun currentValue(name: String, environment: String?): String? =
            current.getOrPut(environment) { github.listVariables(repo, environment) }?.get(name)
        // Repository-level first; the production-environment variable only once its protection is confirmed.
        manifest.variables.entries.sortedBy { it.value.level == StarterTemplateManifest.LEVEL_ENVIRONMENT }.forEach { (name, v) ->
            val value = values[name] ?: throw Stop(EXIT_CHECK, "starter_template_invalid", "The template declares $name, which has no value.")
            if (v.environment != null) {
                val required = if (environmentReviewers) reviewerIds else emptyList()
                val protectedNow = rulesetId != null && github.rulesetActive(repo, rulesetId, STEP_VARIABLES) &&
                    github.environmentProtected(repo, v.environment, required, STEP_VARIABLES)
                if (!protectedNow) {
                    throw Stop(
                        EXIT_GH, "github_environment_unprotected",
                        "The production approval (ruleset ${GitHubCli.RULESET_NAME} on ${repo.defaultBranch}, and GitHub environment ${v.environment}) " +
                            "is not in place, so $name was not set.",
                        "Check the repository's rulesets and the environment's protection rules, then re-run.",
                    )
                }
            }
            val unchanged = currentValue(name, v.environment) == value
            if (!unchanged) github.setVariable(repo, name, value, v.environment, STEP_VARIABLES)
            variables += linkedMapOf("name" to name, "value" to value, "level" to v.level, "environment" to v.environment, "changed" to !unchanged)
        }
        val repoLevel = variables.filter { it["environment"] == null }.map { it["name"] }
        val envLevel = variables.filter { it["environment"] != null }
        val changedVariables = variables.count { it["changed"] == true }
        step(
            STEP_VARIABLES, if (changedVariables > 0) "set" else "unchanged",
            "${repoLevel.joinToString(", ")} (repository)" + envLevel.joinToString("") { "; ${it["name"]} (environment ${it["environment"]})" } +
                if (changedVariables == variables.size) "" else "; ${variables.size - changedVariables} already at their value",
        )
        report["variables"] = variables

        currentStep = STEP_FILES
        if (request.repo == null) writeFiles(files)
        val createdRepo = steps.first { it.name == STEP_REPOSITORY }.status == "created"
        report["hasTemplateFiles"] = when {
            request.repo == null || createdRepo -> true
            else -> github.fileExists(repo.fullName, StarterTemplateManifest.PATH, STEP_VARIABLES)
        }
        currentStep = STEP_PROVISIONING
        seedFiles(targets, repo, workspaceSlug, sandboxSlug, sandboxName, createdRepo)
        if (configProject != null) {
            currentStep = STEP_CONFIG_PROJECT
            proposeProductionClient(configProject, repo)
        }
        report["steps"] = steps.map { linkedMapOf("step" to it.name, "status" to it.status, "detail" to it.detail) }
        report["nextSteps"] = nextSteps(repo, config, productionGithubEnvironment)
        return report
    }

    // ── Pre-flight helpers ───────────────────────────────────────────────────────────────────────

    private fun environments(): List<Env> {
        val body = thoryn.workspace.listEnvironments()
        val items = (body["environments"] ?: body["data"] ?: body).takeIf { it.isArray }?.toList().orEmpty()
        return items.mapNotNull { n ->
            val id = text(n, "id") ?: return@mapNotNull null
            val slug = text(n, "slug") ?: return@mapNotNull null
            Env(id, slug, text(n, "name"), production = text(n, "kind") == "production", suspended = n["suspended"]?.asBoolean(false) ?: false)
        }
    }

    private fun mine(type: String): Set<String> {
        val body = thoryn.workspace.listMyAccess(type, "manager")
        return body["data"]?.takeIf { it.isArray }?.toList()?.mapNotNull { it.asString() }?.toSet().orEmpty()
    }

    /** The config project's sandbox: the named one, else the only one, else a new `sandbox`. */
    private fun chooseSandbox(environments: List<Env>): Pair<Env?, String> {
        val named = request.sandbox
        if (named != null) {
            val env = environments.firstOrNull { it.slug == named } ?: return null to named
            if (env.production) throw Stop(EXIT_USAGE, "sandbox_required", "'$named' is the production environment; --sandbox names a sandbox.")
            if (env.suspended) throw Stop(EXIT_CHECK, "environment_suspended", "Sandbox '$named' is suspended.", "Reactivate it with `thoryn env reactivate ${env.id}`, or name another.")
            return env to named
        }
        val sandboxes = environments.filter { !it.production && !it.suspended }
        return when (sandboxes.size) {
            0 -> if (environments.any { it.slug == DEFAULT_SANDBOX }) {
                throw Stop(EXIT_CHECK, "environment_suspended", "Sandbox '$DEFAULT_SANDBOX' is suspended.", "Reactivate it, or name another with --sandbox.")
            } else {
                null to DEFAULT_SANDBOX
            }
            1 -> sandboxes.single() to sandboxes.single().slug
            else -> throw Stop(
                EXIT_USAGE, "sandbox_ambiguous",
                "The workspace has several sandboxes (${sandboxes.joinToString(", ") { it.slug }}); name the config project's sandbox.",
                "Re-run with --sandbox <slug>.",
            )
        }
    }

    private fun readTemplate(): StarterTemplateManifest {
        val raw = github.templateDeclaration(request.template, STEP_PREFLIGHT)
            ?: throw Stop(
                EXIT_CHECK, "starter_template_unavailable",
                "The template repository ${request.template} has no ${StarterTemplateManifest.PATH} on its default branch.",
                "The template may not be published yet. Nothing was changed; re-run once it is.",
            )
        val version = StarterTemplateManifest.apiVersionOf(raw)
        if (version != StarterTemplateManifest.API_VERSION) {
            throw Stop(
                EXIT_CHECK, "starter_template_invalid",
                "The template ${request.template} declares apiVersion '${version ?: "none"}'; this CLI needs ${StarterTemplateManifest.API_VERSION}.",
                "The published template is older than this CLI. Nothing was changed; re-run once the v2 template is published.",
            )
        }
        return try {
            StarterTemplateManifest.parse(raw, request.kind.templateKind)
        } catch (ex: StarterTemplateManifest.TemplateException) {
            throw Stop(EXIT_CHECK, "starter_template_invalid", "The template ${request.template} breaks the v2 contract: ${ex.message}.", "Nothing was changed.")
        }
    }

    /**
     * The scope ceiling (transitive, never trimmed): a trust carries exactly the template's scopes, and may carry
     * only scopes the caller holds; the calls themselves need their own scopes. product-api enforces all of it —
     * checking here means a refusal creates nothing. Skipped when the token does not say what it carries.
     */
    private fun checkScopeCeiling(manifest: StarterTemplateManifest, createsSandbox: Boolean) {
        val held = thoryn.workspace.sessionScopes() ?: return
        val needed = linkedSetOf(
            "tenant:environments.read", "tenant:workload-identity.read", "tenant:workload-identity.write",
            "tenant:access.read", "tenant:access.write",
        )
        if (createsSandbox) needed += "tenant:environments.write"
        manifest.connections.values.forEach { needed += it.scopes }
        val missing = needed.filterNot { it in held }
        if (missing.isNotEmpty()) {
            throw Stop(
                EXIT_CHECK, "scope_not_grantable",
                "Your session does not hold ${missing.joinToString(" ")} — the template's trusts carry exactly its scopes, and you can grant only scopes you hold.",
                "Sign in again with them: `thoryn login` (its default scopes include them) or `thoryn login --scope \"${missing.joinToString(" ")}\"`.",
                mapOf("missingScopes" to missing),
            )
        }
    }

    private fun planFiles(codeowners: String?, manifest: StarterTemplateManifest, repository: GhRepository): List<PlannedFile> {
        val tarball = github.templateTarball(request.template, STEP_PREFLIGHT)
        val entries = try {
            TemplateArchive.read(tarball)
        } catch (ex: TemplateArchive.ArchiveException) {
            throw Stop(EXIT_CHECK, "starter_template_invalid", "The template's files could not be read: ${ex.message}.")
        }
        val root = request.dir.toAbsolutePath().normalize()
        // A config project's CODEOWNERS (the reviewers own production, the workflows and CODEOWNERS) replaces the template's;
        // the seeded `.thoryn/` files (connection.json + the starter provision.yaml per connection) replace the template's
        // placeholders at those paths — they are rendered once the trusts exist (see seedFiles).
        val seeded = manifest.connections.values.flatMap { listOf(it.provisionFile, ProjectSeeds.connectionPath(it.provisionFile)) }.toSet()
        val templateEntries = entries.filter { it.path !in seeded }
        val all = if (codeowners == null) templateEntries else templateEntries.filter { it.path != CODEOWNERS_PATH } + TemplateArchive.Entry(CODEOWNERS_PATH, codeowners.toByteArray(), false)
        // An existing connection.json that is not this repository's own (another repository's, or a client_credentials one)
        // is a conflict like any other differing file; one this command wrote is re-rendered. provision.yaml is never a
        // conflict: an existing one is kept as it is.
        val seedConflicts = manifest.connections.values.map { ProjectSeeds.connectionPath(it.provisionFile) }.filter { path ->
            val target = root.resolve(path).normalize()
            Files.exists(target) && !(Files.isRegularFile(target) && ProjectSeeds.isOurConnection(Files.readAllBytes(target), repository.id))
        }
        val planned = all.map { e ->
            val target = root.resolve(e.path).normalize()
            if (!target.startsWith(root) || e.path.split('/').firstOrNull() == ".git") {
                throw Stop(EXIT_CHECK, "starter_template_invalid", "The template has a file outside the repository (${e.path}).")
            }
            val action = when {
                !Files.exists(target) -> FileAction.WRITE
                Files.isRegularFile(target) && Files.readAllBytes(target).contentEquals(e.bytes) -> FileAction.SAME
                else -> FileAction.OVERWRITE
            }
            PlannedFile(e, target, action)
        }
        val conflicts = planned.filter { it.action == FileAction.OVERWRITE }.map { it.entry.path } + seedConflicts
        if (conflicts.isNotEmpty() && !request.force) {
            throw Stop(
                EXIT_CHECK, "file_conflicts",
                "These files already exist with different content: ${conflicts.joinToString(", ")}. Nothing was changed.",
                "Move them aside (or commit them elsewhere) and re-run, or re-run with --force to overwrite them.",
                mapOf("conflicts" to conflicts),
            )
        }
        return planned
    }

    // ── Steps ────────────────────────────────────────────────────────────────────────────────────

    private fun ensureSandbox(slug: String): String {
        try {
            val created = thoryn.workspace.createEnvironment(mapOf("slug" to slug, "name" to "Sandbox $slug"))
            text(created, "id")?.let { return it }
        } catch (ex: ProductApiException) {
            if (ex.errorCode != "environment_slug_exists") throw ex
        }
        val env = environments().firstOrNull { it.slug == slug }
            ?: throw Stop(EXIT_HTTP, "environment_not_found", "Sandbox '$slug' could not be created or found.")
        if (env.production) throw Stop(EXIT_USAGE, "sandbox_required", "'$slug' is the production environment.")
        return env.id
    }

    /**
     * The default-branch approval: the `thoryn-production-approval` ruleset and, with --repo, the reviewers' CODEOWNERS.
     *
     * An ACTIVE ruleset is never disabled or weakened — not to commit CODEOWNERS, not with --force: that would put an
     * unreviewed change on the default branch.
     *  - **The ruleset does not exist yet** (this run creates it; nothing was protected before): it is created
     *    disabled, CODEOWNERS is committed, then it is enforced — or created active when there is nothing to commit.
     *  - **The ruleset exists** (active, evaluating, or disabled by someone): it is brought back to the required
     *    shape and enforced FIRST (that only tightens); a CODEOWNERS change then goes through a pull request from the
     *    deterministic branch `thoryn/codeowners` (reused on a re-run), and waits for review.
     * In an existing clone, CODEOWNERS is written to the working tree and reaches GitHub with the user's pull request.
     * Throws [GhPlanLimitException] when GitHub has no rulesets for this private repository (GitHub Free).
     */
    private fun approvalRuleset(repo: GhRepository, codeowners: String, remote: GitHubCli.RepoFile?): Long {
        val createdRepo = steps.firstOrNull { it.name == STEP_REPOSITORY }?.status == "created"
        var existing = remote
        if (request.repo != null && createdRepo) {
            github.awaitDefaultBranch(repo, STEP_APPROVAL)
            existing = github.readFile(repo, CODEOWNERS_PATH, STEP_APPROVAL)
        }
        val change = request.repo != null && existing?.content != codeowners
        val found = github.rulesetId(repo, GitHubCli.RULESET_NAME, STEP_APPROVAL)
        var pullRequest: String? = null
        var inShape = false
        val id: Long
        if (found == null) {
            if (change) {
                id = github.createRuleset(repo, GitHubCli.ENFORCEMENT_DISABLED, STEP_APPROVAL)
                github.writeFile(repo, CODEOWNERS_PATH, codeowners, existing?.sha, CODEOWNERS_MESSAGE, STEP_APPROVAL)
                github.updateRuleset(repo, id, GitHubCli.ENFORCEMENT_ACTIVE, STEP_APPROVAL)
            } else {
                id = github.createRuleset(repo, GitHubCli.ENFORCEMENT_ACTIVE, STEP_APPROVAL)
            }
        } else {
            id = found
            // Read first: a ruleset already in the required shape is left alone (a re-run makes no writes).
            inShape = github.rulesetInShape(repo, id, STEP_APPROVAL)
            if (!inShape) github.updateRuleset(repo, id, GitHubCli.ENFORCEMENT_ACTIVE, STEP_APPROVAL)
            if (change) {
                pullRequest = github.proposeFile(
                    repo, CODEOWNERS_PATH, codeowners, GitHubCli.CODEOWNERS_BRANCH, CODEOWNERS_MESSAGE,
                    "Proposed by `thoryn project init config`: the production approval needs these code owners. " +
                        "The default branch is protected by ${GitHubCli.RULESET_NAME}, so this change needs a review like any other.",
                    STEP_APPROVAL,
                )
            }
        }
        report["codeownersPullRequest"] = pullRequest
        step(
            STEP_CODEOWNERS,
            when {
                request.repo == null -> "pending"
                pullRequest != null -> "pending review"
                change -> "committed"
                else -> "unchanged"
            },
            when {
                pullRequest != null -> "CODEOWNERS update pending review: $pullRequest"
                else -> "$CODEOWNERS_PATH: ${request.reviewers.joinToString(" ") { "@$it" }} own ${CODEOWNED_PATHS.joinToString(", ")}" +
                    if (request.repo == null) " (written with the template's files; it lands with your pull request)" else ""
            },
        )
        step(
            STEP_RULESET, if (found == null) "created" else if (inShape) "in place" else "enforced",
            "${GitHubCli.RULESET_NAME} on ${repo.defaultBranch}: pull request with 1 approval + code-owner review, stale approvals dismissed, " +
                "no force-push or deletion, no bypass",
        )
        return id
    }

    /** True when [subject] already holds [relation] on [objectRef] — read so an existing grant is left alone. */
    private fun grantExists(subject: String, relation: String, objectRef: String): Boolean = try {
        val body = thoryn.workspace.listGrants(objectRef = objectRef)
        body["data"]?.takeIf { it.isArray }?.toList().orEmpty().any { text(it, "subject") == subject && text(it, "relation") == relation }
    } catch (ex: ProductApiException) {
        false // the create decides, and names the real refusal
    }

    // ── The seeded .thoryn/ files (ADR 2026-10-13 §3 and §6) ────────────────────────────────────

    /**
     * Seed, per connection, its `connection.json` (derived from the trust, re-rendered when it differs) and — when
     * absent — a starter `provision.yaml`, so the repository is in the converge loop from its first commit:
     *  - **in a clone**: written to the working tree; they land with the user's commit or pull request;
     *  - **`--repo` that CREATED the repository this run**: committed to the default branch for an app project;
     *    proposed through a pull request from [ProjectSeeds.PROVISIONING_BRANCH] for a config project, whose default
     *    branch the approval ruleset now protects;
     *  - **`--repo` on an existing repository**: not added — the same rule as the template's files; the report says
     *    whether they are present, and the next steps say how to add them (run inside a clone).
     */
    private fun seedFiles(targets: List<Target>, repo: GhRepository, workspaceSlug: String, sandboxSlug: String, sandboxName: String, createdRepo: Boolean) {
        val seeds = targets.flatMap { t ->
            val trust = t.trust ?: throw Stop(EXIT_HTTP, "invalid_response", "No trust for connection ${t.connection}.")
            val clientId = text(trust, "clientId")!!
            val provision = when {
                request.kind == Kind.APP -> ProjectSeeds.appProvisionYaml(repo, request.stack, sandboxSlug, clientId)
                t.spec.production -> ProjectSeeds.configProductionProvisionYaml(repo, sandboxSlug, sandboxName, clientId, t.githubEnvironment!!)
                else -> ProjectSeeds.configSandboxProvisionYaml(repo, sandboxSlug, clientId)
            }
            listOf(
                ProjectSeeds.Seed(t.connectionPath, ProjectSeeds.connectionJson(workspaceSlug, trust, t.envSlug, t.spec.production), ProjectSeeds.KIND_CONNECTION),
                ProjectSeeds.Seed(t.spec.provisionFile, provision, ProjectSeeds.KIND_PROVISION),
            )
        }
        val files = mutableListOf<Map<String, Any?>>()
        var proposal: GitHubCli.Proposal? = null
        fun record(seed: ProjectSeeds.Seed, status: String) {
            files += linkedMapOf("path" to seed.path, "kind" to seed.kind, "status" to status)
        }
        when {
            request.repo == null -> {
                val root = request.dir.toAbsolutePath().normalize()
                seeds.forEach { s ->
                    val target = root.resolve(s.path).normalize()
                    val bytes = s.content.toByteArray()
                    val status = when {
                        !Files.exists(target) -> "written"
                        s.kind == ProjectSeeds.KIND_PROVISION -> "kept" // the file is in control: never overwritten
                        Files.isRegularFile(target) && Files.readAllBytes(target).contentEquals(bytes) -> "unchanged"
                        else -> "rewritten"
                    }
                    if (status == "written" || status == "rewritten") {
                        target.parent?.let { Files.createDirectories(it) }
                        Files.write(target, bytes)
                    }
                    record(s, status)
                }
            }
            createdRepo && request.kind == Kind.CONFIG -> {
                // The default branch is protected now: the seeds go through a reviewed pull request, like CODEOWNERS would.
                proposal = github.proposeFiles(
                    repo, seeds.map { it.path to it.content }, ProjectSeeds.PROVISIONING_BRANCH, ProjectSeeds.PROVISIONING_MESSAGE,
                    "Proposed by `thoryn project init config`: each connection's `connection.json` (its workload identity, no secret) and a starter " +
                        "`provision.yaml`, so this repository converges its own configuration — `thoryn provision plan` on a pull request, `apply` on ${repo.defaultBranch}.",
                    STEP_PROVISIONING,
                )
                seeds.forEach { record(it, if (proposal!!.changed) "pending review" else "open") }
            }
            createdRepo -> {
                github.awaitDefaultBranch(repo, STEP_PROVISIONING)
                seeds.forEach { s ->
                    val existing = github.readFile(repo, s.path, STEP_PROVISIONING)
                    if (existing?.content == s.content) {
                        record(s, "unchanged")
                    } else {
                        github.writeFile(repo, s.path, s.content, existing?.sha, ProjectSeeds.PROVISIONING_MESSAGE, STEP_PROVISIONING)
                        record(s, "committed")
                    }
                }
            }
            // An existing repository: not added (the template's files aren't either) — except a config project whose earlier run
            // proposed them: that pull request is converged (idempotent) and named again.
            request.kind == Kind.CONFIG && github.openPullRequest(repo, ProjectSeeds.PROVISIONING_BRANCH, STEP_PROVISIONING) != null -> {
                proposal = github.proposeFiles(
                    repo, seeds.map { it.path to it.content }, ProjectSeeds.PROVISIONING_BRANCH, ProjectSeeds.PROVISIONING_MESSAGE, "", STEP_PROVISIONING,
                )
                seeds.forEach { record(it, if (proposal!!.changed) "pending review" else "open") }
            }
            else -> seeds.forEach { s -> record(s, if (github.fileExists(repo.fullName, s.path, STEP_PROVISIONING)) "present" else "not added") }
        }
        val pullRequest = proposal?.url
        report["provisioning"] = linkedMapOf("files" to files, "pullRequest" to pullRequest)
        val statuses = files.map { it["status"] as String }
        val status = when {
            proposal != null -> if (proposal.changed) "pending review" else "open"
            "committed" in statuses -> "committed"
            "written" in statuses || "rewritten" in statuses -> "written"
            "not added" in statuses -> "not added"
            else -> "unchanged"
        }
        step(
            STEP_PROVISIONING, status,
            (pullRequest?.let { "pull request ${if (proposal!!.changed) "pending review" else "open"}: $it — " } ?: "") + files.joinToString(", ") { "${it["path"]} (${it["status"]})" },
        )
    }

    /** Adopt a matching trust (by name, or one the orchestrator made — by its pins), else create it. */
    private fun ensureTrust(t: Target, repo: GhRepository): Pair<JsonNode, Boolean> {
        findTrust(t, repo)?.let { return it to true }
        val client = thoryn.inEnvironment(t.envSlug)
        val body = linkedMapOf(
            "name" to trustName(t.connection, repo.id),
            "provider" to "github_actions",
            "github" to linkedMapOf(
                "owner" to repo.ownerLogin,
                "ownerId" to repo.ownerId,
                "repository" to repo.name,
                "repositoryId" to repo.id,
                "environment" to t.githubEnvironment,
                "ref" to refOf(t, repo),
                "githubHostedRunnersOnly" to false,
            ),
            "scopes" to t.spec.scopes,
            "confirmProduction" to t.spec.production.takeIf { it },
        )
        return try {
            client.createWorkloadIdentityTrust(body) to false
        } catch (ex: ProductApiException) {
            if (ex.errorCode == "workload_identity_trust_name_taken") findTrust(t, repo)?.let { return it to true }
            throw ex
        }
    }

    /** The existing trust this connection should use, or null. Throws when the deterministic name is taken by a different trust. */
    private fun findTrust(t: Target, repo: GhRepository): JsonNode? {
        val client = thoryn.inEnvironment(t.envSlug)
        val items = mutableListOf<JsonNode>()
        var cursor: String? = null
        for (page in 0 until MAX_TRUST_PAGES) {
            val body = client.listWorkloadIdentityTrusts(null, cursor)
            items += body["data"]?.takeIf { it.isArray }?.toList().orEmpty()
            cursor = body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            if (cursor == null || body["pagination"]?.get("hasMore")?.asBoolean(true) == false) break
        }
        val name = trustName(t.connection, repo.id)
        items.firstOrNull { text(it, "name") == name }?.let { existing ->
            if (matches(existing, t, repo)) return existing
            throw Stop(
                EXIT_CHECK, "workload_identity_trust_conflict",
                "Trust '$name' in ${t.envSlug} exists but pins another repository, GitHub environment or ref, or carries other scopes than the template's.",
                "Delete it (thoryn workload-identity trusts delete ${text(existing, "id")} --environment ${t.envSlug}) and re-run.",
            )
        }
        return items.firstOrNull { matches(it, t, repo) }
    }

    private fun matches(trust: JsonNode, t: Target, repo: GhRepository): Boolean {
        val gh = trust["github"] ?: return false
        if (gh["repositoryId"]?.asLong(0) != repo.id) return false
        if (text(gh, "environment") != t.githubEnvironment) return false
        if (text(gh, "ref") != refOf(t, repo)) return false
        if (trust["enabled"]?.asBoolean(true) == false) return false
        val scopes = trust["scopes"]?.takeIf { it.isArray }?.toList()?.mapNotNull { it.asString() }?.toSet().orEmpty()
        return scopes == t.spec.scopes.toSet()
    }

    private fun refOf(t: Target, repo: GhRepository): String? = if (t.spec.production) "refs/heads/${repo.defaultBranch}" else null

    private fun writeFiles(files: List<PlannedFile>) {
        val written = mutableListOf<String>()
        val overwritten = mutableListOf<String>()
        val unchanged = mutableListOf<String>()
        files.forEach { f ->
            when (f.action) {
                FileAction.SAME -> unchanged += f.entry.path
                FileAction.WRITE, FileAction.OVERWRITE -> {
                    f.target.parent?.let { Files.createDirectories(it) }
                    Files.write(f.target, f.entry.bytes)
                    if (f.entry.executable) makeExecutable(f.target)
                    if (f.action == FileAction.WRITE) written += f.entry.path else overwritten += f.entry.path
                }
            }
        }
        val detail = buildList {
            add("${written.size} added")
            if (overwritten.isNotEmpty()) add("${overwritten.size} overwritten (--force)")
            add("${unchanged.size} already identical")
        }.joinToString(", ")
        step(STEP_FILES, if (written.isEmpty() && overwritten.isEmpty()) "unchanged" else "written", detail)
        report["files"] = linkedMapOf("added" to written, "overwritten" to overwritten, "unchanged" to unchanged)
    }

    private fun makeExecutable(path: Path) {
        try {
            val perms = Files.getPosixFilePermissions(path).toMutableSet()
            perms += setOf(PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_EXECUTE)
            Files.setPosixFilePermissions(path, perms)
        } catch (_: UnsupportedOperationException) {
            // Not a POSIX file system (Windows): git keeps the mode the template repository recorded only on POSIX.
        }
    }

    private fun nextSteps(repo: GhRepository, config: Boolean, productionGithubEnvironment: String?): List<String> = buildList {
        val createdRepo = steps.firstOrNull { it.name == STEP_REPOSITORY }?.status == "created"
        when {
            request.repo == null -> {
                @Suppress("UNCHECKED_CAST")
                val files = report["files"] as Map<String, List<String>>
                val touched = (files["added"].orEmpty() + files["overwritten"].orEmpty() + seededPaths("written", "rewritten"))
                    .map { it.substringBefore('/') }.distinct().sorted()
                if (touched.isNotEmpty() && config) {
                    // The default branch now takes reviewed pull requests only (the approval ruleset).
                    add(
                        "The default branch now accepts only a reviewed pull request. Push the files on a branch and open one: " +
                            "git switch -c thoryn-config && git add ${touched.joinToString(" ")} && git commit -m \"Add the Thoryn config project\" && " +
                            "git push -u origin thoryn-config && gh pr create --fill — then ${request.reviewers.joinToString(" or ")} approves it.",
                    )
                } else if (touched.isNotEmpty()) {
                    add("Commit and push the added files: git add ${touched.joinToString(" ")} && git commit -m \"Add the Thoryn ${request.kind.label} project\" && git push")
                } else {
                    add("The template's files are already in this clone; push a commit (or re-run the workflow) to start a run.")
                }
                add("The first run after the push reads the variables that are now set; no secret is stored anywhere.")
            }
            createdRepo -> {
                add("Clone it: gh repo clone ${repo.fullName}")
                val committed = seededPaths("committed")
                if (committed.isNotEmpty()) {
                    add(
                        "${committed.joinToString(" and ")} are committed on ${repo.defaultBranch}: the repository converges its own provisioning " +
                            "(`thoryn provision plan` on a pull request, `thoryn provision apply` on ${repo.defaultBranch}); that commit's run uses the variables.",
                    )
                } else {
                    add(
                        "GitHub's initial commit started a first workflow run before the variables existed, so its Thoryn jobs skipped. " +
                            "Re-run it (gh run list --repo ${repo.fullName}, then gh run rerun <id> --repo ${repo.fullName}) or push a commit; that run uses the variables.",
                    )
                }
            }
            report["hasTemplateFiles"] == false || seededPaths("not added").isNotEmpty() -> add(
                "${repo.fullName} does not contain the template's files" +
                    (if (seededPaths("not added").isNotEmpty()) " or its .thoryn/ connection.json + provision.yaml" else "") +
                    " yet: clone it and run `thoryn project init ${request.kind.label} …` inside the clone (without --repo) to add them; the steps above are kept and re-used.",
            )
            else -> add("Push a commit (or re-run the workflow) to start a run with the variables set.")
        }
        (report["codeownersPullRequest"] as? String)?.let {
            add("CODEOWNERS update pending review: $it — the ruleset already requires an approved pull request; merge this one to make the reviewers the code owners.")
        }
        @Suppress("UNCHECKED_CAST")
        ((report["provisioning"] as? Map<String, Any?>)?.get("pullRequest") as? String)?.let {
            add(
                "Provisioning files pending review: $it — each connection's connection.json and starter provision.yaml. Merge it, and the repository " +
                    "converges its own configuration from then on (`thoryn provision plan` on a pull request, `thoryn provision apply` on ${repo.defaultBranch}).",
            )
        }
        @Suppress("UNCHECKED_CAST")
        (report["configProject"] as? Map<String, Any?>)?.let { cp ->
            val variable = ProjectSeeds.PRODUCTION_CLIENT_ID_VARIABLE
            val environment = ProjectSeeds.PRODUCTION_GITHUB_ENVIRONMENT
            val url = cp["pullRequest"] as? String
            if (url != null) {
                add(
                    "Production client pending review: $url — a reviewer of ${cp["repository"]} merges it, and the config project's production run " +
                        "(approved in its GitHub environment) creates the client and publishes its id to ${repo.fullName} as $variable on its GitHub " +
                        "environment `$environment` (created when absent). Until then the app has no production client. If that publish cannot reach " +
                        "${repo.fullName}, set it by hand with the id from ${ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE}'s receipt: " +
                        "gh variable set $variable --body <id> --repo ${repo.fullName} --env $environment",
                )
            } else {
                add(
                    "${cp["repository"]} already declares the production client of ${repo.fullName}; the config project's production run publishes its id " +
                        "as $variable on ${repo.fullName}'s GitHub environment `$environment`.",
                )
            }
        }
        if (!config && request.configRepo == null) {
            add(
                "No production client was proposed. Re-run with --config-repo <owner>/<config-repo> --production-url https://<where the app runs> to open a " +
                    "pull request on the workspace's config repository declaring one (public, PKCE; its id is published to this repository's `production` GitHub environment).",
            )
        }
        if (config) {
            val reviewers = request.reviewers.joinToString(", ")
            @Suppress("UNCHECKED_CAST")
            val envReviewers = ((report["productionApproval"] as? Map<String, Any?>)?.get("mechanisms") as? List<String>)?.contains("environment_reviewers") == true
            add(
                "Production changes need a pull request to ${repo.defaultBranch} approved by a code owner ($reviewers); only ${repo.defaultBranch} deploys to " +
                    "the GitHub environment $productionGithubEnvironment" +
                    if (envReviewers) ", and each production run also waits for approval by: $reviewers." else ". (Environment reviewers are not offered by this GitHub plan.)",
            )
        }
    }

    /** The seeded `.thoryn/` paths whose status is one of [statuses]. */
    @Suppress("UNCHECKED_CAST")
    private fun seededPaths(vararg statuses: String): List<String> =
        ((report["provisioning"] as? Map<String, Any?>)?.get("files") as? List<Map<String, Any?>>).orEmpty()
            .filter { it["status"] in statuses }.map { it["path"] as String }

    // ── SSO-3669: the app's production client, proposed on the config repository (ADR 2026-10-13 §1) ──

    /**
     * Pre-flight (reads only): the config repository as the signed-in `gh` sees it — absent or invisible stops the
     * run with the by-hand steps; it is NEVER created here — and its production-section file converged with this
     * app's production client ([ProjectSeeds.productionClientEntry]): the entry is appended when absent (every other
     * line of the file is kept), replaced when it differs, and left alone when identical. The result must be a file
     * the provisioning loader accepts, or the run stops before the first change.
     */
    private fun preflightConfigProject(configRepo: String, appRepository: String): ConfigProject {
        val path = ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE
        val manual = configProjectManualSteps(configRepo, appRepository)
        val repository = github.repository(configRepo.substringBefore('/'), configRepo.substringAfter('/'), STEP_PREFLIGHT)
            ?: throw Stop(
                EXIT_CHECK, "config_repository_not_found",
                "GitHub does not show the config repository $configRepo to your gh sign-in: it does not exist, or you have no access to it. " +
                    "Nothing was changed — not on GitHub, not in Thoryn.",
                "`thoryn project init app` never creates the config repository. Create it (thoryn project init config --repo $configRepo " +
                    "--reviewer <login> --confirm-production) or ask for access, then re-run: ${request.commandLine}",
                mapOf("manualSteps" to manual, "configRepository" to configRepo),
            )
        val existing = github.readFile(repository, path, STEP_PREFLIGHT)
        val entry = ProjectSeeds.productionClientEntry(appRepository, request.productionUrl!!)
        val source = "$configRepo:$path"
        val converged = try {
            ProvisionYamlEdit.converge(existing?.content, entry, source, ProjectSeeds.productionClientHeader(appRepository)) {
                ProjectSeeds.isProductionClientOf(it, appRepository)
            }.also { ProvisionFile.parse(it.content.toByteArray(), source) }
        } catch (ex: ProvisionException) {
            throw Stop(
                EXIT_CHECK, "config_provision_file_unusable",
                "The production client cannot be added to $source: ${ex.message}. Nothing was changed — not on GitHub, not in Thoryn.",
                "Fix the file on ${repository.defaultBranch} (or add the entry by hand — the steps below) and re-run: ${request.commandLine}",
                mapOf("manualSteps" to manual, "configRepository" to configRepo),
            )
        }
        return ConfigProject(repository, appRepository, entry, converged)
    }

    /**
     * Propose the converged production-section file through the deterministic branch and ONE pull request
     * ([GitHubCli.proposeFiles]: the branch is created from the default branch when absent, the file committed only
     * where it differs from the branch's copy, an open pull request reused) — or nothing, when the default branch
     * already declares the entry as it must be. The default branch is never written; nothing is merged.
     */
    private fun proposeProductionClient(cp: ConfigProject, appRepo: GhRepository) {
        val path = ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE
        val spec = cp.entry["spec"]
        val target = cp.entry["publishTo"].get(0)
        val application = linkedMapOf<String, Any?>(
            "name" to cp.name, "clientType" to text(spec, "clientType"),
            "grantTypes" to spec["grantTypes"].toList().map { it.asString() }, "scopes" to spec["scopes"].toList().map { it.asString() },
            "redirectUris" to spec["redirectUris"].toList().map { it.asString() },
            "postLogoutRedirectUris" to spec["postLogoutRedirectUris"].toList().map { it.asString() },
            "publishTo" to linkedMapOf(
                "kind" to text(target, "kind"), "repository" to text(target, "repository"),
                "environment" to text(target, "environment"), "name" to text(target, "name"),
            ),
        )
        val outcome = cp.converged.outcome
        var pullRequest: String? = null
        var changed = false
        if (outcome == ProvisionYamlEdit.Outcome.UNCHANGED) {
            step(
                STEP_CONFIG_PROJECT, "declared",
                "${cp.repository.fullName}: $path on ${cp.repository.defaultBranch} already declares application ${cp.name} with these redirect URIs and publish target; nothing proposed",
            )
        } else {
            val proposal = github.proposeFiles(
                cp.repository, listOf(path to cp.converged.content), cp.branch,
                "Thoryn: the production client of ${appRepo.fullName}", productionClientPullRequestBody(cp, appRepo), STEP_CONFIG_PROJECT,
            )
            pullRequest = proposal.url
            changed = proposal.changed
            step(
                STEP_CONFIG_PROJECT, if (changed) "pending review" else "open",
                "pull request ${if (changed) "pending review" else "open"}: ${proposal.url} — application ${cp.name} ${outcome.name.lowercase()} in " +
                    "${cp.repository.fullName}:$path (branch ${cp.branch})" +
                    if (outcome == ProvisionYamlEdit.Outcome.UPDATED) "; the entry differed, so the file was re-rendered and its comments are not kept" else "",
            )
        }
        report["configProject"] = linkedMapOf(
            "repository" to cp.repository.fullName, "file" to path, "branch" to cp.branch, "pullRequest" to pullRequest,
            "outcome" to if (pullRequest == null) "declared" else outcome.name.lowercase(), "changed" to changed, "application" to application,
        )
    }

    /** The pull request's body: what the reviewer approves — a production public client, its redirect URIs, where its id is published. */
    private fun productionClientPullRequestBody(cp: ConfigProject, appRepo: GhRepository): String {
        val spec = cp.entry["spec"]
        val redirects = spec["redirectUris"].toList().map { it.asString() }
        val signedOut = spec["postLogoutRedirectUris"].toList().map { it.asString() }
        return buildString {
            appendLine("Proposed by `thoryn project init app` for the application repository ${appRepo.fullName}.")
            appendLine()
            appendLine("Approving and merging this pull request approves, for this config project's next production run:")
            appendLine()
            appendLine("- **A production OAuth client** `${cp.name}` (`kind: application`, production plane): a PUBLIC client — PKCE proves it, no secret exists anywhere — with grant type `authorization_code` and scopes `openid profile email`.")
            appendLine("- **Its redirect URIs**: sign-in callback ${redirects.joinToString(", ") { "`$it`" }}; post-logout ${signedOut.joinToString(", ") { "`$it`" }} (the starter stack's `${ProjectSeeds.CALLBACK_PATH}` and `${ProjectSeeds.SIGNED_OUT_PATH}` under `${request.productionUrl}`).")
            appendLine("- **Where its id is published**: as the GitHub Actions variable `${ProjectSeeds.PRODUCTION_CLIENT_ID_VARIABLE}` on the `${ProjectSeeds.PRODUCTION_GITHUB_ENVIRONMENT}` environment of ${appRepo.fullName}, on every production apply (`publishTo`). A variable, never a secret: a client id is public by construction.")
            appendLine()
            appendLine("Nothing is created until this is merged and the production run is approved. ${appRepo.fullName}'s own `.thoryn/provision.yaml` is unchanged: it declares only its sandbox client. ")
            append("A later `thoryn project init app` run for the same repository updates this branch and pull request; it never opens a second one.")
        }
    }

    /** The by-hand version of the config-repository pull request — printed when `gh` is unavailable or the config repository is not. */
    private fun configProjectManualSteps(configRepo: String, appRepository: String): List<String> {
        val path = ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE
        val placeholder = appRepository.startsWith("<")
        val name = if (placeholder) "<app repository name>" else ProjectSeeds.productionClientName(appRepository)
        val branch = ProjectSeeds.productionClientBranch(if (placeholder) "<app repository name>" else appRepository.substringAfter('/'))
        val entry = ProjectSeeds.productionClientEntry(appRepository, request.productionUrl ?: "https://<where the app runs>", name)
        val fragment = ProvisionYamlEdit.fragment(tools.jackson.databind.json.JsonMapper.builder().build().createArrayNode().add(entry))
        return listOf(
            "# The app's PRODUCTION client is declared on the config repository $configRepo — a pull request, never its default branch:",
            "gh repo clone $configRepo && cd ${configRepo.substringAfter('/')} && git switch -c $branch",
            "# append to $path (under its resources: list):\n$fragment".trimEnd(),
            "git add $path && git commit -m \"Thoryn: the production client of $appRepository\" && git push -u origin $branch && " +
                "gh pr create --repo $configRepo --title \"Thoryn: the production client of $appRepository\" --fill",
        )
    }

    // ── gh unavailable: say what would run, change nothing ───────────────────────────────────────

    private fun ghUnavailable(signedOut: Boolean, workspaceSlug: String, sandboxSlug: String, sandbox: Env?, production: Env?, tenantId: String?): Stop {
        val repo = request.repo ?: "<owner>/<repo>"
        val prodEnv = "thoryn-production"
        val manual = buildList {
            if (request.repo != null) {
                add("gh repo create $repo --template ${request.template} ${if (request.public) "--public" else "--private"}   # if it does not exist yet")
            }
            add("gh api repos/$repo --jq '{id: .id, ownerId: .owner.id, defaultBranch: .default_branch}'   # the ids the trusts pin")
            if (request.kind == Kind.CONFIG) {
                request.reviewers.forEach { add("gh api users/$it --jq .id   # reviewer id") }
                add("# .github/CODEOWNERS, one line each: ${CODEOWNED_PATHS.joinToString("; ") { "$it ${request.reviewers.joinToString(" ") { r -> "@$r" }}" }} — commit it to the default branch")
                add("gh api --method POST repos/$repo/rulesets --input ruleset.json   # name ${GitHubCli.RULESET_NAME}, target ~DEFAULT_BRANCH: pull_request (1 approval, require_code_owner_review, dismiss_stale_reviews_on_push), non_fast_forward, deletion; bypass_actors []")
                add("gh api --method PUT repos/$repo/environments/$prodEnv --input protection.json   # reviewers need GitHub Enterprise on a private repository; omit them otherwise — {\"reviewers\":[{\"type\":\"User\",\"id\":<reviewer id>}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}")
                add("gh api --method POST repos/$repo/environments/$prodEnv/deployment-branch-policies -f name=<default branch> -f type=branch")
                if (sandbox == null) add("thoryn env create --slug $sandboxSlug --name \"Sandbox $sandboxSlug\"")
                add(
                    "thoryn workload-identity trusts create --environment ${production?.slug ?: "production"} --name starter-production-<repository id> --repository $repo " +
                        "--owner-id <owner id> --repository-id <repository id> --github-environment $prodEnv --ref refs/heads/<default branch> " +
                        "--scope \"<connections.production.scopes of .thoryn/template.json>\" --confirm-production",
                )
            }
            add(
                "thoryn workload-identity trusts create --environment $sandboxSlug --name starter-sandbox-<repository id> --repository $repo " +
                    "--owner-id <owner id> --repository-id <repository id> --scope \"<connections.sandbox.scopes of .thoryn/template.json>\"",
            )
            add("thoryn access grant client:<sandbox client id> manager environment:${sandbox?.id ?: "<$sandboxSlug environment id>"}")
            if (request.kind == Kind.CONFIG) {
                add("thoryn access grant client:<production client id> manager workspace:${tenantId ?: "<workspace id>"}")
            }
            add("gh variable set THORYN_ISSUER --body ${session.issuer} --repo $repo")
            add("gh variable set THORYN_WORKSPACE --body $workspaceSlug --repo $repo")
            if (request.kind == Kind.CONFIG) {
                add("gh variable set THORYN_SANDBOX_ENVIRONMENT --body $sandboxSlug --repo $repo")
                add("gh variable set THORYN_SANDBOX_WIF_CLIENT_ID --body <sandbox client id> --repo $repo")
                add("gh variable set THORYN_PRODUCTION_WIF_CLIENT_ID --body <production client id> --repo $repo --env $prodEnv")
            } else {
                add("gh variable set THORYN_ENVIRONMENT --body $sandboxSlug --repo $repo")
                add("gh variable set THORYN_WIF_CLIENT_ID --body <sandbox client id> --repo $repo")
            }
            add(
                "# .thoryn/connection.json next to each connection's provision.yaml: {\"apiVersion\":\"thoryn.io/connection/v1\",\"workspace\":{\"slug\":\"$workspaceSlug\"}," +
                    "\"auth\":{\"method\":\"workload_identity\",\"clientId\":\"<client id>\",\"audience\":\"<the trust's audience>\",\"scopes\":[<the trust's scopes>]}} " +
                    "— and a starter provision.yaml (apiVersion thoryn.io/provision/v1) declaring what the connection owns; commit both",
            )
        }.toMutableList()
        request.configRepo?.let { manual.addAll(configProjectManualSteps(it, repo)) }
        val what = if (signedOut) "gh is not signed in" else "the GitHub CLI (gh) is not installed"
        val fix = if (signedOut) "Run `gh auth login`" else "Install gh (https://cli.github.com) and run `gh auth login`"
        return Stop(
            EXIT_CHECK, if (signedOut) "gh_not_signed_in" else "gh_not_installed",
            "$what. Nothing was changed — not on GitHub, not in Thoryn.",
            "$fix, then re-run: ${request.commandLine}",
            mapOf("manualSteps" to manual),
        )
    }

    /**
     * A private config repository on GitHub Free, which has no rulesets for private repositories: refused, no fallback
     * (product-owner settlement 2026-09-30, revised). The approval runs before any Thoryn write, so the only thing that
     * can remain is a repository this run created with --repo — it is kept, never deleted. Exit [EXIT_CHECK] when nothing changed,
     * [EXIT_GH] when that repository was created.
     */
    private fun planLimitRefusal(repo: GhRepository): Stop {
        val created = steps.firstOrNull { it.name == STEP_REPOSITORY }?.status == "created"
        val remains = if (created) {
            "What remains: the repository ${repo.fullName}, which this run created (private, from ${request.template}). It is kept; " +
                "delete it yourself if you do not want it (gh repo delete ${repo.fullName}), or re-run with --public on a new name. " +
                "Nothing was created in Thoryn."
        } else {
            "Nothing was changed — not on GitHub, not in Thoryn."
        }
        return Stop(
            if (created) EXIT_GH else EXIT_CHECK, "github_plan_required",
            "Production approval needs a reviewed pull request on the default branch, which GitHub Free does not support for private repositories. " +
                "Use GitHub Pro, Team or Enterprise, or a public repository.",
            remains,
            mapOf("repositoryCreated" to created, "repository" to repo.fullName),
        )
    }

    private fun productionRefused() = Stop(
        EXIT_USAGE, "production_refused",
        "An app project connects to an existing SANDBOX; it never gets a production trust.",
        "Name a sandbox with --environment <slug> (thoryn env list). Production is configured by the workspace's config project.",
    )

    // ── Internals ────────────────────────────────────────────────────────────────────────────────

    private fun step(name: String, status: String, detail: String) {
        steps += Step(name, status, detail)
    }

    private fun visibility(repo: GhRepository) = if (repo.private) "private" else "public"

    companion object {
        const val EXIT_HTTP: Int = 2
        const val EXIT_GH: Int = 3
        const val EXIT_CHECK: Int = 4
        const val EXIT_USAGE: Int = 64

        const val STEP_PREFLIGHT: String = "pre-flight"
        const val STEP_REPOSITORY: String = "repository"
        const val STEP_PROTECTION: String = "protection"
        const val STEP_ENVIRONMENTS: String = "environments"
        const val STEP_TRUSTS: String = "workload-trust"
        const val STEP_ACCESS: String = "access"
        const val STEP_VARIABLES: String = "variables"
        const val STEP_FILES: String = "files"
        /** The seeded `.thoryn/` files: connection.json + the starter provision.yaml per connection (ADR 2026-10-13). */
        const val STEP_PROVISIONING: String = "provisioning"
        /** SSO-3669 — the app's production client, proposed on the config repository. */
        const val STEP_CONFIG_PROJECT: String = "config-project"

        const val DEFAULT_SANDBOX: String = "sandbox"
        const val STEP_APPROVAL: String = "approval"
        const val STEP_CODEOWNERS: String = "codeowners"
        const val STEP_RULESET: String = "ruleset"
        const val CODEOWNERS_PATH: String = ".github/CODEOWNERS"
        private const val CODEOWNERS_MESSAGE = "Thoryn config project: reviewers own production, the workflows and CODEOWNERS"
        /** What the reviewers own, in this order — the same file the orchestrator (#3817) writes. */
        val CODEOWNED_PATHS: List<String> = listOf("/.thoryn/environments/production/", "/.github/workflows/", "/.github/CODEOWNERS")

        /**
         * The config project's CODEOWNERS: the --reviewer logins own production's configuration, the workflows and the
         * CODEOWNERS file itself (product-owner decision 2026-09-30) — exactly one line per path, nothing else.
         */
        fun codeownersFor(reviewers: List<String>): String {
            val owners = reviewers.joinToString(" ") { "@$it" }
            return CODEOWNED_PATHS.joinToString("") { "$it $owners\n" }
        }

        private const val MAX_TRUST_PAGES = 20

        /**
         * The deterministic trust name of a connection for one repository — unique per environment (one trust per
         * repository and connection), stable across re-runs, within the 64-character name grammar. A trust the
         * server-side orchestrator created (named after its project id) is adopted by its pins instead.
         */
        fun trustName(connection: String, repositoryId: Long): String = "starter-$connection-$repositoryId".take(64)

        /** product-api's platform-reference id encoding (`PlatformRefs.encodeId`): `%`, `@`, `#`, whitespace escaped. */
        fun encodeId(raw: String): String = buildString {
            raw.forEach { c ->
                when {
                    c == '%' -> append("%25")
                    c == '@' -> append("%40")
                    c == '#' -> append("%23")
                    c == ' ' -> append("%20")
                    c.isWhitespace() -> append("%%%02X".format(c.code))
                    else -> append(c)
                }
            }
        }

        private fun text(node: JsonNode?, field: String): String? =
            node?.get(field)?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
    }
}
