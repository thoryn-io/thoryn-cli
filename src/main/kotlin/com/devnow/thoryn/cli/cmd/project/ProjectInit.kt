package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
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

    private data class Env(val id: String, val slug: String, val production: Boolean, val suspended: Boolean)

    private data class Target(
        val connection: String,
        val spec: StarterTemplateManifest.Connection,
        val envSlug: String,
        var envId: String?,
        val githubEnvironment: String?,
    )

    private enum class FileAction { WRITE, OVERWRITE, SAME }

    private class PlannedFile(val entry: TemplateArchive.Entry, val target: Path, val action: FileAction)

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
        val files = if (request.repo == null) planFiles() else emptyList()

        val targets = buildList {
            val (sandboxName, sandboxSpec) = manifest.sandboxConnection
            add(Target(sandboxName, sandboxSpec, sandboxSlug, sandbox?.id, null))
            manifest.productionConnection?.let { (name, spec) ->
                add(Target(name, spec, production!!.slug, production.id, manifest.productionGithubEnvironment))
            }
        }
        // An existing repository may already carry trusts: refuse up front when one of ours conflicts.
        repository?.let { repo -> targets.filter { it.envId != null }.forEach { findTrust(it, repo) } }

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
        if (config) {
            currentStep = STEP_PROTECTION
            github.protectEnvironment(repo, productionGithubEnvironment!!, reviewerIds, repo.defaultBranch, STEP_PROTECTION)
            step(STEP_PROTECTION, "set", "GitHub environment $productionGithubEnvironment: reviewers ${request.reviewers.joinToString(", ")}; deploys from ${repo.defaultBranch} only")
            report["productionEnvironment"] = linkedMapOf(
                "githubEnvironment" to productionGithubEnvironment, "reviewers" to request.reviewers, "branch" to repo.defaultBranch,
            )
        }

        currentStep = STEP_ENVIRONMENTS
        if (config) {
            val sandboxTarget = targets.first { !it.spec.production }
            if (sandboxTarget.envId == null) {
                sandboxTarget.envId = ensureSandbox(sandboxSlug)
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
            grants += linkedMapOf("subject" to subject, "relation" to t.spec.grant.relation, "object" to objectRef)
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
        // Repository-level first; the production-environment variable only once its protection is confirmed.
        manifest.variables.entries.sortedBy { it.value.level == StarterTemplateManifest.LEVEL_ENVIRONMENT }.forEach { (name, v) ->
            val value = values[name] ?: throw Stop(EXIT_CHECK, "starter_template_invalid", "The template declares $name, which has no value.")
            if (v.environment != null && !github.environmentProtected(repo, v.environment, reviewerIds, STEP_VARIABLES)) {
                throw Stop(
                    EXIT_GH, "github_environment_unprotected",
                    "GitHub environment ${v.environment} does not show the required reviewers and branch policy, so $name was not set.",
                    "Check the environment's protection rules in the repository settings, then re-run.",
                )
            }
            github.setVariable(repo, name, value, v.environment, STEP_VARIABLES)
            variables += linkedMapOf("name" to name, "value" to value, "level" to v.level, "environment" to v.environment)
        }
        val repoLevel = variables.filter { it["environment"] == null }.map { it["name"] }
        val envLevel = variables.filter { it["environment"] != null }
        step(STEP_VARIABLES, "set", "${repoLevel.joinToString(", ")} (repository)" + envLevel.joinToString("") { "; ${it["name"]} (environment ${it["environment"]})" })
        report["variables"] = variables

        currentStep = STEP_FILES
        if (request.repo == null) writeFiles(files)
        val createdRepo = steps.first { it.name == STEP_REPOSITORY }.status == "created"
        report["hasTemplateFiles"] = when {
            request.repo == null || createdRepo -> true
            else -> github.fileExists(repo.fullName, StarterTemplateManifest.PATH, STEP_VARIABLES)
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
            Env(id, slug, production = text(n, "kind") == "production", suspended = n["suspended"]?.asBoolean(false) ?: false)
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

    private fun planFiles(): List<PlannedFile> {
        val tarball = github.templateTarball(request.template, STEP_PREFLIGHT)
        val entries = try {
            TemplateArchive.read(tarball)
        } catch (ex: TemplateArchive.ArchiveException) {
            throw Stop(EXIT_CHECK, "starter_template_invalid", "The template's files could not be read: ${ex.message}.")
        }
        val root = request.dir.toAbsolutePath().normalize()
        val planned = entries.map { e ->
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
        val conflicts = planned.filter { it.action == FileAction.OVERWRITE }.map { it.entry.path }
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
                val touched = (files["added"].orEmpty() + files["overwritten"].orEmpty()).map { it.substringBefore('/') }.distinct().sorted()
                if (touched.isNotEmpty()) {
                    add("Commit and push the added files: git add ${touched.joinToString(" ")} && git commit -m \"Add the Thoryn ${request.kind.label} project\" && git push")
                } else {
                    add("The template's files are already in this clone; push a commit (or re-run the workflow) to start a run.")
                }
                add("The first run after the push reads the variables that are now set; no secret is stored anywhere.")
            }
            createdRepo -> {
                add("Clone it: gh repo clone ${repo.fullName}")
                add(
                    "GitHub's initial commit started a first workflow run before the variables existed, so its Thoryn jobs skipped. " +
                        "Re-run it (gh run list --repo ${repo.fullName}, then gh run rerun <id> --repo ${repo.fullName}) or push a commit; that run uses the variables.",
                )
            }
            report["hasTemplateFiles"] == false -> add(
                "${repo.fullName} does not contain the template's files yet: clone it and run `thoryn project init ${request.kind.label} …` " +
                    "inside the clone (without --repo) to add them; the steps above are kept and re-used.",
            )
            else -> add("Push a commit (or re-run the workflow) to start a run with the variables set.")
        }
        if (config) {
            add("Production runs wait in the GitHub environment $productionGithubEnvironment for approval by: ${request.reviewers.joinToString(", ")}.")
        }
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
                add("gh api --method PUT repos/$repo/environments/$prodEnv --input protection.json   # {\"reviewers\":[{\"type\":\"User\",\"id\":<reviewer id>}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}")
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
        }
        val what = if (signedOut) "gh is not signed in" else "the GitHub CLI (gh) is not installed"
        val fix = if (signedOut) "Run `gh auth login`" else "Install gh (https://cli.github.com) and run `gh auth login`"
        return Stop(
            EXIT_CHECK, if (signedOut) "gh_not_signed_in" else "gh_not_installed",
            "$what. Nothing was changed — not on GitHub, not in Thoryn.",
            "$fix, then re-run: ${request.commandLine}",
            mapOf("manualSteps" to manual),
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

        const val DEFAULT_SANDBOX: String = "sandbox"
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
