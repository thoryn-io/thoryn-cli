package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.VersionProvider
import com.devnow.thoryn.cli.auth.JobIdentity
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPlan
import java.io.File
import java.io.IOException
import java.io.PrintStream
import java.net.URI
import java.nio.file.Path

/**
 * SSO-3710 — the CLI side of the fix request ([FixRequest], oauthy ADR 2026-10-15 §1): where the file goes
 * (`--fix-request <path>`, or the env var [FixRequest.ENV] so a workflow can name it before it pins a release that
 * reads it), what the two producers know about the job (the runner's `GITHUB_*` variables at plan time, the job
 * token's claims at sign-in), how `provision plan` resolves the trust (only when the session may list trusts), and
 * the write itself — which never changes an exit code: a request that cannot be written is a warning on stderr,
 * the failure it describes is still the failure.
 */
internal object FixRequests {

    /** The scope a session needs to resolve its own trust's name and id (`GET /api/v1/workload-identity/trusts`). */
    const val SCOPE_TRUSTS_READ: String = "tenant:workload-identity.read"

    /** The file to write: the flag, else [FixRequest.ENV] (a `-D` property first — tests — then the environment), else none. */
    fun target(flag: File?): Path? = flag?.toPath() ?: WorkloadIdentityFlow.runnerEnv(FixRequest.ENV)?.let { Path.of(it) }

    /**
     * The repository as the GitHub Actions RUNNER states it (`GITHUB_REPOSITORY`, `GITHUB_REPOSITORY_OWNER`,
     * `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_REPOSITORY_ID`) — what `provision plan` has, holding no job token. Null
     * outside a runner. A hint: the consumer rebinds to GitHub's record of the run.
     */
    fun runnerRepository(): FixRequest.Repository? {
        val full = WorkloadIdentityFlow.runnerEnv("GITHUB_REPOSITORY")
        val owner = WorkloadIdentityFlow.runnerEnv("GITHUB_REPOSITORY_OWNER") ?: full?.substringBefore('/', "")?.takeIf { it.isNotEmpty() }
        val ownerId = WorkloadIdentityFlow.runnerEnv("GITHUB_REPOSITORY_OWNER_ID")?.toLongOrNull()
        val repositoryId = WorkloadIdentityFlow.runnerEnv("GITHUB_REPOSITORY_ID")?.toLongOrNull()
        val name = full?.substringAfter('/', "")?.takeIf { it.isNotEmpty() }
        if (owner == null && ownerId == null && name == null && repositoryId == null) return null
        return FixRequest.Repository(owner, ownerId, name, repositoryId)
    }

    /** The run as the runner states it (`GITHUB_RUN_ID`, `GITHUB_SHA`) plus the session's recorded job environment. */
    fun runnerRun(jobEnvironment: String?): FixRequest.Run? {
        val id = WorkloadIdentityFlow.runnerEnv("GITHUB_RUN_ID")?.toLongOrNull()
        val sha = WorkloadIdentityFlow.runnerEnv("GITHUB_SHA")
        if (id == null && sha == null && jobEnvironment == null) return null
        return FixRequest.Run(id, sha, jobEnvironment)
    }

    /** The repository as the JOB TOKEN's claims state it — what a refused sign-in has (never the token). */
    fun repositoryOf(identity: JobIdentity): FixRequest.Repository? {
        val owner = identity.repositoryOwner ?: identity.repository?.substringBefore('/', "")?.takeIf { it.isNotEmpty() }
        val name = identity.repository?.substringAfter('/', "")?.takeIf { it.isNotEmpty() }
        if (owner == null && name == null && identity.repositoryId == null && identity.repositoryOwnerId == null) return null
        return FixRequest.Repository(owner, identity.repositoryOwnerId?.toLongOrNull(), name, identity.repositoryId?.toLongOrNull())
    }

    /** The run as the job token's claims state it (`run_id`, `sha`, `environment`). */
    fun runOf(identity: JobIdentity): FixRequest.Run? {
        if (identity.runId == null && identity.sha == null && identity.environment == null) return null
        return FixRequest.Run(identity.runId?.toLongOrNull(), identity.sha, identity.environment)
    }

    /** The plane a workload-identity session's audience names: its `/{env}` path, or `production` with none. */
    fun planeOf(issuer: String?): String {
        val path = issuer?.let { runCatching { URI(it.trim()).path }.getOrNull() }?.trim('/').orEmpty()
        return path.ifEmpty { ProvisionEngine.PRODUCTION_ENV_SLUG }
    }

    /**
     * The request a refused `login --connection` writes: the one [FixRequest.Kind.PLAN_PROFILE] item, the trust as the
     * connection states it (the `wi_` client and the apply environment pin; name and id null — there is no token to
     * resolve them with), the repository and run from the job token's claims.
     */
    fun forRefusedSignIn(
        item: FixRequest.MissingRight,
        identity: JobIdentity,
        clientId: String,
        plane: String,
        applyEnvironment: String?,
        workspace: String?,
    ): FixRequest = FixRequest(
        cliVersion = cliVersion(),
        repository = repositoryOf(identity),
        run = runOf(identity),
        workspace = workspace,
        file = null,
        trust = FixRequest.Trust(name = null, plane = plane, applyEnvironment = applyEnvironment, id = null, clientId = clientId),
        missing = listOf(item),
    )

    /**
     * The request a red `provision plan` / `apply` writes: one item per `access_*` row that is a missing right, the
     * file-fix rows as notes, the file and its digest, the repository / run from the runner, the trust resolved from the
     * session — [resolveTrust]. Null when the plan has no `ERROR` row at all (nothing to ask for).
     */
    fun forPlan(plan: ProvisionPlan, file: ProvisionFile, tokens: Tokens, gateway: String): FixRequest? {
        if (!plan.hasErrors) return null
        val (items, notes) = FixRequest.fromPlan(plan)
        return FixRequest(
            cliVersion = cliVersion(),
            repository = runnerRepository(),
            run = runnerRun(tokens.jobEnvironment),
            workspace = tokens.workspace,
            file = FixRequest.FileRef(file.source, file.digest),
            trust = resolveTrust(tokens, gateway),
            missing = items,
            notes = notes,
        )
    }

    /**
     * The session's trust: its `wi_` client from the session, the plane from its audience; name, id and apply
     * environment through `GET /api/v1/workload-identity/trusts` on that plane ONLY when the session is a workload
     * identity one whose scopes allow it ([SCOPE_TRUSTS_READ]) — a plan-profile session usually holds no such scope,
     * and the request then names the client only. Every failure of that read leaves the fields null: the request is
     * a hint, never worth a second failure.
     */
    fun resolveTrust(tokens: Tokens, gateway: String): FixRequest.Trust {
        val plane = planeOf(tokens.issuer)
        val clientId = tokens.clientId?.takeIf { tokens.authMode == Tokens.AUTH_MODE_WORKLOAD_IDENTITY }
            ?: return FixRequest.Trust(name = null, plane = plane, applyEnvironment = null, id = null, clientId = null)
        val scopes = ProvisionCommand.callerScopesOf(tokens)
        if (scopes != null && SCOPE_TRUSTS_READ !in scopes) return FixRequest.Trust(null, plane, null, null, clientId)
        val found = runCatching {
            val client = CommandSupport.gatewayClient(
                gateway, tokens, applyEnvironment = false,
                environmentOverride = plane.takeIf { it != ProvisionEngine.PRODUCTION_ENV_SLUG } ?: "",
            )
            var cursor: String? = null
            var pages = 0
            var hit: Map<String, Any?>? = null
            do {
                val page = client.listWorkloadIdentityTrusts(cursor = cursor)
                val data = page["data"]
                if (data != null && data.isArray) {
                    for (t in data) {
                        if (t["clientId"]?.asString() == clientId) {
                            hit = mapOf(
                                "name" to t["name"]?.takeUnless { it.isNull }?.asString(),
                                "id" to t["id"]?.takeUnless { it.isNull }?.asString(),
                                "applyEnvironment" to t["github"]?.get("environment")?.takeUnless { it.isNull }?.asString(),
                            )
                            break
                        }
                    }
                }
                val pagination = page["pagination"]
                cursor = pagination?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
                pages++
            } while (hit == null && cursor != null && pages < MAX_TRUST_PAGES)
            hit
        }.getOrNull()
        return FixRequest.Trust(
            name = found?.get("name") as String?,
            plane = plane,
            applyEnvironment = found?.get("applyEnvironment") as String?,
            id = found?.get("id") as String?,
            clientId = clientId,
        )
    }

    /**
     * Write [request] to [path] and say so on stderr (the artifact name a workflow uploads it as). A write that fails
     * is a warning — the exit code stays the failure's own; the request is a convenience, the failure is the fact.
     */
    fun write(request: FixRequest, path: Path, err: PrintStream = System.err) {
        try {
            request.write(path)
            err.println("Fix request written to $path (${request.missing.size} missing right(s), ${request.notes.size} note(s)) — upload it as the run artifact `${FixRequest.ARTIFACT_NAME}`.")
        } catch (ex: IOException) {
            err.println("Warning: could not write the fix request to $path (${ex.message}); the failure above stands.")
        }
    }

    private fun cliVersion(): String? = runCatching { VersionProvider.readVersion() }.getOrNull()?.takeIf { it != "unknown" }

    private const val MAX_TRUST_PAGES = 20
}
