package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.provision.FixRequest
import java.net.URI

/**
 * SSO-3308 — a workload identity trust's GitHub pins as the CLI knows them (from a connection
 * contract's `auth.github`), so a refused exchange can name the field that differs. Every field is
 * optional: the CLI compares only what it was told.
 */
data class TrustPins(
    val owner: String? = null,
    val repository: String? = null,
    val ownerId: Long? = null,
    val repositoryId: Long? = null,
    val environment: String? = null,
    val ref: String? = null,
    val githubHostedRunnersOnly: Boolean? = null,
)

/**
 * SSO-3684 — a `kubernetes` trust's pins as the CLI knows them (a connection contract's `auth.kubernetes`),
 * compared against the projected ServiceAccount token's `iss` and `kubernetes.io` claims on a refusal.
 */
data class KubernetesPins(
    val issuer: String? = null,
    val namespace: String? = null,
    val serviceAccount: String? = null,
)

/**
 * SSO-4472 — a `forgejo` trust's pins as the CLI knows them (a connection contract's `auth.forgejo`, the same names as
 * the trust API's `forgejo` block), compared against the Forgejo Actions job token's `iss`, repository and `ref` claims
 * on a refusal. The instance is the trust's: its issuer is `<instanceUrl>/api/actions`.
 */
data class ForgejoPins(
    val instanceUrl: String? = null,
    val owner: String? = null,
    val repository: String? = null,
    val ownerId: Long? = null,
    val repositoryId: Long? = null,
    val ref: String? = null,
)

/** SSO-3308 — everything a workload identity sign-in sends, plus the pins it may compare against. */
data class WorkloadIdentityBinding(
    val clientId: String,
    val audience: String,
    val tokenEndpoint: String,
    /** Space-separated scopes to request, or null for the trust's full set. */
    val scope: String?,
    val pins: TrustPins? = null,
    /** SSO-3684 — the trust's provider when the sign-in knows it (`github_actions` / `kubernetes`); null ⇒ inferred from the token. */
    val provider: String? = null,
    /** SSO-3684 — a `kubernetes` trust's pins, when the connection names them. */
    val kubernetesPins: KubernetesPins? = null,
    /**
     * SSO-3702 — the trust PROFILE the sign-in expected the hub to match, judged from the job's `environment`
     * claim against [TrustPins.environment] ([WorkloadProfile.select]); null when the CLI could not tell. Decides
     * whether [scope] was sent at all (a plan job sends none) and is named on a refusal.
     */
    val profile: WorkloadProfile? = null,
    /**
     * SSO-3722 — the connection named no apply environment and the job carries an `environment` claim, so NO scope was
     * sent and the hub decided the profile ([WorkloadProfile.hubDecides]). Named on a refusal and in the fix.
     */
    val hubDecided: Boolean = false,
    /** SSO-3722 — the `--connection` file the sign-in read, when any: the fix names the exact file to edit. */
    val connectionFile: String? = null,
    /**
     * SSO-3722 — the scopes the caller ASKED for (the connection's `auth.scopes`, the flag's `--scope`), whatever was
     * sent: the `trusts create` the fix proposes carries them even when a plan job sent none.
     */
    val requestedScope: String? = scope,
    /** SSO-4472 — a `forgejo` trust's pins, when the connection names them. */
    val forgejoPins: ForgejoPins? = null,
    /** SSO-4472 — the connection mirrors a plan profile of the `forgejo` trust (`auth.plan`). */
    val forgejoPlanProfile: Boolean = false,
) {
    /** SSO-4472 — the provider this sign-in is judged as: the one it named, else what the token looks like. */
    internal fun providerOf(identity: JobIdentity?): String = provider ?: when {
        identity?.isKubernetes == true -> WorkloadIdentityDiagnostics.PROVIDER_KUBERNETES
        identity?.isForgejo == true -> WorkloadIdentityDiagnostics.PROVIDER_FORGEJO
        else -> WorkloadIdentityDiagnostics.PROVIDER_GITHUB_ACTIONS
    }
}

/**
 * SSO-3308 — turns a refused workload identity sign-in into something a person can act on.
 *
 * The platform refuses every mismatch with the same `401 invalid_client` and records the reason only
 * in the workspace audit log (ADR D9 — a caller learns nothing about which check failed). So the CLI
 * prints what it sent, the job's own public identity (the claims of the job token it holds — never the
 * token), every difference it can establish locally, and where the exact reason is recorded.
 */
object WorkloadIdentityDiagnostics {

    /** The audit event carrying the exact refusal reason (field `errorReason`). */
    const val AUDIT_EVENT: String = "workload_identity.exchange_failed"

    /** The command a workspace admin runs to read the exact reason. */
    const val AUDIT_COMMAND: String = "thoryn audit query --event-type $AUDIT_EVENT"

    /**
     * SSO-3710 — the one refusal shape the CLI can turn into a RIGHT to grant: the job's GitHub `environment` claim
     * differs from the trust's apply environment, and nothing else differs locally — the trust has no plan profile
     * for the environment the job ran in (the hub's `environment_mismatch`, answered as `invalid_client`).
     */
    data class PlanProfileGap(val jobEnvironment: String, val applyEnvironment: String) {
        /** The fix-request item: a plan profile on the trust for the job's environment ([FixRequest.planProfile]). */
        fun item(trustName: String? = null, trustId: String? = null): FixRequest.MissingRight =
            FixRequest.planProfile(trustName, trustId, jobEnvironment, applyEnvironment)
    }

    /**
     * The [PlanProfileGap] of a refusal, or null: only an `invalid_client` on a GitHub Actions token whose connection
     * pins an apply environment, where the job DECLARES an environment, and where the ONLY local mismatch is that
     * environment. Any other shape (a repository id, a ref, a runner, no environment at all, a Kubernetes token) is
     * today's diagnostic alone — a different pin, not a missing right.
     */
    fun planProfileGap(e: WorkloadIdentityException, binding: WorkloadIdentityBinding): PlanProfileGap? {
        if (e.oauthError != "invalid_client") return null
        val identity = e.jobIdentity ?: return null
        if (binding.provider == PROVIDER_KUBERNETES || identity.isKubernetes) return null
        // SSO-4472 — a Forgejo trust has no plan profile to grant yet (its selector is SSO-4471's to define).
        if (binding.provider == PROVIDER_FORGEJO || identity.isForgejo) return null
        val apply = binding.pins?.environment ?: return null
        val job = identity.environment ?: return null
        if (job == apply) return null
        val mismatches = localMismatches(identity, binding.audience, binding.pins, binding.provider, binding.kubernetesPins, binding.forgejoPins, binding.forgejoPlanProfile)
        if (mismatches.size != 1 || !mismatches.single().startsWith("environment:")) return null
        return PlanProfileGap(jobEnvironment = job, applyEnvironment = apply)
    }

    /**
     * Differences between the job and what the trust requires that the CLI can see without the
     * platform: the issuer and audience of the job token, the event kinds the platform always (or on
     * production) refuses, and — when [pins] are known — each pinned field.
     */
    fun localMismatches(
        identity: JobIdentity,
        audience: String,
        pins: TrustPins?,
        provider: String? = null,
        kubernetesPins: KubernetesPins? = null,
        forgejoPins: ForgejoPins? = null,
        forgejoPlanProfile: Boolean = false,
    ): List<String> = buildList {
        // SSO-3684 — a Kubernetes ServiceAccount token is judged against the cluster pins, not GitHub's issuer.
        if (provider == PROVIDER_KUBERNETES || (provider == null && identity.isKubernetes)) {
            addAll(kubernetesMismatches(identity, audience, kubernetesPins))
            return@buildList
        }
        // SSO-4472 — a Forgejo job token is judged against its instance and repository pins, not GitHub's issuer.
        if (provider == PROVIDER_FORGEJO || (provider == null && identity.isForgejo)) {
            addAll(forgejoMismatches(identity, audience, forgejoPins, forgejoPlanProfile))
            return@buildList
        }
        identity.issuer?.let { iss ->
            if (iss != WorkloadIdentityFlow.GITHUB_ACTIONS_ISSUER) {
                add("iss: the job token was issued by '$iss'; a trust accepts only ${WorkloadIdentityFlow.GITHUB_ACTIONS_ISSUER}.")
            }
        }
        if (identity.audience.isNotEmpty() && audience !in identity.audience) {
            add("aud: the job token is for ${identity.audience.joinToString()} but the sign-in named '$audience'.")
        }
        if (identity.eventName == "pull_request_target") {
            add("event_name: pull_request_target jobs are always refused (they run with the base repository's permissions on untrusted code).")
        }
        val production = namesProductionPlane(audience)
        if (production && identity.eventName == "pull_request") {
            add("event_name: pull_request jobs are refused by a production trust (the audience '$audience' names the production plane).")
        }
        if (production && identity.environment == null && pins?.environment == null) {
            add("environment: a production trust requires the job to run in the GitHub environment it pins; this job declares no `environment:`.")
        }
        if (pins == null) return@buildList

        val pinnedRepository = listOfNotNull(pins.owner, pins.repository).takeIf { it.size == 2 }?.joinToString("/")
        if (pinnedRepository != null && identity.repository != null && !pinnedRepository.equals(identity.repository, ignoreCase = true)) {
            add("repository: the trust pins '$pinnedRepository'; this job runs in '${identity.repository}'.")
        }
        if (pins.repositoryId != null && identity.repositoryId != null && pins.repositoryId.toString() != identity.repositoryId) {
            add(
                "repository_id: the trust pins ${pins.repositoryId}; this job's repository has id ${identity.repositoryId} " +
                    "(a repository deleted and re-created under the same name gets a new id).",
            )
        }
        if (pins.ownerId != null && identity.repositoryOwnerId != null && pins.ownerId.toString() != identity.repositoryOwnerId) {
            add(
                "repository_owner_id: the trust pins ${pins.ownerId}; this job's owner has id ${identity.repositoryOwnerId} " +
                    "(an account renamed or re-registered under the same name gets a new id).",
            )
        }
        if (pins.environment != null && pins.environment != identity.environment) {
            add(
                if (identity.environment == null) {
                    "environment: the trust pins GitHub environment '${pins.environment}'; this job declares no `environment:` " +
                        "(add `environment: ${pins.environment}` to the job)."
                } else {
                    "environment: the trust pins GitHub environment '${pins.environment}'; this job runs in '${identity.environment}'."
                },
            )
        }
        if (pins.ref != null && identity.ref != null && pins.ref != identity.ref) {
            add("ref: the trust pins '${pins.ref}'; this job runs on '${identity.ref}'.")
        }
        if (pins.githubHostedRunnersOnly == true && identity.runnerEnvironment != null && identity.runnerEnvironment != "github-hosted") {
            add("runner_environment: the trust accepts only GitHub-hosted runners; this job runs on a '${identity.runnerEnvironment}' runner.")
        }
    }

    /**
     * SSO-3684 — what the CLI can see locally about a pod's token against a `kubernetes` trust: the audience
     * the projected volume asked for, the shape of the subject, and — when the connection names them — the
     * pinned issuer, namespace and service account (the hub refuses `namespace_mismatch` /
     * `service_account_mismatch` / `claim_missing` for these, all as `invalid_client`).
     */
    internal fun kubernetesMismatches(identity: JobIdentity, audience: String, pins: KubernetesPins?): List<String> = buildList {
        if (identity.audience.isNotEmpty() && audience !in identity.audience) {
            add(
                "aud: the ServiceAccount token is for ${identity.audience.joinToString()} but the sign-in named '$audience' " +
                    "(the projected volume's `audience:` must be the trust's audience).",
            )
        }
        if (identity.subject != null && !identity.subject.startsWith(JobIdentity.KUBERNETES_SUBJECT_PREFIX)) {
            add("sub: '${identity.subject}' is not a ServiceAccount subject (${JobIdentity.KUBERNETES_SUBJECT_PREFIX}<namespace>:<name>).")
        }
        if (identity.kubernetesNamespace == null && identity.kubernetesServiceAccount == null) {
            add(
                "kubernetes.io: the token carries no `kubernetes.io` claim — a legacy Secret-based ServiceAccount token, " +
                    "not a projected one. Mount a `projected` volume with a `serviceAccountToken` source.",
            )
        }
        if (pins == null) return@buildList
        if (pins.issuer != null && identity.issuer != null && pins.issuer.trimEnd('/') != identity.issuer.trimEnd('/')) {
            add("iss: the trust pins issuer '${pins.issuer}'; this token was issued by '${identity.issuer}'.")
        }
        if (pins.namespace != null && identity.kubernetesNamespace != null && pins.namespace != identity.kubernetesNamespace) {
            add("namespace: the trust pins '${pins.namespace}'; this pod runs in '${identity.kubernetesNamespace}'.")
        }
        if (pins.serviceAccount != null && identity.kubernetesServiceAccount != null && pins.serviceAccount != identity.kubernetesServiceAccount) {
            add("serviceAccount: the trust pins '${pins.serviceAccount}'; this pod runs as '${identity.kubernetesServiceAccount}'.")
        }
    }

    /**
     * SSO-4472 — what the CLI can see locally about a Forgejo Actions job token against a `forgejo` trust: the audience it
     * was requested for; the job's TRIGGER CLASS judged by the amendment's rule ([TriggerProfileRule], the same mapping the
     * hub's evaluator uses: a `trigger:` line when the hub is expected to refuse it — `event_not_allowed`, `ref_mismatch`,
     * `base_ref_mismatch`); and — when the connection names them — the instance (the token's `iss` is
     * `<instance>/api/actions`), the repository and its immutable ids. The hub refuses each of these as `invalid_client`.
     */
    internal fun forgejoMismatches(identity: JobIdentity, audience: String, pins: ForgejoPins?, hasPlanProfile: Boolean = false): List<String> = buildList {
        if (identity.audience.isNotEmpty() && audience !in identity.audience) {
            add(
                "aud: the job token is for ${identity.audience.joinToString()} but the sign-in named '$audience' " +
                    "(a Forgejo job's default audience is <instance>/<owner>; the CLI asks for the trust's with ?audience=).",
            )
        }
        val expectation = WorkloadProfile.forgejoExpectation(identity, pins?.ref, namesProductionPlane(audience), hasPlanProfile)
        if (expectation is TriggerExpectation.Refused) add("trigger: ${expectation.reason} — ${expectation.explanation}")
        if (pins == null) return@buildList
        val expectedIssuer = pins.instanceUrl?.trimEnd('/')?.let { it + WorkloadIdentityFlow.FORGEJO_ISSUER_PATH }
        if (expectedIssuer != null && identity.issuer != null && identity.issuer.trimEnd('/') != expectedIssuer) {
            add("iss: the trust pins instance '${pins.instanceUrl}' (issuer $expectedIssuer); this token was issued by '${identity.issuer}'.")
        }
        val pinnedRepository = listOfNotNull(pins.owner, pins.repository).takeIf { it.size == 2 }?.joinToString("/")
        if (pinnedRepository != null && identity.repository != null && !pinnedRepository.equals(identity.repository, ignoreCase = true)) {
            add("repository: the trust pins '$pinnedRepository'; this job runs in '${identity.repository}'.")
        }
        if (pins.repositoryId != null && identity.repositoryId != null && pins.repositoryId.toString() != identity.repositoryId) {
            add(
                "repository_id: the trust pins ${pins.repositoryId}; this job's repository has id ${identity.repositoryId} " +
                    "(a repository deleted and re-created under the same name, or a fork, has another id).",
            )
        }
        if (pins.ownerId != null && identity.repositoryOwnerId != null && pins.ownerId.toString() != identity.repositoryOwnerId) {
            add(
                "repository_owner_id: the trust pins ${pins.ownerId}; this job's owner has id ${identity.repositoryOwnerId} " +
                    "(an account renamed or re-registered under the same name gets a new id).",
            )
        }
    }

    /** SSO-4472 — the profile the amendment's rule expects for this Forgejo job under [binding]'s connection. */
    internal fun forgejoExpectation(identity: JobIdentity, binding: WorkloadIdentityBinding): TriggerExpectation =
        WorkloadProfile.forgejoExpectation(identity, binding.forgejoPins?.ref, namesProductionPlane(binding.audience), binding.forgejoPlanProfile)

    /** SSO-4472 — "a push on 'refs/heads/main'": the job's trigger class and ref, for a sign-in line. */
    fun forgejoJobDescription(identity: JobIdentity): String {
        val trigger = ForgejoTriggerMapping.classify(identity.eventName)
        val event = identity.eventName ?: "(no event_name)"
        return when (trigger) {
            TriggerClass.CHANGE_REQUEST -> "a pull request ($event) into '${identity.baseRef ?: "(no base_ref)"}'"
            else -> "a ${trigger.wire} ($event) on '${identity.ref ?: "(no ref)"}'"
        }
    }

    /** SSO-3684 — the provider name of a `kubernetes` trust (the trust API's `provider`). */
    const val PROVIDER_KUBERNETES: String = "kubernetes"

    /** SSO-4472 — the provider name of a `forgejo` trust (the trust API's `provider`). */
    const val PROVIDER_FORGEJO: String = WorkloadIdentityFlow.PROVIDER_FORGEJO

    /** The default provider of a workload identity sign-in. */
    const val PROVIDER_GITHUB_ACTIONS: String = "github_actions"

    /**
     * True when [audience] names an environment's PRODUCTION plane: a sandbox audience always carries
     * the `/{environment}` path (oathy #3787 D5), so an audience with no path is the workspace issuer
     * (or its custom domain) itself.
     */
    internal fun namesProductionPlane(audience: String): Boolean {
        val path = runCatching { URI(audience.trim()).path }.getOrNull() ?: return false
        return path.trim('/').isEmpty()
    }

    /**
     * SSO-3722 — the fix of ONE refusal, in the fix request's own terms: missing RIGHTS ([items], each with the command a
     * workspace admin runs) and FILE / job edits ([notes], imperative, copy-pasteable). Every refusal has at least one.
     */
    data class Fix(val items: List<FixRequest.MissingRight>, val notes: List<String>) {
        val isEmpty: Boolean get() = items.isEmpty() && notes.isEmpty()
    }

    /**
     * SSO-3722 — what fixes [e], per refusal shape (the audited list is the PR's table): a missing plan profile is the
     * ONE right; everything else is an edit to the job, the connection file or the trust, named with the exact command.
     */
    fun fixFor(e: WorkloadIdentityException, binding: WorkloadIdentityBinding): Fix {
        val file = binding.connectionFile ?: "connection.json"
        val identity = e.jobIdentity
        if (identity == null) {
            return Fix(
                emptyList(),
                when (e.oauthError) {
                    WorkloadIdentityFlow.ERROR_NOT_ON_GITHUB_ACTIONS -> listOf(
                        "job: add `permissions: id-token: write` (with `contents: read`) to the job that runs `thoryn login` — GitHub sets ${WorkloadIdentityFlow.REQUEST_URL_ENV} / ${WorkloadIdentityFlow.REQUEST_TOKEN_ENV} only then",
                        "outside GitHub Actions: sign in with `thoryn login` (a person) or `thoryn login --client-credentials` (an API key) instead",
                    )
                    // SSO-4472 — the Forgejo runner's own key, and the proxy case.
                    WorkloadIdentityFlow.ERROR_NOT_ON_FORGEJO_ACTIONS -> listOf(
                        "job: set `enable-openid-connect: true` on the Forgejo Actions job that runs `thoryn login` (a runner that issues ID tokens: forgejo-runner v12.5.0 or later) — Forgejo sets ${WorkloadIdentityFlow.REQUEST_URL_ENV} / ${WorkloadIdentityFlow.REQUEST_TOKEN_ENV} only then",
                        "behind an authenticating proxy: mint the token inside the job for audience '${binding.audience}' and set auth.tokenSource to {\"kind\": \"file\", \"path\": …} in $file",
                    )
                    WorkloadIdentityFlow.ERROR_JOB_TOKEN_REDIRECTED -> listOf(
                        "job: the runner's token URL redirects (an authenticating proxy in front of the instance) — mint the token inside the job for audience '${binding.audience}' and set auth.tokenSource to {\"kind\": \"file\", \"path\": …} in $file",
                    )
                    WorkloadIdentityFlow.ERROR_JOB_TOKEN_REQUEST_FAILED -> listOf(
                        if (binding.provider == PROVIDER_FORGEJO) {
                            "job: set `enable-openid-connect: true` and re-run — the runner refused the job-token request for audience '${binding.audience}'"
                        } else {
                            "job: grant `permissions: id-token: write` and re-run — the runner refused the job-token request for audience '${binding.audience}'"
                        },
                    )
                    WorkloadIdentityFlow.ERROR_TOKEN_FILE_UNREADABLE -> listOf(
                        if (binding.provider == PROVIDER_FORGEJO) {
                            "job: write the Forgejo Actions token for audience '${binding.audience}' to the file auth.tokenSource.path names in $file before `thoryn login` — a fresh one for every sign-in (a job token works once)"
                        } else {
                            "pod: mount the projected ServiceAccount token where the connection reads it — a `projected` volume with a `serviceAccountToken` source (`audience: ${binding.audience}`), or set auth.tokenSource.path in $file to the mounted path"
                        },
                    )
                    else -> listOf("re-run the job; if it persists, a workspace admin reads the reason with `$AUDIT_COMMAND`")
                },
            )
        }
        val kubernetes = binding.provider == PROVIDER_KUBERNETES || (binding.provider == null && identity.isKubernetes)
        val forgejo = binding.providerOf(identity) == PROVIDER_FORGEJO
        return when (e.oauthError) {
            "invalid_client" -> {
                planProfileGap(e, binding)?.let { return Fix(listOf(it.item()), emptyList()) }
                val mismatches = localMismatches(identity, binding.audience, binding.pins, binding.provider, binding.kubernetesPins, binding.forgejoPins, binding.forgejoPlanProfile)
                val notes = mutableListOf<String>()
                if (mismatches.any { it.startsWith("aud:") }) notes += "$file: set auth.audience to the trust's audience exactly (`thoryn workload-identity trusts get <id>` prints it)" + if (kubernetes) "; the projected volume's `audience:` must be the same value" else ""
                if (mismatches.any { it.startsWith("iss:") } && !kubernetes && !forgejo) notes += "job: a trust accepts only a GitHub Actions job token (${WorkloadIdentityFlow.GITHUB_ACTIONS_ISSUER}) — run `thoryn login --connection` inside the GitHub Actions job itself"
                if (mismatches.any { it.startsWith("event_name: pull_request_target") }) notes += "job: trigger the workflow on `pull_request`, never `pull_request_target` — the platform always refuses it"
                // SSO-4472 — the trigger-class rule: which job gets which profile, and what a refused one should be instead.
                if (forgejo) forgejoTriggerNote(identity, binding, file)?.let { notes += it }
                if (mismatches.any { it.startsWith("event_name: pull_request jobs") } && !forgejo) notes += "job: a production trust refuses `pull_request` jobs — run the plan from the App-dispatched workflow in the trust's plan GitHub environment, or use a sandbox trust"
                if (mismatches.any { it.startsWith("environment:") && it.contains("declares no `environment:`") }) notes += "job: add `environment: ${binding.pins?.environment ?: "<the trust's GitHub environment>"}` to the job"
                if (mismatches.any { it.startsWith("kubernetes.io:") }) notes += "pod: mount a `projected` volume with a `serviceAccountToken` source — a legacy Secret-based token carries no `kubernetes.io` claim"
                val pinMismatch = mismatches.any { m -> PIN_FIELDS.any { m.startsWith("$it:") } && !m.contains("declares no `environment:`") }
                if (forgejo && !pinMismatch && notes.isNotEmpty()) return Fix(emptyList(), notes)
                if (pinMismatch) {
                    notes += "trust: re-create it with the ${if (kubernetes) "pod's" else "job's"} own pins — `${trustsCreateCommand(identity, binding)}` — then replace $file with the connection.json it prints (`thoryn workload-identity trusts get <id> --connection`); or align the ${if (kubernetes) "pod" else "job"} with the trust (the differences above)"
                }
                if (notes.isEmpty()) {
                    notes += "read the exact reason (field errorReason): `$AUDIT_COMMAND`"
                    notes += "then re-create the trust with the ${if (kubernetes) "pod's" else "job's"} own pins — `${trustsCreateCommand(identity, binding)}` — and replace $file with the connection.json it prints (`thoryn workload-identity trusts get <id> --connection`), or align the ${if (kubernetes) "pod" else "job"} with the trust (`thoryn workload-identity trusts get <id>`)"
                }
                Fix(emptyList(), notes)
            }
            "invalid_scope" -> Fix(
                emptyList(),
                when (profileOutside(e.errorDescription)) {
                    WorkloadProfile.PLAN -> when {
                        // SSO-4472 — a Forgejo plan job is selected by its trigger, never by anything the job or the file declares.
                        forgejo ->
                            listOf("job: request no scope from ${forgejoJobDescription(identity)} — the hub mints the plan profile's read-only scopes there (`thoryn login --connection` does this on its own; drop --scope from the flag form)")
                        binding.connectionFile != null && binding.pins?.environment != null ->
                            listOf("$file: auth.github.environment names '${binding.pins.environment}' but the hub matched the PLAN profile for this job's environment '${identity.environment ?: "(none)"}' — set auth.github.environment to the trust's APPLY environment (paste the whole github block from `thoryn workload-identity trusts get <id> --connection`), or drop auth.scopes")
                        binding.connectionFile != null ->
                            listOf("$file: names no apply environment — add auth.github.environment: <the trust's apply environment> (paste the whole github block from `thoryn workload-identity trusts get <id> --connection`), or drop auth.scopes so the hub mints the matched profile")
                        else -> listOf("job: drop --scope (the hub then mints the plan profile's read-only scopes), or request only .read scopes — never a write scope from a plan job")
                    }
                    WorkloadProfile.APPLY -> listOf(
                        if (binding.connectionFile != null) "$file: auth.scopes must be a subset of the trust's scopes (`thoryn workload-identity trusts get <id>` lists them) — remove the ones outside, or list exactly the trust's scopes for its full set" else "job: pass --scope with a subset of the trust's scopes (`thoryn workload-identity trusts get <id>` lists them), or no --scope at all to receive the trust's full set",
                    )
                    null -> listOf(
                        if (binding.connectionFile != null) "$file: auth.scopes must be a subset of the trust's scopes (`thoryn workload-identity trusts get <id>` lists them)" else "job: pass --scope with a subset of the trust's scopes (`thoryn workload-identity trusts get <id>` lists them), or no --scope at all",
                    )
                },
            )
            WorkloadIdentityFlow.ERROR_TRANSPORT -> Fix(emptyList(), listOf("runner: make ${binding.tokenEndpoint} reachable (egress / DNS from this runner) and re-run; the audience's host is the platform the trust lives on"))
            else -> Fix(emptyList(), listOf("re-run the job; if it persists, a workspace admin reads the reason with `$AUDIT_COMMAND`"))
        }
    }

    /**
     * SSO-4472 — the fix of a Forgejo job the trigger-class rule refuses: a missing plan profile (a push / schedule / pull
     * request the plan profile is selected for), a hidden trigger (`workflow_call`), or a job on the wrong ref / branch.
     */
    private fun forgejoTriggerNote(identity: JobIdentity, binding: WorkloadIdentityBinding, file: String): String? {
        val refused = forgejoExpectation(identity, binding) as? TriggerExpectation.Refused ?: return null
        val pin = binding.forgejoPins?.ref
        val trigger = ForgejoTriggerMapping.classify(identity.eventName)
        return when {
            trigger == TriggerClass.HIDDEN_TRIGGER ->
                "job: run `thoryn login` in the job's own steps (an action), never inside a reusable workflow — the hub refuses every workflow_call job"
            trigger == TriggerClass.BASE_CODE_CHANGE_INPUT ->
                "job: trigger the workflow on `pull_request`, never `pull_request_target` — the platform always refuses it"
            refused.reason == TriggerProfileRule.EVENT_NOT_ALLOWED && trigger in setOf(TriggerClass.PUSH, TriggerClass.SCHEDULE, TriggerClass.CHANGE_REQUEST) ->
                "trust: give it a plan profile — `thoryn workload-identity trusts set-plan-profile <id>` (its scopes are derived from the trust's .read scopes, or --plan-scope) — then add the auth.plan block to $file (`thoryn workload-identity trusts get <id> --connection` prints it); or apply from a workflow_dispatch on '$pin'"
            else ->
                "job: on this trust a workflow_dispatch on '$pin' applies; a push or schedule on it, or a pull request into its branch, plans (with a plan profile); every other job is refused"
        }
    }

    /** The pinned fields whose mismatch means "the trust's pins are not this job's". */
    private val PIN_FIELDS = listOf("repository", "repository_id", "repository_owner_id", "environment", "ref", "runner_environment", "namespace", "serviceAccount", "iss")

    /**
     * SSO-3722 — the ONE `thoryn workload-identity trusts create` that pins the trust to THIS job (or pod), built from
     * the token's own public claims: the repository and its immutable ids, the GitHub environment the job declares, the
     * ref / runner pins when the connection had them, the scopes the sign-in requested (or a placeholder), the sandbox
     * (`--environment`) the audience names or `--confirm-production` for the production plane.
     */
    fun trustsCreateCommand(identity: JobIdentity, binding: WorkloadIdentityBinding): String = buildString {
        append("thoryn workload-identity trusts create --name <name>")
        val plane = runCatching { URI(binding.audience.trim()).path }.getOrNull()?.trim('/')?.takeIf { it.isNotEmpty() }
        plane?.let { append(" --environment $it") }
        val kubernetes = binding.provider == PROVIDER_KUBERNETES || (binding.provider == null && identity.isKubernetes)
        if (kubernetes) {
            append(" --provider kubernetes --issuer ${identity.issuer ?: "<cluster issuer>"}")
            append(" --namespace ${identity.kubernetesNamespace ?: "<namespace>"} --service-account ${identity.kubernetesServiceAccount ?: "<service-account>"}")
        } else if (binding.providerOf(identity) == PROVIDER_FORGEJO) {
            // SSO-4472 — the instance from the token's own issuer; a production trust always pins the job's ref.
            append(" --provider forgejo --instance ${identity.forgejoInstance ?: binding.forgejoPins?.instanceUrl ?: "<instance url>"}")
            append(" --repository ${identity.repository ?: "<owner/repo>"}")
            if (identity.repositoryOwnerId != null && identity.repositoryId != null) append(" --owner-id ${identity.repositoryOwnerId} --repository-id ${identity.repositoryId}")
            if (plane == null || binding.forgejoPins?.ref != null) append(" --ref ${identity.ref ?: binding.forgejoPins?.ref ?: "<ref>"}")
        } else {
            append(" --repository ${identity.repository ?: "<owner/repo>"}")
            if (identity.repositoryOwnerId != null && identity.repositoryId != null) append(" --owner-id ${identity.repositoryOwnerId} --repository-id ${identity.repositoryId}")
            (identity.environment ?: binding.pins?.environment)?.let { append(" --github-environment $it") }
            if (binding.pins?.ref != null) append(" --ref ${identity.ref ?: binding.pins.ref}")
            if (binding.pins?.githubHostedRunnersOnly == true) append(" --github-hosted-runners-only")
        }
        append(" --scope \"${binding.requestedScope?.takeIf { it.isNotBlank() } ?: "<scopes>"}\"")
        if (plane == null) append(" --confirm-production")
    }

    /**
     * The whole multi-line report for a failed sign-in (no trailing newline): what was sent, who the job is, every
     * difference the CLI can see — and, SSO-3722, always the one "To fix" block ([FixRequest.render], two options:
     * the CLI commands / edits and the run's browser consent link when [consentUrl] is known).
     */
    fun render(e: WorkloadIdentityException, binding: WorkloadIdentityBinding, consentUrl: String? = null): String {
        val fix = fixFor(e, binding)
        val identity = e.jobIdentity
        // Failures before the exchange (no runner vars, GitHub refused the job-token request): the message says it all.
        if (identity == null) return "Sign-in failed: ${e.message}\n\n" + FixRequest.render(fix.items, fix.notes, consentUrl)

        return buildString {
            when (e.oauthError) {
                "invalid_client" -> {
                    appendLine("Sign-in failed: the platform refused the workload identity exchange (HTTP ${e.status ?: 401}: invalid_client).")
                    appendLine("The platform does not say which check failed. The exact reason is in the workspace audit log")
                    appendLine("(event $AUDIT_EVENT, field errorReason); a workspace admin can read it with:")
                    appendLine("    $AUDIT_COMMAND")
                }
                "invalid_scope" -> {
                    // SSO-3702 — the hub names the PROFILE whose ceiling refused the request (SSO-3700).
                    when (profileOutside(e.errorDescription)) {
                        WorkloadProfile.PLAN -> {
                            appendLine("Sign-in failed: the requested scope is outside the trust's PLAN profile (HTTP ${e.status ?: 400}: invalid_scope, $REASON_OUTSIDE_PLAN).")
                            if (binding.providerOf(identity) == PROVIDER_FORGEJO) appendLine(
                                "This job is ${forgejoJobDescription(identity)}, so the hub matched the trust's plan profile and mints only its " +
                                    "read-only (.read) scopes; a write scope is never minted to a plan job.",
                            ) else appendLine(
                                "This job runs in GitHub environment '${identity.environment ?: "(none)"}'" +
                                    (binding.pins?.environment?.let { " — not the trust's apply environment '$it'" } ?: " and the connection names no apply environment") +
                                    ", so the hub matched the trust's plan profile and mints only its read-only (.read) scopes there; a write scope is never minted to a plan job.",
                            )
                        }
                        WorkloadProfile.APPLY -> {
                            appendLine("Sign-in failed: the requested scope is outside the trust's APPLY profile (HTTP ${e.status ?: 400}: invalid_scope, $REASON_OUTSIDE_APPLY).")
                            appendLine("The trust's scopes are the ceiling for a job in its apply environment '${identity.environment ?: "(none)"}'.")
                        }
                        null -> {
                            appendLine("Sign-in failed: the requested scope is not within the trust's scopes (HTTP ${e.status ?: 400}: invalid_scope).")
                            e.errorDescription?.let { appendLine("  platform said: ${sanitize(it)}") }
                        }
                    }
                }
                else -> {
                    appendLine("Sign-in failed: ${e.message}.")
                    e.errorDescription?.let { appendLine("  platform said: ${sanitize(it)}") }
                }
            }
            appendLine()
            appendLine("Sent:")
            appendLine(field("client id", binding.clientId))
            appendLine(field("audience", binding.audience))
            appendLine(field("token endpoint", binding.tokenEndpoint))
            appendLine(
                field(
                    "scope",
                    binding.scope ?: when {
                        binding.profile == WorkloadProfile.PLAN -> "(none requested — the hub mints the matched plan profile's read-only scopes)"
                        binding.hubDecided -> "(none requested — the connection names no apply environment; the hub matches the profile from the job's environment claim)"
                        else -> "(none requested — the trust's full set)"
                    },
                ),
            )
            // SSO-3702 — which profile the CLI expected the hub to match, and why.
            binding.profile?.takeIf { binding.providerOf(identity) == PROVIDER_FORGEJO }?.let { p ->
                appendLine(field("profile", "${p.wire} expected (${forgejoJobDescription(identity)})"))
            }
            binding.profile?.takeIf { binding.providerOf(identity) != PROVIDER_FORGEJO }?.let { p ->
                appendLine(
                    field(
                        "profile",
                        "${p.wire} (job environment '${identity.environment ?: "(none)"}' " +
                            (if (p == WorkloadProfile.APPLY) "= " else "≠ ") + "apply environment '${binding.pins?.environment}')",
                    ),
                )
            }
            val forgejoJob = binding.providerOf(identity) == PROVIDER_FORGEJO
            if (binding.hubDecided && forgejoJob) {
                appendLine(field("profile", "decided by the hub (${forgejoJobDescription(identity)}; the connection's scopes are requested only for a workflow_dispatch on the pinned ref)"))
            } else if (binding.hubDecided) {
                appendLine(field("profile", "decided by the hub (no auth.github.environment in the connection)"))
            }
            appendLine()
            val kubernetes = binding.provider == PROVIDER_KUBERNETES || (binding.provider == null && identity.isKubernetes)
            val forgejo = !kubernetes && binding.providerOf(identity) == PROVIDER_FORGEJO
            if (forgejo) {
                // SSO-4472 — a Forgejo Actions job token: its instance's issuer, the repository, the ref, the event.
                appendLine("This job (claims of its Forgejo Actions OIDC token; the token itself is not shown):")
                appendLine(field("iss", identity.issuer))
                appendLine(field("sub", identity.subject))
                appendLine(field("aud", identity.audience.joinToString().ifEmpty { null }))
                appendLine(field("repository", identity.repository))
                appendLine(field("repository_id", identity.repositoryId))
                appendLine(field("repository_owner_id", identity.repositoryOwnerId))
                appendLine(field("ref", identity.ref))
                appendLine(field("base_ref", identity.baseRef))
                appendLine(field("event_name", identity.eventName))
                appendLine(field("trigger class", ForgejoTriggerMapping.classify(identity.eventName).wire))
            } else if (kubernetes) {
                // SSO-3684 — a pod's projected ServiceAccount token has a different public shape.
                appendLine("This pod (claims of its projected ServiceAccount token; the token itself is not shown):")
                appendLine(field("iss", identity.issuer))
                appendLine(field("sub", identity.subject))
                appendLine(field("aud", identity.audience.joinToString().ifEmpty { null }))
                appendLine(field("namespace", identity.kubernetesNamespace))
                appendLine(field("service account", identity.kubernetesServiceAccount))
            } else {
                appendLine("This job (claims of its GitHub OIDC token; the token itself is not shown):")
                appendLine(field("sub", identity.subject))
                appendLine(field("repository", identity.repository))
                appendLine(field("repository_id", identity.repositoryId))
                appendLine(field("repository_owner_id", identity.repositoryOwnerId))
                appendLine(field("ref", identity.ref))
                appendLine(field("environment", identity.environment))
                appendLine(field("event_name", identity.eventName))
                appendLine(field("runner_environment", identity.runnerEnvironment))
            }
            appendLine()
            val mismatches = localMismatches(identity, binding.audience, binding.pins, binding.provider, binding.kubernetesPins, binding.forgejoPins, binding.forgejoPlanProfile)
            val pinsKnown = when {
                kubernetes -> binding.kubernetesPins != null
                forgejo -> binding.forgejoPins != null
                else -> binding.pins != null
            }
            if (mismatches.isNotEmpty()) {
                appendLine("Differences found locally:")
                mismatches.forEach { appendLine("  - $it") }
            } else {
                appendLine(
                    when {
                        pinsKnown -> "No difference found locally against the pins the connection names."
                        kubernetes -> "No difference found locally (name the trust's pins in the connection's auth.kubernetes to have the CLI compare them)."
                        forgejo -> "No difference found locally (name the trust's pins in the connection's auth.forgejo to have the CLI compare them)."
                        else -> "No difference found locally (name the trust's pins in the connection's auth.github to have the CLI compare them)."
                    },
                )
            }
            appendLine()
            appendLine(
                if (forgejo) {
                    "Compare the job above with the trust (`thoryn workload-identity trusts get <id>`): its client id, audience, " +
                        "instance (the token's issuer), repository ids and ref must all match, and it must live in the environment " +
                        "the audience names. Whoever administers the instance controls its signing keys."
                } else if (kubernetes) {
                    "Compare the pod above with the trust (`thoryn workload-identity trusts get <id>`): its client id, audience, " +
                        "issuer, namespace and service account must all match, the token must be a PROJECTED one (a `kubernetes.io` " +
                        "claim), and the trust must live in the environment the audience names. A cluster that rotated its " +
                        "signing key needs the trust's inline JWKS replaced."
                } else {
                    "Compare the job above with the trust (`thoryn workload-identity trusts get <id>`): its client id, audience, " +
                        "repository ids, GitHub environment, ref and runner pin must all match, and it must live in the " +
                        "environment the audience names."
                },
            )
            appendLine()
            // SSO-3710 / SSO-3722 — the fix, from the ONE renderer the fix request is rendered with: the plan-profile gap is
            // an item with the same `set-plan-profile` command `--fix-request` writes; every other shape is a file / job edit.
            append(FixRequest.render(fix.items, fix.notes, consentUrl))
        }
    }

    /** SSO-3702 / SSO-3700 — the hub's `error_description` when a plan-profile job asks for a scope outside the plan profile. */
    const val REASON_OUTSIDE_PLAN: String = "scope_outside_plan_profile"

    /** SSO-3702 / SSO-3700 — the hub's `error_description` when an apply-profile job asks for a scope outside the trust's scopes. */
    const val REASON_OUTSIDE_APPLY: String = "scope_outside_apply_profile"

    /** SSO-3702 — the profile an `invalid_scope` description names (`scope_outside_<profile>_profile`), or null. */
    internal fun profileOutside(description: String?): WorkloadProfile? = when {
        description == null -> null
        description.contains(REASON_OUTSIDE_PLAN) -> WorkloadProfile.PLAN
        description.contains(REASON_OUTSIDE_APPLY) -> WorkloadProfile.APPLY
        else -> null
    }

    private fun field(name: String, value: String?): String = "  ${name.padEnd(20)} ${value ?: "(none)"}"

    /** A platform description is shown on one line and bounded, never trusted as formatting. */
    private fun sanitize(s: String): String = s.replace(Regex("\\s+"), " ").trim().take(300)
}
