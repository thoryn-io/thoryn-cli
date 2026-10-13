package com.devnow.thoryn.cli.auth

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

/** SSO-3308 — everything a workload identity sign-in sends, plus the pins it may compare against. */
data class WorkloadIdentityBinding(
    val clientId: String,
    val audience: String,
    val tokenEndpoint: String,
    /** Space-separated scopes to request, or null for the trust's full set. */
    val scope: String?,
    val pins: TrustPins? = null,
)

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
     * Differences between the job and what the trust requires that the CLI can see without the
     * platform: the issuer and audience of the job token, the event kinds the platform always (or on
     * production) refuses, and — when [pins] are known — each pinned field.
     */
    fun localMismatches(identity: JobIdentity, audience: String, pins: TrustPins?): List<String> = buildList {
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
     * True when [audience] names an environment's PRODUCTION plane: a sandbox audience always carries
     * the `/{environment}` path (oathy #3787 D5), so an audience with no path is the workspace issuer
     * (or its custom domain) itself.
     */
    internal fun namesProductionPlane(audience: String): Boolean {
        val path = runCatching { URI(audience.trim()).path }.getOrNull() ?: return false
        return path.trim('/').isEmpty()
    }

    /** The whole multi-line report for a failed sign-in (no trailing newline). */
    fun render(e: WorkloadIdentityException, binding: WorkloadIdentityBinding): String {
        val identity = e.jobIdentity
        // Failures before the exchange (no runner vars, GitHub refused the job-token request): the message says it all.
        if (identity == null) return "Sign-in failed: ${e.message}"

        return buildString {
            when (e.oauthError) {
                "invalid_client" -> {
                    appendLine("Sign-in failed: the platform refused the workload identity exchange (HTTP ${e.status ?: 401}: invalid_client).")
                    appendLine("The platform does not say which check failed. The exact reason is in the workspace audit log")
                    appendLine("(event $AUDIT_EVENT, field errorReason); a workspace admin can read it with:")
                    appendLine("    $AUDIT_COMMAND")
                }
                "invalid_scope" -> {
                    appendLine("Sign-in failed: the requested scope is not within the trust's scopes (HTTP ${e.status ?: 400}: invalid_scope).")
                    appendLine("Request a subset of the trust's scopes, or no --scope at all to receive the trust's full set.")
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
            appendLine(field("scope", binding.scope ?: "(none requested — the trust's full set)"))
            appendLine()
            appendLine("This job (claims of its GitHub OIDC token; the token itself is not shown):")
            appendLine(field("sub", identity.subject))
            appendLine(field("repository", identity.repository))
            appendLine(field("repository_id", identity.repositoryId))
            appendLine(field("repository_owner_id", identity.repositoryOwnerId))
            appendLine(field("ref", identity.ref))
            appendLine(field("environment", identity.environment))
            appendLine(field("event_name", identity.eventName))
            appendLine(field("runner_environment", identity.runnerEnvironment))
            appendLine()
            val mismatches = localMismatches(identity, binding.audience, binding.pins)
            if (mismatches.isNotEmpty()) {
                appendLine("Differences found locally:")
                mismatches.forEach { appendLine("  - $it") }
            } else {
                appendLine(
                    if (binding.pins != null) {
                        "No difference found locally against the pins the connection names."
                    } else {
                        "No difference found locally (name the trust's pins in the connection's auth.github to have the CLI compare them)."
                    },
                )
            }
            appendLine()
            append(
                "Compare the job above with the trust (`thoryn workload-identity trusts get <id>`): its client id, audience, " +
                    "repository ids, GitHub environment, ref and runner pin must all match, and it must live in the " +
                    "environment the audience names.",
            )
        }
    }

    private fun field(name: String, value: String?): String = "  ${name.padEnd(20)} ${value ?: "(none)"}"

    /** A platform description is shown on one line and bounded, never trusted as formatting. */
    private fun sanitize(s: String): String = s.replace(Regex("\\s+"), " ").trim().take(300)
}
