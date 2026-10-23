package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.provision.MissingScopeException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPlan
import com.devnow.thoryn.provision.ScopeRequirements
import com.devnow.thoryn.provision.ScopeRequirements.Phase

/**
 * SSO-3926 — `config.trust-scopes`: the scopes a provisioning file needs ([ScopeRequirements]) held against the scopes the
 * identity that plans and applies it signs in with, and — when one is missing — WHERE to add it, named for the identity
 * at hand. Three places ask, with one wording:
 *
 *  - `thoryn provision workflow check` ([evaluate]) — statically, against `connection.json` `auth.scopes` (the trust's apply
 *    profile, which the CLI requests exactly) and the trust's PLAN profile as the connection implies it: a plan profile set
 *    without explicit scopes is every `.read` scope of the trust (product-api `WorkloadIdentityTrustController`), and an
 *    explicit one must be among the trust's scopes — so a read scope the connection does not list cannot be in the profile.
 *    The repository identity cannot read its own trust's profile (that needs `tenant:workload-identity.read`, the very scope
 *    this rule is most often about), so the check derives it and `provision plan` re-checks against the token itself.
 *  - `thoryn provision plan` / `apply` ([preflight]) — before the first read, against the scopes the session's token carries:
 *    a plan-profile job is minted exactly its profile, so a missing plan scope is named there, not met as a `403`.
 *  - a `403` that happens anyway ([MissingScopeException], [render]) — the same message: which scope, which profile.
 */
internal object TrustScopes {

    const val RULE_ID = "config.trust-scopes"

    /** Who is signed in, as far as "where do I add the scope" goes. */
    data class Session(val authMode: String?, val profile: String?, val clientId: String?, val jobEnvironment: String?) {
        val isWorkloadIdentity: Boolean get() = authMode == Tokens.AUTH_MODE_WORKLOAD_IDENTITY
        val isApiKey: Boolean get() = authMode == Tokens.AUTH_MODE_CLIENT_CREDENTIALS

        companion object {
            fun of(tokens: Tokens): Session = Session(tokens.authMode, tokens.profile, tokens.clientId, tokens.jobEnvironment)
        }
    }

    /** SSO-3925 — a trust's scopes change in place (`trusts set-scopes`): same trust, same wi_ client, no ownership moves. */
    const val TRUST_FIXED_NOTE: String =
        "Add it in place with `thoryn workload-identity trusts set-scopes <trust> --scope <scope> --plan-scope <scope>`: the trust " +
            "keeps its id and wi_ client, so connection.json and ownership stay as they are. Narrowing works from CI; widening " +
            "is a person's act with a recent passkey sign-in (`thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300`)."

    /**
     * Where [scopes], needed in [phase], are added for [session] — one sentence a person can act on. [connection] is the
     * connection file the session signed in with, when the caller knows it (the workflow check does; a run does not).
     */
    fun where(scopes: List<String>, phase: Phase, session: Session, connection: String? = null): String {
        val list = scopes.joinToString(" ")
        val conn = connection ?: "its connection.json"
        val trust = session.clientId?.let { "trust $it" } ?: "the workload identity trust"
        return when {
            session.isWorkloadIdentity && session.profile == Tokens.PROFILE_PLAN && phase == Phase.PLAN ->
                "add $list to the plan profile of $trust — the read-only scopes a job in GitHub environment " +
                    "'${session.jobEnvironment ?: "<plan environment>"}' is minted. A plan scope must also be among the trust's scopes " +
                    "($conn auth.scopes lists them). $TRUST_FIXED_NOTE"
            session.isWorkloadIdentity && session.profile == Tokens.PROFILE_PLAN ->
                "this session holds the PLAN profile of $trust (GitHub environment '${session.jobEnvironment ?: "<plan environment>"}'), " +
                    "which never writes — run apply in the trust's apply environment, whose scopes must carry $list " +
                    "(the trust's scopes and $conn auth.scopes). $TRUST_FIXED_NOTE"
            session.isWorkloadIdentity ->
                "add $list to the scopes of $trust (its apply profile) and to auth.scopes of $conn" +
                    (if (phase == Phase.PLAN) " — and, for a github_actions trust, to its plan profile when the plan job signs in under it" else "") +
                    ". $TRUST_FIXED_NOTE"
            session.isApiKey ->
                "grant the API key client ${session.clientId ?: "this session signs in with"} $list and list it in auth.scopes of $conn " +
                    "(`thoryn login --connection` requests exactly those)"
            else ->
                "sign in with it: `thoryn login --scope $list` (--scope replaces the default set — list every scope you use)"
        }
    }

    /**
     * The run-time check before a plan ([Phase.PLAN], from the file) or an apply ([Phase.APPLY], from the computed [plan]):
     * the message to print when the session's token ([held]) lacks a scope the work needs, else null. Null as well when the
     * token's scopes are unknown (an opaque token) — the API's own `403` then names it ([render]). A conditional plan need
     * (a sandbox id resolved only for a create) never blocks here.
     */
    fun preflight(file: ProvisionFile, prune: Boolean, held: Set<String>?, session: Session, plan: ProvisionPlan? = null): String? {
        held ?: return null
        val phase = if (plan == null) Phase.PLAN else Phase.APPLY
        val needs = if (plan == null) {
            ScopeRequirements.of(file, prune).filter { it.phase == Phase.PLAN && !it.conditional }
        } else {
            ScopeRequirements.forChanges(plan)
        }
        val missing = ScopeRequirements.missing(needs, held)
        if (missing.isEmpty()) return null
        val grouped = ScopeRequirements.byScope(missing)
        val verb = if (phase == Phase.PLAN) "plan" else "apply"
        return buildString {
            appendLine("Error: $RULE_ID — this session's token does not carry ${grouped.size} scope(s) ${file.source} needs to $verb:")
            grouped.forEach { (scope, why) -> appendLine("  - $scope — ${why.joinToString("; ") { it.label }}") }
            appendLine("To fix: ${where(grouped.keys.toList(), phase, session)}")
            append(if (phase == Phase.PLAN) "Nothing was read or written." else "Nothing was changed.")
        }
    }

    /** A [MissingScopeException] the engine raised from a `403`, with the profile to add the scope to. */
    fun render(ex: MissingScopeException, session: Session): String =
        "Error: $RULE_ID — ${ex.resource?.let { "$it: " } ?: ""}could not ${ex.operation}: product-api refused it (HTTP 403) because the token " +
            "does not carry ${ex.scope}.\nTo fix: ${where(listOf(ex.scope), ex.phase, session)}"

    // ── the static rule (`thoryn provision workflow check`) ─────────────────────────────────────────────────────

    /** One configured `{file, connection}` pair's verdict: what is missing (each a sentence), and what holds. */
    data class Verdict(val problems: List<String>, val satisfied: String)

    /**
     * [file] (at [filePath]) against [connection] (at [connectionPath]): every scope the file needs to apply must be in
     * `auth.scopes` (the CLI requests exactly those in the apply environment, and the hub refuses one the trust lacks); every
     * scope it needs to PLAN must, for a `github_actions` trust, be in its plan profile too — derived from the connection,
     * see the class doc. [prune] is the workflow's `apply.prune`.
     */
    fun evaluate(file: ProvisionFile, filePath: String, connection: Connection, connectionPath: String, prune: Boolean): Verdict {
        val needs = ScopeRequirements.of(file, prune)
        val declared = connection.scopes.toSet()
        val planProfile = connection.isWorkloadIdentity && connection.effectiveProvider == Connection.PROVIDER_GITHUB_ACTIONS
        val trust = "trust ${connection.clientId}"
        val problems = mutableListOf<String>()
        val missing = ScopeRequirements.byScope(ScopeRequirements.missing(needs, declared))
        missing.forEach { (scope, why) ->
            val toPlan = why.any { it.phase == Phase.PLAN }
            val uses = why.joinToString("; ") { it.label }
            problems += when {
                toPlan && planProfile ->
                    "$filePath needs $scope to PLAN ($uses), and $connectionPath does not declare it — add $scope to the plan profile of $trust " +
                        "(the read-only scopes the plan job is minted) and, because a plan scope must be among the trust's scopes, to the trust's " +
                        "scopes and auth.scopes of $connectionPath"
                toPlan ->
                    "$filePath needs $scope to plan ($uses), and $connectionPath does not declare it — add $scope to the scopes of " +
                        "${if (connection.isWorkloadIdentity) trust else "API key client ${connection.clientId}"} and to auth.scopes of $connectionPath"
                else ->
                    "$filePath needs $scope to APPLY ($uses), and $connectionPath does not declare it — add $scope to the scopes of " +
                        "${if (connection.isWorkloadIdentity) "$trust (its apply profile)" else "API key client ${connection.clientId}"} and to auth.scopes of $connectionPath"
            }
        }
        val planScopes = needs.filter { it.phase == Phase.PLAN }.map { it.scope }.distinct()
        val applyScopes = needs.filter { it.phase == Phase.APPLY }.map { it.scope }.distinct()
        val satisfied = "$filePath needs to plan: ${planScopes.joinToString(" ").ifEmpty { "nothing" }}; to apply, also: " +
            "${applyScopes.filterNot { it in planScopes }.joinToString(" ").ifEmpty { "nothing" }} — $connectionPath declares every one" +
            (if (planProfile) " (the plan profile of $trust must carry the plan scopes: one set without explicit scopes derives every .read scope of the trust; `provision plan` re-checks the minted token)" else "")
        return Verdict(problems, satisfied)
    }

    /** The fix line of a failing [RULE_ID] verdict. */
    const val FIX: String =
        "add each named scope where the line says: a PLAN scope to the trust's plan profile (and so its scopes), an APPLY scope to the trust's " +
            "scopes, and both to connection.json auth.scopes — or drop the resource that needs it. $TRUST_FIXED_NOTE"
}
