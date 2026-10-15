package com.devnow.thoryn.provision

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3710 (epic SSO-3304; oauthy ADR `2026-10-15-missing-rights-fix-path-cli-and-web-consent.md` §1) — the **fix
 * request**: the one file a red provisioning job writes, `thoryn-provision-request.json`, naming every RIGHT the
 * repository's identity is missing and the exact CLI command that grants it. The job uploads it as the run artifact
 * [ARTIFACT_NAME]; the Thoryn GitHub App relays it onto the failed check run as "Option 1 — CLI" and offers a web
 * consent a workspace admin approves (SSO-3711 / SSO-3712, in oauthy).
 *
 * Two producers, one shape: `thoryn login --connection --fix-request` on an `invalid_client` refusal whose ONLY local
 * mismatch is the GitHub environment (the trust has no plan profile for the environment the job runs in — a
 * [Kind.PLAN_PROFILE] item), and `thoryn provision plan` / `apply --fix-request` on a plan with `access_*` rows
 * ([fromPlan]: [Kind.OWNER] on an existing object the subject does not own, [Kind.MANAGER] on the parent environment
 * of a refused create, [Kind.VIEWER] for a `readOnly` reference refused for no relation). Rows that are FILE fixes —
 * `access_read_only` on a differing file, `workload_identity_trust_is_self` / `_immutable`, `scope_not_grantable` —
 * produce no item; they are listed under [notes] so the request says so.
 *
 * **The request is a hypothesis, not a credential.** Every binding field it carries — repository ids, run id, head
 * sha — is taken by the consumer from GitHub's own `workflow_run` record and the body's copy is discarded; the body
 * contributes only the `missing` items and the trust it names. Nothing here grants anything: the commands are what a
 * WORKSPACE ADMIN runs (or approves) — `owner` is never set by a manager or by the repository's own identity.
 *
 * **One renderer.** The prose the CLI prints for these failures and the `cli` string the JSON carries come from the
 * same functions ([grantCommand], [setPlanProfileCommand], [render]), so the check run and the terminal never
 * disagree. Schema: [SCHEMA_RESOURCE], shipped beside `provision.schema.json`.
 *
 * **SSO-3722 / SSO-3723 — every refusal ends with "To fix", in two options.** [render] is the ONE block every red
 * sign-in and every red plan row ends with: `To fix — Option 1, with the CLI (a workspace admin):` (the items' commands
 * and the notes' file edits) and `To fix — Option 2, in the browser:` (the run's consent link, [consentUrl], or
 * [NO_CONSENT_LINK_LINE]). The request carries the same two as [Options] (`options.cli`, `options.consentUrl`). A
 * refusal whose fix is a FILE edit (a connection.json without its apply environment, a scope outside the trust's)
 * has no item: it is a note, and the request is still written so the App can show it.
 */
data class FixRequest(
    /** The schema version of this document ([VERSION]). */
    val version: Int = VERSION,
    /** The `thoryn` CLI that wrote it (`thoryn --version`), or null when unknown. */
    val cliVersion: String?,
    /** The repository the job ran for, from the job's own OIDC claims / runner variables — a HINT the consumer rebinds. */
    val repository: Repository?,
    /** The run, from the runner variables and the job token's `environment` claim — a HINT the consumer rebinds. */
    val run: Run?,
    /** The workspace slug the identity signs in to (the connection's `workspace.slug` / the session's workspace). */
    val workspace: String?,
    /** `provision plan` / `apply` only: the provisioning file and its digest, so the consumer can re-read it at the head sha. */
    val file: FileRef?,
    /** The trust the identity presents: what the producer could tell, null fields when it could not. */
    val trust: Trust,
    /** The rights that are missing, each with the command that grants it. */
    val missing: List<MissingRight>,
    /** Failed rows that are NOT a missing right (a file fix), so the request says so instead of staying silent. */
    val notes: List<String> = emptyList(),
    /**
     * SSO-3723 — "Option 2, in the browser": the consent link for THIS run, resolvable by run
     * (`<consentBaseUrl>/github/consent/run/<owner>/<repository>/<run_id>`, [consentUrl]), or null when the job has no
     * configured base URL ([CONSENT_URL_ENV]) or is not a GitHub Actions run. The App resolves it to the consent it mints.
     */
    val consentUrl: String? = null,
) {
    /**
     * SSO-3723 — the two options a reader has, as DATA: [Options.cli] is the Option-1 body exactly as the log prints it
     * (the commands and the file edits, one rendering), [Options.consentUrl] the Option-2 link or null.
     */
    data class Options(val cli: String?, val consentUrl: String?) {
        fun toStructured(): Map<String, Any?> = linkedMapOf("cli" to cli, "consentUrl" to consentUrl)
    }

    /** The two options of this request — what the check-run summary shows and what the log printed. */
    val options: Options get() = Options(renderOption1Body(missing, notes).ifEmpty { null }, consentUrl)

    /** GitHub's names and immutable ids of the repository (`GITHUB_REPOSITORY*` / the OIDC `repository*` claims). */
    data class Repository(val owner: String?, val ownerId: Long?, val repository: String?, val repositoryId: Long?)

    /** The run id and head sha (`GITHUB_RUN_ID` / `GITHUB_SHA`) and the GitHub environment the job declared. */
    data class Run(val id: Long?, val headSha: String?, val jobEnvironment: String?)

    /** The provisioning file as planned: its path as given and the `sha256:` digest the plan header prints. */
    data class FileRef(val path: String, val sha256: String)

    /**
     * The trust: [name] / [id] when the producer could resolve them (a session that may list trusts), [clientId] the
     * `wi_` workload client the identity signs in as (always known from the connection or the session), [plane] the
     * environment the trust lives in (`production` for the plane without one), [applyEnvironment] the GitHub
     * environment the trust pins for apply when known (the connection's `auth.github.environment`).
     */
    data class Trust(val name: String?, val plane: String?, val applyEnvironment: String?, val id: String?, val clientId: String?)

    /** The kinds of right a request may ask for — exactly the ADR's grantable set, nothing else. */
    enum class Kind(val wire: String) {
        /** A plan profile on the trust for the environment the job ran in (`trusts set-plan-profile`). */
        PLAN_PROFILE("plan_profile"),
        /** The platform `owner` relation on an existing object the file declares (`access grant … owner …`). */
        OWNER("owner"),
        /** `manager` on the parent environment of a resource the file would create. */
        MANAGER("manager"),
        /** `viewer` on an existing object the file declares `readOnly: true`. */
        VIEWER("viewer");

        companion object {
            fun of(wire: String?): Kind? = entries.firstOrNull { it.wire == wire }
        }
    }

    /**
     * One missing right. [objectRef] is the platform object (`application:cli`, `environment:<id>`, `trust:<name>`),
     * [subject] the identity to grant it to (`client:<wi_>`; null for a plan profile, which is set on the trust),
     * [environment] the GitHub environment a [Kind.PLAN_PROFILE] is for, [reason] the engine's row reason or the
     * sign-in's finding, and [cli] the command a workspace admin runs — null when the right is a DISPUTE the CLI
     * shows but never resolves (an object another repository owns: the admin decides, the Owner ADR's
     * revoke-then-grant is in the reason).
     */
    data class MissingRight(
        val kind: Kind,
        val objectRef: String?,
        val subject: String?,
        val environment: String?,
        val reason: String,
        val cli: String?,
    ) {
        fun toStructured(): Map<String, Any?> = linkedMapOf(
            "kind" to kind.wire,
            "object" to objectRef,
            "subject" to subject,
            "environment" to environment,
            "reason" to reason,
            "cli" to cli,
        )
    }

    fun toStructured(): Map<String, Any?> = linkedMapOf(
        "version" to version,
        "cliVersion" to cliVersion,
        "repository" to repository?.let { linkedMapOf("owner" to it.owner, "ownerId" to it.ownerId, "repository" to it.repository, "repositoryId" to it.repositoryId) },
        "run" to run?.let { linkedMapOf("id" to it.id, "headSha" to it.headSha, "jobEnvironment" to it.jobEnvironment) },
        "workspace" to workspace,
        "file" to file?.let { linkedMapOf("path" to it.path, "sha256" to it.sha256) },
        "trust" to linkedMapOf("name" to trust.name, "plane" to trust.plane, "applyEnvironment" to trust.applyEnvironment, "id" to trust.id, "clientId" to trust.clientId),
        "missing" to missing.map { it.toStructured() },
        "notes" to notes,
        "options" to options.toStructured(),
    )

    fun toJson(mapper: ObjectMapper = jacksonObjectMapper()): String =
        mapper.writerWithDefaultPrettyPrinter().writeValueAsString(toStructured()) + "\n"

    /** Write the document to [path] (parent directories created). Never a secret: ids, names, commands. */
    fun write(path: Path, mapper: ObjectMapper = jacksonObjectMapper()) {
        path.toAbsolutePath().parent?.let { Files.createDirectories(it) }
        Files.writeString(path, toJson(mapper))
    }

    companion object {
        const val VERSION: Int = 1

        /** The file name the workflows write and upload (the ADR's one file). */
        const val FILE_NAME: String = "thoryn-provision-request.json"

        /** The run artifact name the App looks for on `workflow_run.completed`. */
        const val ARTIFACT_NAME: String = "thoryn-provision-request"

        /** The env var spelling of `--fix-request <file>` — an older CLI ignores it, which is what lets a workflow set it before it pins a release that reads it. */
        const val ENV: String = "THORYN_FIX_REQUEST"

        /** The bundled schema (beside `provision.schema.json`). */
        const val SCHEMA_RESOURCE: String = "/provision/fix-request.schema.json"

        /** The placeholder for a subject the producer could not name (an opaque session token). */
        const val SUBJECT_PLACEHOLDER: String = "<subject>"

        /** The placeholder for a trust id the producer could not resolve (a sign-in that was refused holds no token). */
        const val TRUST_ID_PLACEHOLDER: String = "<trust-id>"

        /** The command that resolves [TRUST_ID_PLACEHOLDER]: lists the workspace's trusts with their pins. */
        const val LIST_TRUSTS_COMMAND: String = "thoryn workload-identity trusts list"

        /**
         * SSO-3723 — the env var naming the consent BASE URL (configuration: `.thoryn/workflow.yaml` `consentUrl` or the
         * reusable workflow's `consent-url` input — never guessed from the issuer). Unset ⇒ Option 1 alone.
         */
        const val CONSENT_URL_ENV: String = "THORYN_CONSENT_URL"

        /** The heading of Option 1 — the commands / file edits a workspace admin (or the repository) runs. */
        const val OPTION_CLI_HEADING: String = "To fix — Option 1, with the CLI (a workspace admin):"

        /** The heading of Option 2 — the browser consent for this run. */
        const val OPTION_BROWSER_HEADING: String = "To fix — Option 2, in the browser:"

        /** What Option 2 says when no link can be built: no configured base URL, or not a GitHub Actions run. */
        const val NO_CONSENT_LINK_LINE: String = "Run through the Thoryn GitHub App to get a browser link."

        /**
         * SSO-3723 — the consent link for ONE run: `<base>/github/consent/run/<owner>/<repository>/<runId>`, built from the
         * job's own GitHub context; null unless the base URL, both repository names and the run id are all known. The
         * opaque consent id the App mints after the run completes is unknowable here, so the link is resolvable BY RUN
         * (the orchestrator's `/github/consent/run/{owner}/{repo}/{runId}`, oauthy SSO-3723).
         */
        fun consentUrl(baseUrl: String?, owner: String?, repository: String?, runId: Long?): String? {
            val base = baseUrl?.trim()?.trimEnd('/')?.takeIf { it.startsWith("https://") || it.startsWith("http://") } ?: return null
            if (owner.isNullOrBlank() || repository.isNullOrBlank() || runId == null) return null
            return "$base/github/consent/run/${owner.trim()}/${repository.trim()}/$runId"
        }

        /** `thoryn access grant <subject> <relation> <object>` — THE spelling of a grant, for the prose and the JSON alike. */
        fun grantCommand(subject: String?, relation: String, objectRef: String): String =
            "thoryn access grant ${subject ?: SUBJECT_PLACEHOLDER} $relation $objectRef"

        /** `thoryn workload-identity trusts set-plan-profile <id> --plan-environment <env>` — the plan profile's one additive call. */
        fun setPlanProfileCommand(trustId: String?, planEnvironment: String): String =
            "thoryn workload-identity trusts set-plan-profile ${trustId ?: TRUST_ID_PLACEHOLDER} --plan-environment $planEnvironment"

        /**
         * The [Kind.PLAN_PROFILE] item of a refused sign-in: the job ran in [jobEnvironment], the trust pins
         * [applyEnvironment] for apply and the hub refused the exchange — so the trust needs a plan profile for the
         * job's environment. [trustName] / [trustId] when known (a connection names neither; the id is a placeholder).
         */
        fun planProfile(trustName: String?, trustId: String?, jobEnvironment: String, applyEnvironment: String?): MissingRight = MissingRight(
            kind = Kind.PLAN_PROFILE,
            objectRef = trustName?.let { "trust:$it" },
            subject = null,
            environment = jobEnvironment,
            reason = "the job runs in GitHub environment '$jobEnvironment'; the trust pins " +
                (applyEnvironment?.let { "apply environment '$it'" } ?: "another environment") +
                " and has no plan profile for the job's, so the exchange was refused (environment_mismatch, as invalid_client)",
            cli = setPlanProfileCommand(trustId, jobEnvironment),
        )

        /** An existing object the file declares and [subject] does not own: `owner` (set by a workspace admin only). */
        fun owner(subject: String?, objectRef: String, reason: String): MissingRight =
            MissingRight(Kind.OWNER, objectRef, subject, null, reason, grantCommand(subject, AccessRefs.RELATION_OWNER, objectRef))

        /**
         * An existing object another repository OWNS: the dispute the CLI shows and never resolves — no command, the
         * reason carries the Owner ADR's revoke-then-grant for an admin who decides.
         */
        fun ownedElsewhere(subject: String?, objectRef: String, reason: String): MissingRight =
            MissingRight(Kind.OWNER, objectRef, subject, null, reason, cli = null)

        /** A create refused for no `manager` on its parent environment (never on the workspace — see [fromPlan]). */
        fun manager(subject: String?, parentRef: String, reason: String): MissingRight =
            MissingRight(Kind.MANAGER, parentRef, subject, null, reason, grantCommand(subject, AccessRefs.RELATION_MANAGER, parentRef))

        /** A `readOnly: true` reference the identity holds no relation on: `viewer`. */
        fun viewer(subject: String?, objectRef: String, reason: String): MissingRight =
            MissingRight(Kind.VIEWER, objectRef, subject, null, reason, grantCommand(subject, AccessRefs.RELATION_VIEWER, objectRef))

        /**
         * The items and notes of a red [plan]: every `ERROR` row carrying a [PlannedChange.fix] is an item; every other
         * `ERROR` row (a file fix, a trust the file cannot declare, a scope the identity does not hold) is a note.
         */
        fun fromPlan(plan: ProvisionPlan): Pair<List<MissingRight>, List<String>> {
            val items = plan.errors.mapNotNull { it.fix }
            val notes = plan.errors.filter { it.fix == null }.map { "${it.kind} ${it.name}: ${it.fixNote ?: it.reason}" }
            return items to notes
        }

        /**
         * THE rendering of what is missing — the "To fix" block the CLI prints on stderr after every refusal and what a
         * reader copies. SSO-3723: two options in one fixed shape. Option 1 ([OPTION_CLI_HEADING]) lists each missing
         * right — its kind and object, the reason, the command (indented, one line) and, for a placeholder trust id, the
         * command that resolves it — then every [notes] entry as a FILE edit. Option 2 ([OPTION_BROWSER_HEADING]) is the
         * run's consent link, or [NO_CONSENT_LINK_LINE] when none can be built. The same text is the request's
         * [Options]. Nothing to fix (no item, no note) ⇒ empty string.
         */
        fun render(items: List<MissingRight>, notes: List<String> = emptyList(), consentUrl: String? = null, writtenTo: Path? = null): String {
            val body = renderOption1Body(items, notes)
            if (body.isEmpty()) return ""
            return buildString {
                appendLine(OPTION_CLI_HEADING)
                appendLine(body)
                append(OPTION_BROWSER_HEADING).append(' ').append(consentUrl ?: NO_CONSENT_LINK_LINE)
                writtenTo?.let { appendLine(); append("(fix request written to $it)") }
            }
        }

        /** The body of Option 1 — the items then the notes, without the heading (the request's `options.cli`). */
        fun renderOption1Body(items: List<MissingRight>, notes: List<String> = emptyList()): String = buildString {
            items.forEach { item ->
                val target = item.objectRef ?: item.environment?.let { "GitHub environment '$it'" } ?: "(unknown object)"
                appendLine("  - ${item.kind.wire} on $target" + (item.subject?.let { " for $it" } ?: "") + ": ${item.reason}")
                when {
                    item.cli != null -> {
                        appendLine("      ${item.cli}")
                        if (item.cli.contains(TRUST_ID_PLACEHOLDER)) appendLine("      ($TRUST_ID_PLACEHOLDER: `$LIST_TRUSTS_COMMAND` shows the trust pinned to this repository and its id)")
                    }
                    else -> appendLine("      (no command runs for you: an admin decides — declare it `readOnly: true`, or move the ownership as the reason says)")
                }
            }
            notes.forEach { appendLine("  - $it") }
        }.trimEnd()

        /** The prose hint the engine appends to a row's reason for a right it can name — the same [MissingRight.cli]. */
        fun hint(item: MissingRight): String = item.cli?.let { "a workspace admin grants it with `$it`" } ?: ""
    }
}
