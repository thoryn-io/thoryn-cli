package com.devnow.thoryn.provision

/**
 * SSO-3738 (oauthy ADR `2026-10-15-missing-rights-fix-path-cli-and-web-consent.md`, amendment and As built SSO-3737 /
 * SSO-3755) — ONE run a missing-rights consent is for: `<owner>/<repository>/<runId>`, the three names of the by-run
 * consent address `<base>/github/consent/run/<owner>/<repository>/<runId>` that both entry points open — the check run's
 * Option 2 link and `thoryn access approve` (Option 1).
 *
 * **The names are checked against GitHub's own grammar, strictly, before anything is built from them.** They end up in a
 * URL the CLI hands to a browser, so nothing that could change where that URL goes may pass: no `/`, `?`, `#`, `%`,
 * `@`, `\`, whitespace or control character, no `.` / `..` segment, no leading `-` (never an option to the platform
 * opener), no number that is not a run id. The orchestrator never trusts these names either (it resolves them through
 * the App's own records and answers *not found* otherwise) — this is the CLI refusing to build a link that could point
 * anywhere else.
 */
data class ConsentRun(val owner: String, val repository: String, val runId: Long) {

    /** `<owner>/<repository>/<runId>` — the argument `thoryn access approve` takes and the check run prints. */
    val ref: String get() = "$owner/$repository/$runId"

    /** The path under a consent base URL: `/github/consent/run/<owner>/<repository>/<runId>`. */
    val path: String get() = "$PATH_PREFIX/$owner/$repository/$runId"

    /** The by-run consent address under [baseUrl] (already validated by the caller; a trailing `/` is dropped). */
    fun urlUnder(baseUrl: String): String = baseUrl.trimEnd('/') + path

    companion object {
        /** The orchestrator's by-run consent route (oauthy SSO-3723 `/github/consent/run/{owner}/{repository}/{runId}`). */
        const val PATH_PREFIX: String = "/github/consent/run"

        /**
         * A GitHub account login: letters, digits and `-`, 1–39 characters, never starting with `-`. (GitHub also refuses
         * a trailing or doubled `-` for new accounts; older ones exist, so those are accepted — they cannot change a URL.)
         */
        val OWNER: Regex = Regex("^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")

        /** A GitHub repository name: letters, digits, `.`, `_`, `-`, 1–100 characters; never `.` or `..`. */
        val REPOSITORY: Regex = Regex("^[A-Za-z0-9._-]{1,100}$")

        /** A GitHub Actions run id: a positive decimal number that fits a Long, no sign, no leading zero. */
        val RUN_ID: Regex = Regex("^[1-9][0-9]{0,18}$")

        /** The violation of [owner] / [repository] / [runId], or null when all three conform. */
        fun violation(owner: String, repository: String, runId: String): String? = when {
            !OWNER.matches(owner) ->
                "'${printable(owner)}' is not a GitHub account name (letters, digits and '-', 1–39 characters, not starting with '-')"
            !REPOSITORY.matches(repository) || repository == "." || repository == ".." ->
                "'${printable(repository)}' is not a GitHub repository name (letters, digits, '.', '_' and '-', 1–100 characters)"
            !RUN_ID.matches(runId) || runId.toLongOrNull() == null ->
                "'${printable(runId)}' is not a GitHub Actions run id (a positive number — the digits after /actions/runs/ in the run's URL)"
            else -> null
        }

        /** The run of three already-split names, or null when any violates the grammar ([violation]). */
        fun of(owner: String?, repository: String?, runId: String?): ConsentRun? {
            if (owner == null || repository == null || runId == null) return null
            if (violation(owner, repository, runId) != null) return null
            return ConsentRun(owner, repository, runId.toLong())
        }

        /**
         * Parse `<owner>/<repository>/<runId>` exactly — three segments, nothing before or after. The left side carries the
         * value or the human-readable reason it was refused.
         */
        fun parseRef(raw: String): Result {
            val parts = raw.split('/')
            if (parts.size != 3) {
                return Result.Refused("'${printable(raw)}' is not <owner>/<repository>/<run_id> (three parts separated by '/')")
            }
            violation(parts[0], parts[1], parts[2])?.let { return Result.Refused(it) }
            return Result.Ok(ConsentRun(parts[0], parts[1], parts[2].toLong()))
        }

        /**
         * The run a by-run consent LINK names — the trailing `/github/consent/run/<owner>/<repository>/<runId>` of a link
         * the CLI itself built ([FixRequest.consentUrl]) — or null when the link does not end that way. Scheme and host are
         * not judged here (the link is configuration the job was given); `thoryn access approve` judges a link a PERSON
         * passes it far more strictly.
         */
        fun ofConsentLink(link: String?): ConsentRun? {
            if (link == null) return null
            val idx = link.lastIndexOf("$PATH_PREFIX/")
            if (idx < 0) return null
            val rest = link.substring(idx + PATH_PREFIX.length + 1).removeSuffix("/")
            return (parseRef(rest) as? Result.Ok)?.run
        }

        /** Echo a refused value without letting it smuggle a control sequence into the terminal; long values are cut. */
        fun printable(raw: String): String {
            val cleaned = raw.map { if (it.isISOControl()) '?' else it }.joinToString("")
            return if (cleaned.length > 120) cleaned.take(120) + "…" else cleaned
        }
    }

    /** The outcome of [parseRef]: the run, or why the argument was refused. */
    sealed interface Result {
        data class Ok(val run: ConsentRun) : Result
        data class Refused(val reason: String) : Result
    }
}
