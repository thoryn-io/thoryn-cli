package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfigException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.provision.ConsentRun
import java.io.PrintStream
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3738 (oauthy ADR `2026-10-15-missing-rights-fix-path-cli-and-web-consent.md`, amendment + As built SSO-3737 /
 * SSO-3755) — the logic behind `thoryn access approve <owner>/<repo>/<run_id> | <consent URL>`: the CLI entry point to
 * the SAME hub consent the check run's Option-2 link opens.
 *
 * **It grants nothing.** It resolves ONE address — the run's by-run consent, `<base>/github/consent/run/<owner>/<repo>/<run_id>`
 * — and hands it to the browser, or prints it to open on any device (the sign-in pattern). It makes no HTTP request of
 * its own, so it follows no redirect: the browser goes to the starters service, which rebuilds the request from GitHub's
 * record of the run and redirects to the hub's consent screen, where a workspace admin approves item by item. Every
 * decision — which workspace, which rights, whether the visitor may grant them — is made there, not here.
 *
 * **The base URL, in order** ([resolve]):
 *  1. a consent URL passed as the argument (the check run's or the job log's Option-2 link) — it names its own base;
 *  2. `--consent-url <base>`;
 *  3. the `consentUrl` of the nearest `.thoryn/workflow.yaml` from the working directory up to the repository root
 *     (running it inside the repository uses that deployment's address — what the job log's link was built from);
 *  4. derived from the signed-in session's platform: `https://starters.<platform domain>`, the platform domain being the
 *     base issuer without its host label (`https://auth.stg.thoryn.org` ⇒ `https://starters.stg.thoryn.org`).
 * None of them ⇒ a usage error naming the two ways to pass one.
 *
 * **Strict input.** The run names follow GitHub's grammar ([ConsentRun]); a consent URL must be `https://`, a DNS host
 * (lowercased), an optional port, an optional plain path prefix, and end in exactly `/github/consent/run/<owner>/<repo>/<run_id>`
 * — no user-info, query, fragment, percent-encoding, backslash, whitespace or dot segment. The URL handed to the browser
 * is REBUILT from the validated parts, never the string as typed.
 */
internal object AccessApprove {

    /** The browser opener; tests replace it (it returns whether a browser was launched — never throws). */
    @Volatile
    internal var opener: (String) -> Boolean = BrowserLauncher::open

    /** Where `.thoryn/workflow.yaml` is looked for (upwards to the repository root); tests replace it. */
    @Volatile
    internal var workingDirectory: () -> Path = { Path.of(System.getProperty("user.dir")).toAbsolutePath() }

    /** The signed-in session, read quietly (null when there is none); tests replace it. */
    @Volatile
    internal var session: () -> Tokens? = { runCatching { TokenStoreFactory.default().read() }.getOrNull() }

    internal fun resetForTest() {
        opener = BrowserLauncher::open
        workingDirectory = { Path.of(System.getProperty("user.dir")).toAbsolutePath() }
        session = { runCatching { TokenStoreFactory.default().read() }.getOrNull() }
    }

    /** The host prefix of the platform-derived consent base: `starters.<platform domain>` (oauthy starter-orchestrator). */
    const val STARTERS_HOST_LABEL: String = "starters"

    /** Where the consent base came from — printed, so a reader can tell which deployment the link points at. */
    enum class Source(val describe: String) {
        ARGUMENT("the consent URL you passed"),
        FLAG("--consent-url"),
        WORKFLOW_CONFIG("the repository's .thoryn/workflow.yaml consentUrl"),
        PLATFORM("your signed-in platform (starters.<platform domain>)"),
    }

    /** The resolved consent: the run, the address to open, and where its base came from. */
    data class Target(val run: ConsentRun, val url: String, val source: Source)

    /** The outcome of [resolve]. */
    sealed interface Resolution {
        data class Ok(val target: Target) : Resolution
        data class Refused(val message: String) : Resolution
    }

    /**
     * Resolve [argument] (`<owner>/<repo>/<run_id>` or a consent URL) and [consentUrlFlag] to the address to open, by the
     * order in the class KDoc. [err] receives the notes (an ignored flag, an unreadable `.thoryn/workflow.yaml`).
     */
    fun resolve(argument: String, consentUrlFlag: String?, err: PrintStream = System.err): Resolution {
        val arg = argument.trim()
        if (looksLikeUrl(arg)) {
            val parsed = parseConsentUrl(arg)
            if (parsed is UrlParse.Refused) return Resolution.Refused(parsed.reason)
            parsed as UrlParse.Ok
            if (!consentUrlFlag.isNullOrBlank()) err.println("Note: --consent-url is ignored — the consent URL you passed names its own address.")
            return Resolution.Ok(Target(parsed.run, parsed.run.urlUnder(parsed.base), Source.ARGUMENT))
        }
        val run = when (val r = ConsentRun.parseRef(arg)) {
            is ConsentRun.Result.Refused -> return Resolution.Refused(r.reason + " — pass <owner>/<repository>/<run_id> or the consent URL from the check run.")
            is ConsentRun.Result.Ok -> r.run
        }
        consentUrlFlag?.trim()?.takeIf { it.isNotEmpty() }?.let { flag ->
            val base = validateBase(flag) ?: return Resolution.Refused(baseRefusal("--consent-url", flag))
            return Resolution.Ok(Target(run, run.urlUnder(base), Source.FLAG))
        }
        workflowConfigBase(err)?.let { return Resolution.Ok(Target(run, run.urlUnder(it), Source.WORKFLOW_CONFIG)) }
        startersBaseFor(session())?.let { return Resolution.Ok(Target(run, run.urlUnder(it), Source.PLATFORM)) }
        return Resolution.Refused(
            "no consent address for ${run.ref}: pass the consent URL from the check run (`thoryn access approve " +
                "https://starters.<your Thoryn domain>${run.path}`), or --consent-url https://starters.<your Thoryn domain>, " +
                "or sign in to the platform (`thoryn login`) so the address can be derived from it.",
        )
    }

    /** Anything with a scheme is judged as a URL (and refused unless it is an https consent URL). */
    internal fun looksLikeUrl(raw: String): Boolean = raw.contains("://") || raw.contains(':')

    /** The outcome of [parseConsentUrl]. */
    sealed interface UrlParse {
        data class Ok(val base: String, val run: ConsentRun) : UrlParse
        data class Refused(val reason: String) : UrlParse
    }

    /** `https://` + host + optional port + optional plain path prefix + the by-run path, nothing else (checked again below). */
    private val CONSENT_URL = Regex(
        "^https://([A-Za-z0-9.-]+)(:[0-9]{1,5})?((?:/[A-Za-z0-9._~-]+)*)" + Regex.escape(ConsentRun.PATH_PREFIX) + "/([^/]+)/([^/]+)/([^/]+)/?$",
    )

    /**
     * Parse a consent URL a PERSON passed: the base it names and the run. Refused unless it is exactly the shape in the
     * class KDoc; the base is rebuilt (lowercased host) and must then satisfy the same grammar a configured base does.
     */
    fun parseConsentUrl(raw: String): UrlParse {
        val shown = ConsentRun.printable(raw)
        if (!raw.startsWith("https://")) {
            return UrlParse.Refused("'$shown' is not an https:// consent URL — only https:// links are opened")
        }
        val m = CONSENT_URL.matchEntire(raw)
            ?: return UrlParse.Refused(
                "'$shown' is not a consent URL: expected https://<host>${ConsentRun.PATH_PREFIX}/<owner>/<repository>/<run_id> " +
                    "(no user-info, query, fragment or encoded characters)",
            )
        val (host, port, prefix, owner, repository, runId) = m.destructured
        ConsentRun.violation(owner, repository, runId)?.let { return UrlParse.Refused(it) }
        val base = validateBase("https://" + host.lowercase() + port + prefix)
            ?: return UrlParse.Refused("'$shown' does not name a valid https host for the consent")
        return UrlParse.Ok(base, ConsentRun(owner, repository, runId.toLong()))
    }

    /**
     * A consent BASE (`--consent-url`, `.thoryn/workflow.yaml` `consentUrl`, or the base a consent URL names) normalised
     * (trailing `/` dropped), or null when it is not an `https://` DNS host with an optional port in range and an
     * optional plain path — the configuration grammar ([WorkflowConfig.CONSENT_URL_GRAMMAR]) plus no empty or dot path
     * segment, and not already a by-run address.
     */
    fun validateBase(raw: String): String? {
        val base = raw.trim().trimEnd('/')
        if (!WorkflowConfig.CONSENT_URL_GRAMMAR.matches(base)) return null
        val uri = runCatching { URI(base) }.getOrNull() ?: return null
        if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) return null
        if (uri.port != -1 && uri.port !in 1..65535) return null
        val segments = uri.rawPath.orEmpty().removePrefix("/").takeIf { it.isNotEmpty() }?.split('/').orEmpty()
        if (segments.any { it.isEmpty() || it == "." || it == ".." }) return null
        if (base.contains(ConsentRun.PATH_PREFIX)) return null
        return base
    }

    private fun baseRefusal(what: String, raw: String): String {
        val shown = ConsentRun.printable(raw)
        return if (raw.contains(ConsentRun.PATH_PREFIX)) {
            "$what '$shown' is a full consent link — pass it as the argument instead (`thoryn access approve $shown`)"
        } else {
            "$what '$shown' is not an https:// base URL (https://<host>[:port][/path], no query, fragment or user-info)"
        }
    }

    /**
     * The `consentUrl` of the nearest `.thoryn/workflow.yaml` from [workingDirectory] up to the repository root (the first
     * directory holding `.git`), or null when there is none, it declares none, or it cannot be read (a note on [err]).
     */
    internal fun workflowConfigBase(err: PrintStream): String? {
        val file = findWorkflowConfig(workingDirectory()) ?: return null
        val config = try {
            WorkflowConfig.load(file.toFile(), file.toString())
        } catch (ex: WorkflowConfigException) {
            err.println("Note: ${ex.message} — its consentUrl is not used.")
            return null
        } catch (ex: Exception) {
            err.println("Note: could not read $file (${ex.message}) — its consentUrl is not used.")
            return null
        }
        val declared = config.consentUrl ?: return null
        return validateBase(declared) ?: run {
            err.println("Note: $file declares consentUrl '${ConsentRun.printable(declared)}', which is not an https:// base URL — not used.")
            null
        }
    }

    /** The nearest `.thoryn/workflow.yaml` at or above [start], stopping at the repository root (a `.git` entry). */
    internal fun findWorkflowConfig(start: Path): Path? {
        var dir: Path? = start.toAbsolutePath().normalize()
        while (dir != null) {
            val candidate = dir.resolve(WorkflowConfig.DEFAULT_PATH)
            if (Files.isRegularFile(candidate)) return candidate
            if (Files.exists(dir.resolve(".git"))) return null
            dir = dir.parent
        }
        return null
    }

    /**
     * `https://starters.<platform domain>` for the signed-in session, or null when it cannot be derived: no session, or a
     * platform issuer that is not an `https://` BASE host (`<label>.<platform domain>`, label `auth` / `hub` or the
     * `THORYN_TENANT_HOST_LABEL` override) — a local hub, an IP literal or a custom domain names no platform domain. The
     * platform issuer is the session's recorded base issuer, else the base of its workspace issuer.
     */
    fun startersBaseFor(tokens: Tokens?): String? {
        tokens ?: return null
        val platform = tokens.platformIssuer?.takeIf { it.isNotBlank() }
            ?: tokens.issuer?.takeIf { it.isNotBlank() }?.let { ThorynConfig.baseHubOf(it) }
            ?: return null
        val uri = runCatching { URI(platform.trim()) }.getOrNull() ?: return null
        if (uri.scheme != "https") return null
        val host = uri.host?.lowercase() ?: return null
        if (ThorynConfig.labelIndex(host) != 0) return null
        val domain = host.substringAfter('.')
        if (!domain.contains('.')) return null
        val port = if (uri.port == -1) "" else ":${uri.port}"
        return validateBase("https://$STARTERS_HOST_LABEL.$domain$port")
    }

    /**
     * Open [target] in the browser unless [noBrowser], and say what happened on [out]: either way the address is printed,
     * so it can be opened on any device. Returns whether a browser was launched.
     */
    fun deliver(target: Target, noBrowser: Boolean, out: PrintStream = System.out): Boolean {
        val opened = !noBrowser && runCatching { opener(target.url) }.getOrDefault(false)
        if (opened) {
            out.println("Opening Thoryn's consent for run ${target.run.ref} in your browser…")
            out.println("If it doesn't open, visit this URL:")
        } else {
            out.println("To approve the rights run ${target.run.ref} asks for, open this URL on any device:")
        }
        out.println()
        out.println("    ${target.url}")
        out.println()
        out.println("A workspace admin of the run's workspace signs in there and approves exactly what the repository asks for, on")
        out.println("Thoryn's own consent screen. This command granted nothing.")
        out.println("(consent address from ${target.source.describe})")
        return opened
    }
}

