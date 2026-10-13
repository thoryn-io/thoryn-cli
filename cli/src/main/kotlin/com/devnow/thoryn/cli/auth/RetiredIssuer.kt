package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.config.ThorynConfig
import tools.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-3377 — **is the issuer this command is about to use still served?**
 *
 * The SSO-3297 auth-host cutover moved the public sign-in host from `{slug}.hub.<env>` to
 * `{slug}.auth.<env>`. The retired hosts answer every request — discovery, `/oauth2/authorize`,
 * `/oauth2/token` — with an RFC 9457 problem-details `410`:
 *
 * ```
 * {"type":"https://thoryn.io/problems/issuer_retired","title":"Gone","status":410,
 *  "detail":"This host has been retired. Use the issuer advertised in the current discovery document.",
 *  "errorCode":"issuer_retired", ...}
 * ```
 *
 * A CLI that signed in before the cutover remembers the retired base issuer and, on the next
 * `thoryn login`, opened a browser at a host that can only ever answer `410` — a sign-in that could
 * never succeed, with nothing on the terminal saying why.
 *
 * Every login mode now asks the issuer's discovery document first ([check]); a `410` stops the
 * sign-in before anything is opened or posted, with guidance ([loginGuidance]) naming the retired
 * issuer and — where the platform can be inferred ([suggestionFor]) — the successor issuer.
 *
 * **A saved issuer is never rewritten.** The CLI does not silently swap `hub.` for `auth.`: a
 * guessed issuer is a guessed trust decision (which platform receives the user's credentials), so it
 * is printed as a suggestion and the user makes the choice explicitly with `--issuer`.
 *
 * Commands that run on a remembered session learn about retirement from the hub's own answer to a
 * refresh / re-mint / workspace exchange (the token flows all surface the problem-details
 * `errorCode`, see [isRetiredError]) and print [sessionGuidance] instead of a raw error.
 *
 * Any probe failure other than a `410` — unreachable, `404`, unparseable — answers [Status.Live]:
 * the probe exists only to recognise retirement, and every other failure is reported by the flow
 * that follows exactly as it was before.
 *
 * ## SSO-3415 — a workspace that moved to its custom domain names its successor
 *
 * Once a workspace's custom domain is ACTIVE, its platform host `{slug}.auth.<env>` answers the same
 * `410`, and (oathy ADR `2026-09-25-custom-domains.md`, amendment 2026-09-28) the body NAMES the
 * workspace's current issuer as the problem-details member `issuer` — `https://auth.acme.com`, or
 * `https://auth.acme.com/{env}` on a sandbox path. [classify] reads it into [Status.Retired.successor]
 * after [successorOf] has checked it. [resolve] follows it **once** for an issuer the CLI DERIVED from a
 * workspace slug (the connection contract, `--workspace`): the platform host the CLI was already going to
 * trust names where the workspace went, so no application repository has to change when a domain goes
 * live. A successor that is itself retired is a chain and is refused, never followed further.
 *
 * The SSO-3377 fleet-wide retirement (`hub.` → `auth.`) names no successor and keeps its guidance.
 */
object RetiredIssuer {

    /** The RFC 9457 `errorCode` a retired host answers with. */
    const val ERROR_CODE: String = "issuer_retired"

    /** The problem `type` URI a retired host answers with (recognised when `errorCode` is absent). */
    const val PROBLEM_TYPE: String = "https://thoryn.io/problems/issuer_retired"

    /** HTTP 410 Gone. */
    const val HTTP_GONE: Int = 410

    /**
     * The host label that replaced the retired `hub` label at the SSO-3297 cutover (ADR
     * `2026-09-22-public-issuer-host-auth-subdomain.md`). Used only to SUGGEST an issuer.
     */
    const val SUCCESSOR_LABEL: String = "auth"

    /** The outcome of a discovery probe. */
    sealed interface Status {
        /** Not retired as far as the probe can tell (includes every non-410 answer and no answer). */
        data object Live : Status

        /**
         * `410` with `errorCode: issuer_retired` — the platform retired this host. [successor] is the
         * issuer the platform named in its `issuer` member (SSO-3415), when it passed [successorOf].
         */
        data class Retired(val issuer: String, val detail: String?, val successor: String? = null) : Status

        /** A `410` that does not say `issuer_retired` — gone, for a reason the CLI does not recognise. */
        data class Gone(val issuer: String, val detail: String?) : Status
    }

    /** A discovery-document answer: status + body. */
    internal data class Answer(val status: Int, val body: String?)

    /**
     * Test seam — fetches a discovery document URL. Null means "no answer" (unreachable, timed out),
     * which [check] treats as [Status.Live].
     */
    internal var fetcher: (String) -> Answer? = { fetch(it) }

    /** Test seam — restore the real network fetch. */
    internal fun resetForTest() {
        fetcher = { fetch(it) }
    }

    /**
     * Probe `{issuer}/.well-known/openid-configuration` and classify the answer. One small anonymous
     * `GET`, no credentials.
     */
    fun check(issuer: String): Status {
        val base = issuer.trim().trimEnd('/')
        if (base.isEmpty()) return Status.Live
        val answer = runCatching { fetcher("$base$DISCOVERY_PATH") }.getOrNull() ?: return Status.Live
        return classify(base, answer.status, answer.body)
    }

    /** Pure classification of a discovery answer. */
    internal fun classify(issuer: String, status: Int, body: String?): Status {
        if (status != HTTP_GONE) return Status.Live
        val problem = runCatching { body?.takeIf { it.isNotBlank() }?.let { MAPPER.readTree(it) } }.getOrNull()
        val errorCode = problem?.get("errorCode")?.asString() ?: problem?.get("error")?.asString()
        val type = problem?.get("type")?.asString()
        val detail = problem?.get("detail")?.asString()?.takeIf { it.isNotBlank() }
            ?: problem?.get("error_description")?.asString()?.takeIf { it.isNotBlank() }
        return if (isRetiredError(errorCode) || type == PROBLEM_TYPE) {
            Status.Retired(issuer, detail, successorOf(issuer, problem?.get(SUCCESSOR_MEMBER)?.asString()))
        } else {
            Status.Gone(issuer, detail)
        }
    }

    /** SSO-3415 — the problem-details member a workspace's retired platform host names its current issuer in. */
    const val SUCCESSOR_MEMBER: String = "issuer"

    /**
     * SSO-3415 — [raw] as a successor of [retiredIssuer], or null when it is not one the CLI will follow:
     *
     *  - `https` on a plain DNS name (at least two labels, an alphabetic top label — no IP literal, no
     *    `localhost`), default port, no user-info / query / fragment; `http` only on a loopback host and
     *    only when [retiredIssuer] is itself a loopback `http` issuer (a local stack — the same exception
     *    [IssuerUrlValidator] makes). A remote platform can never send the CLI to plain HTTP.
     *  - the same path as [retiredIssuer] — none for a workspace issuer, the same `/{env}` for a sandbox —
     *    so a successor can move the HOST, never change which environment the caller asked about;
     *  - not the retired issuer itself.
     *
     * The value is normalised (lower-case host, no trailing slash).
     */
    fun successorOf(retiredIssuer: String, raw: String?): String? {
        val candidate = raw?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() } ?: return null
        return try {
            val from = URI(retiredIssuer.trim().trimEnd('/'))
            val to = URI(candidate)
            if (to.rawUserInfo != null || to.rawQuery != null || to.rawFragment != null) return null
            val host = to.host?.lowercase() ?: return null
            val scheme = to.scheme?.lowercase() ?: return null
            val acceptable = when (scheme) {
                "https" -> isPublicDnsName(host) && (to.port == -1 || to.port == 443)
                "http" -> isLoopback(host) && from.scheme?.lowercase() == "http" && isLoopback(from.host?.lowercase())
                else -> false
            }
            if (!acceptable) return null
            val path = to.rawPath.orEmpty().trimEnd('/')
            if (path != from.rawPath.orEmpty().trimEnd('/')) return null
            if (path.isNotEmpty() && !ENV_PATH.matches(path)) return null
            normalize(to).takeIf { it != normalize(from) }
        } catch (_: Exception) {
            null
        }
    }

    /** SSO-3415 — how a DERIVED issuer resolved: still served, moved (once), or refused. */
    sealed interface Resolution {
        /** Not retired — use it as it is. */
        data class Current(val issuer: String) : Resolution

        /** Retired, and the platform named a live successor: use [to]. */
        data class Moved(val from: String, val to: String) : Resolution

        /** Retired with no usable successor, or gone: the SSO-3377 refusal applies. */
        data class Stop(val status: Status) : Resolution

        /** The named successor is itself retired or gone — a chain, which is never followed. */
        data class ChainRefused(val from: String, val to: String, val next: Status) : Resolution
    }

    /**
     * SSO-3415 — probe [issuer]; when it is retired and names a successor, probe the successor ONCE and
     * use it if it is served. Never more than two discovery GETs, never a second hop.
     */
    fun resolve(issuer: String): Resolution {
        val base = issuer.trim().trimEnd('/')
        return when (val first = check(base)) {
            Status.Live -> Resolution.Current(base)
            is Status.Gone -> Resolution.Stop(first)
            is Status.Retired -> {
                val next = first.successor ?: return Resolution.Stop(first)
                when (val second = check(next)) {
                    Status.Live -> Resolution.Moved(base, next)
                    else -> Resolution.ChainRefused(base, next, second)
                }
            }
        }
    }

    /** SSO-3415 — the one line a sign-in prints when it followed a workspace to its new issuer. */
    fun movedNotice(moved: Resolution.Moved, workspace: String?): String =
        (workspace?.let { "Workspace '$it'" } ?: "This workspace") +
            " now signs in at ${moved.to} (${moved.from} answered HTTP 410 $ERROR_CODE naming it); using ${moved.to}."

    /** SSO-3415 — the guidance when the named successor is retired too: the CLI follows one hop only. */
    fun chainGuidance(refused: Resolution.ChainRefused): String = buildString {
        appendLine(
            "Error: the issuer ${refused.from} has been retired (HTTP 410 $ERROR_CODE) and names ${refused.to}, " +
                "which is not served either (HTTP 410). The CLI follows one move only.",
        )
        append("Check the workspace's current issuer (`thoryn domain status --json` prints it as `.issuer`) and sign in with it.")
    }

    /** `scheme://host[:port][/path]` — lower-case scheme and host, default https port dropped, no trailing slash. */
    private fun normalize(uri: URI): String {
        val scheme = uri.scheme?.lowercase()
        val port = if (scheme == "https" && uri.port == 443) -1 else uri.port
        val path = uri.rawPath.orEmpty().trimEnd('/').ifEmpty { null }
        return URI(scheme, null, uri.host?.lowercase(), port, path, null, null).toString().trimEnd('/')
    }

    private fun isLoopback(host: String?): Boolean =
        host != null && host.trim('[', ']') in setOf("127.0.0.1", "localhost", "::1")

    private fun isPublicDnsName(host: String): Boolean =
        DNS_NAME.matches(host) && host.substringAfterLast('.').any { it.isLetter() }

    private val DNS_NAME = Regex("^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
    private val ENV_PATH = Regex("^/[a-z0-9][a-z0-9-]{0,62}$")

    /** True when a token-endpoint / API error code is the retired-issuer one. */
    fun isRetiredError(errorCode: String?): Boolean = errorCode == ERROR_CODE

    /** The issuer (and workspace) to suggest in place of a retired one. */
    data class Suggestion(val issuer: String, val workspace: String?) {
        /** The [command] line that signs in with it (`--workspace` only when [includeWorkspace]). */
        fun loginCommand(command: String = "thoryn login", includeWorkspace: Boolean = true): String =
            "$command --issuer $issuer" + (workspace?.takeIf { includeWorkspace }?.let { " --workspace $it" } ?: "")
    }

    /**
     * The successor of a retired Thoryn issuer, when the platform can be inferred: the retired
     * `hub` label becomes [SUCCESSOR_LABEL] on the same apex, keeping scheme and port.
     *
     *  - base host `https://hub.<env>`            → `https://auth.<env>` (with [workspace] when known)
     *  - workspace host `https://<slug>.hub.<env>` → `https://auth.<env>` and `--workspace <slug>`
     *
     * Null for any other host (a custom domain, `localhost`, an `auth.` host that is itself retired):
     * there is nothing to infer, and guessing a host would be guessing where credentials go.
     */
    fun suggestionFor(issuer: String?, workspace: String? = null): Suggestion? {
        if (issuer.isNullOrBlank()) return null
        return try {
            val uri = URI(issuer.trim().trimEnd('/'))
            val host = uri.host ?: return null
            val parts = host.lowercase().split('.')
            val idx = ThorynConfig.labelIndex(host)
            if (idx < 0 || parts[idx] != ThorynConfig.LEGACY_TENANT_HOST_LABEL) return null
            val apex = parts.drop(idx + 1).joinToString(".").takeIf { it.isNotEmpty() } ?: return null
            val slug = workspace?.trim()?.takeIf { it.isNotEmpty() } ?: parts[0].takeIf { idx == 1 }
            val successor = URI(uri.scheme, null, "$SUCCESSOR_LABEL.$apex", uri.port, null, null, null)
                .toString().trimEnd('/')
            Suggestion(successor, slug)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * The guidance a login prints when the issuer it was about to use is retired.
     *
     * @param retired  the issuer whose host answered `410` (a workspace host after `--workspace`).
     * @param base     the platform base issuer the user named / the CLI remembered.
     * @param workspace the workspace the sign-in was for, if any.
     * @param remembered true when [base] came from the previous sign-in rather than the user.
     * @param fix      how to name a different issuer in this mode; defaults to the `thoryn login` line.
     */
    fun loginGuidance(
        retired: Status.Retired,
        base: String,
        workspace: String?,
        remembered: Boolean,
        fix: (Suggestion?) -> String = { defaultFix(it) },
    ): String = buildString {
        append("Error: the issuer ${retired.issuer} has been retired (HTTP 410 $ERROR_CODE)")
        retired.detail?.let { append(" — $it") }
        appendLine()
        // SSO-3415 — an issuer the user NAMED is never swapped for them; say where the platform points.
        retired.successor?.let { appendLine("The platform names this workspace's current issuer: $it") }
        if (remembered) {
            appendLine(
                "$base was remembered from your previous sign-in on this machine; " +
                    "the CLI does not change a saved issuer for you.",
            )
        }
        append(fix(suggestionFor(base, workspace) ?: suggestionFor(retired.issuer, workspace)))
    }

    /** The guidance a login prints when the issuer answers a `410` that does NOT say `issuer_retired`. */
    fun goneGuidance(gone: Status.Gone): String = buildString {
        append("Error: the issuer ${gone.issuer} answered HTTP 410 Gone to its discovery document")
        gone.detail?.let { append(" — $it") }
        appendLine(".")
        append("Check the issuer, and pass the platform's current one with --issuer <issuer>.")
    }

    /**
     * The guidance a command prints when the hub refused to renew a REMEMBERED session because the
     * session's issuer is retired. Signing in again is the only way forward, and it has to name the
     * new issuer: a plain `thoryn login` would reuse the retired one.
     */
    fun sessionGuidance(
        sessionIssuer: String?,
        platformIssuer: String?,
        workspace: String?,
        command: String = "thoryn login",
        includeWorkspace: Boolean = true,
    ): String = buildString {
        val named = sessionIssuer?.takeIf { it.isNotBlank() } ?: platformIssuer ?: "this session's issuer"
        appendLine(
            "Your sign-in session belongs to $named, which has been retired (HTTP 410 $ERROR_CODE); " +
                "it cannot be renewed there.",
        )
        append(
            defaultFix(
                suggestionFor(platformIssuer, workspace) ?: suggestionFor(sessionIssuer, workspace),
                command,
                includeWorkspace,
            ),
        )
    }

    /**
     * "Sign in with …" — the suggested [command] line, or the generic `--issuer` instruction when no
     * successor can be inferred.
     */
    fun defaultFix(suggestion: Suggestion?, command: String = "thoryn login", includeWorkspace: Boolean = true): String =
        if (suggestion != null) {
            "Sign in with the platform's current issuer:\n    ${suggestion.loginCommand(command, includeWorkspace)}"
        } else {
            "Sign in with the platform's current issuer: $command --issuer <issuer> " +
                "(the issuer named in the platform's current discovery document)."
        }

    private const val DISCOVERY_PATH = "/.well-known/openid-configuration"

    private fun fetch(url: String): Answer? = try {
        val client = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build()
        val request = HttpRequest.newBuilder(URI.create(url))
            .timeout(READ_TIMEOUT)
            .header("Accept", "application/json")
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        Answer(response.statusCode(), response.body())
    } catch (_: Exception) {
        null
    }

    private val MAPPER = ObjectMapper()
    private val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(3)
    private val READ_TIMEOUT: Duration = Duration.ofSeconds(5)
}
