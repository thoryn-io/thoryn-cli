package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.io.IOException
import java.net.URI
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-3308 (epic SSO-3304) — the secret-less `thoryn login --workload-identity`: a GitHub Actions job
 * exchanges its own OIDC token for a short-lived workspace token under a **workload identity trust** a
 * workspace admin created (`thoryn workload-identity trusts create`, product-api
 * `/api/v1/workload-identity/trusts`, oathy SSO-3307). No secret exists anywhere.
 *
 * Retargets the SSO-2879 flow, which exchanged the job token by RFC 8693 token-exchange under an
 * operator-registered issuer and authenticated the client with a CI signing key. The customer trust
 * needs neither: the job token IS the client authentication (ADR
 * `2026-09-22-customer-configurable-workload-identity-federation.md`, D1).
 *
 * The wire contract (oathy #3787):
 *  1. **Job token.** `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<the trust's audience>` with
 *     `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN` → `{"value":"<jwt>"}`. GitHub only sets those
 *     variables for a job whose workflow grants `permissions: id-token: write`.
 *  2. **Exchange.** `POST {tokenEndpoint}` (= `{audience}/oauth2/token`) with `grant_type=client_credentials`,
 *     `client_id` (the trust's `wi_…` client), `client_assertion_type=…jwt-bearer`,
 *     `client_assertion=<job token>` and, when asked for, `scope` (a subset of the trust's scopes). A DPoP
 *     proof rides along exactly as on every other token request — [tokenSender] is the CLI's
 *     [Dpop.sender], which attaches one only to a platform that advertises DPoP.
 *  3. **Response.** `{access_token, token_type, expires_in ≤ 900, scope}` — never a refresh token.
 *
 * **A job token works once** (the platform records its `jti`; a replay is `invalid_client`). So every
 * [run] asks the runner for a FRESH job token — including the renewal of an expired session
 * ([com.devnow.thoryn.cli.cmd.CommandSupport.forceRefresh]). Nothing here caches a job token.
 *
 * **SSO-3684 — a token FILE instead of the runner.** A pod under a `kubernetes` trust (oathy SSO-3678) holds
 * its credential as a projected ServiceAccount token on disk (`/var/run/secrets/tokens/thoryn/token`, the
 * path the connection's `auth.tokenSource` names). With [tokenFile] set, step 1 is a read of that file —
 * Kubernetes refreshes it in place, so every [run] re-reads it — and the exchange in step 2 is byte-identical.
 * The file's content is the credential: it is never logged, never persisted, never put on an exception.
 *
 * **Every refusal is `401 invalid_client`**, by design: the platform tells a caller nothing about which
 * check failed (the reason is in the workspace audit log only, `workload_identity.exchange_failed`). A
 * refusal therefore carries the job's own [JobIdentity] — public job metadata read from the token the
 * CLI holds — so [WorkloadIdentityDiagnostics] can print what was sent and who the job is, and name any
 * difference it can see locally. The job token itself is never kept on the exception, never printed.
 */
class WorkloadIdentityFlow(
    /** The trust's workload client (`wi_<24 hex>`), sent as `client_id`. */
    private val clientId: String,
    /** The trust's audience, EXACTLY — requested from GitHub as the job token's `aud`. */
    private val audience: String,
    /** Where the job token is exchanged: `{audience}/oauth2/token` unless the trust says otherwise. */
    private val tokenEndpoint: String,
    /** Sender for the token endpoint — [Dpop.sender] in production (DPoP when the platform wants it). */
    private val tokenSender: HttpSender,
    /** Sender for the GitHub runner's job-token endpoint — a plain sender, never a DPoP proof. */
    private val oidcSender: HttpSender = plainSender(),
    /** Environment lookup; `-D` system properties first, so tests (and `java -D…`) can supply the runner vars. */
    private val env: (String) -> String? = ::runnerEnv,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
    /**
     * SSO-3684 — read the identity token from this file (a projected ServiceAccount token) instead of asking
     * the GitHub Actions runner. Null ⇒ the runner variables are the source.
     */
    private val tokenFile: Path? = null,
) {

    /**
     * Fetch a fresh job token and exchange it. Returns the minted [Tokens] (no refresh token);
     * throws [WorkloadIdentityException] on any failure — with the job's [JobIdentity] attached once a
     * job token was obtained.
     *
     * @param scope space-separated scopes to request (a subset of the trust's), or null/blank to request
     *   none and receive the trust's full set.
     */
    fun run(scope: String? = null): Tokens = run { _ -> scope }

    /**
     * SSO-3702 (SSO-3699 option B) — like [run], with the scope decided AFTER the job's own identity token is in
     * hand: [scopeFor] receives the token's public [JobIdentity] and answers the space-separated scopes to request,
     * or null to request none. This is how `login --connection` picks the trust's PROFILE from the job's
     * `environment` claim ([WorkloadProfile.select]): a job in the trust's apply environment requests the
     * connection's scopes; a job in any other environment omits `scope`, so the hub mints exactly the matched
     * (plan) profile's read-only set — never a write scope from a plan job.
     */
    fun run(scopeFor: (JobIdentity) -> String?): Tokens {
        val jobToken = requestJobToken()
        val identity = JobIdentity.of(jobToken)
        val scope = scopeFor(identity)
        val request = HttpRequest.newBuilder()
            .uri(URI.create(tokenEndpoint))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(buildForm(jobToken, scope)))
            .build()

        val response = try {
            tokenSender.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: IOException) {
            throw WorkloadIdentityException(
                "could not reach the token endpoint $tokenEndpoint (${e.message ?: e.javaClass.simpleName})",
                oauthError = ERROR_TRANSPORT,
                jobIdentity = identity,
            )
        }
        if (response.statusCode() != 200) {
            val (code, description) = parseError(response.body())
            throw WorkloadIdentityException(
                "the platform refused the exchange (HTTP ${response.statusCode()}: ${code ?: "no error code"})",
                oauthError = code ?: "unknown",
                status = response.statusCode(),
                errorDescription = description,
                jobIdentity = identity,
            )
        }
        val map: Map<String, Any?> = try {
            mapper.readValue(response.body())
        } catch (_: Exception) {
            emptyMap()
        }
        val accessToken = (map["access_token"] as? String)?.takeIf { it.isNotBlank() }
            ?: throw WorkloadIdentityException(
                "the token endpoint answered 200 without an access_token",
                oauthError = "invalid_token_response",
                status = 200,
                jobIdentity = identity,
            )
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            accessToken = accessToken,
            // Never a refresh token: a workload session renews by a fresh exchange.
            refreshToken = null,
            idToken = null,
            tokenType = (map["token_type"] as? String) ?: "Bearer",
            expiresAtEpochSecond = expiresIn?.let { System.currentTimeMillis() / 1000 + it },
            scope = (map["scope"] as? String)?.takeIf { it.isNotBlank() } ?: scope?.takeIf { it.isNotBlank() },
        )
    }

    /**
     * A FRESH identity token for [audience] — one request per call, never cached (a job token works
     * once). From [tokenFile] when set (SSO-3684: Kubernetes rewrites the projected token in place, so a
     * re-read is a fresh token), else from the GitHub Actions runner.
     */
    internal fun requestJobToken(): String {
        tokenFile?.let { return readTokenFile(it) }
        val requestUrl = env(REQUEST_URL_ENV)
        val requestToken = env(REQUEST_TOKEN_ENV)
        if (requestUrl == null || requestToken == null) {
            val missing = listOfNotNull(
                REQUEST_URL_ENV.takeIf { requestUrl == null },
                REQUEST_TOKEN_ENV.takeIf { requestToken == null },
            )
            throw WorkloadIdentityException(
                "no GitHub Actions job token available: ${missing.joinToString(" and ")} " +
                    "${if (missing.size == 1) "is" else "are"} not set. Workload identity sign-in runs inside a " +
                    "GitHub Actions job whose workflow (or job) grants `permissions: id-token: write` — without " +
                    "that permission GitHub does not expose these variables. Outside GitHub Actions, sign in with " +
                    "`thoryn login` (a person) or `thoryn login --client-credentials` (an API key) instead.",
                oauthError = ERROR_NOT_ON_GITHUB_ACTIONS,
            )
        }
        val request = buildJobTokenRequest(requestUrl, requestToken, audience)
        val response = try {
            oidcSender.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: IOException) {
            throw WorkloadIdentityException(
                "could not reach the GitHub Actions job-token endpoint (${e.message ?: e.javaClass.simpleName})",
                oauthError = ERROR_JOB_TOKEN_REQUEST_FAILED,
            )
        }
        if (response.statusCode() != 200) {
            throw WorkloadIdentityException(
                "GitHub refused the job-token request for audience '$audience' (HTTP ${response.statusCode()}). " +
                    "Check that the job grants `permissions: id-token: write`.",
                oauthError = ERROR_JOB_TOKEN_REQUEST_FAILED,
                status = response.statusCode(),
            )
        }
        val value = runCatching { mapper.readValue<Map<String, Any?>>(response.body())["value"] as? String }.getOrNull()
        return value?.takeIf { it.isNotBlank() }
            ?: throw WorkloadIdentityException(
                "GitHub's job-token response had no `value` field.",
                oauthError = ERROR_JOB_TOKEN_REQUEST_FAILED,
            )
    }

    /**
     * SSO-3684 — the token at [file], whitespace-trimmed. A missing, unreadable or empty file is
     * [ERROR_TOKEN_FILE_UNREADABLE] naming the PATH (never any content): the usual causes are a projected
     * volume mounted elsewhere than the connection says, or no `serviceAccountToken` source at all.
     */
    internal fun readTokenFile(file: Path): String {
        val raw = try {
            Files.readString(file, Charsets.UTF_8)
        } catch (e: NoSuchFileException) {
            throw WorkloadIdentityException(
                "no identity token at '$file': the file does not exist. Mount the projected ServiceAccount token " +
                    "there (a `projected` volume with a `serviceAccountToken` source whose `audience` is the trust's " +
                    "audience), or point the connection's auth.tokenSource.path at where it is mounted.",
                oauthError = ERROR_TOKEN_FILE_UNREADABLE,
            )
        } catch (e: IOException) {
            throw WorkloadIdentityException(
                "could not read the identity token at '$file' (${e.javaClass.simpleName}${e.message?.let { ": $it" } ?: ""}).",
                oauthError = ERROR_TOKEN_FILE_UNREADABLE,
            )
        }
        return raw.trim().takeIf { it.isNotEmpty() }
            ?: throw WorkloadIdentityException(
                "the identity token file '$file' is empty.",
                oauthError = ERROR_TOKEN_FILE_UNREADABLE,
            )
    }

    /** The exchange form: client_credentials, the workload client, the job token as its assertion. No secret. */
    internal fun buildForm(jobToken: String, scope: String?): String {
        val pairs = buildList {
            add("grant_type" to CLIENT_CREDENTIALS_GRANT)
            add("client_id" to clientId)
            add("client_assertion_type" to CLIENT_ASSERTION_TYPE)
            add("client_assertion" to jobToken)
            scope?.trim()?.takeIf { it.isNotEmpty() }?.let { add("scope" to it) }
        }
        return pairs.joinToString("&") { (k, v) -> "${encode(k)}=${encode(v)}" }
    }

    private fun parseError(body: String?): Pair<String?, String?> {
        if (body.isNullOrBlank()) return null to null
        return try {
            val map: Map<String, Any?> = mapper.readValue(body)
            ((map["error"] as? String) ?: (map["errorCode"] as? String)) to
                ((map["error_description"] as? String) ?: (map["detail"] as? String))
        } catch (_: Exception) {
            null to null
        }
    }

    companion object {
        /** GitHub Actions runner variable: the job-token endpoint (set only with `id-token: write`). */
        const val REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL"

        /** GitHub Actions runner variable: the bearer that authorises the job-token request. */
        const val REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

        const val CLIENT_CREDENTIALS_GRANT = "client_credentials"
        const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        /** The only job-token issuer a trust accepts (operator config on the platform; D4). */
        const val GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"

        /** SSO-3684 — where a pod's projected ServiceAccount token is mounted in the documented manifest. */
        const val DEFAULT_KUBERNETES_TOKEN_FILE = "/var/run/secrets/tokens/thoryn/token"

        /** CLI-side failure codes (never sent by the platform). */
        const val ERROR_NOT_ON_GITHUB_ACTIONS = "not_on_github_actions"
        const val ERROR_JOB_TOKEN_REQUEST_FAILED = "job_token_request_failed"
        const val ERROR_TRANSPORT = "token_endpoint_unreachable"

        /** SSO-3684 — the token file named by `--token-file` / `auth.tokenSource.path` is missing, unreadable or empty. */
        const val ERROR_TOKEN_FILE_UNREADABLE = "token_file_unreadable"

        /** A runner variable: `-D` property first (tests, `java -D…`), then the environment; blank ⇒ null. */
        fun runnerEnv(name: String): String? =
            System.getProperty(name)?.takeIf { it.isNotBlank() } ?: System.getenv(name)?.takeIf { it.isNotBlank() }

        /**
         * The job-token request: `GET <requestUrl>&audience=<aud>` with the runner's request token as a
         * bearer. GitHub answers `{"value":"<jwt>"}`.
         */
        internal fun buildJobTokenRequest(requestUrl: String, requestToken: String, audience: String): HttpRequest {
            val separator = if (requestUrl.contains('?')) "&" else "?"
            return HttpRequest.newBuilder()
                .uri(URI.create("$requestUrl${separator}audience=${encode(audience)}"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer $requestToken")
                .header("Accept", "application/json")
                .GET()
                .build()
        }

        /**
         * The token endpoint for [audience]: `{audience}/oauth2/token`, or [explicit] when given — which must
         * sit on the audience's own origin. A job token minted for the audience is a single-use credential
         * for exactly that platform; posting it anywhere else would hand it to a host that could spend it
         * first, so a token endpoint on another origin is refused rather than trusted.
         */
        fun tokenEndpointFor(audience: String, explicit: String?): String {
            val derived = audience.trim().trimEnd('/') + "/oauth2/token"
            val chosen = explicit?.trim()?.takeIf { it.isNotEmpty() } ?: return derived
            val a = runCatching { URI(audience.trim()) }.getOrNull()
            val e = runCatching { URI(chosen) }.getOrNull()
            require(a?.scheme != null && a.host != null && e?.scheme != null && e.host != null) {
                "token endpoint '$chosen' is not an absolute URL"
            }
            require(origin(a!!) == origin(e!!)) {
                "token endpoint '$chosen' is not on the audience's origin (${origin(a)}); a job token is only ever " +
                    "sent to the platform it was minted for"
            }
            return chosen
        }

        /** `scheme://host[:port]` of [u], lower-cased — the unit [tokenEndpointFor] compares. */
        fun origin(u: URI): String {
            val port = if (u.port == -1) "" else ":${u.port}"
            return "${u.scheme.lowercase()}://${u.host?.lowercase()}$port"
        }

        private fun encode(s: String): String = URLEncoder.encode(s, Charsets.UTF_8)

        private fun plainSender(): HttpSender {
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build()
            return HttpSender { request, handler -> client.send(request, handler) }
        }
    }
}

/**
 * SSO-3308 — the public identity of a GitHub Actions job, read (UNVERIFIED, display and local
 * comparison only — see [JwtClaims]) from the job token the CLI holds. These are job metadata GitHub
 * documents as claims, not secrets; the token itself is never retained here.
 */
data class JobIdentity(
    val issuer: String?,
    val audience: List<String>,
    val subject: String?,
    val repository: String?,
    val repositoryId: String?,
    val repositoryOwner: String?,
    val repositoryOwnerId: String?,
    val ref: String?,
    val environment: String?,
    val eventName: String?,
    val runnerEnvironment: String?,
    /** SSO-3684 — a projected ServiceAccount token's `kubernetes.io.namespace`; null for a CI job token. */
    val kubernetesNamespace: String? = null,
    /** SSO-3684 — a projected ServiceAccount token's `kubernetes.io.serviceaccount.name`. */
    val kubernetesServiceAccount: String? = null,
    /** SSO-3710 — the GitHub Actions `run_id` claim (the workflow run the job belongs to), for a fix request's `run.id`. */
    val runId: String? = null,
    /** SSO-3710 — the GitHub Actions `sha` claim (the commit the run is for), for a fix request's `run.headSha`. */
    val sha: String? = null,
) {
    /** SSO-3684 — true when the token is a Kubernetes ServiceAccount token (`sub` = `system:serviceaccount:…`). */
    val isKubernetes: Boolean get() = subject?.startsWith(KUBERNETES_SUBJECT_PREFIX) == true || kubernetesNamespace != null

    companion object {
        const val KUBERNETES_SUBJECT_PREFIX: String = "system:serviceaccount:"

        fun of(jobToken: String): JobIdentity {
            val c = JwtClaims.of(jobToken)
            fun text(name: String): String? = c[name]?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            val audNode = c["aud"]
            val aud = when {
                audNode == null || audNode.isNull -> emptyList()
                audNode.isArray -> audNode.toList().mapNotNull { it.asString() }
                else -> listOfNotNull(audNode.asString())
            }
            return JobIdentity(
                issuer = text("iss"),
                audience = aud,
                subject = text("sub"),
                repository = text("repository"),
                repositoryId = text("repository_id"),
                repositoryOwner = text("repository_owner"),
                repositoryOwnerId = text("repository_owner_id"),
                ref = text("ref"),
                environment = text("environment"),
                eventName = text("event_name"),
                runnerEnvironment = text("runner_environment"),
                kubernetesNamespace = c["kubernetes.io"]?.get("namespace")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() },
                kubernetesServiceAccount = c["kubernetes.io"]?.get("serviceaccount")?.get("name")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() },
                runId = text("run_id"),
                sha = text("sha"),
            )
        }
    }
}

/**
 * SSO-3702 (SSO-3699 option B; oauthy ADR `2026-10-14-plan-identity-and-resource-ownership`) — the two scope
 * PROFILES of ONE `github_actions` trust, selected by the hub from the job token's `environment` claim: the
 * **apply** profile (the trust's GitHub environment — the reviewed one — and its full scope set) and the
 * optional **plan** profile (another GitHub environment, a read-only subset). One trust, one `wi_` client,
 * one `connection.json`; the environment is the only thing that separates "may read" from "may write".
 */
enum class WorkloadProfile(val wire: String) {
    APPLY(Tokens.PROFILE_APPLY),
    PLAN(Tokens.PROFILE_PLAN);

    companion object {
        /**
         * Which profile the hub will match for [identity], as far as the CLI can tell from the connection's
         * `auth.github.environment` ([applyEnvironment]): the job's `environment` claim equal to it ⇒ [APPLY];
         * any OTHER declared environment ⇒ [PLAN]; null when the CLI cannot tell — no apply environment known
         * (no pin in the connection, or a sandbox trust that pins none), a job declaring no environment at all
         * (a production trust refuses it anyway, `environment_mismatch`), or a Kubernetes token (no profiles).
         * The hub decides; this only chooses whether to send `scope`. A `null` answer keeps today's behaviour.
         */
        fun select(identity: JobIdentity, applyEnvironment: String?): WorkloadProfile? {
            val apply = applyEnvironment?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            if (identity.isKubernetes) return null
            val claimed = identity.environment ?: return null
            return if (claimed == apply) APPLY else PLAN
        }

        fun of(wire: String?): WorkloadProfile? = entries.firstOrNull { it.wire == wire }

        /**
         * SSO-3722 — whether a `--connection` sign-in leaves the profile to the HUB: the connection names NO apply
         * environment (no `auth.github` block, or one without `environment`) yet the job token carries an `environment`
         * claim. The CLI then requests NO scope and the hub mints the profile the claim matches (SSO-3700's empty-request
         * rule) — never the connection's scopes blindly, which is how the forge-plan job of thoryn-cicd run 38751382032
         * asked for write scopes from a plan environment and was refused (`invalid_scope`, `scope_outside_plan_profile`).
         * False for a Kubernetes token (no profiles), outside GitHub (no claim), or with the apply environment known
         * ([select] decides locally then).
         */
        fun hubDecides(identity: JobIdentity, applyEnvironment: String?): Boolean =
            applyEnvironment?.trim().isNullOrEmpty() && !identity.isKubernetes && identity.environment != null
    }
}

/**
 * Thrown on any workload-identity sign-in failure. [oauthError] carries the platform's RFC 6749 §5.2
 * code (`invalid_client`, `invalid_scope`, …) or a CLI-side one ([WorkloadIdentityFlow.ERROR_NOT_ON_GITHUB_ACTIONS],
 * [WorkloadIdentityFlow.ERROR_JOB_TOKEN_REQUEST_FAILED], [WorkloadIdentityFlow.ERROR_TRANSPORT]).
 * [jobIdentity] is set once a job token was obtained — the job's public claims, never the token.
 */
class WorkloadIdentityException(
    message: String,
    val oauthError: String,
    val status: Int? = null,
    val errorDescription: String? = null,
    val jobIdentity: JobIdentity? = null,
) : RuntimeException(message)
