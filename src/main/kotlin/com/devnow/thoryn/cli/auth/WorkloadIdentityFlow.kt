package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-2879 (epic SSO-2871) — secret-less `thoryn login --workload-identity` for the thoryn-examples
 * conformance CI, replacing the static shared `THORYN_CI_CLIENT_SECRET`.
 *
 * Two secret-less credentials combine (RFC 8693 token-exchange, the shipped V59 WIF pattern):
 *  1. **subject_token** — the GitHub Actions OIDC token for the running job, fetched from the
 *     runner's `$ACTIONS_ID_TOKEN_REQUEST_URL` (with `audience=<hub issuer>`) authenticated by the
 *     ephemeral `$ACTIONS_ID_TOKEN_REQUEST_TOKEN`. It attests the workflow origin (repo + ref).
 *  2. **client_assertion** — an ES256 `private_key_jwt` (RFC 7523) the CLI signs with the CI signing
 *     key, so the hub authenticates the exchange CLIENT against its INLINE public JWKS (hub V143).
 *
 * The hub validates the subject_token as an external WIF issuer (GitHub Actions, seeded in
 * `trusted_external_issuer`), pins the audience, matches `sub` against the repo-scoped
 * subject_patterns, and mints `sub=workload:github-actions-conformance:<gh-sub>` with the client's
 * registered `tenant:*` scopes.
 *
 * **Two distinct hub URLs** (proven by `WorkloadIdentityFederationPrivateKeyJwtE2ETest`):
 *  - [tokenEndpoint] — the request is POSTed to the TENANT-SUBDOMAIN token endpoint so the hub's
 *    TenantResolutionFilter resolves the `ci-conformance` tenant (external issuers are keyed by the
 *    UUID tenant id; the apex/`default` tenant is rejected by design).
 *  - [assertionAudience] — the client-assertion `aud` must be the DEFAULT-issuer token endpoint
 *    (the hub does NOT override Spring AS's AuthorizationServerContext issuer per tenant), so a
 *    tenant-subdomain `aud` fails the decoder's RFC 7523 audience validator with `invalid_client`.
 */
class WorkloadIdentityFlow(
    /** Tenant-subdomain token endpoint the request is POSTed to (resolves the tenant). */
    private val tokenEndpoint: String,
    /** Client-assertion `aud` — the DEFAULT-issuer token endpoint. */
    private val assertionAudience: String,
    private val clientId: String,
    private val signer: EcPrivateKeyJwtSigner,
    /** The `audience` value requested from GitHub for the OIDC token (== the hub's allowed_audience). */
    private val oidcAudience: String,
    private val sender: HttpSender,
    /** Explicit subject token (testing / `--subject-token` override). When set, GitHub is not called. */
    private val explicitSubjectToken: String? = null,
    private val env: (String) -> String? = { System.getenv(it) },
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    /** Run the exchange. Returns [Tokens] on success; throws [WorkloadIdentityException] on any failure. */
    fun run(scope: String? = null): Tokens {
        val subjectToken = resolveSubjectToken()
        val assertion = signer.sign(clientId = clientId, audience = assertionAudience)
        val form = buildForm(subjectToken, assertion, scope)

        val request = HttpRequest.newBuilder()
            .uri(URI.create(tokenEndpoint))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build()

        val response = sender.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            val errorCode = parseErrorCode(response.body()) ?: "unknown"
            val detail = response.body().take(300).replace(Regex("\\s+"), " ").trim().ifBlank { "(empty body)" }
            throw WorkloadIdentityException(
                "Hub returned ${response.statusCode()}: $errorCode",
                oauthError = errorCode,
                status = response.statusCode(),
                bodySnippet = detail,
            )
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            accessToken = map["access_token"] as String,
            // A WIF token-exchange never returns a refresh token — CI re-authenticates each run.
            refreshToken = null,
            idToken = null,
            tokenType = (map["token_type"] as? String) ?: "Bearer",
            expiresAtEpochSecond = expiresIn?.let { System.currentTimeMillis() / 1000 + it },
            scope = map["scope"] as? String,
        )
    }

    /** The GitHub Actions OIDC token, or the explicit override when supplied. */
    internal fun resolveSubjectToken(): String {
        explicitSubjectToken?.takeIf { it.isNotBlank() }?.let { return it }

        val requestUrl = env("ACTIONS_ID_TOKEN_REQUEST_URL")?.takeIf { it.isNotBlank() }
            ?: throw WorkloadIdentityException(
                "No subject token. Set ACTIONS_ID_TOKEN_REQUEST_URL (GitHub Actions with `permissions: id-token: write`) " +
                    "or pass --subject-token for local testing.",
                oauthError = "missing_subject_token",
            )
        val requestToken = env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?.takeIf { it.isNotBlank() }
            ?: throw WorkloadIdentityException(
                "ACTIONS_ID_TOKEN_REQUEST_URL is set but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing.",
                oauthError = "missing_subject_token",
            )

        val request = buildOidcTokenRequest(requestUrl, requestToken, oidcAudience)
        val response = sender.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            throw WorkloadIdentityException(
                "GitHub OIDC token request returned ${response.statusCode()}.",
                oauthError = "subject_token_request_failed",
                status = response.statusCode(),
            )
        }
        val value = try {
            (mapper.readValue<Map<String, Any?>>(response.body())["value"] as? String)
        } catch (_: Exception) {
            null
        }
        return value?.takeIf { it.isNotBlank() }
            ?: throw WorkloadIdentityException(
                "GitHub OIDC token response had no `value` field.",
                oauthError = "subject_token_request_failed",
            )
    }

    companion object {
        /** GitHub OIDC token type — RFC 8693 subject_token_type for an OIDC id_token. */
        const val SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
        const val TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
        const val CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        /**
         * Build the GitHub OIDC token request: `GET <requestUrl>&audience=<aud>` with the ephemeral
         * request token as a Bearer header. GitHub returns `{"value":"<jwt>"}`.
         */
        internal fun buildOidcTokenRequest(requestUrl: String, requestToken: String, audience: String): HttpRequest {
            val separator = if (requestUrl.contains('?')) "&" else "?"
            val url = "$requestUrl${separator}audience=${URLEncoder.encode(audience, Charsets.UTF_8)}"
            return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer $requestToken")
                .header("Accept", "application/json")
                .GET()
                .build()
        }
    }

    /**
     * Assemble the RFC 8693 + RFC 7523 token-exchange form body. `client_id` is REQUIRED alongside
     * the assertion (Spring AS short-circuits `invalid_request` without it — SSO-1608); [includeClientId]
     * `false` reproduces that bug for the regression test.
     */
    internal fun buildForm(subjectToken: String, clientAssertion: String, scope: String?, includeClientId: Boolean = true): String {
        val pairs = buildList {
            add("grant_type" to TOKEN_EXCHANGE_GRANT)
            add("subject_token" to subjectToken)
            add("subject_token_type" to SUBJECT_TOKEN_TYPE)
            if (includeClientId) add("client_id" to clientId)
            add("client_assertion_type" to CLIENT_ASSERTION_TYPE)
            add("client_assertion" to clientAssertion)
            if (!scope.isNullOrBlank()) add("scope" to scope)
        }
        return pairs.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}"
        }
    }

    private fun parseErrorCode(body: String): String? = try {
        val map: Map<String, Any?> = mapper.readValue(body)
        (map["error"] as? String) ?: (map["errorCode"] as? String)
    } catch (_: Exception) {
        null
    }
}

/**
 * Thrown on any workload-identity sign-in failure. [oauthError] carries the RFC 6749 §5.2 machine
 * error code the hub returned (`invalid_client`, `invalid_grant`, `unauthorized_client`, …) or one
 * of the CLI-side codes (`missing_subject_token`, `subject_token_request_failed`).
 */
class WorkloadIdentityException(
    message: String,
    val oauthError: String,
    val status: Int? = null,
    val bodySnippet: String? = null,
) : RuntimeException(message)
