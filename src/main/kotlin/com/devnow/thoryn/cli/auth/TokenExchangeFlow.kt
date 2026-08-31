package com.devnow.thoryn.cli.auth

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Base64

/**
 * SSO-2818 — RFC 8693 token exchange for the silent `thoryn workspace switch`.
 *
 * Exchanges the user's CURRENT hub access token (the `subject_token`) for a token in a DIFFERENT
 * tenant they belong to (named by `resource` = the target tenant's hub issuer), with NO browser.
 * The hub grants it only when the caller is an active member of the target tenant (ADR
 * 2026-08-31-same-user-cross-tenant-token-exchange) — otherwise it returns `invalid_grant`.
 *
 * Client authentication: HTTP Basic when a [clientSecret] is supplied (confidential client);
 * otherwise the public `client_id` is sent in the form body (native/loopback CLI client). The
 * requesting client must have `allow_token_exchange` enabled on the hub.
 */
class TokenExchangeFlow(
    private val issuer: String,
    private val clientId: String,
    private val clientSecret: String?,
    private val subjectToken: String,
    private val targetResource: String,
    private val sender: HttpSender,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    /** Run the exchange. Returns [Tokens] on success; throws [TokenExchangeException] on any non-200. */
    fun run(scope: String? = null): Tokens {
        val form = buildList {
            add("grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange")
            add("subject_token" to subjectToken)
            add("subject_token_type" to "urn:ietf:params:oauth:token-type:access_token")
            add("resource" to targetResource)
            if (clientSecret == null) add("client_id" to clientId)
            if (!scope.isNullOrBlank()) add("scope" to scope)
        }
        val builder = HttpRequest.newBuilder()
            .uri(URI.create("${issuer.trimEnd('/')}/oauth2/token"))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
        if (clientSecret != null) builder.header("Authorization", basicAuth(clientId, clientSecret))

        val response = sender.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            val errorCode = parseErrorCode(response.body()) ?: "unknown"
            throw TokenExchangeException("Hub returned ${response.statusCode()}: $errorCode", oauthError = errorCode)
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            accessToken = map["access_token"] as String,
            refreshToken = map["refresh_token"] as? String,
            idToken = null,
            tokenType = (map["token_type"] as? String) ?: "Bearer",
            expiresAtEpochSecond = expiresIn?.let { System.currentTimeMillis() / 1000 + it },
            scope = map["scope"] as? String,
        )
    }

    private fun parseErrorCode(body: String): String? = try {
        val map: Map<String, Any?> = mapper.readValue(body)
        (map["error"] as? String) ?: (map["errorCode"] as? String)
    } catch (_: Exception) {
        null
    }

    private fun formEncode(pairs: List<Pair<String, String>>): String =
        pairs.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}"
        }

    private fun basicAuth(id: String, secret: String): String =
        "Basic ${Base64.getEncoder().encodeToString("$id:$secret".toByteArray(Charsets.UTF_8))}"
}

/**
 * Thrown on any token-exchange failure. [oauthError] carries the RFC 6749 §5.2 machine error code
 * (`invalid_grant` when the caller is not a member of the target tenant, `unauthorized_client` when
 * the client lacks `allow_token_exchange`, …), or `"unknown"` when the body was not parseable.
 */
class TokenExchangeException(
    message: String,
    val oauthError: String,
) : RuntimeException(message)
