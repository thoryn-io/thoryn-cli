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
 * SSO-2820 — RFC 6749 §4.1 Authorization Code redemption for the interactive
 * `thoryn login` loopback flow (RFC 8252 native app + RFC 7636 PKCE).
 *
 * The browser dance itself (open the authorize URL, capture the `?code=` redirect on the
 * [LoopbackRedirectServer]) is orchestrated by `LoginCommand`; this class owns the final leg —
 * exchanging the captured `code` + PKCE `code_verifier` for tokens at `/oauth2/token`.
 *
 * Client authentication mirrors [TokenExchangeFlow]: HTTP Basic when a [clientSecret] is supplied
 * (confidential client), otherwise the public `client_id` in the form body (native/loopback public
 * client — PKCE is the authorize↔token binding). The `redirect_uri` MUST byte-match the one sent on
 * the authorize request (RFC 6749 §4.1.3), so the caller passes the loopback server's `redirectUri`.
 *
 * ## Transport security (mirrors [DeviceCodeFlow], SSO-1993)
 *
 * The token exchange returns access + refresh tokens, so the [init] block re-validates the issuer
 * through [IssuerUrlValidator] before any request is built — a non-loopback `http://` issuer is
 * rejected unless [devMode] is set. The endpoint URI is built from the validated [baseIssuer].
 */
class AuthorizationCodeFlow(
    private val issuer: String,
    private val clientId: String,
    private val clientSecret: String?,
    private val redirectUri: String,
    private val codeVerifier: String,
    private val sender: HttpSender,
    private val devMode: Boolean = false,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    init {
        IssuerUrlValidator.validate(issuer, devMode)
    }

    private val baseIssuer: String = issuer.trimEnd('/')

    /** Redeem [code] for tokens. Returns [Tokens] on success; throws [AuthorizationCodeException] on any non-200. */
    fun exchange(code: String): Tokens {
        val form = buildList {
            add("grant_type" to "authorization_code")
            add("code" to code)
            add("redirect_uri" to redirectUri)
            add("code_verifier" to codeVerifier)
            if (clientSecret == null) add("client_id" to clientId)
        }
        val builder = HttpRequest.newBuilder()
            .uri(URI.create("$baseIssuer/oauth2/token"))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
        if (clientSecret != null) builder.header("Authorization", basicAuth(clientId, clientSecret))

        val response = sender.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            val errorCode = parseErrorCode(response.body()) ?: "unknown"
            throw AuthorizationCodeException(
                "Hub returned ${response.statusCode()}: $errorCode",
                oauthError = errorCode,
            )
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            accessToken = map["access_token"] as String,
            refreshToken = map["refresh_token"] as? String,
            idToken = map["id_token"] as? String,
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
 * Thrown on any authorization-code redemption failure. [oauthError] carries the RFC 6749 §5.2
 * machine error code (`invalid_grant` on a bad/expired code, `invalid_client` on bad client auth,
 * …), or `"unknown"` when the body was not parseable.
 */
class AuthorizationCodeException(
    message: String,
    val oauthError: String,
) : RuntimeException(message)
