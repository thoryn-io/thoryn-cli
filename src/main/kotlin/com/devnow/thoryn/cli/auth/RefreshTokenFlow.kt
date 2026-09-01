package com.devnow.thoryn.cli.auth

import com.devnow.thoryn.cli.config.ThorynConfig
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-2834 — RFC 6749 §6 Refresh Token grant for the `thoryn` CLI.
 *
 * The CLI has always persisted a `refresh_token` (login requests `offline_access`) but never used
 * it: once the ~15-minute access token expired, every hub/gateway call returned `401` until the user
 * re-ran `thoryn login`. This flow redeems the stored refresh token at `/oauth2/token` for a fresh
 * access token so [com.devnow.thoryn.cli.cmd.CommandSupport.ensureFresh] can refresh transparently
 * before a call.
 *
 * Client authentication mirrors [AuthorizationCodeFlow] / [DeviceCodeFlow]: the default `thoryn-cli`
 * is a PUBLIC client (RFC 8252) so the `client_id` rides in the form body with no secret. The issuer
 * is re-validated through [IssuerUrlValidator] before any request (a non-loopback `http://` issuer is
 * rejected unless [devMode]) — the same transport-security contract the other token flows enforce.
 *
 * The refresh response may or may not rotate the refresh token; when the response omits one the
 * previous refresh token is retained. The issuer/gateway session fields ([Tokens.issuer],
 * [Tokens.gateway]) are CLI-local and are NOT part of the token response — the caller preserves them.
 */
class RefreshTokenFlow(
    private val issuer: String,
    private val sender: HttpSender,
    private val clientId: String = ThorynConfig.DEFAULT_CLIENT_ID,
    private val clientSecret: String? = null,
    private val devMode: Boolean = false,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    init {
        IssuerUrlValidator.validate(issuer, devMode)
    }

    private val baseIssuer: String = issuer.trimEnd('/')

    /** Redeem [refreshToken] for a fresh [Tokens]. Throws [RefreshTokenException] on any non-200. */
    fun refresh(refreshToken: String): Tokens {
        val form = buildList {
            add("grant_type" to "refresh_token")
            add("refresh_token" to refreshToken)
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
            throw RefreshTokenException(
                "Hub returned ${response.statusCode()}: $errorCode",
                oauthError = errorCode,
            )
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            accessToken = map["access_token"] as String,
            // RFC 6749 §6: the AS MAY issue a new refresh token; when it doesn't, keep the current one.
            refreshToken = (map["refresh_token"] as? String) ?: refreshToken,
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

    private fun basicAuth(id: String, secret: String): String {
        val creds = "${URLEncoder.encode(id, Charsets.UTF_8)}:${URLEncoder.encode(secret, Charsets.UTF_8)}"
        return "Basic " + java.util.Base64.getEncoder().encodeToString(creds.toByteArray(Charsets.UTF_8))
    }
}

/** Thrown when the refresh-token redemption returns a non-200 (expired/revoked refresh token, …). */
class RefreshTokenException(message: String, val oauthError: String) : RuntimeException(message)
