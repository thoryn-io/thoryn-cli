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
 * RFC 6749 §4.4 — OAuth 2.0 Client Credentials Grant.
 *
 * The non-interactive counterpart to [DeviceCodeFlow]: a service-account /
 * machine principal exchanges its `client_id` + `client_secret` for an access
 * token directly at the hub token endpoint, with no browser and no user
 * interaction. Used by CI / automation (e.g. `thoryn tenant seed`) and by
 * `thoryn login --client-credentials`.
 *
 * Flow (single round-trip):
 *
 *  1. POST `/oauth2/token` with `grant_type=client_credentials` and the
 *     requested `scope`, authenticating the client via HTTP Basic
 *     (`client_secret_basic`) — the same client-auth shape [DeviceCodeFlow]
 *     uses, and the shape the hub's token endpoint accepts for service-account
 *     clients (verified: oauthy `HubInternalClientCredentialsAuthTest`).
 *  2. 200 → parse the RFC 6749 §5.1 token response into [Tokens].
 *  3. Non-200 → throw [ClientCredentialsException] carrying the parsed OAuth2
 *     `error` code (RFC 6749 §5.2), e.g. `invalid_client`, `invalid_scope`,
 *     `unauthorized_client`.
 *
 * **Tenant binding.** A client_credentials token carries no user; its `tnt`
 * claim (required by product-api's customer-plane endpoints) is minted by the
 * hub from the *tenant-subdomain issuer* the token is requested against
 * (`TenantResolutionFilter` → `TenantClaimCustomizer` on the hub side). The
 * caller therefore points [issuer] at the tenant's hub host
 * (e.g. `https://acme.hub.thoryn.org`) so the minted token is scoped to that
 * tenant. This class does not know or care about the tenant — it only performs
 * the grant.
 *
 * **Secret handling.** The secret is supplied to the constructor by the caller
 * (read from an env var / `--client-secret-file` / stdin — never argv). It is
 * used only to build the Basic auth header for the single token request and is
 * never logged, persisted, or echoed. Only the resulting short-lived access
 * token is stored (same as the device flow).
 */
class ClientCredentialsFlow(
    private val issuer: String,
    private val clientId: String,
    private val clientSecret: String,
    private val sender: HttpSender,
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    /**
     * Run the client-credentials grant. Returns [Tokens] on success; throws
     * [ClientCredentialsException] with the parsed OAuth2 error code on any
     * non-200 response.
     */
    fun run(scope: String): Tokens {
        val body = formEncode(
            buildList {
                add("grant_type" to "client_credentials")
                if (scope.isNotBlank()) add("scope" to scope)
            },
        )
        val request = HttpRequest.newBuilder()
            .uri(URI.create("${issuer.trimEnd('/')}/oauth2/token"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", basicAuth(clientId, clientSecret))
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        val response = sender.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            val errorCode = parseErrorCode(response.body()) ?: "unknown"
            throw ClientCredentialsException(
                "Hub returned ${response.statusCode()}: $errorCode",
                oauthError = errorCode,
            )
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        val expiresIn = (map["expires_in"] as? Number)?.toLong()
        return Tokens(
            // client_credentials never returns a refresh token (RFC 6749 §4.4.3)
            // or an id_token — the CLI just stores the access token.
            accessToken = map["access_token"] as String,
            refreshToken = null,
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
 * Thrown on any client-credentials grant failure. [oauthError] carries the
 * RFC 6749 §5.2 machine error code (`invalid_client`, `invalid_scope`, …) when
 * the hub returned a parseable error body, or `"unknown"` otherwise.
 */
class ClientCredentialsException(
    message: String,
    val oauthError: String,
) : RuntimeException(message)
