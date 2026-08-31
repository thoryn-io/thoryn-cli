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
 * RFC 8628 — OAuth 2.0 Device Authorization Grant.
 *
 * Flow:
 *
 *  1. POST `/oauth2/device_authorization` (with client auth) — returns
 *     `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`.
 *  2. Print the verification URI and user code. The user opens the URL on
 *     another device, enters the code, and authenticates.
 *  3. Poll POST `/oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
 *     at the spec'd interval. Possible per-poll responses (RFC 8628 §3.5):
 *      - 400 `authorization_pending` — keep polling at current interval.
 *      - 400 `slow_down` — increase interval by 5s and keep polling.
 *      - 400 `access_denied` — user pressed "deny"; fail.
 *      - 400 `expired_token` — user took too long; fail.
 *      - 200 with tokens — success.
 *
 * Client authentication is confidential OR public (SSO-2822): with a [clientSecret] the CLI uses
 * HTTP Basic; without one it sends only its `client_id` in the form body (RFC 8628 §3.1) — the hub's
 * `DeviceAuthorizationEndpointFilter` accepts a public client (`thoryn-cli`) by client_id alone.
 *
 * ## Transport security (SSO-1993 / pentest SSO-849 item 5)
 *
 * Both device-code endpoints carry secrets over the wire: the
 * `/oauth2/device_authorization` request authenticates the client, and the
 * `/oauth2/token` poll returns the access + refresh tokens. Running either
 * against a non-loopback host over plaintext `http://` would expose those to a
 * network attacker. `LoginCommand` already validates `--issuer` up front
 * (SSO-1145), but this class is a reusable component, so it re-validates the
 * issuer itself — the guarantee then holds at the exact point the requests are
 * built, regardless of caller. The [init] block rejects a non-loopback
 * `http://` issuer *before any device-code request is made*; both request
 * sites build their URI from the validated [baseIssuer].
 */
class DeviceCodeFlow(
    private val issuer: String,
    private val clientId: String,
    /**
     * SSO-2822 — nullable. A CONFIDENTIAL client supplies its secret (HTTP Basic on both device-code
     * requests); a PUBLIC client (RFC 8252 native app — `thoryn-cli`) passes `null` and authenticates
     * with just its `client_id` in the form body (RFC 8628 §3.1). The device_code itself is the
     * security material for a public device client.
     */
    private val clientSecret: String?,
    private val sender: HttpSender,
    /**
     * When `true`, a non-loopback `http://` issuer is permitted (with a WARN to
     * stderr) for local development where TLS is unavailable. Threaded from the
     * CLI `--dev` flag; defaults to `false` (fail-safe) for every other caller.
     */
    private val devMode: Boolean = false,
    private val sleeper: Sleeper = Sleeper.real(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

    init {
        // SSO-1993: require https:// (or http:// only for a loopback host)
        // before any device-code traffic. Throws IssuerUrlValidationException
        // on a non-loopback http:// issuer unless devMode is set. Reuses the
        // SSO-1145 validator so the rule stays in one place.
        IssuerUrlValidator.validate(issuer, devMode)
    }

    /**
     * The validated, trailing-slash-normalised issuer. Both request sites build
     * their endpoint URI from this field so the transport-security guard above
     * covers the device-authorization request AND the token-polling exchange.
     */
    private val baseIssuer: String = issuer.trimEnd('/')

    /**
     * Run the full device-code flow. Returns [Tokens] on success;
     * throws [DeviceCodeException] with a specific [DeviceCodeError] on
     * any terminal failure.
     *
     * [onAuthorizationStarted] is called once with the verification URI and
     * user code so the caller can render them however it likes (CLI prints,
     * GUI dialog, etc.).
     */
    fun run(scope: String, onAuthorizationStarted: (DeviceAuthorizationResponse) -> Unit): Tokens {
        val authorization = startDeviceAuthorization(scope)
        onAuthorizationStarted(authorization)
        return pollForTokens(authorization)
    }

    private fun startDeviceAuthorization(scope: String): DeviceAuthorizationResponse {
        val body = formEncode(
            buildList {
                if (scope.isNotBlank()) add("scope" to scope)
                // SSO-2822: public client authenticates with client_id in the body (no Basic).
                if (clientSecret == null) add("client_id" to clientId)
            },
        )
        val builder = HttpRequest.newBuilder()
            // SSO-1993: baseIssuer was https/loopback-validated in init.
            .uri(URI.create("$baseIssuer/oauth2/device_authorization"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
        if (clientSecret != null) builder.header("Authorization", basicAuth(clientId, clientSecret))
        val request = builder.build()

        val response = sender.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            val errorCode = parseErrorCode(response.body()) ?: "unknown"
            throw DeviceCodeException(DeviceCodeError.AUTHORIZATION_FAILED, "Hub returned ${response.statusCode()}: $errorCode")
        }
        val map: Map<String, Any?> = mapper.readValue(response.body())
        return DeviceAuthorizationResponse(
            deviceCode = map["device_code"] as String,
            userCode = map["user_code"] as String,
            verificationUri = map["verification_uri"] as String,
            verificationUriComplete = map["verification_uri_complete"] as? String,
            expiresIn = (map["expires_in"] as Number).toInt(),
            interval = (map["interval"] as? Number)?.toInt() ?: 5,
        )
    }

    private fun pollForTokens(authorization: DeviceAuthorizationResponse): Tokens {
        var interval = authorization.interval.coerceAtLeast(1).toLong()
        val deadline = System.currentTimeMillis() + (authorization.expiresIn * 1000L)

        while (System.currentTimeMillis() < deadline) {
            sleeper.sleepSeconds(interval)
            val pollResponse = pollOnce(authorization.deviceCode)
            when (pollResponse) {
                is PollResult.Success -> return pollResponse.tokens
                is PollResult.Pending -> {
                    // Loop again at current interval.
                }
                is PollResult.SlowDown -> {
                    interval += 5
                }
                is PollResult.Failed -> throw DeviceCodeException(pollResponse.error, pollResponse.message)
            }
        }
        throw DeviceCodeException(DeviceCodeError.EXPIRED_TOKEN, "Device code expired before user authenticated")
    }

    private fun pollOnce(deviceCode: String): PollResult {
        val body = formEncode(
            listOf(
                "grant_type" to "urn:ietf:params:oauth:grant-type:device_code",
                "device_code" to deviceCode,
                "client_id" to clientId,
            ),
        )
        val builder = HttpRequest.newBuilder()
            // SSO-1993: baseIssuer was https/loopback-validated in init.
            .uri(URI.create("$baseIssuer/oauth2/token"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
        // SSO-2822: confidential client authenticates with Basic; public client already carried its
        // client_id in the form body above.
        if (clientSecret != null) builder.header("Authorization", basicAuth(clientId, clientSecret))
        val request = builder.build()

        val response = sender.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() == 200) {
            val map: Map<String, Any?> = mapper.readValue(response.body())
            val expiresIn = (map["expires_in"] as? Number)?.toLong()
            val tokens = Tokens(
                accessToken = map["access_token"] as String,
                refreshToken = map["refresh_token"] as? String,
                idToken = map["id_token"] as? String,
                tokenType = (map["token_type"] as? String) ?: "Bearer",
                expiresAtEpochSecond = expiresIn?.let { System.currentTimeMillis() / 1000 + it },
                scope = map["scope"] as? String,
            )
            return PollResult.Success(tokens)
        }
        return when (val error = parseErrorCode(response.body())) {
            "authorization_pending" -> PollResult.Pending
            "slow_down" -> PollResult.SlowDown
            "access_denied" -> PollResult.Failed(DeviceCodeError.ACCESS_DENIED, "User denied the authorization request")
            "expired_token" -> PollResult.Failed(DeviceCodeError.EXPIRED_TOKEN, "Device code expired before user authenticated")
            null -> PollResult.Failed(DeviceCodeError.AUTHORIZATION_FAILED, "Hub returned ${response.statusCode()} with unparseable body")
            else -> PollResult.Failed(DeviceCodeError.AUTHORIZATION_FAILED, "Hub returned $error")
        }
    }

    private fun parseErrorCode(body: String): String? = try {
        val map: Map<String, Any?> = mapper.readValue(body)
        map["error"] as? String
    } catch (_: Exception) {
        null
    }

    private fun formEncode(pairs: List<Pair<String, String>>): String =
        pairs.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}"
        }

    private fun basicAuth(id: String, secret: String): String =
        "Basic ${Base64.getEncoder().encodeToString("$id:$secret".toByteArray(Charsets.UTF_8))}"

    /**
     * Sealed result of a single poll iteration. Internal — the public API
     * either returns [Tokens] or throws [DeviceCodeException].
     */
    private sealed interface PollResult {
        data class Success(val tokens: Tokens) : PollResult
        data object Pending : PollResult
        data object SlowDown : PollResult
        data class Failed(val error: DeviceCodeError, val message: String) : PollResult
    }
}

/**
 * Successful response from `POST /oauth2/device_authorization`.
 *
 * Hub returns snake_case JSON; this class is camelCase and populated
 * manually from a [Map] in [DeviceCodeFlow] so we don't need to fiddle with
 * Jackson 3 naming strategies (which differ from Jackson 2).
 */
data class DeviceAuthorizationResponse(
    val deviceCode: String,
    val userCode: String,
    val verificationUri: String,
    val verificationUriComplete: String? = null,
    val expiresIn: Int,
    val interval: Int = 5,
)

enum class DeviceCodeError {
    AUTHORIZATION_FAILED,
    ACCESS_DENIED,
    EXPIRED_TOKEN,
}

class DeviceCodeException(val error: DeviceCodeError, message: String) : RuntimeException(message)

/**
 * Thin abstraction over [java.net.http.HttpClient.send] so [DeviceCodeFlow]
 * can be unit-tested with stubbed responses.
 */
fun interface HttpSender {
    fun send(request: HttpRequest, bodyHandler: HttpResponse.BodyHandler<String>): HttpResponse<String>
}

/**
 * Sleep abstraction for tests; the real implementation calls
 * [java.lang.Thread.sleep].
 */
fun interface Sleeper {
    fun sleepSeconds(seconds: Long)

    companion object {
        fun real(): Sleeper = Sleeper { seconds -> Thread.sleep(seconds * 1000) }
    }
}
