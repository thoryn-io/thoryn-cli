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
 * The CLI authenticates as a confidential client (Basic Auth using
 * `client_id` + `client_secret`). True public-client support (no secret)
 * lands when the hub's `DeviceAuthorizationEndpointFilter` grows a public
 * client branch.
 */
class DeviceCodeFlow(
    private val issuer: String,
    private val clientId: String,
    private val clientSecret: String,
    private val sender: HttpSender,
    private val sleeper: Sleeper = Sleeper.real(),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
) {

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
            },
        )
        val request = HttpRequest.newBuilder()
            .uri(URI.create("${issuer.trimEnd('/')}/oauth2/device_authorization"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", basicAuth(clientId, clientSecret))
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

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
        val request = HttpRequest.newBuilder()
            .uri(URI.create("${issuer.trimEnd('/')}/oauth2/token"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", basicAuth(clientId, clientSecret))
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

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
