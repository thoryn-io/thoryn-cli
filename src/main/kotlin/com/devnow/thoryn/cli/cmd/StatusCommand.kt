package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import tools.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.concurrent.Callable

/**
 * `thoryn status` — SSO-2862 (CLI maturity) — the online sibling of `whoami`: is the platform
 * reachable and is my session still good?
 *
 * Probes the two hosts the CLI talks to and reports reachability + latency:
 *  - **hub** — a `GET {hub}/.well-known/openid-configuration` (unauthenticated OIDC discovery);
 *    `200` means the hub is healthy.
 *  - **gateway** — a `GET {gateway}/api/v1/applications` carrying the CURRENT stored bearer (if
 *    any). Any HTTP response means the gateway is reachable; a `401` means the token was rejected,
 *    anything else (`200/403/404`) means the gateway accepted it.
 *
 * It reads the token from the local store but — unlike every other command — does **not** refresh
 * it (SSO-2834 / SSO-2861): `status` must report the session as it actually is, so an expired token
 * shows as `EXPIRED` rather than being silently renewed. Runs signed-out too (auth is reported as
 * "not signed in").
 *
 * Exit: **0** when hub is healthy and the gateway is reachable; **3** ([CommandSupport.EXIT_IO_ERROR])
 * when either host cannot be reached — so scripts can gate on `thoryn status`.
 */
@Command(
    name = "status",
    description = ["Check platform reachability + session health: hub, gateway, and token validity."],
    mixinStandardHelpOptions = true,
)
class StatusCommand : Callable<Int> {

    @Option(names = ["--hub"], description = ["Override the hub base URL (default: signed-in hub, else \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_HUB)
    var hub: String = ThorynConfig.DEFAULT_HUB

    @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: signed-in gateway, else \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
    var gateway: String = ThorynConfig.DEFAULT_GATEWAY

    @Option(names = ["--output"])
    var outputRaw: String? = null

    override fun call(): Int {
        val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE

        // Read the token WITHOUT refreshing — status reports the session as-is (an expired token
        // must show as EXPIRED, not be silently renewed). Signed-out is a valid state to report.
        val tokens: Tokens? = runCatching { TokenStoreFactory.default().read() }.getOrNull()
        hub = CommandSupport.resolveHub(hub, tokens)
        gateway = CommandSupport.resolveGateway(gateway, tokens)

        val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(PROBE_TIMEOUT_SECONDS)).build()
        val hubProbe = probe(http, "${hub.trimEnd('/')}/.well-known/openid-configuration", bearer = null)
        val gwProbe = probe(http, "${gateway.trimEnd('/')}/api/v1/applications", bearer = tokens?.accessToken)

        val claims = tokens?.let { JwtClaims.of(it.accessToken) }
        val expEpoch = tokens?.expiresAtEpochSecond ?: claims?.get("exp")?.asLong()
        val tokenStatus = when {
            tokens == null -> "not signed in"
            else -> tokenStatus(expEpoch)
        }
        // The gateway accepted the token when we are signed in and it did not answer 401.
        val authAccepted = tokens != null && gwProbe.reachable && gwProbe.httpStatus != 401

        val hubHealthy = hubProbe.httpStatus == 200
        val ok = hubHealthy && gwProbe.reachable

        val node = mapper.createObjectNode().apply {
            put("ok", ok)
            put("hub", hub)
            put("hubStatus", hubProbe.label)
            hubProbe.latencyMs?.let { put("hubLatencyMs", it) }
            put("gateway", gateway)
            put("gatewayStatus", gwProbe.label)
            gwProbe.latencyMs?.let { put("gatewayLatencyMs", it) }
            put("signedIn", tokens != null)
            claims?.get("sub")?.asString()?.let { put("subject", it) }
            claims?.get("tnt")?.asString()?.let { put("tenant", it) }
            // SSO-2867 — the workspace an active `switch` operates on (base `tenant` is the login tenant).
            // SSO-2870 — and the environment targeted inside it (X-Thoryn-Environment on every request).
            runCatching { SelectedWorkspaceStore().read() }.getOrNull()?.let { sel ->
                put("activeWorkspace", sel.slug)
                sel.environmentSlug?.let { put("activeEnvironment", it) }
            }
            if (tokens != null) put("authAccepted", authAccepted)
            put("tokenStatus", tokenStatus)
        }

        CommandSupport.emitRecord(format, node, { n: JsonNode ->
            listOf(
                "ok" to n["ok"]?.asBoolean(),
                "hub" to n["hub"]?.asString(),
                "hubStatus" to n["hubStatus"]?.asString(),
                "hubLatencyMs" to n["hubLatencyMs"]?.asLong(),
                "gateway" to n["gateway"]?.asString(),
                "gatewayStatus" to n["gatewayStatus"]?.asString(),
                "gatewayLatencyMs" to n["gatewayLatencyMs"]?.asLong(),
                "signedIn" to n["signedIn"]?.asBoolean(),
                "subject" to n["subject"]?.asString(),
                "tenant" to n["tenant"]?.asString(),
                "activeWorkspace" to n["activeWorkspace"]?.asString(),
                "activeEnvironment" to n["activeEnvironment"]?.asString(),
                "authAccepted" to n["authAccepted"]?.asBoolean(),
                "tokenStatus" to n["tokenStatus"]?.asString(),
            ).filter { it.second != null }
        })

        return if (ok) CommandSupport.EXIT_OK else CommandSupport.EXIT_IO_ERROR
    }

    /** Result of one reachability probe: [reachable] is true when we got any HTTP response. */
    private class ProbeResult(val reachable: Boolean, val httpStatus: Int, val label: String, val latencyMs: Long?)

    private fun probe(http: HttpClient, url: String, bearer: String?): ProbeResult {
        val builder = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(PROBE_TIMEOUT_SECONDS))
            .header("Accept", "application/json")
            .GET()
        if (bearer != null) builder.header("Authorization", "Bearer $bearer")
        val start = System.nanoTime()
        return try {
            val response = http.send(builder.build(), HttpResponse.BodyHandlers.discarding())
            val ms = (System.nanoTime() - start) / 1_000_000
            ProbeResult(reachable = true, httpStatus = response.statusCode(), label = "HTTP ${response.statusCode()}", latencyMs = ms)
        } catch (e: Exception) {
            ProbeResult(reachable = false, httpStatus = -1, label = "unreachable — ${CommandSupport.describeThrowable(e)}", latencyMs = null)
        }
    }

    private fun tokenStatus(expEpoch: Long?): String {
        if (expEpoch == null) return "valid (expiry unknown)"
        val remaining = expEpoch - Instant.now().epochSecond
        return if (remaining <= 0) "EXPIRED — run `thoryn login`" else "valid (expires in ${humanDuration(remaining)})"
    }

    private fun humanDuration(seconds: Long): String {
        val h = seconds / 3600
        val m = (seconds % 3600) / 60
        val s = seconds % 60
        return when {
            h > 0 -> "${h}h ${m}m"
            m > 0 -> "${m}m ${s}s"
            else -> "${s}s"
        }
    }

    private companion object {
        const val PROBE_TIMEOUT_SECONDS: Long = 10
        val mapper = ObjectMapper()
    }
}
