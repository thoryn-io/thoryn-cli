package com.devnow.thoryn.cli.cmd.project

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.net.URLDecoder

/**
 * SSO-3435 — the product-api surfaces `thoryn project init` uses, as a MockWebServer [Dispatcher] with live
 * state: `/api/v1/environments`, `/api/v1/workload-identity/trusts` (per `X-Thoryn-Environment`),
 * `/api/v1/access/grants` and `/api/v1/access/mine`. Every write is recorded.
 */
internal class FakeProjectApi : Dispatcher() {

    data class Write(val method: String, val path: String, val env: String?, val body: Map<String, Any?>)

    private val json = JsonMapper.builder().addModule(kotlinModule()).build()

    val writes = mutableListOf<Write>()
    val requests = mutableListOf<String>()
    val authorizations = mutableListOf<String?>()
    val environments = mutableListOf(
        linkedMapOf<String, Any?>("id" to PRODUCTION_ID, "slug" to "production", "name" to "Production", "kind" to "production", "suspended" to false),
    )
    val trusts = mutableListOf<MutableMap<String, Any?>>()
    val grants = mutableListOf<Map<String, Any?>>()
    /** What `/api/v1/access/mine` answers (object refs). */
    val mine = mutableListOf("workspace:$TENANT_ID")
    /** Scopes the caller does not hold: a trust asking for one is `403 scope_not_grantable`. */
    val notGrantable = mutableSetOf<String>()
    /** The platform before workspace grants exist: a `workspace:` grant is the opaque 404. */
    var workspaceGrantUnavailable = false
    private var nextTrust = 1

    fun seedSandbox(slug: String, id: String = "env-$slug"): String {
        environments += linkedMapOf("id" to id, "slug" to slug, "name" to "Sandbox $slug", "kind" to "sandbox", "suspended" to false)
        mine += "environment:$id"
        return id
    }

    fun trustsIn(env: String) = trusts.filter { it["environment"] == env }

    override fun dispatch(request: RecordedRequest): MockResponse {
        val req = request
        val method = req.method ?: "GET"
        val fullPath = req.path ?: "/"
        val route = fullPath.substringBefore('?')
        val query = fullPath.substringAfter('?', "").split('&').filter { it.contains('=') }
            .associate { it.substringBefore('=') to URLDecoder.decode(it.substringAfter('='), Charsets.UTF_8) }
        val env = req.getHeader("X-Thoryn-Environment")
        requests += "$method $route${env?.let { " [$it]" } ?: ""}"
        authorizations += req.getHeader("Authorization")
        val raw = req.body.readUtf8()
        @Suppress("UNCHECKED_CAST")
        val body = if (raw.isBlank()) emptyMap() else json.readValue(raw, Map::class.java) as Map<String, Any?>
        if (method != "GET") writes += Write(method, route, env, body)
        return when {
            route == "/api/v1/environments" && method == "GET" -> ok(mapOf("environments" to environments))
            route == "/api/v1/environments" && method == "POST" -> {
                val slug = body["slug"] as String
                if (environments.any { it["slug"] == slug }) return problem(409, "environment_slug_exists")
                val id = "env-$slug"
                val created = linkedMapOf<String, Any?>("id" to id, "slug" to slug, "name" to body["name"], "kind" to "sandbox", "suspended" to false)
                environments += created
                mine += "environment:$id"
                json(201, created)
            }
            route == "/api/v1/access/mine" && method == "GET" ->
                ok(mapOf("data" to mine.filter { query["type"] == null || it.startsWith("${query["type"]}:") }))
            route == "/api/v1/access/grants" && method == "POST" -> {
                val objectRef = body["object"] as String
                if (objectRef.startsWith("workspace:") && workspaceGrantUnavailable) return problem(404, "not_found")
                val grant = linkedMapOf("subject" to body["subject"], "relation" to body["relation"], "object" to objectRef)
                if (grant in grants) {
                    ok(grant + ("createdAt" to "2026-09-30T10:00:00Z"))
                } else {
                    grants += grant
                    json(201, grant + ("createdAt" to "2026-09-30T10:00:00Z"))
                }
            }
            route == "/api/v1/workload-identity/trusts" && method == "GET" ->
                ok(mapOf("data" to trustsIn(env ?: "production"), "pagination" to mapOf("cursor" to null, "hasMore" to false)))
            route == "/api/v1/workload-identity/trusts" && method == "POST" -> createTrust(env ?: "production", body)
            else -> MockResponse().setResponseCode(599).setBody("FakeProjectApi: unexpected $method $fullPath")
        }
    }

    private fun createTrust(env: String, body: Map<String, Any?>): MockResponse {
        @Suppress("UNCHECKED_CAST")
        val scopes = body["scopes"] as List<String>
        scopes.firstOrNull { it in notGrantable }?.let {
            return json(
                403,
                mapOf(
                    "type" to "about:blank", "title" to "Forbidden", "status" to 403, "errorCode" to "scope_not_grantable",
                    "detail" to "Caller does not hold these scopes and therefore cannot grant them: $it",
                ),
            )
        }
        if (trustsIn(env).any { it["name"] == body["name"] }) return problem(409, "workload_identity_trust_name_taken")
        if (env == "production" && body["confirmProduction"] != true) return problem(400, "production_confirmation_required")
        val n = nextTrust++
        val trust = linkedMapOf<String, Any?>(
            "id" to "trust-$n", "environment" to env, "name" to body["name"], "provider" to "github_actions",
            "clientId" to "wi_client$n", "audience" to "https://acme.auth.stg.thoryn.org/$env",
            "tokenEndpoint" to "https://acme.auth.stg.thoryn.org/$env/oauth2/token",
            "github" to body["github"], "scopes" to scopes, "enabled" to true, "createdAt" to "2026-09-30T10:00:00Z",
        )
        trusts += trust
        return json(201, trust)
    }

    private fun ok(value: Any?) = json(200, value)

    private fun json(status: Int, value: Any?): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(json.writeValueAsString(value))

    private fun problem(status: Int, code: String): MockResponse = MockResponse().setResponseCode(status)
        .setHeader("Content-Type", "application/problem+json")
        .setBody(json.writeValueAsString(mapOf("type" to "about:blank", "status" to status, "errorCode" to code, "detail" to "Refused: $code.")))

    companion object {
        const val TENANT_ID: String = "3f6c2a10-acme-4000-8000-000000000001"
        const val PRODUCTION_ID: String = "env-production"
    }
}
