package com.devnow.thoryn.cli.cmd.provision

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule

/**
 * SSO-3089 — an in-memory stand-in for the product-api surfaces `thoryn provision` converges against,
 * mounted as the MockWebServer [Dispatcher]. It keeps live state per environment (the
 * `X-Thoryn-Environment` header; absent ⇒ production), answers the read-by-key lookups, applies
 * writes, and RECORDS every write so a test can assert "a second apply issued no writes" or "exactly
 * one PATCH carrying only the changed field" without scripting response order.
 */
internal class FakeProductApi : Dispatcher() {

    data class Write(val method: String, val path: String, val env: String?, val confirm: String?, val body: Map<String, Any?>)

    val writes = mutableListOf<Write>()
    val environments = mutableListOf<MutableMap<String, Any?>>()
    val applications = mutableListOf<MutableMap<String, Any?>>()
    val users = mutableListOf<MutableMap<String, Any?>>()
    val federationMembers = mutableListOf<MutableMap<String, Any?>>()
    val emailProviders = mutableMapOf<String?, MutableMap<String, Any?>>()
    val branding = mutableMapOf<String?, MutableMap<String, Any?>>()
    val activeFlow = mutableMapOf<String?, Int>()
    /** SSO-3100 — the stored sign-in method allow-list per environment (absent ⇒ the default policy). */
    val loginMethods = mutableMapOf<String?, List<String>>()
    private val supportedLoginMethods = listOf("password", "magic_link", "magic_code", "passkey", "totp", "sms")
    private var seq = 0
    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    fun writesTo(pathPrefix: String) = writes.filter { it.path.startsWith(pathPrefix) }

    /** SSO-3100 — the PROVISIONING writes only: the recipe interpreter's best-effort receipt attestation POST is not one. */
    val provisioningWrites: List<Write> get() = writes.filter { !it.path.startsWith("/api/v1/attestations") }
    fun reset() { writes.clear() }

    fun seedEnvironment(slug: String, name: String = slug): String =
        "env-${++seq}".also { environments += mutableMapOf("id" to it, "slug" to slug, "name" to name, "kind" to "sandbox", "suspended" to false) }

    fun seedApplication(env: String?, displayName: String, redirectUris: List<String> = listOf("http://127.0.0.1/callback")): String =
        "app-${++seq}".also { applications += mutableMapOf("clientId" to it, "displayName" to displayName, "redirectUris" to redirectUris, "status" to "active", "_env" to env) }

    private fun body(req: RecordedRequest): Map<String, Any?> {
        val raw = req.body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        @Suppress("UNCHECKED_CAST")
        return mapper.readValue(raw, Map::class.java) as Map<String, Any?>
    }

    private fun json(status: Int, value: Any?): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(mapper.writeValueAsString(value))

    private fun problem(status: Int, code: String): MockResponse =
        json(status, mapOf("type" to "about:blank", "status" to status, "title" to code, "errorCode" to code, "detail" to code))

    private fun visible(rec: Map<String, Any?>, env: String?) = rec["_env"] == env

    private fun public(rec: Map<String, Any?>) = rec.filterKeys { !it.startsWith("_") }

    override fun dispatch(req: RecordedRequest): MockResponse {
        val method = req.method ?: "GET"
        val path = req.path ?: "/"
        val route = path.substringBefore('?')
        val env = req.getHeader("X-Thoryn-Environment")
        val confirm = req.getHeader("X-Thoryn-Confirm")
        val b = if (method == "GET" || method == "DELETE") emptyMap() else body(req)
        if (method != "GET") writes += Write(method, route, env, confirm, b)
        val seg = route.removePrefix("/api/v1/").split('/')
        return when {
            // ── environments ──
            route == "/api/v1/environments" && method == "GET" -> json(200, mapOf("environments" to environments))
            route == "/api/v1/environments" && method == "POST" -> {
                val id = seedEnvironment(b["slug"].toString(), b["name"]?.toString() ?: b["slug"].toString())
                json(201, environments.first { it["id"] == id })
            }
            seg[0] == "environments" && seg.size == 2 && method == "PATCH" -> {
                val e = environments.firstOrNull { it["id"] == seg[1] } ?: return problem(404, "not_found")
                b["name"]?.let { e["name"] = it }; json(200, e)
            }
            seg[0] == "environments" && seg.size == 2 && method == "DELETE" -> {
                val e = environments.firstOrNull { it["id"] == seg[1] } ?: return problem(404, "not_found")
                if (confirm != e["slug"]) return problem(if (confirm == null) 428 else 422, "production_confirmation_required")
                environments.remove(e); MockResponse().setResponseCode(204)
            }
            // ── applications ──
            route == "/api/v1/applications" && method == "GET" -> json(200, mapOf("data" to applications.filter { visible(it, env) }.map { public(it) }))
            route == "/api/v1/applications" && method == "POST" -> {
                val id = "app-${++seq}"
                applications += (b + mapOf("clientId" to id, "status" to "active", "_env" to env)).toMutableMap()
                json(201, public(applications.last()))
            }
            seg[0] == "applications" && seg.size == 2 -> {
                val a = applications.firstOrNull { it["clientId"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, public(a))
                    "PATCH" -> { a.putAll(b); json(200, public(a)) }
                    "DELETE" -> { applications.remove(a); MockResponse().setResponseCode(204) }
                    else -> problem(405, "method")
                }
            }
            // ── users ──
            route == "/api/v1/users" && method == "GET" -> {
                val email = path.substringAfter("email=", "").substringBefore('&').let { java.net.URLDecoder.decode(it, "UTF-8") }
                json(200, mapOf("items" to users.filter { visible(it, env) && (email.isBlank() || it["email"] == email) }.map { public(it) }))
            }
            route == "/api/v1/users" && method == "POST" -> {
                val id = "u-${++seq}"
                users += (b.filterKeys { it != "password" } + mapOf("id" to id, "status" to "active", "_env" to env)).toMutableMap()
                json(201, public(users.last()))
            }
            seg[0] == "users" && seg.size == 2 -> {
                val u = users.firstOrNull { it["id"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, public(u))
                    "PATCH" -> { u.putAll(b); json(200, public(u)) }
                    "DELETE" -> { users.remove(u); json(200, emptyMap<String, Any>()) }
                    else -> problem(405, "method")
                }
            }
            // ── federation members ──
            route == "/api/v1/federation-members" && method == "GET" -> json(200, mapOf("data" to federationMembers.filter { visible(it, env) }.map { public(it) }))
            route == "/api/v1/federation-members" && method == "POST" -> {
                val id = "fm-${++seq}"
                federationMembers += (b.filterKeys { it != "clientSecret" } + mapOf("id" to id, "_env" to env)).toMutableMap()
                json(201, public(federationMembers.last()))
            }
            seg[0] == "federation-members" && seg.size == 2 -> {
                val m = federationMembers.firstOrNull { it["id"] == seg[1] && visible(it, env) } ?: return problem(404, "not_found")
                when (method) {
                    "GET" -> json(200, public(m))
                    "PATCH" -> { m.putAll(b.filterKeys { it != "clientSecret" }); json(200, public(m)) }
                    "DELETE" -> { federationMembers.remove(m); MockResponse().setResponseCode(204) }
                    else -> problem(405, "method")
                }
            }
            // ── email provider (singleton per env) ──
            route == "/api/v1/email-provider" && method == "GET" -> {
                val p = emailProviders[env]
                json(200, p?.plus(mapOf("configured" to true)) ?: mapOf("configured" to false, "providerType" to "platform", "enabled" to false))
            }
            route == "/api/v1/email-provider" && method == "PUT" -> {
                val p = emailProviders.getOrPut(env) { mutableMapOf("providerType" to "smtp", "configVersion" to 0) }
                p.putAll(b.filterKeys { it != "smtpPassword" }); p["hasPassword"] = b.containsKey("smtpPassword") || p["hasPassword"] == true
                p["configVersion"] = (p["configVersion"] as Int) + 1
                json(200, p)
            }
            route == "/api/v1/email-provider" && method == "DELETE" -> { emailProviders.remove(env); MockResponse().setResponseCode(204) }
            // ── branding (singleton per env) ──
            route == "/api/v1/login-experience/branding" && method == "GET" -> {
                val stored = branding[env] ?: emptyMap()
                json(200, mapOf("stored" to stored, "effective" to (mapOf("theme" to "light", "primaryColor" to "#000000") + stored)))
            }
            route == "/api/v1/login-experience/branding" && method == "PUT" -> {
                val stored = branding.getOrPut(env) { mutableMapOf() }; stored.putAll(b)
                json(200, mapOf("stored" to stored, "effective" to (mapOf("theme" to "light", "primaryColor" to "#000000") + stored)))
            }
            // ── login methods (singleton per env; SSO-3100 — product-api /api/v1/login-methods) ──
            route == "/api/v1/login-methods" && method == "GET" -> {
                val stored = loginMethods[env]
                json(200, mapOf("stored" to stored, "effective" to (stored ?: supportedLoginMethods), "supported" to supportedLoginMethods))
            }
            route == "/api/v1/login-methods" && method == "PUT" -> {
                val methods = (b["methods"] as? List<*>).orEmpty().map { it.toString() }
                if (methods.isEmpty() || methods.any { it !in supportedLoginMethods }) return problem(400, "invalid_login_method")
                loginMethods[env] = methods
                json(200, mapOf("stored" to methods, "effective" to methods, "supported" to supportedLoginMethods))
            }
            route == "/api/v1/login-methods" && method == "DELETE" -> { loginMethods.remove(env); MockResponse().setResponseCode(204) }
            // ── login flows ──
            route == "/api/v1/login-flows/active" && method == "GET" ->
                activeFlow[env]?.let { json(200, mapOf("version" to it, "status" to "active", "stages" to emptyList<Any>())) } ?: problem(404, "not_found")
            seg[0] == "login-flows" && seg.size == 4 && seg[1] == "templates" && seg[3] == "apply" ->
                json(200, mapOf("version" to (++seq), "status" to "draft", "stages" to emptyList<Any>()))
            route == "/api/v1/login-flows/activate" && method == "POST" -> {
                val v = (b["version"] as Number).toInt(); activeFlow[env] = v
                json(200, mapOf("version" to v, "status" to "active", "stages" to emptyList<Any>()))
            }
            // ── receipt attestation (SSO-2878; the recipe interpreter's best-effort signed layer) ──
            route == "/api/v1/attestations" && method == "POST" ->
                json(200, mapOf("kid" to "receipt-attestation-fake-v1", "signature" to "sig", "canonicalPayload" to "e30", "attestedAt" to "2026-01-01T00:00:00Z"))
            else -> problem(404, "no_route:$method $route")
        }
    }
}
