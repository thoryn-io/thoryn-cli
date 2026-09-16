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
    /** SSO-3113 — access grants (`/api/v1/access/grants`, the SSO-3112 contract): `{subject, relation, object, createdAt}`. */
    val grants = mutableListOf<MutableMap<String, Any?>>()
    /** SSO-3113 — what `/api/v1/access/mine` answers for the caller (object refs). */
    val mine = mutableListOf<String>()
    /** SSO-3113 — simulate a token WITHOUT `tenant:access.write` / `tenant:access.read` (403 insufficient_scope). */
    var denyGrantWrites = false
    var denyGrantReads = false
    /** SSO-3113 — the one-shot client secrets the fake minted for confidential applications, by clientId (test-side ledger only). */
    val mintedSecrets = mutableMapOf<String, String>()
    private val supportedLoginMethods = listOf("password", "magic_link", "magic_code", "passkey", "totp", "sms")
    private var seq = 0
    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    fun writesTo(pathPrefix: String) = writes.filter { it.path.startsWith(pathPrefix) }

    /** SSO-3100 — the PROVISIONING writes only: the recipe interpreter's best-effort receipt attestation POST is not one. */
    val provisioningWrites: List<Write> get() = writes.filter { !it.path.startsWith("/api/v1/attestations") }
    fun reset() { writes.clear() }

    fun seedEnvironment(slug: String, name: String = slug): String =
        "env-${++seq}".also { environments += mutableMapOf("id" to it, "slug" to slug, "name" to name, "kind" to "sandbox", "suspended" to false) }

    /** [clientId] pins the id (a file may declare a fixed one); otherwise the fake allocates `app-<n>`. */
    fun seedApplication(
        env: String?,
        displayName: String,
        redirectUris: List<String> = listOf("http://127.0.0.1/callback"),
        clientId: String? = null,
    ): String =
        (clientId ?: "app-${++seq}").also { applications += mutableMapOf("clientId" to it, "displayName" to displayName, "redirectUris" to redirectUris, "status" to "active", "_env" to env) }

    fun seedGrant(subject: String, relation: String, objectRef: String) {
        grants += mutableMapOf("subject" to subject, "relation" to relation, "object" to objectRef, "createdAt" to "2026-09-15T00:00:00Z")
    }

    fun grantsOn(objectRef: String): List<String> = grants.filter { it["object"] == objectRef }.map { "${it["subject"]} ${it["relation"]}" }

    private fun query(path: String): Map<String, String> =
        path.substringAfter('?', "").split('&').filter { it.contains('=') }.associate { kv ->
            kv.substringBefore('=') to java.net.URLDecoder.decode(kv.substringAfter('='), "UTF-8")
        }

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
        // SSO-3113 — a DELETE may carry a JSON body (`DELETE /api/v1/access/grants`); `body` tolerates an empty one.
        val b = if (method == "GET") emptyMap() else body(req)
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
                // SSO-3104 / SSO-3119 — product-api honours a REQUESTED `clientId` (that is how the
                // committed file pins `cli` / `cli-ci`); only an absent one is allocated. The fake used
                // to overwrite it unconditionally, which hid both the fixed-id create and the grant that
                // names it as a subject.
                val id = (b["clientId"] as? String)?.takeIf { it.isNotBlank() } ?: "app-${++seq}"
                if (applications.any { it["clientId"] == id }) return problem(409, "client_id_taken")
                applications += (b + mapOf("clientId" to id, "status" to "active", "_env" to env)).toMutableMap()
                // SSO-3113 — a CONFIDENTIAL client's one-shot secret rides ONLY on the create response (never on a later
                // GET). product-api's `clientType` defaults to confidential, so only an explicit `public` is secret-less.
                val response = public(applications.last()).toMutableMap()
                if (b["clientType"] != "public") {
                    val secret = "minted-secret-$id"
                    mintedSecrets[id] = secret
                    response["clientSecret"] = secret
                }
                json(201, response)
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
            // ── access grants (SSO-3113; the SSO-3112 /api/v1/access contract) ──
            route == "/api/v1/access/grants" && method == "GET" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                val q = query(path)
                val matching = grants.filter { g -> (q["object"] == null || g["object"] == q["object"]) && (q["subject"] == null || g["subject"] == q["subject"]) }
                json(200, mapOf("data" to matching, "pagination" to mapOf("total" to matching.size, "nextCursor" to null)))
            }
            route == "/api/v1/access/grants" && method == "POST" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                if (listOf("subject", "relation", "object").any { (b[it] as? String).isNullOrBlank() }) return problem(400, "invalid_grant_shape")
                // SSO-3119 — product-api resolves the SUBJECT in the workspace before it writes the tuple
                // (AccessGrantService.subjectBelongsToWorkspace) and answers the opaque 404 of ADR
                // 2026-09-15 §8 when it cannot. Modelling that is what makes the ordering regression
                // visible here: a grant naming a client the same file has not created yet MUST fail.
                // Only `client:` refs are checked — the fake carries no membership registry, so a
                // `member:` subject is taken on trust.
                val subjectRef = b["subject"].toString()
                if (subjectRef.startsWith("client:") && applications.none { it["clientId"] == subjectRef.removePrefix("client:") }) {
                    return problem(404, "not_found")
                }
                val existing = grants.firstOrNull { it["subject"] == b["subject"] && it["relation"] == b["relation"] && it["object"] == b["object"] }
                if (existing != null) return json(200, existing)
                seedGrant(b["subject"].toString(), b["relation"].toString(), b["object"].toString())
                json(201, grants.last())
            }
            route == "/api/v1/access/grants" && method == "DELETE" -> {
                if (denyGrantWrites) return problem(403, "insufficient_scope")
                grants.removeIf { it["subject"] == b["subject"] && it["relation"] == b["relation"] && it["object"] == b["object"] }
                MockResponse().setResponseCode(204)
            }
            route == "/api/v1/access/mine" && method == "GET" -> {
                if (denyGrantReads) return problem(403, "insufficient_scope")
                val q = query(path)
                json(200, mapOf("data" to mine.filter { q["type"] == null || it.startsWith(q["type"] + ":") }))
            }
            // ── receipt attestation (SSO-2878; the recipe interpreter's best-effort signed layer) ──
            route == "/api/v1/attestations" && method == "POST" ->
                json(200, mapOf("kid" to "receipt-attestation-fake-v1", "signature" to "sig", "canonicalPayload" to "e30", "attestedAt" to "2026-01-01T00:00:00Z"))
            else -> problem(404, "no_route:$method $route")
        }
    }
}
