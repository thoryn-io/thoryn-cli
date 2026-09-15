package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.time.Instant

internal enum class ChangeAction { CREATE, UPDATE, ADOPT, NOOP, REMOVE, SKIP }

/** One row of a plan: what `apply` / `destroy` would do to a resource, why, and (for updates) which fields change. */
internal data class PlannedChange(
    val kind: String,
    val name: String,
    val action: ChangeAction,
    val reason: String,
    val resource: ProvisionResource? = null,
    val owned: OwnedResource? = null,
    /** SSO-3089 — the live id the resource resolved to (owned, or matched by its converge key). */
    val liveId: String? = null,
    /** SSO-3089 — for UPDATE: field → "old → new" (non-secret fields only). */
    val diff: Map<String, String> = emptyMap(),
    /** SSO-3089 — the resource existed before this file managed it (never deleted by destroy/prune). */
    val adopted: Boolean = false,
) {
    fun toStructured(): Map<String, Any?> = buildMap {
        put("kind", kind); put("name", name); put("action", action.name.lowercase()); put("reason", reason)
        liveId?.let { put("id", it) }
        if (diff.isNotEmpty()) put("diff", diff)
        if (adopted) put("adopted", true)
    }
}

internal class ProvisionPlan(val changes: List<PlannedChange>) {
    val creates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.CREATE }
    val updates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.UPDATE }
    val adopts: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.ADOPT }
    val removes: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.REMOVE }
    val hasChanges: Boolean get() = creates.isNotEmpty() || updates.isNotEmpty() || adopts.isNotEmpty() || removes.isNotEmpty()

    /** True when any planned removal targets the workspace's PRODUCTION plane (confirmation-gated). */
    val removesOnProductionPlane: Boolean
        get() = removes.any { it.owned?.let { o -> ProvisionEngine.onProductionPlane(o) } == true }

    fun toStructured(): Map<String, Any?> = mapOf(
        "changes" to changes.map { it.toStructured() },
        "summary" to mapOf(
            "create" to creates.size,
            "update" to updates.size,
            "adopt" to adopts.size,
            "remove" to removes.size,
            "noop" to changes.count { it.action == ChangeAction.NOOP },
            "skip" to changes.count { it.action == ChangeAction.SKIP },
        ),
    )
}

/** The outcome of a destroy / prune pass: what is still owned, and which removals failed. */
internal data class RemovalOutcome(val remaining: ProvisionReceipt, val failures: List<String>)

/**
 * SSO-3088 / SSO-3089 (epic SSO-3087) — the provisioning engine behind `thoryn provision plan | apply | destroy`.
 *
 * **Converge, not create (SSO-3089).** Every declared resource is looked up LIVE by its converge key
 * before any write: an owned resource by its recorded id (a 404 means it was deleted out of band and is
 * re-created); an unowned one by its natural key (environment `slug`, application `displayName` within
 * its environment, user `email`, federation member `displayName`, the per-environment singletons by
 * existence — `loginMethods` (SSO-3100) by its stored allow-list, compared as a set). Found + equal ⇒ `noop`; found + different ⇒ `update` with exactly the changed fields;
 * found but not yet managed ⇒ `adopt` (recorded as owned with `adopted=true` — converged from then on,
 * but NEVER deleted by `destroy`/`--prune`: the CLI only removes what it created); absent ⇒ `create`.
 * A second `apply` therefore issues no writes.
 *
 * **Ownership is the receipt.** `destroy` and `--prune` act only on receipt-recorded, non-adopted ids.
 *
 * **Secrets.** A `spec` key ending in `Env` names the env var carrying a secret; it is resolved at apply
 * time, forwarded to the product API, and NEVER written to the receipt, the plan, or the console. A
 * write-only secret (an SMTP password, a federation client secret) cannot be read back, so it never
 * causes a diff on its own; it is re-sent whenever the resource is created or updated.
 *
 * [clients] yields a tenant-scoped [ProductApiClient] bound to an environment slug (`null` ⇒ the
 * production plane); [persist] is invoked after every successful write so the receipt on disk always
 * reflects reality even when a later step fails.
 */
internal class ProvisionEngine(
    private val clients: (environmentSlug: String?) -> ProductApiClient,
    private val out: PrintStream = System.out,
    private val err: PrintStream = System.err,
    private val env: (String) -> String? = { System.getenv(it) },
    private val cliVersion: String? = null,
    private val now: () -> Instant = { Instant.now() },
) {

    // ── plan ─────────────────────────────────────────────────────────────────────────────────────

    fun plan(file: ProvisionFile, receipt: ProvisionReceipt?, prune: Boolean): ProvisionPlan {
        val ownedByKey = receipt?.resources.orEmpty().associateBy { it.key }
        val changes = mutableListOf<PlannedChange>()
        // Environment slugs known so far (owned / live), so dependants can be probed in the right plane.
        val envSlugs = mutableMapOf<String, String>()
        orderForApply(file.resources).forEach { r ->
            val owned = ownedByKey[r.key]
            val change = probe(r, file, owned, envSlugs)
            changes += change
            if (r.kind == ProvisionFile.KIND_ENVIRONMENT && change.liveId != null) {
                // The RESOLVED slug (a `{{env.NAME}}` placeholder names a per-run sandbox), never the raw spec.
                envSlugs[r.name] = resolveSpec(r, strict = false)["slug"].toString()
            }
        }
        val declared = file.resources.map { it.key }.toSet()
        orderForRemove(receipt?.resources.orEmpty().filter { it.key !in declared }).forEach { o ->
            changes += when {
                !prune -> PlannedChange(o.kind, o.name, ChangeAction.SKIP, "owned but no longer declared — re-run with --prune to remove", owned = o, liveId = o.id)
                o.adopted -> PlannedChange(o.kind, o.name, ChangeAction.SKIP, "adopted (not created by this file) — left in place, dropped from the receipt", owned = o, liveId = o.id, adopted = true)
                !deletable(o.kind) -> PlannedChange(o.kind, o.name, ChangeAction.SKIP, "no delete API for a ${o.kind} singleton — left in place, dropped from the receipt", owned = o, liveId = o.id)
                else -> PlannedChange(o.kind, o.name, ChangeAction.REMOVE, "owned but no longer declared (--prune)", owned = o, liveId = o.id)
            }
        }
        return ProvisionPlan(changes)
    }

    /** Live lookup by converge key → create / update / adopt / noop for one declared resource. */
    private fun probe(r: ProvisionResource, file: ProvisionFile, owned: OwnedResource?, envSlugs: Map<String, String>): PlannedChange {
        val slug: String? = when {
            r.kind == ProvisionFile.KIND_ENVIRONMENT -> null
            r.environment == null -> null
            file.environmentResource(r.environment) == null -> r.environment
            else -> envSlugs[r.environment]
                ?: return PlannedChange(r.kind, r.name, ChangeAction.CREATE, "environment '${r.environment}' will be created first", resource = r)
        }
        val desired = resolveSpec(r, strict = false)
        val live = try {
            lookup(r, owned, slug, desired)
        } catch (ex: ProductApiException) {
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        return when {
            live == null && owned != null -> PlannedChange(r.kind, r.name, ChangeAction.CREATE, "owned id ${owned.id} no longer exists — will be re-created", resource = r, owned = owned)
            live == null -> PlannedChange(r.kind, r.name, ChangeAction.CREATE, "not found by its converge key", resource = r)
            live.diff.isNotEmpty() -> PlannedChange(
                r.kind, r.name, ChangeAction.UPDATE,
                if (owned == null) "exists (adopting) — ${live.diff.size} field(s) differ" else "${live.diff.size} field(s) differ",
                resource = r, owned = owned, liveId = live.id, diff = live.diff, adopted = owned?.adopted ?: true,
            )
            owned == null -> PlannedChange(r.kind, r.name, ChangeAction.ADOPT, "exists and matches — adopted under management (never deleted by destroy)", resource = r, liveId = live.id, adopted = true)
            else -> PlannedChange(r.kind, r.name, ChangeAction.NOOP, "owned (id ${live.id}) and matches", resource = r, owned = owned, liveId = live.id, adopted = owned.adopted)
        }
    }

    // ── apply ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Execute [plan]: creates / updates / adopts in dependency order (environments first), then prunes.
     * [confirmSlug] is the workspace slug confirming production-plane removals (refused up front when
     * missing). Returns the receipt as it stands after the pass; throws on the first failed step (with
     * everything before it already persisted).
     */
    fun apply(
        file: ProvisionFile,
        receipt: ProvisionReceipt?,
        plan: ProvisionPlan,
        workspace: String?,
        confirmSlug: String?,
        persist: (ProvisionReceipt) -> Unit,
    ): ProvisionReceipt {
        if (plan.removesOnProductionPlane && confirmSlug.isNullOrBlank()) {
            throw ProvisionException("--prune would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
        }
        val owned = receipt?.resources.orEmpty().toMutableList()
        fun current() = ProvisionReceipt(
            file = ProvisionFileRef(file.source, file.digest),
            appliedAt = now().toString(),
            cliVersion = cliVersion,
            workspace = workspace ?: receipt?.workspace,
            resources = owned.toList(),
        )
        fun record(o: OwnedResource) {
            // Replace IN PLACE so the receipt keeps creation order (destroy removes child-first by it).
            val i = owned.indexOfFirst { it.key == o.key }
            if (i >= 0) owned[i] = o else owned += o
            persist(current())
        }
        plan.changes.filter { it.resource != null }.forEach { change ->
            val r = change.resource!!
            when (change.action) {
                ChangeAction.CREATE -> record(create(r, file, owned))
                ChangeAction.UPDATE -> record(update(r, file, owned, change))
                ChangeAction.ADOPT -> record(adopt(r, file, owned, change))
                else -> Unit
            }
        }
        // Prune: drop skipped entries from the receipt, remove the rest child-first.
        plan.changes.filter { it.action == ChangeAction.SKIP && it.owned != null && (it.owned.adopted || !deletable(it.owned.kind)) }.forEach { change ->
            owned.removeIf { it.key == change.owned!!.key }
            persist(current())
        }
        plan.removes.forEach { change ->
            val o = change.owned ?: return@forEach
            remove(o, confirmSlug)
            owned.removeIf { it.key == o.key }
            persist(current())
        }
        val result = current()
        persist(result)
        return result
    }

    // ── destroy ──────────────────────────────────────────────────────────────────────────────────

    /**
     * Remove every owned resource this file CREATED, child-first (environments last); adopted resources
     * and singletons without a delete API are left in place and dropped from the receipt. Best-effort: a
     * failed removal is reported and kept for a retry. Refuses up front when a production-plane removal
     * lacks [confirmSlug].
     */
    fun destroy(receipt: ProvisionReceipt, confirmSlug: String?, persist: (ProvisionReceipt) -> Unit): RemovalOutcome {
        val targets = orderForRemove(receipt.resources)
        if (targets.any { removable(it) && onProductionPlane(it) } && confirmSlug.isNullOrBlank()) {
            throw ProvisionException("destroy would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
        }
        val owned = receipt.resources.toMutableList()
        val failures = mutableListOf<String>()
        fun current() = receipt.copy(appliedAt = now().toString(), resources = owned.toList())
        targets.forEach { o ->
            if (!removable(o)) {
                val why = if (o.adopted) "adopted, not created by this file" else "no delete API for this singleton"
                out.println("  ${o.kind} ${o.name}: $why — left in place, dropped from the receipt")
                owned.removeIf { it.key == o.key }
                persist(current())
                return@forEach
            }
            try {
                remove(o, confirmSlug)
                owned.removeIf { it.key == o.key }
                persist(current())
            } catch (ex: Exception) {
                failures += "${o.key} (id ${o.id}): ${ex.message}"
                err.println("  ! ${o.kind} ${o.name} could not be removed (${ex.message}); kept in the receipt for a retry.")
            }
        }
        val remaining = current()
        persist(remaining)
        return RemovalOutcome(remaining, failures)
    }

    // ── live lookup per kind (SSO-3089) ──────────────────────────────────────────────────────────

    /** What exists live for a declared resource: its id and the non-secret fields that differ from [desired]. */
    private class Live(val id: String, val diff: Map<String, String>, val attributes: Map<String, String> = emptyMap())

    private fun lookup(r: ProvisionResource, owned: OwnedResource?, slug: String?, desired: Map<String, Any?>): Live? = when (r.kind) {
        ProvisionFile.KIND_ENVIRONMENT -> {
            val wanted = desired["slug"].toString()
            val node = listItems(clients(null).listEnvironments(), "environments").firstOrNull { it.str("slug") == wanted }
            node?.let { n ->
                val diff = diffOf(mapOf("displayName" to desired["displayName"]), mapOf("displayName" to n.str("name")))
                Live(n.str("id") ?: wanted, diff, mapOf("slug" to wanted))
            }
        }
        ProvisionFile.KIND_APPLICATION -> {
            val client = clients(slug)
            // SSO-3104 — a spec with a fixed `clientId` (the CLI's own `cli` login client) is adopted by that
            // id, so a re-apply from a receipt that does not own it (CI) converges it instead of creating a
            // duplicate by display name.
            val fixedId = desired["clientId"]?.toString()?.takeIf { it.isNotBlank() }
            val node = owned?.let { fetchOrNull { client.getApplication(it.id) } }
                ?: fixedId?.let { fetchOrNull { client.getApplication(it) } }
                ?: listItems(client.listApplications(), "data").filter { it.str("displayName") == desired["displayName"] }.singleOrNull()
            node?.let { n ->
                val fields = listOf("displayName", "redirectUris", "postLogoutRedirectUris", "scopes", "grantTypes")
                Live(n.str("clientId") ?: n.str("client_id") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)))
            }
        }
        ProvisionFile.KIND_USER -> {
            val client = clients(slug)
            val email = desired["email"].toString()
            val node = owned?.let { fetchOrNull { client.getUser(it.id) } }
                ?: listItems(client.listUsers(email = email), "items").firstOrNull { it.str("email").equals(email, ignoreCase = true) }
            node?.let { n ->
                val fields = listOf("emailVerified")
                Live(n.str("id") ?: n.str("userId") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)))
            }
        }
        ProvisionFile.KIND_FEDERATION_MEMBER -> {
            val client = clients(slug)
            val node = owned?.let { fetchOrNull { client.getFederationMember(it.id) } }
                ?: desired["displayName"]?.let { dn -> listItems(client.listFederationMembers(), "data").filter { it.str("displayName") == dn }.singleOrNull() }
            node?.let { n ->
                val fields = listOf("displayName", "discoveryUrl", "clientId")
                Live(n.str("memberId") ?: n.str("id") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)))
            }
        }
        ProvisionFile.KIND_EMAIL_PROVIDER -> {
            val n = clients(slug).getEmailProvider()
            if (n["configured"]?.asBoolean() == false && owned == null) null
            else {
                val fields = listOf("smtpHost", "smtpPort", "smtpUsername", "transportSecurity", "fromAddress", "fromName", "replyTo", "enabled")
                Live(n.str("providerType") ?: "email-provider", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)))
            }
        }
        ProvisionFile.KIND_LOGIN_THEME -> {
            val stored = clients(slug).getLoginBranding()["stored"]
            val fields = listOf("logoUrl", "primaryColor", "backgroundColor", "borderRadiusPx", "theme", "cssVariables")
            val live = stored?.toMap(fields).orEmpty()
            if (owned == null && live.values.all { it == null }) null
            else Live("login-theme", diffOf(desired.filterKeys { it in fields }, live))
        }
        ProvisionFile.KIND_LOGIN_FLOW -> {
            val active = fetchOrNull { clients(slug).getActiveLoginFlow() }
            val version = active?.get("version")?.takeIf { !it.isNull }?.asInt()?.toString()
            when {
                owned == null -> null // a template can't be recognised from the active flow; applying it mints a version
                version == owned.id -> Live(version, emptyMap())
                else -> Live(version ?: "", mapOf("activeVersion" to "${version ?: "(none)"} → re-apply template ${desired["templateId"]}"))
            }
        }
        ProvisionFile.KIND_LOGIN_METHODS -> {
            // SSO-3100 — the stored allow-list (null ⇒ the platform default policy, nothing to converge
            // against unless already owned). Compared as a SET: order is display-only.
            val stored = clients(slug).getLoginMethods()["stored"]?.takeIf { !it.isNull && it.isArray }
            val wanted = (desired["methods"] as? List<*>)?.map { it.toString().trim().lowercase() }
            if (stored == null && owned == null) null
            else Live("login-methods", diffOf(mapOf("methods" to wanted), mapOf("methods" to stored?.let { plain(it) })))
        }
        else -> null
    }

    // ── per-kind create / update / adopt ─────────────────────────────────────────────────────────

    private fun create(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>): OwnedResource {
        val spec = resolveSpec(r, strict = true)
        return when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                val slug = spec["slug"].toString()
                val body = mapOf("slug" to slug, "name" to (spec["displayName"]?.toString()?.takeIf { it.isNotBlank() } ?: slug))
                val resp = clients(null).createEnvironment(body)
                val id = resp.str("id") ?: throw ProvisionException("${r.key}: the environment create returned no id")
                val liveSlug = resp.str("slug") ?: slug
                out.println("  + environment ${r.name}: id=$id slug=$liveSlug")
                OwnedResource(r.kind, r.name, id, environment = null, attributes = mapOf("slug" to liveSlug))
            }
            ProvisionFile.KIND_APPLICATION -> {
                val slug = targetSlug(r, file, owned)
                val resp = clients(slug).createApplication(spec)
                val id = resp.str("clientId") ?: resp.str("client_id") ?: throw ProvisionException("${r.key}: the application create returned no clientId")
                out.println("  + application ${r.name}: clientId=$id${slug?.let { " env=$it" } ?: ""}")
                OwnedResource(r.kind, r.name, id, slug, buildMap {
                    (spec["redirectUris"] as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) }
                })
            }
            ProvisionFile.KIND_USER -> {
                val slug = targetSlug(r, file, owned)
                val resp = clients(slug).createUser(spec)
                val id = resp.str("id") ?: resp.str("userId") ?: throw ProvisionException("${r.key}: the user create returned no id")
                val email = resp.str("email") ?: spec["email"]?.toString()
                out.println("  + user ${r.name}: id=$id${email?.let { " email=$it" } ?: ""}")
                OwnedResource(r.kind, r.name, id, slug, buildMap { email?.let { put("email", it) } })
            }
            ProvisionFile.KIND_FEDERATION_MEMBER -> {
                val slug = targetSlug(r, file, owned)
                val resp = clients(slug).createFederationMember(spec)
                val id = resp.str("memberId") ?: resp.str("id") ?: throw ProvisionException("${r.key}: the federation-member create returned no id")
                out.println("  + federationMember ${r.name}: id=$id")
                OwnedResource(r.kind, r.name, id, slug, buildMap { spec["providerType"]?.toString()?.let { put("providerType", it) } })
            }
            ProvisionFile.KIND_EMAIL_PROVIDER -> putEmailProvider(r, targetSlug(r, file, owned), spec, "+")
            ProvisionFile.KIND_LOGIN_THEME -> putLoginTheme(r, targetSlug(r, file, owned), spec, "+")
            ProvisionFile.KIND_LOGIN_FLOW -> applyLoginFlow(r, targetSlug(r, file, owned), spec, "+")
            ProvisionFile.KIND_LOGIN_METHODS -> putLoginMethods(r, targetSlug(r, file, owned), spec, "+")
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        }
    }

    /** Converge an existing resource: send exactly the changed (non-secret) fields plus any write-only secret. */
    private fun update(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>, change: PlannedChange): OwnedResource {
        val spec = resolveSpec(r, strict = true)
        val id = change.liveId ?: throw ProvisionException("${r.key}: update planned without a live id")
        val changed = spec.filterKeys { it in change.diff.keys }
        val slug = if (r.kind == ProvisionFile.KIND_ENVIRONMENT) null else targetSlug(r, file, owned)
        val base = OwnedResource(r.kind, r.name, id, slug, adopted = change.adopted)
        return when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                clients(null).renameEnvironment(id, mapOf("name" to spec["displayName"].toString()))
                out.println("  ~ environment ${r.name}: renamed (id $id)")
                base.copy(attributes = mapOf("slug" to spec["slug"].toString()))
            }
            ProvisionFile.KIND_APPLICATION -> {
                clients(slug).updateApplication(id, changed)
                out.println("  ~ application ${r.name}: updated ${change.diff.keys} (clientId $id)")
                base.copy(attributes = buildMap { (spec["redirectUris"] as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) } })
            }
            ProvisionFile.KIND_USER -> {
                clients(slug).updateUser(id, changed)
                out.println("  ~ user ${r.name}: updated ${change.diff.keys} (id $id)")
                base.copy(attributes = buildMap { spec["email"]?.toString()?.let { put("email", it) } })
            }
            ProvisionFile.KIND_FEDERATION_MEMBER -> {
                // A write-only client secret can never diff; re-send it with any update.
                val body = changed + spec.filterKeys { it == "clientSecret" }
                clients(slug).updateFederationMember(id, body)
                out.println("  ~ federationMember ${r.name}: updated ${change.diff.keys} (id $id)")
                base.copy(attributes = buildMap { spec["providerType"]?.toString()?.let { put("providerType", it) } })
            }
            ProvisionFile.KIND_EMAIL_PROVIDER -> putEmailProvider(r, slug, spec, "~").copy(adopted = change.adopted)
            ProvisionFile.KIND_LOGIN_THEME -> putLoginTheme(r, slug, spec, "~").copy(adopted = change.adopted)
            ProvisionFile.KIND_LOGIN_FLOW -> applyLoginFlow(r, slug, spec, "~").copy(adopted = change.adopted)
            ProvisionFile.KIND_LOGIN_METHODS -> putLoginMethods(r, slug, spec, "~").copy(adopted = change.adopted)
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        }
    }

    /** Take an existing, matching resource under management without writing anything. */
    private fun adopt(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>, change: PlannedChange): OwnedResource {
        val id = change.liveId ?: throw ProvisionException("${r.key}: adopt planned without a live id")
        val slug = if (r.kind == ProvisionFile.KIND_ENVIRONMENT) null else targetSlug(r, file, owned)
        out.println("  = ${r.kind} ${r.name}: adopted (id $id) — will be converged, never deleted by destroy")
        val resolved = resolveSpec(r, strict = true)
        val attributes = when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> mapOf("slug" to resolved["slug"].toString())
            ProvisionFile.KIND_USER -> mapOf("email" to resolved["email"].toString())
            else -> emptyMap()
        }
        return OwnedResource(r.kind, r.name, id, slug, attributes, adopted = true)
    }

    private fun putEmailProvider(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): OwnedResource {
        val body = linkedMapOf<String, Any?>()
        spec["smtpHost"].nonBlank()?.let { body["smtpHost"] = it }
        spec["providerType"].nonBlank()?.let { body["providerType"] = it }
        spec["smtpPort"]?.let { coerceInt(it)?.let { p -> body["smtpPort"] = p } }
        spec["smtpUsername"].nonBlank()?.let { body["smtpUsername"] = it }
        spec["smtpPassword"]?.toString()?.takeIf { it.isNotEmpty() }?.let { body["smtpPassword"] = it }
        spec["transportSecurity"].nonBlank()?.let { body["transportSecurity"] = it }
        spec["allowInsecureTransport"]?.let { body["allowInsecureTransport"] = coerceBool(it) }
        spec["fromAddress"].nonBlank()?.let { body["fromAddress"] = it }
        spec["fromName"].nonBlank()?.let { body["fromName"] = it }
        spec["replyTo"].nonBlank()?.let { body["replyTo"] = it }
        body["enabled"] = spec["enabled"]?.let { coerceBool(it) } ?: true
        val resp = clients(slug).putEmailProvider(body)
        val id = resp.str("providerType") ?: "email-provider"
        out.println("  $mark emailProvider: type=$id host=${body["smtpHost"]}")
        // NEVER the password — only the non-secret provider shape.
        return OwnedResource(r.kind, r.name, id, slug, buildMap {
            resp.str("smtpHost")?.let { put("smtpHost", it) }
            resp.str("fromAddress")?.let { put("fromAddress", it) }
            resp.str("configVersion")?.let { put("configVersion", it) }
        })
    }

    private fun putLoginTheme(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): OwnedResource {
        val body = linkedMapOf<String, Any?>()
        listOf("logoUrl", "primaryColor", "backgroundColor", "theme").forEach { k -> spec[k].nonBlank()?.let { body[k] = it } }
        spec["borderRadiusPx"]?.let { coerceInt(it)?.let { px -> body["borderRadiusPx"] = px } }
        (spec["cssVariables"] as? Map<*, *>)?.let { raw ->
            val css = raw.entries.mapNotNull { (k, v) ->
                val key = k?.toString()?.trim()?.takeIf { it.isNotEmpty() }
                val value = v?.toString()?.trim()?.takeIf { it.isNotEmpty() }
                if (key != null && value != null) key to value else null
            }.toMap()
            if (css.isNotEmpty()) body["cssVariables"] = css
        }
        val resp = clients(slug).putLoginBranding(body)
        val effective = resp["effective"]
        out.println("  $mark loginTheme: theme=${effective?.str("theme") ?: "(default)"}")
        return OwnedResource(r.kind, r.name, "login-theme", slug, buildMap {
            effective?.str("theme")?.let { put("theme", it) }
            effective?.str("primaryColor")?.let { put("primaryColor", it) }
        })
    }

    private fun applyLoginFlow(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): OwnedResource {
        val client = clients(slug)
        val templateId = spec["templateId"].toString()
        val draft = client.applyLoginFlowTemplate(templateId)
        val version = draft["version"]?.takeIf { !it.isNull }?.asInt()
            ?: throw ProvisionException("${r.key}: the login-flow template apply returned no version")
        val activate = spec["activate"]?.let { coerceBool(it) } ?: true
        if (activate) client.activateLoginFlow(version)
        out.println("  $mark loginFlow: template=$templateId version=$version${if (activate) " (active)" else " (draft)"}")
        return OwnedResource(r.kind, r.name, version.toString(), slug, mapOf("templateId" to templateId, "activated" to activate.toString()))
    }

    /**
     * SSO-3100 — PUT the FULL sign-in method allow-list (`thoryn login-methods set`): replace, not merge.
     * Tokens are normalised (trimmed, lower-cased); the server rejects an unknown or empty list.
     */
    private fun putLoginMethods(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): OwnedResource {
        val methods = (spec["methods"] as? List<*>).orEmpty().mapNotNull { it?.toString()?.trim()?.lowercase()?.takeIf { m -> m.isNotEmpty() } }.distinct()
        if (methods.isEmpty()) throw ProvisionException("${r.key}: spec.methods must list at least one sign-in method")
        val resp = clients(slug).putLoginMethods(methods)
        val stored = resp["stored"]?.takeIf { !it.isNull && it.isArray }?.toList()?.map { it.asString() } ?: methods
        out.println("  $mark loginMethods: ${stored.joinToString(", ")}")
        return OwnedResource(r.kind, r.name, "login-methods", slug, mapOf("methods" to stored.joinToString(",")))
    }

    // ── per-kind remove ──────────────────────────────────────────────────────────────────────────

    private fun remove(o: OwnedResource, confirmSlug: String?) {
        when (o.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                // A sandbox hard-delete is confirmed by the environment's OWN slug (SSO-2960 contract).
                clients(null).deleteEnvironment(o.id, o.attributes["slug"])
                out.println("  - environment ${o.name}: hard-deleted (id ${o.id})")
            }
            ProvisionFile.KIND_APPLICATION -> {
                clients(o.environment).deleteApplication(o.id, confirmSlug)
                out.println("  - application ${o.name}: deleted (clientId ${o.id})")
            }
            ProvisionFile.KIND_USER -> {
                clients(o.environment).deleteUser(o.id, confirmSlug)
                out.println("  - user ${o.name}: deleted (id ${o.id})")
            }
            ProvisionFile.KIND_FEDERATION_MEMBER -> {
                clients(o.environment).deleteFederationMember(o.id, confirmSlug)
                out.println("  - federationMember ${o.name}: detached (id ${o.id})")
            }
            ProvisionFile.KIND_EMAIL_PROVIDER -> {
                clients(o.environment).deleteEmailProvider(confirmSlug)
                out.println("  - emailProvider: reset to the platform sender")
            }
            ProvisionFile.KIND_LOGIN_METHODS -> {
                // SSO-3100 — the delete path IS a reset: back to the default (every method offered).
                clients(o.environment).resetLoginMethods()
                out.println("  - loginMethods: reset to the default (every method offered)")
            }
            else -> throw ProvisionException("${o.key}: no delete API for kind '${o.kind}'")
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    /** Environments first (file order), then everything else (file order): dependants after their env. */
    private fun orderForApply(resources: List<ProvisionResource>): List<ProvisionResource> =
        resources.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT } + resources.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT }

    /** Child-first: everything in reverse order, environments last (their hard-delete cascades). */
    private fun orderForRemove(owned: List<OwnedResource>): List<OwnedResource> =
        owned.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT }.reversed() + owned.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT }.reversed()

    /** The slug a resource targets: an env resource of this file (must already be owned), an existing slug, or null. */
    private fun targetSlug(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>): String? {
        val ref = r.environment ?: return null
        if (file.environmentResource(ref) == null) return ref
        return owned.firstOrNull { it.kind == ProvisionFile.KIND_ENVIRONMENT && it.name == ref }?.attributes?.get("slug")
            ?: throw ProvisionException("${r.key} targets environment '$ref', declared in this file but not provisioned")
    }

    /**
     * Resolve the spec: a `<key>Env` entry becomes `<key>` with the env var's value, and `{{env.NAME}}`
     * placeholders are substituted. [strict] (apply) fails closed on an unset var — never a silent blank
     * credential; lenient (plan) skips `<key>Env` entries (write-only secrets never diff) and leaves an
     * unset placeholder literal. The resolved map is forwarded and discarded — never persisted.
     */
    private fun resolveSpec(r: ProvisionResource, strict: Boolean): Map<String, Any?> {
        val resolved = LinkedHashMap<String, Any?>()
        r.spec.forEach { (k, v) ->
            if (k.endsWith("Env") && k.length > 3 && v is String) {
                if (!strict) return@forEach
                val varName = v.trim()
                if (!ENV_NAME_PATTERN.matches(varName)) throw ProvisionException("${r.key}: spec.$k must name an env var (was '$v')")
                val value = env(varName)?.takeIf { it.isNotEmpty() }
                    ?: throw ProvisionException("${r.key}: spec.$k names env var '$varName', which is not set")
                resolved[k.removeSuffix("Env")] = value
            } else {
                resolved[k] = substituteDeep(v, r, strict)
            }
        }
        return resolved
    }

    private fun substituteDeep(value: Any?, r: ProvisionResource, strict: Boolean): Any? = when (value) {
        is String -> ENV_PLACEHOLDER.replace(value) { m ->
            val varName = m.groupValues[1]
            env(varName)?.takeIf { it.isNotEmpty() }
                ?: if (strict) throw ProvisionException("${r.key}: '{{env.$varName}}' references env var '$varName', which is not set") else m.value
        }
        is Map<*, *> -> value.entries.associate { (k, v) -> k.toString() to substituteDeep(v, r, strict) }
        is List<*> -> value.map { substituteDeep(it, r, strict) }
        else -> value
    }

    /** Fields of [desired] whose normalised value differs from [live] (lists compare as sets; numbers/booleans as text). */
    private fun diffOf(desired: Map<String, Any?>, live: Map<String, Any?>): Map<String, String> {
        val diff = LinkedHashMap<String, String>()
        desired.forEach { (field, want) ->
            if (want == null) return@forEach
            val have = live[field]
            if (norm(want) != norm(have)) diff[field] = "${render(have)} → ${render(want)}"
        }
        return diff
    }

    private fun norm(v: Any?): Any? = when (v) {
        null -> null
        is List<*> -> v.map { norm(it) }.toSet()
        is Map<*, *> -> v.entries.associate { (k, x) -> k.toString() to norm(x) }
        is Boolean, is Number -> v.toString()
        else -> v.toString().trim()
    }

    private fun render(v: Any?): String = when (v) {
        null -> "(unset)"
        is List<*> -> v.joinToString(",", "[", "]")
        is Map<*, *> -> v.entries.joinToString(",", "{", "}") { "${it.key}=${it.value}" }
        else -> v.toString()
    }

    /** A record's fields as a plain map (arrays → lists, objects → maps, scalars → text/bool/number). */
    private fun JsonNode.toMap(fields: List<String>): Map<String, Any?> = fields.associateWith { f -> this[f]?.let { plain(it) } }

    private fun plain(n: JsonNode): Any? = when {
        n.isNull -> null
        n.isArray -> n.toList().map { plain(it) }
        n.isObject -> n.properties().associate { it.key to plain(it.value) }
        n.isBoolean -> n.asBoolean()
        n.isNumber -> n.numberValue()
        else -> n.asString()
    }

    /** A list envelope's items: the [preferred] key, any of the known envelope keys, or a bare array. */
    private fun listItems(node: JsonNode, preferred: String): List<JsonNode> {
        if (node.isArray) return node.toList()
        val key = listOf(preferred, "data", "items", "environments", "members", "users", "applications").firstOrNull { node[it]?.isArray == true }
        return key?.let { node[it].toList() }.orEmpty()
    }

    /** A GET that treats 404 (deleted out of band / cross-tenant) as "absent". */
    private fun fetchOrNull(call: () -> JsonNode): JsonNode? = try {
        call()
    } catch (ex: ProductApiException) {
        if (ex.httpStatus == 404) null else throw ex
    }

    private fun JsonNode.str(field: String): String? =
        this[field]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() }

    private fun Any?.nonBlank(): String? = this?.toString()?.trim()?.takeIf { it.isNotEmpty() }

    private fun coerceBool(v: Any?): Boolean = when (v) {
        is Boolean -> v
        else -> v?.toString()?.trim().equals("true", ignoreCase = true)
    }

    private fun coerceInt(v: Any?): Int? = when (v) {
        is Number -> v.toInt()
        else -> v?.toString()?.trim()?.toIntOrNull()
    }

    companion object {
        val ENV_NAME_PATTERN = Regex("^[A-Za-z_][A-Za-z0-9_]*$")
        val ENV_PLACEHOLDER = Regex("""\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*}}""")

        /** Kinds the customer plane can delete; `loginTheme` / `loginFlow` have no delete surface (`loginMethods` resets via DELETE, SSO-3100). */
        fun deletable(kind: String): Boolean = kind !in setOf(ProvisionFile.KIND_LOGIN_THEME, ProvisionFile.KIND_LOGIN_FLOW)

        /** Owned, created by this file (not adopted), and of a deletable kind. */
        fun removable(o: OwnedResource): Boolean = !o.adopted && deletable(o.kind)

        /** An owned non-environment resource with no sandbox slug lives on the production plane. */
        fun onProductionPlane(o: OwnedResource): Boolean =
            o.kind != ProvisionFile.KIND_ENVIRONMENT &&
                (o.environment.isNullOrBlank() || o.environment == ThorynConfig.PRODUCTION_ENV_SLUG)
    }
}
