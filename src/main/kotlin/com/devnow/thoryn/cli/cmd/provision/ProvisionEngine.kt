package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.config.ThorynConfig
import java.io.PrintStream
import java.time.Instant

internal enum class ChangeAction { CREATE, NOOP, REMOVE, SKIP }

/** One row of a plan: what `apply` / `destroy` would do to a resource, and why. */
internal data class PlannedChange(
    val kind: String,
    val name: String,
    val action: ChangeAction,
    val reason: String,
    val resource: ProvisionResource? = null,
    val owned: OwnedResource? = null,
) {
    fun toStructured(): Map<String, Any?> = mapOf("kind" to kind, "name" to name, "action" to action.name.lowercase(), "reason" to reason)
}

internal class ProvisionPlan(val changes: List<PlannedChange>) {
    val creates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.CREATE }
    val removes: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.REMOVE }
    val hasChanges: Boolean get() = creates.isNotEmpty() || removes.isNotEmpty()

    /** True when any planned removal targets the workspace's PRODUCTION plane (confirmation-gated). */
    val removesOnProductionPlane: Boolean
        get() = removes.any { it.owned?.let { o -> ProvisionEngine.onProductionPlane(o) } == true }

    fun toStructured(): Map<String, Any?> = mapOf(
        "changes" to changes.map { it.toStructured() },
        "summary" to mapOf(
            "create" to creates.size,
            "remove" to removes.size,
            "noop" to changes.count { it.action == ChangeAction.NOOP },
            "skip" to changes.count { it.action == ChangeAction.SKIP },
        ),
    )
}

/** The outcome of a destroy / prune pass: what is still owned, and which removals failed. */
internal data class RemovalOutcome(val remaining: ProvisionReceipt, val failures: List<String>)

/**
 * SSO-3088 (epic SSO-3087) — the provisioning engine behind `thoryn provision plan | apply | destroy`.
 *
 * **Ownership is the receipt.** A resource declared in the file and recorded in the receipt is OWNED:
 * `apply` leaves it alone (a second `apply` issues no writes), `destroy` removes it, and `--prune`
 * removes owned resources the file no longer declares. A resource the receipt does not record is
 * never touched — the CLI cannot delete what it did not create through this file. (Live
 * read-by-key drift detection — an owned resource whose spec changed → `update` — is SSO-3089.)
 *
 * **Secrets.** A `spec` key ending in `Env` names the env var carrying a secret; it is resolved here at
 * apply time, forwarded to the product API, and NEVER written to the receipt or printed.
 *
 * [clients] yields a tenant-scoped [ProductApiClient] bound to an environment slug (`null` ⇒ the
 * production plane); [persist] is invoked after every successful create/remove so the receipt on disk
 * always reflects reality even when a later step fails.
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
        val owned = receipt?.resources.orEmpty().associateBy { it.key }
        val changes = mutableListOf<PlannedChange>()
        orderForApply(file.resources).forEach { r ->
            val existing = owned[r.key]
            changes += if (existing == null) {
                PlannedChange(r.kind, r.name, ChangeAction.CREATE, "not yet provisioned by this file", resource = r)
            } else {
                PlannedChange(r.kind, r.name, ChangeAction.NOOP, "owned (id ${existing.id})", resource = r, owned = existing)
            }
        }
        val declared = file.resources.map { it.key }.toSet()
        orderForRemove(receipt?.resources.orEmpty().filter { it.key !in declared }).forEach { o ->
            changes += when {
                !prune -> PlannedChange(o.kind, o.name, ChangeAction.SKIP, "owned but no longer declared — re-run with --prune to remove", owned = o)
                !deletable(o.kind) -> PlannedChange(o.kind, o.name, ChangeAction.SKIP, "no delete API for a $o.kind singleton — left in place, dropped from the receipt", owned = o)
                else -> PlannedChange(o.kind, o.name, ChangeAction.REMOVE, "owned but no longer declared (--prune)", owned = o)
            }
        }
        return ProvisionPlan(changes)
    }

    // ── apply ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Execute [plan]: creates in dependency order (environments first), then prunes. [confirmSlug] is
     * the workspace slug confirming production-plane removals (refused up front when missing).
     * Returns the receipt as it stands after the pass; throws [ProvisionException] / the API
     * exception on the first failed step (with everything before it already persisted).
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
        var owned = receipt?.resources.orEmpty().toMutableList()
        fun current() = ProvisionReceipt(
            file = ProvisionFileRef(file.source, file.digest),
            appliedAt = now().toString(),
            cliVersion = cliVersion,
            workspace = workspace ?: receipt?.workspace,
            resources = owned.toList(),
        )
        plan.creates.forEach { change ->
            val r = change.resource ?: return@forEach
            val created = create(r, file, owned)
            owned += created
            persist(current())
        }
        // Prune: drop skipped singletons from the receipt, remove the rest child-first.
        plan.changes.filter { it.action == ChangeAction.SKIP && it.owned != null && !deletable(it.owned.kind) }.forEach { change ->
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
     * Remove EVERY owned resource, child-first (environments last). Best-effort: a failed removal is
     * reported and kept in the receipt so a re-run retries it. Refuses up front when a production-plane
     * removal lacks [confirmSlug].
     */
    fun destroy(receipt: ProvisionReceipt, confirmSlug: String?, persist: (ProvisionReceipt) -> Unit): RemovalOutcome {
        val targets = orderForRemove(receipt.resources)
        if (targets.any { deletable(it.kind) && onProductionPlane(it) } && confirmSlug.isNullOrBlank()) {
            throw ProvisionException(
                "destroy would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.",
            )
        }
        val owned = receipt.resources.toMutableList()
        val failures = mutableListOf<String>()
        fun current() = receipt.copy(appliedAt = now().toString(), resources = owned.toList())
        targets.forEach { o ->
            if (!deletable(o.kind)) {
                out.println("  ${o.kind} ${o.name}: no delete API for this singleton — left in place, dropped from the receipt")
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

    // ── per-kind create ──────────────────────────────────────────────────────────────────────────

    private fun create(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>): OwnedResource {
        val spec = resolveSpec(r)
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
            ProvisionFile.KIND_EMAIL_PROVIDER -> {
                val slug = targetSlug(r, file, owned)
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
                out.println("  + emailProvider: type=$id host=${body["smtpHost"]}")
                // NEVER the password — only the non-secret provider shape.
                OwnedResource(r.kind, r.name, id, slug, buildMap {
                    resp.str("smtpHost")?.let { put("smtpHost", it) }
                    resp.str("fromAddress")?.let { put("fromAddress", it) }
                    resp.str("configVersion")?.let { put("configVersion", it) }
                })
            }
            ProvisionFile.KIND_LOGIN_THEME -> {
                val slug = targetSlug(r, file, owned)
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
                out.println("  + loginTheme: theme=${effective?.str("theme") ?: "(default)"}")
                OwnedResource(r.kind, r.name, "login-theme", slug, buildMap {
                    effective?.str("theme")?.let { put("theme", it) }
                    effective?.str("primaryColor")?.let { put("primaryColor", it) }
                })
            }
            ProvisionFile.KIND_LOGIN_FLOW -> {
                val slug = targetSlug(r, file, owned)
                val client = clients(slug)
                val templateId = spec["templateId"].toString()
                val draft = client.applyLoginFlowTemplate(templateId)
                val version = draft["version"]?.takeIf { !it.isNull }?.asInt()
                    ?: throw ProvisionException("${r.key}: the login-flow template apply returned no version")
                val activate = spec["activate"]?.let { coerceBool(it) } ?: true
                if (activate) client.activateLoginFlow(version)
                out.println("  + loginFlow: template=$templateId version=$version${if (activate) " (active)" else " (draft)"}")
                OwnedResource(r.kind, r.name, version.toString(), slug, mapOf("templateId" to templateId, "activated" to activate.toString()))
            }
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        }
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
     * Resolve the spec for the API: a `<key>Env` entry becomes `<key>` with the env var's value (fails
     * closed when unset — never a silent blank credential); `{{env.NAME}}` placeholders in strings are
     * substituted. The resolved map is forwarded and discarded — never persisted.
     */
    private fun resolveSpec(r: ProvisionResource): Map<String, Any?> {
        val resolved = LinkedHashMap<String, Any?>()
        r.spec.forEach { (k, v) ->
            if (k.endsWith("Env") && k.length > 3 && v is String) {
                val varName = v.trim()
                if (!ENV_NAME_PATTERN.matches(varName)) throw ProvisionException("${r.key}: spec.$k must name an env var (was '$v')")
                val value = env(varName)?.takeIf { it.isNotEmpty() }
                    ?: throw ProvisionException("${r.key}: spec.$k names env var '$varName', which is not set")
                resolved[k.removeSuffix("Env")] = value
            } else {
                resolved[k] = substituteDeep(v, r)
            }
        }
        return resolved
    }

    private fun substituteDeep(value: Any?, r: ProvisionResource): Any? = when (value) {
        is String -> ENV_PLACEHOLDER.replace(value) { m ->
            val varName = m.groupValues[1]
            env(varName)?.takeIf { it.isNotEmpty() } ?: throw ProvisionException("${r.key}: '{{env.$varName}}' references env var '$varName', which is not set")
        }
        is Map<*, *> -> value.entries.associate { (k, v) -> k.toString() to substituteDeep(v, r) }
        is List<*> -> value.map { substituteDeep(it, r) }
        else -> value
    }

    private fun tools.jackson.databind.JsonNode.str(field: String): String? =
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

        /** Kinds the customer plane can delete; `loginTheme` / `loginFlow` have no delete surface. */
        fun deletable(kind: String): Boolean = kind !in setOf(ProvisionFile.KIND_LOGIN_THEME, ProvisionFile.KIND_LOGIN_FLOW)

        /** An owned non-environment resource with no sandbox slug lives on the production plane. */
        fun onProductionPlane(o: OwnedResource): Boolean =
            o.kind != ProvisionFile.KIND_ENVIRONMENT &&
                (o.environment.isNullOrBlank() || o.environment == ThorynConfig.PRODUCTION_ENV_SLUG)
    }
}
