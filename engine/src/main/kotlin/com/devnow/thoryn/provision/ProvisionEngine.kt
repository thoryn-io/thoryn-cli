package com.devnow.thoryn.provision

import tools.jackson.databind.JsonNode
import java.io.File
import java.io.PrintStream
import java.time.Instant

/**
 * [ERROR] (SSO-3659) is a per-resource VERDICT, not a step: the declared resource failed the ownership
 * gate (`access_read_only` / `access_not_owned` / `access_owned_elsewhere`, see [PlannedChange.error]).
 * A plan carrying one is red (non-zero exit) and `apply` refuses it before writing anything.
 */
enum class ChangeAction { CREATE, UPDATE, ADOPT, NOOP, REMOVE, SKIP, ERROR }

/** SSO-3659 — the relation the signed-in identity holds on a live platform object (ADR 2026-10-13 §1). */
enum class Access(val label: String) { MANAGER("manager"), VIEWER("viewer"), NONE("none") }

/** One row of a plan: what `apply` / `destroy` would do to a resource, why, and (for updates) which fields change. */
data class PlannedChange(
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
    /** SSO-3113 — grants (`<subject> <relation>`) the file declares on this object that do not exist live. */
    val grantAdds: List<String> = emptyList(),
    /** SSO-3113 — grants live on this object that the file no longer declares (never the admin userset). */
    val grantRemoves: List<String> = emptyList(),
    /**
     * SSO-3413 / SSO-3414 — a `customDomain`'s live view: host, state, entitlement, the issuer in use, and
     * the DNS records to publish as `{type, name, value, ttl}` ([DnsRecord]).
     */
    val customDomain: Map<String, Any?>? = null,
    /**
     * SSO-3659 — the relation the signed-in identity holds on the live object (`manager` / `viewer` /
     * `none`), or `manager` for a create whose parent it manages. Null for receipt-only rows (skip / remove).
     */
    val access: String? = null,
    /** SSO-3659 — the file declares this resource `readOnly: true` (a dependency; never owned, never in the receipt). */
    val readOnly: Boolean = false,
    /** SSO-3659 — the ownership-gate error code when [action] is [ChangeAction.ERROR] (`access_*`), else null. */
    val error: String? = null,
    /**
     * SSO-3673 — the platform `owner` of the live object as its response renders it (`owner.subject`), or null
     * when the platform reports none (or the kind renders none). Carried to the receipt ([OwnedResource.owner]).
     */
    val owner: String? = null,
    /**
     * SSO-3668 — the outputs `apply` will PUBLISH this resource's id to once it is converged (every apply, an
     * upsert). Shown as a line of the plan — a pull-request check shows where the id will land — and never
     * written by `plan`. Empty on an [ChangeAction.ERROR] row and on a read-only reference.
     */
    val publishTo: List<PublishTarget> = emptyList(),
    /**
     * SSO-3659 (ADR 2026-10-13 §5) — where `apply` will DELIVER the client secret this CREATE mints, the moment the
     * client is converged and recorded. Shown as a line of the plan (a pull-request check shows where the secret
     * will land); nothing is minted by `plan`. Only on a CREATE of a confidential application with a `secretSink:`.
     */
    val secretSink: SecretTarget? = null,
) {
    val hasGrantChanges: Boolean get() = grantAdds.isNotEmpty() || grantRemoves.isNotEmpty()

    fun toStructured(): Map<String, Any?> = buildMap {
        put("kind", kind); put("name", name); put("action", action.name.lowercase()); put("reason", reason)
        liveId?.let { put("id", it) }
        if (diff.isNotEmpty()) put("diff", diff)
        if (adopted) put("adopted", true)
        if (hasGrantChanges) put("grants", mapOf("add" to grantAdds, "remove" to grantRemoves))
        customDomain?.let { put("customDomain", it) }
        access?.let { put("access", it) }
        if (readOnly) put("readOnly", true)
        error?.let { put("error", it) }
        owner?.let { put("owner", it) }
        if (publishTo.isNotEmpty()) {
            put("publishTo", publishTo.map { mapOf("kind" to it.kind, "repository" to it.repository, "environment" to it.environment, "name" to it.name) })
        }
        secretSink?.let { put("secretSink", it.toStructured()) }
    }
}

class ProvisionPlan(val changes: List<PlannedChange>) {
    val creates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.CREATE }
    val updates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.UPDATE }
    val adopts: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.ADOPT }
    val removes: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.REMOVE }
    /** SSO-3113 — resources whose grants differ (a no-op resource can still carry grant changes). */
    val grantChanges: Int get() = changes.sumOf { it.grantAdds.size + it.grantRemoves.size }
    /**
     * SSO-3668 — outputs `apply` will publish (an upsert on EVERY apply, so a no-op resource with a `publishTo:`
     * still gives `apply` something to do — that is what makes a re-created client propagate, and a re-run
     * repair a variable someone changed by hand).
     */
    val publishes: Int get() = changes.sumOf { it.publishTo.size }
    /** SSO-3659 — client secrets `apply` will mint AND deliver to a declared `secretSink:` (a CREATE each; never by plan). */
    val deliveries: Int get() = changes.count { it.secretSink != null }
    val hasChanges: Boolean get() = creates.isNotEmpty() || updates.isNotEmpty() || adopts.isNotEmpty() || removes.isNotEmpty() || grantChanges > 0 || publishes > 0
    /** SSO-3659 — resources that failed the ownership gate; a plan with one is red and `apply` refuses it. */
    val errors: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.ERROR }
    val hasErrors: Boolean get() = errors.isNotEmpty()

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
            "grants" to grantChanges,
            "error" to errors.size,
            "publish" to publishes,
            "deliver" to deliveries,
        ),
    )
}

/**
 * SSO-3659 (ADR 2026-10-13 §2) — one live resource `import` would add to the provisioning file: the
 * rendered [resource] (owned, or `readOnly: true` when the identity may only view it or another receipt
 * owns it), its live id, the [access] the identity holds, the receipt entry it becomes ([owned] —
 * `adopted: true`, never deleted by destroy; null for a read-only reference), and a [note] for what the
 * file cannot carry (a write-only secret, an unrecoverable template).
 */
data class ImportedResource(
    val resource: ProvisionResource,
    val liveId: String,
    val access: Access,
    val owned: OwnedResource?,
    val note: String? = null,
) {
    /** The `provision.yaml` entry, key order as a human would write it. */
    fun toEntry(): Map<String, Any?> = buildMap {
        put("kind", resource.kind)
        if (!resource.isSingleton || resource.name != resource.kind) put("name", resource.name)
        resource.environment?.let { put("environment", it) }
        if (resource.readOnly) put(ProvisionFile.READ_ONLY, true)
        put("spec", resource.spec)
    }

    fun toStructured(): Map<String, Any?> = buildMap {
        putAll(toEntry()); put("id", liveId); put("access", access.label); note?.let { put("note", it) }
    }
}

/** The outcome of an import: what would be added, and what was reachable but could not be rendered (with why). */
data class ImportResult(val resources: List<ImportedResource>, val skipped: List<String>)

/** The outcome of a destroy / prune pass: what is still owned, and which removals failed. */
data class RemovalOutcome(val remaining: ProvisionReceipt, val failures: List<String>)

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
 * **Server-minted client secrets (SSO-3113).** A confidential `application` (product-api's default
 * `clientType`) is created with a ONE-TIME `client_secret` on the create response. It leaves the engine
 * EXCLUSIVELY through [secretSink] (the consumer's channel: the CLI's `--secret-file` / guarded-stdout
 * `SecretIo`) — never the receipt, the plan, the console, or a log. When the sink refuses it, the
 * resource is still recorded (it exists) and its clientId lands on [undeliveredSecrets] so the CLI's
 * `apply` can exit `SecretIo.EXIT_NO_SECRET` and point at `thoryn clients rotate-secret`.
 *
 * **Grants (SSO-3113, ordering SSO-3119).** A resource's `grants:` block is converged in a SECOND pass,
 * once EVERY resource in the file exists: the object's grants are listed (`GET /api/v1/access/grants?object=…`),
 * missing ones POSTed and ones the file no longer declares DELETEd — for THAT object only (never an
 * object the file does not own), never the workspace admin userset. The object ref derives from the
 * receipt id ([objectRef]). The second pass is what lets a block name a subject the same file declares
 * under another kind or further down; converging inline would read the file's own kind ordering as a
 * dependency order it never had. A session without `tenant:access.write` fails closed with a clear message.
 *
 * **Ownership is decided by the identity's platform reach (SSO-3659; ADR 2026-10-13 §1), asked per
 * OBJECT (SSO-3673; ADR 2026-10-13 platform-owner-relation-and-forward-check).** Before any write, every
 * declared resource is gated on the relation the signed-in identity holds on the live object in the
 * platform authorization graph, through `POST /api/v1/access/check {object, relation}` for the caller's
 * own subject (`tenant:access.read`) — `manager` for a change, `viewer` for a `readOnly: true` reference —
 * answered over the platform store with the model's containment rules (`manager = this ∪ owner ∪
 * parent.manager`). `manager` ⇒ the normal converge; `viewer` ⇒ the resource may be declared
 * `readOnly: true` as a dependency and must MATCH (any diff is `access_read_only`); none ⇒
 * `access_not_owned` — not visible, never adopted, imported or converged. A CREATE needs `manager` on the
 * parent (`environment:<id>`, or the workspace for the production plane / an environment / the custom
 * domain), asked with the same check on the parent object; creator-becomes-manager (and, for a `client:`
 * creator, creator-becomes-OWNER) on the platform then makes this identity the resource's manager — no
 * grant step, no race. A failed gate is a [ChangeAction.ERROR] row (red plan, non-zero exit) and [apply]
 * refuses the whole plan before writing. **One owning repository per resource is a PLATFORM fact:** the
 * `owner` relation (one subject per `application` / `environment`, a database invariant on the platform,
 * granted by a workspace admin or set at create for a `client:` creator) is rendered on the resource as
 * `owner: { subject }`; when the live object has an owner and `/access/check` says this identity is not
 * it, the resource is `access_owned_elsewhere` unless declared `readOnly: true` here — the plan names no
 * other subject, only "another repository". The receipt records the owner the platform reported
 * ([OwnedResource.owner]). The former `--peer-receipt` comparison of receipts is gone: the receipt is no
 * longer the marker. `GET /api/v1/access/mine` (the per-TYPE reverse index) remains the LISTING read
 * [import] is built on. Note that the public `POST /api/v1/fga/check` / `list-objects` evaluate the
 * TENANT's own authorization model over the environment-partitioned tenant tuple store, not the platform
 * resource graph — `/api/v1/access/check` and `/mine` are that graph's check and list-objects.
 *
 * **Outputs (SSO-3668; ADR 2026-10-13 production-clients-declared-in-the-config-project §2).** An
 * `application`'s `publishTo:` targets receive its clientId through [outputSink] — the sibling of
 * [secretSink] for a value that is PUBLIC by construction — AFTER the resource is converged and recorded
 * in the receipt (the id is known), on EVERY apply (an upsert: a re-created client propagates without a
 * second step). A target the sink cannot reach does not undo anything: the client exists, the receipt
 * records its id, and `apply` ends with [PublishTargetUnreachableException] (`publish_target_unreachable`)
 * naming the one `gh variable set` a human can run with the id from the receipt. `plan` never publishes;
 * it shows the pending publish as a line. The receipt records what WAS published ([OwnedResource.published]).
 * Like [SecretSink], the library ships no [OutputSink] that runs a process: the CLI's is `gh variable set`.
 *
 * **Declared secret delivery (SSO-3659; ADR 2026-10-13 converge §5, production-clients ADR §3 tier 3).** A
 * confidential `application` may declare a `secretSink:` ([SecretTarget] — a key of an existing namespace's
 * Kubernetes Secret, or an owner-only file): where the one-time `client_secret` is CONSUMED. `apply` hands
 * the minted value to [declaredSecretSink] IMMEDIATELY AFTER the client is converged and recorded in the
 * receipt (so an unreachable sink never costs the client its receipt entry), falls back to the generic
 * [secretSink] (the CLI's `--secret-file` / guarded TTY) when the declared one answers a reason, and — when
 * neither reaches — leaves the client in place and reports it on [undeliveredSecretDetails]
 * (`undelivered_secrets`): the host exits non-zero naming the resource and the recovery
 * `thoryn clients rotate-secret <clientId> --secret-file <path>`. The value never enters the receipt, the
 * plan, the console or a log — a sink's reason is redacted of it before it is printed. `plan` shows the
 * intended delivery as a line ([PlannedChange.secretSink]) and mints nothing. The library ships no sink
 * that runs `kubectl` or writes a file: the CLI's does (`CliDeclaredSecretSink`).
 *
 * [clients] yields a tenant-scoped [ProvisionApi] bound to an environment slug (`null` ⇒ the
 * production plane); [persist] is invoked after every successful write so the receipt on disk always
 * reflects reality even when a later step fails.
 *
 * **A library since SSO-3662** (ADR 2026-10-13-provision-engine-shared-library): this class, the file
 * model, the receipt model and [SecretSink] are `io.thoryn:thoryn-provision-engine`, the module the CLI
 * is built on and that anything else needing to converge a provisioning file in-process consumes. The
 * module knows nothing of picocli, a TTY, or the CLI's session — it reaches product-api only through the
 * [ProvisionApi] port the consumer hands it, and reports through the [out] / [err] streams it is given.
 */
class ProvisionEngine(
    private val clients: (environmentSlug: String?) -> ProvisionApi,
    private val out: PrintStream = System.out,
    private val err: PrintStream = System.err,
    private val env: (String) -> String? = { System.getenv(it) },
    private val cliVersion: String? = null,
    private val now: () -> Instant = { Instant.now() },
    /** SSO-3113 — the single channel a minted `client_secret` leaves through; the default delivers nothing. */
    private val secretSink: SecretSink = SecretSink.undeliverable(),
    /**
     * SSO-3413 — the signed-in workspace's id (the token's `tnt`): the id of the workspace-level
     * `customDomain` singleton, and so of its access object `custom_domain:<workspaceId>`.
     */
    private val workspaceId: String? = null,
    /**
     * SSO-3659 — the signed-in identity's platform subject (`client:<clientId>` / `member:<sub>`), derived
     * from the token by the caller exactly as product-api derives it. Recorded on the receipt
     * ([ProvisionReceipt.subject]) for display / audit; the gate itself never sends it — `/api/v1/access/check`
     * and `/mine` answer for the CALLER's own subject, so the subject is always the token's, never the file's.
     */
    private val subject: String? = null,
    /**
     * SSO-3668 — the channel an application's clientId is PUBLISHED through to its `publishTo:` targets. The
     * default reaches nothing, so a file that declares a target and an engine without a publisher fail loud
     * (`publish_target_unreachable`) rather than silently skipping the publish.
     */
    private val outputSink: OutputSink = OutputSink.unavailable(),
    /**
     * SSO-3659 — the channel a minted client secret is DELIVERED through to its declared `secretSink:`. The
     * default reaches nothing, so a file that declares a sink and a host without a delivery fall through to
     * [secretSink] and then to `undelivered_secrets` — never a silent skip.
     */
    private val declaredSecretSink: DeclaredSecretSink = DeclaredSecretSink.unavailable(),
) {

    /**
     * SSO-3659 (ADR 2026-10-13 §5) — the port a minted client secret leaves the engine through on its way to a
     * declared [SecretTarget]. Same shape as [OutputSink]: no picocli, no TTY, no process in the library — the
     * CLI implements it with the operator's own `kubectl` (value on stdin, never argv) and the owner-only file
     * writer. [deliver] answers `null` when the value landed, else WHY it did not (shown to the operator after
     * the engine redacts the value from it; the message names the recovery, never the secret).
     */
    fun interface DeclaredSecretSink {
        fun deliver(target: SecretTarget, clientId: String, secret: String): String?

        companion object {
            /** Reaches nothing — every declared sink is reported unreachable (the engine's default). */
            fun unavailable(): DeclaredSecretSink = DeclaredSecretSink { _, _, _ -> "no secret delivery is available in this context" }
        }
    }

    /**
     * SSO-3659 — one client secret `apply` minted but could NOT deliver: the resource, its clientId, the declared
     * target (if any) and the (redacted) reason. The client exists and is owned; [recovery] mints a new secret.
     */
    data class UndeliveredSecret(val resourceKey: String, val clientId: String, val target: SecretTarget?, val reason: String) {
        /** The one command a human runs instead — with the clientId from the receipt. */
        val recovery: String get() = recoverSecret(clientId)
    }

    /**
     * SSO-3668 — the port an application's clientId leaves the engine through on its way to a `publishTo:`
     * target. Same shape as [SecretSink]: no picocli, no TTY, no process — the CLI implements it with
     * `gh variable set … --env` (creating the environment when absent, never touching an existing one's
     * protection); the GitHub App with its own gateway. [publish] answers `null` when the value landed,
     * else WHY the target could not be reached (shown to the operator; never the value itself — which is a
     * client id and public anyway, but the message names the receipt as its source).
     */
    fun interface OutputSink {
        fun publish(target: PublishTarget, value: String): String?

        companion object {
            /** Reaches nothing — every target is reported unreachable (the engine's default). */
            fun unavailable(): OutputSink = OutputSink { _, _ -> "no publisher is available in this context" }
        }
    }

    /** SSO-3668 — one `publishTo:` target `apply` could not reach: which resource, which target, and why. */
    data class PublishFailure(val resourceKey: String, val target: PublishTarget, val value: String, val reason: String) {
        /** The one command a human runs instead, with the id from the receipt. */
        val byHand: String get() = target.byHand(value)
    }

    /**
     * SSO-3668 — `apply` converged and recorded every resource, but one or more outputs could not be
     * published (`publish_target_unreachable`). Raised AFTER convergence, once the receipt is persisted
     * ([receipt] is that receipt), so nothing is lost: the human fallback is each failure's [PublishFailure.byHand].
     */
    class PublishTargetUnreachableException(val failures: List<PublishFailure>, val receipt: ProvisionReceipt) : ProvisionException(
        "$ERROR_PUBLISH_UNREACHABLE — every resource was converged and recorded in the receipt, but " +
            "${failures.size} output(s) could not be published:\n  " +
            failures.joinToString("\n  ") { "${it.resourceKey} → ${it.target.label}: ${it.reason}\n    publish it by hand: ${it.byHand}" },
    )

    /**
     * SSO-3113 — clientIds of confidential applications created by the last [apply] whose one-time
     * secret the [secretSink] could NOT deliver. The clients exist (and are owned); the operator must
     * mint a new secret with `thoryn clients rotate-secret <clientId>`.
     */
    private val undelivered = mutableListOf<UndeliveredSecret>()
    val undeliveredSecrets: List<String> get() = undelivered.map { it.clientId }
    /** SSO-3659 — the same, with the declared target and the (redacted) reason per client (`undelivered_secrets`). */
    val undeliveredSecretDetails: List<UndeliveredSecret> get() = undelivered.toList()

    /**
     * SSO-3113 — the single channel a server-minted `client_secret` leaves the engine through. [emit]
     * returns `true` when delivered, `false` when refused — the resource is still recorded and its
     * clientId lands on [undeliveredSecrets]. SSO-3662: the library ships NO sink that touches a TTY or a
     * file system; each consumer brings its own — the CLI's `CliSecretSink` (the `--secret-file` /
     * guarded-stdout `SecretIo` channel `thoryn clients create` uses, exit `SecretIo.EXIT_NO_SECRET` when
     * refused), a `secretSink:` delivery kind (ADR 2026-10-13 §5) in whatever runs the engine for it.
     */
    fun interface SecretSink {
        fun emit(clientId: String, secret: String): Boolean

        companion object {
            /** Delivers nothing — every minted secret is reported as undelivered (the engine's default). */
            fun undeliverable(): SecretSink = SecretSink { _, _ -> false }
        }
    }

    // ── plan ─────────────────────────────────────────────────────────────────────────────────────

    fun plan(file: ProvisionFile, receipt: ProvisionReceipt?, prune: Boolean): ProvisionPlan {
        val ownedByKey = receipt?.resources.orEmpty().associateBy { it.key }
        val changes = mutableListOf<PlannedChange>()
        // Environment slugs known so far (owned / live), so dependants can be probed in the right plane.
        val envSlugs = mutableMapOf<String, String>()
        val reach = Reach()
        orderForApply(file.resources).forEach { r ->
            val owned = ownedByKey[r.key]
            val slug = planSlug(r, file, envSlugs)
            // SSO-3659 — the ownership gate sits between the live lookup and everything that would write:
            // a resource that fails it plans no grants (its object may not even be visible to this identity).
            val change = gate(r, probe(r, file, owned, envSlugs), file, envSlugs, slug, reach)
                .let { c -> if (c.action == ChangeAction.ERROR || c.readOnly) c else planGrants(r, c, slug, owned) }
                // SSO-3668 — a resource that will be converged publishes its id afterwards (every apply); shown, never done, by plan.
                .let { c -> if (c.action == ChangeAction.ERROR || c.readOnly || r.publishTo.isEmpty()) c else c.copy(publishTo = r.publishTo, reason = c.reason + "; publishes its id to ${r.publishTo.size} target(s)") }
                // SSO-3659 — a CREATE of a confidential application mints a secret; where it will be delivered is shown, never done, by plan.
                .let { c -> if (c.action == ChangeAction.CREATE && !c.readOnly && r.secretSink != null && isConfidential(r.spec)) c.copy(secretSink = r.secretSink) else c }
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

    /**
     * The environment slug a declared resource is probed in at plan time: `null` for the production
     * plane (and for an `environment` resource itself), a pre-existing slug, or the RESOLVED slug of an
     * `environment` resource of this file — `null` as well when that environment does not exist yet.
     */
    private fun planSlug(r: ProvisionResource, file: ProvisionFile, envSlugs: Map<String, String>): String? = when {
        r.kind == ProvisionFile.KIND_ENVIRONMENT -> null
        r.environment == null -> null
        file.environmentResource(r.environment) == null -> r.environment
        else -> envSlugs[r.environment]
    }

    /** Live lookup by converge key → create / update / adopt / noop for one declared resource. */
    private fun probe(r: ProvisionResource, file: ProvisionFile, owned: OwnedResource?, envSlugs: Map<String, String>): PlannedChange {
        if (r.kind == ProvisionFile.KIND_CUSTOM_DOMAIN) return probeCustomDomain(r, owned)
        val slug: String? = when {
            r.kind == ProvisionFile.KIND_ENVIRONMENT -> null
            r.environment == null -> null
            file.environmentResource(r.environment) == null -> r.environment
            else -> envSlugs[r.environment]
                ?: return PlannedChange(r.kind, r.name, ChangeAction.CREATE, "environment '${r.environment}' will be created first${mintNote(r)}", resource = r)
        }
        val desired = resolveSpec(r, strict = false)
        val live = try {
            lookup(r, owned, slug, desired)
        } catch (ex: ProductApiException) {
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        return when {
            live == null && owned != null -> PlannedChange(r.kind, r.name, ChangeAction.CREATE, "owned id ${owned.id} no longer exists — will be re-created${mintNote(r)}", resource = r, owned = owned)
            live == null -> PlannedChange(r.kind, r.name, ChangeAction.CREATE, "not found by its converge key${mintNote(r)}", resource = r)
            live.diff.isNotEmpty() -> PlannedChange(
                r.kind, r.name, ChangeAction.UPDATE,
                if (owned == null) "exists (adopting) — ${live.diff.size} field(s) differ" else "${live.diff.size} field(s) differ",
                resource = r, owned = owned, liveId = live.id, diff = live.diff, adopted = owned?.adopted ?: true, owner = live.owner,
            )
            owned == null -> PlannedChange(r.kind, r.name, ChangeAction.ADOPT, "exists and matches — adopted under management (never deleted by destroy)", resource = r, liveId = live.id, adopted = true, owner = live.owner)
            else -> PlannedChange(r.kind, r.name, ChangeAction.NOOP, "owned (id ${live.id}) and matches", resource = r, owned = owned, liveId = live.id, adopted = owned.adopted, owner = live.owner)
        }
    }

    /** SSO-3113 — the plan marker for a confidential application about to be created (its secret is shown once). */
    private fun mintNote(r: ProvisionResource): String = when {
        r.kind != ProvisionFile.KIND_APPLICATION || !isConfidential(r.spec) -> ""
        // SSO-3659 — with a declared sink the secret is delivered, not shown.
        r.secretSink != null -> " (a client secret will be minted and delivered to ${r.secretSink.label})"
        else -> " (a client secret will be minted and shown once)"
    }

    /** product-api's `clientType` defaults to `confidential`; only an explicit `public` client is secret-less. */
    private fun isConfidential(spec: Map<String, Any?>): Boolean =
        !spec["clientType"]?.toString()?.trim().equals("public", ignoreCase = true)

    /**
     * SSO-3113 — attach the grant diff to a planned change: for a CREATE every declared grant is an add
     * (nothing exists yet); otherwise the object's live grants are listed and compared as a set. A
     * resource without a `grants:` block is left untouched (nothing is even read).
     */
    private fun planGrants(r: ProvisionResource, change: PlannedChange, slug: String?, owned: OwnedResource?): PlannedChange {
        val declared = r.grants ?: return change
        if (change.action == ChangeAction.CREATE || change.liveId == null) {
            return change.copy(grantAdds = declared.map { it.label })
        }
        val (adds, removes) = grantDiff(declared, liveGrants(r, objectRef(r.kind, change.liveId, slug)), owned?.grants.orEmpty())
        if (adds.isEmpty() && removes.isEmpty()) return change
        val note = "; grants: +${adds.size} −${removes.size}"
        return change.copy(reason = change.reason + note, grantAdds = adds, grantRemoves = removes)
    }

    // ── ownership gate (SSO-3659; ADR 2026-10-13 §1 — per object since SSO-3673) ────────────────

    /**
     * The signed-in identity's own platform reach for one plan / import pass. Per OBJECT through
     * `POST /api/v1/access/check` ([check], cached per `(object, relation)`); per TYPE through
     * `GET /api/v1/access/mine` ([ids], the listing `import` is built on). Workspace-level: the environment is
     * an object in that graph, never a partition, so every read goes through the production-plane client.
     * Both answers are fail-closed on the platform side (an indeterminate check is `false`; a truncated reverse
     * walk can only SHORTEN a listing), so neither can widen what this identity may touch.
     */
    private inner class Reach {
        private val checks = HashMap<Pair<String, String>, AccessCheck>()
        private val listed = HashMap<Pair<String, String>, Set<String>>()
        private var environments: List<JsonNode>? = null

        /** SSO-3673 — the platform's answer to "does this identity hold [relation] on [ref]?" (the ADR's literal question). */
        fun check(ref: String, relation: String): AccessCheck = checks.getOrPut(ref to relation) {
            try {
                clients(null).checkAccess(ref, relation)
            } catch (ex: ProductApiException) {
                throw accessFailure(ex)
            }
        }

        fun holds(ref: String, relation: String): Boolean = check(ref, relation).allowed

        /** The ids (percent-decoded AND as sent) of every `type` object the identity holds [relation] on (`import`). */
        fun ids(type: String, relation: String): Set<String> = listed.getOrPut(type to relation) {
            try {
                listItems(clients(null).listMyAccess(type, relation), "data")
                    .mapNotNull { n -> n.takeIf { it.isString }?.asString()?.takeIf { it.startsWith("$type:") }?.substringAfter(':') }
                    .flatMap { listOf(it, decodePlatformId(it)) }
                    .toSet()
            } catch (ex: ProductApiException) {
                throw accessFailure(ex)
            }
        }

        /** The relation held on `type:id` — `manager` implies `viewer`, so the stronger one is asked first. */
        fun on(ref: String): Access = when {
            holds(ref, RELATION_MANAGER) -> Access.MANAGER
            holds(ref, RELATION_VIEWER) -> Access.VIEWER
            else -> Access.NONE
        }

        /**
         * SSO-3673 — whether THIS identity is the platform `owner` of [ref] (`owner` is direct-only on the model, so
         * this is never inherited and never implied by `manager` or workspace standing). Asked only for an ownable
         * type whose live response reported an owner — the one case where "someone owns it" has to be resolved to
         * "me" or "another repository".
         */
        fun owns(ref: String): Boolean = holds(ref, RELATION_OWNER)

        /**
         * Whether the identity manages the workspace (`workspace#manager` is the model's alias of `admin`), asked on
         * the workspace object when the session names it (`tnt`). A session without a `tnt` cannot name the
         * workspace, but it is signed in to exactly one — so a non-empty `/mine` listing is that one.
         */
        fun managesWorkspace(): Boolean =
            if (workspaceId != null) holds("$OBJECT_TYPE_WORKSPACE:$workspaceId", RELATION_MANAGER) else ids(OBJECT_TYPE_WORKSPACE, RELATION_MANAGER).isNotEmpty()

        fun managesParent(parentRef: String): Boolean =
            if (parentRef.startsWith("$OBJECT_TYPE_WORKSPACE:")) managesWorkspace() else holds(parentRef, RELATION_MANAGER)

        /** The workspace's environments (one list per pass). */
        fun environments(): List<JsonNode> = environments ?: try {
            listItems(clients(null).listEnvironments(), "environments").also { environments = it }
        } catch (ex: ProductApiException) {
            throw ProvisionException("could not list the workspace's environments to resolve a resource's parent (${ex.message})")
        }

        fun environmentId(slug: String): String? = environments().firstOrNull { it.str("slug") == slug }?.str("id")
    }

    /**
     * Gate one probed resource on the identity's reach, asked PER OBJECT. The verdict table of ADR 2026-10-13
     * §1, plus the "one owning repository" rule as the platform states it: `manager` ⇒ converge (unless the
     * platform says another identity OWNS it); `viewer` ⇒ only a matching `readOnly: true` reference; none ⇒
     * not visible; a create ⇒ `manager` on the parent.
     */
    private fun gate(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange {
        if (change.action == ChangeAction.ERROR) return change
        val liveId = change.liveId
        if (liveId != null) {
            val ref = objectRef(r.kind, liveId, slug)
            // Containment is the model's own rule (`manager = this ∪ owner ∪ parent.manager`) and the check applies it;
            // the fallback is for an object the graph does not know yet — a singleton that was reset out of band and so
            // has no `parent` edge — which is still this identity's to manage when it manages the parent. The platform
            // re-checks every write server-side, so this can never admit a write the platform would refuse.
            val access = reach.on(ref).let { direct ->
                if (direct == Access.NONE && parentRef(r, file, envSlugs, slug, reach)?.let { reach.managesParent(it) } == true) Access.MANAGER else direct
            }
            val differs = change.diff.isNotEmpty()
            return when (access) {
                Access.NONE -> refuse(
                    r, change, ERROR_NOT_OWNED, access,
                    "this identity holds no relation on $ref — the resource is not visible to it and cannot be adopted, imported or converged " +
                        "(a workspace admin grants reach with `thoryn access grant <subject> manager $ref`)",
                )
                Access.VIEWER -> when {
                    !r.readOnly -> refuse(
                        r, change, ERROR_READ_ONLY, access,
                        "this identity may only VIEW $ref — declare the resource `readOnly: true` to depend on it without owning it, " +
                            "or have a workspace admin grant it `manager`",
                    )
                    differs -> refuse(
                        r, change, ERROR_READ_ONLY, access,
                        "read-only reference differs from the live resource in ${change.diff.size} field(s) (${change.diff.keys.joinToString(", ")}) — " +
                            "a repository that does not own a resource cannot change it; align the file with what is live",
                    )
                    else -> reference(change, access)
                }
                Access.MANAGER -> when {
                    r.readOnly && differs -> refuse(
                        r, change, ERROR_READ_ONLY, access,
                        "declared `readOnly: true` but differs from the live resource in ${change.diff.size} field(s) (${change.diff.keys.joinToString(", ")}) — " +
                            "a read-only reference is never written; drop `readOnly` to converge it from this file, or align the file with what is live",
                    )
                    r.readOnly -> reference(change, access)
                    // SSO-3673 — the platform renders the object's `owner`; when there is one and the check says it is not
                    // this identity, another repository owns it. Nothing about that subject is echoed (no oracle).
                    change.owner != null && !reach.owns(ref) -> refuse(
                        r, change, ERROR_OWNED_ELSEWHERE, access,
                        "$ref is owned by another repository (the platform's `owner` relation) — one repository owns a resource; " +
                            "declare it `readOnly: true` here to depend on it, or have a workspace admin move the ownership " +
                            "(`thoryn access revoke <current-owner> owner $ref`, then `thoryn access grant <subject> owner $ref`)",
                    )
                    else -> change.copy(access = access.label)
                }
            }
        }
        // A create. A read-only reference is a dependency on something that exists — it is never created.
        if (r.readOnly) {
            return refuse(r, change, ERROR_READ_ONLY, null, "declared `readOnly: true` but nothing matches it live — a read-only reference is never created; declare it without `readOnly` to own it")
        }
        val parent = parentRef(r, file, envSlugs, slug, reach)
            ?: return change.copy(access = Access.MANAGER.label) // the parent environment is created by this very apply: creator-becomes-manager covers both
        return if (reach.managesParent(parent)) {
            change.copy(access = Access.MANAGER.label)
        } else {
            refuse(r, change, ERROR_NOT_OWNED, null, "creating a ${r.kind} here requires `manager` on its parent $parent, which this identity does not hold")
        }
    }

    private fun refuse(r: ProvisionResource, change: PlannedChange, code: String, access: Access?, why: String): PlannedChange =
        change.copy(action = ChangeAction.ERROR, reason = "$code — $why", error = code, access = access?.label, readOnly = r.readOnly, owned = change.owned)

    /** A read-only reference that exists and matches: a no-op that is never owned (a stale receipt entry is dropped by `apply`). */
    private fun reference(change: PlannedChange, access: Access): PlannedChange = change.copy(
        action = ChangeAction.NOOP,
        reason = "read-only reference (${access.label}) — exists and matches; this file does not own it" +
            if (change.owned != null) "; dropped from the receipt" else "",
        readOnly = true, access = access.label, adopted = false, diff = emptyMap(),
    )

    /**
     * The platform object a CREATE needs `manager` on: the workspace for an environment, the custom domain and
     * any production-plane resource; `environment:<id>` for a resource inside an existing sandbox; `null` when
     * the sandbox is an `environment` resource of this file that does not exist yet (it is created first).
     */
    private fun parentRef(r: ProvisionResource, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): String? {
        val workspace = "$OBJECT_TYPE_WORKSPACE:${workspaceId ?: "(this workspace)"}"
        if (r.kind == ProvisionFile.KIND_ENVIRONMENT || r.kind in ProvisionFile.WORKSPACE_KINDS) return workspace
        val envRef = r.environment ?: return workspace
        if (file.environmentResource(envRef) != null && envSlugs[envRef] == null) return null
        val envSlug = slug ?: return workspace
        if (envSlug == PRODUCTION_ENV_SLUG) return workspace
        // An environment the workspace does not list cannot be anyone's but a workspace manager's to fill (the API
        // refuses the unknown plane either way); never a verdict invented from a slug.
        val id = reach.environmentId(envSlug) ?: return workspace
        return objectRef(ProvisionFile.KIND_ENVIRONMENT, id, null)
    }

    /** Fail closed: an access read (`/access/check`, `/access/mine`) names the scope it needs; every other failure keeps its cause. */
    private fun accessFailure(ex: ProductApiException): ProvisionException = when {
        ex.isInsufficientScope -> ProvisionException(
            "could not check this identity's access (${ex.message}) — ownership is decided by the relation it holds on each resource " +
                "(`POST /api/v1/access/check`), which needs the '${AccessRefs.SCOPE_READ}' scope. Sign in with `thoryn login --scope ${AccessRefs.SCOPE_READ}` " +
                "(or grant the CI identity that scope) and re-run.",
        )
        else -> ProvisionException("could not check this identity's access (${ex.message}); nothing was planned or written")
    }

    // ── import (SSO-3659; ADR 2026-10-13 §2) ─────────────────────────────────────────────────────

    /**
     * The inverse of [plan], bounded by the same relations: every live platform object the identity holds
     * `manager` on is rendered as an OWNED entry (its receipt row `adopted: true` — never deleted by destroy),
     * every one it may only `viewer` as `readOnly: true`; an object the platform says another identity OWNS
     * (SSO-3673: its response renders an `owner` and `/access/check owner` is false for this identity) is
     * rendered `readOnly: true` as well. Nothing the identity has no relation to is listed by the platform, so
     * nothing it has no relation to can be imported — the file cannot claim by being written. Resources
     * [existing] already declares (or [receipt] already owns) are left out; what is reachable but cannot be
     * rendered as a `provision.yaml` entry lands on [ImportResult.skipped] with the reason. Reads only.
     */
    fun import(existing: ProvisionFile?, receipt: ProvisionReceipt?): ImportResult {
        val reach = Reach()
        val out = mutableListOf<ImportedResource>()
        val skipped = mutableListOf<String>()
        fun skip(why: String) { skipped += why }
        val declared = existing?.resources.orEmpty()
        val ownedRefs = receipt?.resources.orEmpty().mapNotNull { o -> runCatching { objectRef(o.kind, o.id, o.environment) }.getOrNull() }.toSet()
        val names = declared.map { it.key }.toMutableSet()
        fun uniqueName(kind: String, base: String): String {
            val root = slugName(base).ifEmpty { kind.lowercase() }
            var candidate = root
            var n = 2
            while (!names.add("$kind/$candidate")) candidate = "$root-${n++}".take(63).trimEnd('-')
            return candidate
        }
        // Every object of a kind the identity holds any relation on, strongest first.
        fun reachable(type: String): List<Pair<String, Access>> {
            val managed = reach.ids(type, RELATION_MANAGER)
            val viewed = reach.ids(type, RELATION_VIEWER)
            return (managed.map { it to Access.MANAGER } + viewed.filter { it !in managed }.map { it to Access.VIEWER })
                .filter { (id, _) -> id == decodePlatformId(id) } // the decoded spelling is the product id; the encoded twin duplicates it
                .sortedBy { it.first }
        }
        fun readOnlyFor(ref: String, access: Access, owner: String?): Pair<Boolean, String?> = when {
            access == Access.VIEWER -> true to null
            owner != null && !reach.owns(ref) -> true to "owned by another repository (the platform's `owner` relation) — imported as a read-only reference"
            else -> false to null
        }
        fun add(kind: String, name: String, environment: String?, environmentSlug: String?, id: String, access: Access, spec: Map<String, Any?>, attributes: Map<String, String> = emptyMap(), note: String? = null, owner: String? = null) {
            val ref = objectRef(kind, id, environmentSlug)
            if (ref in ownedRefs) return
            val (readOnly, ownerNote) = readOnlyFor(ref, access, owner)
            val resource = ProvisionResource(kind = kind, name = name, environment = environment, spec = spec, readOnly = readOnly)
            val owned = if (readOnly) null else OwnedResource(kind, name, id, environmentSlug, attributes, adopted = true, owner = owner)
            out += ImportedResource(resource, id, access, owned, listOfNotNull(ownerNote, note).joinToString("; ").ifEmpty { null })
        }

        // Environments first: a child rendered below names its sandbox by the resource NAME when the same import adds it.
        val envName = declared.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT }.associate { it.spec["slug"].toString() to it.name }.toMutableMap()
        val sandboxSlugs = reach.environments().filter { it.str("kind") != PRODUCTION_ENV_SLUG && it.str("slug") != PRODUCTION_ENV_SLUG }.mapNotNull { it.str("slug") }
        reachable(OBJECT_TYPE_ENVIRONMENT).forEach { (id, access) ->
            val node = reach.environments().firstOrNull { it.str("id") == id } ?: return@forEach skip("environment:$id — listed as reachable but not in the workspace's environment list")
            val slug = node.str("slug") ?: return@forEach
            if (slug == PRODUCTION_ENV_SLUG || node.str("kind") == PRODUCTION_ENV_SLUG) return@forEach // the production plane is not a declarable resource
            if (declared.any { it.kind == ProvisionFile.KIND_ENVIRONMENT && it.spec["slug"] == slug }) return@forEach
            val name = uniqueName(ProvisionFile.KIND_ENVIRONMENT, slug)
            envName[slug] = name
            add(ProvisionFile.KIND_ENVIRONMENT, name, null, null, id, access, linkedMapOf("slug" to slug, "displayName" to (node.str("name") ?: slug)), mapOf("slug" to slug), owner = ProvisionApi.ownerOf(node))
        }
        /** The environment a per-environment object lives in: the first plane that answers its GET (production first). */
        fun locate(read: (ProvisionApi) -> JsonNode): Pair<String?, JsonNode>? =
            (listOf<String?>(null) + sandboxSlugs).firstNotNullOfOrNull { plane -> fetchOrNull { read(clients(plane)) }?.let { plane to it } }
        fun environmentField(slug: String?): String? = slug?.let { envName[it] ?: it }

        reachable(OBJECT_TYPE_APPLICATION).forEach { (id, access) ->
            if (declared.any { it.kind == ProvisionFile.KIND_APPLICATION && it.spec["clientId"] == id }) return@forEach
            val (plane, n) = locate { it.getApplication(id) } ?: return@forEach skip("application:$id — listed as reachable but not readable in any environment")
            val spec = linkedMapOf<String, Any?>("clientId" to id, "displayName" to (n.str("displayName") ?: id))
            n.str("clientType")?.let { spec["clientType"] = it }
            listOf("grantTypes", "redirectUris", "postLogoutRedirectUris", "scopes").forEach { f -> (plain(n[f] ?: return@forEach) as? List<*>)?.takeIf { it.isNotEmpty() }?.let { spec[f] = it } }
            val confidential = !n.str("clientType").equals("public", ignoreCase = true)
            add(
                ProvisionFile.KIND_APPLICATION, uniqueName(ProvisionFile.KIND_APPLICATION, n.str("displayName") ?: id), environmentField(plane), plane, id, access, spec,
                buildMap { (spec["redirectUris"] as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) } },
                if (confidential && access == Access.MANAGER) "its existing client secret is not recoverable; `thoryn clients rotate-secret $id --secret-file <path>` mints a new one" else null,
                owner = ProvisionApi.ownerOf(n),
            )
        }
        reachable(OBJECT_TYPE_USER).forEach { (id, access) ->
            val (plane, n) = locate { it.getUser(id) } ?: return@forEach skip("user:$id — listed as reachable but not readable in any environment")
            val email = n.str("email") ?: return@forEach skip("user:$id — no email on the live record")
            if (declared.any { it.kind == ProvisionFile.KIND_USER && it.spec["email"].toString().equals(email, ignoreCase = true) }) return@forEach
            val spec = linkedMapOf<String, Any?>("email" to email)
            n["emailVerified"]?.takeIf { it.isBoolean }?.let { spec["emailVerified"] = it.asBoolean() }
            add(ProvisionFile.KIND_USER, uniqueName(ProvisionFile.KIND_USER, email.substringBefore('@')), environmentField(plane), plane, id, access, spec, mapOf("email" to email))
        }
        reachable(OBJECT_TYPE_FEDERATION_MEMBER).forEach { (id, access) ->
            val (plane, n) = locate { it.getFederationMember(id) } ?: return@forEach skip("federation_member:$id — listed as reachable but not readable in any environment")
            if (declared.any { it.kind == ProvisionFile.KIND_FEDERATION_MEMBER && it.spec["displayName"] == n.str("displayName") }) return@forEach
            val spec = linkedMapOf<String, Any?>("providerType" to (n.str("providerType") ?: "oidc"))
            listOf("displayName", "discoveryUrl", "clientId").forEach { f -> n.str(f)?.let { spec[f] = it } }
            add(
                ProvisionFile.KIND_FEDERATION_MEMBER, uniqueName(ProvisionFile.KIND_FEDERATION_MEMBER, n.str("displayName") ?: id), environmentField(plane), plane, id, access, spec,
                buildMap { spec["providerType"]?.toString()?.let { put("providerType", it) } },
                if (access == Access.MANAGER) "its upstream client secret is write-only: add `clientSecretEnv: <VAR>` before an update is converged" else null,
            )
        }
        // The per-environment singletons: the object id IS the environment slug (`production` for the plane without one).
        fun singletonPlane(id: String): String? = if (id == PRODUCTION_ENV_SLUG) null else id.takeIf { it in sandboxSlugs }
        fun singletonDeclared(kind: String, plane: String?): Boolean =
            declared.any { it.kind == kind && (it.environment == plane || (plane != null && it.environment == envName[plane])) }
        reachable(OBJECT_TYPE_EMAIL_PROVIDER).forEach { (id, access) ->
            if (id != PRODUCTION_ENV_SLUG && id !in sandboxSlugs) return@forEach skip("email_provider:$id — no environment with that slug")
            val plane = singletonPlane(id)
            if (singletonDeclared(ProvisionFile.KIND_EMAIL_PROVIDER, plane)) return@forEach
            val n = fetchOrNull { clients(plane).getEmailProvider() } ?: return@forEach
            if (n["configured"]?.asBoolean() == false) return@forEach
            val spec = linkedMapOf<String, Any?>()
            listOf("smtpHost", "smtpUsername", "transportSecurity", "fromAddress", "fromName", "replyTo", "providerType").forEach { f -> n.str(f)?.let { spec[f] = it } }
            n["smtpPort"]?.takeIf { it.isNumber }?.let { spec["smtpPort"] = it.asInt() }
            n["enabled"]?.takeIf { it.isBoolean }?.let { spec["enabled"] = it.asBoolean() }
            if (spec["smtpHost"] == null) return@forEach skip("email_provider:$id — configured without an SMTP host; not a declarable emailProvider")
            add(
                ProvisionFile.KIND_EMAIL_PROVIDER, ProvisionFile.KIND_EMAIL_PROVIDER, environmentField(plane), plane, n.str("providerType") ?: "email-provider", access, spec,
                buildMap { n.str("smtpHost")?.let { put("smtpHost", it) }; n.str("fromAddress")?.let { put("fromAddress", it) } },
                if (access == Access.MANAGER) "the SMTP password is write-only: add `smtpPasswordEnv: <VAR>` before an update is converged" else null,
            )
        }
        reachable(OBJECT_TYPE_LOGIN_THEME).forEach { (id, access) ->
            if (id != PRODUCTION_ENV_SLUG && id !in sandboxSlugs) return@forEach skip("login_theme:$id — no environment with that slug")
            val plane = singletonPlane(id)
            if (singletonDeclared(ProvisionFile.KIND_LOGIN_THEME, plane)) return@forEach
            val stored = fetchOrNull { clients(plane).getLoginBranding() }?.get("stored") ?: return@forEach
            val fields = listOf("logoUrl", "primaryColor", "backgroundColor", "borderRadiusPx", "theme", "cssVariables")
            val spec = stored.toMap(fields).filterValues { it != null && !(it is Map<*, *> && it.isEmpty()) }
            if (spec.isEmpty()) return@forEach // nothing stored ⇒ the platform default ⇒ nothing to declare
            add(ProvisionFile.KIND_LOGIN_THEME, ProvisionFile.KIND_LOGIN_THEME, environmentField(plane), plane, "login-theme", access, spec)
        }
        reachable(OBJECT_TYPE_LOGIN_METHODS).forEach { (id, access) ->
            if (id != PRODUCTION_ENV_SLUG && id !in sandboxSlugs) return@forEach skip("login_methods:$id — no environment with that slug")
            val plane = singletonPlane(id)
            if (singletonDeclared(ProvisionFile.KIND_LOGIN_METHODS, plane)) return@forEach
            val stored = fetchOrNull { clients(plane).getLoginMethods() }?.get("stored")?.takeIf { !it.isNull && it.isArray } ?: return@forEach
            val methods = stored.toList().map { it.asString() }
            add(ProvisionFile.KIND_LOGIN_METHODS, ProvisionFile.KIND_LOGIN_METHODS, environmentField(plane), plane, "login-methods", access, linkedMapOf("methods" to methods), mapOf("methods" to methods.joinToString(",")))
        }
        reachable(OBJECT_TYPE_LOGIN_FLOW).forEach { (id, _) ->
            skipped += "login_flow:$id — a loginFlow is declared by its templateId, which the active flow does not record; declare it by hand"
        }
        reachable(OBJECT_TYPE_CUSTOM_DOMAIN).forEach { (id, access) ->
            if (declared.any { it.kind == ProvisionFile.KIND_CUSTOM_DOMAIN }) return@forEach
            val body = fetchOrNull { clients(null).getCustomDomain() } ?: return@forEach
            val view = CustomDomainView.of(body)
            val host = view.domain?.takeIf { it.isNotBlank() } ?: return@forEach
            if (view.state == CustomDomainView.NONE) return@forEach
            add(
                ProvisionFile.KIND_CUSTOM_DOMAIN, ProvisionFile.KIND_CUSTOM_DOMAIN, null, null, id, access, linkedMapOf("host" to host),
                buildMap { put("host", host); put("state", view.state); view.issuer?.let { put("issuer", it) } },
            )
        }
        return ImportResult(out, skipped)
    }

    // ── apply ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Execute [plan]: creates / updates / adopts in dependency order (environments first), then converges
     * every `grants:` block (SSO-3119 — after all of them exist, so a grant may name any subject the file
     * declares), then prunes. [confirmSlug] is the workspace slug confirming production-plane removals
     * (refused up front when missing). Returns the receipt as it stands after the pass; throws on the
     * first failed step (with everything before it already persisted).
     */
    fun apply(
        file: ProvisionFile,
        receipt: ProvisionReceipt?,
        plan: ProvisionPlan,
        workspace: String?,
        confirmSlug: String?,
        persist: (ProvisionReceipt) -> Unit,
    ): ProvisionReceipt {
        // SSO-3659 — a plan with an ownership error is refused WHOLE, before the first write: a red plan on a
        // pull request must mean "nothing would have happened", and a partial apply would silently own the half
        // this identity may touch.
        if (plan.hasErrors) {
            throw ProvisionException(
                "${plan.errors.size} resource(s) failed the ownership check — nothing was written:\n  " +
                    plan.errors.joinToString("\n  ") { "${it.kind} ${it.name}: ${it.reason}" },
            )
        }
        if (plan.removesOnProductionPlane && confirmSlug.isNullOrBlank()) {
            throw ProvisionException("--prune would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
        }
        val owned = receipt?.resources.orEmpty().toMutableList()
        fun current() = ProvisionReceipt(
            file = ProvisionFileRef(file.source, file.digest),
            appliedAt = now().toString(),
            cliVersion = cliVersion,
            workspace = workspace ?: receipt?.workspace,
            // SSO-3659 — the ownership marker: who applied this receipt (kept from the receipt when unknown here).
            subject = subject ?: receipt?.subject,
            resources = owned.toList(),
        )
        fun record(o: OwnedResource) {
            // Replace IN PLACE so the receipt keeps creation order (destroy removes child-first by it).
            val i = owned.indexOfFirst { it.key == o.key }
            // SSO-3119 — a resource write carries no grants; keep the grant ownership the receipt holds,
            // so dropping a `grants:` block does not silently disown what this file granted.
            // SSO-3668 — likewise the published outputs: the publish pass below sets them explicitly.
            val merged = o.copy(
                grants = if (i >= 0 && o.grants.isEmpty()) owned[i].grants else o.grants,
                published = if (i >= 0 && o.published.isEmpty()) owned[i].published else o.published,
            )
            if (i >= 0) owned[i] = merged else owned += merged
            persist(current())
        }
        /** SSO-3119 — set the owned-grant set EXPLICITLY (it may legitimately become empty). */
        fun recordGrants(key: String, grants: List<String>) {
            val i = owned.indexOfFirst { it.key == key }
            if (i < 0 || owned[i].grants == grants) return
            owned[i] = owned[i].copy(grants = grants)
            persist(current())
        }
        /** SSO-3668 — set what this apply PUBLISHED for a resource EXPLICITLY (only the targets that were reached). */
        fun recordPublished(key: String, published: List<PublishedOutput>) {
            val i = owned.indexOfFirst { it.key == key }
            if (i < 0 || owned[i].published == published) return
            owned[i] = owned[i].copy(published = published)
            persist(current())
        }
        undelivered.clear()
        // SSO-3119 — grants converge in a SECOND pass, after EVERY resource in the file exists.
        // product-api resolves a grant's SUBJECT (`client:<clientId>`, `member:<sub>`) in the workspace
        // before it writes the tuple, and [orderForApply] converges environments ahead of applications —
        // so converging a block inline, the moment its own object resolved, could name a client the same
        // file had not created yet. That earns the opaque 404 of ADR 2026-09-15 §8 (one answer for an
        // unknown object, an unknown subject and insufficient reach), and it DEADLOCKS: a re-run reaches
        // the same grant before the same missing client. Deferring the whole block drops the ordering
        // dependency — a `grants:` block may name anything the file declares, in any order. Ownership is
        // still safe: every resource is recorded in the receipt by the time the pass runs, so a grant
        // failure loses nothing and a re-run converges the outstanding grants alone.
        // The grants THIS FILE already owns per object, from the receipt as it stood before this pass —
        // `record` rewrites the entry from the resource write, which carries no grants (SSO-3119).
        val ownedGrantsByKey = receipt?.resources.orEmpty().associate { it.key to it.grants }
        val pendingGrants = mutableListOf<Pair<ProvisionResource, String>>()
        // SSO-3668 — outputs publish in their own pass too, once the resource is converged and RECORDED (the id
        // is known and already in the receipt), so an unreachable target can never cost the id.
        val pendingPublishes = mutableListOf<Pair<ProvisionResource, String>>()
        plan.changes.filter { it.resource != null }.forEach { change ->
            val r = change.resource!!
            // SSO-3659 — a read-only reference is never written and never owned: a receipt entry from before the
            // file declared it `readOnly` is dropped (disowned, not deleted) so destroy / --prune cannot reach it.
            if (r.readOnly) {
                if (owned.removeIf { it.key == r.key }) {
                    out.println("  = ${r.kind} ${r.name}: read-only reference — dropped from the receipt, left in place")
                    persist(current())
                }
                return@forEach
            }
            val resolved: OwnedResource? = when (change.action) {
                // SSO-3659 — a minted client secret is delivered AFTER the client is recorded: the receipt holds the id before
                // any sink is reached for, so an unreachable sink can never cost the client its entry.
                ChangeAction.CREATE -> create(r, file, owned).let { c -> record(c.owned); c.mintedSecret?.let { deliverSecret(r, c.owned.id, it) }; c.owned }
                ChangeAction.UPDATE -> update(r, file, owned, change).also { record(it) }
                ChangeAction.ADOPT -> adopt(r, file, owned, change).also { record(it) }
                // SSO-3673 — a no-op still refreshes the owner the platform reported (an admin may have moved it since).
                ChangeAction.NOOP -> owned.firstOrNull { it.key == r.key }?.let { o -> if (o.owner == change.owner) o else o.copy(owner = change.owner).also { record(it) } }
                else -> null
            }
            if (r.grants != null && resolved != null) {
                pendingGrants += r to objectRef(r.kind, resolved.id, resolved.environment)
            }
            if (r.publishTo.isNotEmpty() && resolved != null) {
                pendingPublishes += r to resolved.id
            }
        }
        // SSO-3668 — publish AFTER convergence: every resource exists and is in the receipt by now. Failures are
        // collected, not thrown, so the grants and prune below still converge; they end the apply afterwards.
        val publishFailures = mutableListOf<PublishFailure>()
        pendingPublishes.forEach { (r, id) ->
            val reached = mutableListOf<PublishedOutput>()
            r.publishTo.forEach { target ->
                val reason = try {
                    outputSink.publish(target, id)
                } catch (ex: Exception) {
                    ex.message ?: ex.javaClass.simpleName
                }
                if (reason == null) {
                    reached += PublishedOutput.of(target)
                    out.println("  > ${r.kind} ${r.name}: published clientId=$id → ${target.label}")
                } else {
                    publishFailures += PublishFailure(r.key, target, id, reason)
                    err.println("  ! ${r.kind} ${r.name}: could not publish its clientId to ${target.label} ($reason). The client exists and is recorded; by hand: ${target.byHand(id)}")
                }
            }
            recordPublished(r.key, reached)
        }
        pendingGrants.forEach { (r, ref) ->
            recordGrants(r.key, convergeGrants(r, ref, ownedGrantsByKey[r.key].orEmpty()))
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
        // SSO-3668 — raised LAST: the receipt above records every id, so the fallback is one command per target.
        if (publishFailures.isNotEmpty()) throw PublishTargetUnreachableException(publishFailures, result)
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

    /**
     * What exists live for a declared resource: its id, the non-secret fields that differ from [desired], and
     * (SSO-3673) the platform `owner` its response renders, if any.
     */
    private class Live(val id: String, val diff: Map<String, String>, val attributes: Map<String, String> = emptyMap(), val owner: String? = null)

    private fun lookup(r: ProvisionResource, owned: OwnedResource?, slug: String?, desired: Map<String, Any?>): Live? = when (r.kind) {
        ProvisionFile.KIND_ENVIRONMENT -> {
            val wanted = desired["slug"].toString()
            val node = listItems(clients(null).listEnvironments(), "environments").firstOrNull { it.str("slug") == wanted }
            node?.let { n ->
                val diff = diffOf(mapOf("displayName" to desired["displayName"]), mapOf("displayName" to n.str("name")))
                Live(n.str("id") ?: wanted, diff, mapOf("slug" to wanted), owner = ProvisionApi.ownerOf(n))
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
                Live(n.str("clientId") ?: n.str("client_id") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)), owner = ProvisionApi.ownerOf(n))
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

    /** A created resource and — for a confidential application — the one-time secret the create response carried. */
    private class Created(val owned: OwnedResource, val mintedSecret: String? = null)

    private fun create(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>): Created {
        val spec = resolveSpec(r, strict = true)
        if (r.kind == ProvisionFile.KIND_APPLICATION) return createApplication(r, file, owned, spec)
        return Created(when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                val slug = spec["slug"].toString()
                val body = mapOf("slug" to slug, "name" to (spec["displayName"]?.toString()?.takeIf { it.isNotBlank() } ?: slug))
                val resp = clients(null).createEnvironment(body)
                val id = resp.str("id") ?: throw ProvisionException("${r.key}: the environment create returned no id")
                val liveSlug = resp.str("slug") ?: slug
                out.println("  + environment ${r.name}: id=$id slug=$liveSlug")
                OwnedResource(r.kind, r.name, id, environment = null, attributes = mapOf("slug" to liveSlug), owner = ProvisionApi.ownerOf(resp))
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
            ProvisionFile.KIND_CUSTOM_DOMAIN -> claimCustomDomain(r, spec)
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        })
    }

    private fun createApplication(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>, spec: Map<String, Any?>): Created {
        val slug = targetSlug(r, file, owned)
        val resp = clients(slug).createApplication(spec)
        val id = resp.str("clientId") ?: resp.str("client_id") ?: throw ProvisionException("${r.key}: the application create returned no clientId")
        // SSO-3113 — the ONE server-minted secret goes to a sink and NOWHERE else: never a field, the receipt, the
        // plan, the console, or a log. The response node is not retained. SSO-3659 — it is handed back to [apply],
        // which delivers it only once the client is RECORDED ([deliverSecret]).
        val secret = (resp.str("clientSecret") ?: resp.str("client_secret"))?.takeIf { it.isNotEmpty() }
        val note = when {
            secret == null -> ""
            r.secretSink != null -> " (client secret minted)"
            else -> " (client secret minted — shown once)"
        }
        out.println("  + application ${r.name}: clientId=$id${slug?.let { " env=$it" } ?: ""}$note")
        // SSO-3673 — the owner the create established (creator-becomes-owner for a `client:` caller), as reported.
        val created = OwnedResource(r.kind, r.name, id, slug, buildMap {
            (spec["redirectUris"] as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) }
        }, owner = ProvisionApi.ownerOf(resp))
        return Created(created, secret)
    }

    /**
     * SSO-3659 (ADR 2026-10-13 §5) — deliver a minted client secret, called by [apply] right AFTER the client is
     * recorded: first the declared `secretSink:` through [declaredSecretSink] (a reason ⇒ not delivered, printed
     * redacted of the value), then the host's generic [secretSink] (`--secret-file` / guarded TTY). When neither
     * reaches, the client stays (it exists and is owned) and lands on [undeliveredSecretDetails] with the recovery.
     */
    private fun deliverSecret(r: ProvisionResource, clientId: String, secret: String) {
        fun redact(text: String?): String = (text ?: "unknown failure").replace(secret, "[redacted]")
        val target = r.secretSink
        var reason: String? = null
        if (target != null) {
            reason = try {
                declaredSecretSink.deliver(target, clientId, secret)
            } catch (ex: Exception) {
                ex.message ?: ex.javaClass.simpleName
            }
            if (reason == null) {
                out.println("  > application ${r.name}: client secret delivered → ${target.label}")
                return
            }
            err.println("  ! application ${r.name}: could not deliver its client secret to ${target.label} (${redact(reason)})")
        }
        val delivered = try {
            secretSink.emit(clientId, secret)
        } catch (ex: Exception) {
            reason = reason ?: ex.message ?: ex.javaClass.simpleName
            false
        }
        if (delivered) return
        undelivered += UndeliveredSecret(r.key, clientId, target, redact(reason ?: "no secret channel is available"))
        err.println(
            "  ! application ${r.name}: $ERROR_UNDELIVERED_SECRETS — its client secret was minted but could NOT be delivered (clientId $clientId). " +
                "The client exists and is owned; mint a new secret with `${recoverSecret(clientId)}`.",
        )
    }

    /** Converge an existing resource: send exactly the changed (non-secret) fields plus any write-only secret. */
    private fun update(r: ProvisionResource, file: ProvisionFile, owned: List<OwnedResource>, change: PlannedChange): OwnedResource {
        val spec = resolveSpec(r, strict = true)
        val id = change.liveId ?: throw ProvisionException("${r.key}: update planned without a live id")
        val changed = spec.filterKeys { it in change.diff.keys }
        val slug = if (r.kind == ProvisionFile.KIND_ENVIRONMENT) null else targetSlug(r, file, owned)
        val base = OwnedResource(r.kind, r.name, id, slug, adopted = change.adopted, owner = change.owner)
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
            ProvisionFile.KIND_CUSTOM_DOMAIN -> verifyDomain(r, spec).copy(adopted = change.adopted)
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
            ProvisionFile.KIND_CUSTOM_DOMAIN -> mapOf("host" to hostOf(resolved))
            else -> emptyMap()
        }
        return OwnedResource(r.kind, r.name, id, slug, attributes, adopted = true, owner = change.owner)
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

    // ── customDomain (SSO-3413 / SSO-3414) ───────────────────────────────────────────────────────

    /**
     * SSO-3413 — the workspace's ONE custom domain, read LIVE (`GET /api/v1/custom-domain`) and converged by
     * claim + verify rather than by a field diff:
     *
     * | Live | Action | `apply` does |
     * |---|---|---|
     * | no domain (`NONE`) | create | claims `spec.host` (`PUT`), then verifies once |
     * | `spec.host`, `PENDING` / `SUSPENDED` | update | verifies the DNS records (`POST /verify`) |
     * | `spec.host`, `VERIFIED` / `ACTIVE`, not yet in the receipt | adopt | nothing (recorded, never released) |
     * | `spec.host`, `VERIFIED` / `ACTIVE`, owned | noop | nothing |
     * | another host | — | refuses: moving the issuer to another host is a deliberate `thoryn domain remove` first |
     *
     * A failing DNS proof is NOT an apply failure — the records are the customer's to publish, and DNS takes
     * a while to propagate: the change reports the state and the reason, and a re-run (or `--wait`) converges.
     * A workspace without the operator entitlement is planned but stops `apply` with the operator step named
     * ([CustomDomainMessages.NOT_ENTITLED]); an identity with no reach gets the grant it needs
     * named ([CustomDomainMessages.NO_ACCESS]).
     */
    private fun probeCustomDomain(r: ProvisionResource, owned: OwnedResource?): PlannedChange {
        val host = hostOf(resolveSpec(r, strict = false))
        val body = try {
            clients(null).getCustomDomain()
        } catch (ex: ProductApiException) {
            if (ex.httpStatus == 404) throw ProvisionException("${r.key}: ${CustomDomainMessages.NO_ACCESS}")
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        val view = CustomDomainView.of(body)
        val id = customDomainId()
        val details = view.toStructured() + ("desiredHost" to host)
        return when {
            view.state == CustomDomainView.NONE && !view.entitled -> PlannedChange(
                r.kind, r.name, ChangeAction.CREATE,
                "claim $host — NOT ENTITLED: ${CustomDomainMessages.NOT_ENTITLED} (apply stops here until then)",
                resource = r, owned = owned, customDomain = details,
            )
            view.state == CustomDomainView.NONE -> PlannedChange(
                r.kind, r.name, ChangeAction.CREATE,
                (if (owned != null) "owned domain no longer exists — " else "") +
                    "claim $host and verify it (the claim issues the TXT ownership value; the CNAME points at ${view.cnameTarget ?: "the platform host"})",
                resource = r, owned = owned, customDomain = details + ("records" to plannedRecords(host, view)),
            )
            !view.domain.equals(host, ignoreCase = true) -> throw ProvisionException(
                "${r.key}: the workspace already has the custom domain '${view.domain}' (${view.state}), not '$host'. " +
                    "A workspace has one domain and moving it changes the issuer; remove the current one deliberately " +
                    "(`thoryn domain remove`) or declare '${view.domain}'.",
            )
            view.state in CustomDomainView.VERIFIABLE -> PlannedChange(
                r.kind, r.name, ChangeAction.UPDATE,
                "${view.state}${view.lastCheckReason?.let { " ($it)" } ?: ""} — apply verifies the DNS records" +
                    (view.releaseAt?.let { "; released at $it unless it verifies before" } ?: ""),
                resource = r, owned = owned, liveId = id, diff = mapOf("state" to "${view.state} → verify"),
                adopted = owned?.adopted ?: true, customDomain = details,
            )
            owned == null -> PlannedChange(
                r.kind, r.name, ChangeAction.ADOPT,
                "exists (${view.state}) — adopted under management (never released by destroy)",
                resource = r, liveId = id, adopted = true, customDomain = details,
            )
            else -> PlannedChange(
                r.kind, r.name, ChangeAction.NOOP, "owned and ${view.state}",
                resource = r, owned = owned, liveId = id, adopted = owned.adopted, customDomain = details,
            )
        }
    }

    /** Before the claim only the CNAME is known (the TXT value is minted by the claim); after it, the live records. */
    private fun plannedRecords(host: String, view: CustomDomainView): List<Map<String, Any>> =
        view.records.map { it.toStructured() }.ifEmpty {
            listOfNotNull(view.cnameTarget?.let { DnsRecord("CNAME", host, it, DnsRecord.DEFAULT_TTL_SECONDS).toStructured() })
        }

    /** `PUT /api/v1/custom-domain`, then one verify attempt. */
    private fun claimCustomDomain(r: ProvisionResource, spec: Map<String, Any?>): OwnedResource {
        val host = hostOf(spec)
        val claimed = try {
            clients(null).putCustomDomain(host, coerceBool(spec["acceptReSignIn"]))
        } catch (ex: ProductApiException) {
            throw customDomainFailure(r, ex)
        }
        out.println("  + customDomain: claimed $host (${CustomDomainView.of(claimed).state})")
        printDomainRecords(claimed)
        return verifyDomain(r, spec, after = claimed)
    }

    /**
     * `POST /api/v1/custom-domain/verify` while the domain is `PENDING` / `SUSPENDED`. A failing proof
     * (`422 verification_failed`) or an inconclusive resolver (`503 dns_unavailable`) is reported, not thrown.
     */
    private fun verifyDomain(r: ProvisionResource, spec: Map<String, Any?>, after: JsonNode? = null): OwnedResource {
        val host = hostOf(spec)
        val client = clients(null)
        var body = after ?: client.getCustomDomain()
        if (CustomDomainView.of(body).state in CustomDomainView.VERIFIABLE) {
            body = try {
                client.verifyCustomDomain()
            } catch (ex: ProductApiException) {
                when (ex.errorCode) {
                    "verification_failed" -> {
                        val reason = CustomDomainMessages.problemReason(ex)
                        out.println(
                            "  ~ customDomain: $host — DNS does not prove the claim yet: ${CustomDomainMessages.reasonText(reason)} " +
                                "Publish the records, then re-run (or add --wait).",
                        )
                        client.getCustomDomain()
                    }
                    "dns_unavailable" -> {
                        out.println("  ~ customDomain: $host — DNS could not be checked right now; nothing changed. Re-run to verify.")
                        client.getCustomDomain()
                    }
                    else -> throw customDomainFailure(r, ex)
                }
            }
        }
        val view = CustomDomainView.of(body)
        out.println("  = customDomain: $host is ${view.state}; the workspace issues on ${view.issuer ?: "its platform host"}")
        return OwnedResource(r.kind, r.name, customDomainId(), null, buildMap {
            put("host", host)
            put("state", view.state)
            view.issuer?.let { put("issuer", it) }
        })
    }

    private fun printDomainRecords(body: JsonNode) {
        val records = CustomDomainView.of(body).records
        if (records.isEmpty()) return
        out.println("    DNS records to publish at your DNS provider:")
        records.forEach { out.println("      ${it.type}  ${it.name}  ${it.value}  (ttl ${it.ttl})") }
    }

    /** The custom-domain refusals, each with what to do next. */
    private fun customDomainFailure(r: ProvisionResource, ex: ProductApiException): ProvisionException = ProvisionException(
        "${r.key}: " + when (ex.errorCode) {
            "entitlement_required" -> CustomDomainMessages.NOT_ENTITLED
            "custom_domain_not_found" -> CustomDomainMessages.NO_ACCESS
            "production_users_present" ->
                "the workspace already has production users, so a custom domain makes each of them sign in again once. " +
                    "Accept that explicitly with `acceptReSignIn: true` in the resource's spec and re-run."
            "domain_not_allowed", "invalid_domain" -> "the host is not allowed (${ex.errorDescription ?: ex.errorCode}); use a subdomain you control, e.g. auth.<your-domain>."
            "domain_taken" -> "the host is already in use by another workspace."
            "custom_domain_exists" -> "the workspace already has another custom domain; remove it first (`thoryn domain remove`)."
            "claim_expired" -> "the claim expired before it was verified; re-run to claim it again and publish the new TXT value."
            else -> ex.message ?: "the custom-domain API refused the request"
        },
    )

    /** The receipt id of the workspace-level singleton: the workspace id (`tnt`), else a stable placeholder. */
    private fun customDomainId(): String = workspaceId?.takeIf { it.isNotBlank() } ?: CUSTOM_DOMAIN_FALLBACK_ID

    private fun hostOf(spec: Map<String, Any?>): String =
        spec["host"]?.toString()?.trim()?.trimEnd('.')?.lowercase()?.takeIf { it.isNotEmpty() }
            ?: throw ProvisionException("customDomain: spec.host is required")

    // ── grants (SSO-3113) ────────────────────────────────────────────────────────────────────────

    /** The live grants on [ref] as `<subject> <relation>` labels (the product-api ListEnvelope: the array is under `data`). */
    private fun liveGrants(r: ProvisionResource, ref: String): List<String> = try {
        listItems(clients(null).listGrants(objectRef = ref), "data")
            .mapNotNull { g -> g.str("subject")?.let { s -> g.str("relation")?.let { rel -> "$s $rel" } } }
    } catch (ex: ProductApiException) {
        throw grantFailure(r, ex, AccessRefs.SCOPE_READ, "read the grants on $ref")
    }

    /**
     * Adds = declared but not live.
     *
     * Removes = live, no longer declared, AND previously granted by THIS FILE ([owned], carried on the
     * receipt) — SSO-3119. A `grants:` block converges what it placed itself, never what it merely found:
     * the creator's own `member:<sub> manager` (SSO-3110 creator-becomes-manager) and any grant an admin
     * made by hand survive an apply that does not mention them. Same rule [OwnedResource.adopted] states
     * for resources; without it a CI apply would silently revoke the human who created the sandbox. The
     * workspace admin userset (`workspace:<id>#admin`) stays excluded besides, as defence in depth.
     */
    private fun grantDiff(declared: List<ProvisionGrant>, live: List<String>, owned: List<String>): Pair<List<String>, List<String>> {
        val wanted = declared.map { it.label }.distinct()
        val have = live.distinct()
        val adds = wanted.filter { it !in have }
        val removes = have.filter {
            it !in wanted && it in owned && !AccessRefs.ADMIN_USERSET_PATTERN.matches(it.substringBefore(' '))
        }
        return adds to removes
    }

    /**
     * Converge the `grants:` block on ONE object: list, POST the missing, DELETE the undeclared ones this
     * file granted itself. Returns the grants the file owns AFTERWARDS — what it just POSTed, plus what it
     * already owned and still declares and is still live — for the receipt (SSO-3119).
     */
    private fun convergeGrants(r: ProvisionResource, ref: String, owned: List<String>): List<String> {
        val declared = r.grants ?: return owned
        val live = liveGrants(r, ref)
        val (adds, removes) = grantDiff(declared, live, owned)
        val wanted = declared.map { it.label }.distinct()
        val nextOwned = (owned.filter { it in live && it in wanted } + adds).distinct()
        if (adds.isEmpty() && removes.isEmpty()) return nextOwned
        val client = clients(null)
        try {
            adds.forEach { label ->
                val (subject, relation) = label.split(' ', limit = 2)
                client.createGrant(subject, relation, ref)
                out.println("  + grant ${r.kind} ${r.name}: $subject $relation on $ref")
            }
            removes.forEach { label ->
                val (subject, relation) = label.split(' ', limit = 2)
                client.deleteGrant(subject, relation, ref)
                out.println("  - grant ${r.kind} ${r.name}: $subject $relation on $ref (no longer declared)")
            }
        } catch (ex: ProductApiException) {
            throw grantFailure(r, ex, AccessRefs.SCOPE_WRITE, "converge the grants on $ref")
        }
        return nextOwned
    }

    /** Fail closed: a 403 `insufficient_scope` on the access API names the missing scope and the login line. */
    private fun grantFailure(r: ProvisionResource, ex: ProductApiException, scope: String, what: String): ProvisionException =
        if (ex.isInsufficientScope) {
            ProvisionException(
                "${r.key}: could not $what — this session lacks the '$scope' scope (${ex.message}). " +
                    "Grants are NOT converged; sign in with `thoryn login --scope $scope` (or grant the CI client that scope) and re-run.",
            )
        } else {
            ProvisionException("${r.key}: could not $what (${ex.message})")
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
            ProvisionFile.KIND_CUSTOM_DOMAIN -> {
                // SSO-3413 — reached only through `--prune` / `destroy`, both production-plane gated by `--confirm`.
                clients(null).deleteCustomDomain()
                out.println("  - customDomain: released ${o.attributes["host"] ?: ""} — the workspace issues on its platform host again")
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
        /** The production plane's environment slug (mirrors oathy `core` `TrustedTenantIssuers.PRODUCTION_ENV_SLUG`). */
        const val PRODUCTION_ENV_SLUG: String = "production"

        val ENV_NAME_PATTERN = Regex("^[A-Za-z_][A-Za-z0-9_]*$")

        /** SSO-3413 — the customDomain receipt id when the session carries no `tnt` (grants then cannot name it). */
        const val CUSTOM_DOMAIN_FALLBACK_ID = "custom-domain"

        // ── SSO-3659 — the ownership gate's vocabulary (ADR 2026-10-13 §1) ──

        /** The resource may only be viewed (or is declared `readOnly`) and the file would change it. */
        const val ERROR_READ_ONLY = "access_read_only"
        /** No relation on the resource, or no `manager` on the parent a create needs. */
        const val ERROR_NOT_OWNED = "access_not_owned"
        /**
         * SSO-3673 — the PLATFORM says another identity owns the resource: its response renders an `owner` and
         * `POST /api/v1/access/check {object, relation: owner}` is false for this one. Declare it `readOnly: true`.
         */
        const val ERROR_OWNED_ELSEWHERE = "access_owned_elsewhere"

        /**
         * SSO-3668 — an output's `publishTo:` target could not be reached by the signed-in credential; raised
         * AFTER convergence (the resource exists and its id is in the receipt), never a refusal before it.
         */
        const val ERROR_PUBLISH_UNREACHABLE = "publish_target_unreachable"

        /**
         * SSO-3659 (ADR 2026-10-13 §5) — a minted client secret reached neither its declared `secretSink:` nor the
         * host's generic channel. Reported AFTER the client is converged and recorded; the recovery is [recoverSecret].
         */
        const val ERROR_UNDELIVERED_SECRETS = "undelivered_secrets"

        /** The one command a human runs for a client whose secret was not delivered (ADR production-clients §3 tier 3). */
        fun recoverSecret(clientId: String): String = "thoryn clients rotate-secret $clientId --secret-file <path>"

        const val RELATION_MANAGER = AccessRefs.RELATION_MANAGER
        const val RELATION_VIEWER = AccessRefs.RELATION_VIEWER
        /** SSO-3673 — the platform's one-owner relation on `application` / `environment` (never declared in a file). */
        const val RELATION_OWNER = AccessRefs.RELATION_OWNER

        /** The platform object types (`GET /api/v1/access/mine?type=…`); the per-kind mapping is [objectRef]. */
        const val OBJECT_TYPE_WORKSPACE = "workspace"
        const val OBJECT_TYPE_ENVIRONMENT = "environment"
        const val OBJECT_TYPE_APPLICATION = "application"
        const val OBJECT_TYPE_USER = "user"
        const val OBJECT_TYPE_FEDERATION_MEMBER = "federation_member"
        const val OBJECT_TYPE_EMAIL_PROVIDER = "email_provider"
        const val OBJECT_TYPE_LOGIN_THEME = "login_theme"
        const val OBJECT_TYPE_LOGIN_FLOW = "login_flow"
        const val OBJECT_TYPE_LOGIN_METHODS = "login_methods"
        const val OBJECT_TYPE_CUSTOM_DOMAIN = "custom_domain"

        /**
         * A platform id as `/api/v1/access/mine` renders it is percent-encoded (`@`, `#`, whitespace — the
         * SSO-3123 `PlatformRefs.encodeId` mapping); the product id the engine compares against is the raw form.
         */
        fun decodePlatformId(encoded: String): String {
            if (!encoded.contains('%')) return encoded
            val bytes = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < encoded.length) {
                val c = encoded[i]
                if (c == '%' && i + 2 < encoded.length && encoded[i + 1].isHexDigit() && encoded[i + 2].isHexDigit()) {
                    bytes.write(encoded.substring(i + 1, i + 3).toInt(16)); i += 3
                } else {
                    bytes.write(c.toString().toByteArray(Charsets.UTF_8)); i++
                }
            }
            return bytes.toByteArray().toString(Charsets.UTF_8)
        }

        private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

        /** A resource name ([ProvisionFile.NAME_PATTERN]) derived from a display name / slug / email local part. */
        fun slugName(raw: String): String = raw.lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .take(63)
            .trimEnd('-')
        val ENV_PLACEHOLDER = Regex("""\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*}}""")

        /** Kinds the customer plane can delete; `loginTheme` / `loginFlow` have no delete surface (`loginMethods` resets via DELETE, SSO-3100). */
        fun deletable(kind: String): Boolean = kind !in setOf(ProvisionFile.KIND_LOGIN_THEME, ProvisionFile.KIND_LOGIN_FLOW)

        /** Owned, created by this file (not adopted), and of a deletable kind. */
        fun removable(o: OwnedResource): Boolean = !o.adopted && deletable(o.kind)

        /** An owned non-environment resource with no sandbox slug lives on the production plane. */
        fun onProductionPlane(o: OwnedResource): Boolean =
            o.kind != ProvisionFile.KIND_ENVIRONMENT &&
                (o.environment.isNullOrBlank() || o.environment == PRODUCTION_ENV_SLUG)

        /**
         * SSO-3113 — the access-API OBJECT ref of an owned resource, derived from its receipt id (the
         * SSO-3112 contract): `environment:<id>`, `application:<clientId>`, `user:<id>`,
         * `federation_member:<id>`; the per-environment singletons are keyed by their environment SLUG
         * (`email_provider:<envSlug>`, `login_theme:<envSlug>`, `login_flow:<envSlug>`,
         * `login_methods:<envSlug>`; the production plane ⇒ `production`); SSO-3413 — the workspace's
         * custom domain is `custom_domain:<workspaceId>`.
         */
        fun objectRef(kind: String, id: String, environmentSlug: String?): String {
            val envSlug = environmentSlug?.takeIf { it.isNotBlank() } ?: PRODUCTION_ENV_SLUG
            return when (kind) {
                ProvisionFile.KIND_ENVIRONMENT -> "environment:$id"
                ProvisionFile.KIND_APPLICATION -> "application:$id"
                ProvisionFile.KIND_USER -> "user:$id"
                ProvisionFile.KIND_FEDERATION_MEMBER -> "federation_member:$id"
                ProvisionFile.KIND_EMAIL_PROVIDER -> "email_provider:$envSlug"
                ProvisionFile.KIND_LOGIN_THEME -> "login_theme:$envSlug"
                ProvisionFile.KIND_LOGIN_FLOW -> "login_flow:$envSlug"
                ProvisionFile.KIND_LOGIN_METHODS -> "login_methods:$envSlug"
                // SSO-3413 — the workspace-level singleton; its receipt id IS the workspace id (`tnt`).
                ProvisionFile.KIND_CUSTOM_DOMAIN -> "custom_domain:$id"
                else -> throw ProvisionException("$kind: no access object type for this kind")
            }
        }
    }
}
