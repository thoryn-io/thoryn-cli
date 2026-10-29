package com.devnow.thoryn.provision

import tools.jackson.databind.JsonNode
import java.io.File
import java.io.PrintStream

/**
 * [ERROR] (SSO-3659) is a per-resource VERDICT, not a step: the declared resource failed the ownership
 * gate (`access_read_only` / `access_not_owned` / `access_owned_elsewhere`, see [PlannedChange.error]), its plane
 * is not reachable by this identity at all (SSO-3722, `access_not_reachable`: the live read answered 404), or
 * (SSO-3715) its converge key is ambiguous (`converge_key_ambiguous`). A plan carrying one is red (non-zero
 * exit) and `apply` refuses it before writing anything.
 *
 * SSO-3715 (ADR 2026-10-15 platform-is-the-ledger §1) — `ADOPT` is gone from the vocabulary: a live match is
 * [NOOP] ("exists and matches") or [UPDATE]; the first apply of an existing resource is not an event.
 */
enum class ChangeAction { CREATE, UPDATE, NOOP, REMOVE, SKIP, ERROR }

/** SSO-3659 — the relation the signed-in identity holds on a live platform object (ADR 2026-10-13 §1). */
enum class Access(val label: String) { MANAGER("manager"), VIEWER("viewer"), NONE("none") }

/** One row of a plan: what `apply` / `destroy` would do to a resource, why, and (for updates) which fields change. */
data class PlannedChange(
    val kind: String,
    val name: String,
    val action: ChangeAction,
    val reason: String,
    val resource: ProvisionResource? = null,
    /** SSO-3089 — the live id the resource resolved to by its converge key (null for a create). */
    val liveId: String? = null,
    /**
     * SSO-3715 — the environment SLUG the live resource lives in (`null` ⇒ the production plane; an `environment`
     * resource records its own slug under [attributes]). Rendered as `environment` by `--output json` so a workflow
     * reads where an id lands from the plan / apply output — there is no receipt.
     */
    val environment: String? = null,
    /**
     * SSO-3715 — non-secret attributes of the live resource a reader needs next to its id (`slug` of an environment,
     * `email` of a user, `clientId` of a trust's workload client, the first `redirectUri`); never a key or a secret.
     */
    val attributes: Map<String, String> = emptyMap(),
    /** SSO-3089 — for UPDATE: field → "old → new" (non-secret fields only). */
    val diff: Map<String, String> = emptyMap(),
    /** SSO-3113 — grants (`<subject> <relation>`) the file declares on this object that do not exist live. */
    val grantAdds: List<String> = emptyList(),
    /**
     * SSO-3113 / SSO-3715 (ADR 2026-10-15 §2) — grants live on this object that the file does not declare and that
     * `apply --prune` WILL revoke: only on an object the caller may delete ([mayRemove]), never the `owner` tuple, a
     * workspace userset (`workspace:…`) or the caller's own subject.
     */
    val grantRemoves: List<String> = emptyList(),
    /**
     * SSO-3715 (ADR 2026-10-15 §2) — grants live on this object that the file does not declare and that this run
     * leaves in place: "present, not declared" (informational, never red). Without `--prune` every undeclared
     * grant lands here; with it, the ones the exclusions keep (owner / workspace userset / self) and every one on an
     * object the caller may not delete.
     */
    val grantUndeclared: List<String> = emptyList(),
    /**
     * SSO-3413 / SSO-3414 — a `customDomain`'s live view: host, state, entitlement, the issuer in use, and
     * the DNS records to publish as `{type, name, value, ttl}` ([DnsRecord]).
     */
    val customDomain: Map<String, Any?>? = null,
    /**
     * SSO-3659 — the relation the signed-in identity holds on the live object (`manager` / `viewer` /
     * `none`), or `manager` for a create whose parent it manages. Null for a remove / skip row.
     */
    val access: String? = null,
    /** SSO-3659 — the file declares this resource `readOnly: true` (a dependency; never owned, never removed). */
    val readOnly: Boolean = false,
    /** SSO-3715 — the file declares this resource `retain: true`: converged and owned, never removed by destroy / --prune. */
    val retain: Boolean = false,
    /** SSO-3659 — the gate's error code when [action] is [ChangeAction.ERROR] (`access_*`, `converge_key_ambiguous`), else null. */
    val error: String? = null,
    /**
     * SSO-3673 — the platform `owner` of the live object as its response renders it (`owner.subject`), or null
     * when the platform reports none (or the kind renders none).
     */
    val owner: String? = null,
    /**
     * SSO-3715 — on a removal row that is refused or left to a person ([ChangeAction.SKIP] in a destroy / prune plan):
     * the command a human would run instead, or null when the row needs no command (retained, removed with its sandbox).
     */
    val byHand: String? = null,
    /**
     * SSO-3668 — the outputs `apply` will PUBLISH this resource's id to once it is converged (every apply, an
     * upsert). Shown as a line of the plan — a pull-request check shows where the id will land — and never
     * written by `plan`. Empty on an [ChangeAction.ERROR] row and on a read-only reference.
     */
    val publishTo: List<PublishTarget> = emptyList(),
    /**
     * SSO-3659 (ADR 2026-10-13 §5) — where `apply` will DELIVER the client secret this CREATE mints, the moment the
     * client is converged. Shown as a line of the plan (a pull-request check shows where the secret will land);
     * nothing is minted by `plan`. Only on a CREATE of a confidential application that mints a secret: its declared sink,
     * or — with none declared — [SecretTarget.CUSTOMER_MANAGED] (SSO-3954, the default: the create's value is discarded and
     * a person mints the secret). SSO-3921 — a `workloadPull` sink (DEPRECATED, SSO-3951) is shown on EVERY converging row of
     * its application (nothing is delivered; the line says who pulls the secret at runtime), with the workload client in
     * [pullClientId].
     */
    val secretSink: SecretTarget? = null,
    /**
     * SSO-3921 — on a `workloadPull` row: the `wi_` workload client of the named trust, which holds (or `apply` grants)
     * `manager` on the application so its pod can mint the secret. Null while the trust is created by this apply.
     */
    val pullClientId: String? = null,
    /**
     * SSO-3689 — a `workloadIdentityTrust`'s live view when it exists (`id`, `clientId` — the `wi_…` workload client,
     * `audience`, `tokenEndpoint`, `provider`, `scopes`, the provider's pins): what a plan shows and what `apply`
     * renders the consumer's `connection.json` from. Null for a trust that does not exist yet.
     */
    val trust: Map<String, Any?>? = null,
    /**
     * SSO-3710 — on an `access_*` [ChangeAction.ERROR] row: the RIGHT that is missing and the command that grants it
     * ([FixRequest.MissingRight]), the structured twin of the hint the [reason] already carries in prose — the one
     * rendering, so a fix request written from this plan says exactly what the terminal said. Null on a row whose
     * fix is a change to the FILE (a differing read-only reference, a trust the file cannot declare); see [fixNote].
     */
    val fix: FixRequest.MissingRight? = null,
    /** SSO-3710 — on an `ERROR` row with no [fix]: why no right would fix it (a file fix), for the request's `notes`. */
    val fixNote: String? = null,
    /**
     * SSO-3792 (oauthy ADR 2026-10-17 §6) — on a [ChangeAction.CREATE] of an application this identity may not create on
     * its own reach: the unexpired CREATION SLOT a workspace admin reserved for exactly this client id on exactly this
     * plane, which product-api consumes at apply. Null on every other row.
     */
    val reservation: CreationSlot? = null,
) {
    val hasGrantChanges: Boolean get() = grantAdds.isNotEmpty() || grantRemoves.isNotEmpty()

    /** `<kind>/<name>` — the file's key of this row. */
    val key: String get() = "$kind/$name"

    /** SSO-3715 — a non-environment resource with no sandbox slug lives on the production plane. */
    val onProductionPlane: Boolean get() = kind != ProvisionFile.KIND_ENVIRONMENT && (environment.isNullOrBlank() || environment == ProvisionEngine.PRODUCTION_ENV_SLUG)

    fun toStructured(): Map<String, Any?> = buildMap {
        put("kind", kind); put("name", name); put("action", action.name.lowercase()); put("reason", reason)
        liveId?.let { put("id", it) }
        // SSO-3715 — the plane as a workflow needs it: `environment` is the slug (null ⇒ production), so an
        // `environment` resource's own slug rides on `attributes.slug` exactly as `apply --output json` renders it.
        if (kind != ProvisionFile.KIND_ENVIRONMENT) put("environment", environment)
        if (attributes.isNotEmpty()) put("attributes", attributes)
        if (diff.isNotEmpty()) put("diff", diff)
        if (hasGrantChanges) put("grants", mapOf("add" to grantAdds, "remove" to grantRemoves))
        if (grantUndeclared.isNotEmpty()) put("grantsUndeclared", grantUndeclared)
        customDomain?.let { put("customDomain", it) }
        access?.let { put("access", it) }
        if (readOnly) put("readOnly", true)
        if (retain) put("retain", true)
        error?.let { put("error", it) }
        owner?.let { put("owner", it) }
        byHand?.let { put("byHand", it) }
        if (publishTo.isNotEmpty()) {
            put("publishTo", publishTo.map { mapOf("kind" to it.kind, "repository" to it.repository, "environment" to it.environment, "name" to it.name) })
        }
        secretSink?.let { put("secretSink", it.toStructured() + (pullClientId?.let { id -> mapOf("workloadClientId" to id) } ?: emptyMap())) }
        trust?.let { put("trust", it) }
        fix?.let { put("fix", it.toStructured()) }
        reservation?.let { put("reservation", it.toStructured()) }
    }
}

/**
 * SSO-3792 (oauthy ADR 2026-10-17 §2 / §6) — one application creation slot as the plan uses it: the application
 * ([clientId], raw), the plane ([environment], `production` for the production plane), and when it stops admitting the
 * create ([expiresAt], ISO-8601 as product-api renders it). Only an UNEXPIRED slot held by the planning identity is ever
 * attached to a row.
 */
data class CreationSlot(val clientId: String, val environment: String, val expiresAt: String?) {
    fun toStructured(): Map<String, Any?> = linkedMapOf(
        "object" to FixRequest.applicationRef(clientId),
        "environment" to environment,
        "expiresAt" to expiresAt,
    )
}

class ProvisionPlan(val changes: List<PlannedChange>) {
    val creates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.CREATE }
    val updates: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.UPDATE }
    val removes: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.REMOVE }
    /** SSO-3715 — rows a destroy / prune plan leaves in place (retained, refused, left to a person, removed with their sandbox). */
    val skips: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.SKIP }
    /** SSO-3113 — resources whose grants differ (a no-op resource can still carry grant changes). */
    val grantChanges: Int get() = changes.sumOf { it.grantAdds.size + it.grantRemoves.size }
    /**
     * SSO-3668 — outputs `apply` will publish (an upsert on EVERY apply, so a no-op resource with a `publishTo:`
     * still gives `apply` something to do — that is what makes a re-created client propagate, and a re-run
     * repair a variable someone changed by hand).
     */
    val publishes: Int get() = changes.sumOf { it.publishTo.size }
    /** SSO-3659 — client secrets `apply` will mint AND deliver to a declared `secretSink:` (a CREATE each; never by plan). */
    val deliveries: Int get() = changes.count { it.secretSink != null && !it.secretSink.discardsMintedSecret }
    /** SSO-3921 — applications whose secret a workload pulls at runtime (`secretSink: { kind: workloadPull }`): nothing is delivered. */
    val runtimePulls: Int get() = changes.count { it.secretSink?.runtimePull == true }
    /**
     * SSO-3954 — CREATEs whose client secret the CUSTOMER manages (`secretSink: { kind: customerManaged }`, or no sink — the
     * default): `apply` discards the minted value and a person mints the one the runtime gets.
     */
    val customerManaged: Int get() = changes.count { it.secretSink?.customerManaged == true }
    /**
     * SSO-3954 — what a reader of this plan must know beyond the rows: today the `workloadPull` deprecation, once per
     * application that declares it ([ProvisionFile.WORKLOAD_PULL_DEPRECATION]). Printed by the engine on plan and apply.
     */
    val warnings: List<String>
        get() = changes.filter { it.resource?.secretSink?.runtimePull == true }.map { "${it.kind} ${it.name}: ${ProvisionFile.WORKLOAD_PULL_DEPRECATION}" }
    val hasChanges: Boolean get() = creates.isNotEmpty() || updates.isNotEmpty() || removes.isNotEmpty() || grantChanges > 0 || publishes > 0
    /** SSO-3659 — resources that failed the ownership gate; a plan with one is red and `apply` refuses it. */
    val errors: List<PlannedChange> get() = changes.filter { it.action == ChangeAction.ERROR }
    val hasErrors: Boolean get() = errors.isNotEmpty()

    /** True when any planned removal targets the workspace's PRODUCTION plane (confirmation-gated). */
    val removesOnProductionPlane: Boolean get() = removes.any { it.onProductionPlane }

    /**
     * SSO-3715 — the resolved ids per declared resource, `{kind, name, id, environment, action}` (+ `attributes`,
     * `owner`), in file order: what a workflow reads from `plan --output json` instead of a receipt.
     */
    fun resolvedResources(): List<Map<String, Any?>> = changes.filter { it.resource != null && it.liveId != null }.map { it.toResolved() }

    fun toStructured(): Map<String, Any?> = mapOf(
        "changes" to changes.map { it.toStructured() },
        "resources" to resolvedResources(),
        "summary" to mapOf(
            "create" to creates.size,
            "update" to updates.size,
            "remove" to removes.size,
            "noop" to changes.count { it.action == ChangeAction.NOOP },
            "skip" to skips.size,
            "grants" to grantChanges,
            "error" to errors.size,
            "publish" to publishes,
            "deliver" to deliveries,
            "pull" to runtimePulls,
            "customerManaged" to customerManaged,
        ),
        "warnings" to warnings,
    )
}

/** SSO-3715 — a plan row's `{kind, name, id, environment, action, attributes, owner}` for `--output json`. */
private fun PlannedChange.toResolved(): Map<String, Any?> = buildMap {
    put("kind", kind); put("name", name); put("id", liveId)
    put("environment", if (kind == ProvisionFile.KIND_ENVIRONMENT) attributes["slug"] else environment)
    put("action", action.name.lowercase())
    if (attributes.isNotEmpty()) put("attributes", attributes)
    owner?.let { put("owner", it) }
}

/**
 * SSO-3659 (ADR 2026-10-13 §2) — one live resource `import` would add to the provisioning file: the
 * rendered [resource] (`readOnly: true` when the identity may only view it or another repository owns it),
 * its live id, the [access] the identity holds, and a [note] for what the file cannot carry (a write-only
 * secret, an unrecoverable template). SSO-3715 — `import` writes the file only; nothing else is recorded.
 */
data class ImportedResource(
    val resource: ProvisionResource,
    val liveId: String,
    val access: Access,
    val note: String? = null,
    /**
     * SSO-4042 — files the entry refers to, to be written NEXT TO the provisioning file by the host: path relative to the file →
     * content. An `emailTemplate`'s body goes to `emails/[<sandbox-slug>/]<type>[.<locale>].html` (SSO-4057 — a `legalDocument`'s to
     * `legal/[<sandbox-slug>/]<type>.md|.txt`) and its spec names it as `bodyFile`; the engine
     * (a library) writes nothing, the CLI's `import --write` does.
     */
    val files: Map<String, String> = emptyMap(),
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
        if (files.isNotEmpty()) put("files", files.keys.toList())
    }
}

/** The outcome of an import: what would be added, and what was reachable but could not be rendered (with why). */
data class ImportResult(val resources: List<ImportedResource>, val skipped: List<String>)

/**
 * SSO-3990 (thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13.3 / §13.5) — what bounds one `import` to the file it
 * writes and the identity that will plan and apply that file, so the written file plans as all `noop` and passes
 * `config.trust-scopes`:
 *
 *  - [part] — the target file's part when it does not exist yet (an existing file's own part wins): only its kinds are rendered;
 *  - [planScopes] — the scopes the identity PLANS with (the session's token, narrowed to the connection's `auth.scopes` when a
 *    connection plans the file); a kind it cannot read is listed, never read. Null ⇒ unknown: every read is attempted, and a
 *    scope `403` is listed the same way;
 *  - [applyScopes] — the scopes the identity APPLIES with (the connection's `auth.scopes`, else the token's); an entry whose
 *    write need lies outside them is rendered `readOnly: true`. Null ⇒ unknown: nothing is made read-only for want of a scope;
 *  - [routing] — plane routing over the repository's configured files; null ⇒ every plane goes to this file;
 *  - [ownTrustClients] — the workload clients of the repository's own trusts (every configured connection): never imported.
 */
data class ImportOptions(
    val part: ProvisionPart = ProvisionPart.MIXED,
    val planScopes: Set<String>? = null,
    val applyScopes: Set<String>? = null,
    val routing: PlaneRouting? = null,
    val ownTrustClients: Set<String> = emptySet(),
)

/**
 * SSO-3990 — which configured provisioning file an object's PLANE belongs to: a sandbox's objects to the file whose connection
 * is that sandbox's (`connection.json` `auth.environment`), everything else — the environments themselves, workspace-level
 * kinds, the production plane, a sandbox no connection covers — to the production connection's file. Every object lands in
 * exactly one file. [target] is the file being imported.
 */
class PlaneRouting(
    val target: String,
    /** The file planned with a production-plane connection; null when the workflow configures none. */
    val productionFile: String?,
    /** Sandbox slug → the file planned with that sandbox's connection. */
    val sandboxFiles: Map<String, String>,
) {
    /** The configured file an object of [plane] (null ⇒ the production plane) goes to, or null when none is configured. */
    fun fileFor(plane: String?): String? = plane?.let { sandboxFiles[it] } ?: productionFile

    fun owns(plane: String?): Boolean = fileFor(plane) == target
}

/**
 * SSO-3715 (ADR 2026-10-15 §5 "nothing stays local") — one declared resource as `apply` left it: its `kind` +
 * `name` (the file's key), the live id, the environment SLUG it lives in (`null` ⇒ the production plane; an
 * `environment` records its own slug under `attributes.slug`), non-secret attributes, the platform `owner` the
 * response rendered, and what this apply did to it. The in-memory shape behind `apply --output json` — never
 * written anywhere: the platform is the ledger, and the next run reads it live again.
 */
data class AppliedResource(
    val kind: String,
    val name: String,
    val id: String,
    val environment: String? = null,
    val attributes: Map<String, String> = emptyMap(),
    val owner: String? = null,
    val action: ChangeAction = ChangeAction.NOOP,
) {
    val key: String get() = "$kind/$name"

    fun toStructured(): Map<String, Any?> = buildMap {
        put("kind", kind); put("name", name); put("id", id)
        put("environment", if (kind == ProvisionFile.KIND_ENVIRONMENT) attributes["slug"] else environment)
        put("action", action.name.lowercase())
        if (attributes.isNotEmpty()) put("attributes", attributes)
        owner?.let { put("owner", it) }
    }
}

/**
 * SSO-3715 — the outcome of an `apply`: every declared resource with the id it resolved to ([resources], file
 * order), the `plan --output json` shape a workflow reads ids from (`{kind, name, id, environment, action}`).
 */
class ApplyResult(val resources: List<AppliedResource>, val workspace: String? = null) {
    fun toStructured(): Map<String, Any?> = mapOf(
        "workspace" to workspace,
        "resources" to resources.map { it.toStructured() },
        "summary" to mapOf(
            "create" to resources.count { it.action == ChangeAction.CREATE },
            "update" to resources.count { it.action == ChangeAction.UPDATE },
            "noop" to resources.count { it.action == ChangeAction.NOOP },
        ),
    )
}

/** The outcome of a destroy / prune pass: what was removed, and which planned removals failed (kept live; a re-run retries). */
data class RemovalOutcome(val removed: List<AppliedResource>, val failures: List<String>)

/**
 * SSO-3088 / SSO-3089 (epic SSO-3087) — the provisioning engine behind `thoryn provision plan | apply | destroy`.
 *
 * **Converge, not create (SSO-3089).** Every declared resource is looked up LIVE by its converge key
 * before any write: environment `slug`; application `clientId` when declared, else `displayName` within
 * its environment; user `email`; federation member `displayName`; trust `name`; the per-environment
 * singletons by existence — `loginMethods` (SSO-3100) by its stored allow-list, compared as a set. Found +
 * equal ⇒ `noop`; found + different ⇒ `update` with exactly the changed fields; absent ⇒ `create`. A second
 * `apply` therefore issues no writes. **Ambiguity is an error, not a create (SSO-3715):** two live matches
 * of a converge key are the red row `converge_key_ambiguous` ("declare `clientId`") — never a third copy.
 *
 * **The platform is the ledger (SSO-3715; ADR 2026-10-15 platform-is-the-ledger-no-committed-provisioning-receipt).**
 * `plan`, `apply`, `destroy` and `import` read live state only. Nothing is written beside the file — no
 * receipt, committed or cached — so the plan a reviewer reads and the state the platform enforces cannot
 * diverge. The receipt-era `adopted` bit is retired with the receipt: a live match is `noop` / `update`, and
 * what `destroy` / `--prune` may remove is decided by the platform's `owner` relation ([mayRemove]):
 *
 *  - a **`client:` identity** (a repository's `wi_`) removes a declared `application` / `environment` only
 *    when `/access/check owner` is true for it — `manager` alone (inherited through a sandbox a founder
 *    created, or granted) is never enough for automation to delete;
 *  - a **`member:` identity** (a person) removes what it **manages and nobody owns** — people cannot own, and
 *    an owned resource belongs to its repository ("owned by a repository — change its file");
 *  - SSO-3774 — a **`workloadIdentityTrust`** (`trust:<id>`, ownable since oauthy S1) is removed by the `client:`
 *    identity that OWNS it, on any plane; otherwise it follows the non-ownable rule below (a person never owns one);
 *  - **non-ownable kinds** (`user`, `federationMember`, the singletons) are removed
 *    WITH their sandbox — when the caller may delete the declared parent environment (the hard-delete
 *    cascades them) — and are never removed on the production plane by `destroy` / `--prune`: left in place,
 *    reported with the explicit command ([PlannedChange.byHand]);
 *  - environments are removed after their children, and only when owned;
 *  - **`retain: true`** (the declared replacement for the adopted bit) is converged and owned but never
 *    removed — shown as "retained" in the destroy plan.
 *
 * Every refusal is a `skip` row carrying the reason and the command a human would run; `--confirm
 * <workspace-slug>` is still required for any production-plane removal.
 *
 * **Secrets.** A `spec` key ending in `Env` names the env var carrying a secret; it is resolved at apply
 * time, forwarded to the product API, and NEVER written to the plan or the console. A write-only secret
 * (an SMTP password, a federation client secret) cannot be read back, so it never causes a diff on its
 * own; it is re-sent whenever the resource is created or updated. The same holds for an application's
 * `private_key_jwt` key location (`jwksUri` / `jwks`): product-api does not render it yet (SSO-3716), so it
 * is never diffed — it is sent on create and re-sent, idempotently, on every update of the client.
 *
 * **Server-minted client secrets (SSO-3113).** A confidential `application` (product-api's default
 * `clientType`) is created with a ONE-TIME `client_secret` on the create response. It leaves the engine
 * EXCLUSIVELY through [secretSink] (the consumer's channel: the CLI's `--secret-file` / guarded-stdout
 * `SecretIo`) — never the plan, the console, or a log. When the sink refuses it, the resource exists all
 * the same and its clientId lands on [undeliveredSecrets] so the CLI's `apply` can exit
 * `SecretIo.EXIT_NO_SECRET` and point at `thoryn clients rotate-secret`.
 *
 * **Grants (SSO-3113, ordering SSO-3119, prune SSO-3715 — ADR 2026-10-15 §2).** A resource's `grants:` block
 * is converged in a SECOND pass, once EVERY resource in the file exists: the object's grants are listed
 * (`GET /api/v1/access/grants?object=…`) and the missing ones POSTed. Grants are **additive by default**: a
 * live grant the block does not declare is shown as "present, not declared" and left alone. With `--prune`,
 * on every declared object the caller may delete ([mayRemove]), the undeclared ones are DELETEd — except
 * the `owner` tuple, workspace usersets (`workspace:…`) and the caller's own subject. The object ref
 * derives from the live id ([objectRef]). The second pass is what lets a block name a subject the same
 * file declares under another kind or further down. A session without `tenant:access.write` fails closed.
 *
 * **Ownership is decided by the identity's platform reach (SSO-3659; ADR 2026-10-13 §1), asked per
 * OBJECT (SSO-3673; ADR 2026-10-13 platform-owner-relation-and-forward-check).** Before any write, every
 * declared resource is gated on the relation the signed-in identity holds on the live object in the
 * platform authorization graph, through `POST /api/v1/access/check {object, relation}` for the caller's
 * own subject (`tenant:access.read`) — `manager` for a change, `viewer` for a `readOnly: true` reference —
 * answered over the platform store with the model's containment rules (`manager = this ∪ owner ∪
 * parent.manager`). `manager` ⇒ the normal converge; `viewer` ⇒ the resource may be declared
 * `readOnly: true` as a dependency and must MATCH (any diff is `access_read_only`); none ⇒
 * `access_not_owned` — not visible, never imported or converged. A CREATE needs `manager` on the parent
 * (`environment:<id>`, or the workspace for the production plane / an environment / the custom domain),
 * asked with the same check on the parent object; creator-becomes-manager (and, for a `client:` creator,
 * creator-becomes-OWNER) on the platform then makes this identity the resource's manager — no grant step,
 * no race. A failed gate is a [ChangeAction.ERROR] row (red plan, non-zero exit) and [apply] refuses the
 * whole plan before writing. **One owning repository per resource is a PLATFORM fact:** the `owner`
 * relation (one subject per `application` / `environment`, a database invariant on the platform, granted
 * by a workspace admin or set at create for a `client:` creator) is rendered on the resource as
 * `owner: { subject }`; when the live object has an owner and `/access/check` says this identity is not
 * it, the resource is `access_owned_elsewhere` unless declared `readOnly: true` here — the plan names no
 * other subject, only "another repository". `GET /api/v1/access/mine` (the per-TYPE reverse index) is the
 * LISTING read [import] is built on, and (SSO-3715) what `--prune` reads to find the resources a `client:`
 * identity OWNS and the file no longer declares. Note that the public `POST /api/v1/fga/check` /
 * `list-objects` evaluate the TENANT's own authorization model over the environment-partitioned tenant
 * tuple store, not the platform resource graph — `/api/v1/access/check` and `/mine` are that graph's
 * check and list-objects.
 *
 * **Creation slots (SSO-3792; oauthy ADR 2026-10-17 consent-approved-application-creation-slots §6).** A production-plane
 * application create needs `manager` on the workspace, which a repository identity is never granted. When the file
 * declares it with a fixed `clientId` and this identity may not create it — or cannot even see the plane — the row asks
 * for a CREATION SLOT ([FixRequest.Kind.CREATOR], `thoryn access reserve`): a workspace admin approves that this identity
 * creates that one name on that plane, once, within 30 days. `plan` reads the slots once
 * (`GET /api/v1/access/application-slots`, `tenant:access.read`; a platform without them answers 404 ⇒ none); a create
 * matching an unexpired slot of this identity on client id AND plane plans as "will create (reserved …)" and passes, and
 * `apply` is the ordinary create — product-api consumes the slot and the identity becomes the owner. Sandboxes keep
 * `manager` on their environment (decision D3); a slot never lifts the token-exchange rule.
 *
 * **Outputs (SSO-3668; ADR 2026-10-13 production-clients-declared-in-the-config-project §2).** An
 * `application`'s `publishTo:` targets receive its clientId through [outputSink] — the sibling of
 * [secretSink] for a value that is PUBLIC by construction — AFTER the resource is converged (the id is
 * known), on EVERY apply (an upsert: a re-created client propagates without a second step). A target the
 * sink cannot reach does not undo anything: the client exists, and `apply` ends with
 * [PublishTargetUnreachableException] (`publish_target_unreachable`) naming the one `gh variable set` a
 * human can run with the id from the apply output. `plan` never publishes; it shows the pending publish as
 * a line. Like [SecretSink], the library ships no [OutputSink] that runs a process: the CLI's is `gh variable set`.
 *
 * **Declared secret delivery (SSO-3659; ADR 2026-10-13 converge §5, production-clients ADR §3 tier 3).** A
 * confidential `application` may declare a `secretSink:` ([SecretTarget] — a key of an existing namespace's
 * Kubernetes Secret, or an owner-only file): where the one-time `client_secret` is CONSUMED. `apply` hands
 * the minted value to [declaredSecretSink] IMMEDIATELY AFTER the client is converged, falls back to the
 * generic [secretSink] (the CLI's `--secret-file` / guarded TTY) when the declared one answers a reason, and
 * — when neither reaches — leaves the client in place and reports it on [undeliveredSecretDetails]
 * (`undelivered_secrets`): the host exits non-zero naming the resource and the recovery
 * `thoryn clients rotate-secret <clientId> --secret-file <path>`. The value never enters the plan, the
 * console or a log — a sink's reason is redacted of it before it is printed. `plan` shows the intended
 * delivery as a line ([PlannedChange.secretSink]) and mints nothing. The library ships no sink that runs
 * `kubectl` or writes a file: the CLI's does (`CliDeclaredSecretSink`).
 *
 * [clients] yields a tenant-scoped [ProvisionApi] bound to an environment slug (`null` ⇒ the
 * production plane).
 *
 * **A library since SSO-3662** (ADR 2026-10-13-provision-engine-shared-library): this class, the file
 * model and [SecretSink] are `io.thoryn:thoryn-provision-engine`, the module the CLI is built on and that
 * anything else needing to converge a provisioning file in-process consumes. The module knows nothing of
 * picocli, a TTY, or the CLI's session — it reaches product-api only through the [ProvisionApi] port the
 * consumer hands it, and reports through the [out] / [err] streams it is given.
 */
class ProvisionEngine(
    private val clients: (environmentSlug: String?) -> ProvisionApi,
    private val out: PrintStream = System.out,
    private val err: PrintStream = System.err,
    private val env: (String) -> String? = { System.getenv(it) },
    /** SSO-3113 — the single channel a minted `client_secret` leaves through; the default delivers nothing. */
    private val secretSink: SecretSink = SecretSink.undeliverable(),
    /**
     * SSO-3413 — the signed-in workspace's id (the token's `tnt`): the id of the workspace-level
     * `customDomain` singleton, and so of its access object `custom_domain:<workspaceId>`.
     */
    private val workspaceId: String? = null,
    /**
     * SSO-3659 — the signed-in identity's platform subject (`client:<clientId>` / `member:<sub>`), derived
     * from the token by the caller exactly as product-api derives it. SSO-3715 — it decides the SHAPE of the
     * deletion authority ([mayRemove]: owner for a `client:`, unowned-manager for a `member:`) and is excluded
     * from `--prune`'s grant revocations; the gate itself never sends it — `/api/v1/access/check` and `/mine`
     * answer for the CALLER's own subject, so the subject is always the token's, never the file's. Null (a
     * person's opaque token — a machine session always names its client) ⇒ the person's rule applies.
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
    /**
     * SSO-3689 — the scopes the signed-in identity's token carries (its `scope` claim), when the host knows them. A
     * `workloadIdentityTrust` may carry only scopes the APPLYING identity itself holds (the hub's scope ceiling,
     * `403 scope_not_grantable`); with the set known, `plan` refuses a trust that overreaches before any write, with
     * the hub's own code. Null ⇒ unknown here — the plan states the ceiling and the hub enforces it at apply.
     */
    private val callerScopes: Set<String>? = null,
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
        /** The one command a human runs instead — with the clientId from the apply output. */
        val recovery: String get() = recoverSecret(clientId)
    }

    /**
     * SSO-3668 — the port an application's clientId leaves the engine through on its way to a `publishTo:`
     * target. Same shape as [SecretSink]: no picocli, no TTY, no process — the CLI implements it with
     * `gh variable set … --env` (creating the environment when absent, never touching an existing one's
     * protection); the GitHub App with its own gateway. [publish] answers `null` when the value landed,
     * else WHY the target could not be reached (shown to the operator; never the value itself — which is a
     * client id and public anyway, but the message names the apply output as its source).
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
        /** The one command a human runs instead, with the id from the apply output. */
        val byHand: String get() = target.byHand(value)
    }

    /**
     * SSO-3668 — `apply` converged every resource, but one or more outputs could not be published
     * (`publish_target_unreachable`). Raised AFTER convergence ([result] is what was applied, ids included), so
     * nothing is lost: the human fallback is each failure's [PublishFailure.byHand].
     */
    class PublishTargetUnreachableException(val failures: List<PublishFailure>, val result: ApplyResult) : ProvisionException(
        "$ERROR_PUBLISH_UNREACHABLE — every resource was converged, but " +
            "${failures.size} output(s) could not be published:\n  " +
            failures.joinToString("\n  ") { "${it.resourceKey} → ${it.target.label}: ${it.reason}\n    publish it by hand: ${it.byHand}" },
    )

    /**
     * SSO-3113 — clientIds of confidential applications created by the last [apply] whose one-time
     * secret the [secretSink] could NOT deliver. The clients exist; the operator must
     * mint a new secret with `thoryn clients rotate-secret <clientId>`.
     */
    private val undelivered = mutableListOf<UndeliveredSecret>()
    val undeliveredSecrets: List<String> get() = undelivered.map { it.clientId }
    /** SSO-3659 — the same, with the declared target and the (redacted) reason per client (`undelivered_secrets`). */
    val undeliveredSecretDetails: List<UndeliveredSecret> get() = undelivered.toList()

    /**
     * SSO-3113 — the single channel a server-minted `client_secret` leaves the engine through. [emit]
     * returns `true` when delivered, `false` when refused — the resource exists all the same and its
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

    /**
     * What `apply` would do: every declared resource probed live, gated, its grants diffed, then (with
     * [prune]) the resources this `client:` identity OWNS on the platform and the file no longer declares, as
     * removals. SSO-3715 — reads live only; there is no receipt to consult.
     */
    fun plan(file: ProvisionFile, prune: Boolean): ProvisionPlan {
        trustLists.clear()
        trustVerdicts.clear()
        trustsHidden.clear()
        val changes = mutableListOf<PlannedChange>()
        // Environment slugs known so far (live), so dependants can be probed in the right plane.
        val envSlugs = mutableMapOf<String, String>()
        val reach = Reach()
        orderForApply(file.resources).forEach { r ->
            val slug = planSlug(r, file, envSlugs)
            // SSO-3659 — the ownership gate sits between the live lookup and everything that would write:
            // a resource that fails it plans no grants (its object may not even be visible to this identity).
            val change = gate(r, probe(r, file, envSlugs, reach), file, envSlugs, slug, reach)
                // SSO-3774 — a trust's verdict is what an application naming it (planned after every trust) reads.
                .also { c -> if (r.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST) trustVerdicts[r.name] = c }
                // SSO-3921 — a `workloadPull` sink: resolve the trust (same plane, kubernetes, tenant:applications.write) before the grants,
                // whose diff then carries the workload client's `manager` on the application.
                .let { c -> if (c.action == ChangeAction.ERROR || c.readOnly || r.secretSink?.runtimePull != true) c else planWorkloadPull(r, c, file, envSlugs, slug) }
                .let { c -> if (c.action == ChangeAction.ERROR || c.readOnly) c else planGrants(r, c, slug, prune, file, envSlugs, reach, pullGrant(r, c)) }
                // SSO-3668 — a resource that will be converged publishes its id afterwards (every apply); shown, never done, by plan.
                .let { c -> if (c.action == ChangeAction.ERROR || c.readOnly || r.publishTo.isEmpty()) c else c.copy(publishTo = r.publishTo, reason = c.reason + "; publishes its id to ${r.publishTo.size} target(s)") }
                // SSO-3659 — a CREATE of a confidential application mints a secret; where it will be delivered is shown, never done, by plan.
                // SSO-3954 — with no sink declared that is `customerManaged` (the default): discarded by apply, minted by a person.
                .let { c -> val sink = r.effectiveSecretSink; if (c.action == ChangeAction.CREATE && !c.readOnly && sink != null && !sink.runtimePull) c.copy(secretSink = sink) else c }
            changes += change
            if (r.kind == ProvisionFile.KIND_ENVIRONMENT && change.liveId != null) {
                // The RESOLVED slug (a `{{env.NAME}}` placeholder names a per-run sandbox), never the raw spec.
                envSlugs[r.name] = resolveSpec(r, strict = false)["slug"].toString()
            }
        }
        if (prune) changes += planPruneOwned(file, changes, reach)
        return ProvisionPlan(changes).also { warn(it) }
    }

    /** SSO-3954 — print a plan's [ProvisionPlan.warnings] (the `workloadPull` deprecation) on [err], once per plan and once per apply. */
    private fun warn(plan: ProvisionPlan) {
        plan.warnings.forEach { err.println("  ! $it") }
    }

    /**
     * SSO-3715 (ADR 2026-10-15 §1 / §5) — what `--prune` removes besides grants: every `application` /
     * `environment` (and, SSO-3774, `trust`) the platform lists this identity as OWNER of (`GET /api/v1/access/mine?relation=owner`) that
     * the file does not declare. The platform is the ledger of what a repository owns, so "owned but no longer
     * declared" needs no receipt. A `member:` identity owns nothing (people are managers, never owners), so
     * nothing undeclared can be attributed to its file — reported as one note. Children first, environments last.
     */
    private fun planPruneOwned(file: ProvisionFile, declared: List<PlannedChange>, reach: Reach): List<PlannedChange> {
        if (subject == null || !subject.startsWith("client:")) {
            return listOf(
                PlannedChange(
                    "prune", "undeclared", ChangeAction.SKIP,
                    "--prune removes what this identity OWNS and the file no longer declares; a ${subject?.substringBefore(':') ?: "person's"} identity owns nothing on the platform " +
                        "(people are managers, never owners), so only undeclared grants on the declared objects are pruned — remove a resource by hand (`thoryn clients delete <clientId>`, `thoryn env delete <id> --confirm <slug>`)",
                ),
            )
        }
        val declaredApps = declared.filter { it.kind == ProvisionFile.KIND_APPLICATION }.mapNotNull { it.liveId }.toSet()
        val declaredEnvs = declared.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT }.mapNotNull { it.liveId }.toSet()
        val rows = mutableListOf<PlannedChange>()
        val sandboxSlugs = reach.environments().filter { it.str("kind") != PRODUCTION_ENV_SLUG && it.str("slug") != PRODUCTION_ENV_SLUG }.mapNotNull { it.str("slug") }
        reach.ids(OBJECT_TYPE_APPLICATION, RELATION_OWNER).filter { it == decodePlatformId(it) && it !in declaredApps }.sorted().forEach { id ->
            // The plane it lives in: the first one whose GET answers (production first) — the engine needs the header to delete it.
            val plane = (listOf<String?>(null) + sandboxSlugs).firstOrNull { fetchOrNull { clients(it).getApplication(id) } != null }
            rows += if (plane == null && fetchOrNull { clients(null).getApplication(id) } == null) {
                PlannedChange(ProvisionFile.KIND_APPLICATION, id, ChangeAction.SKIP, "owned by this identity on the platform but not readable in any environment — left in place", liveId = id)
            } else {
                PlannedChange(ProvisionFile.KIND_APPLICATION, id, ChangeAction.REMOVE, "owned by this identity (the platform's `owner` relation) and not declared in the file (--prune)", liveId = id, environment = plane, owner = subject)
            }
        }
        reach.ids(OBJECT_TYPE_ENVIRONMENT, RELATION_OWNER).filter { it == decodePlatformId(it) && it !in declaredEnvs }.sorted().forEach { id ->
            val node = reach.environments().firstOrNull { it.str("id") == id }
            rows += if (node == null) {
                PlannedChange(ProvisionFile.KIND_ENVIRONMENT, id, ChangeAction.SKIP, "owned by this identity on the platform but not in the workspace's environment list — left in place", liveId = id)
            } else {
                PlannedChange(ProvisionFile.KIND_ENVIRONMENT, node.str("slug") ?: id, ChangeAction.REMOVE, "owned by this identity (the platform's `owner` relation) and not declared in the file (--prune); its contents go with it", liveId = id, attributes = buildMap { node.str("slug")?.let { put("slug", it) } }, owner = subject)
            }
        }
        // SSO-3774 (ADR 2026-10-16 §4) — the workload-identity trusts this identity OWNS (`trust:<id>`, S1) that the file no
        // longer declares. A platform that predates trust objects lists none, so nothing is pruned there.
        val declaredTrusts = declared.filter { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }.mapNotNull { it.liveId }.toSet()
        val ownClientId = subject.substringAfter(':')
        reach.ids(OBJECT_TYPE_TRUST, RELATION_OWNER).filter { it == decodePlatformId(it) && it !in declaredTrusts }.sorted().forEach { id ->
            // The plane it lives in: the first whose (filtered) list carries it — the engine needs the header to delete it.
            val located = (listOf<String?>(null) + sandboxSlugs).firstNotNullOfOrNull { plane -> fetchOrNull { trustsOf(plane) }?.firstOrNull { it.str("id") == id }?.let { plane to it } }
            rows += when {
                located == null -> PlannedChange(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, id, ChangeAction.SKIP, "owned by this identity on the platform but not readable in any environment — left in place", liveId = id)
                // I6 makes this unreachable on the platform; the engine still never removes the trust it signs in with.
                located.second.str("clientId") == ownClientId -> PlannedChange(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, located.second.str("name") ?: id, ChangeAction.SKIP, "the trust this identity itself signs in with — never removed by the file it applies", liveId = id, environment = located.first)
                else -> {
                    val view = trustView(located.second)
                    PlannedChange(
                        ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, located.second.str("name") ?: id, ChangeAction.REMOVE,
                        "owned by this identity (the platform's `owner` relation on trust:$id) and not declared in the file (--prune); its wi_ workload client stops authenticating at once",
                        liveId = id, environment = located.first, attributes = trustAttributes(view), owner = subject, trust = view,
                    )
                }
            }
        }
        return orderForRemove(rows)
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

    /**
     * Live lookup by converge key → create / update / noop for one declared resource. [reach] is the PLAN's (null from
     * [planDestroy]): with it, a 404 on the live read may plan a reserved create or ask for a creation slot (SSO-3792);
     * without it — a destroy, which never creates — the read keeps asking for `owner` on a fixed id.
     */
    private fun probe(r: ProvisionResource, file: ProvisionFile, envSlugs: Map<String, String>, reach: Reach? = null): PlannedChange {
        if (r.kind == ProvisionFile.KIND_CUSTOM_DOMAIN) return probeCustomDomain(r)
        val slug: String? = when {
            r.kind == ProvisionFile.KIND_ENVIRONMENT -> null
            r.environment == null -> null
            file.environmentResource(r.environment) == null -> r.environment
            else -> envSlugs[r.environment]
                ?: return PlannedChange(r.kind, r.name, ChangeAction.CREATE, "environment '${r.environment}' will be created first${mintNote(r)}", resource = r, retain = r.retain)
        }
        var desired = resolveSpec(r, strict = false)
        // SSO-3689 — a trust converges by its name and is never updated in place (its pins are immutable on the hub).
        if (r.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST) return probeTrust(r, slug, desired)
        // SSO-3689 — `federatedTrust` names a trust; the API takes its id, so the name is resolved (same environment) first.
        if (r.kind == ProvisionFile.KIND_APPLICATION) {
            federatedTrustRef(r, file, slug, atApply = false)?.let { ref ->
                // SSO-3774 — a trust this file declares that this identity cannot see is a missing RIGHT (`access_not_reachable`,
                // `owner` on the trust by name), never the misleading "not found".
                ref.fix?.let { fix ->
                    val row = PlannedChange(r.kind, r.name, ChangeAction.ERROR, ref.error ?: "", resource = r, environment = slug)
                    return refuse(r, row, ERROR_NOT_REACHABLE, Access.NONE, "${ref.error} (${FixRequest.hint(fix)})", fix = fix)
                }
                ref.error?.let { why -> return PlannedChange(r.kind, r.name, ChangeAction.ERROR, "$ERROR_FEDERATED_TRUST_NOT_FOUND — $why", resource = r, error = ERROR_FEDERATED_TRUST_NOT_FOUND) }
                desired = desired + (ProvisionFile.SPEC_FEDERATED_TRUST to (ref.id ?: "${ref.name} $PENDING_TRUST_MARKER"))
            }
        }
        val live = try {
            lookup(r, slug, desired)
        } catch (ex: ConvergeKeyAmbiguousException) {
            // SSO-3715 (ADR 2026-10-15 §5) — two live matches: red, never a third copy.
            return PlannedChange(r.kind, r.name, ChangeAction.ERROR, "$ERROR_CONVERGE_KEY_AMBIGUOUS — ${ex.message}", resource = r, environment = slug, error = ERROR_CONVERGE_KEY_AMBIGUOUS, fixNote = FILE_FIX_NOTE_AMBIGUOUS)
        } catch (ex: LegalDocumentVersionImmutableException) {
            // SSO-4057 — the declared version label is published with OTHER content: a published version never changes.
            return PlannedChange(r.kind, r.name, ChangeAction.ERROR, "$ERROR_LEGAL_DOCUMENT_VERSION_IMMUTABLE — ${ex.message}", resource = r, liveId = ex.liveId, environment = slug, diff = ex.diff, error = ERROR_LEGAL_DOCUMENT_VERSION_IMMUTABLE, fixNote = FILE_FIX_NOTE_LEGAL_DOCUMENT_VERSION)
        } catch (ex: ProductApiException) {
            // SSO-3722 — product-api answers 404 `unknown_environment` not only for a plane that does not exist but for
            // one this identity has NO reach into (SSO-3118, the 404-not-403 rule): a brand-new repository identity gets it
            // on its very first read. That is the missing-rights shape, not a broken read — a red row with its fix.
            if (ex.httpStatus == 404) return unreachable(r, slug, desired, ex, reach)
            // SSO-3926 — a 403 here is the token's SCOPE, not a right: name the scope (the host names the profile).
            MissingScopeException.of(ex, ScopeRequirements.readScope(r.kind), ScopeRequirements.Phase.PLAN, r.key, "read live state")?.let { throw it }
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        return when {
            live == null -> PlannedChange(r.kind, r.name, ChangeAction.CREATE, "not found by its converge key${mintNote(r)}", resource = r, environment = slug, retain = r.retain)
            live.diff.isNotEmpty() -> PlannedChange(
                r.kind, r.name, ChangeAction.UPDATE, "exists — ${live.diff.size} field(s) differ${keyLocationNote(r)}",
                resource = r, liveId = live.id, environment = slug, attributes = live.attributes, diff = live.diff, owner = live.owner, retain = r.retain,
            )
            else -> PlannedChange(r.kind, r.name, ChangeAction.NOOP, "exists and matches${keyLocationNote(r)}", resource = r, liveId = live.id, environment = slug, attributes = live.attributes, owner = live.owner, retain = r.retain)
        }
    }

    /**
     * SSO-3722 (the thoryn-cicd run 38751887466 shape) — the live read of a declared resource answered 404: the plane it
     * lives in is not reachable by this identity (product-api's `EnvironmentClaimFilter` answers `unknown_environment`
     * both for a missing environment and for one the caller holds no relation into — a new repository identity with no
     * relation on anything). The row is red with the code [ERROR_NOT_REACHABLE] and the RIGHT that opens the plane.
     *
     * SSO-3792 (oauthy ADR 2026-10-17 §6; absorbs SSO-3787) — a confined identity cannot tell ABSENT from INVISIBLE, so an
     * application the file declares by a fixed `clientId` never asks for `owner` (a right on a thing that may not exist —
     * the consent offered it, product-api answered `not_found`, PR 34). Instead:
     *  - on the PRODUCTION plane: a creation slot ([FixRequest.Kind.CREATOR], `thoryn access reserve`) — or, when this
     *    identity already holds an unexpired slot for that id on that plane, a reserved CREATE ([reservedCreate]): a slot
     *    is only ever reserved for a name that did not exist, and any creation of the name sweeps it;
     *  - on a sandbox (decision D3): `manager` on the declared environment, as for every other sandbox resource;
     *  - an application without a fixed id on the production plane: the workspace note, plus "declare `spec.clientId`".
     * A [planDestroy] probe ([reach] null) never creates, so there a fixed id keeps asking for `owner` — what may remove it.
     */
    private fun unreachable(r: ProvisionResource, slug: String?, desired: Map<String, Any?>, ex: ProductApiException, reach: Reach?): PlannedChange {
        val plane = planeLabel(slug)
        val code = ex.errorCode ?: "not_found"
        val why = "the live read of ${r.key} in $plane was answered HTTP 404 ($code): this identity has no relation that reaches $plane, " +
            "so nothing there is visible to it (a new repository identity holds no relation until a workspace admin grants one)"
        val change = PlannedChange(r.kind, r.name, ChangeAction.ERROR, why, resource = r, environment = slug)
        val fixedId = desired["clientId"]?.toString()?.trim()?.takeIf { r.kind == ProvisionFile.KIND_APPLICATION && it.isNotEmpty() }
        val production = slug == null || slug == PRODUCTION_ENV_SLUG
        return when {
            fixedId != null && reach == null -> {
                val ref = objectRef(r.kind, fixedId, slug)
                val fix = FixRequest.owner(subject, ref, "$why; the file declares `clientId: $fixedId`, so this identity is to OWN it")
                refuse(r, change, ERROR_NOT_REACHABLE, Access.NONE, "$why (${FixRequest.hint(fix)})", fix = fix)
            }
            fixedId != null && production -> {
                val pending = PlannedChange(r.kind, r.name, ChangeAction.CREATE, "", resource = r, environment = slug, retain = r.retain)
                reach!!.slot(fixedId, slug)?.let { return reservedCreate(r, pending, slug, it) }
                creatorRefusal(r, change, ERROR_NOT_REACHABLE, Access.NONE, why, fixedId, reach)
            }
            slug != null && slug != PRODUCTION_ENV_SLUG -> {
                val ref = "$OBJECT_TYPE_ENVIRONMENT:$slug"
                val fix = FixRequest.manager(subject, ref, "$why; the file declares `environment: $slug`, which this identity cannot see")
                refuse(r, change, ERROR_NOT_REACHABLE, Access.NONE, "$why (${FixRequest.hint(fix)}; `$ref` is the environment as `thoryn env list` names it)", fix = fix)
            }
            else -> workspaceParentRefusal(r, change, ERROR_NOT_REACHABLE, Access.NONE, why)
        }
    }

    /**
     * SSO-3792 — the production-plane refusal of an application with a fixed [clientId] this identity may not create: a
     * creation slot ([FixRequest.creator]). When the identity holds a slot for the id on this plane that has EXPIRED, the
     * reason says so (an expired slot reads as no slot: the admin reserves it again).
     */
    private fun creatorRefusal(r: ProvisionResource, change: PlannedChange, code: String, access: Access?, why: String, clientId: String, reach: Reach): PlannedChange {
        val expired = reach.expiredSlot(clientId, PRODUCTION_ENV_SLUG)
        val reason = "$why; the file declares `clientId: $clientId` on the production plane, where only a workspace admin may approve its creation" +
            (expired?.let { " (this identity's creation slot for it expired${it.expiresAt?.let { at -> " at $at" } ?: ""}: a slot admits the create for 30 days)" } ?: "")
        val fix = FixRequest.creator(subject, clientId, PRODUCTION_ENV_SLUG, reason)
        return refuse(r, change, code, access, "$reason (${FixRequest.hint(fix)})", fix = fix)
    }

    /**
     * SSO-3710 / SSO-3792 — a refusal whose parent is the WORKSPACE: a note, never a right. An application additionally
     * learns how to make its creation approvable: declare a fixed `spec.clientId` (a creation slot names one id).
     */
    private fun workspaceParentRefusal(r: ProvisionResource, change: PlannedChange, code: String, access: Access?, why: String): PlannedChange {
        val note = if (r.kind == ProvisionFile.KIND_APPLICATION) "$WORKSPACE_PARENT_NOTE; $DECLARE_CLIENT_ID_NOTE" else WORKSPACE_PARENT_NOTE
        return refuse(r, change, code, access, "$why ($note)", fixNote = note)
    }

    /**
     * SSO-3792 (oauthy ADR 2026-10-17 §3 / §6) — a CREATE this identity may make only because a workspace admin reserved
     * a creation slot for exactly this client id on exactly this plane: green, with the reservation on the row. Apply is
     * the ordinary create — product-api's gate consumes the slot and the identity becomes the owner. The slot lifts
     * nothing else (ADR §3, "What the slot does not lift"): turning token exchange or token introspection on at create
     * still needs `manager` on the plane (product-api answers `403 token_exchange_not_grantable` /
     * `403 token_introspection_not_grantable` before it claims the slot), so the plan says so first, as
     * [gateTokenExchange] / [gateTokenIntrospection] do for an update.
     */
    private fun reservedCreate(r: ProvisionResource, change: PlannedChange, slug: String?, slot: CreationSlot): PlannedChange {
        val pending = change.copy(action = ChangeAction.CREATE, access = null, reservation = slot, retain = r.retain, error = null, fix = null, fixNote = null)
        SLOT_EXCLUDED_SETTINGS.firstOrNull { (field, _, _) -> coerceBool(r.spec[field]) }?.let { (field, errorCode, workspaceNote) ->
            val why = "${r.key} is to be created under a creation slot, and a slot does not include turning $field on — " +
                "that needs `manager` on its environment (product-api answers `403 $errorCode`)"
            return if (slug == null || slug == PRODUCTION_ENV_SLUG) {
                refuse(r, pending, errorCode, null, "$why ($workspaceNote)", fixNote = workspaceNote).copy(reservation = null)
            } else {
                val parent = "$OBJECT_TYPE_ENVIRONMENT:$slug"
                val fix = FixRequest.manager(subject, parent, why)
                refuse(r, pending, errorCode, null, "$why (${FixRequest.hint(fix)})", fix = fix).copy(reservation = null)
            }
        }
        val expires = slot.expiresAt?.let { "; expires $it" } ?: ""
        return pending.copy(reason = "will create (reserved by a workspace admin$expires)${mintNote(r)}")
    }

    /**
     * SSO-3715 — until product-api renders the key location (SSO-3716), a declared `jwksUri` / `jwks` is never diffed:
     * it is sent on create and re-sent with every update. The plan says so, so a reader knows why a changed key
     * location alone plans no update.
     */
    private fun keyLocationNote(r: ProvisionResource): String =
        if (r.kind == ProvisionFile.KIND_APPLICATION && KEY_LOCATION_FIELDS.any { r.spec[it] != null }) " (key location declared — not readable from the API, re-sent with any update; SSO-3716)" else ""

    /** SSO-3113 — the plan marker for a confidential application about to be created (its secret is shown once). */
    private fun mintNote(r: ProvisionResource): String {
        val sink = r.effectiveSecretSink ?: return ""
        return when {
            // SSO-3921 — a runtime pull: the one-time value is discarded; the trust's pod mints its own at start.
            sink.runtimePull -> " (a client secret will be minted and discarded — the pods of trust ${sink.trust} mint their own at start)"
            // SSO-3954 — the customer manages the secret (the default): the one-time value is discarded; a person mints the real one.
            sink.customerManaged -> " (a client secret will be minted and discarded — managed by the customer: ${ProvisionFile.CUSTOMER_MANAGED_RUNBOOK})"
            // SSO-3659 — with a declared sink the secret is delivered, not shown.
            else -> " (a client secret will be minted and delivered to ${sink.label})"
        }
    }

    /** product-api's `clientType` defaults to `confidential`; only an explicit `public` client is secret-less. */
    private fun isConfidential(spec: Map<String, Any?>): Boolean = ProvisionFile.isConfidential(spec)

    /** SSO-3689 — whether the create MINTS a client secret ([ProvisionFile.mintsSecret]). */
    private fun mintsSecret(spec: Map<String, Any?>): Boolean = ProvisionFile.mintsSecret(spec)

    /**
     * SSO-3113 — attach the grant diff to a planned change: for a CREATE every declared grant is an add
     * (nothing exists yet); otherwise the object's live grants are listed and compared as a set. A
     * resource without a `grants:` block is left untouched (nothing is even read). SSO-3715 (ADR 2026-10-15
     * §2) — an undeclared live grant is "present, not declared" unless [prune] is set AND the caller may
     * delete the object ([mayRemove]); the exclusions ([grantDiff]) hold either way.
     */
    private fun planGrants(r: ProvisionResource, change: PlannedChange, slug: String?, prune: Boolean, file: ProvisionFile, envSlugs: Map<String, String>, reach: Reach, implicit: ProvisionGrant? = null): PlannedChange {
        // SSO-3921 — [implicit] is the `workloadPull` workload client's `manager`: part of a declared block (so `--prune`
        // never revokes it), or, without one, the ONE grant converged on the object — additive only, nothing else read as
        // "undeclared" (a file without `grants:` does not manage the object's grants).
        val manages = r.grants != null
        val declared = (r.grants.orEmpty() + listOfNotNull(implicit)).distinctBy { it.label }.takeIf { manages || implicit != null } ?: return change
        if (change.action == ChangeAction.CREATE || change.liveId == null) {
            return change.copy(grantAdds = declared.map { it.label })
        }
        val revoke = manages && prune && mayRemove(r, change, slug, file, envSlugs, reach).allowed
        val (adds, removes, undeclaredAll) = grantDiff(declared, liveGrants(r, objectRef(r.kind, change.liveId, slug)), revoke)
        val undeclared = if (manages) undeclaredAll else emptyList()
        if (adds.isEmpty() && removes.isEmpty() && undeclared.isEmpty()) return change
        val note = buildString {
            if (adds.isNotEmpty() || removes.isNotEmpty()) append("; grants: +${adds.size} −${removes.size}")
            if (undeclared.isNotEmpty()) append("; ${undeclared.size} grant(s) present, not declared" + if (prune && !revoke) " (kept: this identity may not delete the object)" else "")
        }
        return change.copy(reason = change.reason + note, grantAdds = adds, grantRemoves = removes, grantUndeclared = undeclared)
    }

    // ── runtime pull (SSO-3921; oauthy ADR 2026-10-14 credential ladder, rung 3) ─────────────────────────────

    /**
     * SSO-3921 — resolve a `secretSink: { kind: workloadPull, trust }` against the plane the application lives in: the trust
     * is live there (its view gives the `wi_` client), or declared in this file and created by this apply (pending; the file
     * loader already pinned its plane, provider and scopes). A live trust must be a `kubernetes` trust carrying
     * [ProvisionFile.ROTATE_SECRET_SCOPE]; one this identity cannot see is `access_not_reachable` (`viewer` on it by name —
     * the engine only needs to READ its workload client); anything else is [ProvisionFile.ERR_WORKLOAD_PULL_TRUST_NOT_FOUND].
     * A resolved row carries the sink (the plan's line) and the workload client ([PlannedChange.pullClientId]).
     */
    private fun planWorkloadPull(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?): PlannedChange {
        val sink = r.secretSink!!
        val name = sink.trust ?: return change
        val declared = file.resources.firstOrNull { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST && it.name == name }
        // An environment this apply creates first holds no live trust yet: only one declared beside it can be named.
        val planePending = r.environment != null && file.environmentResource(r.environment) != null && envSlugs[r.environment] == null
        val live = if (planePending) null else try {
            fetchOrNull { trustsOf(slug) }?.firstOrNull { it.str("name") == name }
        } catch (ex: ProductApiException) {
            MissingScopeException.of(ex, ScopeRequirements.SCOPE_WORKLOAD_IDENTITY_READ, ScopeRequirements.Phase.PLAN, r.key, "list the trusts of ${planeLabel(slug)} to resolve secretSink.trust '$name'")?.let { throw it }
            throw ProvisionException("${r.key}: could not list the trusts of ${planeLabel(slug)} to resolve secretSink.trust '$name' (${ex.message})")
        }
        fun red(code: String, why: String, fix: FixRequest.MissingRight? = null): PlannedChange =
            change.copy(action = ChangeAction.ERROR, reason = "$code — $why", error = code, fix = fix?.copy(reason = "$code — ${fix.reason}"), fixNote = if (fix == null) WORKLOAD_PULL_FILE_FIX_NOTE else null)
        if (live != null) {
            val view = trustView(live)
            val provider = view["provider"]?.toString()
            if (provider != ProvisionFile.WORKLOAD_PULL_PROVIDER) {
                return red(ProvisionFile.ERR_WORKLOAD_PULL_TRUST_PROVIDER, "trust '$name' in ${planeLabel(slug)} is a '$provider' trust; a runtime pull is a POD minting its own secret at start (provider: ${ProvisionFile.WORKLOAD_PULL_PROVIDER})")
            }
            val scopes = (view["scopes"] as? List<*>).orEmpty().map { it.toString() }
            if (ProvisionFile.ROTATE_SECRET_SCOPE !in scopes) {
                return red(ProvisionFile.ERR_WORKLOAD_PULL_SCOPE_MISSING, "trust '$name' does not carry ${ProvisionFile.ROTATE_SECRET_SCOPE} (it has ${scopes.joinToString(" ").ifEmpty { "none" }}): its pods could not run `thoryn clients rotate-secret` — add it to the trust in place (declare it in the trust's spec.scopes, or `thoryn workload-identity trusts set-scopes $name --scope …`; adding a scope is a person's act with a passkey sign-in), then re-run")
            }
            val clientId = view["clientId"]?.toString() ?: return red(ProvisionFile.ERR_WORKLOAD_PULL_TRUST_NOT_FOUND, "trust '$name' in ${planeLabel(slug)} renders no workload client")
            return change.copy(secretSink = sink, pullClientId = clientId)
        }
        val verdict = trustVerdicts[name]
        return when {
            declared != null && (verdict == null || verdict.action != ChangeAction.ERROR) -> change.copy(secretSink = sink, pullClientId = null)
            declared != null && name in trustsHidden -> {
                val why = "trust '$name' is declared in this file for ${planeLabel(slug)} but is not visible to this identity — it holds no relation on it, so ${r.key} cannot resolve secretSink.trust"
                val fix = FixRequest.byName(FixRequest.Kind.VIEWER, subject, name, slug, why)
                red(ERROR_NOT_REACHABLE, "$why (${FixRequest.hint(fix)})", fix)
            }
            declared != null -> red(ProvisionFile.ERR_WORKLOAD_PULL_TRUST_NOT_FOUND, "trust '$name' is declared in this file but its own row is red (${verdict?.error}) — it will not be created by this apply, so no workload can pull this secret")
            else -> red(
                ProvisionFile.ERR_WORKLOAD_PULL_TRUST_NOT_FOUND,
                "no workloadIdentityTrust named '$name' in ${planeLabel(slug)} is visible to this identity — declare it in this file (same environment, provider kubernetes) " +
                    "or create it first (`thoryn workload-identity trusts create --provider kubernetes`); a trust another identity owns is listed only to who holds a relation on it",
            )
        }
    }

    /**
     * SSO-3921 — the grant a `workloadPull` row converges on its application: `manager` for the trust's workload client, the
     * relation product-api's rotate-secret requires (`manageable(...)`, oauthy SSO-3111) and the one under which the hub lets
     * that client REPLACE an in-flight secret (oauthy SSO-3696). While the trust is created by this apply its client id is
     * not known yet: the plan shows a placeholder subject and `apply` resolves the real one ([workloadPullGrantAtApply]).
     */
    private fun pullGrant(r: ProvisionResource, change: PlannedChange): ProvisionGrant? {
        val sink = change.secretSink?.takeIf { it.runtimePull && r.secretSink?.runtimePull == true } ?: return null
        val subject = change.pullClientId?.let { "client:$it" } ?: "client:<wi_ client of trust ${sink.trust}, created by this apply>"
        // The applying identity never grants itself (it already holds what it applies with).
        if (subject == this.subject) return null
        return ProvisionGrant(subject, RELATION_MANAGER)
    }

    /** SSO-3921 — the `workloadPull` grant with the trust's REAL workload client, read fresh (the trust may have been created by this apply). */
    private fun workloadPullGrantAtApply(r: ProvisionResource, change: PlannedChange, plane: String?): ProvisionGrant? {
        val name = r.secretSink?.takeIf { it.runtimePull }?.trust ?: return null
        val clientId = change.pullClientId ?: fetchOrNull { trustsOf(plane, fresh = true) }?.firstOrNull { it.str("name") == name }?.str("clientId")
            ?: throw ProvisionException("${r.key}: secretSink.trust '$name' is not visible in ${planeLabel(plane)} — the application exists, but no workload was granted to pull its secret; re-run once the trust exists")
        if ("client:$clientId" == subject) return null
        return ProvisionGrant("client:$clientId", RELATION_MANAGER)
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
                    .also { if (type == OBJECT_TYPE_TRUST) trustObjectsKnown = true }
            } catch (ex: ProductApiException) {
                // SSO-3774 — a platform that predates trust objects answers `400 invalid_type` for `trust`: it lists none.
                if (type == OBJECT_TYPE_TRUST && isUnknownTrustType(ex)) emptySet<String>().also { trustObjectsKnown = false } else throw accessFailure(ex)
            }
        }

        /**
         * SSO-3774 (oauthy ADR 2026-10-16 §1, story S1 SSO-3772) — whether the platform knows `trust:<id>` as an object.
         * Null until asked; `false` once a check / listing on a trust answered `400` (a product-api from before S1, whose
         * grammar has no such type). The engine then gates a trust by its PLANE, exactly as before S1.
         */
        private var trustObjectsKnown: Boolean? = null

        private fun isUnknownTrustType(ex: ProductApiException): Boolean = ex.httpStatus == 400 && !ex.isInsufficientScope

        /** [holds] on a `trust:<id>`, or null when the platform predates trust objects (see [trustObjectsKnown]). */
        private fun trustHolds(ref: String, relation: String): Boolean? {
            if (trustObjectsKnown == false) return null
            checks[ref to relation]?.let { return it.allowed }
            return try {
                clients(null).checkAccess(ref, relation).also { checks[ref to relation] = it; trustObjectsKnown = true }.allowed
            } catch (ex: ProductApiException) {
                if (isUnknownTrustType(ex)) null.also { trustObjectsKnown = false } else throw accessFailure(ex)
            }
        }

        /**
         * SSO-3774 — the relation held on the TRUST object itself (`manager` ⊇ owner ∪ parent.manager on the model), or null
         * when the platform predates trust objects. The caller unions it with the plane's relation (ADR §1 / §5: a trust whose
         * parent edge is not stored yet is still reached through its environment).
         */
        fun onTrust(ref: String): Access? = when (trustHolds(ref, RELATION_MANAGER)) {
            null -> null
            true -> Access.MANAGER
            false -> if (trustHolds(ref, RELATION_VIEWER) == true) Access.VIEWER else Access.NONE
        }

        /** SSO-3774 — whether THIS identity is the `owner` of the trust (`false` on a platform that predates trust objects). */
        fun ownsTrust(ref: String): Boolean = trustHolds(ref, RELATION_OWNER) == true

        /**
         * SSO-3774 — whether the platform knows `trust:<id>` objects, asked (once, by listing this identity's trusts) only when
         * no trust has been checked yet: what decides whether a trust this identity cannot see may exist anyway.
         */
        fun trustObjectsSupported(): Boolean = trustObjectsKnown ?: run { ids(OBJECT_TYPE_TRUST, RELATION_VIEWER); trustObjectsKnown ?: true }

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
            // SSO-3722 — a 404 is the platform's "you reach nothing here" (SSO-3118): an empty list, so every declared
            // resource becomes an `access_not_reachable` row with its fix instead of one opaque exception.
            if (ex.httpStatus == 404) emptyList<JsonNode>().also { environments = it }
            // SSO-3990 — a scope 403 names the scope (import lists it and goes on; a plan renders it with the profile to add it to).
            else throw MissingScopeException.of(ex, ScopeRequirements.SCOPE_ENVIRONMENTS_READ, ScopeRequirements.Phase.PLAN, null, "list the workspace's environments")
                ?: ProvisionException("could not list the workspace's environments to resolve a resource's parent (${ex.message})")
        }

        fun environmentId(slug: String): String? = environments().firstOrNull { it.str("slug") == slug }?.str("id")

        /**
         * SSO-3792 — the creation slots this identity may see (`GET /api/v1/access/application-slots`), read ONCE per plan and
         * only when a create would otherwise be refused. A product-api from before SSO-3789 answers `404` (no such route):
         * no slots. Any other failure fails closed, like every access read.
         */
        private var slotList: List<JsonNode>? = null

        private fun slots(): List<JsonNode> = slotList ?: try {
            listItems(clients(null).listApplicationSlots(), "data").also { slotList = it }
        } catch (ex: ProductApiException) {
            if (ex.httpStatus == 404 || ex.httpStatus == 405) emptyList<JsonNode>().also { slotList = it } else throw accessFailure(ex)
        }

        /** The slots for [clientId] on [plane] HELD BY THIS IDENTITY (an admin's listing carries every holder's). */
        private fun slotsFor(clientId: String, plane: String): List<JsonNode> {
            val me = subject ?: return emptyList()
            return slots().filter { n ->
                n.str("subject") == me && (n.str("environment") ?: "") == plane &&
                    n.str("object")?.takeIf { it.startsWith("$OBJECT_TYPE_APPLICATION:") }?.substringAfter(':')?.let { decodePlatformId(it) } == clientId
            }
        }

        private fun JsonNode.expiredSlot(): Boolean =
            this["expired"]?.takeIf { it.isBoolean }?.asBoolean() == true ||
                str("expiresAt")?.let { runCatching { java.time.Instant.parse(it) }.getOrNull() }?.isBefore(java.time.Instant.now()) == true

        /** SSO-3792 — this identity's UNEXPIRED creation slot for [clientId] on the plane [slug] (null ⇒ production), or null. */
        fun slot(clientId: String, slug: String?): CreationSlot? {
            val plane = slug ?: PRODUCTION_ENV_SLUG
            return slotsFor(clientId, plane).firstOrNull { !it.expiredSlot() }?.let { CreationSlot(clientId, plane, it.str("expiresAt")) }
        }

        /** SSO-3792 — this identity's EXPIRED slot for [clientId] on [plane], to say why the plan is red again; null otherwise. */
        fun expiredSlot(clientId: String, plane: String): CreationSlot? =
            slotsFor(clientId, plane).firstOrNull { it.expiredSlot() }?.let { CreationSlot(clientId, plane, it.str("expiresAt")) }
    }

    /**
     * Gate one probed resource on the identity's reach, asked PER OBJECT. The verdict table of ADR 2026-10-13
     * §1, plus the "one owning repository" rule as the platform states it: `manager` ⇒ converge (unless the
     * platform says another identity OWNS it); `viewer` ⇒ only a matching `readOnly: true` reference; none ⇒
     * not visible; a create ⇒ `manager` on the parent.
     */
    private fun gate(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange {
        if (change.action == ChangeAction.ERROR) return change
        // SSO-3774 (oauthy ADR 2026-10-16 §4) — a trust is a platform object of its own (`trust:<id>`, S1 SSO-3772), gated
        // per object like an application; its own gate keeps the plane rules a trust still has (create, the pre-S1 platform).
        if (r.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST) return gateTrust(r, change, file, envSlugs, slug, reach)
        // SSO-3941 — a role is not a platform access object: product-api gates it on `tenant:roles.*` alone. SSO-4057 — nor is a
        // tenant-level legal document (`tenant:compliance.*` alone).
        if (r.kind in ProvisionFile.SCOPE_ONLY_KINDS) return gateScopeOnly(r, change)
        val gated = gateObject(r, change, file, envSlugs, slug, reach)
        // SSO-3774 (ADR 2026-10-16 I4) — an application this identity may converge may still not BIND a trust it does not manage.
        if (r.kind != ProvisionFile.KIND_APPLICATION || gated.action == ChangeAction.ERROR || gated.readOnly) return gated
        val bound = gateBinding(r, gated, slug, reach)
        // SSO-3767 — nor turn token exchange ON without reach on its environment.
        val exchange = if (bound.action == ChangeAction.ERROR) bound else gateTokenExchange(r, bound, file, envSlugs, slug, reach)
        // SSO-3810 — nor token introspection: the same reach, for the same kind of reason.
        return if (exchange.action == ChangeAction.ERROR) exchange else gateTokenIntrospection(r, exchange, file, envSlugs, slug, reach)
    }

    /**
     * SSO-3767 (oauthy SSO-3758) — turning `allowTokenExchange` ON for an EXISTING application needs `manager` on its
     * environment (the workspace on the production plane): the reach that may create an application there, so an identity
     * that manages one application — a repository's CI identity that owns it — cannot widen it into a token minter for its
     * users. product-api refuses that PATCH with `403 token_exchange_not_grantable`; the plan says so first, with the right
     * that fixes it (`manager` on the environment — a grantable item; on the production plane a note: the workspace's
     * `manager` is never granted to a repository identity). Asked only when the update TURNS IT ON (the diff names the field
     * and the file says `true`): turning it off, omitting it, or re-declaring the stored value is never refused, and a create
     * already needs `manager` on the parent ([gateObject]).
     */
    private fun gateTokenExchange(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange =
        gateEnvironmentWideSetting(
            r, change, file, envSlugs, slug, reach,
            ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE, ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE, TOKEN_EXCHANGE_WORKSPACE_NOTE,
        )

    /**
     * SSO-3810 (oauthy SSO-3810) — turning `allowTokenIntrospection` ON for an EXISTING application needs `manager` on its
     * environment, exactly like [gateTokenExchange]: an introspecting client reads the metadata of every token the
     * environment issues (other applications' included), so an identity that manages one application may not grant it to
     * itself. product-api answers `403 token_introspection_not_grantable`; the plan says so first. Turning it off, omitting
     * it, or re-declaring the stored value is never refused.
     */
    private fun gateTokenIntrospection(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange =
        gateEnvironmentWideSetting(
            r, change, file, envSlugs, slug, reach,
            ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION, ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE, TOKEN_INTROSPECTION_WORKSPACE_NOTE,
        )

    /** The shared rule of [gateTokenExchange] / [gateTokenIntrospection]: a boolean [field] the update TURNS ON needs `manager` on the parent. */
    private fun gateEnvironmentWideSetting(
        r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach,
        field: String, errorCode: String, workspaceNote: String,
    ): PlannedChange {
        if (change.action != ChangeAction.UPDATE || field !in change.diff) return change
        if (!coerceBool(r.spec[field])) return change
        val parent = parentRef(r, file, envSlugs, slug, reach) ?: return change
        if (reach.managesParent(parent)) return change
        val appAccess = Access.entries.firstOrNull { it.label == change.access }
        val why = "turning $field on for ${r.key} requires `manager` on its environment $parent — the reach that may create an " +
            "application there; managing the application alone is not enough (product-api answers `403 $errorCode`)"
        return if (parent.startsWith("$OBJECT_TYPE_WORKSPACE:")) {
            refuse(r, change, errorCode, appAccess, "$why ($workspaceNote)", fixNote = workspaceNote)
        } else {
            val fix = FixRequest.manager(subject, parent, why)
            refuse(r, change, errorCode, appAccess, "$why (${FixRequest.hint(fix)})", fix = fix)
        }
    }

    /** The per-object verdict of [gate] for every kind but a trust. */
    private fun gateObject(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange {
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
                // SSO-3710 — the right that fixes "not visible" is `viewer` for a read-only reference, `owner` for a
                // resource this file is to own (the ADR's grantable set: rights on existing things, set by an admin).
                Access.NONE -> {
                    val why = "this identity holds no relation on $ref — the resource is not visible to it and cannot be imported or converged"
                    val fix = if (r.readOnly) FixRequest.viewer(subject, ref, why) else FixRequest.owner(subject, ref, why)
                    refuse(r, change, ERROR_NOT_OWNED, access, "$why (${FixRequest.hint(fix)})", fix = fix)
                }
                Access.VIEWER -> when {
                    !r.readOnly -> {
                        val why = "this identity may only VIEW $ref — declare the resource `readOnly: true` to depend on it without owning it, or own it"
                        val fix = FixRequest.owner(subject, ref, why)
                        refuse(r, change, ERROR_READ_ONLY, access, "$why (${FixRequest.hint(fix)})", fix = fix)
                    }
                    differs -> refuse(
                        r, change, ERROR_READ_ONLY, access,
                        "read-only reference differs from the live resource in ${change.diff.size} field(s) (${change.diff.keys.joinToString(", ")}) — " +
                            "a repository that does not own a resource cannot change it; align the file with what is live",
                        fixNote = FILE_FIX_NOTE,
                    )
                    else -> reference(change, access)
                }
                Access.MANAGER -> when {
                    r.readOnly && differs -> refuse(
                        r, change, ERROR_READ_ONLY, access,
                        "declared `readOnly: true` but differs from the live resource in ${change.diff.size} field(s) (${change.diff.keys.joinToString(", ")}) — " +
                            "a read-only reference is never written; drop `readOnly` to converge it from this file, or align the file with what is live",
                        fixNote = FILE_FIX_NOTE,
                    )
                    r.readOnly -> reference(change, access)
                    // SSO-3673 — the platform renders the object's `owner`; when there is one and the check says it is not
                    // this identity, another repository owns it. Nothing about that subject is echoed (no oracle).
                    // SSO-3710 — a dispute: the request names it (kind `owner`) with NO command — an admin decides.
                    change.owner != null && !reach.owns(ref) -> {
                        val why = "$ref is owned by another repository (the platform's `owner` relation) — one repository owns a resource; " +
                            "declare it `readOnly: true` here to depend on it, or have a workspace admin move the ownership " +
                            "(`thoryn access revoke <current-owner> owner $ref`, then `${FixRequest.grantCommand(FixRequest.SUBJECT_PLACEHOLDER, RELATION_OWNER, ref)}`)"
                        refuse(r, change, ERROR_OWNED_ELSEWHERE, access, why, fix = FixRequest.ownedElsewhere(subject, ref, why))
                    }
                    else -> change.copy(access = access.label)
                }
            }
        }
        // A create. A read-only reference is a dependency on something that exists — it is never created.
        if (r.readOnly) {
            return refuse(
                r, change, ERROR_READ_ONLY, null,
                "declared `readOnly: true` but nothing matches it live — a read-only reference is never created; declare it without `readOnly` to own it",
                fixNote = FILE_FIX_NOTE,
            )
        }
        val parent = parentRef(r, file, envSlugs, slug, reach)
            ?: return change.copy(access = Access.MANAGER.label) // the parent environment is created by this very apply: creator-becomes-manager covers both
        if (reach.managesParent(parent)) return change.copy(access = Access.MANAGER.label)
        // SSO-3792 — a workspace admin may have reserved a creation slot for exactly this client id on exactly this plane.
        val fixedId = fixedClientId(r)
        fixedId?.let { id -> reach.slot(id, slug)?.let { return reservedCreate(r, change, slug, it) } }
        return refuseCreate(r, change, parent, slug, fixedId, reach, "creating a ${r.kind} here requires `manager` on its parent $parent, which this identity does not hold")
    }

    /**
     * SSO-3941 — the verdict for a `role`. A role is NOT an object of the platform authorization graph (there is no `role:`
     * type; product-api gates `/api/v1/roles` on the token's `tenant:roles.read` / `.write` alone, in the plane the caller
     * reaches), so there is no relation to ask and no owner: the token's scope is the whole gate, and the plan preflight
     * names it ([ScopeRequirements]). What remains is the file's own `readOnly` contract — a reference must exist and match.
     */
    private fun gateScopeOnly(r: ProvisionResource, change: PlannedChange): PlannedChange = when {
        !r.readOnly -> change
        change.liveId == null -> refuse(
            r, change, ERROR_READ_ONLY, null,
            "declared `readOnly: true` but nothing matches it live — a read-only reference is never created; declare it without `readOnly` to own it",
            fixNote = FILE_FIX_NOTE,
        )
        change.diff.isNotEmpty() -> refuse(
            r, change, ERROR_READ_ONLY, null,
            "declared `readOnly: true` but differs from the live ${r.kind} in ${change.diff.size} field(s) (${change.diff.keys.joinToString(", ")}) — " +
                "a read-only reference is never written; drop `readOnly` to converge it from this file, or align the file with what is live",
            fixNote = FILE_FIX_NOTE,
        )
        else -> change.copy(action = ChangeAction.NOOP, reason = "read-only reference — exists and matches; this file does not own it", readOnly = true, diff = emptyMap())
    }

    /** SSO-3792 — the fixed `spec.clientId` of an application (the converge key and the slot's name), or null. */
    private fun fixedClientId(r: ProvisionResource): String? =
        if (r.kind != ProvisionFile.KIND_APPLICATION) null else resolveSpec(r, strict = false)["clientId"]?.toString()?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * SSO-3710 — a create refused on its parent: `manager` on a parent ENVIRONMENT is a grantable right (an item with
     * its command); `manager` on the WORKSPACE is not — a production-plane create needs a workspace manager, which a
     * confined repository identity must never be — so that row is a note, not a right (ADR §3 grantable set).
     *
     * SSO-3792 (oauthy ADR 2026-10-17 §6, decision D3) — except an APPLICATION on the PRODUCTION plane with a fixed
     * `clientId`: its creation is approvable, one name at a time, as a creation slot ([creatorRefusal]). Without a fixed id
     * the note says to declare one. Sandboxes keep `manager` on their environment.
     */
    private fun refuseCreate(r: ProvisionResource, change: PlannedChange, parent: String, slug: String?, fixedId: String?, reach: Reach, why: String): PlannedChange =
        if (parent.startsWith("$OBJECT_TYPE_WORKSPACE:")) {
            val production = slug == null || slug == PRODUCTION_ENV_SLUG
            if (fixedId != null && production) creatorRefusal(r, change, ERROR_NOT_OWNED, null, why, fixedId, reach)
            else workspaceParentRefusal(r, change, ERROR_NOT_OWNED, null, why)
        } else {
            val fix = FixRequest.manager(subject, parent, why)
            refuse(r, change, ERROR_NOT_OWNED, null, "$why (${FixRequest.hint(fix)})", fix = fix)
        }

    /**
     * SSO-3774 (oauthy ADR 2026-10-16 §1 / §4) — the ownership gate for a `workloadIdentityTrust`, asked PER OBJECT like
     * [gateObject] asks for an application. A live trust is gated on the relation held on `trust:<id>` UNIONED with the
     * relation held on its plane (the environment, the workspace for the production plane): the model's containment
     * already folds `parent.manager` into the trust, and the union keeps an existing trust whose parent edge the
     * platform has not stored yet (ADR §5) reachable by everyone who reaches its plane. `manager` ⇒ converge (unless the
     * response's `owner` names another repository: `access_owned_elsewhere`); `viewer` ⇒ only a matching `readOnly: true`
     * reference; none ⇒ `access_not_owned`, each with the right on the trust itself as its fix (`owner trust:<id>`).
     *
     * A CREATE keeps the plane rule — `manager` on the environment, the workspace note on production — plus the PERSON
     * rule of ADR §3 / Q2: a production-plane trust is created by a person, once, so a `client:` identity (CI) is refused
     * with the founder's command ([ERROR_TRUST_PRODUCTION_PERSON]); when that identity cannot see the whole plane, the
     * trust may exist and be invisible to it, so the row is `access_not_reachable` with `owner` on the trust by NAME.
     *
     * A platform that predates trust objects (product-api before S1 answers `400 invalid_type` for `trust:`) is gated by
     * the plane alone, exactly as before ([gateTrustByPlane]). The platform re-checks every write either way.
     */
    private fun gateTrust(r: ProvisionResource, change: PlannedChange, file: ProvisionFile, envSlugs: Map<String, String>, slug: String?, reach: Reach): PlannedChange {
        val parent = parentRef(r, file, envSlugs, slug, reach)
        val plane = planeAccess(parent, reach)
        val liveId = change.liveId
        if (liveId != null) {
            val ref = objectRef(r.kind, liveId, slug)
            val direct = reach.onTrust(ref) ?: return gateTrustByPlane(r, change, parent, plane)
            return when (val access = stronger(direct, plane)) {
                Access.NONE -> {
                    val why = "this identity holds no relation on $ref (nor on its plane) — the trust is not visible to it and cannot be imported or converged"
                    val fix = if (r.readOnly) FixRequest.viewer(subject, ref, why) else FixRequest.owner(subject, ref, why)
                    refuse(r, change, ERROR_NOT_OWNED, access, "$why (${FixRequest.hint(fix)})", fix = fix)
                }
                Access.VIEWER -> if (!r.readOnly) {
                    val why = "this identity may only VIEW $ref — declare the trust `readOnly: true` to depend on it without owning it, or own it"
                    val fix = FixRequest.owner(subject, ref, why)
                    refuse(r, change, ERROR_READ_ONLY, access, "$why (${FixRequest.hint(fix)})", fix = fix)
                } else {
                    reference(change, access)
                }
                Access.MANAGER -> when {
                    r.readOnly -> reference(change, access)
                    // The response renders the trust's `owner` (S1); another subject owns it ⇒ another repository's trust.
                    change.owner != null && !reach.ownsTrust(ref) -> {
                        val why = "$ref is owned by another repository (the platform's `owner` relation) — one repository owns a trust; " +
                            "declare it `readOnly: true` here to depend on it, or have a workspace admin move the ownership " +
                            "(`thoryn access revoke <current-owner> owner $ref`, then `${FixRequest.grantCommand(FixRequest.SUBJECT_PLACEHOLDER, RELATION_OWNER, ref)}`)"
                        refuse(r, change, ERROR_OWNED_ELSEWHERE, access, why, fix = FixRequest.ownedElsewhere(subject, ref, why))
                    }
                    else -> change.copy(access = access.label)
                }
            }
        }
        val production = r.environment == null || slug == PRODUCTION_ENV_SLUG
        // Not visible to this identity: the plane is not fully readable to it, and the platform filters the list (S1), so
        // "absent" may be "present, but nothing held on it". Then the right that reveals it is a right on the trust.
        val hidden = plane == Access.NONE && parent != null && reach.trustObjectsSupported()
        if (hidden) trustsHidden += r.name
        if (r.readOnly) {
            if (hidden) {
                val why = "no trust named '${r.name}' is visible to this identity in ${planeLabel(slug)} — a read-only reference must exist; if it does, this identity holds no relation on it"
                val fix = FixRequest.byName(FixRequest.Kind.VIEWER, subject, r.name, slug, why)
                return refuse(r, change, ERROR_NOT_REACHABLE, Access.NONE, "$why (${FixRequest.hint(fix)})", fix = fix)
            }
            return refuse(
                r, change, ERROR_READ_ONLY, null,
                "declared `readOnly: true` but nothing matches it live — a read-only reference is never created; declare it without `readOnly` to own it",
                fixNote = FILE_FIX_NOTE,
            )
        }
        if (production && subject?.startsWith("client:") == true) {
            val note = productionTrustPersonNote(subject, r.name)
            if (hidden) {
                val why = "no trust named '${r.name}' is visible to this identity on the production plane: either it exists and this identity holds no " +
                    "relation on it, or it does not exist yet — and a production trust is created by a person, never by this file from CI ($note)"
                val fix = FixRequest.byName(FixRequest.Kind.OWNER, subject, r.name, slug, why)
                return refuse(r, change, ERROR_NOT_REACHABLE, Access.NONE, "$why (if it exists: ${FixRequest.hint(fix)})", fix = fix)
            }
            return refuse(r, change, ERROR_TRUST_PRODUCTION_PERSON, null, "creating a ${r.kind} on the PRODUCTION plane is a person's act, never this CI identity's ($note)", fixNote = note)
        }
        return if (plane == Access.MANAGER) {
            change.copy(access = Access.MANAGER.label)
        } else {
            refuseOnParent(r, change, ERROR_NOT_OWNED, null, parent, "creating a ${r.kind} here requires `manager` on its environment ${parent ?: "its environment (created by this apply)"}, which this identity does not hold")
        }
    }

    /** The pre-S1 gate of a live trust: the relation on its PLANE only (a platform without `trust:` objects reaches a trust through it). */
    private fun gateTrustByPlane(r: ProvisionResource, change: PlannedChange, parent: String?, access: Access): PlannedChange {
        val where = parent ?: "its environment (created by this apply)"
        return when (access) {
            // The right is `manager` on its PARENT environment (a note when that parent is the workspace: a confined identity
            // must never manage the workspace).
            Access.NONE -> refuseOnParent(r, change, ERROR_NOT_OWNED, access, parent, "this identity holds no relation on $where — this platform reaches a trust through its environment, so it is not visible to it")
            Access.VIEWER -> if (!r.readOnly) {
                refuseOnParent(r, change, ERROR_READ_ONLY, access, parent, "this identity may only VIEW $where — declare the trust `readOnly: true` to depend on it without owning it, or manage its environment")
            } else {
                reference(change, access)
            }
            Access.MANAGER -> if (r.readOnly) reference(change, access) else change.copy(access = access.label)
        }
    }

    /** The relation held on a trust's PLANE: `manager` when the plane is created by this apply ([parent] null). */
    private fun planeAccess(parent: String?, reach: Reach): Access = when {
        parent == null -> Access.MANAGER // the environment is created by this very apply: creator-becomes-manager covers both
        reach.managesParent(parent) -> Access.MANAGER
        reach.holds(parent, RELATION_VIEWER) -> Access.VIEWER
        else -> Access.NONE
    }

    private fun stronger(a: Access, b: Access): Access = if (a.ordinal <= b.ordinal) a else b

    /** The plane object of a resource living in [slug]: the workspace for the production plane, else `environment:<id>`. */
    private fun planeParentRef(slug: String?, reach: Reach): String {
        val workspace = "$OBJECT_TYPE_WORKSPACE:${workspaceId ?: "(this workspace)"}"
        if (slug == null || slug == PRODUCTION_ENV_SLUG) return workspace
        return reach.environmentId(slug)?.let { objectRef(ProvisionFile.KIND_ENVIRONMENT, it, null) } ?: workspace
    }

    /**
     * SSO-3774 (oauthy ADR 2026-10-16 I4; product-api SSO-3773) — binding a login client to a trust needs `manager` on the
     * TRUST as well as on the application, checked where the platform checks it: when the binding is SET (a create) or
     * CHANGED (an update whose diff names `federatedTrust`) — an unchanged binding is never re-checked. The platform answers
     * a refused binding with the same opaque `400 federated_trust_not_found` as an unknown trust; the plan says why instead,
     * with the right that fixes it (`owner trust:<id>`), or — when another repository owns the trust — the dispute.
     * A trust this apply creates is the creator's to bind (creator-becomes-manager); a trust the identity cannot see is the
     * `access_not_reachable` row [federatedTrustRef] already made.
     */
    private fun gateBinding(r: ProvisionResource, change: PlannedChange, slug: String?, reach: Reach): PlannedChange {
        val name = r.spec[ProvisionFile.SPEC_FEDERATED_TRUST]?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return change
        val sets = change.action == ChangeAction.CREATE || (change.action == ChangeAction.UPDATE && ProvisionFile.SPEC_FEDERATED_TRUST in change.diff)
        if (!sets) return change
        val node = fetchOrNull { trustsOf(slug) }?.firstOrNull { it.str("name") == name } ?: return change
        val id = node.str("id") ?: return change
        val ref = objectRef(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, id, slug)
        val plane = planeAccess(planeParentRef(slug, reach), reach)
        if (stronger(reach.onTrust(ref) ?: Access.NONE, plane) == Access.MANAGER) return change
        val appAccess = Access.entries.firstOrNull { it.label == change.access }
        val why = "binding ${r.key} to trust '$name' ($ref) requires `manager` on the trust, which this identity does not hold — the platform refuses " +
            "a binding to a trust its caller does not manage (answered as `$ERROR_FEDERATED_TRUST_NOT_FOUND`)"
        return if (ProvisionApi.ownerOf(node) != null) {
            val dispute = "$why; $ref is owned by another repository — bind a trust this repository owns, or have a workspace admin move the ownership " +
                "(`thoryn access revoke <current-owner> owner $ref`, then `${FixRequest.grantCommand(FixRequest.SUBJECT_PLACEHOLDER, RELATION_OWNER, ref)}`)"
            refuse(r, change, ERROR_OWNED_ELSEWHERE, appAccess, dispute, fix = FixRequest.ownedElsewhere(subject, ref, dispute))
        } else {
            val fix = FixRequest.owner(subject, ref, why)
            refuse(r, change, ERROR_NOT_OWNED, appAccess, "$why (${FixRequest.hint(fix)})", fix = fix)
        }
    }

    /** SSO-3710 — a trust row refused on its parent plane: `manager` on an environment is an item, on the workspace a note. */
    private fun refuseOnParent(r: ProvisionResource, change: PlannedChange, code: String, access: Access?, parent: String?, why: String): PlannedChange =
        when {
            parent == null || parent.startsWith("$OBJECT_TYPE_WORKSPACE:") -> refuse(r, change, code, access, "$why ($WORKSPACE_PARENT_NOTE)", fixNote = WORKSPACE_PARENT_NOTE)
            else -> FixRequest.manager(subject, parent, why).let { fix -> refuse(r, change, code, access, "$why (${FixRequest.hint(fix)})", fix = fix) }
        }

    private fun refuse(
        r: ProvisionResource,
        change: PlannedChange,
        code: String,
        access: Access?,
        why: String,
        fix: FixRequest.MissingRight? = null,
        fixNote: String? = null,
    ): PlannedChange =
        change.copy(
            action = ChangeAction.ERROR, reason = "$code — $why", error = code, access = access?.label, readOnly = r.readOnly, retain = r.retain,
            // The item's reason carries the gate's code like the row's does (`access_not_owned — …`), so a consumer reads one shape.
            fix = fix?.copy(reason = "$code — ${fix.reason}"), fixNote = fixNote,
        )

    /** A read-only reference that exists and matches: a no-op that is never owned, never removed. */
    private fun reference(change: PlannedChange, access: Access): PlannedChange = change.copy(
        action = ChangeAction.NOOP,
        reason = "read-only reference (${access.label}) — exists and matches; this file does not own it",
        readOnly = true, access = access.label, diff = emptyMap(),
    )

    // ── deletion authority (SSO-3715; ADR 2026-10-15 §1) ────────────────────────────────────────

    /** The verdict of [mayRemove]: whether this identity may remove the live resource, else why not and what a human runs. */
    private class RemovalVerdict(val allowed: Boolean, val reason: String, val byHand: String? = null, val cascade: Boolean = false) {
        companion object {
            val ALLOWED = RemovalVerdict(true, "")
        }
    }

    /**
     * Whether the signed-in identity may remove the declared, live resource — the ADR's rule, evaluated here before
     * every removal and re-checked by product-api on the DELETE (404, never widened):
     *  - `retain: true` ⇒ never; a `readOnly` reference ⇒ never (it is not this file's);
     *  - an ownable kind (`application` / `environment`): a `client:` identity needs `/access/check owner` (manager
     *    alone never suffices for automation); a `member:` identity needs `manager` on an object NOBODY owns;
     *  - a non-ownable kind (`user`, `federationMember`, a singleton, a trust): with its sandbox — when the file
     *    declares the parent environment and this identity may remove THAT (the hard-delete cascades); never on
     *    the production plane (left in place, reported with its command).
     * An unknown subject (a person's opaque token; a machine session always names its client) takes the person's rule.
     */
    private fun mayRemove(r: ProvisionResource, change: PlannedChange, slug: String?, file: ProvisionFile, envSlugs: Map<String, String>, reach: Reach, visiting: Set<String> = emptySet()): RemovalVerdict {
        val id = change.liveId ?: return RemovalVerdict(false, "nothing matches it live — nothing to remove")
        if (r.readOnly) return RemovalVerdict(false, "read-only reference — this file does not own it, so it is never removed")
        if (r.retain) return RemovalVerdict(false, RETAINED)
        val plane = if (r.kind == ProvisionFile.KIND_ENVIRONMENT) null else slug
        val subjectType = subject?.substringBefore(':')
        if (r.kind in OWNABLE_KINDS) {
            val ref = objectRef(r.kind, id, plane)
            val byHand = removeByHand(r.kind, id, plane, change.attributes["slug"])
            return when (subjectType) {
                "client" -> when {
                    reach.owns(ref) -> RemovalVerdict.ALLOWED
                    change.owner != null -> RemovalVerdict(false, "$ref is owned by another repository (the platform's `owner` relation) — change its file; a workspace admin moves ownership with `thoryn access revoke <current-owner> owner $ref`", byHand)
                    else -> RemovalVerdict(false, "$ref is not OWNED by this identity — `manager` alone never lets automation delete; a workspace admin grants `${FixRequest.grantCommand(subject, RELATION_OWNER, ref)}`, or a person removes it", byHand)
                }
                else -> when {
                    change.owner != null -> RemovalVerdict(false, "$ref is owned by a repository (the platform's `owner` relation) — change its file; people cannot own, so a person's destroy leaves it", byHand)
                    reach.holds(ref, RELATION_MANAGER) -> RemovalVerdict.ALLOWED
                    else -> RemovalVerdict(false, "this identity does not manage $ref", byHand)
                }
            }
        }
        // SSO-3774 (oauthy ADR 2026-10-16 §4) — a trust is ownable since S1: the `client:` identity that OWNS it removes it, on
        // any plane (production behind `--confirm`). A person never owns one, so a person's destroy keeps the rule below.
        val byHand = removeByHand(r.kind, id, plane, null)
        if (r.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST && subjectType == "client") {
            val ref = objectRef(r.kind, id, plane)
            if (reach.ownsTrust(ref)) return RemovalVerdict.ALLOWED
            if (plane == null || plane == PRODUCTION_ENV_SLUG) {
                return RemovalVerdict(
                    false,
                    if (change.owner != null) "$ref is owned by another repository (the platform's `owner` relation) — change its file; a workspace admin moves ownership with `thoryn access revoke <current-owner> owner $ref`"
                    else "a ${r.kind} on the PRODUCTION plane is removed by destroy / --prune only by the repository that OWNS it, and $ref is not owned by this identity — left in place",
                    byHand,
                )
            }
        }
        // Non-ownable: with the sandbox, never on the production plane.
        if (plane == null || plane == PRODUCTION_ENV_SLUG) {
            return RemovalVerdict(false, "a ${r.kind} on the PRODUCTION plane is never removed by destroy / --prune — left in place", byHand)
        }
        val parent = file.resources.firstOrNull { it.kind == ProvisionFile.KIND_ENVIRONMENT && (it.name == r.environment || envSlugs[it.name] == plane) }
            ?: return RemovalVerdict(false, "lives in sandbox '$plane', which this file does not declare — a ${r.kind} is removed with its sandbox only; left in place", byHand)
        if (parent.key in visiting) return RemovalVerdict(false, "its sandbox '$plane' cannot be removed", byHand)
        val parentId = reach.environmentId(plane) ?: return RemovalVerdict(false, "its sandbox '$plane' is not in the workspace's environment list", byHand)
        val parentChange = PlannedChange(parent.kind, parent.name, ChangeAction.NOOP, "", resource = parent, liveId = parentId, attributes = mapOf("slug" to plane), owner = reach.environments().firstOrNull { it.str("id") == parentId }?.let { ProvisionApi.ownerOf(it) })
        val parentVerdict = mayRemove(parent, parentChange, null, file, envSlugs, reach, visiting + r.key)
        return if (parentVerdict.allowed) {
            RemovalVerdict(true, "removed with its sandbox '$plane' (the environment hard-delete cascades; no call of its own)", cascade = true)
        } else {
            RemovalVerdict(false, "removed only with its sandbox '$plane', which stays (${parentVerdict.reason.substringBefore(" —")}) — left in place", byHand)
        }
    }

    /** The command a person runs to remove one resource of [kind] by hand (the CLI's own verbs; `--environment` for a sandbox). */
    private fun removeByHand(kind: String, id: String, plane: String?, envSlug: String?): String {
        val env = plane?.let { " --environment $it" } ?: ""
        val confirm = if (plane == null) " --confirm <workspace-slug>" else ""
        return when (kind) {
            ProvisionFile.KIND_ENVIRONMENT -> "thoryn env delete $id --confirm ${envSlug ?: "<slug>"}"
            ProvisionFile.KIND_APPLICATION -> "thoryn clients delete $id$confirm$env"
            ProvisionFile.KIND_USER -> "DELETE /api/v1/users/$id (the CLI has no `users delete`; `thoryn users suspend $id$confirm$env` disables the sign-in)"
            ProvisionFile.KIND_FEDERATION_MEMBER -> "thoryn federation delete $id$confirm$env"
            ProvisionFile.KIND_EMAIL_PROVIDER -> "DELETE /api/v1/email-provider (reset to the platform sender)$env"
            ProvisionFile.KIND_LOGIN_METHODS -> "thoryn login-methods reset$env"
            // SSO-4041 — the API has no DELETE; the empty record restores the platform defaults (`thoryn branding set` with an empty value clears one field at a time).
            ProvisionFile.KIND_LOGIN_THEME -> "PUT /api/v1/login-experience/branding {} (the API has no DELETE; the empty record restores the platform defaults — or `thoryn branding set --logo-url '' --primary-color '' --background-color '' --theme '' --display-name '' --page-title '' --favicon-url '' --support-url '' --terms-url '' --privacy-url ''`)$env"
            ProvisionFile.KIND_LOGIN_FLOW -> "activate another login flow (no delete surface)$env"
            ProvisionFile.KIND_CUSTOM_DOMAIN -> "thoryn domain remove --yes"
            // SSO-4042 — the CLI has no `email-templates` verb; the API call, which resets the cell to the built-in default.
            ProvisionFile.KIND_EMAIL_TEMPLATE -> "DELETE /api/v1/login-experience/email-templates/${id.substringBefore(':')}" +
                id.substringAfter(':', ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE).takeIf { it != ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE }?.let { "?locale=$it" }.orEmpty() +
                (plane?.let { " with header X-Thoryn-Environment: $it (resets that environment's copy — it then sends production's" } ?: " (resets it to the built-in default") +
                "; the CLI has no `email-templates` command)"
            // SSO-4057 — the CLI has no `legal-documents` verb; the API call. [id] is `<type>/<version id>`, the API's own path.
            ProvisionFile.KIND_LEGAL_DOCUMENT -> "DELETE /api/v1/login-experience/legal-documents/$id" +
                (plane?.let { " with header X-Thoryn-Environment: $it" } ?: "") +
                " (soft-deletes that version, leaving the environment with no ${id.substringBefore('/')} — no fallback to another environment's; " +
                "refused 409 document_accepted once a user accepted it: a published document is replaced by publishing a new version, never removed; " +
                "the CLI has no `legal-documents` command)"
            ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> "thoryn workload-identity trusts delete $id --yes${if (plane == null) " --confirm <workspace-slug>" else ""}$env"
            // SSO-3941 — the CLI has no `roles delete`; the API call, with the production confirmation it needs.
            ProvisionFile.KIND_ROLE -> "DELETE /api/v1/roles/$id (the CLI has no `roles delete`${if (plane == null) "; send X-Thoryn-Confirm: <workspace-slug>" else "; header X-Thoryn-Environment: $plane"})"
            else -> "remove it through the console"
        }
    }

    // ── destroy (SSO-3715) ───────────────────────────────────────────────────────────────────────

    /**
     * What `destroy` would remove: every declared resource resolved live and judged by [mayRemove] — a
     * [ChangeAction.REMOVE] row when this identity may remove it, a [ChangeAction.SKIP] row (with the reason and
     * the command a human runs) when not. Children first, trusts next, environments last. Reads only.
     */
    fun planDestroy(file: ProvisionFile): ProvisionPlan {
        trustLists.clear()
        val envSlugs = mutableMapOf<String, String>()
        val reach = Reach()
        val probed = mutableListOf<Triple<ProvisionResource, PlannedChange, String?>>()
        orderForApply(file.resources).forEach { r ->
            val slug = planSlug(r, file, envSlugs)
            val change = probe(r, file, envSlugs)
            if (r.kind == ProvisionFile.KIND_ENVIRONMENT && change.liveId != null) envSlugs[r.name] = resolveSpec(r, strict = false)["slug"].toString()
            probed += Triple(r, change, slug)
        }
        val rows = probed.map { (r, change, slug) ->
            if (change.action == ChangeAction.ERROR) return@map change
            val verdict = mayRemove(r, change, slug, file, envSlugs, reach)
            when {
                change.liveId == null -> PlannedChange(r.kind, r.name, ChangeAction.SKIP, "not found by its converge key — nothing to remove", resource = r, environment = slug, retain = r.retain)
                verdict.allowed && verdict.cascade -> change.copy(action = ChangeAction.SKIP, reason = verdict.reason, access = null)
                verdict.allowed -> change.copy(action = ChangeAction.REMOVE, reason = "will be removed" + if (r.kind == ProvisionFile.KIND_ENVIRONMENT) " (its contents go with it)" else "", access = null)
                else -> change.copy(action = ChangeAction.SKIP, reason = verdict.reason, byHand = verdict.byHand, access = null)
            }
        }
        return ProvisionPlan(orderForRemove(rows))
    }

    /**
     * Execute a [planDestroy] plan (or the removals of an `apply --prune` plan): every [ChangeAction.REMOVE] row,
     * child-first. Best-effort: a failed removal is reported and the resource stays live for a retry. Refuses up
     * front when a production-plane removal lacks [confirmSlug].
     */
    fun destroy(plan: ProvisionPlan, confirmSlug: String?): RemovalOutcome {
        if (plan.removesOnProductionPlane && confirmSlug.isNullOrBlank()) {
            throw ProvisionException("destroy would remove resources on the PRODUCTION plane; re-run with --confirm <workspace-slug>.")
        }
        val removed = mutableListOf<AppliedResource>()
        val failures = mutableListOf<String>()
        orderForRemove(plan.removes).forEach { change ->
            try {
                remove(change, confirmSlug)
                removed += AppliedResource(change.kind, change.name, change.liveId ?: "", change.environment, change.attributes, change.owner, ChangeAction.REMOVE)
            } catch (ex: Exception) {
                failures += "${change.key} (id ${change.liveId}): ${ex.message}"
                err.println("  ! ${change.kind} ${change.name} could not be removed (${ex.message}); it stays live — re-run to retry.")
            }
        }
        return RemovalOutcome(removed, failures)
    }


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
    private fun accessFailure(ex: ProductApiException): ProvisionException =
        // SSO-3926 — the scope, as a [MissingScopeException] the host renders with the profile to add it to.
        MissingScopeException.of(
            ex, AccessRefs.SCOPE_READ, ScopeRequirements.Phase.PLAN, null,
            "check this identity's access — ownership is decided by the relation it holds on each resource (`POST /api/v1/access/check`)",
        ) ?: ProvisionException("could not check this identity's access (${ex.message}); nothing was planned or written")

    // ── import (SSO-3659; ADR 2026-10-13 §2; SSO-3990 — for a config project's workflow) ─────────

    /**
     * The inverse of [plan], bounded by the same relations: every live platform object the identity holds
     * `manager` on is rendered as an entry the file converges (and, by the §1 rule, may remove), every one it
     * may only `viewer` as `readOnly: true`; an object the platform says another identity OWNS (SSO-3673: its
     * response renders an `owner` and `/access/check owner` is false for this identity) is rendered
     * `readOnly: true` as well. Nothing the identity has no relation to is listed by the platform, so nothing
     * it has no relation to can be imported — the file cannot claim by being written. Resources [existing]
     * already declares are left out; what is reachable but cannot be rendered as a `provision.yaml` entry
     * lands on [ImportResult.skipped] with the reason. Reads only; SSO-3715 — `import` writes the file only.
     *
     * **SSO-3990 (thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13.5)** — what is written must plan as all
     * `noop` in the target file, with the identity that will plan and apply it ([options]):
     *
     *  - **part-aware** — only the kinds of the target file's part are rendered ([existing]'s part, else
     *    [ImportOptions.part]); every object of another part is listed on [ImportResult.skipped] with the reason;
     *  - **scope-aware** — each entry is held to exactly the needs `config.trust-scopes` holds the file to
     *    ([ScopeRequirements.ofResources]): a plan need outside [ImportOptions.planScopes] ⇒ not imported, naming the
     *    scope (a kind whose read scope is missing is never even read — no `403` aborts the run, and one that happens
     *    anyway is listed the same way); an apply need outside [ImportOptions.applyScopes] ⇒ `readOnly: true`;
     *  - `emailProvider` and `federationMember` are always `readOnly: true` — their secrets are write-only and a CI apply
     *    has no channel for them; production-plane users are never imported (counted), sandbox test users are; the
     *    repository's own trusts ([ImportOptions.ownTrustClients] and the signed-in client) are never imported;
     *  - **plane routing** ([ImportOptions.routing]) — an object goes to exactly one configured file: a sandbox object to
     *    the file planned with that sandbox's connection, everything else to the production connection's file;
     *  - `role` is rendered (name, description, the full permission set) — `readOnly` without `tenant:roles.write`.
     */
    fun import(existing: ProvisionFile?, options: ImportOptions = ImportOptions()): ImportResult {
        val reach = Reach()
        val out = mutableListOf<ImportedResource>()
        val skipped = mutableListOf<String>()
        fun skip(why: String) { skipped += why }
        val part = existing?.part ?: options.part
        val declared = existing?.resources.orEmpty()
        val names = declared.map { it.key }.toMutableSet()
        val routing = options.routing
        fun uniqueName(kind: String, base: String): String {
            val root = slugName(base).ifEmpty { kind.lowercase() }
            var candidate = root
            var n = 2
            while (!names.add("$kind/$candidate")) candidate = "$root-${n++}".take(63).trimEnd('-')
            return candidate
        }
        fun canPlan(scope: String): Boolean = options.planScopes?.let { ScopeRequirements.holds(it, scope) } ?: true
        fun canApply(scope: String): Boolean = options.applyScopes?.let { ScopeRequirements.holds(it, scope) } ?: true
        val addScopeHint = "add it to the identity that plans this file (a workload identity trust's plan profile and scopes, and connection.json auth.scopes) to import it"

        /** The kind's listing needs (its read scope; `tenant:access.read` for an access object) this identity is known to lack. */
        fun listingMissing(kind: String): List<String> =
            (listOfNotNull(ScopeRequirements.readScope(kind)) + if (kind in ProvisionFile.SCOPE_ONLY_KINDS) emptyList() else listOf(AccessRefs.SCOPE_READ))
                .filterNot { canPlan(it) }

        /**
         * Run one kind's import: refused up front (one line, naming the scope) when this identity cannot list it; a scope
         * `403` that happens anyway is listed the same way and the next kind runs — never an aborted import.
         */
        fun importKind(kind: String, block: () -> Unit) {
            val missing = listingMissing(kind)
            if (missing.isNotEmpty()) {
                return skip("$kind — not imported: this identity does not hold ${missing.joinToString(" and ")}, which reading it needs; $addScopeHint")
            }
            try {
                block()
            } catch (ex: MissingScopeException) {
                skip("$kind — not imported: product-api refused a read (HTTP 403) because the token does not carry ${ex.scope}; $addScopeHint")
            } catch (ex: ProductApiException) {
                val scope = ScopeRequirements.readScope(kind)
                MissingScopeException.of(ex, scope, ScopeRequirements.Phase.PLAN, null, "read") ?: throw ex
                skip("$kind — not imported: product-api refused a read (HTTP 403) because the token does not carry $scope; $addScopeHint")
            }
        }

        /** Plane routing: whether an object on [plane] belongs to another configured file (listed, with that file). */
        fun routedAway(plane: String?, label: String): Boolean {
            routing ?: return false
            if (routing.owns(plane)) return false
            val elsewhere = routing.fileFor(plane)
            skip(
                "$label — not imported into ${routing.target}: " + if (elsewhere != null) {
                    "objects of ${planeLabel(plane)} belong to $elsewhere (the file planned with ${if (plane != null && plane in routing.sandboxFiles) "that sandbox's" else "the production"} connection)"
                } else {
                    "objects of ${planeLabel(plane)} belong to the production connection's file, and .thoryn/workflow.yaml configures none"
                },
            )
            return true
        }

        /** Whether an object of [kind] goes to a file of the target's part; otherwise it is listed. */
        fun ofPart(kind: String): Boolean = kind in part.kinds
        fun partReason(kind: String): String = if (part == ProvisionPart.TENANT) {
            "a tenant file (${part.apiVersion}) does not carry kind $kind — an application is declared in its own project's application file (${ProvisionFile.API_VERSION_APPLICATION})"
        } else {
            "an application file (${part.apiVersion}) carries only applications — kind $kind defines the tenant and is declared in the workspace's config project (${ProvisionFile.API_VERSION_TENANT})"
        }

        /**
         * The last step for every rendered entry: the write-only-secret kinds and an apply need this identity lacks make it
         * `readOnly: true`; a plan need it lacks means not imported. Answers whether it was imported.
         */
        fun accept(candidate: ImportedResource, label: String): Boolean {
            var resource = candidate.resource
            val notes = listOfNotNull(candidate.note).toMutableList()
            WRITE_ONLY_SECRET_FIELDS[resource.kind]?.let { field ->
                if (!resource.readOnly) {
                    resource = resource.copy(readOnly = true)
                    notes.clear()
                    notes += "its $field is write-only and a provisioning workflow carries no secret, so this file cannot converge it — imported read-only; " +
                        "to manage it from this file, drop `readOnly` and add `${field}Env: <VAR>` to an apply that holds the secret"
                }
            }
            if (!resource.readOnly && options.applyScopes != null) {
                val lacking = ScopeRequirements.ofResources(listOf(resource)).filter { it.phase == ScopeRequirements.Phase.APPLY }.map { it.scope }.distinct().filterNot { canApply(it) }
                if (lacking.isNotEmpty()) {
                    resource = resource.copy(readOnly = true)
                    notes += "the identity that applies this file does not hold ${lacking.joinToString(" ")} — imported as a read-only reference"
                }
            }
            val planLacking = ScopeRequirements.ofResources(listOf(resource)).filter { it.phase == ScopeRequirements.Phase.PLAN }.map { it.scope }.distinct().filterNot { canPlan(it) }
            if (planLacking.isNotEmpty()) {
                skip("$label — not imported: planning it needs ${planLacking.joinToString(" and ")}, which this identity does not hold; $addScopeHint")
                return false
            }
            out += candidate.copy(resource = resource, note = notes.joinToString("; ").ifEmpty { null })
            return true
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
        fun add(kind: String, name: String, environment: String?, environmentSlug: String?, id: String, access: Access, spec: Map<String, Any?>, note: String? = null, owner: String? = null): Boolean {
            val ref = objectRef(kind, id, environmentSlug)
            val (readOnly, ownerNote) = readOnlyFor(ref, access, owner)
            val resource = ProvisionResource(kind = kind, name = name, environment = environment, spec = spec, readOnly = readOnly)
            return accept(ImportedResource(resource, id, access, listOfNotNull(ownerNote, note).joinToString("; ").ifEmpty { null }), "$kind/$name (${planeLabel(environmentSlug)})")
        }
        /** SSO-3990 — an access-object kind of the other part: each listed object is skipped with the reason. */
        fun listOtherPart(kind: String, type: String) {
            val ids = if (!canPlan(AccessRefs.SCOPE_READ)) null else try { reachable(type).map { it.first } } catch (ex: MissingScopeException) { null }
            if (ids == null) return skip("$kind — not imported: ${partReason(kind)}")
            ids.filterNot { type == OBJECT_TYPE_ENVIRONMENT && it == PRODUCTION_ENV_SLUG }.forEach { id -> skip("$type:$id — not imported: ${partReason(kind)}") }
        }

        // The workspace's sandboxes: listing them needs `tenant:environments.read`; without it only the production plane is imported.
        val noSandboxes = if (ofPart(ProvisionFile.KIND_ENVIRONMENT)) "environment — not imported, nor any object in a sandbox" else "objects in a sandbox — not imported"
        var environmentsListed = true
        val sandboxSlugs: List<String> = when {
            !canPlan(ScopeRequirements.SCOPE_ENVIRONMENTS_READ) -> emptyList<String>().also {
                environmentsListed = false
                skip("$noSandboxes: this identity does not hold ${ScopeRequirements.SCOPE_ENVIRONMENTS_READ}, which listing the workspace's environments needs; $addScopeHint")
            }
            else -> try {
                reach.environments().filter { it.str("kind") != PRODUCTION_ENV_SLUG && it.str("slug") != PRODUCTION_ENV_SLUG }.mapNotNull { it.str("slug") }
            } catch (ex: MissingScopeException) {
                environmentsListed = false
                emptyList<String>().also { skip("$noSandboxes: product-api refused the listing (HTTP 403) because the token does not carry ${ex.scope}; $addScopeHint") }
            }
        }
        val envName = declared.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT }.associate { it.spec["slug"].toString() to it.name }.toMutableMap()
        fun declaredOnPlane(r: ProvisionResource, plane: String?): Boolean =
            if (plane == null) ProvisionFile.isProductionPlane(r.environment) else r.environment == plane || r.environment == envName[plane]

        // Environments first: a child rendered below names its sandbox by the resource NAME when the same import adds it.
        // An environment is a production-plane (workspace-level) object: it goes to the production connection's file.
        if (!ofPart(ProvisionFile.KIND_ENVIRONMENT)) listOtherPart(ProvisionFile.KIND_ENVIRONMENT, OBJECT_TYPE_ENVIRONMENT)
        else if (environmentsListed) importKind(ProvisionFile.KIND_ENVIRONMENT) {
            reachable(OBJECT_TYPE_ENVIRONMENT).forEach { (id, access) ->
                val node = reach.environments().firstOrNull { it.str("id") == id } ?: return@forEach skip("environment:$id — listed as reachable but not in the workspace's environment list")
                val slug = node.str("slug") ?: return@forEach
                if (slug == PRODUCTION_ENV_SLUG || node.str("kind") == PRODUCTION_ENV_SLUG) return@forEach // the production plane is not a declarable resource
                if (declared.any { it.kind == ProvisionFile.KIND_ENVIRONMENT && it.spec["slug"] == slug }) return@forEach
                if (routedAway(null, "environment:$slug")) return@forEach
                val name = uniqueName(ProvisionFile.KIND_ENVIRONMENT, slug)
                if (add(ProvisionFile.KIND_ENVIRONMENT, name, null, null, id, access, linkedMapOf("slug" to slug, "displayName" to (node.str("name") ?: slug)), owner = ProvisionApi.ownerOf(node))) {
                    envName[slug] = name
                }
            }
        }
        /** The environment a per-environment object lives in: the first plane that answers its GET (production first). */
        fun locate(read: (ProvisionApi) -> JsonNode): Pair<String?, JsonNode>? =
            (listOf<String?>(null) + sandboxSlugs).firstNotNullOfOrNull { plane -> fetchOrNull { read(clients(plane)) }?.let { plane to it } }
        fun environmentField(slug: String?): String? = slug?.let { envName[it] ?: it }

        if (!ofPart(ProvisionFile.KIND_APPLICATION)) listOtherPart(ProvisionFile.KIND_APPLICATION, OBJECT_TYPE_APPLICATION)
        else importKind(ProvisionFile.KIND_APPLICATION) {
            reachable(OBJECT_TYPE_APPLICATION).forEach { (id, access) ->
                if (declared.any { it.kind == ProvisionFile.KIND_APPLICATION && it.spec["clientId"] == id }) return@forEach
                val (plane, n) = locate { it.getApplication(id) } ?: return@forEach skip("application:$id — listed as reachable but not readable in any environment")
                if (routedAway(plane, "application:$id")) return@forEach
                val spec = linkedMapOf<String, Any?>("clientId" to id, "displayName" to (n.str("displayName") ?: id))
                n.str("clientType")?.let { spec["clientType"] = it }
                listOf("grantTypes", "redirectUris", "postLogoutRedirectUris", "scopes").forEach { f ->
                    // SSO-3856 — an imported file never declares an operator-plane scope: it could not be applied.
                    val value = plain(n[f] ?: return@forEach).let { if (f == "scopes") withoutOperatorPlaneScopes(it) else it }
                    (value as? List<*>)?.takeIf { it.isNotEmpty() }?.let { spec[f] = it }
                }
                val confidential = !n.str("clientType").equals("public", ignoreCase = true)
                add(
                    ProvisionFile.KIND_APPLICATION, uniqueName(ProvisionFile.KIND_APPLICATION, n.str("displayName") ?: id), environmentField(plane), plane, id, access, spec,
                    if (confidential && access == Access.MANAGER) "its existing client secret is not recoverable; `thoryn clients rotate-secret $id --secret-file <path>` mints a new one" else null,
                    owner = ProvisionApi.ownerOf(n),
                )
            }
        }
        if (!ofPart(ProvisionFile.KIND_USER)) listOtherPart(ProvisionFile.KIND_USER, OBJECT_TYPE_USER)
        else importKind(ProvisionFile.KIND_USER) {
            var productionUsers = 0
            reachable(OBJECT_TYPE_USER).forEach { (id, access) ->
                val (plane, n) = locate { it.getUser(id) } ?: return@forEach skip("user:$id — listed as reachable but not readable in any environment")
                // SSO-3990 — people who sign up on the production plane are not configuration, and a git history cannot honour
                // an erasure request: never imported (counted). A sandbox's test users are imported.
                if (plane == null) { productionUsers++; return@forEach }
                val email = n.str("email") ?: return@forEach skip("user:$id — no email on the live record")
                if (declared.any { it.kind == ProvisionFile.KIND_USER && it.spec["email"].toString().equals(email, ignoreCase = true) }) return@forEach
                if (routedAway(plane, "user:$id")) return@forEach
                val spec = linkedMapOf<String, Any?>("email" to email)
                n["emailVerified"]?.takeIf { it.isBoolean }?.let { spec["emailVerified"] = it.asBoolean() }
                add(ProvisionFile.KIND_USER, uniqueName(ProvisionFile.KIND_USER, email.substringBefore('@')), environmentField(plane), plane, id, access, spec)
            }
            if (productionUsers > 0) {
                skip("user — $productionUsers production-plane user(s) not imported: people who sign up are not configuration, and a git history cannot honour an erasure request (sandbox test users are imported)")
            }
        }
        if (!ofPart(ProvisionFile.KIND_FEDERATION_MEMBER)) listOtherPart(ProvisionFile.KIND_FEDERATION_MEMBER, OBJECT_TYPE_FEDERATION_MEMBER)
        else importKind(ProvisionFile.KIND_FEDERATION_MEMBER) {
            reachable(OBJECT_TYPE_FEDERATION_MEMBER).forEach { (id, access) ->
                val (plane, n) = locate { it.getFederationMember(id) } ?: return@forEach skip("federation_member:$id — listed as reachable but not readable in any environment")
                if (declared.any { it.kind == ProvisionFile.KIND_FEDERATION_MEMBER && it.spec["displayName"] == n.str("displayName") }) return@forEach
                if (routedAway(plane, "federation_member:$id")) return@forEach
                val spec = linkedMapOf<String, Any?>("providerType" to (n.str("providerType") ?: "oidc"))
                listOf("displayName", "discoveryUrl", "clientId").forEach { f -> n.str(f)?.let { spec[f] = it } }
                add(ProvisionFile.KIND_FEDERATION_MEMBER, uniqueName(ProvisionFile.KIND_FEDERATION_MEMBER, n.str("displayName") ?: id), environmentField(plane), plane, id, access, spec)
            }
        }
        // The per-environment singletons: the object id IS the environment slug (`production` for the plane without one).
        fun singletonPlane(id: String): String? = if (id == PRODUCTION_ENV_SLUG) null else id.takeIf { it in sandboxSlugs }
        fun singletonDeclared(kind: String, plane: String?): Boolean = declared.any { it.kind == kind && declaredOnPlane(it, plane) }
        // A singleton's `name` defaults to its kind, but `kind/name` is the file's key: the same kind on a second plane takes a
        // distinct name (`loginmethods-<plane>`) — the singleton converges by its environment, never by its name.
        fun singletonName(kind: String, plane: String?): String =
            if (names.add("$kind/$kind")) kind else uniqueName(kind, "$kind-${plane ?: PRODUCTION_ENV_SLUG}")
        fun singleton(kind: String, type: String, block: (id: String, plane: String?, access: Access) -> Unit) {
            if (!ofPart(kind)) return listOtherPart(kind, type)
            importKind(kind) {
                reachable(type).forEach { (id, access) ->
                    if (id != PRODUCTION_ENV_SLUG && id !in sandboxSlugs) return@forEach skip("$type:$id — no environment with that slug")
                    val plane = singletonPlane(id)
                    if (singletonDeclared(kind, plane)) return@forEach
                    block(id, plane, access)
                }
            }
        }
        singleton(ProvisionFile.KIND_EMAIL_PROVIDER, OBJECT_TYPE_EMAIL_PROVIDER) { id, plane, access ->
            val n = fetchOrNull { clients(plane).getEmailProvider() } ?: return@singleton
            if (n["configured"]?.asBoolean() == false) return@singleton
            val spec = linkedMapOf<String, Any?>()
            listOf("smtpHost", "smtpUsername", "transportSecurity", "fromAddress", "fromName", "replyTo", "providerType").forEach { f -> n.str(f)?.let { spec[f] = it } }
            n["smtpPort"]?.takeIf { it.isNumber }?.let { spec["smtpPort"] = it.asInt() }
            n["enabled"]?.takeIf { it.isBoolean }?.let { spec["enabled"] = it.asBoolean() }
            if (spec["smtpHost"] == null) return@singleton skip("email_provider:$id — configured without an SMTP host; not a declarable emailProvider")
            if (routedAway(plane, "email_provider:$id")) return@singleton
            add(ProvisionFile.KIND_EMAIL_PROVIDER, singletonName(ProvisionFile.KIND_EMAIL_PROVIDER, plane), environmentField(plane), plane, n.str("providerType") ?: "email-provider", access, spec)
        }
        singleton(ProvisionFile.KIND_LOGIN_THEME, OBJECT_TYPE_LOGIN_THEME) { _, plane, access ->
            val stored = fetchOrNull { clients(plane).getLoginBranding() }?.get("stored") ?: return@singleton
            // SSO-4048 — the whole record (name, title, favicon and footer links included), so an imported theme plans as a no-op.
            val spec = stored.toMap(ProvisionFile.LOGIN_THEME_SPEC_KEYS.toList()).filterValues { it != null && !(it is Map<*, *> && it.isEmpty()) }
            if (spec.isEmpty()) return@singleton // nothing stored ⇒ the platform default ⇒ nothing to declare
            if (routedAway(plane, "login_theme:${plane ?: PRODUCTION_ENV_SLUG}")) return@singleton
            add(ProvisionFile.KIND_LOGIN_THEME, singletonName(ProvisionFile.KIND_LOGIN_THEME, plane), environmentField(plane), plane, "login-theme", access, spec)
        }
        singleton(ProvisionFile.KIND_LOGIN_METHODS, OBJECT_TYPE_LOGIN_METHODS) { _, plane, access ->
            val stored = fetchOrNull { clients(plane).getLoginMethods() }?.get("stored")?.takeIf { !it.isNull && it.isArray } ?: return@singleton
            if (routedAway(plane, "login_methods:${plane ?: PRODUCTION_ENV_SLUG}")) return@singleton
            val methods = stored.toList().map { it.asString() }
            add(ProvisionFile.KIND_LOGIN_METHODS, singletonName(ProvisionFile.KIND_LOGIN_METHODS, plane), environmentField(plane), plane, "login-methods", access, linkedMapOf("methods" to methods))
        }
        if (!ofPart(ProvisionFile.KIND_LOGIN_FLOW)) listOtherPart(ProvisionFile.KIND_LOGIN_FLOW, OBJECT_TYPE_LOGIN_FLOW)
        else importKind(ProvisionFile.KIND_LOGIN_FLOW) {
            reachable(OBJECT_TYPE_LOGIN_FLOW).forEach { (id, _) ->
                if (routing != null && !routing.owns(if (id == PRODUCTION_ENV_SLUG) null else id)) return@forEach
                skip("login_flow:$id — a loginFlow is declared by its templateId, which the active flow does not record; declare it by hand")
            }
        }
        if (!ofPart(ProvisionFile.KIND_CUSTOM_DOMAIN)) listOtherPart(ProvisionFile.KIND_CUSTOM_DOMAIN, OBJECT_TYPE_CUSTOM_DOMAIN)
        else importKind(ProvisionFile.KIND_CUSTOM_DOMAIN) {
            reachable(OBJECT_TYPE_CUSTOM_DOMAIN).forEach { (id, access) ->
                if (declared.any { it.kind == ProvisionFile.KIND_CUSTOM_DOMAIN }) return@forEach
                val body = fetchOrNull { clients(null).getCustomDomain() } ?: return@forEach
                val view = CustomDomainView.of(body)
                val host = view.domain?.takeIf { it.isNotBlank() } ?: return@forEach
                if (view.state == CustomDomainView.NONE) return@forEach
                if (routedAway(null, "custom_domain:$id")) return@forEach
                add(ProvisionFile.KIND_CUSTOM_DOMAIN, ProvisionFile.KIND_CUSTOM_DOMAIN, null, null, id, access, linkedMapOf("host" to host))
            }
        }
        // SSO-4042 / SSO-4054 — email templates, PER ENVIRONMENT (oauthy SSO-4043): each plane's listing (`GET …/email-templates`
        // with its `X-Thoryn-Environment`, oauthy SSO-4053) names exactly the (type, locale) cells THAT plane stores — never the
        // rows a sandbox inherits from production — and each cell's body is read by address on the same plane. One resource per
        // (environment, type, locale). The relation is the login experience's (`login_theme:<plane>`): manager ⇒ converge,
        // viewer ⇒ readOnly. The body goes to a file next to the provisioning file — `emails/<type>[.<locale>].html` for
        // production, `emails/<slug>/<type>[.<locale>].html` for a sandbox ([emailTemplateBodyPath]) — and the spec names it as
        // `bodyFile`.
        if (!ofPart(ProvisionFile.KIND_EMAIL_TEMPLATE)) {
            skip("${ProvisionFile.KIND_EMAIL_TEMPLATE} — not imported: ${partReason(ProvisionFile.KIND_EMAIL_TEMPLATE)}")
        } else importKind(ProvisionFile.KIND_EMAIL_TEMPLATE) {
            fun templateAccess(plane: String?): Access {
                val direct = reach.on(objectRef(ProvisionFile.KIND_EMAIL_TEMPLATE, "", plane))
                if (direct != Access.NONE) return direct
                // The login experience's object may be missing from the graph (never written); its parent's relation then decides.
                return if (plane == null) {
                    if (reach.managesWorkspace()) Access.MANAGER else Access.NONE
                } else {
                    reach.environmentId(plane)?.let { reach.on(objectRef(ProvisionFile.KIND_ENVIRONMENT, it, null)) } ?: Access.NONE
                }
            }
            (listOf<String?>(null) + sandboxSlugs).forEach plane@{ plane ->
                val access = templateAccess(plane)
                if (access == Access.NONE) return@plane
                if (routedAway(plane, "emailTemplate (${planeLabel(plane)})")) return@plane
                val rows = try {
                    listItems(clients(plane).listEmailTemplates(), "data")
                } catch (ex: ProductApiException) {
                    if (ex.httpStatus != 404) throw ex
                    return@plane skip(
                        "emailTemplate (${planeLabel(plane)}) — not imported: the listing answered 404${ex.errorCode?.let { " $it" } ?: ""} — this identity has no reach into " +
                            "that environment's login experience, or product-api predates the per-environment listing (oauthy SSO-4053)",
                    )
                }
                rows.forEach row@{ row ->
                    val type = row.str("templateType") ?: return@row
                    val locale = row.str("locale")?.let { ProvisionFile.emailTemplateLocale(it) }?.takeIf { it != ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE }
                    val id = emailTemplateId(type, locale)
                    if (type !in ProvisionFile.EMAIL_TEMPLATE_TYPES) return@row skip("email_template:$id (${planeLabel(plane)}) — type '$type' is not one this CLI declares; update the CLI")
                    val cell = ProvisionFile.emailTemplateCell(type, locale)
                    if (declared.any { it.kind == ProvisionFile.KIND_EMAIL_TEMPLATE && declaredOnPlane(it, plane) && ProvisionFile.emailTemplateCell(it.spec["type"]?.toString(), it.spec["locale"]?.toString()) == cell }) return@row
                    val n = try {
                        clients(plane).getEmailTemplate(type, locale)
                    } catch (ex: ProductApiException) {
                        if (ex.httpStatus == 404 && ex.errorCode == ERROR_TEMPLATE_NOT_CUSTOMIZED) return@row else throw ex
                    }
                    val subject = n.str("subject") ?: return@row skip("email_template:$id (${planeLabel(plane)}) — stored without a subject; not a declarable emailTemplate")
                    val body = n.str("bodyHtml") ?: return@row skip("email_template:$id (${planeLabel(plane)}) — stored without a body; not a declarable emailTemplate")
                    val path = emailTemplateBodyPath(plane, type, locale)
                    val spec = linkedMapOf<String, Any?>("type" to type)
                    locale?.let { spec["locale"] = it }
                    spec["subject"] = subject
                    spec["bodyFile"] = path
                    val name = uniqueName(ProvisionFile.KIND_EMAIL_TEMPLATE, listOfNotNull(type, locale, plane).joinToString("-"))
                    val resource = ProvisionResource(ProvisionFile.KIND_EMAIL_TEMPLATE, name, environmentField(plane), spec, readOnly = access == Access.VIEWER)
                    accept(ImportedResource(resource, id, access, files = mapOf(path to body)), "emailTemplate/$name (${planeLabel(plane)})")
                }
            }
        }
        // SSO-4057 — tenant-level legal documents, PER ENVIRONMENT (oauthy SSO-4047): each plane's ACTIVE version of each type —
        // the one sign-ins accept and the hosted page shows — is rendered as one entry, its body in a file next to the
        // provisioning file ([legalDocumentBodyPath]). A plane with no active document of a type renders nothing: there is no
        // fallback between environments, so a sandbox without its own document has none, and declaring none is not drift. The
        // historical (inactive) versions are not rendered — the file declares which version is active, not the history. Not a
        // platform access object (`tenant:compliance.*` alone), so — like a role — what this identity may change is its write scope.
        if (!ofPart(ProvisionFile.KIND_LEGAL_DOCUMENT)) {
            skip("${ProvisionFile.KIND_LEGAL_DOCUMENT} — not imported: ${partReason(ProvisionFile.KIND_LEGAL_DOCUMENT)}")
        } else importKind(ProvisionFile.KIND_LEGAL_DOCUMENT) {
            val access = if (canApply(ScopeRequirements.writeScope(ProvisionFile.KIND_LEGAL_DOCUMENT)!!)) Access.MANAGER else Access.VIEWER
            (listOf<String?>(null) + sandboxSlugs).forEach plane@{ plane ->
                ProvisionFile.LEGAL_DOCUMENT_TYPES.forEach type@{ type ->
                    if (declared.any { it.kind == ProvisionFile.KIND_LEGAL_DOCUMENT && declaredOnPlane(it, plane) && it.spec["type"]?.toString()?.trim() == type }) return@type
                    // A plane this identity reaches nothing in answers 404 — nothing to import there.
                    val rows = fetchOrNull { listItems(clients(plane).listLegalDocuments(type), "data") } ?: return@plane
                    val active = rows.firstOrNull { it.isActive() } ?: return@type
                    val id = legalDocumentId(type, active.str("id") ?: return@type)
                    val label = "legal_document:$id (${planeLabel(plane)})"
                    if (routedAway(plane, label)) return@type
                    val version = active.str("version")?.trim()
                    val title = active.str("title")?.trim()
                    val format = active.str("format")?.trim()?.lowercase() ?: ProvisionFile.LEGAL_DOCUMENT_DEFAULT_FORMAT
                    val body = active["body"]?.takeIf { !it.isNull }?.asString()
                    val problem = when {
                        version == null || title == null || body == null -> "stored without a version, a title or a body"
                        format !in ProvisionFile.LEGAL_DOCUMENT_FORMATS -> "stored with format '$format', which this CLI does not declare; update the CLI"
                        else -> ProvisionFile.legalDocumentBodyProblem(body)?.let { "its body $it" }
                    }
                    if (problem != null) return@type skip("$label — $problem; not a declarable legalDocument")
                    val path = legalDocumentBodyPath(plane, type, format)
                    val spec = linkedMapOf<String, Any?>("type" to type, "version" to version, "title" to title)
                    if (format != ProvisionFile.LEGAL_DOCUMENT_DEFAULT_FORMAT) spec["format"] = format
                    spec["bodyFile"] = path
                    val name = uniqueName(ProvisionFile.KIND_LEGAL_DOCUMENT, listOfNotNull(type, plane).joinToString("-"))
                    val resource = ProvisionResource(ProvisionFile.KIND_LEGAL_DOCUMENT, name, environmentField(plane), spec)
                    accept(ImportedResource(resource, id, access, files = mapOf(path to body!!)), "legalDocument/$name (${planeLabel(plane)})")
                }
            }
        }
        // SSO-3689 / SSO-3774 — workload-identity trusts: the API lists a plane's trusts filtered to what this identity reaches
        // (S1: the trusts it holds a relation on, every trust of a plane it views); each is rendered with the relation held on
        // `trust:<id>` UNIONED with the plane's (the plane alone on a platform that predates trust objects), and `readOnly`
        // when that is only `viewer` or the response's `owner` names another repository.
        fun planeAccess(plane: String?): Access = when {
            plane == null && reach.managesWorkspace() -> Access.MANAGER
            plane == null -> if (workspaceId != null && reach.holds("$OBJECT_TYPE_WORKSPACE:$workspaceId", RELATION_VIEWER)) Access.VIEWER else Access.NONE
            else -> reach.environmentId(plane)?.let { reach.on(objectRef(ProvisionFile.KIND_ENVIRONMENT, it, null)) } ?: Access.NONE
        }
        // SSO-3990 — the repository's own trusts: the signed-in client's, and every configured connection's.
        val ownClients = options.ownTrustClients + listOfNotNull(subject?.takeIf { it.startsWith("client:") }?.substringAfter(':'))
        if (!ofPart(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST)) {
            skip("${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST} — not imported: ${partReason(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST)}")
        } else importKind(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST) {
            (listOf<String?>(null) + sandboxSlugs).forEach { plane ->
                val onPlane = planeAccess(plane)
                // A plane this identity reaches nothing in answers 404 — nothing to import there.
                val trusts = fetchOrNull { trustsOf(plane) } ?: return@forEach
                trusts.forEach { n ->
                    val name = n.str("name") ?: return@forEach
                    val id = n.str("id") ?: return@forEach
                    val ref = objectRef(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, id, plane)
                    val access = stronger(reach.onTrust(ref) ?: Access.NONE, onPlane)
                    if (access == Access.NONE) return@forEach
                    val envField = environmentField(plane)
                    if (declared.any { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST && it.name == name && declaredOnPlane(it, plane) }) return@forEach
                    // The structural limit: the identity applying a file cannot declare its OWN bootstrap trust (SSO-3990: nor
                    // any trust the repository's configured connections sign in with).
                    if (n.str("clientId") in ownClients) {
                        skipped += "workloadIdentityTrust:$name — the trust this repository itself signs in with (its own bootstrap trust); it was created once by a person and is never declared by the file it applies"
                        return@forEach
                    }
                    if (routedAway(plane, "workloadIdentityTrust:$name")) return@forEach
                    // The trust's NAME is its converge key on the API, so it cannot be renamed to stay unique in the file.
                    if (!names.add("${ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST}/$name")) {
                        skipped += "workloadIdentityTrust:$name (${planeLabel(plane)}) — a trust of the same name is already in the file; a trust converges by its API name, so declare it by hand under a second file"
                        return@forEach
                    }
                    val (spec, note) = trustSpecOf(n, production = plane == null)
                    val owner = ProvisionApi.ownerOf(n)
                    val ownedElsewhere = access == Access.MANAGER && owner != null && !reach.ownsTrust(ref)
                    val resource = ProvisionResource(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, name, envField, spec, readOnly = access == Access.VIEWER || ownedElsewhere)
                    val ownerNote = if (ownedElsewhere) "owned by another repository (the platform's `owner` relation) — imported as a read-only reference" else null
                    accept(ImportedResource(resource, id, access, listOfNotNull(ownerNote, note).joinToString("; ").ifEmpty { null }), "workloadIdentityTrust/$name (${planeLabel(plane)})")
                }
            }
        }
        // SSO-3990 — roles: not platform access objects (product-api gates them on `tenant:roles.*` alone), so what this identity
        // may read is every role of a plane it reaches, and whether it may change one is the write scope.
        if (!ofPart(ProvisionFile.KIND_ROLE)) {
            skip("${ProvisionFile.KIND_ROLE} — not imported: ${partReason(ProvisionFile.KIND_ROLE)}")
        } else importKind(ProvisionFile.KIND_ROLE) {
            val access = if (canApply(ScopeRequirements.writeScope(ProvisionFile.KIND_ROLE)!!)) Access.MANAGER else Access.VIEWER
            (listOf<String?>(null) + sandboxSlugs).forEach { plane ->
                val client = clients(plane)
                val roles = fetchOrNull { allPages { cursor -> client.listRoles(null, cursor) } } ?: return@forEach
                roles.forEach { n ->
                    val name = n.str("name") ?: return@forEach
                    val id = n.str("id") ?: return@forEach
                    if (declared.any { it.kind == ProvisionFile.KIND_ROLE && it.name == name && declaredOnPlane(it, plane) }) return@forEach
                    if (routedAway(plane, "role:$name")) return@forEach
                    // A role converges by its NAME, so the name is the resource name — it cannot be renamed to fit the grammar.
                    if (!ProvisionFile.NAME_PATTERN.matches(name)) {
                        return@forEach skip("role:$name (${planeLabel(plane)}) — a role converges by its name, and '$name' is not a resource name (${ProvisionFile.NAME_PATTERN.pattern}); it cannot be declared in a file")
                    }
                    if (!names.add("${ProvisionFile.KIND_ROLE}/$name")) {
                        return@forEach skip("role:$name (${planeLabel(plane)}) — a role of the same name is already in the file; a role converges by its name, so declare it under a second file")
                    }
                    val permissions = allPages { cursor -> client.listRolePermissions(id, null, cursor) }.mapNotNull { it.str("name") }.sorted()
                    val spec = linkedMapOf<String, Any?>()
                    n.str("description")?.let { spec[ProvisionFile.ROLE_DESCRIPTION] = it }
                    spec[ProvisionFile.ROLE_PERMISSIONS] = permissions
                    val resource = ProvisionResource(ProvisionFile.KIND_ROLE, name, environmentField(plane), spec)
                    accept(ImportedResource(resource, id, access), "role/$name (${planeLabel(plane)})")
                }
            }
        }
        return ImportResult(out, skipped)
    }

    // ── apply ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Execute [plan]: creates / updates in dependency order (environments first), then publishes, then converges
     * every `grants:` block (SSO-3119 — after all of them exist, so a grant may name any subject the file
     * declares), then removes what `--prune` planned. [confirmSlug] is the workspace slug confirming
     * production-plane removals (refused up front when missing). Returns every declared resource with the id it
     * resolved to ([ApplyResult] — the `--output json` document); throws on the first failed step (everything
     * before it is live already — a re-run converges the rest, there is no ledger to repair).
     */
    fun apply(
        file: ProvisionFile,
        plan: ProvisionPlan,
        workspace: String?,
        confirmSlug: String?,
    ): ApplyResult {
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
        trustLists.clear()
        applyWorkspace = workspace
        val applied = mutableListOf<AppliedResource>()
        fun record(a: AppliedResource) {
            val i = applied.indexOfFirst { it.key == a.key }
            if (i >= 0) applied[i] = a else applied += a
        }
        undelivered.clear()
        warn(plan)
        // SSO-3119 — grants converge in a SECOND pass, after EVERY resource in the file exists.
        // product-api resolves a grant's SUBJECT (`client:<clientId>`, `member:<sub>`) in the workspace
        // before it writes the tuple, and [orderForApply] converges environments ahead of applications —
        // so converging a block inline, the moment its own object resolved, could name a client the same
        // file had not created yet. That earns the opaque 404 of ADR 2026-09-15 §8 (one answer for an
        // unknown object, an unknown subject and insufficient reach), and it DEADLOCKS: a re-run reaches
        // the same grant before the same missing client. Deferring the whole block drops the ordering
        // dependency — a `grants:` block may name anything the file declares, in any order.
        val pendingGrants = mutableListOf<PendingGrants>()
        // SSO-3668 — outputs publish in their own pass too, once the resource is converged (the id is known), so an
        // unreachable target can never cost the id.
        val pendingPublishes = mutableListOf<Pair<ProvisionResource, String>>()
        plan.changes.filter { it.resource != null }.forEach { change ->
            val r = change.resource!!
            // SSO-3659 — a read-only reference is never written and never owned.
            if (r.readOnly) return@forEach
            val resolved: AppliedResource? = when (change.action) {
                // SSO-3659 — a minted client secret is delivered AFTER the client exists; an unreachable sink costs nothing.
                // SSO-3921 — a `workloadPull` sink: the value is dropped here, unseen; the trust's pod mints its own at start.
                // SSO-3954 — `customerManaged` (the default): dropped here too, unseen; a person mints the one the runtime gets.
                ChangeAction.CREATE -> writing(r, "create it") { create(r, file, applied, change.reservation) }.let { c ->
                    record(c.applied)
                    c.mintedSecret?.let {
                        val sink = r.effectiveSecretSink
                        when {
                            sink?.runtimePull == true -> discardSecret(r)
                            sink?.customerManaged == true -> discardForCustomer(r, c.applied.id)
                            else -> deliverSecret(r, c.applied.id, it)
                        }
                    }
                    // SSO-3941 — claims in the token are switched on only once the client exists AND its one-time secret has
                    // left: a refusal here can never cost the secret.
                    if (r.kind == ProvisionFile.KIND_APPLICATION) {
                        desiredTokenClaims(resolveSpec(r, strict = true))?.takeIf { it.enabled }?.let { want ->
                            writing(r, "set its token claims") { convergeTokenClaims(r, c.applied.environment, c.applied.id, want) }
                        }
                    }
                    c.applied
                }
                ChangeAction.UPDATE -> writing(r, "update it") { update(r, file, applied, change) }.also { record(it) }
                ChangeAction.NOOP -> change.liveId?.let { AppliedResource(r.kind, r.name, it, change.environment, change.attributes, change.owner, ChangeAction.NOOP) }?.also { record(it) }
                else -> null
            }
            if ((r.grants != null || r.secretSink?.runtimePull == true) && resolved != null) {
                pendingGrants += PendingGrants(r, objectRef(r.kind, resolved.id, resolved.environment), change, resolved.environment)
            }
            if (r.publishTo.isNotEmpty() && resolved != null) {
                pendingPublishes += r to resolved.id
            }
        }
        // SSO-3668 — publish AFTER convergence: every resource exists by now. Failures are collected, not thrown, so
        // the grants and prune below still converge; they end the apply afterwards.
        val publishFailures = mutableListOf<PublishFailure>()
        pendingPublishes.forEach { (r, id) ->
            r.publishTo.forEach { target ->
                val reason = try {
                    outputSink.publish(target, id)
                } catch (ex: Exception) {
                    ex.message ?: ex.javaClass.simpleName
                }
                if (reason == null) {
                    out.println("  > ${r.kind} ${r.name}: published clientId=$id → ${target.label}")
                } else {
                    publishFailures += PublishFailure(r.key, target, id, reason)
                    err.println("  ! ${r.kind} ${r.name}: could not publish its clientId to ${target.label} ($reason). The client exists; by hand: ${target.byHand(id)}")
                }
            }
        }
        pendingGrants.forEach { (r, ref, change, plane) -> convergeGrants(r, ref, change.grantRemoves, workloadPullGrantAtApply(r, change, plane)) }
        // SSO-3715 — `--prune`: the owned-and-undeclared removals the plan carries, child-first (each refusal was a skip row already).
        val pruned = destroy(ProvisionPlan(plan.removes), confirmSlug)
        if (pruned.failures.isNotEmpty()) {
            throw ProvisionException("${pruned.failures.size} planned removal(s) failed (everything else was applied; re-run to retry):\n  " + pruned.failures.joinToString("\n  "))
        }
        val result = ApplyResult(applied.toList(), workspace)
        // SSO-3668 — raised LAST: everything above is live, so the fallback is one command per target with the id from [result].
        if (publishFailures.isNotEmpty()) throw PublishTargetUnreachableException(publishFailures, result)
        return result
    }

    /**
     * SSO-3926 — a write refused by product-api's scope gate (`403 access_denied` / `insufficient_scope`) names the kind's
     * write scope ([MissingScopeException], phase apply) instead of surfacing as a bare HTTP error the host would render
     * with a guessed scope. Every other failure passes through unchanged.
     */
    private fun <T> writing(r: ProvisionResource, operation: String, call: () -> T): T = try {
        call()
    } catch (ex: ProductApiException) {
        throw MissingScopeException.of(ex, ScopeRequirements.writeScope(r.kind), ScopeRequirements.Phase.APPLY, r.key, operation) ?: ex
    }

    // ── live lookup per kind (SSO-3089) ──────────────────────────────────────────────────────────

    /**
     * What exists live for a declared resource: its id, the non-secret fields that differ from [desired], and
     * (SSO-3673) the platform `owner` its response renders, if any.
     */
    private class Live(val id: String, val diff: Map<String, String>, val attributes: Map<String, String> = emptyMap(), val owner: String? = null)

    /** SSO-3715 — two live resources match one converge key; the plan is red (`converge_key_ambiguous`), never a third copy. */
    private class ConvergeKeyAmbiguousException(message: String) : RuntimeException(message)

    /** SSO-4057 — the declared legal-document version label is published with other content ([lookup] → an `ERROR` row in [probe]). */
    private class LegalDocumentVersionImmutableException(message: String, val liveId: String, val diff: Map<String, String>) : RuntimeException(message)

    /** The one live match of a converge key, or none; two or more is [ConvergeKeyAmbiguousException]. */
    private fun <T> List<T>.singleMatchOrNull(what: String, fix: String): T? = when (size) {
        0 -> null
        1 -> first()
        else -> throw ConvergeKeyAmbiguousException("$size live resources match $what — $fix")
    }

    private fun lookup(r: ProvisionResource, slug: String?, desired: Map<String, Any?>): Live? = when (r.kind) {
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
            // SSO-3104 / SSO-3715 — the converge key: a fixed `clientId` when declared (the file SHOULD declare one),
            // else the `displayName` within the environment — and two matches of a display name are an error, not a create.
            val fixedId = desired["clientId"]?.toString()?.takeIf { it.isNotBlank() }
            val node = fixedId?.let { fetchOrNull { client.getApplication(it) } }
                ?: listItems(client.listApplications(), "data").filter { it.str("displayName") == desired["displayName"] }
                    .singleMatchOrNull("displayName '${desired["displayName"]}' in ${planeLabel(slug)}", "declare `clientId` on the resource to say which one")
            node?.let { n ->
                // SSO-3689 — the client-authentication fields converge on UPDATE too (ADR 2026-10-14 §11): the methods and the
                // bound trust are read from the response. SSO-3715 — the key location (`jwksUri` / `jwks`) is NOT rendered by
                // the API (SSO-3716) and there is no receipt to remember it by, so it is never diffed: sent on create, re-sent
                // with every update ([applicationBody]).
                // SSO-3766 / SSO-3767 / SSO-3770 — the token-exchange, authorization-detail-type and session-lifetime settings
                // converge the same way: read from the response, diffed only when DECLARED (an omitted one keeps the live value;
                // `allowedAuthorizationDetailTypes: []` is declared, and clears).
                val fields = listOf("displayName", "redirectUris", "postLogoutRedirectUris", "scopes", "grantTypes", ProvisionFile.SPEC_CLIENT_AUTHENTICATION_METHODS, ProvisionFile.SPEC_FEDERATED_TRUST) +
                    ProvisionFile.APPLICATION_SETTING_FIELDS
                // SSO-3856 — the live client's operator-plane scopes (`platform:` granted by an operator, `admin:`) are not
                // this file's to converge: the hub keeps them across our update and refuses them on our create, so
                // comparing them would plan a change on every run that applying can never make.
                val live = n.toMap(fields).mapValues { (field, value) -> if (field == "scopes") withoutOperatorPlaneScopes(value) else value }
                val want = desired.filterKeys { it in fields }
                val id = n.str("clientId") ?: n.str("client_id") ?: ""
                // SSO-3941 — `tokenClaims` lives on its own sub-resource: read (and diffed) only when the file declares it.
                val claims = desiredTokenClaims(desired)?.let { tokenClaimsDiff(client, id, it) }.orEmpty()
                Live(id, diffOf(want, live) + claims, buildMap { (plain(n["redirectUris"] ?: return@buildMap) as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) } }, owner = ProvisionApi.ownerOf(n))
            }
        }
        ProvisionFile.KIND_ROLE -> {
            // SSO-3941 — a role converges by its NAME within its environment; its permissions as a SET of names. An omitted
            // `description` keeps the live one.
            val client = clients(slug)
            val node = allPages { cursor -> client.listRoles(null, cursor) }.filter { it.str("name") == r.name }
                .singleMatchOrNull("role name '${r.name}' in ${planeLabel(slug)}", "the platform holds one role per name and environment — remove the duplicate")
            node?.let { n ->
                val id = n.str("id") ?: ""
                val livePermissions = allPages { cursor -> client.listRolePermissions(id, null, cursor) }.mapNotNull { it.str("name") }
                val want = mapOf(ProvisionFile.ROLE_DESCRIPTION to desired[ProvisionFile.ROLE_DESCRIPTION], ProvisionFile.ROLE_PERMISSIONS to rolePermissions(desired))
                Live(id, diffOf(want, mapOf(ProvisionFile.ROLE_DESCRIPTION to n.str("description"), ProvisionFile.ROLE_PERMISSIONS to livePermissions)))
            }
        }
        ProvisionFile.KIND_USER -> {
            val client = clients(slug)
            val email = desired["email"].toString()
            val node = listItems(client.listUsers(email = email), "items").firstOrNull { it.str("email").equals(email, ignoreCase = true) }
            node?.let { n ->
                val fields = listOf("emailVerified")
                Live(n.str("id") ?: n.str("userId") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)), mapOf("email" to email))
            }
        }
        ProvisionFile.KIND_FEDERATION_MEMBER -> {
            val client = clients(slug)
            val node = desired["displayName"]?.let { dn ->
                listItems(client.listFederationMembers(), "data").filter { it.str("displayName") == dn }
                    .singleMatchOrNull("federation member displayName '$dn' in ${planeLabel(slug)}", "give the members distinct display names")
            }
            node?.let { n ->
                val fields = listOf("displayName", "discoveryUrl", "clientId")
                Live(n.str("memberId") ?: n.str("id") ?: "", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)), buildMap { n.str("providerType")?.let { put("providerType", it) } })
            }
        }
        ProvisionFile.KIND_EMAIL_PROVIDER -> {
            val n = clients(slug).getEmailProvider()
            if (n["configured"]?.asBoolean() == false) null
            else {
                val fields = listOf("smtpHost", "smtpPort", "smtpUsername", "transportSecurity", "fromAddress", "fromName", "replyTo", "enabled")
                Live(n.str("providerType") ?: "email-provider", diffOf(desired.filterKeys { it in fields }, n.toMap(fields)), buildMap { n.str("smtpHost")?.let { put("smtpHost", it) } })
            }
        }
        ProvisionFile.KIND_LOGIN_THEME -> {
            // SSO-4041 — the PUT replaces the WHOLE record, so the plan diffs the whole record: every field of
            // [ProvisionFile.LOGIN_THEME_SPEC_KEYS], a stored one the file does not declare included (it WILL be cleared).
            val live = brandingRecord(clients(slug).getLoginBranding()["stored"]?.let { plain(it) } as? Map<*, *>)
            val want = brandingRecord(desired)
            when {
                // Nothing stored: a spec declaring nothing is the platform default already (never re-PUT); anything else is a create.
                live.values.all { it == null } -> if (want.values.all { it == null }) Live("login-theme", emptyMap()) else null
                else -> Live("login-theme", brandingDiff(want, live))
            }
        }
        ProvisionFile.KIND_EMAIL_TEMPLATE -> {
            // SSO-4042 / SSO-4054 — the (type, locale) cell of the resource's OWN environment (the plane's client sends
            // `X-Thoryn-Environment`). `404 template_not_customized` is the API's "this environment stores no override" ⇒ a
            // create; any OTHER 404 is the facade's gate (`not_found` — no relation on `login_theme:<plane>`, or
            // `unknown_environment`) and stays a 404 for [unreachable] to turn into the missing right. The comparison is with the
            // environment's own row, never the copy a sandbox inherits from production: the admin read is exact by contract, and a
            // response naming another environment is treated as "not stored" all the same.
            val (type, locale) = emailTemplateAddress(desired)
            val stored = try {
                clients(slug).getEmailTemplate(type, locale)
            } catch (ex: ProductApiException) {
                if (ex.httpStatus == 404 && ex.errorCode == ERROR_TEMPLATE_NOT_CUSTOMIZED) null else throw ex
            }
            stored?.takeIf { n -> n.str("environmentSlug")?.let { it == (slug ?: PRODUCTION_ENV_SLUG) } ?: true }?.let { n ->
                val want = mapOf("subject" to desired["subject"].nonBlank(), "body" to desired["body"]?.toString())
                val have = mapOf("subject" to n.str("subject"), "body" to n.str("bodyHtml"))
                Live(emailTemplateId(type, locale), emailTemplateDiff(want, have), mapOf("type" to type, "locale" to (locale ?: ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE)))
            }
        }
        ProvisionFile.KIND_LEGAL_DOCUMENT -> {
            // SSO-4057 — every version of the type in the resource's OWN environment (the plane's client sends
            // `X-Thoryn-Environment`; identity keys on (tenant, environment, type), no fallback). The declaration is "the ACTIVE
            // version is spec.version with this content"; a published version never changes. So, by the declared label:
            //  - the active version, same content ⇒ no change;
            //  - an inactive version, same content ⇒ re-activate it (no new version; [update] → activate);
            //  - any version, OTHER content ⇒ refused (`legal_document_version_immutable`): new text needs a new label;
            //  - no version: none active ⇒ a create (publish); another active ⇒ an update that publishes the new version.
            val want = legalDocumentWant(desired)
            val rows = listItems(clients(slug).listLegalDocuments(want.type), "data")
            val active = rows.firstOrNull { it.isActive() }
            val labelled = rows.firstOrNull { it.str("version")?.trim() == want.version }
            fun liveIdOf(n: JsonNode) = legalDocumentId(want.type, n.str("id") ?: "")
            fun attributesOf(n: JsonNode) = mapOf("type" to want.type, "version" to (n.str("version")?.trim() ?: ""))
            when {
                labelled != null -> {
                    val differs = legalDocumentContentDiff(want, labelled)
                    if (differs.isNotEmpty()) {
                        throw LegalDocumentVersionImmutableException(
                            "version '${want.version}' of the ${want.type} in ${planeLabel(slug)} is already published with a different ${differs.keys.joinToString(" and ")} " +
                                "(${differs.values.joinToString("; ")}); a published version never changes — users accepted that text — so give the new text a new spec.version",
                            liveIdOf(labelled), differs,
                        )
                    }
                    if (labelled.isActive()) Live(liveIdOf(labelled), emptyMap(), attributesOf(labelled))
                    else Live(
                        liveIdOf(labelled),
                        mapOf("active" to "${active?.str("version")?.trim()?.let { "version $it" } ?: "no active version"} → version ${want.version} (re-activates the stored version; nothing is published)"),
                        attributesOf(labelled) + (ATTR_REACTIVATE to "true"),
                    )
                }
                active == null -> null
                else -> Live(
                    liveIdOf(active),
                    mapOf("version" to "${active.str("version")?.trim()} → ${want.version} (publishes a new version; users accept it at their next sign-in)") + legalDocumentContentDiff(want, active),
                    attributesOf(active),
                )
            }
        }
        ProvisionFile.KIND_LOGIN_FLOW -> {
            // SSO-3715 — the active flow does not record its template, so a loginFlow converges by EXISTENCE: an active
            // flow is a match (its version is the id); none ⇒ the template is applied. A changed `templateId` alone is
            // not detected (the same limit `import` reports) — re-apply it by hand.
            val active = fetchOrNull { clients(slug).getActiveLoginFlow() }
            val version = active?.get("version")?.takeIf { !it.isNull }?.asInt()?.toString()
            version?.let { Live(it, emptyMap(), mapOf("activeVersion" to it)) }
        }
        ProvisionFile.KIND_LOGIN_METHODS -> {
            // SSO-3100 — the stored allow-list (null ⇒ the platform default policy, nothing to converge against).
            // Compared as a SET: order is display-only.
            val stored = clients(slug).getLoginMethods()["stored"]?.takeIf { !it.isNull && it.isArray }
            val wanted = (desired["methods"] as? List<*>)?.map { it.toString().trim().lowercase() }
            stored?.let { Live("login-methods", diffOf(mapOf("methods" to wanted), mapOf("methods" to plain(it))), mapOf("methods" to it.toList().joinToString(",") { m -> m.asString() })) }
        }
        else -> null
    }

    // ── per-kind create / update ─────────────────────────────────────────────────────────────────

    /** SSO-3119 — one object's grant block, converged after every resource exists; SSO-3921 — [plane] resolves a `workloadPull` trust. */
    private data class PendingGrants(val resource: ProvisionResource, val ref: String, val change: PlannedChange, val plane: String?)

    /** A created resource and — for a confidential application — the one-time secret the create response carried. */
    private class Created(val applied: AppliedResource, val mintedSecret: String? = null)

    private fun create(r: ProvisionResource, file: ProvisionFile, applied: List<AppliedResource>, reservation: CreationSlot? = null): Created {
        val spec = resolveSpec(r, strict = true)
        if (r.kind == ProvisionFile.KIND_APPLICATION) return createApplication(r, file, applied, spec, reservation)
        return Created(when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                val slug = spec["slug"].toString()
                val body = mapOf("slug" to slug, "name" to (spec["displayName"]?.toString()?.takeIf { it.isNotBlank() } ?: slug))
                val resp = clients(null).createEnvironment(body)
                val id = resp.str("id") ?: throw ProvisionException("${r.key}: the environment create returned no id")
                val liveSlug = resp.str("slug") ?: slug
                out.println("  + environment ${r.name}: id=$id slug=$liveSlug")
                AppliedResource(r.kind, r.name, id, environment = null, attributes = mapOf("slug" to liveSlug), owner = ProvisionApi.ownerOf(resp), action = ChangeAction.CREATE)
            }
            ProvisionFile.KIND_USER -> {
                val slug = targetSlug(r, file, applied)
                val resp = clients(slug).createUser(spec)
                val id = resp.str("id") ?: resp.str("userId") ?: throw ProvisionException("${r.key}: the user create returned no id")
                val email = resp.str("email") ?: spec["email"]?.toString()
                out.println("  + user ${r.name}: id=$id${email?.let { " email=$it" } ?: ""}")
                AppliedResource(r.kind, r.name, id, slug, buildMap { email?.let { put("email", it) } }, action = ChangeAction.CREATE)
            }
            ProvisionFile.KIND_FEDERATION_MEMBER -> {
                val slug = targetSlug(r, file, applied)
                val resp = clients(slug).createFederationMember(spec)
                val id = resp.str("memberId") ?: resp.str("id") ?: throw ProvisionException("${r.key}: the federation-member create returned no id")
                out.println("  + federationMember ${r.name}: id=$id")
                AppliedResource(r.kind, r.name, id, slug, buildMap { spec["providerType"]?.toString()?.let { put("providerType", it) } }, action = ChangeAction.CREATE)
            }
            ProvisionFile.KIND_EMAIL_PROVIDER -> putEmailProvider(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_LOGIN_THEME -> putLoginTheme(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_LOGIN_FLOW -> applyLoginFlow(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_LOGIN_METHODS -> putLoginMethods(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_CUSTOM_DOMAIN -> claimCustomDomain(r, spec)
            ProvisionFile.KIND_EMAIL_TEMPLATE -> putEmailTemplate(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_LEGAL_DOCUMENT -> publishLegalDocument(r, targetSlug(r, file, applied), spec, "+")
            ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> createTrust(r, file, applied, spec)
            ProvisionFile.KIND_ROLE -> createRole(r, targetSlug(r, file, applied), spec)
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        })
    }

    /**
     * The application create. SSO-3792 — under a creation slot ([reservation], from the plan) the call is the same
     * `POST /api/v1/applications` with the explicit `clientId`; product-api's gate consumes the slot. Its refusals are
     * then mapped to what they mean for a reserved create ([reservedCreateFailure]).
     */
    private fun createApplication(r: ProvisionResource, file: ProvisionFile, applied: List<AppliedResource>, spec: Map<String, Any?>, reservation: CreationSlot? = null): Created {
        val slug = targetSlug(r, file, applied)
        val resp = try {
            clients(slug).createApplication(applicationBody(r, spec, slug))
        } catch (ex: ProductApiException) {
            reservation?.let { slot -> reservedCreateFailure(r, ex, slot)?.let { throw it } }
            throw applicationSettingFailure(r, ex, slug) ?: ex
        }
        val id = resp.str("clientId") ?: resp.str("client_id") ?: throw ProvisionException("${r.key}: the application create returned no clientId")
        // SSO-3113 — the ONE server-minted secret goes to a sink and NOWHERE else: never a field, the plan, the console,
        // or a log. The response node is not retained. SSO-3659 — it is handed back to [apply], which delivers it only
        // once the client exists ([deliverSecret]).
        val secret = (resp.str("clientSecret") ?: resp.str("client_secret"))?.takeIf { it.isNotEmpty() }
        // SSO-3954 — every minted secret has a sink now (the default is `customerManaged`): nothing is "shown once" by apply.
        val note = if (secret == null) "" else " (client secret minted)"
        out.println("  + application ${r.name}: clientId=$id${slug?.let { " env=$it" } ?: ""}$note")
        // SSO-3673 — the owner the create established (creator-becomes-owner for a `client:` caller), as reported.
        val created = AppliedResource(r.kind, r.name, id, slug, applicationAttributes(spec), owner = ProvisionApi.ownerOf(resp), action = ChangeAction.CREATE)
        return Created(created, secret)
    }

    /**
     * SSO-3659 (ADR 2026-10-13 §5) — deliver a minted client secret, called by [apply] right AFTER the client exists:
     * first the declared `secretSink:` through [declaredSecretSink] (a reason ⇒ not delivered, printed redacted of
     * the value), then the host's generic [secretSink] (`--secret-file` / guarded TTY). When neither reaches, the
     * client stays and lands on [undeliveredSecretDetails] with the recovery.
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
                "The client exists; mint a new secret with `${recoverSecret(clientId)}`.",
        )
    }

    /**
     * SSO-3921 (oauthy ADR 2026-10-14 credential ladder, rung 3) — a `workloadPull` sink: the one-time secret the create
     * returned is DROPPED — never printed, written, logged or handed to any sink — and nothing is undelivered: the
     * trust's pod mints its own at start (`thoryn clients rotate-secret`, which the `manager` grant this apply converges
     * allows, and which may replace this unseen in-flight secret — oauthy SSO-3696).
     */
    private fun discardSecret(r: ProvisionResource) {
        out.println("  > application ${r.name}: client secret discarded (never shown or stored) — pulled at runtime by the pods of trust ${r.secretSink?.trust}")
    }

    /**
     * SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951 — Thoryn owns the lifecycle, the customer owns delivery) —
     * a `customerManaged` sink, declared or the default: the one-time secret the create returned is DROPPED — never printed,
     * written, logged or handed to any sink or channel — and nothing is undelivered and nothing is granted. The line names
     * the person's step, with the real client id: mint with `thoryn clients rotate-secret` and store it where the runtime
     * reads it. The unseen create-time secret stays valid until that rotation's overlap expires it; nobody holds it.
     */
    private fun discardForCustomer(r: ProvisionResource, clientId: String) {
        out.println("  > application ${r.name}: client secret discarded (never shown or stored) — managed by the customer: mint it with `${recoverSecret(clientId)}` and store it in your secret manager")
    }

    /** Converge an existing resource: send exactly the changed (non-secret) fields plus any write-only secret. */
    private fun update(r: ProvisionResource, file: ProvisionFile, applied: List<AppliedResource>, change: PlannedChange): AppliedResource {
        val spec = resolveSpec(r, strict = true)
        val id = change.liveId ?: throw ProvisionException("${r.key}: update planned without a live id")
        val changed = spec.filterKeys { it in change.diff.keys }
        val slug = if (r.kind == ProvisionFile.KIND_ENVIRONMENT) null else targetSlug(r, file, applied)
        val base = AppliedResource(r.kind, r.name, id, slug, owner = change.owner, action = ChangeAction.UPDATE)
        return when (r.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                clients(null).renameEnvironment(id, mapOf("name" to spec["displayName"].toString()))
                out.println("  ~ environment ${r.name}: renamed (id $id)")
                base.copy(attributes = mapOf("slug" to spec["slug"].toString()))
            }
            ProvisionFile.KIND_APPLICATION -> {
                // SSO-3715 — the key location rides on every update (idempotent): the API cannot tell us whether it changed.
                val keyLocation = spec.filterKeys { it in KEY_LOCATION_FIELDS }
                // SSO-3941 — `tokenClaims` is converged on its own sub-resource; the application itself is patched only
                // when one of ITS fields (or the always-re-sent key location) is part of the update.
                val fields = changed - ProvisionFile.SPEC_TOKEN_CLAIMS
                if (fields.isNotEmpty() || keyLocation.isNotEmpty()) {
                    try {
                        clients(slug).updateApplication(id, applicationBody(r, fields + keyLocation, slug))
                    } catch (ex: ProductApiException) {
                        throw applicationSettingFailure(r, ex, slug) ?: ex
                    }
                }
                if (ProvisionFile.SPEC_TOKEN_CLAIMS in change.diff) desiredTokenClaims(spec)?.let { convergeTokenClaims(r, slug, id, it) }
                out.println("  ~ application ${r.name}: updated ${change.diff.keys}${if (keyLocation.isNotEmpty()) " + key location" else ""} (clientId $id)")
                base.copy(attributes = applicationAttributes(spec))
            }
            // SSO-3689 — a differing pin is never planned (`workload_identity_trust_immutable`). The updates a plan can carry:
            // SSO-3925 — the trust's scopes (and its live plan profile's) changed in place; SSO-3702 — the additive plan
            // profile on a trust that has none.
            ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> when {
                isTrustScopeChange(change.diff.keys, livePlanScopes(change.trust) != null) -> setTrustScopes(r, change, slug, spec)
                change.diff.keys.all { it.startsWith(PLAN_FIELD_PREFIX) } -> setTrustPlanProfile(r, change, slug, spec)
                else -> throw ProvisionException("${r.key}: $ERROR_TRUST_IMMUTABLE — a trust's pins cannot be changed in place; delete it and re-apply, or declare what is live")
            }
            ProvisionFile.KIND_ROLE -> {
                val client = clients(slug)
                if (ProvisionFile.ROLE_DESCRIPTION in change.diff) client.updateRole(id, mapOf(ProvisionFile.ROLE_DESCRIPTION to spec[ProvisionFile.ROLE_DESCRIPTION]))
                if (ProvisionFile.ROLE_PERMISSIONS in change.diff) client.setRolePermissions(id, permissionIds(r, client, rolePermissions(spec)))
                out.println("  ~ role ${r.name}: updated ${change.diff.keys} (id $id)")
                base
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
            ProvisionFile.KIND_EMAIL_PROVIDER -> putEmailProvider(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            ProvisionFile.KIND_LOGIN_THEME -> putLoginTheme(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            ProvisionFile.KIND_LOGIN_FLOW -> applyLoginFlow(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            ProvisionFile.KIND_LOGIN_METHODS -> putLoginMethods(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            ProvisionFile.KIND_CUSTOM_DOMAIN -> verifyDomain(r, spec).copy(action = ChangeAction.UPDATE)
            ProvisionFile.KIND_EMAIL_TEMPLATE -> putEmailTemplate(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            // SSO-4057 — never a write to a published version: re-activate the stored one, or publish a new one.
            ProvisionFile.KIND_LEGAL_DOCUMENT ->
                if (change.attributes[ATTR_REACTIVATE] == "true") reactivateLegalDocument(r, slug, spec, id)
                else publishLegalDocument(r, slug, spec, "~").copy(action = ChangeAction.UPDATE)
            else -> throw ProvisionException("${r.key}: unsupported kind '${r.kind}'")
        }
    }

    // ── emailTemplate (SSO-4042) ─────────────────────────────────────────────────────────────────

    /** The (type, locale) a declared template addresses: the type as written, the locale in storage form (`null` = the base template). */
    private fun emailTemplateAddress(spec: Map<String, Any?>): Pair<String, String?> {
        val type = spec["type"].nonBlank() ?: throw ProvisionException("emailTemplate: spec.type is required")
        val locale = ProvisionFile.emailTemplateLocale(spec["locale"]).takeIf { it != ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE }
        return type to locale
    }

    /** The live id of a cell, `<type>:<locale>` (`magic_link:*` for the base template) — what `--output json` and [removeByHand] carry. */
    private fun emailTemplateId(type: String, locale: String?): String = "$type:${locale ?: ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE}"

    /**
     * SSO-4054 — where `import` puts a cell's body, relative to the provisioning file: `emails/<type>[.<locale>].html` for the
     * production plane (the SSO-4042 layout, unchanged), `emails/<slug>/<type>[.<locale>].html` for a sandbox — so one file
     * holding several environments never has two cells claim one body file.
     */
    private fun emailTemplateBodyPath(plane: String?, type: String, locale: String?): String =
        "emails/" + (plane?.let { "$it/" } ?: "") + type + (locale?.let { ".$it" } ?: "") + ".html"

    /**
     * `PUT /api/v1/login-experience/email-templates/{type}?locale=` with `{ subject, bodyHtml }` — the body as the file declared it
     * (inline, or read from `bodyFile` when the file was loaded). The API's refusals are surfaced as plain refusals naming the
     * cell and the cause ([emailTemplateFailure]): `unknown_template_variable` with the allowed set, `413` for an oversize subject or
     * body, the blank / locale / type checks the loader also makes.
     */
    private fun putEmailTemplate(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
        val (type, locale) = emailTemplateAddress(spec)
        val subject = spec["subject"].nonBlank() ?: throw ProvisionException("${r.key}: spec.subject is required")
        val body = spec["body"]?.toString()?.takeIf { it.isNotBlank() }
            ?: throw ProvisionException("${r.key}: ${ProvisionFile.ERR_EMAIL_TEMPLATE_BODY_REQUIRED} — spec.body or spec.bodyFile is required")
        val resp = try {
            clients(slug).putEmailTemplate(type, locale, linkedMapOf("subject" to subject, "bodyHtml" to body))
        } catch (ex: ProductApiException) {
            throw emailTemplateFailure(r, ex, type, locale)
        }
        val cell = emailTemplateId(type, locale)
        val source = spec["bodyFile"]?.toString()?.let { " body=$it" } ?: ""
        out.println("  $mark emailTemplate ${r.name}: $cell${slug?.let { " (environment $it)" } ?: ""} subject=\"${subject.take(60)}${if (subject.length > 60) "…" else ""}\"$source")
        return AppliedResource(r.kind, r.name, cell, slug, buildMap {
            put("type", resp.str("templateType") ?: type)
            put("locale", resp.str("locale") ?: locale ?: ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE)
        }, action = ChangeAction.CREATE)
    }

    /** The API's refusal of a template write, named for the cell with the API's own detail (the allowed variables ride in it). */
    private fun emailTemplateFailure(r: ProvisionResource, ex: ProductApiException, type: String, locale: String?): ProvisionException {
        MissingScopeException.of(ex, ScopeRequirements.writeScope(r.kind), ScopeRequirements.Phase.APPLY, r.key, "write the email template")?.let { return it }
        val cell = emailTemplateId(type, locale)
        val detail = ex.errorDescription?.takeIf { it.isNotBlank() } ?: ex.message ?: "the email-template API refused the request"
        return ProvisionException(
            "${r.key}: " + when (ex.errorCode) {
                "unknown_template_variable" -> "unknown_template_variable — $detail Fix the {{variable}} names in the subject or body of $cell and re-run."
                "template_subject_too_large", "template_body_too_large" -> "${ex.errorCode} (HTTP ${ex.httpStatus}) — $detail Shorten the ${if (ex.errorCode == "template_subject_too_large") "subject" else "body"} of $cell and re-run."
                "unknown_template_type", "invalid_template_locale", "template_subject_blank", "template_body_blank" -> "${ex.errorCode} — $detail"
                null -> if (ex.httpStatus == 413) "the subject or body of $cell is too large (HTTP 413) — $detail" else detail
                else -> "${ex.errorCode} — $detail"
            },
        )
    }

    /**
     * `subject` and the body of a cell compared as the API stores them: the subject trimmed; the body with `\r\n` folded to
     * `\n`, trailing whitespace trimmed from every line and the end. A differing body is rendered as a line count, not as
     * the HTML (`body differs (N → M lines, +A −D)`).
     */
    private fun emailTemplateDiff(want: Map<String, String?>, have: Map<String, String?>): Map<String, String> {
        val diff = LinkedHashMap<String, String>()
        if (want["subject"]?.trim() != have["subject"]?.trim()) diff["subject"] = "${render(have["subject"])} → ${render(want["subject"])}"
        bodyDiff(want["body"], have["body"])?.let { diff["body"] = it }
        return diff
    }

    /**
     * Two bodies compared as the APIs store them ([normaliseBody]: `\r\n` folded to `\n`, trailing whitespace trimmed from every
     * line and the end); null when equal, else the difference as a line count, never the text (`body differs (N → M lines, +A −D)`).
     */
    private fun bodyDiff(want: String?, have: String?): String? {
        val wantBody = normaliseBody(want)
        val haveBody = normaliseBody(have)
        if (wantBody == haveBody) return null
        val wantLines = wantBody.lines(); val haveLines = haveBody.lines()
        val wantCount = wantLines.groupingBy { it }.eachCount(); val haveCount = haveLines.groupingBy { it }.eachCount()
        val added = wantCount.entries.sumOf { (line, n) -> maxOf(0, n - (haveCount[line] ?: 0)) }
        val removed = haveCount.entries.sumOf { (line, n) -> maxOf(0, n - (wantCount[line] ?: 0)) }
        return "body differs (${haveLines.size} → ${wantLines.size} lines, +$added −$removed)"
    }

    // ── legalDocument (SSO-4057) ─────────────────────────────────────────────────────────────────

    /** A declared legal document in the API's normal form: the type and the version / title trimmed, the format lower-cased (omitted ⇒ markdown), the body as declared. */
    private data class LegalDocumentWant(val type: String, val version: String, val title: String, val format: String, val body: String)

    private fun legalDocumentWant(spec: Map<String, Any?>): LegalDocumentWant = LegalDocumentWant(
        type = spec["type"].nonBlank() ?: throw ProvisionException("legalDocument: spec.type is required"),
        version = spec["version"].nonBlank() ?: throw ProvisionException("legalDocument: spec.version is required"),
        title = spec["title"].nonBlank() ?: throw ProvisionException("legalDocument: spec.title is required"),
        format = spec["format"].nonBlank()?.lowercase() ?: ProvisionFile.LEGAL_DOCUMENT_DEFAULT_FORMAT,
        body = spec["body"]?.toString() ?: "",
    )

    /** The live id of a legal-document version, `<type>/<id>` — the API's own path below `/legal-documents/` (what `--output json` and [removeByHand] carry). */
    private fun legalDocumentId(type: String, id: String): String = "$type/$id"

    /** Whether a listed legal-document version is the ACTIVE one. */
    private fun JsonNode.isActive(): Boolean = this["active"]?.takeIf { it.isBoolean }?.asBoolean() == true

    /** The content fields of [want] that differ from the stored version [n] — title (trimmed), format, body ([bodyDiff]); empty when it is the same text. */
    private fun legalDocumentContentDiff(want: LegalDocumentWant, n: JsonNode): Map<String, String> {
        val diff = LinkedHashMap<String, String>()
        val title = n.str("title")?.trim()
        if (title != want.title) diff["title"] = "${render(title)} → ${render(want.title)}"
        val format = n.str("format")?.trim()?.lowercase() ?: ProvisionFile.LEGAL_DOCUMENT_DEFAULT_FORMAT
        if (format != want.format) diff["format"] = "$format → ${want.format}"
        bodyDiff(want.body, n["body"]?.takeIf { !it.isNull }?.asString())?.let { diff["body"] = it }
        return diff
    }

    /**
     * SSO-4057 — where `import` puts an environment's active document, relative to the provisioning file: `legal/<type>.md`
     * (`.txt` for `format: text`) for the production plane, `legal/<slug>/<type>.md` for a sandbox — the `emails/` layout of
     * [emailTemplateBodyPath], so one file holding several environments never has two documents claim one body file.
     */
    private fun legalDocumentBodyPath(plane: String?, type: String, format: String): String =
        "legal/" + (plane?.let { "$it/" } ?: "") + type + if (format == "text") ".txt" else ".md"

    /**
     * `POST /api/v1/login-experience/legal-documents/{type}` with `{ version, title, body, format }`: publishes a NEW version, which
     * the API activates (deactivating the previous one). Users accept it at their next sign-in.
     */
    private fun publishLegalDocument(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
        val want = legalDocumentWant(spec)
        if (want.body.isBlank()) throw ProvisionException("${r.key}: ${ProvisionFile.ERR_LEGAL_DOCUMENT_BODY_REQUIRED} — spec.body or spec.bodyFile is required")
        val resp = try {
            clients(slug).publishLegalDocument(want.type, linkedMapOf("version" to want.version, "title" to want.title, "body" to want.body, "format" to want.format))
        } catch (ex: ProductApiException) {
            throw legalDocumentFailure(r, ex, want.type, want.version, slug, "publish")
        }
        val id = legalDocumentId(want.type, resp.str("id") ?: throw ProvisionException("${r.key}: the legal-document publish returned no id"))
        val source = spec["bodyFile"]?.toString()?.let { " body=$it" } ?: ""
        out.println("  $mark legalDocument ${r.name}: ${want.type} version ${want.version}${slug?.let { " (environment $it)" } ?: ""} published and active — users accept it at their next sign-in$source")
        return AppliedResource(r.kind, r.name, id, slug, mapOf("type" to want.type, "version" to want.version), action = ChangeAction.CREATE)
    }

    /** `POST …/{type}/{id}/activate` — the stored version the plan found with the declared label and content becomes the active one again. */
    private fun reactivateLegalDocument(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, id: String): AppliedResource {
        val want = legalDocumentWant(spec)
        try {
            clients(slug).activateLegalDocument(want.type, id.substringAfter('/'))
        } catch (ex: ProductApiException) {
            throw legalDocumentFailure(r, ex, want.type, want.version, slug, "activate")
        }
        out.println("  ~ legalDocument ${r.name}: ${want.type} version ${want.version}${slug?.let { " (environment $it)" } ?: ""} re-activated (the stored version; nothing published)")
        return AppliedResource(r.kind, r.name, id, slug, mapOf("type" to want.type, "version" to want.version), action = ChangeAction.UPDATE)
    }

    /** The API's refusal of a legal-document write, named for the document with the API's own code and detail. */
    private fun legalDocumentFailure(r: ProvisionResource, ex: ProductApiException, type: String, version: String, slug: String?, what: String): ProvisionException {
        MissingScopeException.of(ex, ScopeRequirements.writeScope(r.kind), ScopeRequirements.Phase.APPLY, r.key, "$what the legal document")?.let { return it }
        val where = "the $type version '$version' in ${planeLabel(slug)}"
        val detail = ex.errorDescription?.takeIf { it.isNotBlank() } ?: ex.message ?: "the legal-document API refused the request"
        return ProvisionException(
            "${r.key}: " + when (ex.errorCode) {
                "version_exists" -> "version_exists — $where was published since the plan was made (a label is unique per type and environment, inactive versions included); re-run plan"
                ProvisionFile.ERR_HTML_NOT_ALLOWED -> "${ProvisionFile.ERR_HTML_NOT_ALLOWED} — $detail ($where)"
                null -> "HTTP ${ex.httpStatus} — $detail ($where)"
                else -> "${ex.errorCode} — $detail ($where)"
            },
        )
    }

    private fun normaliseBody(html: String?): String =
        (html ?: "").replace("\r\n", "\n").replace('\r', '\n').lines().joinToString("\n") { it.trimEnd() }.trimEnd()

    private fun putEmailProvider(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
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
        return AppliedResource(r.kind, r.name, id, slug, buildMap {
            resp.str("smtpHost")?.let { put("smtpHost", it) }
            resp.str("fromAddress")?.let { put("fromAddress", it) }
            resp.str("configVersion")?.let { put("configVersion", it) }
        }, action = ChangeAction.CREATE)
    }

    /**
     * SSO-4041 — `PUT /api/v1/login-experience/branding` REPLACES the stored record (identity's `LoginBrandingAdminService.upsert`:
     * an omitted or `null` field clears the stored value; `cssVariables` is one map, `null` clears every token). The body is
     * therefore the FULL record ([brandingRecord]) with an explicit `null` for every field the spec does not declare — what the
     * plan showed as `(cleared)` is exactly what this clears, and nothing is left to the API's defaults by omission.
     */
    private fun putLoginTheme(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
        val body = brandingRecord(spec)
        val resp = clients(slug).putLoginBranding(body)
        val effective = resp["effective"]
        val cleared = body.filterValues { it == null }.keys
        out.println("  $mark loginTheme: theme=${effective?.str("theme") ?: "(default)"}" + if (cleared.isEmpty()) "" else " (cleared: ${cleared.joinToString(", ")})")
        return AppliedResource(r.kind, r.name, "login-theme", slug, buildMap {
            effective?.str("theme")?.let { put("theme", it) }
            effective?.str("primaryColor")?.let { put("primaryColor", it) }
        }, action = ChangeAction.CREATE)
    }

    /**
     * SSO-4041 — the branding record as the PUT writes it and the plan compares it: every field of
     * [ProvisionFile.LOGIN_THEME_SPEC_KEYS], in order, `null` when [spec] does not declare it (or declares it blank / empty —
     * a blank colour and an empty `cssVariables` are "unset", as identity stores them). Scalars are normalised the way identity
     * stores them (trimmed; colours and the theme lower-cased; the radius an integer; SSO-4048 — the name, title, favicon and
     * footer links trimmed only); `cssVariables` keeps only tokens with a non-blank value (an all-blank map is `null`: the PUT
     * clears the column either way).
     */
    private fun brandingRecord(spec: Map<*, *>?): Map<String, Any?> = linkedMapOf<String, Any?>().apply {
        this["logoUrl"] = spec?.get("logoUrl").nonBlank()
        this["primaryColor"] = spec?.get("primaryColor").nonBlank()?.lowercase()
        this["backgroundColor"] = spec?.get("backgroundColor").nonBlank()?.lowercase()
        this["borderRadiusPx"] = spec?.get("borderRadiusPx")?.let { coerceInt(it) }
        this["theme"] = spec?.get("theme").nonBlank()?.lowercase()
        this["cssVariables"] = (spec?.get("cssVariables") as? Map<*, *>)?.entries?.mapNotNull { (k, v) ->
            val key = k?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            val value = v.nonBlank()
            if (key != null && value != null) key to value else null
        }?.toMap()?.takeIf { it.isNotEmpty() }
        // SSO-4048 — name, title, favicon and footer links: stored trimmed and as written (identity lower-cases none of them).
        listOf("displayName", "pageTitle", "faviconUrl", "supportUrl", "termsUrl", "privacyUrl").forEach { field -> this[field] = spec?.get(field).nonBlank() }
    }

    /**
     * SSO-4041 — [diffOf] over the whole branding record: unlike a PATCH-style diff it ALSO lists a field that is stored but that
     * the file does not declare, as `<stored> → (cleared)` — the PUT will clear it, so the plan must say so. `cssVariables` is
     * one entry: the PUT replaces the map, so a token the file omits is cleared with the rest (`{…} → {…}` shows both maps).
     */
    private fun brandingDiff(desired: Map<String, Any?>, live: Map<String, Any?>): Map<String, String> {
        val diff = LinkedHashMap<String, String>()
        ProvisionFile.LOGIN_THEME_SPEC_KEYS.forEach { field ->
            val want = desired[field]
            val have = live[field]
            if (norm(want) == norm(have)) return@forEach
            diff[field] = if (want == null) "${render(have)} → (cleared — the file does not declare it; the platform default applies)" else "${render(have)} → ${render(want)}"
        }
        return diff
    }

    private fun applyLoginFlow(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
        val client = clients(slug)
        val templateId = spec["templateId"].toString()
        val draft = client.applyLoginFlowTemplate(templateId)
        val version = draft["version"]?.takeIf { !it.isNull }?.asInt()
            ?: throw ProvisionException("${r.key}: the login-flow template apply returned no version")
        val activate = spec["activate"]?.let { coerceBool(it) } ?: true
        if (activate) client.activateLoginFlow(version)
        out.println("  $mark loginFlow: template=$templateId version=$version${if (activate) " (active)" else " (draft)"}")
        return AppliedResource(r.kind, r.name, version.toString(), slug, mapOf("templateId" to templateId, "activated" to activate.toString()), action = ChangeAction.CREATE)
    }

    /**
     * SSO-3100 — PUT the FULL sign-in method allow-list (`thoryn login-methods set`): replace, not merge.
     * Tokens are normalised (trimmed, lower-cased); the server rejects an unknown or empty list.
     */
    private fun putLoginMethods(r: ProvisionResource, slug: String?, spec: Map<String, Any?>, mark: String): AppliedResource {
        val methods = (spec["methods"] as? List<*>).orEmpty().mapNotNull { it?.toString()?.trim()?.lowercase()?.takeIf { m -> m.isNotEmpty() } }.distinct()
        if (methods.isEmpty()) throw ProvisionException("${r.key}: spec.methods must list at least one sign-in method")
        val resp = clients(slug).putLoginMethods(methods)
        val stored = resp["stored"]?.takeIf { !it.isNull && it.isArray }?.toList()?.map { it.asString() } ?: methods
        out.println("  $mark loginMethods: ${stored.joinToString(", ")}")
        return AppliedResource(r.kind, r.name, "login-methods", slug, mapOf("methods" to stored.joinToString(",")), action = ChangeAction.CREATE)
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
     * | `spec.host`, `VERIFIED` / `ACTIVE` | noop | nothing |
     * | another host | — | refuses: moving the issuer to another host is a deliberate `thoryn domain remove` first |
     *
     * A failing DNS proof is NOT an apply failure — the records are the customer's to publish, and DNS takes
     * a while to propagate: the change reports the state and the reason, and a re-run (or `--wait`) converges.
     * A workspace without the operator entitlement is planned but stops `apply` with the operator step named
     * ([CustomDomainMessages.NOT_ENTITLED]); an identity with no reach gets the grant it needs
     * named ([CustomDomainMessages.NO_ACCESS]).
     */
    private fun probeCustomDomain(r: ProvisionResource): PlannedChange {
        val host = hostOf(resolveSpec(r, strict = false))
        val body = try {
            clients(null).getCustomDomain()
        } catch (ex: ProductApiException) {
            if (ex.httpStatus == 404) throw ProvisionException("${r.key}: ${CustomDomainMessages.NO_ACCESS}")
            MissingScopeException.of(ex, ScopeRequirements.readScope(r.kind), ScopeRequirements.Phase.PLAN, r.key, "read live state")?.let { throw it }
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        val view = CustomDomainView.of(body)
        val id = customDomainId()
        val details = view.toStructured() + ("desiredHost" to host)
        val attributes = buildMap { put("host", host); put("state", view.state); view.issuer?.let { put("issuer", it) } }
        return when {
            view.state == CustomDomainView.NONE && !view.entitled -> PlannedChange(
                r.kind, r.name, ChangeAction.CREATE,
                "claim $host — NOT ENTITLED: ${CustomDomainMessages.NOT_ENTITLED} (apply stops here until then)",
                resource = r, customDomain = details, retain = r.retain,
            )
            view.state == CustomDomainView.NONE -> PlannedChange(
                r.kind, r.name, ChangeAction.CREATE,
                "claim $host and verify it (the claim issues the TXT ownership value; the CNAME points at ${view.cnameTarget ?: "the platform host"})",
                resource = r, customDomain = details + ("records" to plannedRecords(host, view)), retain = r.retain,
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
                resource = r, liveId = id, attributes = attributes, diff = mapOf("state" to "${view.state} → verify"), customDomain = details, retain = r.retain,
            )
            else -> PlannedChange(r.kind, r.name, ChangeAction.NOOP, "exists and is ${view.state}", resource = r, liveId = id, attributes = attributes, customDomain = details, retain = r.retain)
        }
    }

    /** Before the claim only the CNAME is known (the TXT value is minted by the claim); after it, the live records. */
    private fun plannedRecords(host: String, view: CustomDomainView): List<Map<String, Any>> =
        view.records.map { it.toStructured() }.ifEmpty {
            listOfNotNull(view.cnameTarget?.let { DnsRecord("CNAME", host, it, DnsRecord.DEFAULT_TTL_SECONDS).toStructured() })
        }

    /** `PUT /api/v1/custom-domain`, then one verify attempt. */
    private fun claimCustomDomain(r: ProvisionResource, spec: Map<String, Any?>): AppliedResource {
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
    private fun verifyDomain(r: ProvisionResource, spec: Map<String, Any?>, after: JsonNode? = null): AppliedResource {
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
        return AppliedResource(r.kind, r.name, customDomainId(), null, buildMap {
            put("host", host)
            put("state", view.state)
            view.issuer?.let { put("issuer", it) }
        }, action = ChangeAction.CREATE)
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

    /** The id of the workspace-level singleton: the workspace id (`tnt`), else a stable placeholder. */
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

    /** The grant diff of one object: what to add, what `--prune` revokes, what stays "present, not declared". */
    private data class GrantDiff(val adds: List<String>, val removes: List<String>, val undeclared: List<String>)

    /**
     * Adds = declared but not live. SSO-3715 (ADR 2026-10-15 §2) — grants are additive by default: a live grant the
     * block does not declare is [GrantDiff.undeclared] ("present, not declared"), shown and left alone. With
     * [revoke] (`--prune` on an object the caller may delete) it is a remove — EXCEPT the `owner` tuple (the
     * platform's one-owner relation is an admin's to move), a workspace userset (`workspace:<id>#admin` and any
     * other `workspace:` subject — defence in depth) and the caller's own subject (an apply never saws off the
     * branch it sits on). No "granted by this file" marker exists any more — the declaration is the file, the
     * authority is the owner.
     */
    private fun grantDiff(declared: List<ProvisionGrant>, live: List<String>, revoke: Boolean): GrantDiff {
        val wanted = declared.map { it.label }.distinct()
        val have = live.distinct()
        val adds = wanted.filter { it !in have }
        val undeclared = have.filter { it !in wanted }
        if (!revoke) return GrantDiff(adds, emptyList(), undeclared)
        val (removes, kept) = undeclared.partition { label ->
            val (grantee, relation) = label.split(' ', limit = 2)
            relation != RELATION_OWNER && !grantee.startsWith("$OBJECT_TYPE_WORKSPACE:") && grantee != subject
        }
        return GrantDiff(adds, removes, kept)
    }

    /**
     * Converge the `grants:` block on ONE object: list, POST the missing, DELETE the ones the plan decided to revoke
     * ([removes] — `--prune` on an object the caller may delete, after the exclusions). The live set is re-read here
     * so a grant someone added between plan and apply is never revoked on a stale diff.
     */
    private fun convergeGrants(r: ProvisionResource, ref: String, removes: List<String>, implicit: ProvisionGrant? = null) {
        // SSO-3921 — the `workloadPull` workload client's `manager` joins the declared block, or is the only grant converged.
        val declared = (r.grants.orEmpty() + listOfNotNull(implicit)).distinctBy { it.label }.takeIf { r.grants != null || implicit != null } ?: return
        val live = liveGrants(r, ref)
        val adds = grantDiff(declared, live, revoke = false).adds
        val revoke = removes.filter { it in live }
        if (adds.isEmpty() && revoke.isEmpty()) return
        val client = clients(null)
        try {
            adds.forEach { label ->
                val (subject, relation) = label.split(' ', limit = 2)
                client.createGrant(subject, relation, ref)
                out.println("  + grant ${r.kind} ${r.name}: $subject $relation on $ref")
            }
            revoke.forEach { label ->
                val (subject, relation) = label.split(' ', limit = 2)
                client.deleteGrant(subject, relation, ref)
                out.println("  - grant ${r.kind} ${r.name}: $subject $relation on $ref (not declared; --prune)")
            }
        } catch (ex: ProductApiException) {
            throw grantFailure(r, ex, AccessRefs.SCOPE_WRITE, "converge the grants on $ref")
        }
    }

    /** Fail closed: a 403 `insufficient_scope` on the access API names the missing scope and the login line. */
    private fun grantFailure(r: ProvisionResource, ex: ProductApiException, scope: String, what: String): ProvisionException =
        // SSO-3926 — reading grants is part of a plan (tenant:access.read); writing them only of an apply (tenant:access.write).
        MissingScopeException.of(ex, scope, if (scope == AccessRefs.SCOPE_WRITE) ScopeRequirements.Phase.APPLY else ScopeRequirements.Phase.PLAN, r.key, "$what (grants are NOT converged)")
            ?: if (ex.isInsufficientScope) {
                ProvisionException(
                    "${r.key}: could not $what — this session lacks the '$scope' scope (${ex.message}). " +
                        "Grants are NOT converged; sign in with `thoryn login --scope $scope` (or grant the CI client that scope) and re-run.",
                )
            } else {
                ProvisionException("${r.key}: could not $what (${ex.message})")
            }

    // ── per-kind remove ──────────────────────────────────────────────────────────────────────────

    private fun remove(c: PlannedChange, confirmSlug: String?) {
        val id = c.liveId ?: throw ProvisionException("${c.key}: removal planned without a live id")
        when (c.kind) {
            ProvisionFile.KIND_ENVIRONMENT -> {
                // A sandbox hard-delete is confirmed by the environment's OWN slug (SSO-2960 contract).
                clients(null).deleteEnvironment(id, c.attributes["slug"])
                out.println("  - environment ${c.name}: hard-deleted (id $id)")
            }
            ProvisionFile.KIND_APPLICATION -> {
                clients(c.environment).deleteApplication(id, confirmSlug)
                out.println("  - application ${c.name}: deleted (clientId $id)")
            }
            ProvisionFile.KIND_USER -> {
                clients(c.environment).deleteUser(id, confirmSlug)
                out.println("  - user ${c.name}: deleted (id $id)")
            }
            ProvisionFile.KIND_FEDERATION_MEMBER -> {
                clients(c.environment).deleteFederationMember(id, confirmSlug)
                out.println("  - federationMember ${c.name}: detached (id $id)")
            }
            ProvisionFile.KIND_EMAIL_PROVIDER -> {
                clients(c.environment).deleteEmailProvider(confirmSlug)
                out.println("  - emailProvider: reset to the platform sender")
            }
            ProvisionFile.KIND_LOGIN_METHODS -> {
                // SSO-3100 — the delete path IS a reset: back to the default (every method offered).
                clients(c.environment).resetLoginMethods()
                out.println("  - loginMethods: reset to the default (every method offered)")
            }
            ProvisionFile.KIND_LOGIN_THEME -> {
                // SSO-4041 — the API has no DELETE: the PUT of the EMPTY record (every field null) IS the reset to the platform defaults.
                clients(c.environment).putLoginBranding(brandingRecord(null))
                out.println("  - loginTheme: reset to the platform defaults (the empty record was PUT; the API has no DELETE)")
            }
            ProvisionFile.KIND_CUSTOM_DOMAIN -> {
                // SSO-3413 — reached only through `--prune` / `destroy`, both production-plane gated by `--confirm`.
                clients(null).deleteCustomDomain()
                out.println("  - customDomain: released ${c.attributes["host"] ?: ""} — the workspace issues on its platform host again")
            }
            ProvisionFile.KIND_EMAIL_TEMPLATE -> {
                // SSO-4042 — the DELETE of the (type, locale) cell IS the reset to the built-in default (idempotent on the API).
                val type = c.attributes["type"] ?: id.substringBefore(':')
                val locale = (c.attributes["locale"] ?: id.substringAfter(':', ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE)).takeIf { it != ProvisionFile.EMAIL_TEMPLATE_BASE_LOCALE }
                // SSO-4054 — in the row's OWN environment only (`X-Thoryn-Environment`); a sandbox then sends production's copy.
                clients(c.environment).deleteEmailTemplate(type, locale)
                out.println("  - emailTemplate ${c.name}: ${emailTemplateId(type, locale)}${c.environment?.let { " (environment $it)" } ?: ""} reset to the built-in default")
            }
            ProvisionFile.KIND_LEGAL_DOCUMENT -> {
                // SSO-4057 — the DELETE soft-deletes that version (the environment then has no document of the type); refused
                // `409 document_accepted` once a user accepted it (GDPR Art. 7). Reached only through a plan that carries the row:
                // destroy / --prune never plan one for a production document, and a sandbox's goes with its sandbox.
                val type = c.attributes["type"] ?: id.substringBefore('/')
                try {
                    clients(c.environment).deleteLegalDocument(type, id.substringAfter('/'))
                } catch (ex: ProductApiException) {
                    if (ex.httpStatus == 409 && ex.errorCode == "document_accepted") {
                        throw ProvisionException("${c.key}: document_accepted — users have accepted this $type version, so it cannot be deleted (the acceptances are a GDPR Art. 7 audit trail); publish a new version instead")
                    }
                    throw ex
                }
                out.println("  - legalDocument ${c.name}: $type version ${c.attributes["version"] ?: id.substringAfter('/')}${c.environment?.let { " (environment $it)" } ?: ""} deleted — the environment has no $type now")
            }
            ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> {
                // SSO-3689 — only through `--prune` / `destroy`; the trust's workload client stops authenticating at once.
                clients(c.environment).deleteWorkloadIdentityTrust(id, confirmSlug)
                trustLists.remove(c.environment)
                out.println("  - workloadIdentityTrust ${c.name}: deleted (id $id; its workload client ${c.attributes[ATTR_CLIENT_ID] ?: "wi_…"} stops authenticating at once)")
            }
            ProvisionFile.KIND_ROLE -> {
                // SSO-3941 — the role and every assignment of it go (product-api's CASCADE); its permissions stay (workspace-wide).
                clients(c.environment).deleteRole(id, confirmSlug)
                out.println("  - role ${c.name}: deleted (id $id; every user's assignment of it goes with it)")
            }
            else -> throw ProvisionException("${c.key}: no delete API for kind '${c.kind}'")
        }
    }

    // ── workload-identity trusts and secret-less clients (SSO-3689) ─────────────────────────────

    /** The workspace slug `apply` is bound to — what the consumer's `connection.json` names. */
    private var applyWorkspace: String? = null

    /** Every trust of one plane, listed once per pass (cleared by [plan] / [apply], and after a write to that plane). */
    private val trustLists = HashMap<String?, List<JsonNode>>()

    /** SSO-3774 — each declared trust's verdict in the current [plan], read when an application names it (trusts plan first). */
    private val trustVerdicts = HashMap<String, PlannedChange>()

    /**
     * SSO-3774 — declared trusts that matched nothing live while this identity cannot read their whole plane on a platform
     * that filters the trust list (S1): absent, OR present and invisible to it. Cleared with [trustVerdicts].
     */
    private val trustsHidden = HashSet<String>()

    /** `GET /api/v1/workload-identity/trusts` of one plane, every page. A plane this identity cannot read answers 404 — the caller treats that as "none visible". */
    private fun trustsOf(slug: String?, fresh: Boolean = false): List<JsonNode> {
        if (!fresh) trustLists[slug]?.let { return it }
        val client = clients(slug)
        val items = mutableListOf<JsonNode>()
        var cursor: String? = null
        for (page in 0 until MAX_TRUST_PAGES) {
            val body = client.listWorkloadIdentityTrusts(null, cursor)
            items += listItems(body, "data")
            cursor = body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            if (cursor == null || body["pagination"]?.get("hasMore")?.asBoolean(true) == false) break
        }
        return items.also { trustLists[slug] = it }
    }

    private fun planeLabel(slug: String?): String = slug?.let { "environment '$it'" } ?: "the production plane"

    /**
     * Live lookup of a trust by its NAME in its plane (or by the owned id): absent ⇒ create (refused up front with the
     * hub's `scope_not_grantable` when the host knows the caller's scopes and a declared one is not among them);
     * present and every DECLARED field equal ⇒ adopt / no-op; present with only its scopes different ⇒ an in-place scope
     * change (SSO-3925); present with a pin different ⇒ `workload_identity_trust_immutable` (the pins are immutable by design). A trust whose workload client IS the applying identity is
     * refused: a file cannot declare the bootstrap trust it signs in with.
     */
    private fun probeTrust(r: ProvisionResource, slug: String?, desired: Map<String, Any?>): PlannedChange {
        val node = try {
            fetchOrNull { trustsOf(slug) }?.firstOrNull { it.str("name") == r.name }
        } catch (ex: ProductApiException) {
            MissingScopeException.of(ex, ScopeRequirements.readScope(r.kind), ScopeRequirements.Phase.PLAN, r.key, "read live state")?.let { throw it }
            throw ProvisionException("${r.key}: could not read live state (${ex.message})")
        }
        if (node == null) {
            // SSO-3774 — a production-plane create from CI is refused by the gate (a person's act, or a trust it cannot see):
            // the scope ceiling of a create that will not happen would only hide that verdict.
            val ciOnProduction = (r.environment == null || slug == PRODUCTION_ENV_SLUG) && subject?.startsWith("client:") == true
            val notHeld = if (ciOnProduction) emptyList() else scopesNotHeld(desired)
            if (notHeld.isNotEmpty()) {
                return PlannedChange(
                    r.kind, r.name, ChangeAction.ERROR,
                    "$ERROR_SCOPE_NOT_GRANTABLE — a trust can carry only tenant: scopes the applying identity itself holds, and this one does not hold ${notHeld.joinToString(", ")}: " +
                        "drop the scope from spec.scopes, or sign in with it (grant the CI identity that scope) first",
                    resource = r, environment = slug, error = ERROR_SCOPE_NOT_GRANTABLE,
                )
            }
            return PlannedChange(r.kind, r.name, ChangeAction.CREATE, "not found by its name in ${planeLabel(slug)} — mints its wi_ workload client$SCOPE_CEILING_NOTE", resource = r, environment = slug, retain = r.retain)
        }
        val id = node.str("id") ?: ""
        val view = trustView(node)
        val attributes = trustAttributes(view)
        val clientId = node.str("clientId")
        // SSO-3774 — the platform `owner` of the trust as its response renders it (S1; absent on an older platform).
        val owner = ProvisionApi.ownerOf(node)
        if (clientId != null && subject == "client:$clientId") {
            return PlannedChange(
                r.kind, r.name, ChangeAction.ERROR,
                "$ERROR_TRUST_IS_SELF — this trust's workload client $clientId is the identity applying this file: a repository cannot declare its OWN bootstrap trust " +
                    "(it was created once by a person, and a file that owned it could remove the identity it signs in with); drop the resource",
                resource = r, liveId = id, environment = slug, attributes = attributes, error = ERROR_TRUST_IS_SELF, trust = view,
            )
        }
        val diff = diffOf(trustDesired(desired), trustLive(node))
        // SSO-3702 — the additive exception to immutability: a declared plan profile on a live trust that has none is
        // converged by `set plan profile` (the wi_ client stays). SSO-3925 — the trust's scopes, and its live plan profile's,
        // change in place. Anything else that differs — a pin, a live profile's environment — is still the immutable error.
        val planOnly = diff.isNotEmpty() && diff.keys.all { it.startsWith(PLAN_FIELD_PREFIX) }
        val liveHasPlan = node[ProvisionFile.TRUST_PLAN]?.takeIf { it.isObject && it.str("environment") != null } != null
        return when {
            isTrustScopeChange(diff.keys, liveHasPlan) -> planTrustScopeChange(r, slug, desired, view, id, attributes, diff, clientId, owner)
            planOnly && !liveHasPlan -> PlannedChange(
                r.kind, r.name, ChangeAction.UPDATE,
                "exists — adds the plan profile (GitHub environment '${(desired[ProvisionFile.TRUST_PLAN] as? Map<*, *>)?.get("environment")}', read-only scopes) " +
                    "through the one additive set-plan-profile call; the wi_ workload client ${clientId ?: ""} stays".replace("  ", " "),
                resource = r, liveId = id, environment = slug, attributes = attributes, diff = diff, trust = view, retain = r.retain, owner = owner,
            )
            planOnly -> PlannedChange(
                r.kind, r.name, ChangeAction.ERROR,
                "$ERROR_TRUST_IMMUTABLE — the live trust already carries a plan profile that differs from the declared one (${diff.keys.joinToString(", ")}); a plan profile's environment is set once: " +
                    "declare what is live, or re-create the trust (`thoryn workload-identity trusts delete $id${slug?.let { " --environment $it" } ?: ""}`, then re-apply — a new wi_ client, re-paste it)",
                resource = r, liveId = id, environment = slug, attributes = attributes, diff = diff, error = ERROR_TRUST_IMMUTABLE, trust = view,
            )
            // SSO-3774 (oauthy ADR 2026-10-16 §6, I7) — the engine never mutates a pin; on the production plane the only route to
            // a new pin set is a NEW trust, and creating that is a person's act (a human approves every production pin set).
            diff.isNotEmpty() -> PlannedChange(
                r.kind, r.name, ChangeAction.ERROR,
                "$ERROR_TRUST_IMMUTABLE — ${diff.size} declared field(s) differ from the live trust (${diff.keys.joinToString(", ")}); a trust's pins are immutable on the hub (its scopes change in place, but not together with a pin): " +
                    if (slug == null || slug == PRODUCTION_ENV_SLUG) {
                        "declare what is live. On the PRODUCTION plane a changed pin set is a NEW trust, and a new production trust is created by a PERSON, never by this file " +
                            "from CI: a workspace admin reviews the new pins, creates the trust (declare it under a new name and apply the file signed in as themselves), " +
                            "and grants the owning repository `owner` on it; then rebind the client and delete the old trust (`thoryn workload-identity trusts delete $id --confirm <workspace-slug>`)"
                    } else {
                        "declare what is live, or delete it (`thoryn workload-identity trusts delete $id --environment $slug`) and re-apply to re-create it"
                    },
                resource = r, liveId = id, environment = slug, attributes = attributes, diff = diff, error = ERROR_TRUST_IMMUTABLE, trust = view,
                fixNote = if (slug == null || slug == PRODUCTION_ENV_SLUG) "a change to the file, not a missing right: a production trust's pins never change in place — declare what is live; a new pin set is a new trust a person creates" else null,
            )
            else -> PlannedChange(r.kind, r.name, ChangeAction.NOOP, "exists and matches", resource = r, liveId = id, environment = slug, attributes = attributes, trust = view, retain = r.retain, owner = owner)
        }
    }

    /** SSO-3925 — is a trust's [diff] a pure scope change the hub makes in place? The plan's scopes only when the live trust has a plan profile. */
    private fun isTrustScopeChange(diff: Set<String>, liveHasPlan: Boolean): Boolean =
        diff.isNotEmpty() && diff.all { it in TRUST_SCOPE_FIELDS } && (TRUST_PLAN_SCOPES_FIELD !in diff || liveHasPlan)

    /** SSO-3925 — the live plan profile's scopes from a trust view, or null when the trust has no plan profile. */
    private fun livePlanScopes(view: Map<String, Any?>?): List<String>? =
        (view?.get(ProvisionFile.TRUST_PLAN) as? Map<*, *>)?.takeIf { it["environment"] != null }
            ?.let { plan -> (plan[ProvisionFile.TRUST_SCOPES] as? List<*>).orEmpty().map { it.toString() } }

    /**
     * SSO-3925 — the in-place scope change a declared trust needs against its live view: the `PUT …/{id}/scopes` body (only
     * the sets that differ), whether it WIDENS either set, and what it adds / removes — or, in [problem], why it cannot be
     * planned. A plan profile whose scopes the file leaves to the hub (`plan:` without `scopes`) is never widened here; when
     * the new apply scopes drop some of its live scopes, the profile keeps the rest (`planScopes` = live ∩ new), and with
     * none left the file must name `spec.plan.scopes`.
     */
    private class TrustScopeChange(
        val body: Map<String, Any?>,
        val widened: Boolean,
        val added: List<String>,
        val removed: List<String>,
        val problem: String? = null,
    )

    private fun trustScopeChange(spec: Map<String, Any?>, view: Map<String, Any?>?): TrustScopeChange {
        val liveApply = (view?.get("scopes") as? List<*>).orEmpty().map { it.toString() }
        val livePlan = livePlanScopes(view)
        val desiredApply = (spec[ProvisionFile.TRUST_SCOPES] as? List<*>)?.map { it.toString().trim() }?.distinct() ?: liveApply
        val declaredPlan = ((spec[ProvisionFile.TRUST_PLAN] as? Map<*, *>)?.get(ProvisionFile.TRUST_SCOPES) as? List<*>)?.map { it.toString().trim() }?.distinct()
        val body = linkedMapOf<String, Any?>()
        if (desiredApply.toSet() != liveApply.toSet()) body[ProvisionFile.TRUST_SCOPES] = desiredApply
        var planAfter = livePlan.orEmpty()
        if (livePlan != null) {
            if (declaredPlan != null && declaredPlan.toSet() != livePlan.toSet()) {
                planAfter = declaredPlan
                body[API_PLAN_SCOPES] = declaredPlan
            } else if (declaredPlan == null && livePlan.any { it !in desiredApply }) {
                planAfter = livePlan.filter { it in desiredApply }
                if (planAfter.isEmpty()) {
                    return TrustScopeChange(
                        body, false, emptyList(), emptyList(),
                        problem = "the new spec.scopes keep none of the plan profile's live scopes (${livePlan.joinToString(" ")}): name spec.plan.scopes — read-only scopes from spec.scopes",
                    )
                }
                body[API_PLAN_SCOPES] = planAfter
            }
        }
        val added = desiredApply.filterNot { it in liveApply } + planAfter.filterNot { it in livePlan.orEmpty() }.map { "plan:$it" }
        val removed = liveApply.filterNot { it in desiredApply } + livePlan.orEmpty().filterNot { it in planAfter }.map { "plan:$it" }
        return TrustScopeChange(body, added.isNotEmpty(), added, removed)
    }

    /**
     * SSO-3925 — plan a declared trust whose only difference from the live one is its scopes: an in-place `set scopes`
     * (the id, the `wi_` client, its owner and every consumer's `connection.json` stay). Refused in the plan, with the
     * API's own codes, when the applying identity does not hold a declared scope (`scope_not_grantable`) or when a CI
     * identity would WIDEN the trust (`elevated_action_requires_person`: adding a scope is a person's act with a fresh
     * passkey sign-in, ADR 2026-10-21 §4b); a narrowing converges from CI.
     */
    private fun planTrustScopeChange(
        r: ProvisionResource,
        slug: String?,
        desired: Map<String, Any?>,
        view: Map<String, Any?>,
        id: String,
        attributes: Map<String, String>,
        diff: Map<String, String>,
        clientId: String?,
        owner: String?,
    ): PlannedChange {
        val change = trustScopeChange(desired, view)
        fun red(code: String, why: String, fixNote: String? = null) = PlannedChange(
            r.kind, r.name, ChangeAction.ERROR, "$code — $why",
            resource = r, liveId = id, environment = slug, attributes = attributes, diff = diff, error = code, trust = view, fixNote = fixNote,
        )
        change.problem?.let { return red(ProvisionFile.ERR_PLAN_SCOPE_NOT_SUBSET, it) }
        val requested = ((change.body[ProvisionFile.TRUST_SCOPES] as? List<*>).orEmpty() + (change.body[API_PLAN_SCOPES] as? List<*>).orEmpty())
            .map { it.toString() }.distinct()
        val notHeld = callerScopes?.let { held -> requested.filter { it !in held } }.orEmpty()
        if (notHeld.isNotEmpty()) {
            return red(
                ERROR_SCOPE_NOT_GRANTABLE,
                "a trust can carry only tenant: scopes the applying identity itself holds, and this one does not hold ${notHeld.joinToString(", ")}: " +
                    "drop the scope from spec.scopes, or sign in with it first",
            )
        }
        val setScopes = "thoryn workload-identity trusts set-scopes $id${slug?.let { " --environment $it" } ?: ""}"
        if (change.widened && subject?.startsWith("client:") == true) {
            return red(
                ERROR_ELEVATED_ACTION_REQUIRES_PERSON,
                "this file adds ${change.added.joinToString(" ")} to trust '${r.name}', and adding a scope to a trust is a PERSON's act with a fresh passkey sign-in — " +
                    "never a workload identity's: a workspace member runs `$setScopes ${scopeFlags(change)}` (or applies this file signed in as themselves), " +
                    "then this file converges as a no-op. Removing scopes converges from CI.",
                fixNote = "a person's act, not a missing right: a workload identity may narrow a trust's scopes, never widen them",
            )
        }
        val what = buildList {
            if (change.added.isNotEmpty()) add("adds ${change.added.joinToString(" ")}")
            if (change.removed.isNotEmpty()) add("removes ${change.removed.joinToString(" ")}")
        }.joinToString("; ")
        val elevation = if (change.widened) {
            " — adding a scope needs a passkey sign-in from the last 5 minutes (`thoryn login --acr-values $PASSKEY_ACR --max-age $ELEVATED_MAX_AGE_SECONDS`)"
        } else {
            ""
        }
        return PlannedChange(
            r.kind, r.name, ChangeAction.UPDATE,
            "exists — changes its scopes in place ($what); the wi_ workload client ${clientId ?: ""} stays$elevation".replace("  ", " "),
            resource = r, liveId = id, environment = slug, attributes = attributes, diff = diff, trust = view, retain = r.retain, owner = owner,
        )
    }

    /** SSO-3925 — the `set-scopes` flags that make the live trust what the file declares (for the fix line). */
    private fun scopeFlags(change: TrustScopeChange): String = buildList {
        (change.body[ProvisionFile.TRUST_SCOPES] as? List<*>)?.let { add("--scope \"${it.joinToString(" ")}\"") }
        (change.body[API_PLAN_SCOPES] as? List<*>)?.let { add("--plan-scope \"${it.joinToString(" ")}\"") }
    }.joinToString(" ")

    /**
     * SSO-3925 — apply an in-place scope change ([planTrustScopeChange]): `PUT …/{id}/scopes` with only the sets that differ.
     * A step-up refusal (the applying person's sign-in is not a fresh passkey one) and a platform that predates the route each
     * name what to do; nothing else of the trust changes.
     */
    private fun setTrustScopes(r: ProvisionResource, change: PlannedChange, slug: String?, spec: Map<String, Any?>): AppliedResource {
        val id = change.liveId ?: throw ProvisionException("${r.key}: scope update planned without a live id")
        val scopeChange = trustScopeChange(spec, change.trust)
        scopeChange.problem?.let { throw ProvisionException("${r.key}: ${ProvisionFile.ERR_PLAN_SCOPE_NOT_SUBSET} — $it") }
        val resp = try {
            clients(slug).setWorkloadIdentityTrustScopes(id, scopeChange.body)
        } catch (ex: ProductApiException) {
            throw when {
                ex.isStepUpRequired -> ProvisionException(
                    "${r.key}: adding ${scopeChange.added.joinToString(" ")} to trust '${r.name}' needs a passkey sign-in from the last " +
                        "${(ex.stepUpMaxAge ?: ELEVATED_MAX_AGE_SECONDS) / 60} minutes: sign in again with " +
                        "`thoryn login --acr-values ${ex.stepUpAcrValues ?: PASSKEY_ACR} --max-age ${ex.stepUpMaxAge ?: ELEVATED_MAX_AGE_SECONDS}` and re-run (nothing was changed)",
                )
                ex.errorCode == ERROR_ELEVATED_ACTION_REQUIRES_PERSON -> ProvisionException(
                    "${r.key}: $ERROR_ELEVATED_ACTION_REQUIRES_PERSON — adding a scope to trust '${r.name}' is a person's act with a fresh passkey sign-in; " +
                        "a workload identity may only narrow it (nothing was changed)",
                )
                ex.httpStatus in setOf(404, 405) && ex.errorCode != "workload_identity_trust_not_found" -> ProvisionException(
                    "${r.key}: this platform does not change a trust's scopes in place yet — declare what is live (nothing was changed)",
                )
                else -> trustFailure(r, ex)
            }
        }
        trustLists.remove(slug)
        val view = trustView(resp)
        out.println(
            "  ~ workloadIdentityTrust ${r.name}: scopes changed in place (${(scopeChange.added.map { "+$it" } + scopeChange.removed.map { "-$it" }).joinToString(" ")}); " +
                "wi_ client ${view["clientId"] ?: change.trust?.get("clientId") ?: ""} unchanged (id $id)",
        )
        return AppliedResource(r.kind, r.name, id, slug, trustAttributes(view.ifEmpty { change.trust.orEmpty() }), owner = change.owner, action = ChangeAction.UPDATE)
    }

    /** The declared scopes the caller's token does not carry (empty when the host did not say what it carries). */
    private fun scopesNotHeld(spec: Map<String, Any?>): List<String> {
        val held = callerScopes ?: return emptyList()
        return (spec[ProvisionFile.TRUST_SCOPES] as? List<*>).orEmpty().map { it.toString().trim() }.filter { it !in held }
    }

    /** The trust's declared fields as the flat map the live record is compared against (the pins prefixed with their block; an inline JWKS as its kids). */
    private fun trustDesired(spec: Map<String, Any?>): Map<String, Any?> {
        val provider = spec["provider"].toString()
        val out = linkedMapOf<String, Any?>("provider" to provider, ProvisionFile.TRUST_SCOPES to spec[ProvisionFile.TRUST_SCOPES])
        val block = ProvisionFile.TRUST_PIN_BLOCKS[provider] ?: return out
        (spec[block] as? Map<*, *>)?.forEach { (k, v) -> out["$block.$k"] = if (k == "jwks") jwkKids(v) else v }
        // SSO-3702 — the plan profile: its environment always; its scopes only when the file lists them (omitted ⇒ derived
        // by the hub, so whatever the hub derived is not a difference).
        (spec[ProvisionFile.TRUST_PLAN] as? Map<*, *>)?.let { plan ->
            out["${PLAN_FIELD_PREFIX}environment"] = plan["environment"]
            plan[ProvisionFile.TRUST_SCOPES]?.let { out["$PLAN_FIELD_PREFIX${ProvisionFile.TRUST_SCOPES}"] = it }
        }
        return out
    }

    /** The live trust in the same flat shape (GitHub's `owner` + `repository` as the file's `owner/name`; inline keys as their kids). */
    private fun trustLive(n: JsonNode): Map<String, Any?> {
        val provider = n.str("provider")
        val out = linkedMapOf<String, Any?>("provider" to provider, ProvisionFile.TRUST_SCOPES to n["scopes"]?.let { plain(it) })
        fun pins(block: String, fields: List<String>) = n[block]?.takeIf { it.isObject }?.let { b -> fields.forEach { f -> out["$block.$f"] = b[f]?.let { plain(it) } } }
        when (provider) {
            ProvisionFile.PROVIDER_GITHUB_ACTIONS -> {
                pins("github", listOf("ownerId", "repositoryId", "environment", "ref", "githubHostedRunnersOnly"))
                n["github"]?.takeIf { it.isObject }?.let { g -> out["github.repository"] = listOfNotNull(g.str("owner"), g.str("repository")).joinToString("/") }
                // An unpinned runner rule renders as `false`; a file that leaves it out declares nothing about it.
                if (out["github.githubHostedRunnersOnly"] == false) out["github.githubHostedRunnersOnly"] = null
                // SSO-3702 — the live plan profile (`plan: null` on a trust without one — both keys then absent).
                n[ProvisionFile.TRUST_PLAN]?.takeIf { it.isObject }?.let { p ->
                    out["${PLAN_FIELD_PREFIX}environment"] = p.str("environment")
                    out["$PLAN_FIELD_PREFIX${ProvisionFile.TRUST_SCOPES}"] = p["scopes"]?.let { plain(it) }
                }
            }
            ProvisionFile.PROVIDER_FORGEJO -> pins("forgejo", listOf("instanceUrl", "owner", "ownerId", "repository", "repositoryId", "ref"))
            ProvisionFile.PROVIDER_KUBERNETES -> {
                pins("kubernetes", listOf("issuer", "namespace", "serviceAccount"))
                out["kubernetes.jwks"] = n["kubernetes"]?.get("inlineKeyIds")?.takeIf { it.isArray }?.toList()?.map { it.asString() }?.sorted()
            }
        }
        return out
    }

    /** The `kid`s of an inline JWK Set, sorted — the comparable, never-secret form of a public key set. */
    private fun jwkKids(jwks: Any?): List<String> =
        ((jwks as? Map<*, *>)?.get("keys") as? List<*>).orEmpty().mapNotNull { (it as? Map<*, *>)?.get("kid")?.toString() }.sorted()

    /** The live trust as a plan view: never key material, never anything secret (a trust has none). */
    private fun trustView(n: JsonNode): Map<String, Any?> = buildMap {
        listOf("id", "name", "clientId", "audience", "tokenEndpoint", "provider", "environment").forEach { f -> n.str(f)?.let { put(f, it) } }
        n["scopes"]?.takeIf { it.isArray }?.let { put("scopes", it.toList().map { s -> s.asString() }) }
        n["github"]?.takeIf { it.isObject }?.let { g -> put("github", plain(g)) }
        // SSO-3702 — the plan profile and the per-profile subject patterns (apply, plan), as the API renders them.
        n[ProvisionFile.TRUST_PLAN]?.takeIf { it.isObject }?.let { p -> put(ProvisionFile.TRUST_PLAN, plain(p)) }
        n["subjectPatterns"]?.takeIf { it.isArray }?.let { put("subjectPatterns", it.toList().map { s -> s.asString() }) }
        n["kubernetes"]?.takeIf { it.isObject }?.let { k -> put("kubernetes", listOf("issuer", "namespace", "serviceAccount").mapNotNull { f -> k.str(f)?.let { f to it } }.toMap()) }
    }

    /** The attributes of a trust: its `wi_` workload client, its audience and provider (what a reader needs; nothing secret). */
    private fun trustAttributes(view: Map<String, Any?>): Map<String, String> = buildMap {
        view["clientId"]?.toString()?.let { put(ATTR_CLIENT_ID, it) }
        view["audience"]?.toString()?.let { put("audience", it) }
        view["provider"]?.toString()?.let { put("provider", it) }
    }

    /** The `provision.yaml` spec of a live trust (`import`), and a note for what the file cannot carry (inline keys are not rendered by the API). */
    private fun trustSpecOf(n: JsonNode, production: Boolean): Pair<Map<String, Any?>, String?> {
        val provider = n.str("provider") ?: ProvisionFile.PROVIDER_GITHUB_ACTIONS
        val spec = linkedMapOf<String, Any?>("provider" to provider)
        var note: String? = null
        fun copy(block: String, fields: List<String>) = n[block]?.takeIf { it.isObject }?.let { b ->
            val pins = linkedMapOf<String, Any?>()
            fields.forEach { f -> b[f]?.takeIf { !it.isNull }?.let { pins[f] = plain(it) } }
            pins
        }
        when (provider) {
            ProvisionFile.PROVIDER_GITHUB_ACTIONS -> n["github"]?.takeIf { it.isObject }?.let { g ->
                val pins = linkedMapOf<String, Any?>("repository" to listOfNotNull(g.str("owner"), g.str("repository")).joinToString("/"))
                listOf("ownerId", "repositoryId", "environment", "ref").forEach { f -> g[f]?.takeIf { !it.isNull }?.let { pins[f] = plain(it) } }
                if (g["githubHostedRunnersOnly"]?.asBoolean() == true) pins["githubHostedRunnersOnly"] = true
                spec["github"] = pins
                // SSO-3702 — a live plan profile is rendered with its (possibly derived) scopes made explicit, so the file pins what is live.
                n[ProvisionFile.TRUST_PLAN]?.takeIf { it.isObject && it.str("environment") != null }?.let { p ->
                    spec[ProvisionFile.TRUST_PLAN] = linkedMapOf<String, Any?>("environment" to p.str("environment")).also { plan ->
                        p["scopes"]?.takeIf { it.isArray && !it.isEmpty }?.let { plan[ProvisionFile.TRUST_SCOPES] = it.toList().map { s -> s.asString() } }
                    }
                }
            }
            ProvisionFile.PROVIDER_FORGEJO -> copy("forgejo", listOf("instanceUrl", "owner", "ownerId", "repository", "repositoryId", "ref"))?.let { spec["forgejo"] = it }
            ProvisionFile.PROVIDER_KUBERNETES -> copy("kubernetes", listOf("issuer", "namespace", "serviceAccount"))?.let { pins ->
                spec["kubernetes"] = pins
                n["kubernetes"]?.get("inlineKeyIds")?.takeIf { it.isArray && !it.isEmpty }?.let { kids ->
                    note = "pins inline public keys (kid ${kids.toList().joinToString(", ") { it.asString() }}) that the API does not render; add spec.kubernetes.jwks by hand (`kubectl get --raw /openid/v1/jwks`) before a re-create is planned"
                }
            }
        }
        spec[ProvisionFile.TRUST_SCOPES] = n["scopes"]?.takeIf { it.isArray }?.toList()?.map { it.asString() }.orEmpty()
        if (production) spec[ProvisionFile.TRUST_CONFIRM_PRODUCTION] = true
        return spec to note
    }

    /** `POST /api/v1/workload-identity/trusts` body: the file's `repository: owner/name` becomes the API's `owner` + `repository`. */
    private fun trustBody(name: String, spec: Map<String, Any?>): Map<String, Any?> {
        val provider = spec["provider"].toString()
        val block = ProvisionFile.TRUST_PIN_BLOCKS.getValue(provider)
        val pins = (spec[block] as? Map<*, *>).orEmpty().entries.associate { (k, v) -> k.toString() to v }.toMutableMap()
        if (provider == ProvisionFile.PROVIDER_GITHUB_ACTIONS) {
            val repository = pins.remove("repository").toString()
            pins["owner"] = repository.substringBefore('/')
            pins["repository"] = repository.substringAfter('/')
        }
        return linkedMapOf(
            "name" to name, "provider" to provider, block to pins, ProvisionFile.TRUST_SCOPES to spec[ProvisionFile.TRUST_SCOPES],
            ProvisionFile.TRUST_CONFIRM_PRODUCTION to spec[ProvisionFile.TRUST_CONFIRM_PRODUCTION],
            // SSO-3702 — the plan profile rides on the create when declared (absent otherwise; the client drops nulls).
            ProvisionFile.TRUST_PLAN to planProfileBody(spec),
        )
    }

    /** SSO-3702 — the declared plan profile as the API's `{ environment, scopes? }` (scopes only when the file lists them), or null. */
    private fun planProfileBody(spec: Map<String, Any?>): Map<String, Any?>? {
        val plan = spec[ProvisionFile.TRUST_PLAN] as? Map<*, *> ?: return null
        val environment = plan["environment"]?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return linkedMapOf("environment" to environment, ProvisionFile.TRUST_SCOPES to (plan[ProvisionFile.TRUST_SCOPES] as? List<*>)?.map { it.toString().trim() }?.takeIf { it.isNotEmpty() })
    }

    /**
     * SSO-3702 — the ONE additive mutation of a live trust (SSO-3699 decision (b)): `POST …/{id}/plan-profile` with the
     * declared profile. The `wi_` client, its `owner` relation and the consumer's `connection.json` all stay. Only reached for a plan whose diff is the plan profile on a trust
     * without one ([probeTrust]).
     */
    private fun setTrustPlanProfile(r: ProvisionResource, change: PlannedChange, slug: String?, spec: Map<String, Any?>): AppliedResource {
        val id = change.liveId ?: throw ProvisionException("${r.key}: plan-profile update planned without a live id")
        val body = planProfileBody(spec) ?: throw ProvisionException("${r.key}: plan-profile update planned without a declared spec.${ProvisionFile.TRUST_PLAN}")
        val resp = try {
            clients(slug).setWorkloadIdentityTrustPlanProfile(id, body)
        } catch (ex: ProductApiException) {
            throw trustFailure(r, ex)
        }
        trustLists.remove(slug)
        val view = trustView(resp)
        out.println("  ~ workloadIdentityTrust ${r.name}: plan profile added — GitHub environment '${body["environment"]}' is minted read-only scopes ${((view[ProvisionFile.TRUST_PLAN] as? Map<*, *>)?.get("scopes") as? List<*>)?.joinToString(" ") ?: "(derived by the hub)"}; wi_ client ${view["clientId"] ?: change.trust?.get("clientId") ?: ""} unchanged (id $id)")
        return AppliedResource(r.kind, r.name, id, slug, trustAttributes(view.ifEmpty { change.trust.orEmpty() }), owner = change.owner, action = ChangeAction.UPDATE)
    }

    /**
     * Create the trust; a `409 workload_identity_trust_name_taken` (a race with another writer) converges onto the matching
     * trust of that name — exactly as `project init` does — or refuses when it differs. Prints the `wi_` client, the audience
     * and the consumer's `connection.json`; never writes that file (it belongs to the consumer repository).
     */
    private fun createTrust(r: ProvisionResource, file: ProvisionFile, applied: List<AppliedResource>, spec: Map<String, Any?>): AppliedResource {
        val slug = targetSlug(r, file, applied)
        val resp = try {
            clients(slug).createWorkloadIdentityTrust(trustBody(r.name, spec))
        } catch (ex: ProductApiException) {
            if (ex.errorCode == "workload_identity_trust_name_taken") {
                val live = fetchOrNull { trustsOf(slug, fresh = true) }?.firstOrNull { it.str("name") == r.name }
                val diff = live?.let { diffOf(trustDesired(spec), trustLive(it)) }
                if (live != null && diff!!.isEmpty()) {
                    val view = trustView(live)
                    out.println("  = workloadIdentityTrust ${r.name}: the name was taken by a matching trust meanwhile — converged (id ${view["id"]}, clientId ${view["clientId"]})")
                    printTrustConnection(view)
                    return AppliedResource(r.kind, r.name, view["id"].toString(), slug, trustAttributes(view), owner = ProvisionApi.ownerOf(live), action = ChangeAction.NOOP)
                }
                // SSO-3702 — the racing writer created it WITHOUT the declared plan profile: the additive mutation still applies.
                if (live != null && diff!!.keys.all { it.startsWith(PLAN_FIELD_PREFIX) } && live[ProvisionFile.TRUST_PLAN]?.takeIf { it.isObject && it.str("environment") != null } == null) {
                    val view = trustView(live)
                    out.println("  = workloadIdentityTrust ${r.name}: the name was taken by a matching trust meanwhile — converged (id ${view["id"]}, clientId ${view["clientId"]})")
                    val planned = PlannedChange(r.kind, r.name, ChangeAction.UPDATE, "adds the plan profile", resource = r, liveId = view["id"].toString(), diff = diff, trust = view)
                    val result = setTrustPlanProfile(r, planned, slug, spec)
                    printTrustConnection(view)
                    return result
                }
                throw ProvisionException("${r.key}: $ERROR_TRUST_IMMUTABLE — a trust named '${r.name}' already exists in ${planeLabel(slug)} with other pins or scopes; declare what is live and re-apply (a scope change is then planned in place), or delete it and re-apply")
            }
            throw trustFailure(r, ex)
        }
        trustLists.remove(slug)
        val view = trustView(resp)
        val id = view["id"]?.toString() ?: throw ProvisionException("${r.key}: the trust create returned no id")
        out.println("  + workloadIdentityTrust ${r.name}: id=$id clientId=${view["clientId"]} audience=${view["audience"]}${slug?.let { " env=$it" } ?: ""}")
        printTrustConnection(view)
        // SSO-3774 — creator-becomes-owner for a `client:` creator (S1), as the create response reports it.
        return AppliedResource(r.kind, r.name, id, slug, trustAttributes(view), owner = ProvisionApi.ownerOf(resp), action = ChangeAction.CREATE)
    }

    /** The trust service's refusals, each with what to do next (the same guidance `thoryn workload-identity trusts create` gives). */
    private fun trustFailure(r: ProvisionResource, ex: ProductApiException): ProvisionException = ProvisionException(
        "${r.key}: ${ex.errorCode ?: "the workload-identity API refused the request"} — " + when (ex.errorCode) {
            ERROR_SCOPE_NOT_GRANTABLE -> "a trust can carry only tenant: scopes the applying identity itself holds (${ex.errorDescription ?: "scope ceiling"}); drop the scope from spec.scopes, or sign in with it (grant the CI identity that scope) first"
            ProvisionFile.ERR_INVALID_SCOPE -> "a trust can carry only workspace (tenant:) scopes"
            ProvisionFile.ERR_PRODUCTION_CONFIRMATION_REQUIRED -> "this is the production plane: jobs / pods using the trust act on production; declare spec.confirmProduction: true"
            ProvisionFile.ERR_PRODUCTION_REQUIRES_ENVIRONMENT -> "a production GitHub trust must pin a GitHub environment (spec.github.environment)"
            ProvisionFile.ERR_PRODUCTION_REQUIRES_REF -> "a production Forgejo trust must pin a ref (spec.forgejo.ref)"
            ProvisionFile.ERR_PRODUCTION_REQUIRES_SERVICE_ACCOUNT -> "a production Kubernetes trust must pin spec.kubernetes.namespace and spec.kubernetes.serviceAccount"
            "github_repository_not_found" -> "GitHub has no public repository by that name; for a private repository declare spec.github.ownerId and spec.github.repositoryId"
            "github_unavailable" -> "GitHub could not be reached to look up the repository ids; retry, or declare spec.github.ownerId and spec.github.repositoryId"
            ProvisionFile.ERR_INVALID_GITHUB_IDS -> "spec.github.ownerId and spec.github.repositoryId go together: declare both, or neither"
            "environment_not_found" -> "no such environment, or this identity cannot reach it"
            // SSO-3702 — the plan profile's refusals (product-api SSO-3701 / hub SSO-3700).
            "plan_profile_already_set" -> "the live trust already carries a plan profile; a profile is set once — declare what is live, or re-create the trust (delete and re-apply; a new wi_ client)"
            ProvisionFile.ERR_PLAN_ENVIRONMENT_EQUALS_APPLY -> "spec.plan.environment must differ from spec.github.environment — the GitHub environment is what separates \"may read\" from \"may write\""
            ProvisionFile.ERR_PLAN_SCOPE_NOT_READ_ONLY -> "every spec.plan.scopes entry must be a tenant:<area>.read scope — a plan profile is read-only by construction"
            ProvisionFile.ERR_PLAN_SCOPE_NOT_SUBSET -> "every spec.plan.scopes entry must be among spec.scopes"
            ProvisionFile.ERR_PLAN_PROFILE_REQUIRES_ENVIRONMENT -> "spec.plan.environment is required (the GitHub environment the plan jobs run in)"
            ProvisionFile.ERR_PLAN_SCOPES_EMPTY -> "the plan profile would carry no scope: spec.scopes has no .read member to derive from — list spec.plan.scopes, or add a .read scope"
            ProvisionFile.ERR_PLAN_PROFILE_UNSUPPORTED -> "only a github_actions trust carries a plan profile"
            ProvisionFile.ERR_INVALID_PLAN_ENVIRONMENT -> "spec.plan.environment must be a GitHub environment name, exactly as the plan job declares it"
            else -> if (ex.isInsufficientScope) "this session lacks the '$SCOPE_TRUST_WRITE' scope (${ex.message}); sign in with `thoryn login --scope $SCOPE_TRUST_WRITE` (or grant the CI identity that scope) and re-run" else (ex.errorDescription ?: ex.message ?: "refused")
        },
    )

    /**
     * Print the consumer's `connection.json` for a trust `apply` created or converged onto (ADR 2026-09-09 connection
     * contract) — NEVER written by apply: it belongs to the repository / workload that signs in with the trust.
     */
    private fun printTrustConnection(view: Map<String, Any?>) {
        out.println("    connection.json for the workload that signs in with this trust — not written by apply (it belongs to the consumer repository):")
        json.writerWithDefaultPrettyPrinter().writeValueAsString(connectionDocument(view, applyWorkspace)).lines().forEach { out.println("      $it") }
        if (view["provider"] == ProvisionFile.PROVIDER_FORGEJO) {
            out.println("    (the connection contract knows github_actions and kubernetes today; a forgejo job presents its own Actions token as the client_assertion — `provider` is left out so the document validates.)")
        }
    }

    // ── secret-less clients (SSO-3689): the application's `federatedTrust` NAME → id, inline `jwks` → the API's string ──

    /**
     * How a declared `federatedTrust` name resolved: to a live [id], to a trust this apply creates first ([pending]), or to an
     * [error] — with [fix] when the error is a missing RIGHT (SSO-3774: a trust this file declares that the identity cannot see).
     */
    private class TrustRef(val name: String, val id: String?, val pending: Boolean, val error: String?, val fix: FixRequest.MissingRight? = null)

    /**
     * Resolve `spec.federatedTrust` (a NAME) in the application's OWN plane: a trust of that name declared in this file
     * for another environment is refused (a login client binds a trust of its own environment — the hub checks the
     * same); a live trust gives its id; one declared here but not live yet is pending at plan time (created first by
     * `apply`); anything else is `federated_trust_not_found`.
     *
     * SSO-3774 (oauthy ADR 2026-10-16 §4) — on a platform that filters the trust list by reach (S1), "not live" may be
     * "not visible". A trust declared HERE whose own row is red while this identity cannot read its whole plane
     * ([trustsHidden]) is therefore `access_not_reachable`, its fix `owner` on the trust by NAME in its plane (the consent
     * page resolves the name to the id as the admin) — never the misleading "not found". A declared trust whose row is red
     * for another reason will not be created by this apply, and says so.
     */
    private fun federatedTrustRef(r: ProvisionResource, file: ProvisionFile?, slug: String?, atApply: Boolean): TrustRef? {
        val name = r.spec[ProvisionFile.SPEC_FEDERATED_TRUST]?.toString()?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val declared = file?.resources?.firstOrNull { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST && it.name == name }
        if (declared != null && declared.environment != r.environment) {
            return TrustRef(name, null, false, "trust '$name' is declared in this file for ${declared.environment?.let { "environment '$it'" } ?: "the production plane"} while the application lives in ${r.environment?.let { "environment '$it'" } ?: "the production plane"} — a login client binds a trust of its OWN environment")
        }
        val live = try {
            fetchOrNull { trustsOf(slug, fresh = atApply) }?.firstOrNull { it.str("name") == name }
        } catch (ex: ProductApiException) {
            MissingScopeException.of(ex, ScopeRequirements.SCOPE_WORKLOAD_IDENTITY_READ, ScopeRequirements.Phase.PLAN, r.key, "list the trusts of ${planeLabel(slug)} to resolve spec.federatedTrust '$name'")?.let { throw it }
            throw ProvisionException("${r.key}: could not list the trusts of ${planeLabel(slug)} to resolve spec.federatedTrust '$name' (${ex.message})")
        }
        val verdict = trustVerdicts[name]
        return when {
            live != null -> TrustRef(name, live.str("id"), false, null)
            declared != null && !atApply && (verdict == null || verdict.action != ChangeAction.ERROR) -> TrustRef(name, null, true, null)
            declared != null && !atApply && name in trustsHidden -> {
                val why = "trust '$name' is declared in this file for ${planeLabel(slug)} but is not visible to this identity — it holds no relation on it " +
                    "(the platform lists a trust only to who reaches it), so ${r.key} cannot resolve spec.${ProvisionFile.SPEC_FEDERATED_TRUST}"
                TrustRef(name, null, false, why, fix = FixRequest.byName(FixRequest.Kind.OWNER, subject, name, slug, why))
            }
            declared != null && !atApply -> TrustRef(name, null, false, "trust '$name' is declared in this file but its own row is red (${verdict?.error}) — it will not be created by this apply, so the client cannot be bound to it")
            else -> TrustRef(name, null, false, "no workloadIdentityTrust named '$name' in ${planeLabel(slug)} is visible to this identity — declare it in this file (same environment) or create it first " +
                "(the trust must exist before the client is written); a trust another identity owns is listed only to who holds a relation on it")
        }
    }

    /**
     * SSO-3766 / SSO-3767 / SSO-3770 — product-api's refusals of the application settings, each with what to do next; null
     * for any other failure (it keeps its own rendering). Without this a `403 token_exchange_not_grantable` would read as a
     * missing SCOPE (every 403 does, [ProductApiException.isInsufficientScope]) and send the reader to `thoryn login --scope`.
     * The one refusal a RIGHT fixes — `token_exchange_not_grantable`, which the plan gate predicts but a race or an older
     * reach answer can still meet — ends with the same "To fix" block a red plan prints; the others are file edits.
     */
    private fun applicationSettingFailure(r: ProvisionResource, ex: ProductApiException, slug: String?): ProvisionException? {
        val extension = { name: String -> problemExtension(ex, name) }
        val detail = ex.errorDescription?.takeIf { it.isNotBlank() && it != ex.errorCode }?.let { " (the API said: $it)" } ?: ""
        val head = "${r.key}: ${ex.errorCode} — "
        val message = when (ex.errorCode) {
            ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE -> {
                val parent = runCatching { planeParentRef(slug, Reach()) }.getOrElse { "$OBJECT_TYPE_WORKSPACE:${workspaceId ?: "(this workspace)"}" }
                val why = "turning ${ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE} on requires `manager` on the application's environment $parent " +
                    "(the reach that may create an application there); managing the application alone is not enough"
                val toFix = if (parent.startsWith("$OBJECT_TYPE_WORKSPACE:")) {
                    FixRequest.render(emptyList(), listOf("${r.kind} ${r.name}: $TOKEN_EXCHANGE_WORKSPACE_NOTE"))
                } else {
                    FixRequest.render(listOf(FixRequest.manager(subject, parent, "${ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE} — $why")))
                }
                "$why.\n$toFix"
            }
            ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE -> {
                val parent = runCatching { planeParentRef(slug, Reach()) }.getOrElse { "$OBJECT_TYPE_WORKSPACE:${workspaceId ?: "(this workspace)"}" }
                val why = "turning ${ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION} on requires `manager` on the application's environment $parent " +
                    "(the reach that may create an application there); managing the application alone is not enough"
                val toFix = if (parent.startsWith("$OBJECT_TYPE_WORKSPACE:")) {
                    FixRequest.render(emptyList(), listOf("${r.kind} ${r.name}: $TOKEN_INTROSPECTION_WORKSPACE_NOTE"))
                } else {
                    FixRequest.render(listOf(FixRequest.manager(subject, parent, "${ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE} — $why")))
                }
                "$why.\n$toFix"
            }
            ProvisionFile.ERR_TOKEN_INTROSPECTION_REQUIRES_CONFIDENTIAL_CLIENT ->
                "${ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION}: true needs a client that authenticates (a secret, private_key_jwt or federated_assertion); " +
                    "a public client cannot hold it, and a client that holds it cannot be made public — fix spec.clientType / spec.clientAuthenticationMethods, or drop the setting$detail"
            ProvisionFile.ERR_INVALID_ACCESS_TOKEN_FORMAT ->
                "spec.${ProvisionFile.SPEC_ACCESS_TOKEN_FORMAT} must be ${ProvisionFile.ACCESS_TOKEN_FORMATS.joinToString(" or ") { "'$it'" }}$detail"
            ProvisionFile.ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT ->
                "${ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE}: true needs a client that authenticates (a secret, private_key_jwt or federated_assertion); " +
                    "a public client cannot hold it, and a client that holds it cannot be made public — fix spec.clientType / spec.clientAuthenticationMethods, or drop the setting$detail"
            ProvisionFile.ERR_TOKEN_EXCHANGE_GRANT_REQUIRED ->
                "${ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE}: true needs '${ProvisionFile.GRANT_TOKEN_EXCHANGE}' among the application's grant types — add it to spec.grantTypes$detail"
            ProvisionFile.ERR_UNSUPPORTED_AUTHORIZATION_DETAILS_TYPE ->
                "an entry of spec.${ProvisionFile.SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES} is not a type the authorization server supports (its discovery " +
                    "document's authorization_details_types_supported, plus ${ProvisionFile.AUTHORIZATION_DETAILS_TYPE_ACCESS_GRANT}) — check the spelling, one type per entry$detail"
            ProvisionFile.ERR_AUTHORIZATION_DETAILS_TYPE_NOT_PERMITTED ->
                "'${ProvisionFile.AUTHORIZATION_DETAILS_TYPE_ACCESS_GRANT}' may be declared only for applications of the platform home workspace (thoryn) — " +
                    "remove it from spec.${ProvisionFile.SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES}; no grant changes this"
            ProvisionFile.ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW ->
                "spec.${ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS} applies only with ${ProvisionFile.SPEC_REFRESH_TOKEN_SLIDING_WINDOW}: true — declare the window with it$detail"
            ProvisionFile.ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL ->
                "spec.${ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS} is shorter than the application's refresh-token TTL (refreshTokenTtlSeconds, after this change): " +
                    "the first refresh token would outlive the session — raise the absolute lifetime or lower the TTL$detail"
            ProvisionFile.ERR_TOKEN_TTL_OUT_OF_RANGE -> {
                val field = extension("field") ?: "a token lifetime"
                val bounds = listOfNotNull(extension("min"), extension("max")).takeIf { it.size == 2 }?.joinToString(" – ")?.let { " ($it seconds)" } ?: ""
                "spec.$field is outside the platform bounds$bounds$detail"
            }
            ProvisionFile.ERR_SESSION_EXCEEDS_TENANT_POLICY -> {
                val max = extension("max")?.let { " of $it seconds" } ?: ""
                "spec.${ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS} (or the 90-day default the sliding window turns on) is longer than the environment's " +
                    "refresh-token lifetime cap$max (refreshClipSeconds of its authentication policy) — lower it to the cap or below, or raise the policy cap"
            }
            else -> return null
        }
        return ProvisionException(head + message)
    }

    /**
     * SSO-3792 (oauthy ADR 2026-10-17 §3) — what product-api's refusal of a create under a creation slot means, or null to
     * fall through to the ordinary mapping:
     *  - `404`: the slot no longer admits this create — consumed by an earlier apply, released or revoked by an admin,
     *    expired since the plan, or reserved for another plane; nothing was created. Re-plan; an admin reserves again.
     *  - `409 client_id_taken`: the name exists (someone created it since the reservation); the slot is used up and a slot
     *    never adopts a live application — the right that fits now is `owner` on it.
     *  - `403 token_exchange_not_grantable` / `403 token_introspection_not_grantable`: a slot never includes turning token
     *    exchange or token introspection on (the plan refuses both first).
     */
    private fun reservedCreateFailure(r: ProvisionResource, ex: ProductApiException, slot: CreationSlot): ProvisionException? {
        val ref = FixRequest.applicationRef(slot.clientId)
        val reserve = FixRequest.reserveCommand(subject, slot.clientId, slot.environment)
        val message = when {
            ex.httpStatus == 404 ->
                "${r.key}: the creation slot for $ref in ${slot.environment} no longer admits this create (HTTP 404) — it was used by an earlier apply, " +
                    "released or revoked by a workspace admin, expired since the plan, or reserved for another plane; nothing was created. Re-run the plan: " +
                    "it shows what is live now. A workspace admin approves the creation again with `$reserve`."
            ex.httpStatus == 409 && ex.errorCode == "client_id_taken" ->
                "${r.key}: ${slot.clientId} already exists (HTTP 409 client_id_taken) — it was created after the reservation, so the creation slot is used up and " +
                    "was not applied to it (a creation approval never adopts a live application). If this repository is to own it, a workspace admin grants it: " +
                    "`${FixRequest.grantCommand(subject, RELATION_OWNER, ref)}`; otherwise declare it `readOnly: true` or pick another clientId."
            else -> {
                val (field, code, _) = SLOT_EXCLUDED_SETTINGS.firstOrNull { it.second == ex.errorCode } ?: return null
                "${r.key}: $code — a creation slot does not include turning $field on " +
                    "(that needs `manager` on the plane); nothing was created and the slot is kept. Drop `$field: true` from the file, " +
                    "or have a workspace admin apply it from their own session."
            }
        }
        return ProvisionException(message)
    }

    /** A member of an RFC 9457 problem body (`field`, `min`, `max`, …), as text; null when absent or unparseable. */
    private fun problemExtension(ex: ProductApiException, name: String): String? = runCatching {
        json.readTree(ex.rawBody)[name]?.takeIf { it.isNumber || it.isTextual }?.asString()?.takeIf { it.isNotBlank() }
    }.getOrNull()

    /** The application body the API takes: `federatedTrust` as the trust id, an inline `jwks` as its JSON text. */
    private fun applicationBody(r: ProvisionResource, spec: Map<String, Any?>, slug: String?): Map<String, Any?> {
        // SSO-3941 — `tokenClaims` is not an application field: it is converged through `…/token-claims` ([convergeTokenClaims]).
        val body = LinkedHashMap(spec - ProvisionFile.SPEC_TOKEN_CLAIMS)
        if (spec.containsKey(ProvisionFile.SPEC_FEDERATED_TRUST)) {
            // At apply the trust must be LIVE (this apply created it first, or it existed): the file is not consulted again.
            val ref = federatedTrustRef(r, file = null, slug = slug, atApply = true)
            body[ProvisionFile.SPEC_FEDERATED_TRUST] = ref?.id ?: throw ProvisionException("${r.key}: $ERROR_FEDERATED_TRUST_NOT_FOUND — ${ref?.error ?: "spec.federatedTrust could not be resolved"}")
        }
        (spec[ProvisionFile.SPEC_JWKS] as? Map<*, *>)?.let { body[ProvisionFile.SPEC_JWKS] = json.writeValueAsString(it) }
        return body
    }

    /** The attributes of an application a reader needs next to its id: its first redirect URI — never a key. */
    private fun applicationAttributes(spec: Map<String, Any?>): Map<String, String> = buildMap {
        (spec["redirectUris"] as? List<*>)?.firstOrNull()?.toString()?.let { put("redirectUri", it) }
    }

    // ── roles and claims in the token (SSO-3941) ─────────────────────────────────────────────────

    /** The role create: `POST /api/v1/roles {name, description}`, then its permission set (missing permissions are created). */
    private fun createRole(r: ProvisionResource, slug: String?, spec: Map<String, Any?>): AppliedResource {
        val client = clients(slug)
        val body = linkedMapOf<String, Any?>("name" to r.name)
        spec[ProvisionFile.ROLE_DESCRIPTION]?.let { body[ProvisionFile.ROLE_DESCRIPTION] = it.toString() }
        val resp = client.createRole(body)
        val id = resp.str("id") ?: throw ProvisionException("${r.key}: the role create returned no id")
        val permissions = rolePermissions(spec)
        if (permissions.isNotEmpty()) client.setRolePermissions(id, permissionIds(r, client, permissions))
        out.println("  + role ${r.name}: id=$id${slug?.let { " env=$it" } ?: ""} permissions=${permissions.joinToString(",", "[", "]")}")
        return AppliedResource(r.kind, r.name, id, slug, action = ChangeAction.CREATE)
    }

    /** A role's declared permission names, trimmed and de-duplicated (the loader refuses blanks and reserved names). */
    private fun rolePermissions(spec: Map<String, Any?>): List<String> =
        (spec[ProvisionFile.ROLE_PERMISSIONS] as? List<*>).orEmpty().mapNotNull { it?.toString()?.trim()?.takeIf { p -> p.isNotEmpty() } }.distinct()

    /**
     * The ids of the workspace permissions named [names], in their order, creating each one the workspace does not have yet
     * (`POST /api/v1/permissions`; permissions are workspace-wide, so one created here exists in every environment). A
     * concurrent create of the same name (`409 permission_exists`) is read back, never a failure.
     */
    private fun permissionIds(r: ProvisionResource, client: ProvisionApi, names: List<String>): List<String> {
        if (names.isEmpty()) return emptyList()
        fun known(): Map<String, String> = allPages { cursor -> client.listPermissions(null, cursor) }
            .mapNotNull { n -> n.str("name")?.let { name -> n.str("id")?.let { id -> name to id } } }.toMap()
        var byName = known()
        names.filter { it !in byName }.forEach { name ->
            val id = try {
                client.createPermission(mapOf("name" to name)).str("id")
            } catch (ex: ProductApiException) {
                if (ex.httpStatus != 409) throw ex
                byName = known()
                byName[name]
            } ?: throw ProvisionException("${r.key}: permission '$name' could not be created or read back")
            byName = byName + (name to id)
            out.println("  + permission $name: id=$id (workspace-wide)")
        }
        return names.map { byName.getValue(it) }
    }

    /**
     * What the file declares for an application's claims in the token, or null when it declares nothing (the live toggle is
     * left as it is). SSO-3945 — [roleMapping] is part of the configuration: `null` means NO mapping (every role name is
     * emitted as-is), which is what product-api stores for a PUT without one, because PUT replaces the whole configuration.
     */
    private data class TokenClaims(val enabled: Boolean, val sources: List<String>, val roleMapping: Map<String, String>? = null) {
        fun render(): String = if (enabled) "sources ${sources.joinToString(",", "[", "]")}${roleMapping?.let { " roleMapping ${renderMapping(it)}" } ?: ""}" else "off"
    }

    private fun desiredTokenClaims(spec: Map<String, Any?>): TokenClaims? {
        val declared = spec[ProvisionFile.SPEC_TOKEN_CLAIMS] as? Map<*, *> ?: return null
        val enabled = declared[ProvisionFile.TOKEN_CLAIMS_ENABLED]?.let { coerceBool(it) } ?: true
        val sources = (declared[ProvisionFile.TOKEN_CLAIMS_SOURCES] as? List<*>)?.mapNotNull { it?.toString()?.trim() }?.distinct()
            ?: ProvisionFile.DEFAULT_TOKEN_CLAIM_SOURCES
        // Keys and values exactly as written (the file refuses a non-string value): product-api does not trim them either.
        val roleMapping = (declared[ProvisionFile.TOKEN_CLAIMS_ROLE_MAPPING] as? Map<*, *>)
            ?.entries?.associate { (k, v) -> k.toString() to v.toString() }
        return if (enabled) TokenClaims(true, sources, roleMapping) else TokenClaims(false, emptyList())
    }

    /**
     * The `tokenClaims` diff entry when the live configuration differs from [want], else nothing. The sources are compared as a
     * SET and the role mapping as a MAP — a noop only when both match. With claims on at both ends the entry names only what
     * changes: `sources [a] → sources [b]` and/or the mapping entries added (`+ role: value`), removed (`- role: value`) and
     * changed (`~ role: old → new`). A live mapping the file does not declare is spelled out as a removal, because the PUT
     * that converges the sources stores no mapping.
     */
    private fun tokenClaimsDiff(client: ProvisionApi, clientId: String, want: TokenClaims): Map<String, String> {
        val n = client.getApplicationTokenClaims(clientId)
        val liveEnabled = n["enabled"]?.takeIf { it.isBoolean }?.asBoolean() ?: false
        val live = if (liveEnabled) {
            TokenClaims(true, listItems(n["sources"] ?: n, "sources").map { it.asString() }, liveRoleMapping(n))
        } else {
            TokenClaims(false, emptyList())
        }
        if (!want.enabled) return if (live.enabled) mapOf(ProvisionFile.SPEC_TOKEN_CLAIMS to "${live.render()} → off") else emptyMap()
        if (!live.enabled) return mapOf(ProvisionFile.SPEC_TOKEN_CLAIMS to "off → ${want.render()}")
        val parts = buildList {
            if (live.sources.toSet() != want.sources.toSet()) {
                add("sources ${live.sources.joinToString(",", "[", "]")} → sources ${want.sources.joinToString(",", "[", "]")}")
            }
            roleMappingDiff(live.roleMapping, want.roleMapping)?.let { add(it) }
        }
        return if (parts.isEmpty()) emptyMap() else mapOf(ProvisionFile.SPEC_TOKEN_CLAIMS to parts.joinToString("; "))
    }

    /** The live `roleMapping` (`null` / absent ⇒ none — also what a product-api older than SSO-3943 answers). */
    private fun liveRoleMapping(n: JsonNode): Map<String, String>? =
        n[ProvisionFile.TOKEN_CLAIMS_ROLE_MAPPING]?.takeIf { it.isObject }?.properties()?.associate { (k, v) -> k to v.asString() }

    /** SSO-3945 — a readable, per-entry rendering of how the role mapping changes, or null when it does not. */
    private fun roleMappingDiff(live: Map<String, String>?, want: Map<String, String>?): String? {
        if (live == want) return null
        if (want == null) {
            return "roleMapping removed — the file declares none and the PUT replaces the whole configuration: " +
                (live.orEmpty().toSortedMap().entries.joinToString(", ") { (k, v) -> "- $k: $v" }.ifEmpty { "{}" })
        }
        if (live == null && want.isEmpty()) return "roleMapping none → {} (an empty mapping lets no role through)"
        val before = live.orEmpty()
        val entries = (before.keys + want.keys).toSortedSet().mapNotNull { k ->
            val old = before[k]
            val new = want[k]
            when {
                old == null -> "+ $k: $new"
                new == null -> "- $k: $old"
                old != new -> "~ $k: $old → $new"
                else -> null
            }
        }
        return "roleMapping ${entries.joinToString(", ")}"
    }

    /**
     * `PUT …/token-claims {sources, roleMapping}` to switch it on with exactly [want]'s configuration, or `DELETE …/token-claims`
     * to switch it off. SSO-3945: EVERY PUT carries the role mapping (`null` when the file declares none) — PUT replaces the
     * whole configuration, so a PUT of the sources alone would erase a live mapping the file declares.
     */
    private fun convergeTokenClaims(r: ProvisionResource, slug: String?, clientId: String, want: TokenClaims) {
        val client = clients(slug)
        try {
            if (want.enabled) client.putApplicationTokenClaims(clientId, want.sources, want.roleMapping) else client.deleteApplicationTokenClaims(clientId)
        } catch (ex: ProductApiException) {
            // The source names and the mapping are product-api's to judge (`400 unsupported_claim_source` /
            // `invalid_role_mapping`): name the field, keep the server's words.
            if (ex.httpStatus != 400) throw ex
            throw ProvisionException("${r.key}: spec.${ProvisionFile.SPEC_TOKEN_CLAIMS} refused by the platform — ${ex.errorCode ?: "HTTP 400"}${ex.errorDescription?.let { ": $it" } ?: ""} (the application itself is converged)")
        }
        out.println("  ~ application ${r.name}: claims in the token ${want.render()} (clientId $clientId)")
    }

    /** Every item of a cursor-paginated ListEnvelope (`{ data, pagination: { cursor, hasMore } }`), page by page. */
    private fun allPages(fetch: (cursor: String?) -> JsonNode): List<JsonNode> {
        val items = mutableListOf<JsonNode>()
        var cursor: String? = null
        for (page in 0 until MAX_LIST_PAGES) {
            val body = fetch(cursor)
            items += listItems(body, "data")
            cursor = body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }
            if (cursor == null || body["pagination"]?.get("hasMore")?.asBoolean(true) == false) break
        }
        return items
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    /**
     * Environments first (file order), then (SSO-3689) workload-identity trusts — an application's `federatedTrust`
     * names one, so it must exist before the client is written — then everything else (file order).
     */
    private fun orderForApply(resources: List<ProvisionResource>): List<ProvisionResource> =
        resources.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT } +
            resources.filter { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST } +
            resources.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT && it.kind != ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }

    /** Child-first: everything in reverse order, then the trusts the clients were bound to, environments last (their hard-delete cascades). */
    private fun orderForRemove(rows: List<PlannedChange>): List<PlannedChange> =
        rows.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT && it.kind != ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }.reversed() +
            rows.filter { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }.reversed() +
            rows.filter { it.kind == ProvisionFile.KIND_ENVIRONMENT }.reversed()

    /** The slug a resource targets: an env resource of this file (converged earlier in this apply), an existing slug, or null. */
    private fun targetSlug(r: ProvisionResource, file: ProvisionFile, applied: List<AppliedResource>): String? {
        val ref = r.environment ?: return null
        if (file.environmentResource(ref) == null) return ref
        return applied.firstOrNull { it.kind == ProvisionFile.KIND_ENVIRONMENT && it.name == ref }?.attributes?.get("slug")
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
    /** SSO-3856 — a live scope list without its operator-plane (`platform:` / `admin:`) members; anything else unchanged. */
    private fun withoutOperatorPlaneScopes(value: Any?): Any? =
        (value as? List<*>)?.filterNot { it != null && ProvisionFile.isReservedOperatorPlaneScope(it.toString()) } ?: value

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
    private fun <T> fetchOrNull(call: () -> T): T? = try {
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

        /** SSO-3413 — the customDomain id when the session carries no `tnt` (grants then cannot name it). */
        const val CUSTOM_DOMAIN_FALLBACK_ID = "custom-domain"

        // ── SSO-3659 — the ownership gate's vocabulary (ADR 2026-10-13 §1) ──

        /** The resource may only be viewed (or is declared `readOnly`) and the file would change it. */
        /** SSO-4042 — product-api's answer for a (type, locale) cell with no override: the API's "absent", never a missing right. */
        const val ERROR_TEMPLATE_NOT_CUSTOMIZED = "template_not_customized"
        /** SSO-4057 — the declared `spec.version` of a legal document is published with other content: a published version never changes. */
        const val ERROR_LEGAL_DOCUMENT_VERSION_IMMUTABLE = "legal_document_version_immutable"
        /** SSO-4057 — the fix request's note for that row: the FILE must change. */
        const val FILE_FIX_NOTE_LEGAL_DOCUMENT_VERSION = "a change to the file, not a missing right: give the changed legal document a new spec.version (or declare the stored text again)"
        /** SSO-4057 — the plan attribute that tells [update] to re-activate the stored version instead of publishing one. */
        const val ATTR_REACTIVATE = "reactivate"
        const val ERROR_READ_ONLY = "access_read_only"
        /**
         * SSO-3715 (ADR 2026-10-15 §5) — two or more live resources match the declared converge key (an application's
         * `displayName` within its environment, a federation member's `displayName`): red, never a create of a third.
         */
        const val ERROR_CONVERGE_KEY_AMBIGUOUS = "converge_key_ambiguous"
        /** SSO-3715 — the fix request's note for a `converge_key_ambiguous` row: the FILE must say which one (`clientId`). */
        /** SSO-3921 — the fix request's note for a refused `workloadPull` sink: the FILE (or the trust it names) must change. */
        const val WORKLOAD_PULL_FILE_FIX_NOTE = "a change to the file, not a missing right: secretSink.trust must name a kubernetes workloadIdentityTrust of the application's own environment that carries tenant:applications.write"
        const val FILE_FIX_NOTE_AMBIGUOUS = "a change to the file, not a missing right: declare `clientId` so the converge key names exactly one live resource"
        /** SSO-3715 — the destroy / prune plan's reason for a `retain: true` resource. */
        const val RETAINED = "retained by the file (`retain: true`) — never removed by destroy / --prune"
        /**
         * SSO-3715 — the kinds whose removal follows the generic owner rule ([mayRemove]); every other kind is removed with its
         * sandbox or by hand. SSO-3774: a trust is ownable on the platform too, but keeps its own rule (owner ⇒ removed by its
         * `client:` owner; a person's destroy never removes a production trust) — so it is deliberately not listed here.
         */
        val OWNABLE_KINDS: Set<String> = setOf(ProvisionFile.KIND_APPLICATION, ProvisionFile.KIND_ENVIRONMENT)
        /** No relation on the resource, or no `manager` on the parent a create needs. */
        const val ERROR_NOT_OWNED = "access_not_owned"
        /**
         * SSO-3722 — the live read of the resource answered 404: the plane is not reachable by this identity at all
         * (product-api's 404-not-403 rule, SSO-3118) — a right to grant, never "could not read live state".
         */
        const val ERROR_NOT_REACHABLE = "access_not_reachable"
        /**
         * SSO-3673 — the PLATFORM says another identity owns the resource: its response renders an `owner` and
         * `POST /api/v1/access/check {object, relation: owner}` is false for this one. Declare it `readOnly: true`.
         */
        const val ERROR_OWNED_ELSEWHERE = "access_owned_elsewhere"

        /**
         * SSO-3710 — the fix request's note for an `ERROR` row no right would fix: the FILE must change (a read-only
         * reference that differs from what is live, a reference to something that does not exist).
         */
        const val FILE_FIX_NOTE = "a change to the file, not a missing right: a read-only reference must match what is live and is never created"
        /**
         * SSO-3710 — the note for a create (or a trust) whose parent is the WORKSPACE: `manager` on the workspace is never a
         * consentable right (ADR 2026-10-15 §3) — a confined repository identity must not manage the workspace; a workspace
         * admin creates the production-plane resource and grants this identity `owner` on it, or the file declares it `readOnly`.
         */
        /**
         * SSO-3767 — why a production-plane `token_exchange_not_grantable` has no item: the right that fixes it is `manager` on
         * the WORKSPACE, which a repository identity is never granted. A person with that standing applies the file instead.
         */
        const val TOKEN_EXCHANGE_WORKSPACE_NOTE = "not a grantable right: turning token exchange on for a production-plane application needs `manager` on the " +
            "workspace, which is never granted to a repository identity — a workspace admin applies this file from their own session " +
            "(or drop `allowTokenExchange: true` from the file)"

        /**
         * SSO-3792 (oauthy ADR 2026-10-17 §6) — appended to [WORKSPACE_PARENT_NOTE] for a production-plane APPLICATION
         * without a fixed id: a creation slot names exactly one client id, so an auto-generated one can never be approved.
         */
        const val DECLARE_CLIENT_ID_NOTE = "declare `spec.clientId` to make its creation approvable (a workspace admin then reserves that one name for this identity)"

        /** SSO-3810 — why a production-plane `token_introspection_not_grantable` has no item (as [TOKEN_EXCHANGE_WORKSPACE_NOTE]). */
        const val TOKEN_INTROSPECTION_WORKSPACE_NOTE = "not a grantable right: turning token introspection on for a production-plane application needs `manager` " +
            "on the workspace, which is never granted to a repository identity — a workspace admin applies this file from their own session " +
            "(or drop `allowTokenIntrospection: true` from the file)"

        /**
         * SSO-3792 (oauthy ADR 2026-10-17 §3) — the parent-manager-gated settings a creation slot does NOT lift, each with
         * product-api's refusal code and the production-plane note: `allowTokenExchange` (SSO-3758) and
         * `allowTokenIntrospection` (SSO-3810, gated at a slot create by product-api's `introspectionGate`).
         */
        private val SLOT_EXCLUDED_SETTINGS: List<Triple<String, String, String>> = listOf(
            Triple(ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE, ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE, TOKEN_EXCHANGE_WORKSPACE_NOTE),
            Triple(ProvisionFile.SPEC_ALLOW_TOKEN_INTROSPECTION, ProvisionFile.ERR_TOKEN_INTROSPECTION_NOT_GRANTABLE, TOKEN_INTROSPECTION_WORKSPACE_NOTE),
        )

        const val WORKSPACE_PARENT_NOTE = "not a grantable right: `manager` on the workspace is never granted to a repository identity — a workspace admin creates it, then grants this identity `owner` on it (or declare it `readOnly: true`)"

        /**
         * SSO-3668 — an output's `publishTo:` target could not be reached by the signed-in credential; raised
         * AFTER convergence (the resource exists and its id is in the apply output), never a refusal before it.
         */
        const val ERROR_PUBLISH_UNREACHABLE = "publish_target_unreachable"

        /**
         * SSO-3659 (ADR 2026-10-13 §5) — a minted client secret reached neither its declared `secretSink:` nor the
         * host's generic channel. Reported AFTER the client is converged; the recovery is [recoverSecret].
         */
        const val ERROR_UNDELIVERED_SECRETS = "undelivered_secrets"

        /** The one command a human runs for a client whose secret was not delivered (ADR production-clients §3 tier 3). */
        fun recoverSecret(clientId: String): String = "thoryn clients rotate-secret $clientId --secret-file <path>"

        // ── SSO-3689 — workload-identity trusts and secret-less clients ──

        /** A declared trust field differs from the live trust: the hub has no update (its pins are immutable) — delete + re-create, or declare what is live. */
        const val ERROR_TRUST_IMMUTABLE = "workload_identity_trust_immutable"
        /** SSO-3702 — the flat-diff key prefix of a trust's plan profile (`plan.environment`, `plan.scopes`): the one additive exception to immutability. */
        const val PLAN_FIELD_PREFIX = "plan."

        /** SSO-3925 — the trust fields that change in place (`PUT …/{id}/scopes`): the apply scopes and the plan profile's. */
        private val TRUST_PLAN_SCOPES_FIELD = PLAN_FIELD_PREFIX + ProvisionFile.TRUST_SCOPES
        private val TRUST_SCOPE_FIELDS = setOf(ProvisionFile.TRUST_SCOPES, TRUST_PLAN_SCOPES_FIELD)

        /** SSO-3925 — the scope-change body's plan member (`UpdateWorkloadIdentityTrustScopesRequest.planScopes`). */
        private const val API_PLAN_SCOPES = "planScopes"

        /** SSO-3925 — product-api's refusal of a widening by a workload identity: adding a trust scope is a person's act. */
        const val ERROR_ELEVATED_ACTION_REQUIRES_PERSON = "elevated_action_requires_person"

        /** SSO-3925 — what the step-up of a widening asks for (oauthy ADR 2026-10-21 §4b: passkey + 300 s). */
        const val PASSKEY_ACR = "urn:thoryn:acr:phishing_resistant"
        const val ELEVATED_MAX_AGE_SECONDS = 300L
        /** The hub's scope ceiling: a trust may carry only tenant: scopes the applying identity itself holds. */
        const val ERROR_SCOPE_NOT_GRANTABLE = "scope_not_grantable"
        /** `spec.federatedTrust` names no trust of the application's environment (missing, or declared for another one). */
        const val ERROR_FEDERATED_TRUST_NOT_FOUND = "federated_trust_not_found"
        /**
         * SSO-3774 (oauthy ADR 2026-10-16 §3, Q2) — a `client:` identity (CI) would CREATE a production-plane trust: that is a
         * person's act, once (a human approves every production pin set at creation); the row's note is the founder's
         * command ([productionTrustPersonNote]). Not a grantable right — "no trust creation" is outside the consentable set.
         */
        const val ERROR_TRUST_PRODUCTION_PERSON = "workload_identity_trust_production_needs_person"

        /** SSO-3774 — what a person runs instead of CI creating a production trust: apply the file once as themselves, then grant `owner`. */
        fun productionTrustPersonNote(subject: String?, trustName: String): String =
            "not a grantable right: a production-plane workload identity trust is created by a PERSON, once — every production pin set is approved by a " +
                "human at creation. A workspace admin applies this file signed in as themselves (`thoryn login`, then `thoryn provision apply --file <this file>`), " +
                "then grants this identity `owner` on the trust it created (`${FixRequest.grantCommand(subject, RELATION_OWNER, "$OBJECT_TYPE_TRUST:${FixRequest.TRUST_ID_PLACEHOLDER}")}`; " +
                "`${FixRequest.LIST_TRUSTS_COMMAND}` shows the id of '$trustName'); this file converges it from then on"
        /** The declared trust's workload client IS the applying identity: a file cannot declare its own bootstrap trust. */
        const val ERROR_TRUST_IS_SELF = "workload_identity_trust_is_self"
        /** The plan's wording of the ceiling the hub enforces on every trust create. */
        const val SCOPE_CEILING_NOTE = " (scope ceiling: the hub grants a trust only tenant: scopes the applying identity itself holds — scope_not_grantable otherwise)"
        /** The diff value of a `federatedTrust` whose trust this same apply creates first. */
        const val PENDING_TRUST_MARKER = "(created by this apply)"
        const val SCOPE_TRUST_WRITE = "tenant:workload-identity.write"
        /** The attribute key of a trust's `wi_` workload client (a public client id, never a secret). */
        const val ATTR_CLIENT_ID = "clientId"
        /** SSO-3715 — the `private_key_jwt` key location: never diffed until product-api renders it (SSO-3716); re-sent on every update. */
        val KEY_LOCATION_FIELDS: Set<String> = setOf(ProvisionFile.SPEC_JWKS_URI, ProvisionFile.SPEC_JWKS)
        private const val MAX_TRUST_PAGES = 50
        /** SSO-3941 — the page ceiling of a role / permission listing (500 a page: 25 000 entries). */
        private const val MAX_LIST_PAGES = 50
        private val json = tools.jackson.databind.json.JsonMapper.builder().build()

        /**
         * The consumer's `connection.json` (ADR 2026-09-09 connection contract) for a trust: `workload_identity` with the
         * trust's `wi_` client, audience, scopes and the provider's pins — exactly what `thoryn workload-identity trusts
         * create` prints: for `github_actions` the GitHub pins; for `kubernetes` (SSO-3684) the file token source (the
         * projected ServiceAccount token at [KUBERNETES_TOKEN_FILE]) and the cluster pins. The contract validates those
         * two providers today, so a `forgejo` document carries no `provider` (its job presents its own Actions token).
         * Rendered, never written, by `apply`; nothing in it is secret.
         */
        fun connectionDocument(view: Map<String, Any?>, workspace: String?): Map<String, Any?> {
            val audience = view["audience"]?.toString()?.trimEnd('/')
            val provider = view["provider"]?.toString()
            val auth = linkedMapOf<String, Any?>("method" to "workload_identity")
            if (provider == ProvisionFile.PROVIDER_GITHUB_ACTIONS || provider == ProvisionFile.PROVIDER_KUBERNETES) auth["provider"] = provider
            auth["clientId"] = view["clientId"]
            if (audience != null) auth["audience"] = audience
            view["tokenEndpoint"]?.toString()?.takeIf { audience == null || it != "$audience/oauth2/token" }?.let { auth["tokenEndpoint"] = it }
            if (provider == ProvisionFile.PROVIDER_KUBERNETES) auth["tokenSource"] = linkedMapOf("kind" to "file", "path" to KUBERNETES_TOKEN_FILE)
            auth["scopes"] = (view["scopes"] as? List<*>).orEmpty().map { it.toString() }
            (view["github"] as? Map<*, *>)?.takeIf { provider != ProvisionFile.PROVIDER_KUBERNETES }?.let { g ->
                val pins = linkedMapOf<String, Any?>()
                // SSO-3722 — the COMPLETE block connection.schema.json defines: `environment` is the apply environment the
                // profile selector reads (a snippet without it made the plan job request the apply scopes — thoryn-cicd run
                // 38751382032); `githubHostedRunnersOnly` only when the trust pins it.
                CONNECTION_GITHUB_PINS.forEach { f -> g[f]?.let { v -> if (!(v is Number && v.toLong() <= 0) && v.toString().isNotBlank()) pins[f] = v } }
                if (g["githubHostedRunnersOnly"] == true) pins["githubHostedRunnersOnly"] = true
                if (pins.isNotEmpty()) auth["github"] = pins
            }
            (view["kubernetes"] as? Map<*, *>)?.takeIf { provider == ProvisionFile.PROVIDER_KUBERNETES }?.let { k ->
                // Only the pins the contract defines (never `jwksUri`, `inlineKeyIds` or key material).
                val pins = CONNECTION_KUBERNETES_PINS.mapNotNull { f -> k[f]?.toString()?.takeIf { it.isNotBlank() }?.let { f to it } }.toMap(linkedMapOf())
                if (pins.isNotEmpty()) auth["kubernetes"] = pins
            }
            return linkedMapOf("apiVersion" to "thoryn.io/connection/v1", "workspace" to linkedMapOf("slug" to (workspace ?: "<your-workspace>")), "auth" to auth)
        }

        /** SSO-3684 — where a pod's projected ServiceAccount token is mounted (the CLI's `WorkloadIdentityFlow.DEFAULT_KUBERNETES_TOKEN_FILE`). */
        const val KUBERNETES_TOKEN_FILE = "/var/run/secrets/tokens/thoryn/token"

        /** The `auth.github` members of `connection.schema.json` a trust's view fills (the boolean pin is added when true). */
        val CONNECTION_GITHUB_PINS: List<String> = listOf("owner", "repository", "ownerId", "repositoryId", "environment", "ref")

        /** The `auth.kubernetes` members of `connection.schema.json` (the pins; never the key set). */
        val CONNECTION_KUBERNETES_PINS: List<String> = listOf("issuer", "namespace", "serviceAccount")

        const val RELATION_MANAGER = AccessRefs.RELATION_MANAGER
        const val RELATION_VIEWER = AccessRefs.RELATION_VIEWER
        /** SSO-3673 — the platform's one-owner relation on `application` / `environment` (never declared in a file). */
        const val RELATION_OWNER = AccessRefs.RELATION_OWNER

        /** The platform object types (`GET /api/v1/access/mine?type=…`); the per-kind mapping is [objectRef]. */
        /**
         * SSO-3990 — the kinds whose secret is write-only (never rendered back), by the secret's spec field: `import` always
         * renders them `readOnly: true`, because a provisioning workflow carries no secret and so could never converge them.
         */
        val WRITE_ONLY_SECRET_FIELDS: Map<String, String> = mapOf(
            ProvisionFile.KIND_EMAIL_PROVIDER to "smtpPassword",
            ProvisionFile.KIND_FEDERATION_MEMBER to "clientSecret",
        )

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
         * SSO-3774 (oauthy ADR 2026-10-16 §1, Q4) — a workload-identity trust as a platform object, `trust:<hub-trust-uuid>`:
         * ownable (one `owner`, a `client:`), contained in its environment. ONE constant, so S1's fallback name
         * (`workload_identity_trust`, should a tenant model already declare `trust`) is a one-line change.
         */
        const val OBJECT_TYPE_TRUST = AccessRefs.OBJECT_TYPE_TRUST

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

        /**
         * SSO-3113 — the access-API OBJECT ref of a resource, derived from its live id (the
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
                // SSO-3413 — the workspace-level singleton; its id IS the workspace id (`tnt`).
                ProvisionFile.KIND_CUSTOM_DOMAIN -> "custom_domain:$id"
                // SSO-4042 — an email template has no access object of its own: product-api's LoginExperienceController gates EVERY
                // login-experience call (SSO-3111 `PlatformSingletonGate`) on the caller's relation to `login_theme:<plane>`;
                // SSO-4054 — the templates are per environment (oauthy SSO-4043), so the plane is the template's own.
                ProvisionFile.KIND_EMAIL_TEMPLATE -> "$OBJECT_TYPE_LOGIN_THEME:$envSlug"
                // SSO-3774 — the hub's trust UUID (stable, unique, needs no escaping).
                ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> "$OBJECT_TYPE_TRUST:$id"
                else -> throw ProvisionException("$kind: no access object type for this kind")
            }
        }
    }
}

/** SSO-3945 — a role mapping as `{a: x, b: y}`, keys sorted, for the plan and the apply log. */
private fun renderMapping(m: Map<String, String>): String = m.toSortedMap().entries.joinToString(", ", "{", "}") { (k, v) -> "$k: $v" }
