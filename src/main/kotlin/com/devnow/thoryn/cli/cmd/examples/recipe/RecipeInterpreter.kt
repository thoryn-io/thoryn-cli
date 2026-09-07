package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleState
import com.devnow.thoryn.cli.config.ThorynConfig
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.time.Instant
import java.util.UUID

/** SSO-2875 — the result of applying a recipe: the [ExampleState] the `run`/RP flow reads, plus the
 *  portable [Receipt] recording exactly what was provisioned. */
internal data class RecipeRun(val state: ExampleState, val receipt: Receipt)

/** SSO-2873 — a recipe could not be applied (bad shape, unresolved reference, or a step failure). */
internal open class RecipeException(message: String) : RuntimeException(message)

/** An action that the schema allows but the CLI interpreter does not yet implement (a later phase). */
internal class RecipeUnsupportedActionException(action: String) :
    RecipeException("recipe action '$action' is not yet supported by this CLI (a later SSO-2871 phase adds it)")

/**
 * SSO-2871 Phase 1 (SSO-2873) — the recipe **runner**: interprets a declarative recipe by executing
 * its steps against the REAL product APIs (via [ExampleContext], the same clients the `workspace` /
 * `clients` / `federation` commands use), then runs its `verify` assertions. Recipes are DATA, not
 * code — this interpreter is the only executor, and it dispatches ONLY on the schema's closed action
 * allowlist, so a recipe can never reach past the supported product surface (the product-boundary
 * rule, made structural).
 *
 * The recipe is read as a bundled JSON resource (authored as YAML; a build-time-equivalent
 * `recipe.json` ships alongside with a drift guard) so the runtime needs no YAML parser — keeping the
 * GraalVM native image unchanged.
 *
 * Phase 1 implements the actions `simple-signin` needs (workspace + tenant registration + application
 * create, plus federation create and the delete/verify verbs). Environment actions (`env.*`) are the
 * guided-wizard phase (SSO-2876) and throw [RecipeUnsupportedActionException] until then.
 */
internal class RecipeInterpreter(
    private val ctx: ExampleContext,
    private val recipe: Recipe,
    private val overrides: Map<String, String> = emptyMap(),
    /** SSO-2876 — the environment the recipe's resources are provisioned into (X-Thoryn-Environment); null = production plane. */
    private val environmentSlug: String? = null,
    /** Test seam for the random slug suffix. */
    private val randomSuffix: () -> String = { UUID.randomUUID().toString().replace("-", "").substring(0, 8) },
    /** Deadline budget for the post-create tenant-trust propagation retry (ms). */
    private val trustPropagationBudgetMs: Long = 75_000,
) {
    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    /** Flat resolution scope: a param name, or `"<stepId>.<field>"` for a step output. */
    private val scope = mutableMapOf<String, String>()

    /** The workspace a `hub.createWorkspace` step established — drives which tenant client later steps use. */
    private data class WorkspaceCtx(val slug: String, val tenantId: String, val provisioningToken: String?)
    private var workspace: WorkspaceCtx? = null

    private var createdClientId: String? = null
    private var createdRedirectUri: String? = null

    // SSO-2875 — accumulated as the run proceeds, folded into the receipt on success.
    private val resources = mutableListOf<ResourceRef>()
    private val verifyResults = mutableListOf<VerifyResult>()

    private val placeholder = Regex("""\{\{\s*([a-zA-Z0-9_.]+)\s*}}""")

    /** Provision the recipe: resolve params, run steps in order, verify, then attest. Returns the [RecipeRun]. */
    fun setup(): RecipeRun {
        resolveParams()
        recipe.steps.forEachIndexed { i, step -> executeStep(i + 1, step) }
        runVerify()
        return RecipeRun(buildState(), attest(buildReceipt()))
    }

    /**
     * SSO-2878 — best-effort platform attestation (the receipt's signed layer, "when reachable"): POST
     * the receipt so the platform re-verifies its resources and signs it, and fold the signature into
     * the receipt. Never fatal — an unreachable or refusing platform leaves a valid, unsigned local
     * receipt (the always-on layer).
     */
    private fun attest(receipt: Receipt): Receipt = try {
        val resp = tenantClient().attestReceipt(receipt)
        val attestation = Attestation(
            kid = resp["kid"].asString(),
            signature = resp["signature"].asString(),
            canonicalPayload = resp["canonicalPayload"].asString(),
            attestedAt = resp["attestedAt"].asString(),
        )
        ctx.info("attestation: platform-signed (kid ${attestation.kid})")
        receipt.copy(attestation = attestation)
    } catch (ex: Exception) {
        ctx.warn("platform attestation unavailable (${ex.message}); the local receipt is unsigned.")
        receipt
    }

    /**
     * SSO-2875 — re-check a receipt's `verify` assertions against the LIVE product state (does the
     * provisioned config still exist and match?). Returns fresh [VerifyResult]s; never throws.
     */
    fun verifyReceipt(receipt: Receipt): List<VerifyResult> {
        workspace = WorkspaceCtx(receipt.workspace.slug ?: "", receipt.workspace.tenantId ?: "", null)
        return receipt.verify.map { vr ->
            when (vr.assert) {
                "applications.get" -> {
                    val app = runCatching { tenantClient().getApplication(vr.id ?: "") }.getOrNull()
                    val passed = app != null && vr.expect.all { (field, expected) -> app[field]?.asString() == expected }
                    vr.copy(passed = passed)
                }
                else -> vr.copy(passed = false)
            }
        }
    }

    /**
     * SSO-2878 — verify a receipt's platform attestation OFFLINE: fetch the JWKS and check the detached
     * JWS over the canonical payload. `null` when the receipt carries no attestation.
     */
    fun verifyAttestation(receipt: Receipt): Es256JwsVerifier.Status? {
        val att = receipt.attestation ?: return null
        workspace = WorkspaceCtx(receipt.workspace.slug ?: "", receipt.workspace.tenantId ?: "", null)
        return try {
            val jwks = tenantClient().attestationJwks()
            Es256JwsVerifier.verify(jwks, att.kid, att.signature, att.canonicalPayload)
        } catch (_: Exception) {
            Es256JwsVerifier.Status.UNVERIFIABLE
        }
    }

    /** Best-effort teardown in reverse declaration order; a failure is warned, not fatal. */
    fun teardown(state: ExampleState) {
        // Rebuild the minimal scope teardown references from the persisted state.
        state.clientId?.let { scope["app.clientId"] = it }
        state.workspaceSlug?.let { scope["workspaceSlug"] = it }
        state.tenantId?.let { workspace = WorkspaceCtx(state.workspaceSlug ?: "", it, null) }
        recipe.teardown.asReversed().forEach { t ->
            val action = t["action"].asString()
            try {
                when (action) {
                    "applications.delete" -> tenantClient().deleteApplication(substitute(t["id"].asString()), state.workspaceSlug)
                    "federation.delete" -> tenantClient().deleteFederationMember(substitute(t["id"].asString()))
                    else -> throw RecipeUnsupportedActionException(action)
                }
            } catch (ex: Exception) {
                ctx.warn("teardown step '$action' did not complete (${ex.message}); continuing.")
            }
        }
    }

    // ── param resolution ──────────────────────────────────────────────────────────────────────────

    private fun resolveParams() {
        recipe.params.forEach { p ->
            val name = p["name"].asString()
            val raw = overrides[name]
                ?: p["default"]?.takeIf { !it.isNull }?.asString()
                ?: throw RecipeException("parameter '$name' has no value and no default (guided prompting is SSO-2876)")
            val value = substitute(raw)
            p["validate"]?.takeIf { !it.isNull }?.asString()?.let { pattern ->
                if (!Regex(pattern).matches(value)) {
                    throw RecipeException("parameter '$name' value '$value' does not match /$pattern/")
                }
            }
            scope[name] = value
        }
    }

    // ── steps ───────────────────────────────────────────────────────────────────────────────────

    private fun executeStep(n: Int, step: JsonNode) {
        val id = step["id"].asString()
        val action = step["action"].asString()
        val with = resolveWith(step)
        ctx.step(n, step["description"]?.takeIf { !it.isNull }?.asString() ?: action)
        val outputs: Map<String, String> = when (action) {
            "hub.createWorkspace" -> createWorkspace(with)
            "productApi.registerTenant" -> registerTenant(with)
            "applications.create" -> createApplication(with)
            "federation.create" -> createFederation(with)
            "applications.delete" -> { tenantClient().deleteApplication(with["id"].toString(), workspace?.slug); emptyMap() }
            "federation.delete" -> { tenantClient().deleteFederationMember(with["id"].toString()); emptyMap() }
            else -> throw RecipeUnsupportedActionException(action)
        }
        outputs.forEach { (k, v) -> scope["$id.$k"] = v }
    }

    private fun createWorkspace(with: Map<String, Any?>): Map<String, String> {
        val ws = ctx.hubClient().createWorkspace(with)
        val tenantId = ws["tenantId"]?.asString()
            ?: throw RecipeException("hub.createWorkspace returned no tenantId")
        val slug = (with["slug"] as? String) ?: ws["slug"]?.asString() ?: ""
        val provisioningToken = ws["provisioningToken"]?.takeIf { !it.isNull }?.asString()
        workspace = WorkspaceCtx(slug, tenantId, provisioningToken)
        ctx.info("workspace: slug=$slug tenantId=$tenantId")
        return mapOf("tenantId" to tenantId, "slug" to slug)
    }

    private fun registerTenant(with: Map<String, Any?>): Map<String, String> {
        // Best-effort + idempotent, exactly like the `workspace create` path.
        try {
            ctx.gatewayClient().registerTenant(with)
        } catch (ex: Exception) {
            ctx.warn("product-api tenant registration did not complete (${ex.message}); continuing — it is idempotent.")
        }
        return emptyMap()
    }

    private fun createApplication(with: Map<String, Any?>): Map<String, String> {
        createdRedirectUri = (with["redirectUris"] as? List<*>)?.firstOrNull()?.toString()
        val client = tenantClient()
        val app = retryUntilTenantTrusted { client.createApplication(with) }
        val clientId = (app["clientId"] ?: app["client_id"])?.asString()
            ?: throw RecipeException("applications.create returned no clientId")
        createdClientId = clientId
        resources += ResourceRef(
            kind = "application",
            id = clientId,
            attributes = buildMap { createdRedirectUri?.let { put("redirectUri", it) } },
        )
        ctx.info("client: clientId=$clientId")
        return mapOf("clientId" to clientId)
    }

    private fun createFederation(with: Map<String, Any?>): Map<String, String> {
        val member = retryUntilTenantTrusted { tenantClient().createFederationMember(with) }
        val memberId = (member["memberId"] ?: member["id"])?.asString()
            ?: throw RecipeException("federation.create returned no memberId")
        resources += ResourceRef(kind = "federationMember", id = memberId)
        return mapOf("memberId" to memberId)
    }

    // ── verify ──────────────────────────────────────────────────────────────────────────────────

    private fun runVerify() {
        recipe.verify.forEach { v ->
            when (val assertion = v["assert"].asString()) {
                "applications.get" -> {
                    val id = substitute(v["id"].asString())
                    val expect = expectations(v)
                    val app = tenantClient().getApplication(id)
                    val mismatch = expect.entries.firstOrNull { (field, expected) -> app[field]?.asString() != expected }
                    verifyResults += VerifyResult("applications.get", id, expect, passed = mismatch == null)
                    if (mismatch != null) {
                        throw RecipeException("verify applications.get: expected ${mismatch.key}='${mismatch.value}' but was '${app[mismatch.key]?.asString()}'")
                    }
                }
                else -> throw RecipeUnsupportedActionException(assertion)
            }
        }
    }

    private fun expectations(verify: JsonNode): Map<String, String> {
        val raw = verify["expect"]?.takeIf { !it.isNull }
            ?.let { mapper.convertValue(it, Map::class.java) } as? Map<*, *> ?: emptyMap<Any, Any>()
        return raw.entries.associate { (k, v) -> k.toString() to v.toString() }
    }

    // ── tenant client selection + trust-propagation retry ───────────────────────────────────────

    private fun tenantClient(): ProductApiClient {
        val w = workspace ?: throw RecipeException("this step requires a prior hub.createWorkspace step")
        return w.provisioningToken?.let { ctx.provisioningGatewayClient(it, environmentSlug) }
            ?: ctx.tenantGatewayClient(
                ThorynConfig.tenantIssuer(ctx.hub, w.slug)
                    ?: throw RecipeException("could not derive the tenant issuer for workspace '${w.slug}'"),
                environmentSlug,
            )
    }

    /**
     * A freshly-created workspace's issuer is not yet in the gateway's tenant-trust snapshot
     * (`TrustedTenantSlugRegistry`, refreshed ~45s), so the first tenant-scoped calls can be rejected.
     * Retry within a budget while the gateway's tenant-trust snapshot catches up.
     */
    private fun <T> retryUntilTenantTrusted(call: () -> T): T {
        val deadline = System.currentTimeMillis() + trustPropagationBudgetMs
        var announced = false
        var last: ProductApiException? = null
        while (System.currentTimeMillis() < deadline) {
            try {
                return call()
            } catch (ex: ProductApiException) {
                last = ex
                if (!announced) {
                    ctx.info("waiting for the new workspace to become reachable (its issuer trust refreshes ~45s)…")
                    announced = true
                }
                Thread.sleep(4_000)
            }
        }
        throw last ?: RecipeException("timed out waiting for the workspace to become reachable")
    }

    // ── placeholders + state ─────────────────────────────────────────────────────────────────────

    private fun resolveWith(step: JsonNode): Map<String, Any?> {
        val raw = step["with"]?.takeIf { !it.isNull }
            ?.let { mapper.convertValue(it, Map::class.java) } as? Map<*, *> ?: emptyMap<Any, Any>()
        @Suppress("UNCHECKED_CAST")
        return substituteDeep(raw) as Map<String, Any?>
    }

    private fun substituteDeep(value: Any?): Any? = when (value) {
        is String -> substitute(value)
        is Map<*, *> -> value.entries.associate { (k, v) -> k.toString() to substituteDeep(v) }
        is List<*> -> value.map { substituteDeep(it) }
        else -> value
    }

    private fun substitute(template: String): String =
        placeholder.replace(template) { m ->
            when (val ref = m.groupValues[1]) {
                "generate.slug8" -> randomSuffix()
                "generate.uuid" -> UUID.randomUUID().toString()
                else -> scope[ref] ?: throw RecipeException("unresolved placeholder '{{$ref}}'")
            }
        }

    private fun buildState(): ExampleState {
        val w = workspace
        val slug = w?.slug ?: scope["workspaceSlug"]
        return ExampleState(
            example = recipe.id,
            workspaceSlug = slug,
            tenantId = w?.tenantId,
            clientId = createdClientId,
            redirectUri = createdRedirectUri,
            tenantIssuer = slug?.let { ThorynConfig.tenantIssuer(ctx.hub, it) },
            identityHost = slug?.let { ThorynConfig.tenantIdentityHost(ctx.hub, it) },
        )
    }

    private fun buildReceipt(): Receipt {
        val w = workspace
        return Receipt(
            recipe = RecipeRef(recipe.id, recipe.version, recipe.digest),
            appliedAt = Instant.now().toString(),
            subject = JwtClaims.of(ctx.tokens.accessToken)["sub"]?.takeIf { !it.isNull }?.asString(),
            workspace = WorkspaceRef(slug = w?.slug ?: scope["workspaceSlug"], tenantId = w?.tenantId),
            environment = environmentSlug,
            resources = resources.toList(),
            verify = verifyResults.toList(),
        )
    }
}
