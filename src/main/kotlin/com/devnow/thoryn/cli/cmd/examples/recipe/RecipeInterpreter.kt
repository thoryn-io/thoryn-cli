package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.JwtClaims
import com.devnow.thoryn.cli.cmd.SecretIo
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
 * SSO-2950 — the single channel through which the `clients.createMachine` step's ONE minted
 * `client_secret` leaves the CLI. It is the recipe-interpreter seam over the same [SecretIo] emission
 * `thoryn clients create` uses (a `--secret-file`, or a guarded/interactive stdout). The secret is
 * routed here and NOWHERE else — never to the receipt, a step output (`{{...}}`), a log, or argv.
 *
 * [emit] returns `true` when the secret was delivered, `false` when it was refused (e.g. no
 * `--secret-file` and a non-interactive stdout) — the interpreter then fails the run so the operator
 * notices the secret was NOT surfaced.
 */
internal fun interface SecretSink {
    fun emit(clientId: String, secret: String): Boolean

    companion object {
        /**
         * The production default when no explicit sink is wired: emit through [SecretIo] with no
         * `--secret-file` and `forceStdout=false` — i.e. print to an interactive TTY (with a WARN),
         * and REFUSE a non-interactive pipe. This mirrors `thoryn clients create`'s default exactly,
         * so a `clients.createMachine` step is as secret-safe by default as the imperative command.
         */
        fun default(): SecretSink = SecretSink { _, secret ->
            SecretIo.emitSecret(
                label = "CI machine client secret",
                secret = secret,
                secretFile = null,
                forceStdout = false,
            )
        }
    }
}

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
    /**
     * SSO-2950 — where a `clients.createMachine` step routes its ONE minted `client_secret`. Defaults
     * to the same [SecretIo] behaviour as `thoryn clients create` (interactive TTY, refuse a pipe); the
     * `examples apply` command overrides it with a `--secret-file`-configured sink.
     */
    private val secretSink: SecretSink = SecretSink.default(),
) {
    private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

    /**
     * SSO-2944 — does this recipe create its OWN workspace (a `hub.createWorkspace` step)? When it does
     * NOT (a workspace-less recipe like `ci-signin`), the caller's session token is ALREADY tenant-
     * scoped to a standing workspace, so the interpreter provisions with that token directly — there is
     * no provisioning token to prefer and no token-exchange to a freshly-created tenant. This flag is
     * fixed by the recipe shape, so every tenant-scoped call (steps, verify, teardown, attest) resolves
     * its client the same way. See [tenantClient].
     */
    private val createsWorkspace: Boolean =
        recipe.steps.any { it["action"]?.asString() == "hub.createWorkspace" }

    /** Flat resolution scope: a param name, or `"<stepId>.<field>"` for a step output. */
    private val scope = mutableMapOf<String, String>()

    /** The workspace a `hub.createWorkspace` step established — drives which tenant client later steps use. */
    private data class WorkspaceCtx(val slug: String, val tenantId: String, val provisioningToken: String?)
    private var workspace: WorkspaceCtx? = null

    private var createdClientId: String? = null
    private var createdRedirectUri: String? = null
    private var createdPostLogoutRedirectUri: String? = null

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

    /**
     * Best-effort teardown in DECLARED (child-first) order; a failure is warned, not fatal.
     *
     * SSO-2901 — the recipe lists teardown removals in the order they must run: delete the app FIRST,
     * then `hub.deleteWorkspace` hard-deletes the workspace it lived in (which stops the `ex-signin-*`
     * tenant sprawl — a run that only deleted the app left its workspace/tenant behind forever). The
     * workspace hard-delete is IRREVERSIBLE and name-confirmation guarded: the CLI echoes the workspace
     * slug back in the `X-Thoryn-Confirm` header (the hub 422s a mismatch), and it targets the HUB
     * `/account/workspace/{tenantId}/hard-delete` surface with the founder's session token — NOT the
     * tenant-scoped gateway client used for the app/federation deletes.
     */
    fun teardown(state: ExampleState) {
        // Rebuild the minimal scope teardown references from the persisted state.
        state.clientId?.let { scope["app.clientId"] = it }
        state.workspaceSlug?.let { scope["workspaceSlug"] = it }
        state.tenantId?.let { scope["workspace.tenantId"] = it }
        state.tenantId?.let { workspace = WorkspaceCtx(state.workspaceSlug ?: "", it, null) }
        recipe.teardown.forEach { t ->
            val action = t["action"].asString()
            try {
                when (action) {
                    "applications.delete" -> tenantClient().deleteApplication(substitute(t["id"].asString()), state.workspaceSlug)
                    "federation.delete" -> tenantClient().deleteFederationMember(substitute(t["id"].asString()))
                    "hub.deleteWorkspace" -> {
                        val tenantId = substitute(t["id"].asString())
                        // Confirmation MUST equal the workspace slug (the hub's name-confirmation guard).
                        val confirmSlug = workspace?.slug?.takeIf { it.isNotBlank() } ?: state.workspaceSlug
                        ctx.hubClient().hardDeleteWorkspace(tenantId, confirmSlug)
                        ctx.info("workspace hard-deleted: tenantId=$tenantId")
                    }
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
            "clients.createMachine" -> createMachineClient(with)
            "identity.registerUser" -> registerUser(with)
            "tenant.configureEmailProvider" -> configureEmailProvider(with)
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
        // SSO-2897 — OIDC RP-Initiated-Logout post-logout redirect URI. The full `with` map (including
        // `postLogoutRedirectUris`) is forwarded verbatim to product-api's create-application request,
        // which persists it on the hub's RegisteredClient (SSO-2553); captured here only for the receipt.
        createdPostLogoutRedirectUri = (with["postLogoutRedirectUris"] as? List<*>)?.firstOrNull()?.toString()
        val client = tenantClient()
        val app = retryUntilTenantTrusted { client.createApplication(with) }
        val clientId = (app["clientId"] ?: app["client_id"])?.asString()
            ?: throw RecipeException("applications.create returned no clientId")
        createdClientId = clientId
        resources += ResourceRef(
            kind = "application",
            id = clientId,
            attributes = buildMap {
                createdRedirectUri?.let { put("redirectUri", it) }
                createdPostLogoutRedirectUri?.let { put("postLogoutRedirectUri", it) }
            },
        )
        ctx.info("client: clientId=$clientId")
        return mapOf("clientId" to clientId)
    }

    /**
     * SSO-2950 — the as-code machine-client bootstrap. Provision a CONFIDENTIAL `client_credentials`
     * client through the SUPPORTED product workflow — the SAME product-api `POST /api/v1/applications`
     * call `thoryn clients create` makes (`tenant:applications.write`) — and route the ONE server-minted
     * `client_secret` through the CLI's [SecretIo] channel via [secretSink].
     *
     * **Security boundary (the reason ADR 2026-09-09 exists).** `clients.createMachine` is the only
     * allowlisted action permitted to surface a secret, and it preserves the recipe trust model
     * (recipes are DATA producing SECRET-FREE receipts, ADR 2026-09-05): the minted secret exits
     * EXCLUSIVELY through [secretSink] (a `--secret-file` / guarded stdout). It is NEVER:
     *  - written to the [Receipt] (only the non-secret `machineClient` shape — `clientId` + granted
     *    `scopes` — is recorded), nor
     *  - exposed as a step output / `{{...}}` binding (only `clientId` is returned to [scope]), nor
     *  - logged (only the `clientId` is printed) or placed on argv.
     * If the sink refuses the secret (no `--secret-file`, non-interactive stdout), the run FAILS so the
     * operator notices the credential was not surfaced.
     */
    private fun createMachineClient(with: Map<String, Any?>): Map<String, String> {
        // Enforce the machine-client shape the ADR fixes (the schema documents these as required; we
        // re-check here so a hand-edited recipe cannot mint a differently-shaped secret-bearing client).
        val clientType = (with["clientType"] as? String)?.trim().orEmpty().ifEmpty { "confidential" }
        if (clientType != "confidential") {
            throw RecipeException("clients.createMachine requires clientType 'confidential' (was '$clientType')")
        }
        val grantTypes = stringList(with["grantTypes"])
        if ("client_credentials" !in grantTypes) {
            throw RecipeException("clients.createMachine requires grantTypes to include 'client_credentials' (was $grantTypes)")
        }
        val requestedScopes = stringList(with["scopes"])

        val body = linkedMapOf<String, Any?>("clientType" to clientType, "grantTypes" to grantTypes)
        (with["displayName"] as? String)?.takeIf { it.isNotBlank() }?.let { body["displayName"] = it }
        if (requestedScopes.isNotEmpty()) body["scopes"] = requestedScopes

        val app = retryUntilTenantTrusted { tenantClient().createApplication(body) }
        val clientId = (app["clientId"] ?: app["client_id"])?.takeIf { !it.isNull }?.asString()
            ?: throw RecipeException("clients.createMachine returned no clientId")
        // Prefer the granted scopes echoed by the server; fall back to what the recipe requested.
        val grantedScopes = stringList(app["scopes"]).ifEmpty { requestedScopes }

        // The receipt records ONLY the non-secret shape — clientId + granted scopes. NEVER the secret.
        resources += ResourceRef(
            kind = "machineClient",
            id = clientId,
            attributes = buildMap { if (grantedScopes.isNotEmpty()) put("scopes", grantedScopes.joinToString(",")) },
        )

        // Route the ONE minted secret through SecretIo and NOWHERE else. Read it into a local, hand it
        // to the sink, and never let it reach [scope], the receipt, or a log line.
        val secret = (app["clientSecret"] ?: app["client_secret"])?.takeIf { !it.isNull }?.asString()
        if (!secret.isNullOrEmpty()) {
            val delivered = secretSink.emit(clientId, secret)
            if (!delivered) {
                throw RecipeException(
                    "the machine client '$clientId' was created but its secret could not be delivered — " +
                        "re-run `thoryn examples apply` with --secret-file <path> (or --force-stdout).",
                )
            }
        }
        // clientId ONLY — the secret is deliberately absent from the step-output map.
        ctx.info("machine client: clientId=$clientId (secret via SecretIo — not recorded on the receipt)")
        return mapOf("clientId" to clientId)
    }

    /** Read a JSON/`with` value that should be a string array into a `List<String>` (empty when absent). */
    private fun stringList(value: Any?): List<String> = when (value) {
        is List<*> -> value.mapNotNull { it?.toString() }
        is JsonNode -> if (value.isArray) value.mapNotNull { it.asString() } else emptyList()
        else -> emptyList()
    }

    /**
     * SSO-2907 — provision a sign-in-able tenant user through the SUPPORTED product workflow
     * (product-api `POST /api/v1/users`, `tenant:users.write`; SSO-1884). The recipe's `with` map
     * (`email`, `password`, optional `givenName`/`familyName`/`locale`, `emailVerified`) is forwarded
     * verbatim as the create-user body — a `password` sets an initial credential and
     * `emailVerified:true` marks the account verified, so the example's sign-up→login leg can proceed
     * without an email round-trip. The created user's `id`/`email` are recorded on the receipt (parity
     * with the app/workspace capture) and exposed as `{{<step id>.id}}` / `{{<step id>.email}}`.
     */
    private fun registerUser(with: Map<String, Any?>): Map<String, String> {
        val user = retryUntilTenantTrusted { tenantClient().createUser(with) }
        val userId = (user["id"] ?: user["userId"])?.takeIf { !it.isNull }?.asString()
            ?: throw RecipeException("identity.registerUser returned no user id")
        val email = user["email"]?.takeIf { !it.isNull }?.asString() ?: (with["email"] as? String)
        resources += ResourceRef(
            kind = "user",
            id = userId,
            attributes = buildMap { email?.let { put("email", it) } },
        )
        ctx.info("user: id=$userId${email?.let { " email=$it" } ?: ""}")
        return buildMap {
            put("id", userId)
            put("userId", userId)
            email?.let { put("email", it) }
        }
    }

    /**
     * SSO-2917 — configure the workspace's bring-your-own SMTP transport through the SUPPORTED product
     * workflow (product-api `PUT /api/v1/email-provider`, `tenant:email.write`; PR #3448). The recipe's
     * `with` map (`smtpHost`, `smtpPort`, `smtpUsername`, `smtpPassword`, `transportSecurity`,
     * `fromAddress`, `fromName`, `replyTo`, `enabled`, `providerType`) is forwarded verbatim as the
     * merge-upsert body. The SMTP password is WRITE-ONLY: the response never carries it back, and it is
     * NEVER recorded on the receipt (a recipe author marks its param `secret:true`) — only the
     * non-secret provider shape (type / host / from-address / configVersion / enabled) is attested.
     * The resulting `providerType` / `configVersion` / `enabled` are exposed as
     * `{{<step id>.providerType}}` / `{{<step id>.configVersion}}` / `{{<step id>.enabled}}`.
     */
    private fun configureEmailProvider(with: Map<String, Any?>): Map<String, String> {
        // SSO-2927 — OPTIONAL step. With no SMTP host supplied (the shipped recipe's empty default),
        // configuring a BYO-SMTP transport would be wrong for a real customer, so SKIP the PUT entirely
        // and leave the platform sender unchanged. The example-e2e passes real `--set smtp*` values to
        // point the freshly-provisioned workspace at a sink using the live provisioning token.
        val host = with["smtpHost"]?.toString()?.trim().orEmpty()
        if (host.isBlank()) {
            ctx.info("email provider: no SMTP host supplied — leaving the platform sender unchanged (no BYO-SMTP)")
            return mapOf("configured" to "false")
        }

        // Build a TYPED merge-upsert body: recipe params arrive as strings (from {{…}} substitution),
        // but product-api's PutEmailProviderRequest wants a numeric `smtpPort` and boolean `enabled` /
        // `allowInsecureTransport`. Coerce those; forward the write-only `smtpPassword` verbatim (NEVER
        // logged or receipted). Only non-blank fields are sent (merge-upsert keeps stored values).
        val body = linkedMapOf<String, Any?>()
        body["smtpHost"] = host
        with["providerType"].nonBlankString()?.let { body["providerType"] = it }
        with["smtpPort"]?.let { coerceInt(it)?.let { p -> body["smtpPort"] = p } }
        with["smtpUsername"].nonBlankString()?.let { body["smtpUsername"] = it }
        // Write-only credential — passed through to the PUT, never trimmed, never logged/receipted.
        (with["smtpPassword"]?.toString())?.takeIf { it.isNotEmpty() }?.let { body["smtpPassword"] = it }
        with["transportSecurity"].nonBlankString()?.let { body["transportSecurity"] = it }
        with["allowInsecureTransport"]?.let { body["allowInsecureTransport"] = coerceBool(it) }
        with["fromAddress"].nonBlankString()?.let { body["fromAddress"] = it }
        with["fromName"].nonBlankString()?.let { body["fromName"] = it }
        with["replyTo"].nonBlankString()?.let { body["replyTo"] = it }
        with["enabled"]?.let { body["enabled"] = coerceBool(it) }

        val resp = retryUntilTenantTrusted { tenantClient().putEmailProvider(body) }
        val providerType = resp["providerType"]?.takeIf { !it.isNull }?.asString() ?: "email-provider"
        val configVersion = resp["configVersion"]?.takeIf { !it.isNull }?.asString()
        val enabled = resp["enabled"]?.takeIf { !it.isNull }?.asString()
        resources += ResourceRef(
            kind = "emailProvider",
            id = providerType,
            // NEVER the password — only the non-secret provider shape.
            attributes = buildMap {
                configVersion?.let { put("configVersion", it) }
                enabled?.let { put("enabled", it) }
                resp["smtpHost"]?.takeIf { !it.isNull }?.asString()?.let { put("smtpHost", it) }
                resp["fromAddress"]?.takeIf { !it.isNull }?.asString()?.let { put("fromAddress", it) }
            },
        )
        ctx.info("email provider: type=$providerType${enabled?.let { " enabled=$it" } ?: ""}")
        return buildMap {
            put("providerType", providerType)
            configVersion?.let { put("configVersion", it) }
            enabled?.let { put("enabled", it) }
        }
    }

    /** A `with` value coerced to a non-blank trimmed String, or null (skip the field). */
    private fun Any?.nonBlankString(): String? = this?.toString()?.trim()?.takeIf { it.isNotEmpty() }

    /** Coerce a `with` value (a real JSON boolean or the string "true"/"false") to Boolean. */
    private fun coerceBool(v: Any?): Boolean = when (v) {
        is Boolean -> v
        else -> v?.toString()?.trim().equals("true", ignoreCase = true)
    }

    /** Coerce a `with` value (a real JSON number or a numeric string) to Int, or null if not numeric. */
    private fun coerceInt(v: Any?): Int? = when (v) {
        is Number -> v.toInt()
        else -> v?.toString()?.trim()?.toIntOrNull()
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
        // SSO-2944 — a workspace-less recipe operates inside a STANDING workspace the caller's API key
        // is already scoped to (its `tnt` claim). Use the caller's own tenant-scoped bearer directly:
        // there is no hub.createWorkspace step to mint a provisioning token, and no token-exchange to a
        // just-created tenant. The decision is on the recipe SHAPE, so steps, verify, and teardown all
        // resolve the client identically (teardown/verify set `workspace` from the receipt/state, but
        // for a workspace-less recipe that context is informational — the caller token still applies).
        if (!createsWorkspace) return ctx.callerGatewayClient(environmentSlug)
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
