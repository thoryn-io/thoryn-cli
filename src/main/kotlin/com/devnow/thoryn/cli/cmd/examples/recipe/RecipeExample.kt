package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.Example
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.NodeRelyingParty
import com.devnow.thoryn.cli.cmd.provision.ProvisionFile

/**
 * SSO-2871 — an [Example] whose `setup` / `teardown` are driven by a declarative [Recipe] via
 * [RecipeInterpreter] instead of hand-written Kotlin, and whose `run` launches the **Node** relying
 * party that ships as a signed catalog asset (`recipes/<id>/apps/loopback-rp/server.js`, Part 1 of
 * SSO-2880). The RP logic lives in exactly one place — the readable Node app in `thoryn-examples` —
 * not in the CLI; `run` only obtains the verified asset and orchestrates the browser flow via
 * [NodeRelyingParty]. The in-process Kotlin RP was retired with SSO-2880.
 *
 * SSO-3100 — when the recipe references a provisioning file (`provision:`), `setup` converges it FIRST
 * (via the interpreter) and `teardown` destroys what it created AFTER the recipe's own teardown actions.
 */
internal class RecipeExample(
    private val recipe: Recipe,
    private val receiptStore: ReceiptStore = ReceiptStore(),
    private val relyingParty: NodeRelyingParty = NodeRelyingParty(),
) : Example {

    override val name: String = recipe.id
    override val summary: String = recipe.summary

    override fun setup(ctx: ExampleContext): Int {
        ctx.state.read(name)?.let { existing ->
            ctx.warn("An existing '$name' setup was found (workspace '${existing.workspaceSlug}').")
            ctx.warn("Run `thoryn examples teardown $name` first to start fresh, or `run` to use it.")
            return CommandSupport.EXIT_OK
        }
        return try {
            val run = RecipeInterpreter(ctx, recipe).setup()
            ctx.state.write(run.state)
            receiptStore.write(run.receipt) // SSO-2875 — a portable, verifiable record of the run.
            ctx.out.println()
            ctx.out.println("Setup complete (recipe ${recipe.id} v${recipe.version}). Live state:")
            ctx.info("workspace slug : ${run.state.workspaceSlug}")
            run.state.environmentSlug?.let { ctx.info("environment    : $it") }
            run.state.tenantIssuer?.let { ctx.info("tenant issuer  : $it") }
            run.state.identityHost?.let { ctx.info("sign-in host   : $it") }
            run.state.clientId?.let { ctx.info("app client id  : $it") }
            ctx.out.println()
            ctx.out.println("Receipt written. See it with:  thoryn examples receipt $name")
            ctx.out.println("Next:  thoryn examples run $name")
            CommandSupport.EXIT_OK
        } catch (ex: RecipeException) {
            ctx.warn("Could not apply recipe '${recipe.id}': ${ex.message}")
            CommandSupport.EXIT_HTTP_ERROR
        } catch (ex: ProductApiException) {
            ctx.warn("Could not apply recipe '${recipe.id}': ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}${ex.errorDescription?.let { " — $it" } ?: ""}")
            CommandSupport.EXIT_HTTP_ERROR
        }
    }

    /**
     * Launch the Node relying party against the config the interpreter provisioned. Reads the same
     * [com.devnow.thoryn.cli.cmd.examples.ExampleState] `setup` wrote (tenant issuer + client id) and
     * the RP asset path the recipe declares under `assets.rp`.
     */
    override fun run(ctx: ExampleContext): Int {
        val state = ctx.state.read(name)
            ?: run {
                ctx.warn("No '$name' setup found. Run `thoryn examples setup $name` first.")
                return CommandSupport.EXIT_USAGE
            }
        val tenantIssuer = state.tenantIssuer
            ?: run { ctx.warn("Stored state is missing the tenant issuer; re-run setup."); return CommandSupport.EXIT_USAGE }
        val clientId = state.clientId
            ?: run { ctx.warn("Stored state is missing the client id; re-run setup."); return CommandSupport.EXIT_USAGE }
        val assetDir = recipe.root["assets"]?.get("rp")?.takeIf { !it.isNull }?.asString()
            ?.removePrefix("./")?.trimEnd('/')
            ?: NodeRelyingParty.DEFAULT_ASSET_DIR
        return relyingParty.run(
            ctx = ctx,
            tenantIssuer = tenantIssuer,
            clientId = clientId,
            recipeId = name,
            assetDir = assetDir,
            scopes = requestedScopes(),
        )
    }

    /**
     * The space-separated scopes the recipe's `applications.create` step requests — or, SSO-3100, the
     * scopes of the first `application` resource in the recipe's provisioning file when the app was
     * provisioned rather than created by a step — else null.
     */
    private fun requestedScopes(): String? =
        recipe.steps.firstOrNull { it["action"]?.asString() == "applications.create" }
            ?.get("with")?.get("scopes")?.takeIf { !it.isNull }
            ?.toList()?.mapNotNull { it.asString() }?.takeIf { it.isNotEmpty() }
            ?.joinToString(" ")
            ?: runCatching { recipe.provisionFile() }.getOrNull()
                ?.resources?.firstOrNull { it.kind == ProvisionFile.KIND_APPLICATION }
                ?.spec?.get("scopes")?.let { it as? List<*> }
                ?.mapNotNull { it?.toString() }?.takeIf { it.isNotEmpty() }
                ?.joinToString(" ")

    override fun teardown(ctx: ExampleContext): Int {
        val state = ctx.state.read(name) ?: run {
            ctx.info("Nothing to tear down — no '$name' state found.")
            return CommandSupport.EXIT_OK
        }
        // SSO-3100 — false when the recipe's provisioning file still owns resources that could not be
        // removed: the state (and the provisioning receipt) are KEPT so a re-run can retry.
        val clean = RecipeInterpreter(ctx, recipe).teardown(state)
        if (!clean) {
            ctx.warn("Some provisioned resources remain; state kept — re-run `thoryn examples teardown $name` to retry.")
            return CommandSupport.EXIT_HTTP_ERROR
        }
        ctx.state.clear(name)
        receiptStore.clear(name)
        ctx.out.println()
        ctx.info("Removed what the recipe created (best-effort). Recipe: ${recipe.id} v${recipe.version}.")
        return CommandSupport.EXIT_OK
    }
}
