package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.Example
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.NodeRelyingParty

/**
 * SSO-2871 — an [Example] whose `setup` / `teardown` are driven by a declarative [Recipe] via
 * [RecipeInterpreter] instead of hand-written Kotlin, and whose `run` launches the **Node** relying
 * party that ships as a signed catalog asset (`recipes/<id>/apps/loopback-rp/server.js`, Part 1 of
 * SSO-2880). The RP logic lives in exactly one place — the readable Node app in `thoryn-examples` —
 * not in the CLI; `run` only obtains the verified asset and orchestrates the browser flow via
 * [NodeRelyingParty]. The in-process Kotlin RP was retired with SSO-2880.
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

    /** The space-separated scopes the recipe's `applications.create` step requests, or null. */
    private fun requestedScopes(): String? =
        recipe.steps.firstOrNull { it["action"]?.asString() == "applications.create" }
            ?.get("with")?.get("scopes")?.takeIf { !it.isNull }
            ?.toList()?.mapNotNull { it.asString() }?.takeIf { it.isNotEmpty() }
            ?.joinToString(" ")

    override fun teardown(ctx: ExampleContext): Int {
        val state = ctx.state.read(name) ?: run {
            ctx.info("Nothing to tear down — no '$name' state found.")
            return CommandSupport.EXIT_OK
        }
        RecipeInterpreter(ctx, recipe).teardown(state)
        ctx.state.clear(name)
        receiptStore.clear(name)
        ctx.out.println()
        ctx.info("Removed what the recipe created (best-effort). Recipe: ${recipe.id} v${recipe.version}.")
        return CommandSupport.EXIT_OK
    }
}
