package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.Example
import com.devnow.thoryn.cli.cmd.examples.ExampleContext

/**
 * SSO-2871 Phase 1 (SSO-2873) — an [Example] whose `setup` / `teardown` are driven by a declarative
 * [Recipe] via [RecipeInterpreter] instead of hand-written Kotlin. `run` (the interactive loopback
 * relying-party flow) is delegated to [runDelegate] — Phase 1 reuses the existing compiled RP runner;
 * a recipe cannot yet express the browser interaction (a later phase carries the RP as a recipe asset).
 *
 * Enabled behind a flag (see `ExampleRegistry`): the compiled example remains the default until the
 * recipe path has soaked.
 */
internal class RecipeExample(
    private val recipe: Recipe,
    private val runDelegate: Example,
    private val receiptStore: ReceiptStore = ReceiptStore(),
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

    /** The browser interaction is unchanged (reads the same ExampleState the interpreter wrote). */
    override fun run(ctx: ExampleContext): Int = runDelegate.run(ctx)

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
