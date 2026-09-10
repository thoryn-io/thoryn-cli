package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.recipe.Recipe
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeCatalog
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeCatalogException
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeException
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeExample
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeInterpreter
import com.devnow.thoryn.cli.cmd.examples.recipe.ReceiptStore
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.File
import java.util.concurrent.Callable

/**
 * SSO-2830 — `thoryn examples ...`
 *
 * Runnable, in-boundary product examples. Each example provisions a real
 * configuration in your own account via supported product workflows, lets you see
 * the real interaction, and tears down what it created:
 *
 *   thoryn examples list
 *   thoryn examples setup    <name>
 *   thoryn examples run      <name>
 *   thoryn examples teardown <name>
 *
 * `<name>` may be omitted when there is exactly one example.
 */
@Command(
    name = "examples",
    description = ["Set up and run runnable product examples in your own account."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ExamplesCommand.ListSubcommand::class,
        ExamplesCommand.SetupSubcommand::class,
        ExamplesCommand.RunSubcommand::class,
        ExamplesCommand.TeardownSubcommand::class,
        ExamplesCommand.ReceiptSubcommand::class,
        ExamplesCommand.VerifySubcommand::class,
        ExamplesCommand.CatalogSubcommand::class,
        ExamplesCommand.UpdateSubcommand::class,
        ExamplesCommand.ApplySubcommand::class,
        ExamplesCommand.ShareSubcommand::class,
    ],
)
class ExamplesCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn examples <subcommand>")
        System.err.println("Subcommands: list | setup <name> | run <name> | teardown <name>")
        return CommandSupport.EXIT_USAGE
    }

    @Command(name = "list", description = ["List the available examples."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {
        override fun call(): Int {
            val examples = ExampleRegistry.all()
            if (examples.isEmpty()) {
                println("No examples are bundled.")
                return CommandSupport.EXIT_OK
            }
            val width = examples.maxOf { it.name.length }
            println("Available examples:")
            examples.forEach { println("  ${it.name.padEnd(width)}  ${it.summary}") }
            println()
            println("Run one with:  thoryn examples setup <name>  →  run <name>  →  teardown <name>")
            return CommandSupport.EXIT_OK
        }
    }

    @Command(name = "setup", description = ["Provision an example in your account (workspace + app)."], mixinStandardHelpOptions = true)
    class SetupSubcommand : LifecycleSubcommand({ ex, ctx -> ex.setup(ctx) })

    @Command(name = "run", description = ["Run an example's interaction (opens your browser)."], mixinStandardHelpOptions = true)
    class RunSubcommand : LifecycleSubcommand({ ex, ctx -> ex.run(ctx) })

    /**
     * SSO-2967 — `thoryn examples teardown [name] [--recipe-dir <path>]`. Standalone (not a plain
     * [LifecycleSubcommand]) so it can tear down an EXTERNAL recipe loaded from a checked-out directory,
     * not only a bundled one. With `--recipe-dir` the recipe is loaded from disk (same model +
     * interpreter as a bundled recipe) and its own `id` keys the persisted state/receipt the teardown
     * reloads; without it, the bundled catalog behaviour is unchanged.
     */
    @Command(name = "teardown", description = ["Remove what an example's setup created (best-effort)."], mixinStandardHelpOptions = true)
    class TeardownSubcommand : Callable<Int> {
        @Parameters(index = "0", arity = "0..1", description = ["Example name (optional when only one exists)."])
        var name: String? = null

        @Option(
            names = ["--recipe-dir"],
            description = [
                "Load the recipe from a checked-out directory (e.g. a thoryn-examples recipe) instead of " +
                    "the bundled catalog. Resolves <dir>/recipe.json, else <dir>/<name>/recipe.json.",
            ],
        )
        var recipeDir: File? = null

        @Option(names = ["--hub"], description = ["Override the hub base URL. Defaults to the hub you signed into, else http://localhost:54702."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"], description = ["Override the gateway base URL. Defaults to the gateway you signed into, else http://localhost:8991."])
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val example: Example = if (recipeDir != null) {
                try {
                    RecipeExample(loadRecipe(name, recipeDir).recipe)
                } catch (ex: RecipeException) {
                    System.err.println("Could not load the recipe from --recipe-dir (${ex.message}).")
                    return CommandSupport.EXIT_USAGE
                }
            } else {
                resolveBundledExample() ?: return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val ctx = ExampleContext(
                hub = CommandSupport.resolveHub(hub, tokens),
                gateway = CommandSupport.resolveGateway(gateway, tokens),
                tokens = tokens,
                state = ExampleStateStore(),
            )
            return example.teardown(ctx)
        }

        private fun resolveBundledExample(): Example? {
            val all = ExampleRegistry.all()
            val chosen = when {
                name != null -> ExampleRegistry.byName(name!!)
                all.size == 1 -> all.first()
                else -> null
            }
            if (chosen == null) {
                System.err.println(
                    if (name != null) "Unknown example '$name'." else "Multiple examples exist — specify one by name.",
                )
                System.err.println("Available: ${all.joinToString(", ") { it.name }}")
            }
            return chosen
        }
    }

    /**
     * SSO-2875 — `thoryn examples receipt [name]` — show the portable receipt a recipe run wrote
     * (what was provisioned, the recipe id/version/digest, verify results). Offline; no sign-in needed.
     */
    @Command(name = "receipt", description = ["Show the receipt written by an example's setup."], mixinStandardHelpOptions = true)
    class ReceiptSubcommand : Callable<Int> {
        @Parameters(index = "0", arity = "0..1", description = ["Example name (optional when only one exists)."])
        var name: String? = null

        @Option(names = ["--output"], description = ["Output format: json|yaml (default: yaml)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val exampleName = name ?: singleExampleName() ?: return CommandSupport.EXIT_USAGE
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val receipt = ReceiptStore().read(exampleName)
                ?: run {
                    System.err.println("No receipt for '$exampleName'. Run `thoryn examples setup $exampleName` first.")
                    return CommandSupport.EXIT_USAGE
                }
            when (format) {
                OutputFormat.JSON -> Printers.json(receipt)
                else -> Printers.yaml(receipt)
            }
            return CommandSupport.EXIT_OK
        }
    }

    /**
     * SSO-2875 — `thoryn examples verify [name]` — re-check that the config a recipe run provisioned
     * still exists and matches, using the receipt's recorded resource ids. Exits non-zero on any drift.
     */
    @Command(name = "verify", description = ["Re-check that an example's provisioned config still matches its receipt."], mixinStandardHelpOptions = true)
    class VerifySubcommand : Callable<Int> {
        @Parameters(index = "0", arity = "0..1", description = ["Example name (optional when only one exists)."])
        var name: String? = null

        @Option(
            names = ["--recipe-dir"],
            description = [
                "Load the recipe from a checked-out directory (e.g. a thoryn-examples recipe) instead of " +
                    "the bundled catalog. Resolves <dir>/recipe.json, else <dir>/<name>/recipe.json.",
            ],
        )
        var recipeDir: File? = null

        @Option(names = ["--hub"], description = ["Override the hub base URL."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"], description = ["Override the gateway base URL."])
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val recipe = try {
                loadRecipe(name, recipeDir).recipe
            } catch (ex: RecipeException) {
                System.err.println("`verify` is only available for recipe-backed examples (${ex.message}).")
                return CommandSupport.EXIT_USAGE
            }
            val exampleName = recipe.id
            val receipt = ReceiptStore().read(exampleName)
                ?: run {
                    System.err.println("No receipt for '$exampleName'. Run `thoryn examples setup $exampleName` first.")
                    return CommandSupport.EXIT_USAGE
                }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val ctx = ExampleContext(
                hub = CommandSupport.resolveHub(hub, tokens),
                gateway = CommandSupport.resolveGateway(gateway, tokens),
                tokens = tokens,
                state = ExampleStateStore(),
            )
            val interpreter = RecipeInterpreter(ctx, recipe)
            val results = interpreter.verifyReceipt(receipt)
            results.forEach { println("  ${if (it.passed) "PASS" else "FAIL"}  ${it.assert} ${it.id ?: ""}") }

            // SSO-2878 — also verify the platform attestation signature offline (if the receipt is signed).
            val signature = interpreter.verifyAttestation(receipt)
            signature?.let { println("  ${it.name}  attestation signature (${receipt.attestation?.kid})") }

            val resourcesOk = results.all { it.passed }
            val signatureBad = signature == com.devnow.thoryn.cli.cmd.examples.recipe.Es256JwsVerifier.Status.INVALID
            val ok = resourcesOk && !signatureBad
            println()
            println(
                when {
                    results.isEmpty() && signature == null -> "Recipe '$exampleName' has no verify assertions and the receipt is unsigned."
                    ok -> "All checks passed."
                    signatureBad -> "The attestation signature is INVALID — the receipt was altered after signing."
                    else -> "Some checks failed — the provisioned config has drifted."
                },
            )
            return if (ok) CommandSupport.EXIT_OK else CommandSupport.EXIT_HTTP_ERROR
        }
    }

    /**
     * SSO-2874 — `thoryn examples catalog [--remote] [--tag <tag>]` — list the recipe catalog. Bundled
     * by default (offline, reproducible per CLI version); `--remote` fetches the public
     * thoryn-examples release and lists it ONLY after verifying its Ed25519 signature against the
     * pinned key.
     */
    @Command(name = "catalog", description = ["List the recipe catalog (bundled, or --remote from the signed release)."], mixinStandardHelpOptions = true)
    class CatalogSubcommand : Callable<Int> {
        @Option(names = ["--remote"], description = ["Fetch + verify the catalog from the public thoryn-examples release."])
        var remote: Boolean = false

        @Option(names = ["--tag"], description = ["Release tag to fetch (default: latest). Only with --remote."])
        var tag: String? = null

        override fun call(): Int {
            if (!remote) {
                val bundled = ExampleRegistry.all()
                println("Bundled recipes (this CLI version):")
                bundled.forEach { println("  ${it.name}  —  ${it.summary}") }
                println()
                println("Fetch the signed public catalog with:  thoryn examples catalog --remote")
                return CommandSupport.EXIT_OK
            }
            return try {
                val info = RecipeCatalog().update(tag)
                println("Verified catalog @ ${info.tag} (Ed25519 signature OK against the pinned key):")
                info.recipes.forEach { println("  ${it.id}  v${it.version}  —  ${it.summary}") }
                println()
                println("Cached at ${info.dir}. (This CLI applies its bundled recipes; a later phase runs a fetched one.)")
                CommandSupport.EXIT_OK
            } catch (ex: RecipeCatalogException) {
                System.err.println("Could not load the remote catalog: ${ex.message}")
                CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: Exception) {
                System.err.println("Could not reach the remote catalog (${CommandSupport.describeThrowable(ex)}).")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** SSO-2874 — `thoryn examples update [--tag <tag>]` — fetch + verify + cache the signed catalog. */
    @Command(name = "update", description = ["Fetch, verify, and cache the signed recipe catalog from thoryn-examples."], mixinStandardHelpOptions = true)
    class UpdateSubcommand : Callable<Int> {
        @Option(names = ["--tag"], description = ["Release tag to fetch (default: latest)."])
        var tag: String? = null

        override fun call(): Int = try {
            val info = RecipeCatalog().update(tag)
            println("Updated: fetched + verified ${info.recipes.size} recipe(s) at ${info.tag}.")
            println("Cached at ${info.dir}.")
            CommandSupport.EXIT_OK
        } catch (ex: RecipeCatalogException) {
            System.err.println("Update refused: ${ex.message}")
            CommandSupport.EXIT_HTTP_ERROR
        } catch (ex: Exception) {
            System.err.println("Update failed (${CommandSupport.describeThrowable(ex)}).")
            CommandSupport.EXIT_IO_ERROR
        }
    }

    /**
     * SSO-2876 — `thoryn examples apply [name]` — the GUIDED entry point: prompt for the recipe's
     * params, resolve a target environment (a sandbox by default when the recipe operates in an
     * existing workspace), show a dry-run plan, confirm, then provision. `--set k=v` and `--yes` make
     * it non-interactive (CI). Writes the same state + receipt as `setup`.
     */
    @Command(name = "apply", description = ["Guided: provision a recipe interactively (params, environment, dry-run, confirm)."], mixinStandardHelpOptions = true)
    class ApplySubcommand : Callable<Int> {
        @Parameters(index = "0", arity = "0..1", description = ["Recipe name (optional when only one exists)."])
        var name: String? = null

        @Option(names = ["--set"], description = ["Pre-set a parameter (repeatable): --set name=value. Skips its prompt."])
        var sets: Array<String> = emptyArray()

        @Option(names = ["--environment"], description = ["Target environment slug (skips the prompt)."])
        var environment: String? = null

        @Option(names = ["--yes"], description = ["Skip the confirmation prompt (for non-interactive use)."])
        var yes: Boolean = false

        @Option(
            names = ["--recipe-dir"],
            description = [
                "Load the recipe from a checked-out directory (e.g. a thoryn-examples recipe) instead of " +
                    "the bundled catalog. Resolves <dir>/recipe.json, else <dir>/<name>/recipe.json.",
            ],
        )
        var recipeDir: File? = null

        @Option(names = ["--hub"])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"])
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val loaded = try {
                loadRecipe(name, recipeDir)
            } catch (ex: RecipeException) {
                System.err.println("`apply` is only available for recipe-backed examples (${ex.message}).")
                return CommandSupport.EXIT_USAGE
            }
            val recipe = loaded.recipe
            val exampleName = recipe.id
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val ctx = ExampleContext(
                hub = CommandSupport.resolveHub(hub, tokens),
                gateway = CommandSupport.resolveGateway(gateway, tokens),
                tokens = tokens,
                state = ExampleStateStore(),
            )
            if (ctx.state.read(exampleName) != null) {
                ctx.warn("An existing '$exampleName' setup was found. Run `thoryn examples teardown $exampleName` first.")
                return CommandSupport.EXIT_OK
            }

            val overrides = resolveParams(recipe)
            val env = environment ?: resolveEnvironment(recipe, ctx)
            printPlan(recipe, overrides, env)
            if (!yes && !Prompt.confirm("Apply this recipe now?")) {
                println("Aborted — nothing was provisioned.")
                return CommandSupport.EXIT_OK
            }
            return try {
                val run = RecipeInterpreter(ctx, recipe, overrides = overrides, environmentSlug = env, source = loaded.source).setup()
                ctx.state.write(run.state)
                ReceiptStore().write(run.receipt)
                println()
                println("Applied. Receipt: thoryn examples receipt $exampleName   Next: thoryn examples run $exampleName")
                CommandSupport.EXIT_OK
            } catch (ex: RecipeException) {
                System.err.println("Could not apply '$exampleName': ${ex.message}")
                CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, ctx.gateway, System.err)
            }
        }

        private fun resolveParams(recipe: Recipe): Map<String, String> {
            val preset = sets.mapNotNull { s -> s.split("=", limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
            val resolved = LinkedHashMap<String, String>()
            recipe.params.forEach { p ->
                val paramName = p["name"].asString()
                if (preset.containsKey(paramName)) {
                    resolved[paramName] = preset.getValue(paramName)
                    return@forEach
                }
                val default = p["default"]?.takeIf { !it.isNull }?.asString()
                val promptText = p["prompt"]?.asString() ?: paramName
                val value = Prompt.ask(promptText, default)
                if (value.isNotEmpty()) resolved[paramName] = value
            }
            return resolved
        }

        /** A sandbox by default when the recipe runs in an existing workspace; null (production plane)
         *  when it creates its own workspace (only production exists then). */
        private fun resolveEnvironment(recipe: Recipe, ctx: ExampleContext): String? {
            val createsWorkspace = recipe.steps.any { it["action"]?.asString() == "hub.createWorkspace" }
            if (createsWorkspace) {
                ctx.info("This recipe creates its own workspace; its resources go to that workspace's production environment.")
                return null
            }
            val envs = runCatching { ctx.gatewayClient().listEnvironments()["environments"]?.toList().orEmpty() }.getOrDefault(emptyList())
            if (envs.isEmpty()) return null
            val slugs = envs.mapNotNull { it["slug"]?.asString() }
            val defaultEnv = envs.firstOrNull { it["kind"]?.asString() == "sandbox" && it["suspended"]?.asBoolean() != true }
                ?.get("slug")?.asString() ?: ThorynConfig.PRODUCTION_ENV_SLUG
            ctx.info("Environments: ${slugs.joinToString(", ")}")
            return Prompt.ask("Target environment", defaultEnv).ifEmpty { null }
        }

        private fun printPlan(recipe: Recipe, overrides: Map<String, String>, env: String?) {
            println()
            println("Plan — recipe ${recipe.id} v${recipe.version}")
            if (overrides.isNotEmpty()) {
                println("  parameters:")
                overrides.forEach { (k, v) -> println("    $k = $v") }
            }
            println("  environment: ${env ?: "production (default plane)"}")
            println("  steps:")
            recipe.steps.forEach { s ->
                println("    - ${s["action"]?.asString()}${s["description"]?.takeIf { !it.isNull }?.let { " — ${it.asString()}" } ?: ""}")
            }
        }
    }

    /**
     * SSO-2876 — `thoryn examples share [name] [--output <file>]` — export the run's receipt (which is
     * already secret-free: server-minted secrets are file refs, never values) to a file or stdout, and
     * note whether it carries a platform attestation (verifiable offline).
     */
    @Command(name = "share", description = ["Export a run's receipt (secret-free) to a file or stdout."], mixinStandardHelpOptions = true)
    class ShareSubcommand : Callable<Int> {
        @Parameters(index = "0", arity = "0..1", description = ["Recipe name (optional when only one exists)."])
        var name: String? = null

        @Option(names = ["--output"], description = ["Write to this file instead of stdout."])
        var output: File? = null

        override fun call(): Int {
            val exampleName = name ?: singleExampleName() ?: return CommandSupport.EXIT_USAGE
            val receipt = ReceiptStore().read(exampleName)
                ?: run {
                    System.err.println("No receipt for '$exampleName'. Run `thoryn examples apply $exampleName` first.")
                    return CommandSupport.EXIT_USAGE
                }
            val json = jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(receipt)
            val out = output
            if (out != null) {
                out.writeText(json + "\n")
                println("Wrote receipt to ${out.path}.")
            } else {
                println(json)
            }
            System.err.println(
                if (receipt.attestation != null) {
                    "This receipt is platform-signed (kid ${receipt.attestation.kid}); a recipient can verify it offline."
                } else {
                    "Note: this receipt is NOT platform-signed (the platform was unreachable at apply time)."
                },
            )
            return CommandSupport.EXIT_OK
        }
    }

    /** SSO-2967 — a loaded recipe plus its provenance (recorded on the receipt). */
    internal data class LoadedRecipe(val recipe: Recipe, val source: String)

    internal companion object {
        /** The sole example's name when exactly one is bundled, else null (caller prints usage). */
        fun singleExampleName(): String? = ExampleRegistry.all().singleOrNull()?.name

        /**
         * SSO-2967 — load the recipe an `apply` / `verify` / `teardown` invocation targets, either from a
         * checked-out [recipeDir] (a `thoryn-examples` recipe, run WITHOUT bundling) or the bundled
         * catalog. An external recipe is parsed by the SAME model + interpreter as a bundled one, so the
         * interpreter's closed action allowlist still gates execution. Throws [RecipeException] for every
         * failure mode (unknown bundled id, missing/invalid external file, or an ambiguous absent name).
         */
        fun loadRecipe(name: String?, recipeDir: File?): LoadedRecipe {
            if (recipeDir != null) {
                val file = Recipe.resolveExternalRecipeFile(recipeDir.toPath(), name)
                return LoadedRecipe(Recipe.loadFromFile(file), "recipe-dir:${file.toAbsolutePath()}")
            }
            val id = name ?: singleExampleName()
                ?: throw RecipeException("no recipe name given and more than one is bundled — specify one by name")
            return LoadedRecipe(Recipe.load(id), "bundled")
        }
    }

    /**
     * Shared plumbing for the setup/run/teardown subcommands: resolve the session
     * hosts (SSO-2827 precedence), pick the example, build the context, and invoke
     * the requested lifecycle step.
     */
    abstract class LifecycleSubcommand internal constructor(
        private val action: (Example, ExampleContext) -> Int,
    ) : Callable<Int> {

        @Parameters(index = "0", arity = "0..1", description = ["Example name (optional when only one exists)."])
        var name: String? = null

        @Option(names = ["--hub"], description = ["Override the hub base URL. Defaults to the hub you signed into, else http://localhost:54702."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"], description = ["Override the gateway base URL. Defaults to the gateway you signed into, else http://localhost:8991."])
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val example = resolveExample() ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val ctx = ExampleContext(
                hub = CommandSupport.resolveHub(hub, tokens),
                gateway = CommandSupport.resolveGateway(gateway, tokens),
                tokens = tokens,
                state = ExampleStateStore(),
            )
            return action(example, ctx)
        }

        private fun resolveExample(): Example? {
            val all = ExampleRegistry.all()
            val chosen = when {
                name != null -> ExampleRegistry.byName(name!!)
                all.size == 1 -> all.first()
                else -> null
            }
            if (chosen == null) {
                System.err.println(
                    if (name != null) "Unknown example '$name'." else "Multiple examples exist — specify one by name.",
                )
                System.err.println("Available: ${all.joinToString(", ") { it.name }}")
            }
            return chosen
        }
    }
}
