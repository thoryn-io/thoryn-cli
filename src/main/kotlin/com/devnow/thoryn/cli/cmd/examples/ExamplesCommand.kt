package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.recipe.Recipe
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeException
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeInterpreter
import com.devnow.thoryn.cli.cmd.examples.recipe.ReceiptStore
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
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

    @Command(name = "teardown", description = ["Remove what an example's setup created (best-effort)."], mixinStandardHelpOptions = true)
    class TeardownSubcommand : LifecycleSubcommand({ ex, ctx -> ex.teardown(ctx) })

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

        @Option(names = ["--hub"], description = ["Override the hub base URL."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"], description = ["Override the gateway base URL."])
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        override fun call(): Int {
            val exampleName = name ?: singleExampleName() ?: return CommandSupport.EXIT_USAGE
            val receipt = ReceiptStore().read(exampleName)
                ?: run {
                    System.err.println("No receipt for '$exampleName'. Run `thoryn examples setup $exampleName` first.")
                    return CommandSupport.EXIT_USAGE
                }
            val recipe = try {
                Recipe.load(exampleName)
            } catch (ex: RecipeException) {
                System.err.println("`verify` is only available for recipe-backed examples (${ex.message}).")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val ctx = ExampleContext(
                hub = CommandSupport.resolveHub(hub, tokens),
                gateway = CommandSupport.resolveGateway(gateway, tokens),
                tokens = tokens,
                state = ExampleStateStore(),
            )
            val results = RecipeInterpreter(ctx, recipe).verifyReceipt(receipt)
            if (results.isEmpty()) {
                println("Recipe '$exampleName' has no verify assertions.")
                return CommandSupport.EXIT_OK
            }
            results.forEach { println("  ${if (it.passed) "PASS" else "FAIL"}  ${it.assert} ${it.id ?: ""}") }
            val allPassed = results.all { it.passed }
            println()
            println(if (allPassed) "All ${results.size} check(s) passed." else "Some checks failed — the provisioned config has drifted.")
            return if (allPassed) CommandSupport.EXIT_OK else CommandSupport.EXIT_HTTP_ERROR
        }
    }

    internal companion object {
        /** The sole example's name when exactly one is bundled, else null (caller prints usage). */
        fun singleExampleName(): String? = ExampleRegistry.all().singleOrNull()?.name
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
