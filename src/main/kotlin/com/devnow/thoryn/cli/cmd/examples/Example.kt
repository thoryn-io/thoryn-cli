package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import java.io.PrintStream

/**
 * SSO-2830 — a runnable, in-boundary product example.
 *
 * Each example provisions a real configuration in the caller's OWN account using
 * only supported product workflows (never DB seeds or demo endpoints — the
 * product-boundary rule in CLAUDE.md), lets the caller see the real interaction,
 * and tears down what it created. The lifecycle is deliberately three explicit
 * verbs so a user can inspect the account state between steps:
 *
 *   thoryn examples <name> setup      # provision workspace + client, print live state
 *   thoryn examples <name> run        # drive the real interaction (opens a browser)
 *   thoryn examples <name> teardown   # remove what setup created (best-effort)
 */
internal interface Example {
    /** Stable identifier used on the command line, e.g. `simple-signin`. */
    val name: String

    /** One-line description shown by `thoryn examples list`. */
    val summary: String

    fun setup(ctx: ExampleContext): Int

    fun run(ctx: ExampleContext): Int

    fun teardown(ctx: ExampleContext): Int
}

/**
 * Shared context handed to an [Example]: the resolved hub + gateway, the caller's
 * session token, the on-disk state store, and the output streams. The hub surface
 * (`/account/workspace[s]`) and the gateway surface (`/api/v1/applications`) use
 * the same [ProductApiClient] against different base URLs — mirroring the
 * `workspace` vs `clients` command trees.
 */
internal class ExampleContext(
    val hub: String,
    val gateway: String,
    val tokens: Tokens,
    val state: ExampleStateStore,
    val out: PrintStream = System.out,
    val err: PrintStream = System.err,
) {
    /** Client for the hub `/account/[**]` surface (workspaces). */
    fun hubClient(): ProductApiClient = CommandSupport.client(hub, tokens)

    /** Client for the gateway → product-api surface (clients, federation). */
    fun gatewayClient(): ProductApiClient = CommandSupport.client(gateway, tokens)

    /** Emit a numbered step heading so the walkthrough reads as a sequence. */
    fun step(n: Int, message: String) = out.println("\n[$n] $message")

    fun info(message: String) = out.println("    $message")

    fun warn(message: String) = err.println("    ! $message")
}

/** SSO-2830 — the in-repo registry of runnable examples. Add new examples here. */
internal object ExampleRegistry {
    private val examples: List<Example> = listOf(
        SimpleSigninExample(),
    )

    fun all(): List<Example> = examples

    fun byName(name: String): Example? = examples.firstOrNull { it.name == name }
}
