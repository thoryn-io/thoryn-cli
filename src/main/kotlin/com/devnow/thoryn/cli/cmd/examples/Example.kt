package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.cmd.examples.recipe.Recipe
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeExample
import com.devnow.thoryn.cli.auth.TokenExchangeFlow
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import java.io.PrintStream
import java.net.http.HttpClient

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

    /**
     * SSO-2836 — a gateway client authenticated with the **workspace-scoped provisioning token**
     * that `POST /account/workspace` returns for a just-created workspace (ADR
     * `2026-09-01-workspace-create-returns-scoped-provisioning-token`). Preferred over
     * [tenantGatewayClient]: the hub minted this token for the founder at create time, so it carries
     * `tnt=<new workspace>` directly with NO client-side token-exchange — sidestepping the
     * public-client / membership / refresh-clobber friction of the switch. Resources are created
     * UNDER the workspace, exactly as with the switch.
     */
    fun provisioningGatewayClient(provisioningToken: String, environmentSlug: String? = null): ProductApiClient =
        // SSO-2841: construct the client DIRECTLY with the provisioning token — do NOT route through
        // CommandSupport.client, whose ensureFresh() "prefers the store as the source of truth"
        // (SSO-2834) and would DISCARD this token, replacing it with the logged-in SESSION token
        // (tnt=default) from the keychain. That silently registered the workspace's OAuth client under
        // the `default` tenant, so sign-in at the workspace issuer 400'd. This token is a distinct,
        // one-shot, non-refreshable provisioning credential; it must be sent verbatim.
        // SSO-2876: [environmentSlug] rides as X-Thoryn-Environment so a recipe provisions into the
        // caller-chosen environment (e.g. a sandbox) rather than the production plane.
        ProductApiClient(gateway = gateway, tokens = Tokens(accessToken = provisioningToken), environmentSlug = environmentSlug)

    /**
     * SSO-2831 — a gateway client scoped to the target workspace named by [tenantIssuer]
     * (`https://{slug}.hub.<domain>`). Silently exchanges the session token for a token in that
     * tenant (RFC 8693, the same mechanism as `thoryn workspace switch`), so resources are created
     * UNDER the workspace — not the caller's login tenant. Without this the RP client would be
     * registered in the login tenant while sign-in runs against the workspace's issuer, and the
     * authorize call fails `invalid_request` (client_id not found in that tenant).
     *
     * **Fallback path** (SSO-2836): the create response now returns a provisioning token, so
     * [provisioningGatewayClient] is the preferred route. This token-exchange path stays as the
     * fallback for a hub that predates the provisioning token (the field is absent on the response).
     */
    fun tenantGatewayClient(tenantIssuer: String, environmentSlug: String? = null): ProductApiClient {
        val exchanged = TokenExchangeFlow(
            issuer = hub,
            clientId = ThorynConfig.DEFAULT_CLIENT_ID,
            clientSecret = null,
            subjectToken = tokens.accessToken,
            targetResource = tenantIssuer,
            sender = HttpSender { request, handler -> HttpClient.newHttpClient().send(request, handler) },
        ).run()
        // SSO-2876 — send the exchanged workspace token VERBATIM (as the provisioning path does; do NOT
        // route through ensureFresh, which would read the base session token from the store and discard
        // this one — the SSO-2841 trap) and ride the caller-chosen environment as X-Thoryn-Environment.
        return ProductApiClient(gateway = gateway, tokens = exchanged, environmentSlug = environmentSlug)
    }

    /** Emit a numbered step heading so the walkthrough reads as a sequence. */
    fun step(n: Int, message: String) = out.println("\n[$n] $message")

    fun info(message: String) = out.println("    $message")

    fun warn(message: String) = err.println("    ! $message")
}

/** SSO-2830 — the in-repo registry of runnable examples. Add new examples here. */
internal object ExampleRegistry {

    /**
     * SSO-2873 — when the recipe engine is enabled, `simple-signin` is provisioned by the declarative
     * recipe interpreter (reading `examples/recipes/simple-signin/recipe.json`) instead of the
     * compiled [SimpleSigninExample.setup]. Behind a flag so the compiled path stays the default until
     * the recipe path has soaked; the browser `run` flow is delegated to the compiled example either
     * way. Enable with `THORYN_RECIPE_ENGINE=1` (or `-Dthoryn.recipeEngine=1`).
     */
    private fun recipeEngineEnabled(): Boolean =
        System.getenv("THORYN_RECIPE_ENGINE")?.isNotBlank() == true ||
            System.getProperty("thoryn.recipeEngine")?.isNotBlank() == true

    private fun examples(): List<Example> =
        if (recipeEngineEnabled()) {
            listOf(RecipeExample(Recipe.load("simple-signin"), SimpleSigninExample()))
        } else {
            listOf(SimpleSigninExample())
        }

    fun all(): List<Example> = examples()

    fun byName(name: String): Example? = examples().firstOrNull { it.name == name }
}
