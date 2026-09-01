package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.BrowserLauncher
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.config.ThorynConfig
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * SSO-2830 — "simple user password sign-in" example.
 *
 * setup:    create a dedicated example workspace (real `POST /account/workspace`,
 *           which clones the tenant's default identity-service federation member),
 *           register it in product-api, then register a public loopback
 *           authorization-code RP (the hub auto-attaches the identity provider,
 *           SSO-2815). Prints the live workspace + client state.
 * run:      stand up the ephemeral local relying party, open the browser, and let
 *           the user register + sign in on the real hosted screens and land on the
 *           protected page. Prints the resulting ID-token claims.
 * teardown: delete the RP client. Reports what it cannot remove — the workspace and
 *           the registered user have no customer-plane delete API yet (SSO-2831).
 */
internal class SimpleSigninExample : Example {
    override val name = "simple-signin"
    override val summary = "Provision a workspace + app, then register & sign a user in to a protected page."

    override fun setup(ctx: ExampleContext): Int {
        ctx.state.read(name)?.let { existing ->
            ctx.warn("An existing '$name' setup was found (workspace '${existing.workspaceSlug}').")
            ctx.warn("Run `thoryn examples $name teardown` first to start fresh, or `run` to use it.")
            return CommandSupport.EXIT_OK
        }

        val slug = "ex-signin-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8)
        val displayName = "Sign-in Example"

        ctx.step(1, "Creating a dedicated example workspace '$slug' (real hub workflow)…")
        val tenantId: String
        try {
            val ws = ctx.hubClient().createWorkspace(mapOf("slug" to slug, "displayName" to displayName))
            tenantId = ws["tenantId"]?.asString()
                ?: run { ctx.warn("Workspace created but no tenantId was returned; cannot continue."); return CommandSupport.EXIT_IO_ERROR }
            ctx.info("workspace: slug=$slug  tenantId=$tenantId")
        } catch (ex: ProductApiException) {
            ctx.warn("Could not create workspace: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}${ex.errorDescription?.let { " — $it" } ?: ""}")
            return CommandSupport.EXIT_HTTP_ERROR
        } catch (ex: Exception) {
            return CommandSupport.renderRequestFailure(ex, ctx.hub, ctx.err)
        }

        // Best-effort product-api tenant registration (idempotent) — mirrors `workspace create`.
        try {
            ctx.gatewayClient().registerTenant(mapOf("tenantId" to tenantId, "slug" to slug))
        } catch (ex: Exception) {
            ctx.warn("product-api tenant registration did not complete (${CommandSupport.describeThrowable(ex)}); continuing — it is idempotent.")
        }

        ctx.step(2, "Registering a public loopback OAuth client for the local example app…")
        val redirectUri = "http://127.0.0.1/callback"
        val clientId: String
        try {
            val app = ctx.gatewayClient().createApplication(
                mapOf(
                    "displayName" to "Sign-in Example App",
                    "redirectUris" to listOf(redirectUri),
                    "clientType" to "public",
                    "grantTypes" to listOf("authorization_code"),
                    "scopes" to listOf("openid", "profile", "email"),
                ),
            )
            clientId = (app["clientId"] ?: app["client_id"])?.asString()
                ?: run { ctx.warn("Client created but no clientId was returned; cannot continue."); return CommandSupport.EXIT_IO_ERROR }
            ctx.info("client:    clientId=$clientId  redirectUri=$redirectUri (loopback, port-agnostic)")
        } catch (ex: ProductApiException) {
            ctx.warn("Could not create the OAuth client: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}${ex.errorDescription?.let { " — $it" } ?: ""}")
            return CommandSupport.EXIT_HTTP_ERROR
        } catch (ex: Exception) {
            return CommandSupport.renderRequestFailure(ex, ctx.gateway, ctx.err)
        }

        val tenantIssuer = ThorynConfig.tenantIssuer(ctx.hub, slug)
        val identityHost = ThorynConfig.tenantIdentityHost(ctx.hub, slug)
        ctx.state.write(
            ExampleState(
                example = name,
                workspaceSlug = slug,
                tenantId = tenantId,
                clientId = clientId,
                redirectUri = redirectUri,
                tenantIssuer = tenantIssuer,
                identityHost = identityHost,
            ),
        )

        ctx.out.println()
        ctx.out.println("Setup complete. Live state:")
        ctx.info("workspace slug : $slug")
        ctx.info("tenant issuer  : $tenantIssuer")
        ctx.info("sign-in host   : $identityHost")
        ctx.info("app client id  : $clientId")
        ctx.out.println()
        ctx.out.println("Next:  thoryn examples $name run")
        return CommandSupport.EXIT_OK
    }

    override fun run(ctx: ExampleContext): Int {
        val state = ctx.state.read(name)
            ?: run { ctx.warn("No '$name' setup found. Run `thoryn examples $name setup` first."); return CommandSupport.EXIT_USAGE }
        val tenantIssuer = state.tenantIssuer
            ?: run { ctx.warn("Stored state is missing the tenant issuer; re-run setup."); return CommandSupport.EXIT_USAGE }
        val clientId = state.clientId
            ?: run { ctx.warn("Stored state is missing the client id; re-run setup."); return CommandSupport.EXIT_USAGE }

        val signedIn = CountDownLatch(1)
        val rp = ExampleRelyingParty(
            tenantIssuer = tenantIssuer,
            clientId = clientId,
            onSignedIn = { claims ->
                ctx.out.println()
                ctx.out.println("✓ Signed in — the protected page rendered. ID-token claims:")
                claims.entries.sortedBy { it.key }.forEach { (k, v) -> ctx.info("$k = $v") }
                signedIn.countDown()
            },
        ).start()

        try {
            ctx.step(1, "Started the local example app at ${rp.baseUrl}")
            ctx.info("It is registered as client $clientId (loopback redirect ${rp.redirectUri}).")
            ctx.step(2, "Opening your browser. Register a new user, then sign in.")
            ctx.info("If it doesn't open, visit: ${rp.baseUrl}")
            ctx.info("Sign-in happens on the real hosted screens at ${state.identityHost}.")
            BrowserLauncher.open(rp.baseUrl)

            ctx.out.println()
            ctx.out.println("Waiting for you to sign in and reach the protected page (5 min)…")
            val ok = signedIn.await(5, TimeUnit.MINUTES)
            return if (ok) {
                ctx.out.println()
                ctx.out.println("Done. When finished:  thoryn examples $name teardown")
                CommandSupport.EXIT_OK
            } else {
                ctx.warn("Timed out waiting for sign-in. Re-run `thoryn examples $name run` to try again.")
                CommandSupport.EXIT_IO_ERROR
            }
        } finally {
            rp.stop()
        }
    }

    override fun teardown(ctx: ExampleContext): Int {
        val state = ctx.state.read(name)
            ?: run { ctx.info("Nothing to tear down — no '$name' state found."); return CommandSupport.EXIT_OK }

        var clientDeleted = false
        state.clientId?.let { clientId ->
            ctx.step(1, "Deleting the example OAuth client $clientId…")
            try {
                ctx.gatewayClient().deleteApplication(clientId, confirmSlug = state.workspaceSlug)
                clientDeleted = true
                ctx.info("client deleted.")
            } catch (ex: ProductApiException) {
                ctx.warn("Could not delete client $clientId: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}. Remove it via `thoryn clients delete`.")
            } catch (ex: Exception) {
                ctx.warn("Could not delete client $clientId (${CommandSupport.describeThrowable(ex)}).")
            }
        }

        // SSO-2831 — no customer-plane API to delete a workspace or a tenant user yet.
        ctx.out.println()
        ctx.out.println("Partial teardown (a known product gap, SSO-2831):")
        ctx.info("${if (clientDeleted) "removed" else "attempted"} the OAuth client.")
        ctx.info("workspace '${state.workspaceSlug}' and any user you registered CANNOT be removed via the")
        ctx.info("customer plane today — they remain in your account. This is tracked as SSO-2831.")

        ctx.state.clear(name)
        return CommandSupport.EXIT_OK
    }
}
