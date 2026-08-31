package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.net.URI
import java.util.concurrent.Callable

/**
 * `thoryn workspace ...` — workspace (hub tenant) create / list / switch.
 *
 * **Surface.** The workspace surface lives on the HUB (`/account/workspace[s]`),
 * gated by `SCOPE_openid` (any signed-in user) and NOT routed through the
 * api-gateway. These commands therefore call the hub directly via `--hub`
 * (defaulting to the same value as the login `--issuer`), not the gateway.
 *
 *  - `create` — POST hub `/account/workspace`, then register the new tenant in
 *    product-api (`POST /tenants` via the gateway) so subsequent product-api
 *    calls find it. Mirrors the console BFF's two-step orchestration.
 *  - `list`   — GET hub `/account/workspaces`.
 *  - `switch` — there is no server-side "switch" for a bearer-token CLI: a
 *    switch is a re-authentication against the tenant's hub subdomain. This
 *    subcommand validates the workspace, records the selection locally, and
 *    prints the exact `thoryn login --issuer <tenant-hub>` line to run. No
 *    secret is involved.
 *
 * Scope: `SCOPE_openid` only — the default `thoryn login` already requests it.
 */
@Command(
    name = "workspace",
    description = ["Create, list, and switch workspaces (hub tenants)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        WorkspaceCommand.CreateSubcommand::class,
        WorkspaceCommand.ListSubcommand::class,
        WorkspaceCommand.SwitchSubcommand::class,
    ],
)
class WorkspaceCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn workspace <subcommand>")
        System.err.println("Subcommands: create | list | switch")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn workspace list` */
    @Command(name = "list", description = ["List the workspaces you own."], mixinStandardHelpOptions = true)
    class ListSubcommand : Callable<Int> {

        @Option(names = ["--hub"], description = ["Override the hub base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_HUB)
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(hub, tokens)
            return try {
                val body = client.listWorkspaces()
                CommandSupport.emitList(format, body, LIST_HEADERS, ::workspaceRow)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                // The /account surface is gated by SCOPE_openid; a 403 here is not
                // a tenant-scope problem, so no --scope hint is offered.
                CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /**
     * `thoryn workspace create --slug <slug> --display-name <name>`
     *
     * Two-step, mirroring the console BFF: create the hub workspace, then
     * register it in product-api. If the product-api registration fails the
     * command reports it but the hub workspace already exists (the registration
     * is idempotent — re-running `create` with the same slug is safe).
     */
    @Command(name = "create", description = ["Create a new workspace (hub tenant) and register it in product-api."], mixinStandardHelpOptions = true)
    class CreateSubcommand : Callable<Int> {

        @Option(names = ["--slug"], description = ["Subdomain slug: [a-z0-9-]{3,63}."], required = true)
        lateinit var slug: String

        @Option(names = ["--display-name"], description = ["Human-readable workspace name."], required = true)
        lateinit var displayName: String

        @Option(names = ["--hub"], description = ["Override the hub base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_HUB)
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--gateway"], description = ["Override the gateway base URL for the product-api tenant registration (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val hubClient = CommandSupport.client(hub, tokens)

            // Step 1: create the hub workspace.
            val workspace = try {
                hubClient.createWorkspace(mapOf("slug" to slug, "displayName" to displayName))
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                return CommandSupport.EXIT_IO_ERROR
            }

            val tenantId = workspace["tenantId"]?.asString()
            val createdSlug = workspace["slug"]?.asString() ?: slug

            // Step 2: register the tenant in product-api (gateway-routed). Best
            // effort — surfaced as a warning, not a hard failure, because the hub
            // workspace is created and `POST /tenants` is idempotent on retry.
            var registered = false
            if (tenantId != null) {
                try {
                    CommandSupport.client(gateway, tokens)
                        .registerTenant(mapOf("tenantId" to tenantId, "slug" to createdSlug))
                    registered = true
                } catch (ex: ProductApiException) {
                    System.err.println(
                        "Warning: hub workspace created but product-api registration failed " +
                            "(${ex.errorCode ?: "HTTP ${ex.httpStatus}"}). Re-run `thoryn workspace create` " +
                            "with the same slug to retry — registration is idempotent.",
                    )
                } catch (ex: Exception) {
                    System.err.println(
                        "Warning: hub workspace created but product-api registration failed (${ex.message}). " +
                            "Re-run `thoryn workspace create` with the same slug to retry.",
                    )
                }
            }

            // Merge the CLI-synthesized `productApiRegistered` flag into the
            // response body so it appears consistently across table/json/yaml
            // (emitRecord's json/yaml branches serialise the body verbatim).
            if (workspace.isObject) {
                (workspace as tools.jackson.databind.node.ObjectNode).put("productApiRegistered", registered)
            }
            CommandSupport.emitRecord(
                format = format,
                body = workspace,
                recordFields = { node -> workspaceRecordFields(node) + ("productApiRegistered" to registered) },
            )
            // Tell the user how to switch into the new workspace.
            val tenantHub = WorkspaceTenantHost.tenantIssuer(hub, createdSlug)
            if (tenantHub != null && format == OutputFormat.TABLE) {
                System.err.println(
                    "To use this workspace, switch into it:  thoryn login --issuer $tenantHub",
                )
            }
            return CommandSupport.EXIT_OK
        }
    }

    /**
     * `thoryn workspace switch <slug>`
     *
     * Validates the workspace by listing the caller's workspaces, records the
     * selection locally, and prints the `thoryn login --issuer <tenant-hub>`
     * line that re-authenticates into it. The CLI cannot perform the OIDC
     * redirect itself (no browser session); this is the honest thin-client
     * equivalent of the console's `loginUrl` redirect.
     */
    @Command(name = "switch", description = ["Select a workspace to operate on (prints the re-auth command)."], mixinStandardHelpOptions = true)
    class SwitchSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Workspace slug to switch into."])
        lateinit var slug: String

        @Option(names = ["--hub"], description = ["Override the hub base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_HUB)
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--output"])
        var outputRaw: String? = null

        /** Test seam: where the selected-workspace marker is persisted. */
        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            val client = CommandSupport.client(hub, tokens)

            val workspaces = try {
                client.listWorkspaces()
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                System.err.println("Request failed: ${ex.message}")
                return CommandSupport.EXIT_IO_ERROR
            }

            val match = workspaces.toList().firstOrNull { it["slug"]?.asString() == slug }
            if (match == null) {
                System.err.println("Error: no workspace with slug '$slug' found for your account.")
                System.err.println("Run `thoryn workspace list` to see your workspaces.")
                return CommandSupport.EXIT_HTTP_ERROR
            }

            val tenantId = match["tenantId"]?.asString() ?: ""
            val tenantHub = WorkspaceTenantHost.tenantIssuer(hub, slug)
            if (tenantHub == null) {
                System.err.println("Error: could not derive the tenant hub URL from '$hub'.")
                return CommandSupport.EXIT_IO_ERROR
            }

            store.write(SelectedWorkspace(tenantId = tenantId, slug = slug, tenantHubIssuer = tenantHub))

            val loginLine = "thoryn login --issuer $tenantHub"
            CommandSupport.emitValue(
                format,
                mapOf(
                    "selected" to slug,
                    "tenantId" to tenantId,
                    "tenantHubIssuer" to tenantHub,
                    "reauthCommand" to loginLine,
                ),
                "Selected workspace '$slug'. Re-authenticate to activate it:\n  $loginLine",
            )
            return CommandSupport.EXIT_OK
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf(
            "slug", "displayName", "tenantId", "archived",
        )

        internal fun workspaceRow(node: JsonNode): List<Any?> = listOf(
            node["slug"]?.asString(),
            node["displayName"]?.asString(),
            node["tenantId"]?.asString(),
            node["archived"]?.asString(),
        )

        internal fun workspaceRecordFields(node: JsonNode): List<Pair<String, Any?>> = listOf(
            "slug" to node["slug"]?.asString(),
            "displayName" to node["displayName"]?.asString(),
            "tenantId" to node["tenantId"]?.asString(),
            "archived" to node["archived"]?.asString(),
            "loginUrl" to node["loginUrl"]?.asString(),
        )
    }
}

/**
 * Derives a tenant's hub issuer URL (`{slug}.{hubHost}`) from the base hub URL,
 * matching the BFF's `TenantAwareClientRegistrationRepository.withTenantHost`
 * rewrite (scheme/port/path preserved, host prefixed with the slug). Used to
 * print the `thoryn login --issuer …` line for a workspace switch.
 */
internal object WorkspaceTenantHost {

    fun tenantIssuer(hubBaseUrl: String, slug: String): String? {
        return try {
            val parsed = URI(hubBaseUrl.trimEnd('/'))
            val host = parsed.host ?: return null
            val tenantHost = "$slug.$host"
            URI(parsed.scheme, parsed.userInfo, tenantHost, parsed.port, parsed.path, parsed.query, parsed.fragment)
                .toString()
                .trimEnd('/')
        } catch (_: Exception) {
            null
        }
    }
}
