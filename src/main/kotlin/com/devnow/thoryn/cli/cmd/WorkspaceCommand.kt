package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.TokenExchangeException
import com.devnow.thoryn.cli.auth.TokenExchangeFlow
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.net.URI
import java.net.http.HttpClient
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
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
        WorkspaceCommand.ArchiveSubcommand::class,
        WorkspaceCommand.ReactivateSubcommand::class,
        WorkspaceCommand.HardDeleteSubcommand::class,
    ],
)
class WorkspaceCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn workspace <subcommand>")
        System.err.println("Subcommands: create | list | switch | archive | reactivate | hard-delete")
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
            hub = CommandSupport.resolveHub(hub, tokens) // SSO-2827 — default to the hub you signed into
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
                CommandSupport.renderRequestFailure(ex, hub)
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
            // SSO-2827 — default the hub + gateway to the ones recorded at login.
            hub = CommandSupport.resolveHub(hub, tokens)
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val hubClient = CommandSupport.client(hub, tokens)

            // Step 1: create the hub workspace.
            val workspace = try {
                hubClient.createWorkspace(mapOf("slug" to slug, "displayName" to displayName))
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                return CommandSupport.renderRequestFailure(ex, hub)
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
                        "Warning: hub workspace created but product-api registration failed " +
                            "(could not reach $gateway — ${CommandSupport.describeThrowable(ex)}). " +
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
    @Command(name = "switch", description = ["Switch into a workspace you belong to (silent — no browser)."], mixinStandardHelpOptions = true)
    class SwitchSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Workspace slug to switch into."])
        lateinit var slug: String

        @Option(names = ["--hub"], description = ["Override the hub base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_HUB)
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--client-id"], description = ["OAuth client id used for the switch exchange (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_CLIENT_ID)
        var clientId: String = ThorynConfig.DEFAULT_CLIENT_ID

        @Option(names = ["--client-secret-file"], description = ["File with the client secret for a confidential client. Public clients omit it. Falls back to THORYN_CLIENT_SECRET."])
        var clientSecretFile: String? = null

        @Option(names = ["--output"])
        var outputRaw: String? = null

        /** Test seam: where the selected-workspace marker is persisted. */
        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        /** Test seam: HTTP sender for the token exchange. */
        internal var sender: HttpSender = HttpSender { request, handler ->
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().send(request, handler)
        }

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens) // SSO-2827 — the hub you signed into (also feeds the token exchange below)
            val client = CommandSupport.client(hub, tokens)

            val workspaces = try {
                client.listWorkspaces()
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                return CommandSupport.renderRequestFailure(ex, hub)
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

            // SSO-2818 — silent cross-tenant switch: exchange the current token for a token in the
            // target tenant (no browser). The hub grants it only if we're an active member of it.
            //
            // SSO-2863 — this exchange now VALIDATES membership only; its result is discarded. The
            // switch must NOT persist the exchanged token as the session — that token carries no
            // refresh token, so it would kill the CLI's refresh ability and die at ~15 minutes.
            // Instead we record the selection (below) and `CommandSupport.gatewayClient` mints a
            // switched token from the refreshable base session on demand.
            val secret = clientSecretFile
                ?.let { runCatching { Files.readString(Path.of(it)).trim() }.getOrNull()?.takeIf(String::isNotBlank) }
                ?: System.getenv("THORYN_CLIENT_SECRET")?.takeIf { it.isNotBlank() }
            try {
                TokenExchangeFlow(
                    issuer = hub,
                    clientId = clientId,
                    clientSecret = secret,
                    subjectToken = tokens.accessToken,
                    targetResource = tenantHub,
                    sender = sender,
                ).run()
            } catch (ex: TokenExchangeException) {
                System.err.println("Could not switch to '$slug': ${ex.oauthError}.")
                if (ex.oauthError == "invalid_grant") {
                    System.err.println("You may not be a member of '$slug', or your session expired. Run `thoryn login` and retry.")
                } else if (ex.oauthError == "unauthorized_client") {
                    System.err.println("Client '$clientId' is not permitted to switch workspaces (allow_token_exchange).")
                } else if (ex.oauthError == "unknown") {
                    // The hub returned a non-OAuth-shaped error — surface the raw status + body so the
                    // failure is diagnosable instead of an opaque "unknown".
                    System.err.println("The hub returned HTTP ${ex.status ?: "?"}: ${ex.bodySnippet ?: "(empty body)"}")
                }
                return CommandSupport.EXIT_HTTP_ERROR
            } catch (ex: Exception) {
                System.err.println("Could not switch to '$slug': ${CommandSupport.describeThrowable(ex)}")
                return CommandSupport.EXIT_IO_ERROR
            }

            store.write(SelectedWorkspace(tenantId = tenantId, slug = slug, tenantHubIssuer = tenantHub))

            CommandSupport.emitValue(
                format,
                mapOf(
                    "switched" to slug,
                    "tenantId" to tenantId,
                    "tenantHubIssuer" to tenantHub,
                ),
                "Switched to workspace '$slug'. Subsequent commands operate on it.",
            )
            return CommandSupport.EXIT_OK
        }
    }

    /**
     * `thoryn workspace archive <slug> --confirm <slug>` — SSO-2831.
     *
     * Archives (reversible soft-disable) a workspace you own. Name-confirmation guarded:
     * you must pass `--confirm <slug>` (echoed to the hub as `X-Thoryn-Confirm`) so an
     * archive can't be triggered by accident. `reactivate` reverses it.
     */
    @Command(name = "archive", description = ["Archive a workspace you own (reversible). Requires --confirm <slug>."], mixinStandardHelpOptions = true)
    class ArchiveSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Workspace slug to archive."])
        lateinit var slug: String

        @Option(names = ["--hub"], description = ["Override the hub base URL. Defaults to the hub you signed into, else http://localhost:54702."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)
            val tenantId = resolveTenantIdBySlug(client, slug) ?: return workspaceNotFound(slug)
            return try {
                val body = client.archiveWorkspace(tenantId, confirm)
                CommandSupport.emitRecord(format, body, { node -> workspaceRecordFields(node) })
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderConfirmHint(ex, slug) ?: CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, hub)
            }
        }
    }

    /** `thoryn workspace reactivate <slug>` — SSO-2831 — clears the archive flag. */
    @Command(name = "reactivate", description = ["Reactivate an archived workspace you own."], mixinStandardHelpOptions = true)
    class ReactivateSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Workspace slug to reactivate."])
        lateinit var slug: String

        @Option(names = ["--hub"], description = ["Override the hub base URL. Defaults to the hub you signed into, else http://localhost:54702."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)
            val tenantId = resolveTenantIdBySlug(client, slug) ?: return workspaceNotFound(slug)
            return try {
                val body = client.reactivateWorkspace(tenantId)
                CommandSupport.emitRecord(format, body, { node -> workspaceRecordFields(node) })
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, hub)
            }
        }
    }

    /**
     * `thoryn workspace hard-delete <slug> --confirm <slug>` (alias `delete`) — SSO-2859.
     *
     * PERMANENTLY deletes a workspace you own via the hub's distributed teardown (SSO-2831): the
     * tenant is suspended immediately (sign-in, token issuance, and issuer trust die at once) and
     * the purge of every tenant-scoped row across hub / product-api / identity + the per-tenant
     * Vault keys is enqueued (HTTP 202; completed asynchronously). **There is no undo.** Use
     * `archive` instead for a reversible soft-disable. Name-confirmation guarded: pass
     * `--confirm <slug>` (echoed to the hub as `X-Thoryn-Confirm`) so a delete can't happen by
     * accident.
     */
    @Command(
        name = "hard-delete",
        aliases = ["delete"],
        description = ["Permanently delete a workspace you own (IRREVERSIBLE — purges all data). Requires --confirm <slug>. Use `archive` for a reversible soft-disable."],
        mixinStandardHelpOptions = true,
    )
    class HardDeleteSubcommand : Callable<Int> {

        @Parameters(index = "0", description = ["Workspace slug to permanently delete."])
        lateinit var slug: String

        @Option(names = ["--hub"], description = ["Override the hub base URL. Defaults to the hub you signed into, else http://localhost:54702."])
        var hub: String = ThorynConfig.DEFAULT_HUB

        @Option(names = ["--confirm"], description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            hub = CommandSupport.resolveHub(hub, tokens)
            val client = CommandSupport.client(hub, tokens)
            val tenantId = resolveTenantIdBySlug(client, slug) ?: return workspaceNotFound(slug)
            return try {
                val body = client.hardDeleteWorkspace(tenantId, confirm)
                CommandSupport.emitRecord(format, body, { node -> workspaceRecordFields(node) })
                if (format == OutputFormat.TABLE) {
                    System.err.println(
                        "Workspace '$slug' is suspended and permanent deletion is in progress. " +
                            "This is irreversible; the purge completes asynchronously.",
                    )
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderConfirmHint(ex, slug, subcommand = "hard-delete", verb = "Permanently deleting")
                    ?: CommandSupport.renderError(format, ex)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, hub)
            }
        }
    }

    companion object {
        internal val LIST_HEADERS: List<String> = listOf(
            "slug", "displayName", "tenantId", "archived",
        )

        /** Resolve a workspace slug to its tenantId via the caller's workspace list, or null. */
        internal fun resolveTenantIdBySlug(client: com.devnow.thoryn.cli.api.ProductApiClient, slug: String): String? =
            runCatching { client.listWorkspaces() }.getOrNull()
                ?.toList()?.firstOrNull { it["slug"]?.asString() == slug }
                ?.get("tenantId")?.asString()

        /** Consistent "no such workspace" error + exit code for the slug-addressed ops. */
        internal fun workspaceNotFound(slug: String): Int {
            System.err.println("No workspace with slug '$slug' found for your account.")
            System.err.println("Run `thoryn workspace list` to see your workspaces.")
            return CommandSupport.EXIT_HTTP_ERROR
        }

        /**
         * SSO-2831/SSO-2859 — actionable hints for the name-confirmation guard (428/422). Null if
         * not a confirm error. [subcommand] + [verb] tailor the wording for `archive` (reversible)
         * vs `hard-delete` (irreversible) so the re-run line is copy-pasteable for either.
         */
        internal fun renderConfirmHint(
            ex: ProductApiException,
            slug: String,
            subcommand: String = "archive",
            verb: String = "Archiving",
        ): Int? = when (ex.httpStatus) {
            428 -> {
                System.err.println("$verb '$slug' is a protected action. Re-run with:")
                System.err.println("  thoryn workspace $subcommand $slug --confirm $slug")
                CommandSupport.EXIT_HTTP_ERROR
            }
            422 -> {
                System.err.println("The --confirm value did not match the workspace slug '$slug'.")
                CommandSupport.EXIT_HTTP_ERROR
            }
            else -> null
        }

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
