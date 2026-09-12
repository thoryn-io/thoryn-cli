package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import tools.jackson.databind.JsonNode
import java.util.concurrent.Callable

/**
 * `thoryn branding ...` (SSO-3037, epic SSO-2871) — configure the look of the HOSTED sign-in /
 * register screens (identity-service `login.html` / `register.html`) a tenant's end users see.
 *
 * Thin wrapper over product-api's `/api/v1/login-experience/branding` surface (SSO-1926) reached
 * through the api-gateway. The branding is per-(tenant, ENVIRONMENT): it applies to the environment
 * you've selected with `thoryn env use` (the selected slug rides on `X-Thoryn-Environment`), so a
 * sandbox and production can carry different looks. identity-service renders the fields as CSS custom
 * properties (`--brand-primary`, `--brand-bg`, `--brand-radius`, derived `--brand-fg-on-primary`) in
 * the login templates, with strict server-side validation (hex colors, radius range, theme enum,
 * https logo URL) plus a WCAG-AA contrast guard on the color pair.
 *
 * Subcommands:
 *  - `get` — GET /api/v1/login-experience/branding (shows the EFFECTIVE values the page uses, plus
 *            which fields are customer-overridden vs platform defaults)
 *  - `set` — PUT /api/v1/login-experience/branding. A client-side MERGE: only the flags you pass
 *            change; unspecified fields keep their stored value. (The server PUT is a full replace,
 *            so `set` reads the current branding first and re-sends the unchanged fields.) Pass an
 *            EMPTY value to a string flag — e.g. `--logo-url ""` — to CLEAR that override and fall
 *            back to the platform default.
 *
 * Scopes: `get` → `tenant:idp.read`; `set` → `tenant:idp.write` (granted to `thoryn-cli` by hub V83).
 * Request them with `thoryn login --scope all-tenant-config` (which now includes the idp pair).
 */
@Command(
    name = "branding",
    description = ["Configure the look of your hosted sign-in / register screens (per environment)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        BrandingCommand.GetSubcommand::class,
        BrandingCommand.SetSubcommand::class,
    ],
)
class BrandingCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn branding <subcommand>")
        System.err.println("Subcommands: get | set")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn branding get` — the selected environment's hosted-login branding. */
    @Command(name = "get", description = ["Show the hosted-login branding for the selected environment."], mixinStandardHelpOptions = true)
    class GetSubcommand : Callable<Int> {

        @Option(names = ["--gateway"], description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)
            return try {
                val body = client.getLoginBranding()
                CommandSupport.emitRecord(format, body, ::brandingRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.read")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /**
     * `thoryn branding set [--primary-color '#2563eb'] [--logo-url https://…] ...`
     *
     * Merge-upsert: only the fields you pass change; omitted fields keep their stored value. Pass an
     * empty value to a string flag (`--logo-url ""`, `--primary-color ""`, `--theme ""`) to CLEAR that
     * override so resolution falls back to the platform default.
     */
    @Command(name = "set", description = ["Configure (merge) the hosted-login branding for the selected environment."], mixinStandardHelpOptions = true)
    class SetSubcommand : Callable<Int> {

        @Option(names = ["--logo-url"], description = ["Logo image URL (https). Empty value clears the override."])
        var logoUrl: String? = null

        @Option(names = ["--primary-color"], description = ["Primary/brand color as CSS hex (#rgb, #rrggbb, #rrggbbaa). Empty clears."])
        var primaryColor: String? = null

        @Option(names = ["--background-color"], description = ["Page background color as CSS hex. Empty clears."])
        var backgroundColor: String? = null

        @Option(names = ["--border-radius-px"], description = ["Corner radius in px (0-64)."])
        var borderRadiusPx: Int? = null

        @Option(names = ["--theme"], description = ["Color theme: light | dark | auto. Empty clears."])
        var theme: String? = null

        @Option(
            names = ["--var"],
            description = [
                "Set an allowlisted --thoryn-* CSS variable, e.g. --var --thoryn-accent=#7c3aed (repeatable). " +
                    "An empty value clears that one. Allowed: --thoryn-accent, --thoryn-text, --thoryn-muted, --thoryn-font-family.",
            ],
        )
        var cssVars: MutableMap<String, String> = mutableMapOf()

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"])
        var outputRaw: String? = null

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            if (logoUrl == null && primaryColor == null && backgroundColor == null &&
                borderRadiusPx == null && theme == null && cssVars.isEmpty()
            ) {
                System.err.println("Error: pass at least one of --logo-url, --primary-color, --background-color, --border-radius-px, --theme, --var.")
                return CommandSupport.EXIT_USAGE
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens) // SSO-2827 — default to the gateway you signed into
            val client = CommandSupport.gatewayClient(gateway, tokens)

            // The server PUT is a full REPLACE (an absent field is cleared), so to give `set`
            // merge semantics we seed the body from the currently-stored overrides, then overlay
            // the flags the operator supplied. A flag passed with an EMPTY value clears that field.
            val body = linkedMapOf<String, Any?>()
            // The CSS-variable map is also merged: seed from the stored map, overlay the --var flags.
            val cssMap = linkedMapOf<String, String>()
            try {
                val stored = client.getLoginBranding()["stored"]
                stored?.get("logoUrl")?.takeUnless { it.isNull }?.let { body["logoUrl"] = it.asString() }
                stored?.get("primaryColor")?.takeUnless { it.isNull }?.let { body["primaryColor"] = it.asString() }
                stored?.get("backgroundColor")?.takeUnless { it.isNull }?.let { body["backgroundColor"] = it.asString() }
                stored?.get("borderRadiusPx")?.takeUnless { it.isNull }?.let { body["borderRadiusPx"] = it.asInt() }
                stored?.get("theme")?.takeUnless { it.isNull }?.let { body["theme"] = it.asString() }
                stored?.get("cssVariables")?.takeUnless { it.isNull }?.properties()?.forEach { (k, v) ->
                    if (!v.isNull) cssMap[k] = v.asString()
                }
            } catch (ex: ProductApiException) {
                return CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.read")
            } catch (ex: Exception) {
                return CommandSupport.renderRequestFailure(ex, gateway)
            }

            // Overlay supplied flags. An empty string clears (sends null ⇒ server drops the override);
            // borderRadiusPx has no "empty" form, so it only ever sets.
            logoUrl?.let { body["logoUrl"] = it.ifBlank { null } }
            primaryColor?.let { body["primaryColor"] = it.ifBlank { null } }
            backgroundColor?.let { body["backgroundColor"] = it.ifBlank { null } }
            borderRadiusPx?.let { body["borderRadiusPx"] = it }
            theme?.let { body["theme"] = it.ifBlank { null } }
            // Overlay --var entries: a blank value clears that token, else set/replace it.
            cssVars.forEach { (key, value) -> if (value.isBlank()) cssMap.remove(key) else cssMap[key] = value }
            // Always send the merged map — the server PUT replaces, so omitting it would clear overrides.
            body["cssVariables"] = cssMap

            return try {
                val response = client.putLoginBranding(body)
                CommandSupport.emitRecord(format, response, ::brandingRecordFields)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                CommandSupport.renderError(format, ex, requiredScope = "tenant:idp.write")
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    companion object {
        /**
         * Record fields for the `BrandingResponse`. Shows the EFFECTIVE values (what the hosted page
         * actually renders, after fallback to platform defaults) plus, for each field, the raw STORED
         * override (blank when the field falls back to the default) so an operator can see what they've
         * customized vs. what's inherited. `--output json|yaml` emits the full {stored, effective,
         * updatedAt} document unchanged.
         */
        internal fun brandingRecordFields(node: JsonNode): List<Pair<String, Any?>> {
            val stored = node["stored"]
            val effective = node["effective"]
            fun storedStr(field: String): String? = stored?.get(field)?.takeUnless { it.isNull }?.asString()
            fun effStr(field: String): String? = effective?.get(field)?.takeUnless { it.isNull }?.asString()
            return listOf(
                "logoUrl" to (effStr("logoUrl") ?: "(none)"),
                "primaryColor" to effStr("primaryColor"),
                "backgroundColor" to effStr("backgroundColor"),
                "borderRadiusPx" to effStr("borderRadiusPx"),
                "theme" to effStr("theme"),
                // SSO-3038: the effective CSS-variable map, rendered as `--token=value` pairs.
                "cssVariables" to (effective?.get("cssVariables")?.takeUnless { it.isNull }
                    ?.properties()?.joinToString(", ") { (k, v) -> "$k=${v.asString()}" }
                    ?.ifEmpty { "(none)" } ?: "(none)"),
                "overrides" to listOfNotNull(
                    storedStr("logoUrl")?.let { "logoUrl" },
                    storedStr("primaryColor")?.let { "primaryColor" },
                    storedStr("backgroundColor")?.let { "backgroundColor" },
                    stored?.get("borderRadiusPx")?.takeUnless { it.isNull }?.let { "borderRadiusPx" },
                    storedStr("theme")?.let { "theme" },
                ).joinToString(", ").ifEmpty { "(all default)" },
                "updatedAt" to node["updatedAt"]?.takeUnless { it.isNull }?.asString(),
            )
        }
    }
}
