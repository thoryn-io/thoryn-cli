package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.HttpSender
import com.devnow.thoryn.cli.auth.RefreshTokenFlow
import com.devnow.thoryn.cli.auth.ScopeRegistry
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import tools.jackson.databind.JsonNode
import java.io.PrintStream
import java.net.http.HttpClient
import java.time.Duration

/**
 * SSO-1552 — shared helpers for the tenant-configuration command tree
 * (`clients`, `federation`, `workspace`, `audit`).
 *
 * Provides the shared exit-code contract and the token-resolution / output /
 * error-rendering shape for the tenant-config command tree. (The supply-chain
 * command tree that once had a parallel `SupplyChainCommandSupport` was pruned
 * when the CLI was relocated to a Hub-only oauthy — SSO-2817.)
 *
 * Exit codes (consistent across all tenant-config subcommands):
 *  - `0`  — success.
 *  - `1`  — not signed in / no local token.
 *  - `2`  — HTTP non-2xx from the gateway/hub (auth error, validation, 404, …).
 *  - `3`  — unexpected IO/network failure.
 *  - `64` — invalid CLI usage (unknown `--output`, missing required flag).
 *  - `65` — a required secret could not be obtained (see [SecretIo.EXIT_NO_SECRET]).
 */
internal object CommandSupport {

    const val EXIT_OK: Int = 0
    const val EXIT_NOT_SIGNED_IN: Int = 1
    const val EXIT_HTTP_ERROR: Int = 2
    const val EXIT_IO_ERROR: Int = 3
    const val EXIT_USAGE: Int = 64

    /**
     * SSO-2413 — shared help text for the `--confirm <workspace-slug>` option on the
     * destructive subcommands (`clients delete`, `clients rotate-secret`,
     * `federation delete`). Production-plane destructive actions are gated by
     * product-api's `ProductionConfirmationInterceptor` (428 without a matching
     * `X-Thoryn-Confirm` header); sandbox / non-production actions are not.
     */
    const val CONFIRM_OPTION_DESC: String =
        "Confirm a destructive action on a PRODUCTION workspace by passing your workspace slug. " +
            "Required only when the target workspace is a production environment; " +
            "sandbox / non-production actions need no confirmation."

    /** Resolve a [Tokens] from the local store, or print guidance and return null. */
    fun readTokens(err: PrintStream = System.err): Tokens? {
        val tokens = try {
            TokenStoreFactory.default().read()
        } catch (e: Exception) {
            err.println("Failed to read local token store: ${e.message}")
            return null
        }
        if (tokens == null) {
            err.println("Not signed in. Run `thoryn login` first.")
            return null
        }
        return tokens
    }

    /**
     * Build a [ProductApiClient] against [baseUrl] (gateway for product-api, hub for workspace).
     *
     * SSO-2834 — refreshes the access token first when it is at/near expiry (see [ensureFresh]), so
     * every command that builds its client here transparently recovers from a stale ~15-minute access
     * token instead of returning `HTTP 401` until the next `thoryn login`.
     */
    fun client(baseUrl: String, tokens: Tokens): ProductApiClient =
        ProductApiClient(
            gateway = baseUrl,
            tokens = ensureFresh(tokens),
            // SSO-2861 — reactive complement to ensureFresh: on a 401 the client forces one refresh
            // and retries. Covers the cases the proactive skew check misses (unknown/short expiry,
            // clock skew, a token the hub invalidated early).
            reauthenticate = { forceRefresh() },
        )

    /** Seconds before expiry at which [ensureFresh] proactively refreshes the access token. */
    private const val REFRESH_SKEW_SECONDS: Long = 60

    /**
     * SSO-2834 — return a [Tokens] whose access token is valid, refreshing it via [RefreshTokenFlow]
     * (RFC 6749 §6) when it is within [REFRESH_SKEW_SECONDS] of expiry. The refreshed bundle is
     * written back to the store (preserving the CLI-local [Tokens.issuer] / [Tokens.gateway] session
     * fields, which are not part of the token response) so subsequent invocations reuse it.
     *
     * Best-effort and non-fatal: a token whose expiry is unknown, that carries no refresh token, or
     * that recorded no issuer to refresh against is returned unchanged; a failed refresh (expired /
     * revoked refresh token, unreachable hub) prints a one-line hint and falls back to the existing
     * token so the caller still attempts the request (and surfaces the real `401`).
     */
    fun ensureFresh(tokens: Tokens, err: PrintStream = System.err): Tokens {
        // Prefer the store as the source of truth: a prior client() call in THIS process may have
        // already refreshed (and, under refresh-token rotation, consumed the token in `tokens`). Using
        // the freshest persisted bundle avoids a double-refresh that would fail on a rotated token.
        val current = runCatching { TokenStoreFactory.default().read() }.getOrNull() ?: tokens
        val expiresAt = current.expiresAtEpochSecond ?: return current
        val now = System.currentTimeMillis() / 1000
        if (expiresAt - now > REFRESH_SKEW_SECONDS) return current
        return forceRefresh(err) ?: current
    }

    /**
     * SSO-2861 — force a refresh-token redemption regardless of expiry, for the reactive on-401 retry
     * ([ProductApiClient] reauthenticator) and the proactive [ensureFresh] skew path. Reads the
     * freshest persisted bundle (a prior refresh this process may have rotated the token), redeems it
     * via [RefreshTokenFlow] (RFC 6749 §6), writes the result back (preserving the CLI-local
     * [Tokens.issuer] / [Tokens.gateway] session fields, absent from the token response), and returns
     * the refreshed bundle.
     *
     * Returns null when there is nothing to refresh with (no persisted store / refresh token / issuer)
     * or the redemption fails (expired or revoked refresh token, unreachable hub) — the caller then
     * surfaces the original `401` / falls back to the existing token. A one-line hint is printed on a
     * genuine redemption failure so the user knows to re-run `thoryn login`.
     */
    internal fun forceRefresh(err: PrintStream = System.err): Tokens? {
        val current = runCatching { TokenStoreFactory.default().read() }.getOrNull() ?: return null
        val refreshToken = current.refreshToken?.takeIf { it.isNotBlank() } ?: return null
        val issuer = current.issuer?.takeIf { it.isNotBlank() } ?: return null
        return try {
            val refreshed = RefreshTokenFlow(issuer = issuer, sender = realHttpSender())
                .refresh(refreshToken)
                // Preserve the CLI-local session hosts (not returned by /oauth2/token).
                .copy(issuer = current.issuer, gateway = current.gateway)
            runCatching { TokenStoreFactory.default().write(refreshed) }
            refreshed
        } catch (e: Exception) {
            err.println("Could not refresh the session token (${e.message}); run `thoryn login` if the command fails.")
            null
        }
    }

    private fun realHttpSender(): HttpSender {
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build()
        return HttpSender { request, handler -> client.send(request, handler) }
    }

    /**
     * SSO-2827 — resolve the hub base URL with precedence:
     *   1. an explicit, non-default `--hub`;
     *   2. the hub recorded in the session at login ([Tokens.issuer]);
     *   3. the built-in local-dev default ([ThorynConfig.DEFAULT_HUB]).
     *
     * An explicit `--hub` equal to the local-dev default is treated as "unset" so
     * a signed-in session still wins — passing the localhost default while signed
     * into a remote hub is not a real use case, and before SSO-2827 that stale
     * default is exactly what produced `Request failed` after a successful login.
     */
    fun resolveHub(explicit: String, tokens: Tokens?): String =
        if (explicit != ThorynConfig.DEFAULT_HUB) explicit
        else tokens?.issuer?.takeIf { it.isNotBlank() } ?: explicit

    /** SSO-2827 — as [resolveHub], for the gateway base URL ([Tokens.gateway]). */
    fun resolveGateway(explicit: String, tokens: Tokens?): String =
        if (explicit != ThorynConfig.DEFAULT_GATEWAY) explicit
        else tokens?.gateway?.takeIf { it.isNotBlank() } ?: explicit

    /**
     * SSO-2828 — render a transport-level failure with the target host AND a real
     * cause. The bare `System.err.println("Request failed: ${ex.message}")` printed
     * `Request failed: null` whenever the underlying exception carried a null message
     * (a `ConnectException` to a dead host, an HTTP timeout, a TLS handshake error) —
     * no host, no cause, nothing to act on. Returns [EXIT_IO_ERROR].
     */
    fun renderRequestFailure(ex: Throwable, target: String, err: PrintStream = System.err): Int {
        err.println("Request failed: could not reach $target — ${describeThrowable(ex)}")
        return EXIT_IO_ERROR
    }

    /**
     * Summarise a throwable for [renderRequestFailure]: classify the root cause into
     * a human phrase and append the most specific non-blank message in the cause
     * chain. Walks at most 8 links so a self-referential cause can't loop.
     */
    internal fun describeThrowable(ex: Throwable): String {
        val chain = generateSequence(ex as Throwable?) { it.cause }.take(8).toList()
        val root = chain.last()
        val kind = when (root) {
            is java.net.UnknownHostException -> "unknown host"
            is java.net.ConnectException -> "connection refused"
            is java.net.http.HttpConnectTimeoutException -> "connection timed out"
            is java.net.http.HttpTimeoutException -> "request timed out"
            is javax.net.ssl.SSLException -> "TLS handshake failed"
            else -> root.javaClass.simpleName
        }
        val msg = chain.firstNotNullOfOrNull { it.message?.takeIf { m -> m.isNotBlank() } }
        return if (msg != null && !msg.equals(kind, ignoreCase = true)) "$kind ($msg)" else kind
    }

    /** Parse `--output <raw>`; null on unknown values (caller returns [EXIT_USAGE]). */
    fun parseFormat(raw: String?, err: PrintStream = System.err): OutputFormat? {
        val parsed = OutputFormat.parse(raw)
        if (parsed == null) {
            err.println("Error: --output must be one of json|yaml|table (was '$raw').")
        }
        return parsed
    }

    /** Emit a list-shaped response; [tableHeaders]/[rowMapper] drive the table layout. */
    fun emitList(
        format: OutputFormat,
        body: JsonNode,
        tableHeaders: List<String>,
        rowMapper: (JsonNode) -> List<Any?>,
        out: PrintStream = System.out,
    ) {
        when (format) {
            OutputFormat.JSON -> Printers.json(body, out)
            OutputFormat.YAML -> Printers.yaml(body, out)
            OutputFormat.TABLE -> {
                val items: List<JsonNode> = when {
                    body.isArray -> body.toList()
                    body.isObject && body.has("items") && body["items"].isArray ->
                        body["items"].toList()
                    body.isObject -> listOf(body)
                    else -> emptyList()
                }
                val rows = items.map { rowMapper(it) }
                Printers.table(tableHeaders, rows, out)
            }
        }
    }

    /** Emit a single-record response; table format uses a key/value layout. */
    fun emitRecord(
        format: OutputFormat,
        body: JsonNode,
        recordFields: (JsonNode) -> List<Pair<String, Any?>>,
        out: PrintStream = System.out,
    ) {
        when (format) {
            OutputFormat.JSON -> Printers.json(body, out)
            OutputFormat.YAML -> Printers.yaml(body, out)
            OutputFormat.TABLE -> Printers.record(recordFields(body), out)
        }
    }

    /** Emit an arbitrary value (a hand-built confirmation map) honouring [format]. */
    fun emitValue(format: OutputFormat, value: Any?, tableLine: String, out: PrintStream = System.out) {
        when (format) {
            OutputFormat.JSON -> Printers.json(value, out)
            OutputFormat.YAML -> Printers.yaml(value, out)
            OutputFormat.TABLE -> out.println(tableLine)
        }
    }

    /**
     * SSO-2413 — actionable guidance for product-api's production destructive-action
     * confirmation guard. `428 production_confirmation_required` means the target is a
     * production workspace and the caller must re-run with `--confirm <slug>`;
     * `422 production_confirmation_mismatch` means the value did not match.
     */
    private const val CONFIRM_REQUIRED_HINT: String =
        "This is a production workspace. Re-run with --confirm <your-workspace-slug> " +
            "to confirm this destructive action."
    private const val CONFIRM_MISMATCH_HINT: String =
        "The --confirm value did not match this workspace's slug."

    /**
     * Render a [ProductApiException]. On `insufficient_scope` (403) with a
     * supplied [requiredScope], prints the exact `oathy login --scope …` line.
     * On the SSO-2413 production-confirmation responses (428 / 422) prints the
     * actionable `--confirm` guidance. Returns [EXIT_HTTP_ERROR].
     */
    fun renderError(
        format: OutputFormat,
        ex: ProductApiException,
        requiredScope: String? = null,
        out: PrintStream = System.out,
        err: PrintStream = System.err,
    ): Int {
        // SSO-2413 — production destructive-action confirmation guard takes precedence:
        // its guidance ("re-run with --confirm <slug>") is more actionable than the
        // generic HTTP-error rendering.
        if (ex.isProductionConfirmationRequired) return renderConfirmation(format, ex, CONFIRM_REQUIRED_HINT, out, err)
        if (ex.isProductionConfirmationMismatch) return renderConfirmation(format, ex, CONFIRM_MISMATCH_HINT, out, err)

        val structured = linkedMapOf<String, Any?>(
            "error" to (ex.errorCode ?: "unknown"),
            "errorDescription" to ex.errorDescription,
            "httpStatus" to ex.httpStatus,
        )
        if (requiredScope != null && ex.isInsufficientScope) {
            structured["requiredScope"] = requiredScope
            structured["loginHint"] = ScopeRegistry.loginHintForScope(requiredScope)
        }
        when (format) {
            OutputFormat.JSON -> Printers.json(structured, out)
            OutputFormat.YAML -> Printers.yaml(structured, out)
            OutputFormat.TABLE -> {
                val description = ex.errorDescription?.let { " — $it" } ?: ""
                err.println("Error: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}$description")
                if (requiredScope != null && ex.isInsufficientScope) {
                    err.println("Required scope: $requiredScope")
                    err.println("Run: ${ScopeRegistry.loginHintForScope(requiredScope)}")
                }
            }
        }
        return EXIT_HTTP_ERROR
    }

    /**
     * SSO-2413 — render the production-confirmation guard response. TABLE prints the
     * actionable [hint] to stderr; JSON/YAML emit a structured error carrying the same
     * hint so scripted callers can branch on `errorCode`. Returns [EXIT_HTTP_ERROR].
     */
    private fun renderConfirmation(
        format: OutputFormat,
        ex: ProductApiException,
        hint: String,
        out: PrintStream,
        err: PrintStream,
    ): Int {
        when (format) {
            OutputFormat.JSON -> Printers.json(confirmationStructured(ex, hint), out)
            OutputFormat.YAML -> Printers.yaml(confirmationStructured(ex, hint), out)
            OutputFormat.TABLE -> err.println(hint)
        }
        return EXIT_HTTP_ERROR
    }

    private fun confirmationStructured(ex: ProductApiException, hint: String): Map<String, Any?> =
        linkedMapOf(
            "error" to (ex.errorCode ?: "production_confirmation"),
            "errorDescription" to ex.errorDescription,
            "httpStatus" to ex.httpStatus,
            "hint" to hint,
        )
}
