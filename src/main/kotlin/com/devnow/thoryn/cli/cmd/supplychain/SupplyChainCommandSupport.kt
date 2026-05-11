package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.ScopeRegistry
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import tools.jackson.databind.JsonNode
import java.io.PrintStream

/**
 * Shared helpers for every `thoryn supply-chain <area>` leaf subcommand.
 *
 * Each leaf command parses its own picocli flags, then calls into one of
 * the helpers here to:
 *
 *  - resolve the access token from the local store (and bail with a clear
 *    "Run `thoryn login` first" if there isn't one);
 *  - build a [ProductApiClient] pointed at the gateway in [ThorynConfig];
 *  - parse `--output <format>` into an [OutputFormat] (or bail with EXIT_USAGE);
 *  - emit the response via [Printers], driven by the format flag;
 *  - convert a [ProductApiException] into a structured error (`--output json`)
 *    or a one-line `Error: …` plus a `Run: oathy login --scope …` hint, and
 *    return a non-zero exit code.
 *
 * Exit codes (consistent across all supply-chain subcommands):
 *
 *  - `0` — success.
 *  - `1` — not signed in / no local token.
 *  - `2` — HTTP non-2xx from the gateway (auth error, validation error, etc.).
 *  - `64` — invalid CLI usage (unknown `--output`, missing required flag).
 *  - `3` — unexpected IO/network failure.
 */
internal object SupplyChainCommandSupport {

    const val EXIT_OK: Int = 0
    const val EXIT_NOT_SIGNED_IN: Int = 1
    const val EXIT_HTTP_ERROR: Int = 2
    const val EXIT_IO_ERROR: Int = 3
    const val EXIT_USAGE: Int = 64

    /**
     * Resolve a [Tokens] from the local store, or print "Not signed in." and
     * return null. Caller returns [EXIT_NOT_SIGNED_IN] on null.
     */
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
     * Build a [ProductApiClient] against [gateway]. The caller already
     * validated [tokens] is non-null.
     */
    fun client(gateway: String, tokens: Tokens): ProductApiClient =
        ProductApiClient(gateway = gateway, tokens = tokens)

    /**
     * Parse `--output <raw>`. Returns null on unknown values; caller emits
     * "Unknown --output value …" and returns [EXIT_USAGE].
     */
    fun parseFormat(raw: String?, err: PrintStream = System.err): OutputFormat? {
        val parsed = OutputFormat.parse(raw)
        if (parsed == null) {
            err.println("Error: --output must be one of json|yaml|table (was '$raw').")
        }
        return parsed
    }

    /**
     * Emit a list-shaped response. [tableHeaders] / [rowMapper] drive the
     * table layout when the format is [OutputFormat.TABLE].
     */
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
                    body.isObject -> listOf(body) // single-object table
                    else -> emptyList()
                }
                val rows = items.map { rowMapper(it) }
                Printers.table(tableHeaders, rows, out)
            }
        }
    }

    /**
     * Emit a single-record response. Table format uses a two-column
     * key/value layout via [recordFields]; JSON/YAML emit the whole tree.
     */
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

    /**
     * Render a [ProductApiException] in the requested [format].
     *
     * - `TABLE` — one-line `Error: …` on stderr, plus the
     *   `Run: oathy login --scope …` hint when [requiredScope] is supplied
     *   and the failure is a missing-scope (403 / insufficient_scope).
     * - `JSON` — structured error to stdout: `{"error", "errorDescription",
     *   "httpStatus", "requiredScope" (if supplied)}`.
     * - `YAML` — same shape, YAML-encoded.
     *
     * Returns [EXIT_HTTP_ERROR].
     */
    fun renderError(
        format: OutputFormat,
        ex: ProductApiException,
        requiredScope: String? = null,
        out: PrintStream = System.out,
        err: PrintStream = System.err,
    ): Int {
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
}
