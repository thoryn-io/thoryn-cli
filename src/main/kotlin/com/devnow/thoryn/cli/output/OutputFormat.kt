package com.devnow.thoryn.cli.output

/**
 * Output formats accepted by every supply-chain subcommand via `--output`.
 *
 * `TABLE` is the default — human-readable column layout for terminals.
 * `JSON` / `YAML` are for scripting (jq, yq, pipe-into-config-generators).
 */
enum class OutputFormat {
    TABLE,
    JSON,
    YAML;

    companion object {
        /**
         * Parse a `--output` flag value. Unknown values return null so the
         * caller can produce a uniform error message rather than picocli's
         * built-in "invalid value" stack trace.
         */
        fun parse(raw: String?): OutputFormat? = when (raw?.lowercase()) {
            null, "" -> TABLE
            "table" -> TABLE
            "json" -> JSON
            "yaml", "yml" -> YAML
            else -> null
        }
    }
}
