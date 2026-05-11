package com.devnow.thoryn.cli.auth

/**
 * Known OAuth scopes the `thoryn` CLI knows how to request and the wildcard
 * expansions it understands.
 *
 * The hub deliberately does NOT understand wildcards server-side (per ADR
 * `2026-05-10-supply-chain-self-service-namespacing.md` *Open questions*) —
 * wildcards are a client-side ergonomic. The CLI expands them at
 * `thoryn login` time into the literal scope set the hub will see.
 *
 * **Supply-chain namespace** — per ADR
 * `2026-05-10-supply-chain-self-service-namespacing.md` §1, every supply-chain
 * tenant-admin operation sits under `tenant:supply-chain.*`. The wildcard
 * `all-supply-chain` expands to the full literal set so a CI/CD pipeline can
 * grab everything it might need with one `--scope`.
 *
 * The static list here mirrors the per-endpoint scope table in
 * `features/SSO-954-*.md` … `SSO-957-*.md`. When a new supply-chain scope is
 * added, this list must grow in the same PR.
 */
object ScopeRegistry {

    /** Wildcard token recognised by `--scope`. Not a real OAuth scope. */
    const val ALL_SUPPLY_CHAIN: String = "all-supply-chain"

    /**
     * Literal `tenant:supply-chain.*` scopes the hub will mint, in the order
     * they should appear in the `--scope` argument. Read-then-write per
     * domain, then the bridge ops in the order they appear in SSO-957.
     */
    val SUPPLY_CHAIN_SCOPES: List<String> = listOf(
        // SSO-954
        "tenant:supply-chain.trust-registry.read",
        "tenant:supply-chain.trust-registry.write",
        // SSO-955
        "tenant:supply-chain.policy.read",
        "tenant:supply-chain.policy.write",
        // SSO-956
        "tenant:supply-chain.audit.read",
        // SSO-957 (bridge ops; heartbeat-write is a bridge-only service-account
        // scope and is deliberately not part of the wildcard for end-users).
        "tenant:supply-chain.issuer-bridge.read",
        "tenant:supply-chain.issuer-bridge.revoke",
        "tenant:supply-chain.issuer-bridge.rotate-key",
        // SSO-962 (intermediary flow — Receive → Action → Issue). SSO-970
        // adds these so `oathy login --scope all-supply-chain` covers the
        // chain-of-custody CLI subcommands (`thoryn supply-chain chain ...`).
        "tenant:supply-chain.issuer-bridge.intermediary.read",
        "tenant:supply-chain.issuer-bridge.intermediary.write",
    )

    /**
     * Expand wildcard tokens in [raw] (space- or comma-separated, as accepted
     * by `oathy login --scope ...`) into a deduplicated space-separated scope
     * string in encounter order.
     *
     * Unknown wildcards pass through unchanged so the hub returns a clean
     * `invalid_scope` error rather than the CLI guessing.
     */
    fun expand(raw: String): String {
        if (raw.isBlank()) return raw
        val tokens = raw.split(' ', ',').map { it.trim() }.filter { it.isNotEmpty() }
        val expanded = LinkedHashSet<String>()
        for (token in tokens) {
            when (token) {
                ALL_SUPPLY_CHAIN -> expanded.addAll(SUPPLY_CHAIN_SCOPES)
                else -> expanded.add(token)
            }
        }
        return expanded.joinToString(" ")
    }

    /**
     * Format an `oathy login` invocation that would grant the missing
     * [requiredScope]. Used by command-level error messages so the user sees
     * the exact line to re-run.
     */
    fun loginHintForScope(requiredScope: String): String =
        "oathy login --scope $requiredScope"
}
