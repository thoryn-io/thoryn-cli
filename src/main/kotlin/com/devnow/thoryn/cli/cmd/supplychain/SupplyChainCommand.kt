package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.cmd.supplychain.chain.ChainCommand
import picocli.CommandLine.Command
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain ...` — parent of the SSO-959 supply-chain CLI tree.
 *
 * Mirrors the console route group under `apps/console/app/verticals/` per ADR
 * `2026-05-10-supply-chain-self-service-namespacing.md` §4–§5. Each leaf
 * subcommand maps 1:1 to a product-api endpoint set:
 *
 *  - `trust-registry`     — SSO-954
 *  - `policy`             — SSO-955
 *  - `audit`              — SSO-956
 *  - `issuer-bridge`      — SSO-957
 *  - `chain`              — SSO-970 (chain-of-custody: SSO-962, SSO-963,
 *                           SSO-964, SSO-965, SSO-967)
 *
 * Authentication: re-uses the existing `thoryn login` flow. The wildcard
 * scope `all-supply-chain` expands client-side via
 * [com.devnow.thoryn.cli.auth.ScopeRegistry] to the literal set of
 * `tenant:supply-chain.*` scopes.
 *
 * Output: every leaf accepts `--output {json|yaml|table}`; default is
 * `table` for human use. Errors go to stderr with non-zero exit code; on
 * `--output json` errors emit structured JSON on stdout.
 */
@Command(
    name = "supply-chain",
    description = ["Manage supply-chain self-service surfaces (trust registry, policy, audit, issuer bridges, chain-of-custody)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        TrustRegistryCommand::class,
        PolicyCommand::class,
        AuditCommand::class,
        IssuerBridgeCommand::class,
        ChainCommand::class,
    ],
)
class SupplyChainCommand : Callable<Int> {
    override fun call(): Int {
        // Top-level `thoryn supply-chain` with no subcommand — print usage.
        System.err.println("Usage: thoryn supply-chain <subcommand>")
        System.err.println(
            "Subcommands: trust-registry | policy | audit | issuer-bridge | chain",
        )
        return SupplyChainCommandSupport.EXIT_USAGE
    }
}
