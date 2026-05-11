package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import picocli.CommandLine.Command
import java.util.concurrent.Callable

/**
 * `thoryn supply-chain chain ...` — SSO-970 parity for the chain-of-custody
 * console operations (epic SSO-960).
 *
 * Per ADR `2026-05-11-credential-chain-of-custody-with-fan-in-and-split.md`,
 * every operator-facing chain action in SSO-962 / SSO-963 / SSO-964 / SSO-965
 * / SSO-967 must also work from the CLI. The wire shapes (URLs, scopes,
 * request/response bodies) match the console verbatim; the CLI is a thin
 * client.
 *
 * Subcommand map:
 *
 *  - `receive` — verify N parents without state change (SSO-962). Calls
 *    `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/receive`.
 *  - `issue` — mint one combined credential (SSO-962 combine path). Calls
 *    `POST /api/v1/issuer-bridges/{bridgeId}/intermediary/issue` with
 *    `action=processed_combined` (or `packaged_combined`).
 *  - `split` — mint N children from one parent + write QR-PDFs as ZIP
 *    (SSO-962 split path + SSO-963). Calls the same intermediary/issue
 *    endpoint with `action=split` and a templated children list.
 *  - `walk` — chain walker (SSO-964). Calls
 *    `POST /broker/verify/walletless?walkChain=true`.
 *  - `revoke` — direct revoke with downward propagation (SSO-965). Calls
 *    `POST /broker/internal/credentials/{id}/revoke`. `--dry-run` skips the
 *    mutation and only fetches `GET /broker/internal/credentials/{id}/descendants`.
 *  - `descendants` — downward DAG view for operators or producers (SSO-965
 *    blast-radius + SSO-967 holder afstammingen). Defaults to the operator's
 *    view; `--holder` swaps to the privacy-toggle-respecting holder endpoint.
 *
 * Scopes (per [com.devnow.thoryn.cli.auth.ScopeRegistry]):
 *
 *  - `tenant:supply-chain.issuer-bridge.intermediary.read` — `receive`.
 *  - `tenant:supply-chain.issuer-bridge.intermediary.write` — `issue`, `split`.
 *  - `tenant:supply-chain.issuer-bridge.read` — `walk`, `descendants`.
 *  - `tenant:supply-chain.issuer-bridge.revoke` — `revoke`.
 *
 * Output: every leaf accepts `--output {json|yaml|table}` (default `table`).
 * The `walk` and `descendants` subcommands render the DAG as an ASCII tree
 * in table mode (mirroring the console's tree visualisation).
 *
 * **`audit-replay --chain` is NOT redefined here.** SSO-968 already extended
 * the standalone `thoryn audit-replay` command with the `--chain` flag; the
 * existing `thoryn supply-chain audit replay` alias from SSO-959 (in
 * [com.devnow.thoryn.cli.cmd.supplychain.AuditCommand.ReplaySubcommand])
 * already delegates to that code path. No re-implementation here.
 */
@Command(
    name = "chain",
    description = ["Chain-of-custody operations: receive, issue, split, walk, revoke, descendants."],
    mixinStandardHelpOptions = true,
    subcommands = [
        ReceiveCommand::class,
        IssueCommand::class,
        SplitCommand::class,
        WalkCommand::class,
        RevokeCommand::class,
        DescendantsCommand::class,
    ],
)
class ChainCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn supply-chain chain <subcommand>")
        System.err.println(
            "Subcommands: receive | issue | split | walk | revoke | descendants",
        )
        return SupplyChainCommandSupport.EXIT_USAGE
    }
}
