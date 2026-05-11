package com.devnow.thoryn.cli.cmd.supplychain.chain

import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandSupport
import com.devnow.thoryn.cli.cmd.supplychain.SupplyChainCommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-970 — top-level wiring of `thoryn supply-chain chain ...`.
 *
 * Per the spec, the parent command is a usage-printer; the leaf
 * subcommands carry the real behaviour. This test verifies the parent
 * prints the subcommand list and returns EXIT_USAGE when invoked without a
 * subcommand. Per-subcommand tests live alongside this file.
 */
class ChainCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `bare thoryn supply-chain chain prints usage and exits 64`() {
        val (exit, _, err) = runCli("supply-chain", "chain")
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("Usage: thoryn supply-chain chain")
        assertThat(err).contains("receive")
        assertThat(err).contains("issue")
        assertThat(err).contains("split")
        assertThat(err).contains("walk")
        assertThat(err).contains("revoke")
        assertThat(err).contains("descendants")
        // No HTTP traffic was generated.
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `bare thoryn supply-chain still lists chain as a known subcommand`() {
        val (exit, _, err) = runCli("supply-chain")
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("chain")
    }
}
