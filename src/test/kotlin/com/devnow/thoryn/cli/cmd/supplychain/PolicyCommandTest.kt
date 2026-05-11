package com.devnow.thoryn.cli.cmd.supplychain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-959 — unit tests for `thoryn supply-chain policy ...`.
 */
class PolicyCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `list calls GET on verification-policies and renders the table`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"credentialClass":"FSISustainabilityCertification","requireFreshRevocation":false,
                   "statusListCacheTtlSeconds":300,"retentionHorizonYears":7,"policyVersion":"walletless-v1-revocation-unchecked"},
                  {"credentialClass":"SBOMCertification","requireFreshRevocation":true,
                   "statusListCacheTtlSeconds":300,"retentionHorizonYears":7,"policyVersion":"walletless-v1"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "policy", "list",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("FSISustainabilityCertification")
        assertThat(out).contains("SBOMCertification")
        assertThat(out).contains("walletless-v1-revocation-unchecked")

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/verification-policies")
        assertThat(req.method).isEqualTo("GET")
    }

    @Test
    fun `show calls GET with the credential class as path segment`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialClass":"FSISustainabilityCertification","requireFreshRevocation":false,
                  "statusListCacheTtlSeconds":300,"retentionHorizonYears":7,
                  "policyVersion":"walletless-v1-revocation-unchecked"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "policy", "show",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("walletless-v1-revocation-unchecked")

        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/api/v1/verification-policies/FSISustainabilityCertification")
    }

    @Test
    fun `set PUTs the policy body and returns the new policy version`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"credentialClass":"FSISustainabilityCertification",
                   "requireFreshRevocation":true,"statusListCacheTtlSeconds":600,
                   "retentionHorizonYears":10,"policyVersion":"walletless-v1"}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "policy", "set",
            "--credential-class", "FSISustainabilityCertification",
            "--require-fresh-revocation", "true",
            "--status-list-cache-ttl-seconds", "600",
            "--retention-horizon-years", "10",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("walletless-v1")

        val req = gateway.takeRequest()
        assertThat(req.method).isEqualTo("PUT")
        assertThat(req.path).isEqualTo("/api/v1/verification-policies/FSISustainabilityCertification")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"requireFreshRevocation\":true")
        assertThat(body).contains("\"statusListCacheTtlSeconds\":600")
        assertThat(body).contains("\"retentionHorizonYears\":10")
    }

    @Test
    fun `set with no fields rejects with EXIT_USAGE`() {
        // No request to the gateway should be made.
        val (exit, _, err) = runCli(
            "supply-chain", "policy", "set",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("pass at least one of")
        // MockWebServer.requestCount is 0 because no request was made.
        assertThat(gateway.requestCount).isEqualTo(0)
    }

    @Test
    fun `403 on set suggests the policy-write scope`() {
        gateway.enqueue(
            jsonResponse(
                403,
                """{"error":"insufficient_scope"}""",
            ),
        )
        val (exit, _, err) = runCli(
            "supply-chain", "policy", "set",
            "--credential-class", "FSISustainabilityCertification",
            "--require-fresh-revocation", "true",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("oathy login --scope tenant:supply-chain.policy.write")
    }
}
