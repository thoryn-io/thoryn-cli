package com.devnow.thoryn.cli.cmd.supplychain

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-959 — unit tests for `thoryn supply-chain trust-registry ...`.
 *
 * Each test sets up a MockWebServer response for a known product-api URL,
 * runs the CLI in-process via picocli, and asserts on the URL path / body /
 * status and on stdout/stderr.
 */
class TrustRegistryCommandTest : SupplyChainCommandTestBase() {

    @Test
    fun `list returns table rows for the credential class`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[
                  {"issuerId":"https://mps.nl","displayName":"MPS NL","jwksUri":"https://mps.nl/jwks","currentKid":"k1","state":"active"},
                  {"issuerId":"https://globalgap.org","displayName":"GlobalG.A.P.","jwksUri":"https://globalgap.org/jwks","currentKid":"k7","state":"soft-deprecated"}
                ]""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "trust-registry", "list",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("https://mps.nl")
        assertThat(out).contains("MPS NL")
        assertThat(out).contains("https://globalgap.org")
        assertThat(out).contains("soft-deprecated")

        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/api/v1/trust-registry/credential-classes/FSISustainabilityCertification/issuers")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `list with --output json prints the raw JSON`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """[{"issuerId":"https://mps.nl","state":"active"}]""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "trust-registry", "list",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
            "--output", "json",
        )

        assertThat(exit).isEqualTo(0)
        // The pretty-printed JSON contains the issuerId.
        assertThat(out).contains("\"issuerId\"")
        assertThat(out).contains("https://mps.nl")
    }

    @Test
    fun `add POSTs the issuer body and returns the created record`() {
        gateway.enqueue(
            jsonResponse(
                201,
                """{"issuerId":"https://mps.nl","displayName":"MPS NL","state":"active","currentKid":"k1"}""",
            ),
        )

        val (exit, out, _) = runCli(
            "supply-chain", "trust-registry", "add",
            "--credential-class", "FSISustainabilityCertification",
            "--issuer", "https://mps.nl",
            "--display-name", "MPS NL",
            "--soft-deprecate-on", "2027-01-01",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("https://mps.nl")

        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/api/v1/trust-registry/credential-classes/FSISustainabilityCertification/issuers")
        assertThat(req.method).isEqualTo("POST")
        val body = req.body.readUtf8()
        assertThat(body).contains("\"issuer\":\"https://mps.nl\"")
        assertThat(body).contains("\"displayName\":\"MPS NL\"")
        assertThat(body).contains("\"softDeprecateOn\":\"2027-01-01\"")
    }

    @Test
    fun `preview POSTs to the issuers preview endpoint without classId`() {
        gateway.enqueue(
            jsonResponse(
                200,
                """{"issuerId":"https://mps.nl","currentKid":"k1","alg":"ES256"}""",
            ),
        )

        val (exit, _, _) = runCli(
            "supply-chain", "trust-registry", "preview",
            "--issuer", "https://mps.nl",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)

        val req = gateway.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/trust-registry/issuers/preview")
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.body.readUtf8()).contains("\"issuer\":\"https://mps.nl\"")
    }

    @Test
    fun `remove DELETEs the issuer and prints a confirmation`() {
        gateway.enqueue(jsonResponse(204, ""))

        val (exit, out, _) = runCli(
            "supply-chain", "trust-registry", "remove",
            "--credential-class", "FSISustainabilityCertification",
            "--issuer", "https://mps.nl",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Removed issuer 'https://mps.nl'")

        val req = gateway.takeRequest()
        assertThat(req.path)
            .isEqualTo("/api/v1/trust-registry/credential-classes/FSISustainabilityCertification/issuers/https%3A%2F%2Fmps.nl")
        assertThat(req.method).isEqualTo("DELETE")
    }

    @Test
    fun `insufficient-scope failure prints the required scope hint`() {
        gateway.enqueue(
            jsonResponse(
                403,
                """{"error":"insufficient_scope","error_description":"Required scope: tenant:supply-chain.trust-registry.write"}""",
            ),
        )

        val (exit, _, err) = runCli(
            "supply-chain", "trust-registry", "add",
            "--credential-class", "FSISustainabilityCertification",
            "--issuer", "https://mps.nl",
            "--gateway", gatewayUrl(),
        )

        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("insufficient_scope")
        assertThat(err).contains("Run: oathy login --scope tenant:supply-chain.trust-registry.write")
    }

    @Test
    fun `not signed in returns EXIT_NOT_SIGNED_IN`() {
        clearTokens()
        val (exit, _, err) = runCli(
            "supply-chain", "trust-registry", "list",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
    }

    @Test
    fun `unknown --output value returns EXIT_USAGE`() {
        val (exit, _, err) = runCli(
            "supply-chain", "trust-registry", "list",
            "--credential-class", "FSISustainabilityCertification",
            "--gateway", gatewayUrl(),
            "--output", "xml",
        )
        assertThat(exit).isEqualTo(SupplyChainCommandSupport.EXIT_USAGE)
        assertThat(err).contains("--output must be one of")
    }
}
