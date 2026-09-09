package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-2952 (epic SSO-2947) — `thoryn provision ci-identity` mints the CI's confidential
 * `client_credentials` machine client from the declarative `/provision/ci-identity.json` spec, and
 * routes the ONE server-minted secret through the [MachineClientProvisioner.SecretSink] (the SecretIo
 * channel), never to stdout/argv/a log.
 *
 * The MockWebServer stands in for the api-gateway → product-api `POST /api/v1/applications` surface.
 */
class ProvisionCiIdentityTest : CommandTestBase() {

    @Test
    fun `provision ci-identity mints a confidential client_credentials client with the environments scopes and routes the secret to the SecretIo sink`() {
        // The server mints a clientId + a one-shot clientSecret, echoing the granted scopes.
        server.enqueue(
            jsonResponse(
                201,
                """{"clientId":"ci-mc-1","clientSecret":"sek-ret-value","status":"active",
                    "scopes":["tenant:applications.write","tenant:environments.write"]}""",
            ),
        )

        // Capturing sink standing in for the --secret-file / SecretIo channel.
        val captured = mutableListOf<Pair<String, String>>()
        val sink = MachineClientProvisioner.SecretSink { clientId, secret -> captured += clientId to secret; true }

        val client = ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"))
        val spec = MachineClientSpec.ciIdentity()
        val result = MachineClientProvisioner(client, sink).provision(spec)

        // The bundled spec carries the CORRECTED `environments` scope names, never the phantom `env.*`.
        assertThat(spec.scopes)
            .contains("tenant:environments.write", "tenant:environments.read")
            .doesNotContain("tenant:env.write", "tenant:env.read")
        assertThat(spec.clientType).isEqualTo("confidential")
        assertThat(spec.grantTypes).containsExactly("client_credentials")

        // (a) the create request carried the confidential + client_credentials machine shape and the
        //     `environments` scopes (not `env.*`).
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/applications")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        val body = req.body.readUtf8()
        assertThat(body)
            .contains("\"clientType\":\"confidential\"")
            .contains("\"client_credentials\"")
            .contains("tenant:environments.write")
            .contains("tenant:environments.read")
        assertThat(body).doesNotContain("tenant:env.write", "tenant:env.read")

        // (b) the secret was routed to the SecretIo sink — exactly once, keyed by the clientId.
        assertThat(captured).containsExactly("ci-mc-1" to "sek-ret-value")

        // (c) the secret is ABSENT from the returned result (clientId + granted scopes only).
        assertThat(result.clientId).isEqualTo("ci-mc-1")
        assertThat(result.secretDelivered).isTrue()
        val mapper = tools.jackson.module.kotlin.jacksonObjectMapper()
        assertThat(mapper.writeValueAsString(result)).doesNotContain("sek-ret-value")
    }

    @Test
    fun `provision ci-identity writes the secret to the secret-file and keeps it off stdout`() {
        server.enqueue(
            jsonResponse(
                201,
                """{"clientId":"ci-mc-2","clientSecret":"file-secret-99","status":"active",
                    "scopes":["tenant:applications.write","tenant:environments.write"]}""",
            ),
        )
        val secretFile = File(tempHome.toFile(), "ci.secret")

        val result = runCli("provision", "ci-identity", "--gateway", baseUrl(), "--secret-file", secretFile.path)

        assertThat(result.exit).isEqualTo(0)
        // The clientId + granted scopes are printed to stdout…
        assertThat(result.out).contains("ci-mc-2").contains("tenant:environments.write")
        // …but the secret NEVER reaches stdout (it goes only to the owner-only file).
        assertThat(result.out).doesNotContain("file-secret-99")
        assertThat(secretFile.readText().trim()).isEqualTo("file-secret-99")

        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/applications")
        assertThat(req.body.readUtf8())
            .contains("\"clientType\":\"confidential\"")
            .contains("tenant:environments.write")
    }

    @Test
    fun `provision ci-identity exits EXIT_NO_SECRET when the secret cannot be delivered`() {
        server.enqueue(jsonResponse(201, """{"clientId":"ci-mc-3","clientSecret":"undelivered","status":"active"}"""))

        // No --secret-file, and the test JVM's stdout is not an interactive TTY → SecretIo refuses to
        // print into a pipe, so the command exits EXIT_NO_SECRET (the operator must re-run with a file).
        val result = runCli("provision", "ci-identity", "--gateway", baseUrl())

        assertThat(result.exit).isEqualTo(com.devnow.thoryn.cli.cmd.SecretIo.EXIT_NO_SECRET)
        assertThat(result.out).doesNotContain("undelivered")
    }
}
