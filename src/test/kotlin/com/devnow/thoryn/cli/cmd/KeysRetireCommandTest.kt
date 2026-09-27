package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3396 — `thoryn keys retire | retirements [list | get]` and the passkey step-up it needs, against a
 * MockWebServer standing in for the api-gateway → product-api `/api/v1/signing-keys/{kind}/retirements`
 * surface (oathy SSO-3396).
 *
 * The bodies under `src/test/resources/signing-keys/retirement-*.json` and `problem-acknowledgement.json`
 * are CAPTURED from product-api's real `SigningKeyRetirementController` (oathy `SigningKeyRetirementE2ETest`,
 * MockMvc over the real security chain, Postgres and Jackson); the step-up challenge header is the one its
 * `@RequiresAssurance` rail emitted in the same run (RFC 9470 puts it in the header, with no body).
 */
class KeysRetireCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/signing-keys/$name.json")) { "missing fixture $name" }.readText()

    @Test
    fun `retire --kind sign-in --yes acknowledges the consequences and prints what no longer verifies`() {
        server.enqueue(jsonResponse(201, fixture("retirement-signin-done")))

        val (exit, out, _) = runCli("keys", "retire", "--kind", "sign-in", "--through-version", "1", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("tenant-ws.5d460df5-7c71-49c4-bf66-bf4a1cdefa79-v1")
            .contains("DONE — every version up to 1 is retired")
            .contains("tenant-ws.5d460df5-7c71-49c4-bf66-bf4a1cdefa79-v2 signs from now on")
            .contains("sign their users in again")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/signing-keys/sign-in/retirements")
        assertThat(parseJson(req.body.readUtf8())).containsEntry("acknowledgeConsequences", true).containsEntry("throughVersion", 1)
    }

    @Test
    fun `retire without --through-version retires the signing version and names no version`() {
        server.enqueue(jsonResponse(201, fixture("retirement-signin-done")))

        runCli("keys", "retire", "--kind", "sign-in", "--yes", "--gateway", baseUrl())

        assertThat(parseJson(server.takeRequest().body.readUtf8()))
            .containsEntry("acknowledgeConsequences", true).doesNotContainKey("throughVersion")
    }

    @Test
    fun `retire --wait follows a security-event retirement until the rotator has done it`() {
        server.enqueue(jsonResponse(202, fixture("retirement-pending")))
        server.enqueue(jsonResponse(200, fixture("retirement-done")))

        val (exit, out, _) = runCli(
            "keys", "retire", "--kind", "security-events", "--wait", "--poll-interval", "0", "--yes", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Waiting for the key's rotator").contains("DONE — every version up to 2 is retired")
        server.takeRequest()
        assertThat(server.takeRequest().path)
            .isEqualTo("/api/v1/signing-keys/security-events/retirements/53f1314d-1861-4e3b-8df3-6b8dd513f9ff")
    }

    @Test
    fun `without a passkey sign-in the step-up challenge becomes the exact re-login line`() {
        server.enqueue(
            MockResponse().setResponseCode(403).setHeader(
                "WWW-Authenticate",
                "Bearer error=\"insufficient_user_authentication\", " +
                    "error_description=\"A higher level of authentication is required\", " +
                    "acr_values=\"urn:thoryn:acr:phishing_resistant\"",
            ),
        )

        val (exit, _, err) = runCli("keys", "retire", "--kind", "sign-in", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("passkey sign-in")
            .contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .doesNotContain("Required scope")
    }

    @Test
    fun `retire without --yes and no terminal refuses and sends nothing`() {
        val (exit, _, err) = runCli("keys", "retire", "--kind", "sign-in", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("Refusing to retire without confirmation")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a version below 1 is refused before any call`() {
        val (exit, _, err) = runCli("keys", "retire", "--kind", "sign-in", "--through-version", "0", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--through-version must be 1 or above")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a refused acknowledgement is reported as nothing retired`() {
        server.enqueue(
            MockResponse().setResponseCode(400).setHeader("Content-Type", "application/problem+json")
                .setBody(fixture("problem-acknowledgement")),
        )

        val (exit, _, err) = runCli("keys", "retire", "--kind", "sign-in", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("acknowledgement_required").contains("nothing was retired")
    }

    @Test
    fun `retirements list and get read the environment's retirements`() {
        server.enqueue(jsonResponse(200, """{"data":[${fixture("retirement-done")}],"pagination":{"cursor":null,"hasMore":false}}"""))
        val (listExit, listOut, _) = runCli("keys", "retirements", "list", "--kind", "security-events", "--gateway", baseUrl())
        assertThat(listExit).isEqualTo(0)
        assertThat(listOut).contains("53f1314d-1861-4e3b-8df3-6b8dd513f9ff").contains("DONE")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/signing-keys/security-events/retirements")

        server.enqueue(jsonResponse(200, fixture("retirement-signin-done")))
        val (getExit, getOut, _) = runCli("keys", "retirements", "get", "ed2fd9b6-3e2b-4e4c-af5a-72125c31628b", "--kind", "sign-in", "--gateway", baseUrl())
        assertThat(getExit).isEqualTo(0)
        assertThat(getOut).contains("retiredKids").contains("DONE — every version up to 1 is retired")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/signing-keys/sign-in/retirements/ed2fd9b6-3e2b-4e4c-af5a-72125c31628b")
    }
}
