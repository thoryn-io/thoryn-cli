package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3925 — `thoryn workload-identity trusts set-scopes <id|name> [--scope …] [--plan-scope …]`: the in-place scope change
 * (oauthy product-api `PUT /api/v1/workload-identity/trusts/{id}/scopes`). It sends only the sets named, resolves a trust by
 * its name through the (paged) list, refuses locally what the API would refuse with the API's codes, prints before → after
 * and that the wi_ client is unchanged, and renders the widening refusals: the RFC 9470 step-up (with the `thoryn login
 * --acr-values … --max-age …` line) and `elevated_action_requires_person`.
 */
class WorkloadIdentitySetScopesCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(fixture(name))

    private val trustId = "7c2d9e4f-1a3b-4c5d-8e6f-9a0b1c2d3e4f"
    private val wider = "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write tenant:access.read tenant:access.write tenant:workload-identity.read"

    private fun setScopes(vararg args: String) = runCli("workload-identity", "trusts", "set-scopes", *args, "--gateway", baseUrl())

    @Test
    fun `set-scopes by id sends only the named sets as a PUT and prints before, after and the unchanged wi_ client`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))
        server.enqueue(jsonResponse(200, fixture("trust-scopes-widened")))

        val (exit, out, err) = setScopes(trustId, "--scope", wider)

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val get = server.takeRequest()
        assertThat(get.method).isEqualTo("GET")
        assertThat(get.path).isEqualTo("/api/v1/workload-identity/trusts/$trustId")
        val put = server.takeRequest()
        assertThat(put.method).isEqualTo("PUT")
        assertThat(put.path).isEqualTo("/api/v1/workload-identity/trusts/$trustId/scopes")
        val body = parseJson(put.body.readUtf8())
        assertThat(body["scopes"]).isEqualTo(wider.split(' '))
        assertThat(body).doesNotContainKey("planScopes")
        assertThat(out)
            .contains("scopes changed in place")
            .contains("→ $wider")
            .contains("The wi_ client wi_10a7b379c79f7d1353f5798d is unchanged")
            .contains("plan scopes:")
    }

    @Test
    fun `set-scopes by name resolves the trust through the paged list, and --plan-scope alone sends only planScopes`() {
        server.enqueue(jsonResponse(200, fixture("trust-list")))
        server.enqueue(jsonResponse(200, """{"data":[{"id":"$trustId","name":"thoryn-cli-ci"}],"pagination":{"cursor":null,"hasMore":false}}"""))
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))
        server.enqueue(jsonResponse(200, fixture("trust-scopes-widened")))

        val (exit, _, err) = setScopes("thoryn-cli-ci", "--plan-scope", "tenant:environments.read,tenant:access.read")

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/workload-identity/trusts")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/workload-identity/trusts?cursor=c-2")
        server.takeRequest()
        val put = server.takeRequest()
        assertThat(put.path).isEqualTo("/api/v1/workload-identity/trusts/$trustId/scopes")
        val body = parseJson(put.body.readUtf8())
        assertThat(body).doesNotContainKey("scopes")
        assertThat(body["planScopes"]).isEqualTo(listOf("tenant:environments.read", "tenant:access.read"))
    }

    @Test
    fun `an unknown name is workload_identity_trust_not_found and nothing is written`() {
        server.enqueue(jsonResponse(200, """{"data":[],"pagination":{"cursor":null,"hasMore":false}}"""))

        val (exit, _, err) = setScopes("nope", "--scope", "tenant:applications.read")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("workload_identity_trust_not_found").contains("nope")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `set-scopes refuses locally with the API's codes before any request`() {
        assertThat(setScopes(trustId).err).contains("invalid_request")
        assertThat(setScopes(trustId, "--scope", "openid").err).contains("invalid_scope")
        assertThat(setScopes(trustId, "--plan-scope", "tenant:applications.write").err).contains("plan_scope_not_read_only")
        assertThat(setScopes(trustId, "--scope", "tenant:applications.read", "--plan-scope", "tenant:users.read").err).contains("plan_scope_not_subset")
        assertThat(setScopes(trustId).exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a widening without a fresh passkey sign-in renders the step-up and the login line`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))
        server.enqueue(
            problem(403, "problem-insufficient-user-authentication").setHeader(
                "WWW-Authenticate",
                "Bearer error=\"insufficient_user_authentication\", error_description=\"A higher level of authentication is required\", " +
                    "acr_values=\"urn:thoryn:acr:phishing_resistant\", max_age=\"300\"",
            ),
        )

        val (exit, _, err) = setScopes(trustId, "--scope", wider)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err)
            .contains("needs a passkey sign-in from the last 5 minutes")
            .contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .doesNotContain("thoryn login --scope")
    }

    @Test
    fun `a widening by a workload identity renders elevated_action_requires_person with what to do`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-plan")))
        server.enqueue(problem(403, "problem-elevated-action-requires-person"))

        val (exit, _, err) = setScopes(trustId, "--scope", wider)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("elevated_action_requires_person").contains("Adding a scope to a trust is a person's act")
    }

    @Test
    fun `the plan-profile-already-set hint now points at set-scopes for the scopes`() {
        server.enqueue(problem(409, "problem-plan-profile-already-set"))

        val (_, _, err) = runCli("workload-identity", "trusts", "set-plan-profile", trustId, "--plan-environment", "x-plan", "--gateway", baseUrl())

        assertThat(err).contains("plan_profile_already_set").contains("set-scopes <id> --plan-scope")
    }
}
