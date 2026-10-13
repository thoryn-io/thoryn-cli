package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3081 — `thoryn users ...` against a MockWebServer standing in for the api-gateway → product-api
 * `/api/v1/users` surface. Covers the directory list, the confirmation-gated `suspend`, `reactivate`,
 * and the `--email`→id resolution (including its zero/neither-argument failure paths).
 */
class UsersCommandTest : CommandTestBase() {

    private val userId = "11111111-1111-1111-1111-111111111111"
    private val slug = "acme"

    private fun usersEnvelope(vararg users: String): String =
        // The real product-api collection envelope (ListEnvelope): `{ "data": [...], "pagination": {...} }`.
        """{"data":[${users.joinToString(",")}],"pagination":{"cursor":null,"hasMore":false}}"""

    private fun user(id: String = userId, email: String = "jane@example.com", status: String = "ACTIVE"): String =
        """{"id":"$id","email":"$email","status":"$status","emailVerified":true,"createdAt":"2026-09-14T10:00:00Z"}"""

    @Test
    fun `list renders the users table`() {
        server.enqueue(jsonResponse(200, usersEnvelope(user())))

        val (exit, out, _) = runCli("users", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("jane@example.com").contains("ACTIVE")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/users")
        assertThat(req.method).isEqualTo("GET")
    }

    @Test
    fun `list passes the email filter as a query param`() {
        server.enqueue(jsonResponse(200, usersEnvelope(user())))

        val (exit, _, _) = runCli("users", "list", "--email", "jane@example.com", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/users?email=jane%40example.com")
    }

    @Test
    fun `suspend by id POSTs the suspend action with the confirmation header`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("users", "suspend", userId, "--confirm", slug, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains(userId).contains("Suspended")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/users/$userId/suspend")
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.getHeader(ProductApiClient.CONFIRM_HEADER)).isEqualTo(slug)
    }

    @Test
    fun `suspend by email resolves the id via a directory lookup then POSTs`() {
        server.enqueue(jsonResponse(200, usersEnvelope(user())))
        server.enqueue(noContent())

        val (exit, _, _) = runCli("users", "suspend", "--email", "jane@example.com", "--confirm", slug, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val lookup = server.takeRequest()
        assertThat(lookup.path).isEqualTo("/api/v1/users?email=jane%40example.com")
        val suspend = server.takeRequest()
        assertThat(suspend.path).isEqualTo("/api/v1/users/$userId/suspend")
        assertThat(suspend.getHeader(ProductApiClient.CONFIRM_HEADER)).isEqualTo(slug)
    }

    @Test
    fun `reactivate POSTs the reactivate action and sends no confirmation header`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("users", "reactivate", userId, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Reactivated")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/api/v1/users/$userId/reactivate")
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.getHeader(ProductApiClient.CONFIRM_HEADER)).isNull()
    }

    @Test
    fun `--environment rides X-Thoryn-Environment on the list + suspend (client-credentials env targeting, SSO-3068)`() {
        server.enqueue(jsonResponse(200, usersEnvelope(user())))
        server.enqueue(noContent())

        val (exit, _, _) = runCli("users", "suspend", "--email", "jane@example.com", "--environment", "production", "--confirm", slug, "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val lookup = server.takeRequest()
        assertThat(lookup.getHeader(ProductApiClient.ENVIRONMENT_HEADER)).isEqualTo("production")
        val suspend = server.takeRequest()
        assertThat(suspend.getHeader(ProductApiClient.ENVIRONMENT_HEADER)).isEqualTo("production")
    }

    @Test
    fun `suspend by email fails when no user matches and makes no suspend call`() {
        server.enqueue(jsonResponse(200, usersEnvelope())) // empty items

        val (exit, _, err) = runCli("users", "suspend", "--email", "ghost@example.com", "--gateway", baseUrl())

        assertThat(exit).isNotEqualTo(0)
        assertThat(err).contains("no user with email")
        // Only the lookup was issued — no suspend POST.
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `suspend with neither id nor email is a usage error and makes no call`() {
        val (exit, _, err) = runCli("users", "suspend", "--gateway", baseUrl())

        assertThat(exit).isNotEqualTo(0)
        assertThat(err).contains("provide a user id")
        assertThat(server.requestCount).isEqualTo(0)
    }
}
