package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.Tokens
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-2861 — reactive refresh-on-401 retry in [ProductApiClient].
 *
 * The client refreshes once and retries a single time when a request returns `401` and a
 * `reauthenticate` callback is wired; without a callback (or when the refresh yields no new token)
 * the `401` surfaces unchanged, and a still-`401` retry never loops.
 */
class ProductApiClientTest {

    private lateinit var server: MockWebServer

    @BeforeEach
    fun setUp() {
        server = MockWebServer().also { it.start() }
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun json(status: Int, body: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)

    private fun baseUrl(): String = server.url("/").toString().trimEnd('/')

    @Test
    fun `refreshes once and retries with the new bearer on 401`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))
        server.enqueue(json(200, """{"items":[],"total":0}"""))

        var refreshCalls = 0
        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old", refreshToken = "RT"),
            reauthenticate = { refreshCalls++; Tokens(accessToken = "AT-new", refreshToken = "RT") },
        )

        val result = client.listApplications()

        assertThat(result["total"].asInt()).isEqualTo(0)
        assertThat(refreshCalls).isEqualTo(1)
        // First attempt carried the stale bearer; the retry carried the refreshed one.
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer AT-old")
        assertThat(server.takeRequest().getHeader("Authorization")).isEqualTo("Bearer AT-new")
    }

    @Test
    fun `without a reauthenticator a 401 surfaces unchanged and is not retried`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))

        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old"),
        )

        assertThatThrownBy { client.listApplications() }
            .isInstanceOfSatisfying(ProductApiException::class.java) {
                assertThat(it.httpStatus).isEqualTo(401)
            }
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `a still-401 retry raises the 401 and never loops`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))
        server.enqueue(json(401, """{"error":"invalid_token"}"""))

        var refreshCalls = 0
        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old"),
            reauthenticate = { refreshCalls++; Tokens(accessToken = "AT-new") },
        )

        assertThatThrownBy { client.listApplications() }
            .isInstanceOfSatisfying(ProductApiException::class.java) {
                assertThat(it.httpStatus).isEqualTo(401)
            }
        assertThat(refreshCalls).isEqualTo(1) // refreshed once
        assertThat(server.requestCount).isEqualTo(2) // one retry, no loop
    }

    @Test
    fun `a null refresh result declines the retry and surfaces the 401`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))

        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old"),
            reauthenticate = { null }, // e.g. no refresh token / redemption failed
        )

        assertThatThrownBy { client.listApplications() }
            .isInstanceOf(ProductApiException::class.java)
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `an unchanged refresh token declines the retry`() {
        server.enqueue(json(401, """{"error":"invalid_token"}"""))

        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT-old"),
            reauthenticate = { Tokens(accessToken = "AT-old") }, // refresh gave the same token back
        )

        assertThatThrownBy { client.listApplications() }
            .isInstanceOf(ProductApiException::class.java)
        assertThat(server.requestCount).isEqualTo(1)
    }

    /**
     * SSO-2958 — a body-less POST (`rotate-secret` and the other empty-body verbs) must serialise
     * its request body to `{}`. Historically these passed a raw `emptyMap()`
     * (`kotlin.collections.EmptyMap`), which jackson-module-kotlin reflected on and which crashed the
     * NATIVE binary (`KotlinReflectionInternalError: Unresolved class … EmptyMap`). The fix routes
     * empty bodies through a Jackson `ObjectNode`; this JVM guard pins the `{}` wire shape (it cannot
     * catch the native reflection failure — the `__diag empty-post` native proof covers that).
     */
    @Test
    fun `an empty-body POST serialises the request body to an empty JSON object`() {
        server.enqueue(json(200, """{"newSecret":"s","previousSecretExpiresAt":"2026-01-01T00:00:00Z"}"""))

        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT"),
        )

        client.rotateApplicationSecret("client-123")

        val recorded = server.takeRequest()
        assertThat(recorded.method).isEqualTo("POST")
        assertThat(recorded.body.readUtf8()).isEqualTo("{}")
    }
}
