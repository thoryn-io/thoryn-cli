package com.devnow.thoryn.cli.api

import com.devnow.thoryn.cli.auth.Tokens
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-2870 — [ProductApiClient] rides the selected environment on EVERY request as the
 * `X-Thoryn-Environment` header when (and only when) an `environmentSlug` is set, so the whole
 * customer-plane surface targets the caller-selected environment. A null/blank slug ⇒ no header,
 * i.e. the pre-SSO-2870 (production-plane default) behaviour.
 */
class ProductApiClientEnvironmentHeaderTest {

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
    fun `sends X-Thoryn-Environment when an environment slug is set`() {
        server.enqueue(json(200, """{"items":[],"total":0}"""))
        val client = ProductApiClient(
            gateway = baseUrl(),
            tokens = Tokens(accessToken = "AT"),
            environmentSlug = "sandbox-alpha",
        )

        client.listApplications()

        val req = server.takeRequest()
        assertThat(req.getHeader(ProductApiClient.ENVIRONMENT_HEADER)).isEqualTo("sandbox-alpha")
    }

    @Test
    fun `sends no environment header when the slug is null`() {
        server.enqueue(json(200, """{"items":[],"total":0}"""))
        val client = ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT"))

        client.listApplications()

        assertThat(server.takeRequest().getHeader(ProductApiClient.ENVIRONMENT_HEADER)).isNull()
    }

    @Test
    fun `sends no environment header when the slug is blank`() {
        server.enqueue(json(200, """{"items":[],"total":0}"""))
        val client = ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT"), environmentSlug = "  ")

        client.listApplications()

        assertThat(server.takeRequest().getHeader(ProductApiClient.ENVIRONMENT_HEADER)).isNull()
    }
}
