package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-4472 — [ForgejoRepositoryLookup] against a MockWebServer standing in for a Forgejo instance's public REST API
 * (`GET /api/v1/repos/{owner}/{repo}`, the shape Forgejo answers): the ids and the canonical names from a public
 * repository; anonymous (no credential is ever sent); a private one (404) and a proxied API (a redirect, never followed)
 * end in the advice to pass the ids.
 */
class ForgejoRepositoryLookupTest {

    private lateinit var instance: MockWebServer

    @BeforeEach
    fun start() {
        instance = MockWebServer().also { it.start() }
    }

    @AfterEach
    fun stop() {
        instance.shutdown()
    }

    private fun origin() = instance.url("/").toString().trimEnd('/')

    @Test
    fun `a public repository's ids and canonical names come from the instance's API, asked anonymously`() {
        instance.enqueue(
            MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(
                """{"id":42,"owner":{"id":7,"login":"acme","username":"acme"},"name":"infra","full_name":"acme/infra","private":false,"fork":false}""",
            ),
        )

        val result = ForgejoRepositoryLookup().lookup(origin(), "Acme", "Infra")

        assertThat(result).isEqualTo(ForgejoRepositoryLookup.Result.Found(owner = "acme", ownerId = 7, repository = "infra", repositoryId = 42))
        val request = instance.takeRequest()
        assertThat(request.path).isEqualTo("/api/v1/repos/Acme/Infra")
        assertThat(request.getHeader("Authorization")).isNull()
        assertThat(request.getHeader("Cookie")).isNull()
    }

    @Test
    fun `a private repository is not visible anonymously — the failure names the ids to pass and where to read them`() {
        instance.enqueue(MockResponse().setResponseCode(404).setBody("""{"message":"Not Found"}"""))

        val result = ForgejoRepositoryLookup().lookup(origin(), "acme", "secret-infra") as ForgejoRepositoryLookup.Result.Failed

        assertThat(result.message).contains("no public repository acme/secret-infra (HTTP 404)")
            .contains("--owner-id and --repository-id")
            .contains("GET ${origin()}/api/v1/repos/acme/secret-infra")
    }

    @Test
    fun `an API behind an authenticating proxy redirects — the redirect is never followed`() {
        instance.enqueue(MockResponse().setResponseCode(302).setHeader("Location", instance.url("/oauth2/start").toString()))
        instance.enqueue(MockResponse().setResponseCode(200).setBody("""{"id":1,"owner":{"id":1,"login":"proxy"},"name":"login"}"""))

        val result = ForgejoRepositoryLookup().lookup(origin(), "acme", "infra") as ForgejoRepositoryLookup.Result.Failed

        assertThat(result.message).contains("redirected").contains("HTTP 302").contains("authenticating proxy").contains("--owner-id")
        assertThat(instance.requestCount).isEqualTo(1)
    }

    @Test
    fun `an answer without the ids is not trusted`() {
        instance.enqueue(MockResponse().setResponseCode(200).setBody("""<html>a login page</html>"""))

        val result = ForgejoRepositoryLookup().lookup(origin(), "acme", "infra")

        assertThat(result).isInstanceOf(ForgejoRepositoryLookup.Result.Failed::class.java)
    }
}
