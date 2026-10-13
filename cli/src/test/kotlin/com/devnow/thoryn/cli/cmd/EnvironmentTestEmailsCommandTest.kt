package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3026 — `thoryn env test-emails ...` against a MockWebServer standing in for the api-gateway →
 * product-api `/api/v1/environments/{id}/test-emails` surface. The target environment is given by
 * `--env <slug>`, so each command first lists environments (slug → id) and then reads the inbox.
 */
class EnvironmentTestEmailsCommandTest : CommandTestBase() {

    private val envId = "11111111-1111-1111-1111-111111111111"

    private fun enqueueEnvList() = server.enqueue(
        jsonResponse(
            200,
            """{"environments":[{"id":"$envId","slug":"staging","name":"Staging","kind":"sandbox","suspended":false}]}""",
        ),
    )

    @Test
    fun `list resolves the env slug then GETs the inbox, newest first`() {
        enqueueEnvList()
        server.enqueue(
            jsonResponse(
                200,
                """{"emails":[
                     {"id":"a1","channel":"email_verification","to":"dev@example.test","subject":"Verify your Thoryn account","actionLink":"https://id.example/verify-email?token=abc","createdAt":"2026-09-12T09:00:00Z"}
                   ]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("env", "test-emails", "list", "--env", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("email_verification").contains("dev@example.test")
        server.takeRequest() // env list (slug → id)
        val inbox = server.takeRequest()
        assertThat(inbox.method).isEqualTo("GET")
        assertThat(inbox.path).isEqualTo("/api/v1/environments/$envId/test-emails")
    }

    @Test
    fun `list --channel filters client-side`() {
        enqueueEnvList()
        server.enqueue(
            jsonResponse(
                200,
                """{"emails":[
                     {"id":"a1","channel":"email_verification","to":"dev@example.test","subject":"Verify","actionLink":"https://x/verify","createdAt":"2026-09-12T09:00:00Z"},
                     {"id":"a2","channel":"magic_link","to":"dev@example.test","subject":"Your link","actionLink":"https://x/magic","createdAt":"2026-09-12T08:00:00Z"}
                   ]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli(
            "env", "test-emails", "list", "--env", "staging", "--channel", "email_verification",
            "--output", "json", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("email_verification").contains("a1")
        assertThat(out).doesNotContain("magic_link")
    }

    @Test
    fun `get resolves the env slug then GETs one email with its action link`() {
        enqueueEnvList()
        server.enqueue(
            jsonResponse(
                200,
                """{"id":"a1","channel":"email_verification","to":"dev@example.test","subject":"Verify your Thoryn account","actionLink":"https://id.example/verify-email?token=abc","createdAt":"2026-09-12T09:00:00Z"}""",
            ),
        )

        val (exit, out, _) = runCli("env", "test-emails", "get", "a1", "--env", "staging", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("actionLink").contains("verify-email?token=abc")
        server.takeRequest() // env list
        val get = server.takeRequest()
        assertThat(get.method).isEqualTo("GET")
        assertThat(get.path).isEqualTo("/api/v1/environments/$envId/test-emails/a1")
    }
}
