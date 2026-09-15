package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3088 (epic SSO-3087) — the secret boundary of provisioning-as-code: a `<key>Env` spec entry is
 * resolved from the environment at apply time and forwarded to the product API, but NEVER lands in
 * the receipt, the plan, or the console output; an unset env var fails closed (no silent blank
 * credential); `{{env.NAME}}` placeholders resolve the same way.
 */
class ProvisionEngineSecretsTest : CommandTestBase() {

    private val file = ProvisionFile.parse(
        """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: user
            name: tester
            environment: sbx
            spec: { email: "{{env.TEST_USER_EMAIL}}", passwordEnv: TEST_USER_PASSWORD, emailVerified: true }
          - kind: emailProvider
            environment: sbx
            spec: { smtpHost: smtp.example.com, smtpPort: "2525", smtpUsername: ci, smtpPasswordEnv: SMTP_PASSWORD, transportSecurity: starttls, fromAddress: no-reply@example.com }
        """.trimIndent().toByteArray(),
        "provision.yaml",
    )

    private fun engine(env: Map<String, String>, out: PrintStream = PrintStream(ByteArrayOutputStream())): ProvisionEngine =
        ProvisionEngine(
            clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
            out = out,
            err = out,
            env = { env[it] },
        )

    @Test
    fun `env-named secrets are forwarded to the API but never recorded or printed`() {
        server.enqueue(jsonResponse(201, """{"id":"u-9","email":"t@example.com"}"""))
        server.enqueue(jsonResponse(200, """{"providerType":"smtp","smtpHost":"smtp.example.com","fromAddress":"no-reply@example.com","configVersion":"3","enabled":true}"""))
        val console = ByteArrayOutputStream()
        val engine = engine(
            mapOf("TEST_USER_EMAIL" to "t@example.com", "TEST_USER_PASSWORD" to "Sup3r-Secret!", "SMTP_PASSWORD" to "smtp-s3cret"),
            PrintStream(console),
        )
        val plan = engine.plan(file, receipt = null, prune = false)
        val persisted = mutableListOf<ProvisionReceipt>()
        val receipt = engine.apply(file, null, plan, workspace = "acme", confirmSlug = null) { persisted += it }

        val userBody = server.takeRequest().body.readUtf8()
        assertThat(userBody).contains("\"password\":\"Sup3r-Secret!\"").contains("\"email\":\"t@example.com\"").doesNotContain("passwordEnv")
        val smtpBody = server.takeRequest().body.readUtf8()
        assertThat(smtpBody).contains("\"smtpPassword\":\"smtp-s3cret\"").contains("\"smtpPort\":2525").contains("\"enabled\":true")

        val serialised = jacksonObjectMapper().writeValueAsString(receipt)
        assertThat(serialised).doesNotContain("Sup3r-Secret!").doesNotContain("smtp-s3cret")
        assertThat(persisted).isNotEmpty
        assertThat(persisted.map { jacksonObjectMapper().writeValueAsString(it) }).noneMatch { it.contains("s3cret") || it.contains("Secret!") }
        assertThat(console.toString()).doesNotContain("Sup3r-Secret!").doesNotContain("smtp-s3cret")
        assertThat(receipt.resources.map { it.key to it.id }).containsExactly("user/tester" to "u-9", "emailProvider/emailProvider" to "smtp")
        assertThat(receipt.resources[1].attributes).containsEntry("configVersion", "3").doesNotContainKey("smtpPassword")
    }

    @Test
    fun `an unset secret env var fails closed before any write`() {
        val engine = engine(mapOf("TEST_USER_EMAIL" to "t@example.com"))
        val plan = engine.plan(file, null, false)
        assertThatThrownBy { engine.apply(file, null, plan, "acme", null) {} }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("TEST_USER_PASSWORD")
            .hasMessageContaining("not set")
        assertThat(server.requestCount).isZero()
    }
}
