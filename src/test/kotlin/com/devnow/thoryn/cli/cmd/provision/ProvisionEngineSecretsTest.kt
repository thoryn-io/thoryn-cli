package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
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

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

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

    private fun engine(
        env: Map<String, String>,
        out: PrintStream = PrintStream(ByteArrayOutputStream()),
        sink: ProvisionEngine.SecretSink = ProvisionEngine.SecretSink.undeliverable(),
    ): ProvisionEngine =
        ProvisionEngine(
            clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
            out = out,
            err = out,
            env = { env[it] },
            secretSink = sink,
        )

    // ── SSO-3113: a confidential application's server-minted secret ──

    private val confidentialApp = ProvisionFile.parse(
        """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: ci-worker
            environment: sbx
            spec: { displayName: "CI worker", clientType: confidential, grantTypes: [client_credentials], scopes: ["tenant:environments.write"] }
          - kind: application
            name: spa
            environment: sbx
            spec: { displayName: "SPA", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
        """.trimIndent().toByteArray(),
        "provision.yaml",
    )

    @Test
    fun `a minted client secret leaves ONLY through the sink — never the receipt, the plan, or the console`() {
        val console = ByteArrayOutputStream()
        val captured = mutableListOf<Pair<String, String>>()
        val engine = engine(emptyMap(), PrintStream(console), ProvisionEngine.SecretSink { id, secret -> captured += id to secret; true })
        val plan = engine.plan(confidentialApp, null, false)
        assertThat(plan.changes[0].reason).contains("(a client secret will be minted and shown once)")
        assertThat(plan.changes[1].reason).doesNotContain("minted") // public: no secret
        val persisted = mutableListOf<ProvisionReceipt>()
        val receipt = engine.apply(confidentialApp, null, plan, "acme", null) { persisted += it }

        val clientId = receipt.resources[0].id
        val secret = api.mintedSecrets.getValue(clientId)
        assertThat(captured).containsExactly(clientId to secret) // exactly once, the confidential client only
        assertThat(engine.undeliveredSecrets).isEmpty()
        val mapper = jacksonObjectMapper()
        assertThat(mapper.writeValueAsString(receipt)).doesNotContain(secret)
        assertThat(persisted.map { mapper.writeValueAsString(it) }).noneMatch { it.contains(secret) }
        assertThat(mapper.writeValueAsString(plan.toStructured())).doesNotContain(secret)
        assertThat(console.toString()).doesNotContain(secret).contains("client secret minted — shown once")
        assertThat(receipt.resources.map { it.key }).containsExactly("application/ci-worker", "application/spa")
    }

    @Test
    fun `an undeliverable secret still records the resource and names the client for rotate-secret`() {
        val console = ByteArrayOutputStream()
        val engine = engine(emptyMap(), PrintStream(console)) // default sink: delivers nothing
        val receipt = engine.apply(confidentialApp, null, engine.plan(confidentialApp, null, false), "acme", null) {}

        val clientId = receipt.resources[0].id
        assertThat(engine.undeliveredSecrets).containsExactly(clientId)
        assertThat(receipt.resources[0].id).isEqualTo(api.applications[0]["clientId"]) // exists + owned
        assertThat(console.toString())
            .contains("could NOT be delivered")
            .contains("thoryn clients rotate-secret $clientId")
            .doesNotContain(api.mintedSecrets.getValue(clientId))
        // A later apply that creates nothing reports nothing undelivered.
        api.reset()
        engine.apply(confidentialApp, receipt, engine.plan(confidentialApp, receipt, false), "acme", null) {}
        assertThat(engine.undeliveredSecrets).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `env-named secrets are forwarded to the API but never recorded or printed`() {
        val console = ByteArrayOutputStream()
        val engine = engine(
            mapOf("TEST_USER_EMAIL" to "t@example.com", "TEST_USER_PASSWORD" to "Sup3r-Secret!", "SMTP_PASSWORD" to "smtp-s3cret"),
            PrintStream(console),
        )
        val plan = engine.plan(file, receipt = null, prune = false)
        val persisted = mutableListOf<ProvisionReceipt>()
        val receipt = engine.apply(file, null, plan, workspace = "acme", confirmSlug = null) { persisted += it }

        val userBody = api.writes.first { it.path == "/api/v1/users" }.body
        assertThat(userBody).containsEntry("password", "Sup3r-Secret!").containsEntry("email", "t@example.com").doesNotContainKey("passwordEnv")
        val smtpBody = api.writes.first { it.path == "/api/v1/email-provider" }.body
        assertThat(smtpBody).containsEntry("smtpPassword", "smtp-s3cret").containsEntry("smtpPort", 2525).containsEntry("enabled", true)

        val serialised = jacksonObjectMapper().writeValueAsString(receipt)
        assertThat(serialised).doesNotContain("Sup3r-Secret!").doesNotContain("smtp-s3cret")
        assertThat(persisted).isNotEmpty
        assertThat(persisted.map { jacksonObjectMapper().writeValueAsString(it) }).noneMatch { it.contains("s3cret") || it.contains("Secret!") }
        assertThat(console.toString()).doesNotContain("Sup3r-Secret!").doesNotContain("smtp-s3cret")
        assertThat(receipt.resources.map { it.key }).containsExactly("user/tester", "emailProvider/emailProvider")
        assertThat(receipt.resources[1].attributes).containsEntry("configVersion", "1").doesNotContainKey("smtpPassword")
    }

    @Test
    fun `an unset secret env var fails closed before any write`() {
        val engine = engine(mapOf("TEST_USER_EMAIL" to "t@example.com"))
        val plan = engine.plan(file, null, false)
        assertThatThrownBy { engine.apply(file, null, plan, "acme", null) {} }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("TEST_USER_PASSWORD")
            .hasMessageContaining("not set")
        assertThat(api.writes).isEmpty()
    }
}
