package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3430 (follow-up of SSO-3428) — a resource's `environment` may be a `{{env.NAME}}` placeholder,
 * resolved when `thoryn provision` reads the file: an unrendered starter repository names its sandbox
 * through a CI variable (`environment: "{{env.THORYN_ENVIRONMENT}}"`). The field is addressing, so an
 * unset variable fails closed; a file without a placeholder is read exactly as before.
 */
class ProvisionEnvironmentPlaceholderTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private val appFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: web
            environment: "{{env.THORYN_ENVIRONMENT}}"
            spec: { displayName: "{{env.THORYN_APP_NAME}}", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
          - kind: user
            name: test-user
            environment: "{{ env.THORYN_ENVIRONMENT }}"
            spec: { email: tester@example.com }
    """.trimIndent()

    private fun parse(yaml: String, env: Map<String, String>) =
        ProvisionFile.parse(yaml.toByteArray(), "provision.yaml", env = { env[it] })

    @Test
    fun `an environment placeholder resolves from the environment, with or without inner spaces`() {
        val f = parse(appFile, mapOf("THORYN_ENVIRONMENT" to "dev"))
        assertThat(f.resources.map { it.environment }).containsExactly("dev", "dev")
        // `spec` placeholders are still the engine's to resolve at plan / apply time.
        assertThat(f.resources[0].spec["displayName"]).isEqualTo("{{env.THORYN_APP_NAME}}")
    }

    @Test
    fun `an unset or empty variable fails closed and names the variable`() {
        assertThatThrownBy { parse(appFile, emptyMap()) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("resources[0] environment '{{env.THORYN_ENVIRONMENT}}' references env var 'THORYN_ENVIRONMENT', which is not set")
            .hasMessageContaining("resources[1]")
        assertThatThrownBy { parse(appFile, mapOf("THORYN_ENVIRONMENT" to "  ")) }
            .hasMessageContaining("which is not set")
    }

    @Test
    fun `a value that is not an environment slug is refused`() {
        assertThatThrownBy { parse(appFile, mapOf("THORYN_ENVIRONMENT" to "Dev/../prod")) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("resolves to 'Dev/../prod', which is not an environment slug")
    }

    @Test
    fun `a file without a placeholder reads exactly as before`() {
        val plain = appFile.replace("\"{{env.THORYN_ENVIRONMENT}}\"", "dev").replace("\"{{ env.THORYN_ENVIRONMENT }}\"", "dev")
        assertThat(parse(plain, emptyMap()).resources.map { it.environment }).containsExactly("dev", "dev")
    }

    @Test
    fun `parse without an env leaves the field as written (a bundled recipe resolves its own params)`() {
        val f = ProvisionFile.parse(appFile.toByteArray(), "recipe/provision.yaml")
        assertThat(f.resources[0].environment).isEqualTo("{{env.THORYN_ENVIRONMENT}}")
    }

    @Test
    fun `load resolves the placeholder, and apply converges into the resolved sandbox`(@TempDir dir: File) {
        val file = File(dir, "provision.yaml").apply { writeText(appFile) }
        val env = mapOf("THORYN_ENVIRONMENT" to "dev", "THORYN_APP_NAME" to "billing-web")
        val f = ProvisionFile.load(file) { env[it] }
        val engine = ProvisionEngine(
            clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
            out = PrintStream(console), err = PrintStream(console),
            env = { env[it] },
        )
        val receipt = engine.apply(f, null, engine.plan(f, null, false), "acme", null) {}
        assertThat(api.writes.map { it.method + " " + it.path + " @" + it.env }).containsExactly(
            "POST /api/v1/applications @dev",
            "POST /api/v1/users @dev",
        )
        assertThat(api.writes[0].body).containsEntry("displayName", "billing-web")
        assertThat(receipt.resources.map { it.environment }).containsExactly("dev", "dev")
    }
}
