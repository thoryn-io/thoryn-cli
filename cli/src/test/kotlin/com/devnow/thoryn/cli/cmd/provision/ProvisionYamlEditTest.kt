package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3669 — the one provisioning-file text edit the CLI has (lifted from `import --write`, SSO-3659): append under a
 * trailing `resources:` list keeping every other line, and [ProvisionYamlEdit.converge] on top of it — add when absent,
 * leave alone when structurally identical, replace (re-rendered, comments lost) when different.
 */
class ProvisionYamlEditTest {

    private val json = JsonMapper.builder().build()

    private fun entry(url: String = "https://web.acme.example"): JsonNode = json.valueToTree(
        linkedMapOf(
            "kind" to "application", "name" to "web",
            "spec" to linkedMapOf("displayName" to "acme/web", "clientType" to "public", "redirectUris" to listOf("$url/callback")),
        ),
    )

    private val isWeb: (JsonNode) -> Boolean = { it["kind"]?.asString() == "application" && it["name"]?.asString() == "web" }

    private val file = """
        |# The production section — keep this comment.
        |apiVersion: thoryn.io/provision/v1
        |resources:
        |  # The sandbox, adopted by slug.
        |  - kind: environment
        |    name: dev
        |    spec:
        |      slug: dev
        |
    """.trimMargin()

    @Test
    fun `no file yet becomes a fresh file with the header and the entry`() {
        val c = ProvisionYamlEdit.converge(null, entry(), "cfg", "  # hello\n", isWeb)

        assertThat(c.outcome).isEqualTo(ProvisionYamlEdit.Outcome.ADDED)
        assertThat(c.content).startsWith("apiVersion: thoryn.io/provision/v1\nresources:\n  # hello\n  - kind: application\n    name: web\n")
        assertThat(ProvisionFile.parse(c.content.toByteArray(), "cfg").resources.single().spec).containsEntry("clientType", "public")
    }

    @Test
    fun `an absent entry is appended and every existing line, comments included, is kept byte for byte`() {
        val c = ProvisionYamlEdit.converge(file, entry(), "cfg", "\n  # web's production client\n", isWeb)

        assertThat(c.outcome).isEqualTo(ProvisionYamlEdit.Outcome.ADDED)
        assertThat(c.content).startsWith(file).contains("\n  # web's production client\n  - kind: application\n    name: web\n")
        assertThat(ProvisionFile.parse(c.content.toByteArray(), "cfg").resources.map { it.key }).containsExactly("environment/dev", "application/web")
    }

    @Test
    fun `a file without a resources key gets one`() {
        val c = ProvisionYamlEdit.converge("apiVersion: thoryn.io/provision/v1\n", entry(), "cfg", "", isWeb)

        assertThat(c.outcome).isEqualTo(ProvisionYamlEdit.Outcome.ADDED)
        // YamlWriter's style: a sequence under a key at the key's indent, URLs quoted (they carry a ':').
        assertThat(c.content).isEqualTo("apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: web\n    spec:\n      displayName: acme/web\n      clientType: public\n      redirectUris:\n      - \"https://web.acme.example/callback\"\n")
    }

    @Test
    fun `an identical entry, however it is written, is unchanged and the text is returned as it was`() {
        val existing = file + "  - name: web\n    kind: \"application\"\n    spec: { clientType: public, displayName: 'acme/web', redirectUris: [\"https://web.acme.example/callback\"] }\n"

        val c = ProvisionYamlEdit.converge(existing, entry(), "cfg", "  # ignored\n", isWeb)

        assertThat(c.outcome).isEqualTo(ProvisionYamlEdit.Outcome.UNCHANGED)
        assertThat(c.content).isSameAs(existing)
    }

    @Test
    fun `a different entry is replaced in place and the other resources survive the re-render`() {
        val existing = file + "  - kind: application\n    name: web\n    spec:\n      displayName: acme/web\n      clientType: public\n      redirectUris: [https://old.acme.example/callback]\n"

        val c = ProvisionYamlEdit.converge(existing, entry("https://new.acme.example"), "cfg", "", isWeb)

        assertThat(c.outcome).isEqualTo(ProvisionYamlEdit.Outcome.UPDATED)
        assertThat(c.content).doesNotContain("old.acme.example").doesNotContain("# The production section") // re-rendered: comments are lost
        val parsed = ProvisionFile.parse(c.content.toByteArray(), "cfg")
        assertThat(parsed.resources.map { it.key }).containsExactly("environment/dev", "application/web")
        assertThat(parsed.resources[1].spec["redirectUris"]).isEqualTo(listOf("https://new.acme.example/callback"))
    }

    @Test
    fun `resources that is not the last top-level key cannot be appended to`() {
        val odd = "resources:\n  - { kind: environment, name: ci, spec: { slug: ci-sbx } }\napiVersion: thoryn.io/provision/v1\n"

        assertThatThrownBy { ProvisionYamlEdit.converge(odd, entry(), "cfg", "", isWeb) }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("not the last top-level key")
        assertThatThrownBy { ProvisionYamlEdit.converge("- just\n- a list\n", entry(), "cfg", "", isWeb) }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("not a YAML mapping")
    }
}
