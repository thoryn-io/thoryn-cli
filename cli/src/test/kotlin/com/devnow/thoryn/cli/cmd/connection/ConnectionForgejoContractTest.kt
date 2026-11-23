package com.devnow.thoryn.cli.cmd.connection

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-4472 — the `forgejo` provider of the connection contract: `auth.provider: forgejo`, the `auth.forgejo` pin block,
 * the `auth.plan` mirror (forgejo only), the runner as the default token source and `kind: file` behind an
 * authenticating proxy — in the loader AND in the bundled schema (the drift guard), on a neutral instance.
 */
class ConnectionForgejoContractTest {

    private val json = JsonMapper.builder().build()
    private val schema: JsonNode = json.readTree(javaClass.getResourceAsStream(Connection.SCHEMA_RESOURCE)!!.readBytes())

    private fun connection(extra: String = "", provider: String = "forgejo") = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "acme" },
          "auth": {
            "method": "workload_identity",
            "provider": "$provider",
            "clientId": "wi_5e4f3a2b1c0d9e8f7a6b5c4d",
            "audience": "https://acme.auth.example.org",
            "scopes": ["tenant:applications.read", "tenant:applications.write"]$extra
          }
        }
    """.trimIndent()

    private val pins = """,
            "forgejo": { "instanceUrl": "https://codeberg.org", "owner": "acme", "repository": "infra", "ownerId": 7, "repositoryId": 42, "ref": "refs/heads/main" }"""

    private fun violations(doc: String) = Connection.validate(json.readTree(doc))

    @Test
    fun `a forgejo connection parses with its pins and plan mirror, and the runner as the default token source`() {
        val c = Connection.parse(connection(pins + """, "plan": { "scopes": ["tenant:applications.read"] }""").toByteArray())

        assertThat(c.isWorkloadIdentity).isTrue()
        assertThat(c.effectiveProvider).isEqualTo(Connection.PROVIDER_FORGEJO)
        assertThat(c.tokenFile).isNull()
        assertThat(c.forgejo!!.instanceUrl).isEqualTo("https://codeberg.org")
        assertThat(c.forgejo!!.ownerId).isEqualTo(7)
        assertThat(c.forgejo!!.repositoryId).isEqualTo(42)
        assertThat(c.forgejo!!.ref).isEqualTo("refs/heads/main")
        assertThat(c.planScopes).containsExactly("tenant:applications.read")
        assertThat(c.github).isNull()
        // No plan mirror ⇒ null, not empty: the CLI then expects a push to be refused.
        assertThat(Connection.parse(connection(pins).toByteArray()).planScopes).isNull()
    }

    @Test
    fun `behind an authenticating proxy the token comes from a file`() {
        val c = Connection.parse(connection(pins + """, "tokenSource": { "kind": "file", "path": "/runner/tmp/thoryn-token" }""").toByteArray())
        assertThat(c.tokenFile).isEqualTo("/runner/tmp/thoryn-token")
    }

    @Test
    fun `each provider's block belongs to it alone, and the GitHub runner kind does not apply to forgejo`() {
        assertThat(violations(connection(pins + """, "tokenSource": { "kind": "github_actions" }""")))
            .anyMatch { it.contains("auth.tokenSource kind 'github_actions' does not apply to provider 'forgejo'") }
        assertThat(violations(connection(pins + """, "github": { "owner": "acme" }""")))
            .anyMatch { it.contains("auth.github applies to provider 'github_actions' only") }
        assertThat(violations(connection(pins, provider = "github_actions")))
            .anyMatch { it.contains("auth.forgejo applies to provider 'forgejo' only") }
        assertThat(violations(connection(""", "plan": { "scopes": ["tenant:applications.read"] }""", provider = "github_actions")))
            .anyMatch { it.contains("auth has unknown property 'plan'") }
        assertThat(violations(connection(pins + """, "kubernetes": { "namespace": "x" }""")))
            .anyMatch { it.contains("auth.kubernetes applies to provider 'kubernetes' only") }
    }

    @Test
    fun `malformed forgejo pins and plan scopes are refused with the field named`() {
        val bad = violations(
            connection(
                """,
            "forgejo": { "instanceUrl": "https://codeberg.org/acme", "owner": "", "ownerId": 0, "repositoryId": "42", "rogue": 1 },
            "plan": { "scopes": ["tenant:applications.write"], "environment": "x" }""",
            ),
        )
        assertThat(bad).anyMatch { it.contains("auth.forgejo.instanceUrl 'https://codeberg.org/acme' must be the instance's https origin") }
        assertThat(bad).anyMatch { it.contains("auth.forgejo.owner must be a non-empty string") }
        assertThat(bad).anyMatch { it.contains("auth.forgejo.ownerId must be a positive integer") }
        assertThat(bad).anyMatch { it.contains("auth.forgejo.repositoryId must be a positive integer") }
        assertThat(bad).anyMatch { it.contains("auth.forgejo has unknown property 'rogue'") }
        assertThat(bad).anyMatch { it.contains("auth.plan.scopes entry 'tenant:applications.write' must be a tenant:<area>.read scope") }
        assertThat(bad).anyMatch { it.contains("auth.plan has unknown property 'environment'") }
        assertThatThrownBy { Connection.parse(connection(""", "forgejo": { "instanceUrl": "http://codeberg.org" }""").toByteArray()) }
            .isInstanceOf(ConnectionException::class.java).hasMessageContaining("https origin")
    }

    // --- Drift guard: the bundled schema encodes the same provider, blocks and rules. ---

    @Test
    fun `the schema's provider enum is the loader's, and it defines the forgejo and plan blocks`() {
        val auth = schema["properties"]["auth"]
        assertThat(auth["properties"]["provider"]["enum"].toList().map { it.asString() }).containsExactlyElementsOf(Connection.PROVIDERS)
        val forgejo = auth["properties"]["forgejo"]
        assertThat(forgejo["additionalProperties"].asBoolean()).isFalse()
        assertThat(forgejo["properties"].propertyNames().toList()).containsExactlyInAnyOrder("instanceUrl", "owner", "repository", "ownerId", "repositoryId", "ref")
        assertThat(forgejo["properties"]["instanceUrl"]["pattern"].asString()).isEqualTo("^https://[^\\s/?#@]+$")
        val plan = auth["properties"]["plan"]
        assertThat(plan["additionalProperties"].asBoolean()).isFalse()
        assertThat(plan["properties"]["scopes"]["items"]["pattern"].asString()).isEqualTo("^tenant:[a-z-]+\\.read$")
        // The forgejo rule: no github / kubernetes block, a file token source if any; and no forgejo / plan block elsewhere.
        val rules = auth["allOf"].toList()
        val forgejoRule = rules.single { it["if"]?.get("properties")?.get("provider")?.get("const")?.asString() == "forgejo" }
        assertThat(forgejoRule["then"]["properties"]["tokenSource"]["properties"]["kind"]["const"].asString()).isEqualTo("file")
        assertThat(forgejoRule["then"]["not"]["anyOf"].toList().map { it["required"][0].asString() }).containsExactlyInAnyOrder("github", "kubernetes")
        val notForgejo = rules.single { it["if"]?.get("not")?.get("properties")?.get("provider")?.get("const")?.asString() == "forgejo" }
        assertThat(notForgejo["then"]["not"]["anyOf"].toList().map { it["required"][0].asString() }).containsExactlyInAnyOrder("forgejo", "plan")
    }
}
