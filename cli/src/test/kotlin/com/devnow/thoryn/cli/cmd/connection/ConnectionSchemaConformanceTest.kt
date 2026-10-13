package com.devnow.thoryn.cli.cmd.connection

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-2948 (epic SSO-2947) — dogfood `connection.schema.json` against real connection documents, and
 * guard against the bundled schema drifting from the [Connection] loader that validates against it.
 *
 * Like [com.devnow.thoryn.cli.cmd.examples.RecipeSchemaConformanceTest], a full JSON-Schema engine is
 * deliberately NOT pulled in — the loader does the same hand-rolled, message-bearing validation. This
 * test asserts (a) a representative valid connection passes, (b) each class of invalid document is
 * rejected with a clear message, and (c) the schema resource itself still encodes the load-bearing
 * constraints the loader enforces (the drift guard: the schema is the documented contract, the loader
 * is the runtime; they must agree).
 */
class ConnectionSchemaConformanceTest {

    private val json = JsonMapper.builder().build()

    private val schema: JsonNode = json.readTree(readResource(Connection.SCHEMA_RESOURCE))

    private fun readResource(path: String): String =
        javaClass.getResourceAsStream(path)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing test resource $path")

    private fun node(body: String): JsonNode = json.readTree(body)

    private val validConnection = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "thoryn", "hubBaseUrlEnv": "THORYN_HUB" },
          "auth": {
            "method": "client_credentials",
            "clientId": "thoryn-cli-ci-abc123",
            "secretEnv": "THORYN_CLI_CI_CLIENT_SECRET",
            "scopes": ["tenant:applications.write", "tenant:applications.read"]
          }
        }
    """.trimIndent()

    @Test
    fun `a representative valid connection conforms`() {
        assertThat(Connection.validate(node(validConnection))).isEmpty()
    }

    @Test
    fun `a valid connection omitting hubBaseUrlEnv defaults it to THORYN_HUB`() {
        val parsed = Connection.parse(
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "client_credentials",
                "clientId": "cid",
                "secretEnv": "SECRET_VAR",
                "scopes": ["tenant:applications.read"]
              }
            }
            """.trimIndent().toByteArray(),
        )
        assertThat(parsed.hubBaseUrlEnv).isEqualTo("THORYN_HUB")
        assertThat(parsed.slug).isEqualTo("thoryn")
        assertThat(parsed.scopes).containsExactly("tenant:applications.read")
    }

    @Test
    fun `a connection missing workspace slug is rejected`() {
        val bad = node(
            """
            { "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "hubBaseUrlEnv": "THORYN_HUB" },
              "auth": { "method": "client_credentials", "clientId": "c", "secretEnv": "S", "scopes": ["tenant:a.b"] } }
            """.trimIndent(),
        )
        assertThat(Connection.validate(bad)).anyMatch { it.contains("workspace.slug is required") }
    }

    @Test
    fun `a connection with a bad apiVersion is rejected`() {
        val bad = node(validConnection.replace("thoryn.io/connection/v1", "thoryn.io/connection/v2"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("apiVersion must be") }
    }

    @Test
    fun `a connection with empty scopes is rejected`() {
        val bad = node(validConnection.replace("""["tenant:applications.write", "tenant:applications.read"]""", "[]"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth.scopes must be non-empty") }
    }

    @Test
    fun `a connection with a non-tenant scope is rejected`() {
        val bad = node(validConnection.replace("tenant:applications.read", "admin:everything.write"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("admin:everything.write") && it.contains("must match") }
    }

    @Test
    fun `a connection with an unknown top-level property is rejected (additionalProperties false)`() {
        val bad = node(validConnection.replace("\"auth\":", "\"rogue\": true, \"auth\":"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("unknown property 'rogue'") }
    }

    @Test
    fun `a connection with an unknown auth property is rejected`() {
        val bad = node(validConnection.replace("\"method\":", "\"secret\": \"leaked\", \"method\":"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth has unknown property 'secret'") }
    }

    @Test
    fun `a connection with an unknown method is rejected`() {
        val bad = node(validConnection.replace("client_credentials", "authorization_code"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth.method must be one of client_credentials | workload_identity") }
    }

    // --- SSO-3308: the workload_identity method ---

    private val workloadConnection = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "thoryn" },
          "auth": {
            "method": "workload_identity",
            "provider": "github_actions",
            "clientId": "wi_3f0c9a1b2d4e5f6a7b8c9d0e",
            "audience": "https://thoryn.auth.stg.thoryn.org/cli-wif",
            "scopes": ["tenant:environments.read"],
            "github": { "owner": "thoryn-io", "repository": "thoryn-cli", "repositoryId": 1044556677, "environment": "thoryn-staging-wif" }
          }
        }
    """.trimIndent()

    @Test
    fun `a workload_identity connection conforms and parses its binding and pins — no secret env`() {
        assertThat(Connection.validate(node(workloadConnection))).isEmpty()
        val parsed = Connection.parse(workloadConnection.toByteArray())
        assertThat(parsed.isWorkloadIdentity).isTrue()
        assertThat(parsed.secretEnvOrNull).isNull()
        assertThat(parsed.audience).isEqualTo("https://thoryn.auth.stg.thoryn.org/cli-wif")
        assertThat(parsed.github!!.repositoryId).isEqualTo(1044556677L)
        assertThat(parsed.github!!.environment).isEqualTo("thoryn-staging-wif")
    }

    @Test
    fun `a workload_identity connection may derive its audience from an environment instead`() {
        val derived = workloadConnection.replace(
            "\"audience\": \"https://thoryn.auth.stg.thoryn.org/cli-wif\"", "\"environment\": \"cli-wif\"",
        )
        assertThat(Connection.validate(node(derived))).isEmpty()
        assertThat(Connection.parse(derived.toByteArray()).environment).isEqualTo("cli-wif")
    }

    @Test
    fun `a workload_identity connection must not name a secret env var`() {
        val bad = node(workloadConnection.replace("\"clientId\":", "\"secretEnv\": \"SOME_SECRET\", \"clientId\":"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth.secretEnv must not be set for 'workload_identity'") }
    }

    @Test
    fun `workload-only members are refused on a client_credentials connection`() {
        val bad = node(validConnection.replace("\"method\":", "\"audience\": \"https://a.example\", \"method\":"))
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth.audience applies to the 'workload_identity' method only") }
    }

    @Test
    fun `malformed workload members are rejected with the field named`() {
        val bad = node(
            workloadConnection
                .replace("\"github_actions\"", "\"gitlab\"")
                .replace("https://thoryn.auth.stg.thoryn.org/cli-wif", "not a url")
                .replace("1044556677", "-4")
                .replace("\"environment\": \"thoryn-staging-wif\"", "\"environment\": \"x\", \"rogue\": 1"),
        )
        val violations = Connection.validate(bad)
        assertThat(violations).anyMatch { it.contains("auth.provider must be 'github_actions'") }
        assertThat(violations).anyMatch { it.contains("auth.audience 'not a url' must be an absolute http(s) URL") }
        assertThat(violations).anyMatch { it.contains("auth.github.repositoryId must be a positive integer") }
        assertThat(violations).anyMatch { it.contains("auth.github has unknown property 'rogue'") }
    }

    @Test
    fun `a connection missing the auth object is rejected`() {
        val bad = node(
            """{ "apiVersion": "thoryn.io/connection/v1", "workspace": { "slug": "thoryn" } }""",
        )
        assertThat(Connection.validate(bad)).anyMatch { it.contains("auth object is required") }
    }

    // --- Drift guard: the bundled schema still encodes the loader's load-bearing constraints. ---

    @Test
    fun `the bundled schema pins the apiVersion const the loader enforces`() {
        assertThat(schema["properties"]["apiVersion"]["const"].asString()).isEqualTo(Connection.API_VERSION)
    }

    @Test
    fun `the bundled schema forbids additionalProperties at every level`() {
        assertThat(schema["additionalProperties"].asBoolean()).isFalse()
        assertThat(schema["properties"]["workspace"]["additionalProperties"].asBoolean()).isFalse()
        assertThat(schema["properties"]["auth"]["additionalProperties"].asBoolean()).isFalse()
    }

    @Test
    fun `the bundled schema pins the same slug and scope grammars the loader uses`() {
        assertThat(schema["properties"]["workspace"]["properties"]["slug"]["pattern"].asString())
            .isEqualTo(Connection.SLUG_PATTERN.pattern)
        assertThat(schema["properties"]["auth"]["properties"]["scopes"]["items"]["pattern"].asString())
            .isEqualTo(Connection.SCOPE_PATTERN.pattern)
    }

    @Test
    fun `the bundled schema pins the auth methods and the hubBaseUrlEnv default the loader uses`() {
        assertThat(schema["properties"]["auth"]["properties"]["method"]["enum"].toList().map { it.asString() })
            .isEqualTo(Connection.AUTH_METHODS)
        assertThat(schema["properties"]["workspace"]["properties"]["hubBaseUrlEnv"]["default"].asString())
            .isEqualTo(Connection.DEFAULT_HUB_BASE_URL_ENV)
    }
}
