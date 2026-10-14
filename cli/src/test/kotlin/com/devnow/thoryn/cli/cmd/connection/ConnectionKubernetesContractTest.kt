package com.devnow.thoryn.cli.cmd.connection

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3684 — the connection contract for a `kubernetes` trust: `auth.provider: kubernetes`, the identity
 * token from a FILE (`auth.tokenSource: {kind: file, path}`), optional `auth.kubernetes` pins; plus the drift
 * guard that the bundled schema still encodes what the loader enforces (provider enum, token-source kinds).
 */
class ConnectionKubernetesContractTest {

    private val json = JsonMapper.builder().build()
    private fun node(body: String): JsonNode = json.readTree(body)

    private val schema: JsonNode = json.readTree(
        javaClass.getResourceAsStream(Connection.SCHEMA_RESOURCE)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing resource ${Connection.SCHEMA_RESOURCE}"),
    )

    private val kubernetesConnection = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "thoryn" },
          "auth": {
            "method": "workload_identity",
            "provider": "kubernetes",
            "clientId": "wi_9a8b7c6d5e4f3a2b1c0d9e8f",
            "audience": "https://thoryn.auth.stg.thoryn.org",
            "tokenSource": { "kind": "file", "path": "/var/run/secrets/tokens/thoryn/token" },
            "scopes": ["tenant:applications.write"],
            "kubernetes": { "issuer": "https://kubernetes.default.svc.cluster.local", "namespace": "forge", "serviceAccount": "forge-oauth2-proxy" }
          }
        }
    """.trimIndent()

    @Test
    fun `a kubernetes connection conforms and parses its provider, token file and pins — no secret env, no runner`() {
        assertThat(Connection.validate(node(kubernetesConnection))).isEmpty()
        val parsed = Connection.parse(kubernetesConnection.toByteArray())
        assertThat(parsed.isWorkloadIdentity).isTrue()
        assertThat(parsed.provider).isEqualTo("kubernetes")
        assertThat(parsed.effectiveProvider).isEqualTo("kubernetes")
        assertThat(parsed.tokenFile).isEqualTo("/var/run/secrets/tokens/thoryn/token")
        assertThat(parsed.secretEnvOrNull).isNull()
        assertThat(parsed.github).isNull()
        assertThat(parsed.kubernetes).isNotNull
        assertThat(parsed.kubernetes!!.issuer).isEqualTo("https://kubernetes.default.svc.cluster.local")
        assertThat(parsed.kubernetes!!.namespace).isEqualTo("forge")
        assertThat(parsed.kubernetes!!.serviceAccount).isEqualTo("forge-oauth2-proxy")
    }

    @Test
    fun `a GitHub connection without a token source keeps the runner as its source and github_actions as its provider`() {
        val github = kubernetesConnection
            .replace("\"provider\": \"kubernetes\",", "")
            .replace("\"tokenSource\": { \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" },", "")
            .replace(Regex(",\\s*\"kubernetes\": \\{[^}]*}"), "")
        assertThat(Connection.validate(node(github))).isEmpty()
        val parsed = Connection.parse(github.toByteArray())
        assertThat(parsed.provider).isNull()
        assertThat(parsed.effectiveProvider).isEqualTo(Connection.PROVIDER_GITHUB_ACTIONS)
        assertThat(parsed.tokenFile).isNull()
        assertThat(parsed.kubernetes).isNull()
    }

    @Test
    fun `an explicit github_actions token source is accepted and names no file`() {
        val explicit = kubernetesConnection
            .replace("\"provider\": \"kubernetes\"", "\"provider\": \"github_actions\"")
            .replace("{ \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }", "{ \"kind\": \"github_actions\" }")
            .replace(Regex(",\\s*\"kubernetes\": \\{[^}]*}"), "")
        assertThat(Connection.validate(node(explicit))).isEmpty()
        assertThat(Connection.parse(explicit.toByteArray()).tokenFile).isNull()

        val withPath = explicit.replace("{ \"kind\": \"github_actions\" }", "{ \"kind\": \"github_actions\", \"path\": \"/x\" }")
        assertThat(Connection.validate(node(withPath))).anyMatch { it.contains("auth.tokenSource.path applies to kind 'file' only") }
    }

    @Test
    fun `a kubernetes provider requires a file token source`() {
        val noSource = kubernetesConnection.replace("\"tokenSource\": { \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" },", "")
        assertThat(Connection.validate(node(noSource))).anyMatch { it.contains("auth.tokenSource of kind 'file' is required for provider 'kubernetes'") }

        val runnerSource = kubernetesConnection.replace("{ \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }", "{ \"kind\": \"github_actions\" }")
        assertThat(Connection.validate(node(runnerSource))).anyMatch { it.contains("auth.tokenSource of kind 'file' is required for provider 'kubernetes'") }
    }

    @Test
    fun `a file token source needs a non-empty path, a known kind, and no unknown member`() {
        val noPath = kubernetesConnection.replace("{ \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }", "{ \"kind\": \"file\" }")
        assertThat(Connection.validate(node(noPath))).anyMatch { it.contains("auth.tokenSource.path is required for kind 'file'") }

        val blankPath = kubernetesConnection.replace("\"path\": \"/var/run/secrets/tokens/thoryn/token\"", "\"path\": \"  \"")
        assertThat(Connection.validate(node(blankPath))).anyMatch { it.contains("auth.tokenSource.path is required for kind 'file'") }

        val badKind = kubernetesConnection.replace("\"kind\": \"file\"", "\"kind\": \"vault\"")
        assertThat(Connection.validate(node(badKind))).anyMatch { it.contains("auth.tokenSource.kind must be one of github_actions | file") }

        val noKind = kubernetesConnection.replace("\"kind\": \"file\", ", "")
        assertThat(Connection.validate(node(noKind))).anyMatch { it.contains("auth.tokenSource.kind is required") }

        val rogue = kubernetesConnection.replace("\"kind\": \"file\", ", "\"kind\": \"file\", \"token\": \"eyJ\", ")
        assertThat(Connection.validate(node(rogue))).anyMatch { it.contains("auth.tokenSource has unknown property 'token'") }

        val notObject = kubernetesConnection.replace("{ \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }", "\"/var/run/secrets/tokens/thoryn/token\"")
        assertThat(Connection.validate(node(notObject))).anyMatch { it.contains("auth.tokenSource must be an object") }
    }

    @Test
    fun `each provider owns its pin block — github on kubernetes and kubernetes on github_actions are refused`() {
        val githubOnKubernetes = kubernetesConnection.replace("\"kubernetes\": {", "\"github\": { \"owner\": \"acme\" }, \"kubernetes\": {")
        assertThat(Connection.validate(node(githubOnKubernetes))).anyMatch { it.contains("auth.github applies to provider 'github_actions' only") }

        val kubernetesOnGithub = kubernetesConnection
            .replace("\"provider\": \"kubernetes\"", "\"provider\": \"github_actions\"")
            .replace("{ \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }", "{ \"kind\": \"github_actions\" }")
        assertThat(Connection.validate(node(kubernetesOnGithub))).anyMatch { it.contains("auth.kubernetes applies to provider 'kubernetes' only") }
    }

    @Test
    fun `malformed kubernetes pins are rejected with the field named`() {
        val bad = kubernetesConnection
            .replace("https://kubernetes.default.svc.cluster.local", "http://kubernetes.default.svc.cluster.local")
            .replace("\"namespace\": \"forge\"", "\"namespace\": \"\"")
            .replace("\"serviceAccount\": \"forge-oauth2-proxy\"", "\"serviceAccount\": \"sa\", \"jwks\": {}")
        val violations = Connection.validate(node(bad))
        assertThat(violations).anyMatch { it.contains("auth.kubernetes.issuer 'http://kubernetes.default.svc.cluster.local' must be an absolute https URL") }
        assertThat(violations).anyMatch { it.contains("auth.kubernetes.namespace must be a non-empty string") }
        assertThat(violations).anyMatch { it.contains("auth.kubernetes has unknown property 'jwks'") }
    }

    @Test
    fun `the workload-only members tokenSource and kubernetes are refused on a client_credentials connection`() {
        val bad = node(
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "client_credentials",
                "clientId": "ci",
                "secretEnv": "S",
                "scopes": ["tenant:applications.read"],
                "tokenSource": { "kind": "file", "path": "/t" },
                "kubernetes": { "namespace": "forge" }
              }
            }
            """.trimIndent(),
        )
        val violations = Connection.validate(bad)
        assertThat(violations).anyMatch { it.contains("auth.tokenSource applies to the 'workload_identity' method only") }
        assertThat(violations).anyMatch { it.contains("auth.kubernetes applies to the 'workload_identity' method only") }
    }

    @Test
    fun `load refuses a file that names an unknown provider`() {
        assertThatThrownBy { Connection.parse(kubernetesConnection.replace("\"kubernetes\"", "\"openshift\"").toByteArray()) }
            .isInstanceOf(ConnectionException::class.java)
            .hasMessageContaining("auth.provider must be one of github_actions | kubernetes")
    }

    // --- Drift guard: the bundled schema encodes the same providers and token-source kinds. ---

    @Test
    fun `the bundled schema pins the providers and token-source kinds the loader accepts`() {
        val auth = schema["properties"]["auth"]["properties"]
        assertThat(auth["provider"]["enum"].toList().map { it.asString() }).isEqualTo(Connection.PROVIDERS)
        assertThat(auth["provider"]["default"].asString()).isEqualTo(Connection.PROVIDER_GITHUB_ACTIONS)
        assertThat(auth["tokenSource"]["additionalProperties"].asBoolean()).isFalse()
        assertThat(auth["tokenSource"]["properties"]["kind"]["enum"].toList().map { it.asString() }).isEqualTo(Connection.TOKEN_SOURCE_KINDS)
        assertThat(auth["tokenSource"]["required"].toList().map { it.asString() }).containsExactly("kind")
        assertThat(auth["kubernetes"]["additionalProperties"].asBoolean()).isFalse()
        assertThat(auth["kubernetes"]["properties"].propertyNames().toList()).containsExactlyInAnyOrder("issuer", "namespace", "serviceAccount")
    }
}
