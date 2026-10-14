package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3689 (ADR 2026-10-14 credential ladder; ADR 2026-10-14 federated client authentication §11) — the shapes
 * `provision.schema.json` and the [ProvisionFile] loader accept and refuse for a SECRET-LESS client and for the new
 * `workloadIdentityTrust` kind, with the hub's own codes in the refusals. Same drift-guard shape as
 * [ProvisionSchemaConformanceTest]: the schema is the documented contract, the loader the runtime, and the closed
 * enums are read FROM the schema so the two cannot disagree silently.
 */
class ProvisionSecretlessSchemaTest {

    private val yaml = YAMLMapper()
    private val json = JsonMapper.builder().build()

    private val schema: JsonNode = json.readTree(
        javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing resource ${ProvisionFile.SCHEMA_RESOURCE}"),
    )

    private fun applicationRule(): JsonNode =
        schema["\$defs"]["resource"]["allOf"].toList().first { it["if"]["properties"]?.get("kind")?.get("const")?.asString() == "application" && it["if"]["properties"].size() == 1 }

    private fun trustRule(): JsonNode =
        schema["\$defs"]["resource"]["allOf"].toList().first { it["if"]["properties"]?.get("kind")?.get("const")?.asString() == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }

    private val publicJwks = """{ keys: [ { kty: RSA, kid: k1, use: sig, alg: RS256, n: "0vx7agoebGcQSuu…", e: AQAB } ] }"""

    @Test
    fun `every rung of the ladder parses — private_key_jwt by uri or inline key, federated_assertion with its trust, a secret-bearing client with a sink`() {
        val ok = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: billing-ci
                environment: staging
                spec:
                  provider: github_actions
                  github: { repository: acme/billing, ownerId: 1234567, repositoryId: 7654321, environment: staging, ref: refs/heads/main }
                  scopes: [tenant:applications.read, tenant:applications.write]
              - kind: workloadIdentityTrust
                name: forge-main
                spec:
                  provider: forgejo
                  forgejo: { instanceUrl: "https://forge.example.org", owner: thoryn, ownerId: 7, repository: infra, repositoryId: 42, ref: refs/heads/main }
                  scopes: [tenant:applications.write]
                  confirmProduction: true
              - kind: workloadIdentityTrust
                name: billing-pods
                spec:
                  provider: kubernetes
                  kubernetes: { issuer: "https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE", namespace: billing, serviceAccount: billing-web, jwks: $publicJwks }
                  scopes: [tenant:applications.read]
                  confirmProduction: true
              - kind: application
                name: billing-web
                spec:
                  displayName: "Billing web"
                  redirectUris: ["https://billing.acme.example/cb"]
                  grantTypes: [authorization_code, refresh_token]
                  clientAuthenticationMethods: [federated_assertion]
                  federatedTrust: billing-pods
              - kind: application
                name: by-uri
                spec: { displayName: "Key by URI", clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://app.acme.example/.well-known/jwks.json", grantTypes: [client_credentials] }
              - kind: application
                name: by-jwks
                spec: { displayName: "Key inline", clientAuthenticationMethods: [private_key_jwt], jwks: $publicJwks }
              - kind: application
                name: worker
                spec: { displayName: "Worker", clientAuthenticationMethods: [client_secret_basic], grantTypes: [client_credentials] }
                secretSink: { kind: file, path: .secrets/worker.secret }
              - kind: application
                name: spa
                spec: { displayName: "SPA", clientType: public, clientAuthenticationMethods: [none] }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(ok)).isEmpty()
        val parsed = ProvisionFile.parse(json.writeValueAsBytes(ok), "provision.json", yaml = false)
        assertThat(parsed.resources.map { it.key }).containsExactly(
            "workloadIdentityTrust/billing-ci", "workloadIdentityTrust/forge-main", "workloadIdentityTrust/billing-pods",
            "application/billing-web", "application/by-uri", "application/by-jwks", "application/worker", "application/spa",
        )
        assertThat(parsed.resources[3].spec[ProvisionFile.SPEC_FEDERATED_TRUST]).isEqualTo("billing-pods")
        assertThat((parsed.resources[2].spec["kubernetes"] as Map<*, *>)["jwks"]).isInstanceOf(Map::class.java)
        assertThat(parsed.resources[0].environment).isEqualTo("staging")
    }

    @Test
    fun `a client's authentication is refused with the hub's codes — client_secret_post, a key for federated_assertion, a public federated client, the wrong grants, a missing trust, a sink without a secret`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: a, spec: { displayName: a, clientAuthenticationMethods: [client_secret_post] } }
              - { kind: application, name: b, spec: { displayName: b, clientAuthenticationMethods: [private_key_jwt] } }
              - { kind: application, name: c, spec: { displayName: c, clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://a/jwks", jwks: $publicJwks } }
              - { kind: application, name: d, spec: { displayName: d, clientAuthenticationMethods: [federated_assertion, client_secret_basic], federatedTrust: t } }
              - { kind: application, name: e, spec: { displayName: e, clientType: public, clientAuthenticationMethods: [federated_assertion], federatedTrust: t } }
              - { kind: application, name: f, spec: { displayName: f, clientAuthenticationMethods: [federated_assertion], federatedTrust: t, grantTypes: [authorization_code, client_credentials] } }
              - { kind: application, name: g, spec: { displayName: g, clientAuthenticationMethods: [federated_assertion], federatedTrust: t, requireProofKey: false } }
              - { kind: application, name: h, spec: { displayName: h, clientAuthenticationMethods: [federated_assertion], federatedTrust: t, jwksUri: "https://a/jwks" } }
              - { kind: application, name: i, spec: { displayName: i, clientAuthenticationMethods: [federated_assertion] } }
              - { kind: application, name: j, spec: { displayName: j, federatedTrust: t } }
              - { kind: application, name: k, spec: { displayName: k, clientAuthenticationMethods: [federated_assertion], federatedTrust: t }, secretSink: { kind: file, path: k.secret } }
              - { kind: application, name: l, spec: { displayName: l, clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://a/jwks" }, secretSink: { kind: file, path: l.secret } }
              - { kind: application, name: m, spec: { displayName: m, clientAuthenticationMethods: [none, client_secret_basic] } }
              - { kind: application, name: n, spec: { displayName: n, clientAuthenticationMethods: [private_key_jwt], jwks: { keys: [ { kty: RSA, kid: k1, n: x, e: AQAB, d: "PRIVATE", p: p, q: q } ] } } }
              - { kind: application, name: o, spec: { displayName: o, clientAuthenticationMethods: [private_key_jwt], jwks: { keys: [ { kty: EC, kid: k2, crv: P-256, x: x } ] } } }
              - { kind: application, name: p, spec: { displayName: p, clientAuthenticationMethods: [private_key_jwt], jwksUri: "http://plain.example/jwks" } }
              - { kind: application, name: q, spec: { displayName: q, clientAuthenticationMethods: [mtls] } }
              - { kind: application, name: r, spec: { displayName: r, clientAuthenticationMethods: [federated_assertion], federatedTrust: "Not A Name" } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0]") && it.contains(ProvisionFile.ERR_INVALID_CLIENT_AUTHENTICATION_METHOD) && it.contains("client_secret_post") && it.contains("courier rung") }
        assertThat(v).anyMatch { it.contains("resources[1]") && it.contains(ProvisionFile.ERR_PRIVATE_KEY_JWT_KEY_REQUIRED) }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains(ProvisionFile.ERR_JWKS_XOR_JWKS_URI) }
        assertThat(v).anyMatch { it.contains("resources[3]") && it.contains(ProvisionFile.ERR_FEDERATED_ONLY_METHOD) && it.contains("exactly ['federated_assertion']") }
        assertThat(v).anyMatch { it.contains("resources[4]") && it.contains(ProvisionFile.ERR_FEDERATED_ONLY_METHOD) && it.contains("clientType: public") }
        assertThat(v).anyMatch { it.contains("resources[5]") && it.contains(ProvisionFile.ERR_FEDERATED_GRANT_NOT_ALLOWED) && it.contains("client_credentials") }
        assertThat(v).anyMatch { it.contains("resources[6]") && it.contains(ProvisionFile.ERR_FEDERATED_PKCE_REQUIRED) }
        assertThat(v).anyMatch { it.contains("resources[7]") && it.contains(ProvisionFile.ERR_FEDERATED_NO_SECRET_OR_KEY) }
        assertThat(v).anyMatch { it.contains("resources[8]") && it.contains(ProvisionFile.ERR_FEDERATED_TRUST_REQUIRED) }
        assertThat(v).anyMatch { it.contains("resources[9]") && it.contains(ProvisionFile.ERR_FEDERATED_TRUST_WITHOUT_METHOD) }
        assertThat(v).anyMatch { it.contains("resources[10]") && it.contains(ProvisionFile.ERR_SECRET_SINK_WITHOUT_SECRET) && it.contains("federated_assertion") }
        assertThat(v).anyMatch { it.contains("resources[11]") && it.contains(ProvisionFile.ERR_SECRET_SINK_WITHOUT_SECRET) && it.contains("private_key_jwt") }
        assertThat(v).anyMatch { it.contains("resources[12]") && it.contains(ProvisionFile.ERR_INCOHERENT_CLIENT_AUTHENTICATION_METHODS) }
        assertThat(v).anyMatch { it.contains("resources[13] spec.jwks.keys[0]") && it.contains(ProvisionFile.ERR_INVALID_JWKS) && it.contains("PRIVATE key material (d, p, q)") }
        assertThat(v).anyMatch { it.contains("resources[14] spec.jwks.keys[0]") && it.contains("EC public key needs crv, x and y") }
        assertThat(v).anyMatch { it.contains("resources[15] spec.jwksUri must be an https:// URL") }
        assertThat(v).anyMatch { it.contains("resources[16]") && it.contains(ProvisionFile.ERR_INVALID_CLIENT_AUTHENTICATION_METHOD) && it.contains("'mtls'") }
        assertThat(v).anyMatch { it.contains("resources[17] spec.federatedTrust must be the NAME of a workloadIdentityTrust") }
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining(ProvisionFile.ERR_FEDERATED_TRUST_REQUIRED)

        // The schema pins the same closed method set, the https key URI, the XOR, the required key for private_key_jwt and the federated rules.
        val props = applicationRule()["then"]["properties"]["spec"]["properties"]
        assertThat(props["clientAuthenticationMethods"]["items"]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.CLIENT_AUTHENTICATION_METHODS)
        assertThat(ProvisionFile.CLIENT_AUTHENTICATION_METHODS).doesNotContain(ProvisionFile.METHOD_CLIENT_SECRET_POST)
        assertThat(props["jwksUri"]["pattern"].asString()).isEqualTo("^https://")
        assertThat(props["federatedTrust"]["pattern"].asString()).isEqualTo(ProvisionFile.NAME_PATTERN.pattern)
        val rules = schema["\$defs"]["resource"]["allOf"].toList()
        val federated = rules.first { it["if"]["properties"]?.get("spec")?.get("properties")?.get("clientAuthenticationMethods")?.get("contains")?.get("const")?.asString() == "federated_assertion" }
        assertThat(federated["then"]["properties"]["spec"]["required"].toList().map { it.asString() }).containsExactly("federatedTrust")
        assertThat(federated["then"]["properties"]["spec"]["properties"]["grantTypes"]["items"]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.FEDERATED_GRANT_TYPES)
        assertThat(federated["then"]["properties"]["spec"]["properties"]["clientAuthenticationMethods"]["maxItems"].asInt()).isEqualTo(1)
        assertThat(federated["then"]["not"]["required"].toList().map { it.asString() }).containsExactly("secretSink")
        assertThat(rules).anyMatch { it["if"]["properties"]?.get("spec")?.get("properties")?.get("clientAuthenticationMethods")?.get("contains")?.get("const")?.asString() == "private_key_jwt" && it["then"]["properties"]["spec"]["anyOf"].size() == 2 }
    }

    @Test
    fun `a workloadIdentityTrust is refused with the trust service's codes — the provider, its pins, the scope grammar and the production rules`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: workloadIdentityTrust, name: a, environment: s, spec: { provider: gitlab, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: b, environment: s, spec: { provider: github_actions, github: { repository: acme/x }, scopes: [admin:platform.read, openid] } }
              - { kind: workloadIdentityTrust, name: c, spec: { provider: github_actions, github: { repository: acme/x }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: d, spec: { provider: github_actions, github: { repository: acme/x, environment: production }, scopes: [tenant:x.read], confirmProduction: true }, grants: [ { subject: "client:x", relation: viewer } ] }
              - { kind: workloadIdentityTrust, name: e, environment: s, spec: { provider: github_actions, github: { repository: acme/x, ownerId: 1 }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: f, environment: s, spec: { provider: forgejo, forgejo: { instanceUrl: "https://forge.example/path", owner: o, repository: r }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: g, spec: { provider: forgejo, forgejo: { instanceUrl: "https://forge.example", owner: o, ownerId: 1, repository: r, repositoryId: 2 }, scopes: [tenant:x.read], confirmProduction: true } }
              - { kind: workloadIdentityTrust, name: h, spec: { provider: kubernetes, kubernetes: { issuer: "https://oidc.example", namespace: billing }, scopes: [tenant:x.read], confirmProduction: true } }
              - { kind: workloadIdentityTrust, name: i, environment: s, spec: { provider: kubernetes, kubernetes: { issuer: "https://oidc.example", jwks: { keys: [ { kty: RSA, kid: k, n: n, e: e, d: SECRET } ] } }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: j, environment: s, spec: { provider: kubernetes, github: { repository: acme/x }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: k, environment: s, spec: { provider: github_actions, github: { repository: acme/x, branch: main }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: l, environment: s, spec: { provider: github_actions, github: { repository: acme/x }, scopes: [tenant:x.read], audience: "https://x" } }
              - { kind: workloadIdentityTrust, environment: s, spec: { provider: github_actions, github: { repository: acme/x }, scopes: [tenant:x.read] } }
              - { kind: workloadIdentityTrust, name: m, environment: s, spec: { provider: github_actions, github: { repository: acme/x } } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] spec.provider") && it.contains(ProvisionFile.ERR_UNSUPPORTED_PROVIDER) && it.contains("gitlab") }
        assertThat(v).anyMatch { it.contains("resources[1] spec.scopes") && it.contains(ProvisionFile.ERR_INVALID_SCOPE) && it.contains("admin:platform.read") }
        assertThat(v).anyMatch { it.contains("resources[1] spec.scopes") && it.contains("'openid'") }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains(ProvisionFile.ERR_PRODUCTION_CONFIRMATION_REQUIRED) }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains(ProvisionFile.ERR_PRODUCTION_REQUIRES_ENVIRONMENT) }
        assertThat(v).anyMatch { it.contains("resources[3]") && it.contains("cannot carry 'grants'") }
        assertThat(v).anyMatch { it.contains("resources[4] spec.github") && it.contains(ProvisionFile.ERR_INVALID_GITHUB_IDS) && it.contains("go together") }
        assertThat(v).anyMatch { it.contains("resources[5] spec.forgejo") && it.contains(ProvisionFile.ERR_INVALID_FORGEJO_INSTANCE) }
        assertThat(v).anyMatch { it.contains("resources[5] spec.forgejo") && it.contains(ProvisionFile.ERR_INVALID_FORGEJO_IDS) }
        assertThat(v).anyMatch { it.contains("resources[6]") && it.contains(ProvisionFile.ERR_PRODUCTION_REQUIRES_REF) }
        assertThat(v).anyMatch { it.contains("resources[7]") && it.contains(ProvisionFile.ERR_PRODUCTION_REQUIRES_SERVICE_ACCOUNT) }
        assertThat(v).anyMatch { it.contains("resources[8] spec.kubernetes.jwks.keys[0]") && it.contains(ProvisionFile.ERR_INVALID_KUBERNETES_JWKS) && it.contains("PRIVATE key material (d)") }
        assertThat(v).anyMatch { it.contains("resources[9] spec.github does not belong to provider 'kubernetes'") }
        assertThat(v).anyMatch { it.contains("resources[9] spec.kubernetes is required for provider 'kubernetes'") }
        assertThat(v).anyMatch { it.contains("resources[10] spec.github has unknown property 'branch'") }
        assertThat(v).anyMatch { it.contains("resources[11] spec has unknown property 'audience'") }
        assertThat(v).anyMatch { it.contains("resources[12] (workloadIdentityTrust) requires a name") }
        assertThat(v).anyMatch { it.contains("resources[13] (workloadIdentityTrust) spec.scopes is required") }
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining(ProvisionFile.ERR_PRODUCTION_CONFIRMATION_REQUIRED)

        // The schema pins the same shape: the kind is in the enum (the sibling test asserts enum == KINDS), a closed provider
        // set with exactly one pin block each, tenant: scopes, no grants / publishTo / secretSink on a trust.
        assertThat(schema["\$defs"]["resource"]["properties"]["kind"]["enum"].toList().map { it.asString() }).contains(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST)
        val spec = trustRule()["then"]["properties"]["spec"]
        assertThat(spec["additionalProperties"].asBoolean()).isFalse()
        assertThat(spec["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.REQUIRED_SPEC.getValue(ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST))
        assertThat(spec["properties"]["provider"]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.TRUST_PROVIDERS)
        assertThat(spec["properties"].properties().map { it.key }.toSet()).isEqualTo(ProvisionFile.TRUST_SPEC_KEYS)
        assertThat(Regex(spec["properties"]["scopes"]["items"]["pattern"].asString()).pattern).isEqualTo(ProvisionFile.TENANT_SCOPE_PATTERN.pattern)
        assertThat(spec["properties"]["github"]["properties"].properties().map { it.key }.toSet()).isEqualTo(ProvisionFile.GITHUB_PIN_KEYS)
        assertThat(spec["properties"]["forgejo"]["properties"].properties().map { it.key }.toSet()).isEqualTo(ProvisionFile.FORGEJO_PIN_KEYS)
        assertThat(spec["properties"]["kubernetes"]["properties"].properties().map { it.key }.toSet()).isEqualTo(ProvisionFile.KUBERNETES_PIN_KEYS)
        assertThat(spec["allOf"].toList().map { it["if"]["properties"]["provider"]["const"].asString() to it["then"]["required"][0].asString() }.toMap()).isEqualTo(ProvisionFile.TRUST_PIN_BLOCKS)
        assertThat(trustRule()["then"]["not"]["anyOf"].toList().map { it["required"][0].asString() }).containsExactlyInAnyOrder("grants", "publishTo", "secretSink")
    }
}
