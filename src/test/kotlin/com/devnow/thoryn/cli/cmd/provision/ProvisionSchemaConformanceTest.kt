package com.devnow.thoryn.cli.cmd.provision

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3088 (epic SSO-3087) — dogfood `provision.schema.json` against real provisioning documents and
 * guard against the bundled schema drifting from the [ProvisionFile] loader that validates against it
 * (the same drift-guard shape as the recipe + connection conformance tests): the schema is the
 * documented contract, the loader is the runtime, and the closed `kind` allowlist is read FROM the
 * schema so the two cannot disagree silently.
 */
class ProvisionSchemaConformanceTest {

    private val yaml = YAMLMapper()
    private val json = JsonMapper.builder().build()

    private val schema: JsonNode = json.readTree(
        javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing resource ${ProvisionFile.SCHEMA_RESOURCE}"),
    )

    private val representative = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci, displayName: "CI sandbox" }
          - kind: application
            name: loopback-rp
            environment: ci
            spec:
              displayName: "CI Sign-in App"
              clientType: public
              grantTypes: [authorization_code]
              redirectUris: ["http://127.0.0.1/callback"]
          - kind: user
            name: tester
            environment: ci
            spec: { email: tester@example.com, passwordEnv: TEST_USER_PASSWORD, emailVerified: true }
          - kind: emailProvider
            environment: ci
            spec: { smtpHost: smtp.example.com, smtpPort: 587, smtpPasswordEnv: SMTP_PASSWORD }
          - kind: loginTheme
            environment: ci
            spec: { primaryColor: "#0f62fe", theme: light }
          - kind: loginMethods
            environment: ci
            spec: { methods: [password, magic_link, passkey] }
          - kind: application
            name: ci-worker
            environment: ci
            spec: { displayName: "CI worker", clientType: confidential, grantTypes: [client_credentials] }
            grants:
              - { subject: "client:cli-ci", relation: manager }
              - { subject: "member:alice", relation: viewer }
    """.trimIndent()

    @Test
    fun `the schema kind enum equals the loader's closed allowlist`() {
        val enum = schema["\$defs"]["resource"]["properties"]["kind"]["enum"].toList().map { it.asString() }.toSet()
        assertThat(enum).isEqualTo(ProvisionFile.KINDS)
        assertThat(schema["properties"]["apiVersion"]["const"].asString()).isEqualTo(ProvisionFile.API_VERSION)
    }

    @Test
    fun `a representative provisioning file conforms and parses`() {
        assertThat(ProvisionFile.validate(yaml.readTree(representative))).isEmpty()
        val file = ProvisionFile.parse(representative.toByteArray(), "provision.yaml")
        assertThat(file.digest).startsWith("sha256:")
        assertThat(file.resources.map { it.key }).containsExactly(
            "environment/ci", "application/loopback-rp", "user/tester", "emailProvider/emailProvider", "loginTheme/loginTheme", "loginMethods/loginMethods", "application/ci-worker",
        )
        // SSO-3113 — `grants` parses into (subject, relation) pairs; a resource without the block has null (unmanaged).
        assertThat(file.resources[6].grants).containsExactly(ProvisionGrant("client:cli-ci", "manager"), ProvisionGrant("member:alice", "viewer"))
        assertThat(file.resources[1].grants).isNull()
        assertThat(file.resources[1].environment).isEqualTo("ci")
        assertThat(file.environmentResource("ci")).isNotNull
        // A singleton without a name defaults its name to the kind.
        assertThat(file.resources[3].isSingleton).isTrue()
    }

    @Test
    fun `the same document parses as JSON`() {
        val asJson = json.writeValueAsBytes(yaml.readTree(representative))
        assertThat(ProvisionFile.parse(asJson, "provision.json", yaml = false).resources).hasSize(7)
    }

    @Test
    fun `a kind outside the allowlist is rejected`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: dbSeed, name: x, spec: { table: client } }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(bad)).anyMatch { it.contains("dbSeed") && it.contains("allowlist") }
    }

    @Test
    fun `a spec key that would carry a secret value is rejected — name the env var instead`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: user, name: t, spec: { email: t@example.com, password: "hunter2" } }
              - { kind: federationMember, name: okta, spec: { providerType: okta, clientSecret: "s3" } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("spec.password") && it.contains("passwordEnv") }
        assertThat(v).anyMatch { it.contains("spec.clientSecret") && it.contains("clientSecretEnv") }
        // The schema encodes the same rule (propertyNames must NOT end in password/secret/token).
        val pattern = schema["\$defs"]["resource"]["properties"]["spec"]["propertyNames"]["not"]["pattern"].asString()
        assertThat(Regex(pattern).containsMatchIn("smtpPassword")).isTrue()
        assertThat(Regex(pattern).containsMatchIn("smtpPasswordEnv")).isFalse()
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("passwordEnv")
    }

    @Test
    fun `required spec members, names, and uniqueness are enforced per kind`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, environment: other, spec: { displayName: "no slug" } }
              - { kind: application, spec: { redirectUris: [] } }
              - { kind: user, name: Bad_Name, spec: { email: a@b } }
              - { kind: loginFlow, spec: { } }
              - { kind: application, name: dup, spec: { displayName: a } }
              - { kind: application, name: dup, spec: { displayName: b } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("spec.slug is required") }
        assertThat(v).anyMatch { it.contains("cannot itself carry 'environment'") }
        assertThat(v).anyMatch { it.contains("(application) requires a name") }
        assertThat(v).anyMatch { it.contains("spec.displayName is required") }
        assertThat(v).anyMatch { it.contains("name 'Bad_Name'") }
        assertThat(v).anyMatch { it.contains("spec.templateId is required") }
        assertThat(v).anyMatch { it.contains("duplicate resource 'application/dup'") }
    }

    @Test
    fun `loginMethods requires a non-empty list of method names`() {
        // SSO-3100 — the singleton's `methods` is the FULL allow-list; an absent, empty, or non-string list is rejected.
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: loginMethods, environment: ci, spec: { } }
              - { kind: loginMethods, name: empty, environment: ci, spec: { methods: [] } }
              - { kind: loginMethods, name: blank, environment: ci, spec: { methods: [password, ""] } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] (loginMethods) spec.methods is required") }
        assertThat(v).anyMatch { it.contains("resources[1] (loginMethods) spec.methods is required") }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains("non-empty method names") }
        // The schema pins the same shape: minItems 1, string items, and the kind is a singleton (no name needed).
        val methods = schema["\$defs"]["resource"]["allOf"].toList()
            .first { it["if"]["properties"]["kind"]["const"].asString() == "loginMethods" }["then"]["properties"]["spec"]["properties"]["methods"]
        assertThat(methods["minItems"].asInt()).isEqualTo(1)
        assertThat(methods["items"]["type"].asString()).isEqualTo("string")
        assertThat(ProvisionFile.SINGLETON_KINDS).contains(ProvisionFile.KIND_LOGIN_METHODS)
    }

    @Test
    fun `grants are validated — subject grammar, the relation enum, duplicates and unknown keys`() {
        // SSO-3113 — the `grants:` block carries no object (it derives from the receipt id) and no secret.
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: a, spec: { slug: a }, grants: [ { subject: "robot:x", relation: manager } ] }
              - { kind: environment, name: b, spec: { slug: b }, grants: [ { subject: "client:x", relation: owner } ] }
              - { kind: environment, name: c, spec: { slug: c }, grants: [ { subject: "client:x", relation: manager }, { subject: "client:x", relation: manager } ] }
              - { kind: environment, name: d, spec: { slug: d }, grants: [ { subject: "client:x", relation: manager, object: "environment:zzz" } ] }
              - { kind: environment, name: e, spec: { slug: e }, grants: { subject: "client:x" } }
              - { kind: environment, name: f, spec: { slug: f }, grants: [ { relation: viewer } ] }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] grants[0]") && it.contains("subject type 'robot'") }
        assertThat(v).anyMatch { it.contains("resources[1] grants[0]") && it.contains("relation 'owner'") }
        assertThat(v).anyMatch { it.contains("resources[2] grants[1]") && it.contains("duplicates grant 'client:x manager'") }
        assertThat(v).anyMatch { it.contains("resources[3] grants[0]") && it.contains("unknown property 'object'") }
        assertThat(v).anyMatch { it.contains("resources[4] grants must be an array") }
        assertThat(v).anyMatch { it.contains("resources[5] grants[0] subject is required") }
        // The schema pins the same grammar: the relation enum equals the loader's set, the subject pattern equals the CLI's.
        val grants = schema["\$defs"]["resource"]["properties"]["grants"]
        assertThat(grants["items"]["properties"]["relation"]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.GRANT_RELATIONS)
        val subject = Regex(grants["items"]["properties"]["subject"]["pattern"].asString())
        assertThat(subject.matches("client:cli-ci")).isTrue()
        assertThat(subject.matches("member:auth0|abc")).isTrue()
        assertThat(subject.matches("robot:x")).isFalse()
        assertThat(grants["items"]["additionalProperties"].asBoolean()).isFalse()
        assertThat(grants["items"]["required"].toList().map { it.asString() }).containsExactly("subject", "relation")
    }

    @Test
    fun `apiVersion, unknown properties and an empty resource list are rejected`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v2
            steps: []
            resources: []
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(bad)).contains(
            "apiVersion must be '${ProvisionFile.API_VERSION}'",
            "(root) has unknown property 'steps' (additionalProperties:false)",
            "resources must be non-empty",
        )
    }
}
