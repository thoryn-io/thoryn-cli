package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionGrant
import com.devnow.thoryn.provision.PublishTarget
import com.devnow.thoryn.provision.SecretTarget
import com.devnow.thoryn.provision.ProvisionFile
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
        // SSO-3962 — the three apiVersions, and each PART's kind enum (the root `allOf` conditionals) equal the loader's sets.
        assertThat(schema["properties"]["apiVersion"]["enum"].toList().map { it.asString() }).isEqualTo(ProvisionFile.API_VERSIONS)
        val perPart = schema["allOf"].toList().associate { c ->
            c["if"]["properties"]["apiVersion"]["const"].asString() to c["then"]["properties"]["resources"]["items"]["properties"]["kind"]["enum"].toList().map { it.asString() }.toSet()
        }
        assertThat(perPart).containsOnlyKeys(ProvisionFile.API_VERSION_TENANT, ProvisionFile.API_VERSION_APPLICATION)
        assertThat(perPart[ProvisionFile.API_VERSION_TENANT]).isEqualTo(ProvisionFile.TENANT_KINDS)
        assertThat(perPart[ProvisionFile.API_VERSION_APPLICATION]).isEqualTo(ProvisionFile.APPLICATION_KINDS)
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
        // SSO-3673 — `owner` is a real platform relation but never a file's to declare: refused, naming the admin's fix.
        assertThat(v).anyMatch { it.contains("resources[1] grants[0]") && it.contains("relation 'owner'") && it.contains("cannot claim ownership by writing YAML") && it.contains("thoryn access grant <subject> owner <object>") }
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
    fun `readOnly is a boolean on every kind, excludes grants, and the schema pins the same two rules`() {
        // SSO-3659 (ADR 2026-10-13 §1) — a read-only reference is a dependency, not ownership: no grants on it.
        val ok = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: shared, readOnly: true, spec: { clientId: shared, displayName: "Shared" } }
              - { kind: environment, name: ci, readOnly: true, spec: { slug: ci } }
              - { kind: loginMethods, environment: ci, readOnly: true, spec: { methods: [password] } }
              - { kind: customDomain, readOnly: true, spec: { host: auth.example.com } }
              - { kind: user, name: owned, spec: { email: owned@example.com } }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(ok)).isEmpty()
        val parsed = ProvisionFile.parse(json.writeValueAsBytes(ok), "provision.json", yaml = false)
        assertThat(parsed.resources.map { it.readOnly }).containsExactly(true, true, true, true, false)

        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: a, readOnly: "yes", spec: { displayName: a } }
              - { kind: environment, name: b, readOnly: true, spec: { slug: b }, grants: [ { subject: "client:x", relation: viewer } ] }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] readOnly must be true or false") }
        assertThat(v).anyMatch { it.contains("resources[1]") && it.contains("read-only reference cannot carry 'grants'") }

        val readOnly = schema["\$defs"]["resource"]["properties"][ProvisionFile.READ_ONLY]
        assertThat(readOnly["type"].asString()).isEqualTo("boolean")
        assertThat(readOnly["default"].asBoolean()).isFalse()
        // The read-only exclusions the schema pins: `grants` (SSO-3659) and, SSO-3715, `retain` (a reference is never removed anyway).
        val exclusions = schema["\$defs"]["resource"]["allOf"].toList()
            .filter { it["if"]["properties"]?.get(ProvisionFile.READ_ONLY)?.get("const")?.asBoolean() == true && it["then"]["not"]?.get("required") != null }
            .map { it["then"]["not"]["required"].toList().single().asString() }
        assertThat(exclusions).contains("grants", ProvisionFile.RETAIN)
        // SSO-3715 — `retain` is a boolean, refused with readOnly by the loader too.
        val retain = schema["\$defs"]["resource"]["properties"][ProvisionFile.RETAIN]
        assertThat(retain["type"].asString()).isEqualTo("boolean")
        assertThat(retain["default"].asBoolean()).isFalse()
        val both = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: a, readOnly: true, retain: true, spec: { displayName: a } }
              - { kind: application, name: b, retain: "yes", spec: { displayName: b } }
            """.trimIndent(),
        )
        val rv = ProvisionFile.validate(both)
        assertThat(rv).anyMatch { it.contains("resources[0]") && it.contains("read-only reference cannot carry 'retain'") }
        assertThat(rv).anyMatch { it.contains("resources[1] retain must be true or false") }
    }

    @Test
    fun `publishTo is accepted on an application with a well-formed githubActionsVariable target, and parses`() {
        // SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) — the config repository's fragment.
        val ok = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: billing-web
                spec: { displayName: "Billing web", clientType: public, redirectUris: ["https://billing.acme.example/callback"] }
                publishTo:
                  - { kind: githubActionsVariable, repository: acme/billing-web, environment: production, name: THORYN_PRODUCTION_CLIENT_ID }
                  - { kind: githubActionsVariable, repository: acme/billing-web, environment: staging, name: THORYN_PRODUCTION_CLIENT_ID }
              - kind: application
                name: plain
                spec: { displayName: "No outputs" }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(ok)).isEmpty()
        val parsed = ProvisionFile.parse(json.writeValueAsBytes(ok), "provision.json", yaml = false)
        assertThat(parsed.resources[0].publishTo).containsExactly(
            PublishTarget("githubActionsVariable", "acme/billing-web", "production", "THORYN_PRODUCTION_CLIENT_ID"),
            PublishTarget("githubActionsVariable", "acme/billing-web", "staging", "THORYN_PRODUCTION_CLIENT_ID"),
        )
        assertThat(parsed.resources[1].publishTo).isEmpty()
        assertThat(parsed.resources[0].publishTo[0].byHand("app-1")).isEqualTo("gh variable set THORYN_PRODUCTION_CLIENT_ID --body app-1 --repo acme/billing-web --env production")
    }

    @Test
    fun `publishTo is rejected on other kinds, on a read-only reference, and on a malformed target`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, spec: { slug: ci }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, environment: production, name: ENV_ID } ] }
              - { kind: application, name: ref, readOnly: true, spec: { displayName: "Shared" }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, environment: production, name: SHARED_ID } ] }
              - { kind: application, name: a, spec: { displayName: a }, publishTo: [ { kind: forgejoVariable, repository: acme/x, environment: production, name: A_ID } ] }
              - { kind: application, name: b, spec: { displayName: b }, publishTo: [ { kind: githubActionsVariable, repository: "acme/x/y", environment: production, name: B_ID } ] }
              - { kind: application, name: c, spec: { displayName: c }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, environment: production, name: "client-id" } ] }
              - { kind: application, name: d, spec: { displayName: d }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, environment: production, name: GITHUB_CLIENT_ID } ] }
              - { kind: application, name: e, spec: { displayName: e }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, name: E_ID, secret: true } ] }
              - { kind: application, name: f, spec: { displayName: f }, publishTo: [ { kind: githubActionsVariable, repository: acme/x, environment: production, name: F_ID }, { kind: githubActionsVariable, repository: acme/x, environment: production, name: F_ID } ] }
              - { kind: application, name: g, spec: { displayName: g }, publishTo: { kind: githubActionsVariable } }
              - { kind: application, name: h, spec: { displayName: h }, publishTo: [] }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] publishTo is only supported on kind application") }
        assertThat(v).anyMatch { it.contains("resources[1]") && it.contains("read-only reference cannot carry 'publishTo'") }
        assertThat(v).anyMatch { it.contains("resources[2] publishTo[0] kind 'forgejoVariable'") }
        assertThat(v).anyMatch { it.contains("resources[3] publishTo[0] repository 'acme/x/y'") }
        assertThat(v).anyMatch { it.contains("resources[4] publishTo[0] name 'client-id'") }
        assertThat(v).anyMatch { it.contains("resources[5] publishTo[0] name 'GITHUB_CLIENT_ID' is reserved") }
        assertThat(v).anyMatch { it.contains("resources[6] publishTo[0] environment is required") }
        assertThat(v).anyMatch { it.contains("resources[6] publishTo[0] has unknown property 'secret'") }
        assertThat(v).anyMatch { it.contains("resources[7] publishTo[1] duplicates target") }
        assertThat(v).anyMatch { it.contains("resources[8] publishTo must be an array") }
        assertThat(v).anyMatch { it.contains("resources[9] publishTo must name at least one target") }
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("publishTo")

        // The schema pins the same rules: the closed kind enum, the two grammars, exactly four members, application-only, not with readOnly.
        val publishTo = schema["\$defs"]["resource"]["properties"][ProvisionFile.PUBLISH_TO]
        assertThat(publishTo["minItems"].asInt()).isEqualTo(1)
        val item = publishTo["items"]
        assertThat(item["additionalProperties"].asBoolean()).isFalse()
        assertThat(item["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.PUBLISH_TARGET_KEYS)
        assertThat(item["properties"]["kind"]["enum"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.PUBLISH_KINDS)
        assertThat(item["properties"]["repository"]["pattern"].asString()).isEqualTo(ProvisionFile.REPOSITORY_PATTERN.pattern)
        val name = Regex(item["properties"]["name"]["pattern"].asString())
        assertThat(name.matches("THORYN_PRODUCTION_CLIENT_ID")).isTrue()
        assertThat(name.matches("client-id")).isFalse()
        assertThat(name.matches("GITHUB_CLIENT_ID")).isFalse()
        val rules = schema["\$defs"]["resource"]["allOf"].toList()
        val onlyApplication = rules.first { it["if"]["required"]?.toList()?.map { r -> r.asString() } == listOf(ProvisionFile.PUBLISH_TO) }
        assertThat(onlyApplication["then"]["properties"]["kind"]["const"].asString()).isEqualTo(ProvisionFile.KIND_APPLICATION)
        assertThat(rules).anyMatch { r -> r["if"]["properties"]?.get(ProvisionFile.READ_ONLY)?.get("const")?.asBoolean() == true && r["then"]["not"]["required"].toList().map { it.asString() } == listOf(ProvisionFile.PUBLISH_TO) }
    }

    @Test
    fun `secretSink is accepted on a confidential application in both kinds, and parses`() {
        // SSO-3659 (ADR 2026-10-13 converge §5) — the forge login client's fragment, and a file sink.
        val ok = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-login
                spec: { displayName: "Forge login", grantTypes: [authorization_code], redirectUris: ["https://forge.example/cb"] }
                secretSink: { kind: kubernetesSecret, namespace: forge, name: forge-login, key: client-secret }
              - kind: application
                name: worker
                spec: { displayName: "Worker", clientType: confidential, grantTypes: [client_credentials] }
                secretSink: { kind: file, path: .secrets/worker.secret }
              - kind: application
                name: plain
                spec: { displayName: "No sink" }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(ok)).isEmpty()
        val parsed = ProvisionFile.parse(json.writeValueAsBytes(ok), "provision.json", yaml = false)
        assertThat(parsed.resources[0].secretSink).isEqualTo(SecretTarget("kubernetesSecret", namespace = "forge", name = "forge-login", key = "client-secret"))
        assertThat(parsed.resources[0].secretSink!!.label).isEqualTo("kubernetesSecret forge/forge-login key client-secret")
        assertThat(parsed.resources[1].secretSink).isEqualTo(SecretTarget("file", path = ".secrets/worker.secret"))
        assertThat(parsed.resources[1].secretSink!!.label).isEqualTo("file .secrets/worker.secret")
        assertThat(parsed.resources[2].secretSink).isNull()
    }

    @Test
    fun `secretSink is rejected on a public client, on other kinds, on a read-only reference, and on a malformed target`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: spa, spec: { displayName: SPA, clientType: public }, secretSink: { kind: file, path: spa.secret } }
              - { kind: environment, name: ci, spec: { slug: ci }, secretSink: { kind: file, path: env.secret } }
              - { kind: application, name: ref, readOnly: true, spec: { displayName: "Shared" }, secretSink: { kind: file, path: ref.secret } }
              - { kind: application, name: a, spec: { displayName: a }, secretSink: { kind: vaultKv, path: secret/a } }
              - { kind: application, name: b, spec: { displayName: b }, secretSink: { kind: kubernetesSecret, namespace: "Forge", name: b, key: k } }
              - { kind: application, name: c, spec: { displayName: c }, secretSink: { kind: kubernetesSecret, namespace: forge, name: "b_c", key: k } }
              - { kind: application, name: d, spec: { displayName: d }, secretSink: { kind: kubernetesSecret, namespace: forge, name: d, key: "client secret" } }
              - { kind: application, name: e, spec: { displayName: e }, secretSink: { kind: kubernetesSecret, namespace: forge, name: e } }
              - { kind: application, name: f, spec: { displayName: f }, secretSink: { kind: kubernetesSecret, namespace: forge, name: f, key: k, path: f.secret } }
              - { kind: application, name: g, spec: { displayName: g }, secretSink: { kind: file } }
              - { kind: application, name: h, spec: { displayName: h }, secretSink: [ { kind: file, path: h.secret } ] }
              - { kind: application, name: i, spec: { displayName: i }, secretSink: { namespace: forge, name: i, key: k } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0] secretSink on a public client") }
        assertThat(v).anyMatch { it.contains("resources[1] secretSink is only supported on kind application") }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains("read-only reference cannot carry 'secretSink'") }
        assertThat(v).anyMatch { it.contains("resources[3] secretSink kind 'vaultKv'") }
        assertThat(v).anyMatch { it.contains("resources[4] secretSink namespace 'Forge'") }
        assertThat(v).anyMatch { it.contains("resources[5] secretSink name 'b_c'") }
        assertThat(v).anyMatch { it.contains("resources[6] secretSink key 'client secret'") }
        assertThat(v).anyMatch { it.contains("resources[7] secretSink key is required") }
        assertThat(v).anyMatch { it.contains("resources[8] secretSink has unknown property 'path'") }
        assertThat(v).anyMatch { it.contains("resources[9] secretSink path is required") }
        assertThat(v).anyMatch { it.contains("resources[10] secretSink must be an object") }
        assertThat(v).anyMatch { it.contains("resources[11] secretSink kind is required") }
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("secretSink")

        // The schema pins the same rules: the closed kind set (one oneOf branch per kind), exactly the members, the
        // Kubernetes grammars, application-only, not with readOnly, not on a public client.
        val secretSink = schema["\$defs"]["resource"]["properties"][ProvisionFile.SECRET_SINK]
        val branches = secretSink["oneOf"].toList().associateBy { it["properties"]["kind"]["const"].asString() }
        assertThat(branches.keys).isEqualTo(ProvisionFile.SECRET_SINK_KINDS)
        branches.values.forEach { assertThat(it["additionalProperties"].asBoolean()).isFalse() }
        val k8s = branches.getValue(ProvisionFile.SECRET_SINK_KIND_KUBERNETES_SECRET)
        assertThat(k8s["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.SECRET_SINK_KUBERNETES_KEYS)
        assertThat(k8s["properties"]["namespace"]["pattern"].asString()).isEqualTo(ProvisionFile.K8S_NAMESPACE_PATTERN.pattern)
        assertThat(k8s["properties"]["name"]["pattern"].asString()).isEqualTo(ProvisionFile.K8S_SECRET_NAME_PATTERN.pattern)
        assertThat(k8s["properties"]["name"]["maxLength"].asInt()).isEqualTo(ProvisionFile.K8S_SECRET_NAME_MAX)
        assertThat(k8s["properties"]["key"]["pattern"].asString()).isEqualTo(ProvisionFile.K8S_SECRET_KEY_PATTERN.pattern)
        val file = branches.getValue(ProvisionFile.SECRET_SINK_KIND_FILE)
        assertThat(file["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.SECRET_SINK_FILE_KEYS)
        val rules = schema["\$defs"]["resource"]["allOf"].toList().filter { it["if"]["required"]?.toList()?.map { r -> r.asString() } == listOf(ProvisionFile.SECRET_SINK) }
        assertThat(rules).anyMatch { it["then"]["properties"]["kind"]?.get("const")?.asString() == ProvisionFile.KIND_APPLICATION }
        assertThat(rules).anyMatch { it["then"]["properties"]["spec"]?.get("not")?.get("properties")?.get("clientType")?.get("const")?.asString() == ProvisionFile.CLIENT_TYPE_PUBLIC }
        assertThat(schema["\$defs"]["resource"]["allOf"].toList()).anyMatch { r -> r["if"]["properties"]?.get(ProvisionFile.READ_ONLY)?.get("const")?.asBoolean() == true && r["then"]["not"]["required"].toList().map { it.asString() } == listOf(ProvisionFile.SECRET_SINK) }
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
        assertThat(ProvisionFile.validate(bad)).anyMatch { it.startsWith("apiVersion must be '${ProvisionFile.API_VERSION_TENANT}'") && it.contains("(was 'thoryn.io/provision/v2')") }
        assertThat(ProvisionFile.validate(bad)).contains(
            "(root) has unknown property 'steps' (additionalProperties:false)",
            "resources must be non-empty",
        )
    }
}
