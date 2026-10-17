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
 * SSO-3766 / SSO-3767 / SSO-3770 — the shapes `provision.schema.json` and the [ProvisionFile] loader accept and refuse for
 * the three application settings the applications API took on (oauthy SSO-3759 `allowedAuthorizationDetailTypes`, SSO-3758
 * `allowTokenExchange`, SSO-3762 `refreshTokenSlidingWindow` / `refreshTokenAbsoluteMaxTtlSeconds`), with product-api's own
 * codes in the refusals the file alone can decide. Same drift-guard shape as [ProvisionSecretlessSchemaTest]: the schema is
 * the documented contract, the loader the runtime, and the bounds / rules are read FROM the schema so the two cannot
 * disagree silently.
 */
class ProvisionApplicationSettingsSchemaTest {

    private val yaml = YAMLMapper()
    private val json = JsonMapper.builder().build()

    private val schema: JsonNode = json.readTree(
        javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing resource ${ProvisionFile.SCHEMA_RESOURCE}"),
    )

    private val rules: List<JsonNode> get() = schema["\$defs"]["resource"]["allOf"].toList()

    private fun applicationSpecProperties(): JsonNode =
        rules.first { it["if"]["properties"]?.get("kind")?.get("const")?.asString() == "application" && it["if"]["properties"].size() == 1 }["then"]["properties"]["spec"]["properties"]

    private val exchange = ProvisionFile.GRANT_TOKEN_EXCHANGE

    @Test
    fun `every setting parses — token exchange on an authenticating client, detail types (an empty list included), a capped sliding session — and an omitted one is simply absent`() {
        val ok = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: portal-pods
                spec:
                  provider: kubernetes
                  kubernetes: { issuer: "https://oidc.example", namespace: portal, serviceAccount: web }
                  scopes: [tenant:applications.read]
                  confirmProduction: true
              - kind: application
                name: portal
                spec:
                  displayName: "Acme Portal"
                  redirectUris: ["https://app.acme.example/cb"]
                  grantTypes: [authorization_code, refresh_token, "$exchange"]
                  allowTokenExchange: true
                  allowedAuthorizationDetailTypes: [openid_credential]
                  refreshTokenTtlSeconds: 3600
                  refreshTokenSlidingWindow: true
                  refreshTokenAbsoluteMaxTtlSeconds: 28800
              - kind: application
                name: federated
                spec:
                  displayName: "Federated portal"
                  redirectUris: ["https://f.acme.example/cb"]
                  grantTypes: [authorization_code, refresh_token, "$exchange"]
                  clientAuthenticationMethods: [federated_assertion]
                  federatedTrust: portal-pods
                  allowTokenExchange: true
              - kind: application
                name: cleared
                spec: { displayName: "Cleared", allowedAuthorizationDetailTypes: [], allowTokenExchange: false, refreshTokenSlidingWindow: false }
              - kind: application
                name: plain
                spec: { displayName: "Plain" }
            """.trimIndent(),
        )
        assertThat(ProvisionFile.validate(ok)).isEmpty()
        val parsed = ProvisionFile.parse(json.writeValueAsBytes(ok), "provision.json", yaml = false)
        val portal = parsed.resources[1].spec
        assertThat(portal[ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE]).isEqualTo(true)
        assertThat(portal[ProvisionFile.SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES]).isEqualTo(listOf("openid_credential"))
        assertThat(portal[ProvisionFile.SPEC_REFRESH_TOKEN_SLIDING_WINDOW]).isEqualTo(true)
        assertThat(portal[ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS]).isEqualTo(28800)
        assertThat(parsed.resources[3].spec[ProvisionFile.SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES]).isEqualTo(emptyList<String>())
        assertThat(parsed.resources[4].spec.keys).doesNotContainAnyElementsOf(ProvisionFile.APPLICATION_SETTING_FIELDS)
    }

    @Test
    fun `a setting is refused with product-api's codes — a public exchanger, a missing grant, the session without its window, out of range, below the refresh TTL, malformed types`() {
        val bad = yaml.readTree(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: a, spec: { displayName: a, clientType: public, grantTypes: ["$exchange"], allowTokenExchange: true } }
              - { kind: application, name: b, spec: { displayName: b, clientAuthenticationMethods: [none], grantTypes: ["$exchange"], allowTokenExchange: true } }
              - { kind: application, name: c, spec: { displayName: c, grantTypes: [authorization_code], allowTokenExchange: true } }
              - { kind: application, name: d, spec: { displayName: d, allowTokenExchange: true } }
              - { kind: application, name: e, spec: { displayName: e, refreshTokenAbsoluteMaxTtlSeconds: 28800 } }
              - { kind: application, name: f, spec: { displayName: f, refreshTokenSlidingWindow: false, refreshTokenAbsoluteMaxTtlSeconds: 28800 } }
              - { kind: application, name: g, spec: { displayName: g, refreshTokenSlidingWindow: true, refreshTokenAbsoluteMaxTtlSeconds: 1800 } }
              - { kind: application, name: h, spec: { displayName: h, refreshTokenSlidingWindow: true, refreshTokenAbsoluteMaxTtlSeconds: 7776001 } }
              - { kind: application, name: i, spec: { displayName: i, refreshTokenTtlSeconds: 86400, refreshTokenSlidingWindow: true, refreshTokenAbsoluteMaxTtlSeconds: 28800 } }
              - { kind: application, name: j, spec: { displayName: j, refreshTokenSlidingWindow: true, refreshTokenAbsoluteMaxTtlSeconds: "8h" } }
              - { kind: application, name: k, spec: { displayName: k, allowTokenExchange: "yes", refreshTokenSlidingWindow: 1 } }
              - { kind: application, name: l, spec: { displayName: l, allowedAuthorizationDetailTypes: "openid_credential" } }
              - { kind: application, name: m, spec: { displayName: m, allowedAuthorizationDetailTypes: ["openid_credential thoryn_access_grant", ""] } }
              - { kind: application, name: n, spec: { displayName: n, allowedAuthorizationDetailTypes: [openid_credential, openid_credential] } }
              - { kind: application, name: o, spec: { displayName: o, clientAuthenticationMethods: [federated_assertion], federatedTrust: t, grantTypes: [authorization_code, "$exchange"] } }
            """.trimIndent(),
        )
        val v = ProvisionFile.validate(bad)
        assertThat(v).anyMatch { it.contains("resources[0]") && it.contains(ProvisionFile.ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT) }
        assertThat(v).anyMatch { it.contains("resources[1]") && it.contains(ProvisionFile.ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT) }
        assertThat(v).anyMatch { it.contains("resources[2]") && it.contains(ProvisionFile.ERR_TOKEN_EXCHANGE_GRANT_REQUIRED) && it.contains(exchange) }
        assertThat(v).anyMatch { it.contains("resources[3]") && it.contains(ProvisionFile.ERR_TOKEN_EXCHANGE_GRANT_REQUIRED) }
        assertThat(v).anyMatch { it.contains("resources[4]") && it.contains(ProvisionFile.ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW) }
        assertThat(v).anyMatch { it.contains("resources[5]") && it.contains(ProvisionFile.ERR_SESSION_LIFETIME_REQUIRES_SLIDING_WINDOW) }
        assertThat(v).anyMatch { it.contains("resources[6]") && it.contains(ProvisionFile.ERR_TOKEN_TTL_OUT_OF_RANGE) && it.contains("1800") }
        assertThat(v).anyMatch { it.contains("resources[7]") && it.contains(ProvisionFile.ERR_TOKEN_TTL_OUT_OF_RANGE) && it.contains("7776001") }
        assertThat(v).anyMatch { it.contains("resources[8]") && it.contains(ProvisionFile.ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL) && it.contains("86400") }
        assertThat(v).anyMatch { it.contains("resources[9] spec.refreshTokenAbsoluteMaxTtlSeconds must be a whole number of seconds") }
        assertThat(v).anyMatch { it.contains("resources[10] spec.allowTokenExchange must be true or false") }
        assertThat(v).anyMatch { it.contains("resources[10] spec.refreshTokenSlidingWindow must be true or false") }
        assertThat(v).anyMatch { it.contains("resources[11] spec.allowedAuthorizationDetailTypes must be a list") }
        assertThat(v).anyMatch { it.contains("resources[12] spec.allowedAuthorizationDetailTypes[0] must be ONE authorization-details type") }
        assertThat(v).anyMatch { it.contains("resources[12] spec.allowedAuthorizationDetailTypes[1] must be ONE authorization-details type") }
        assertThat(v).anyMatch { it.contains("resources[13] spec.allowedAuthorizationDetailTypes lists a type twice") }
        // SSO-3767 — a federated login client registers the exchange grant only WITH the setting (ladder guide's grant row).
        assertThat(v).anyMatch { it.contains("resources[14]") && it.contains(ProvisionFile.ERR_FEDERATED_GRANT_NOT_ALLOWED) && it.contains("together with allowTokenExchange: true") }
        assertThatThrownBy { ProvisionFile.parse(json.writeValueAsBytes(bad), "bad.json", yaml = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining(ProvisionFile.ERR_TOKEN_EXCHANGE_GRANT_REQUIRED)
    }

    @Test
    fun `the schema pins the same contract — the four properties, the absolute bounds, the session and token-exchange rules, the federated exchange grant`() {
        val props = applicationSpecProperties()
        assertThat(props[ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE]["type"].asString()).isEqualTo("boolean")
        assertThat(props[ProvisionFile.SPEC_REFRESH_TOKEN_SLIDING_WINDOW]["type"].asString()).isEqualTo("boolean")
        val types = props[ProvisionFile.SPEC_ALLOWED_AUTHORIZATION_DETAIL_TYPES]
        assertThat(types["type"].asString()).isEqualTo("array")
        assertThat(types["uniqueItems"].asBoolean()).isTrue()
        assertThat(types["minItems"]).isNull() // `[]` is legal: it clears the list
        assertThat(types["items"]["pattern"].asString()).isEqualTo(ProvisionFile.AUTHORIZATION_DETAILS_TYPE_PATTERN.pattern)
        assertThat(types["items"]["enum"]).isNull() // the SERVER decides which types are supported — never frozen into the CLI
        val absolute = props[ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS]
        assertThat(absolute["type"].asString()).isEqualTo("integer")
        assertThat(absolute["minimum"].asLong()).isEqualTo(ProvisionFile.ABSOLUTE_SESSION_MIN_SECONDS)
        assertThat(absolute["maximum"].asLong()).isEqualTo(ProvisionFile.ABSOLUTE_SESSION_MAX_SECONDS)
        assertThat(ProvisionFile.APPLICATION_SETTING_FIELDS).allMatch { props.has(it) && !ProvisionFile.SECRET_KEY_PATTERN.containsMatchIn(it) }

        val session = rules.first { it["if"]["properties"]?.get("spec")?.get("required")?.toList()?.map { r -> r.asString() } == listOf(ProvisionFile.SPEC_REFRESH_TOKEN_ABSOLUTE_MAX_TTL_SECONDS) }
        assertThat(session["then"]["properties"]["spec"]["required"].toList().map { it.asString() }).containsExactly(ProvisionFile.SPEC_REFRESH_TOKEN_SLIDING_WINDOW)
        assertThat(session["then"]["properties"]["spec"]["properties"][ProvisionFile.SPEC_REFRESH_TOKEN_SLIDING_WINDOW]["const"].asBoolean()).isTrue()

        val tokenExchange = rules.first { it["if"]["properties"]?.get("spec")?.get("properties")?.get(ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE)?.get("const")?.asBoolean() == true }
        val then = tokenExchange["then"]["properties"]["spec"]
        assertThat(then["required"].toList().map { it.asString() }).containsExactly(ProvisionFile.SPEC_GRANT_TYPES)
        assertThat(then["properties"]["grantTypes"]["contains"]["const"].asString()).isEqualTo(exchange)
        assertThat(then["properties"]["clientAuthenticationMethods"]["not"]["contains"]["const"].asString()).isEqualTo(ProvisionFile.METHOD_NONE)
        assertThat(then["not"]["properties"]["clientType"]["const"].asString()).isEqualTo(ProvisionFile.CLIENT_TYPE_PUBLIC)

        val federated = rules.first { it["if"]["properties"]?.get("spec")?.get("properties")?.get("clientAuthenticationMethods")?.get("contains")?.get("const")?.asString() == "federated_assertion" }
        assertThat(federated["then"]["properties"]["spec"]["properties"]["grantTypes"]["items"]["enum"].toList().map { it.asString() }.toSet())
            .isEqualTo(ProvisionFile.FEDERATED_GRANT_TYPES + exchange)
        val federatedExchange = rules.first {
            it["if"]["properties"]?.get("spec")?.get("properties")?.get("grantTypes")?.get("contains")?.get("const")?.asString() == exchange
        }
        assertThat(federatedExchange["then"]["properties"]["spec"]["properties"][ProvisionFile.SPEC_ALLOW_TOKEN_EXCHANGE]["const"].asBoolean()).isTrue()
    }
}
