package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.SecretTarget
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.assertj.core.api.InstanceOfAssertFactories
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.dataformat.yaml.YAMLMapper
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951 — Thoryn owns the client-secret lifecycle, the customer owns
 * delivery) — `secretSink: { kind: customerManaged }`, and the SAME thing with no `secretSink:` at all (the default for a
 * confidential application): `apply` creates the client, DISCARDS the one-time value the create returns (it reaches no
 * declared sink and no generic channel — not even one that would accept it), grants nothing to anyone, reports nothing
 * undelivered, and names the person's step with the real client id; `plan` marks the create and prints the runbook; a
 * re-apply mints nothing. The file refuses the sink's wrong shapes exactly as every other sink's.
 */
class ProvisionCustomerManagedSecretTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun yaml(sink: String = "") = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-login
            spec:
              displayName: "Forge login"
              grantTypes: ["authorization_code"]
              redirectUris: ["https://forge.example/oauth2/callback"]
    """.trimIndent() + sink

    private val explicit = "\n    secretSink: { kind: customerManaged }\n"

    private fun parse(text: String) = ProvisionFile.parse(text.toByteArray(), "provision.yaml")

    /** Records any delivery attempt: a customer-managed secret must never reach one. */
    private class RecordingDeclaredSink : ProvisionEngine.DeclaredSecretSink {
        val calls = mutableListOf<String>()
        override fun deliver(target: SecretTarget, clientId: String, secret: String): String? { calls += clientId; return null }
    }

    /** A generic channel that WOULD accept the value (a `--secret-file`): it must not be offered it. */
    private class AcceptingGenericSink : ProvisionEngine.SecretSink {
        val calls = mutableListOf<String>()
        override fun emit(clientId: String, secret: String): Boolean { calls += clientId; return true }
    }

    private val declared = RecordingDeclaredSink()
    private val generic = AcceptingGenericSink()
    private val console = ByteArrayOutputStream()
    private val errors = ByteArrayOutputStream()

    private fun engine(): ProvisionEngine = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(errors),
        secretSink = generic, declaredSecretSink = declared,
    )

    private fun assertCustomerManagedCreate(file: ProvisionFile) {
        val e = engine()
        val plan = e.plan(file, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.reason)
            .contains("a client secret will be minted and discarded — managed by the customer: a person mints it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and stores it in your secret manager")
            .doesNotContain("shown once")
        assertThat(change.secretSink).isEqualTo(SecretTarget.CUSTOMER_MANAGED)
        assertThat(change.secretSink!!.label).isEqualTo("customerManaged")
        assertThat(change.pullClientId).isNull()
        assertThat(change.grantAdds).isEmpty()
        assertThat(change.toStructured()["secretSink"]).isEqualTo(mapOf("kind" to "customerManaged"))
        assertThat(plan.deliveries).isZero()
        assertThat(plan.runtimePulls).isZero()
        assertThat(plan.customerManaged).isEqualTo(1)
        assertThat(plan.warnings).isEmpty()
        assertThat(plan.toStructured()["summary"]).asInstanceOf(InstanceOfAssertFactories.MAP)
            .containsEntry("customerManaged", 1).containsEntry("deliver", 0).containsEntry("pull", 0)
        assertThat(api.writes).isEmpty()

        val result = e.apply(file, plan, "acme", null)
        val id = result.resources.single().id
        val secret = api.mintedSecrets.getValue(id)
        // The value went nowhere: not to a sink, not to the channel that would have taken it, and nothing is undelivered.
        assertThat(declared.calls).isEmpty()
        assertThat(generic.calls).isEmpty()
        assertThat(e.undeliveredSecrets).isEmpty()
        // No grant to anyone: the file manages no grants and a customer-managed secret needs no workload.
        assertThat(api.grantsOn("application:$id")).isEmpty()
        assertThat(api.writesTo("/api/v1/access")).isEmpty()
        // The person's step, with the real id; the secret nowhere.
        val mapper = jacksonObjectMapper()
        assertThat(console.toString()).doesNotContain(secret).doesNotContain("shown once")
            .contains("+ application forge-login: clientId=$id (client secret minted)")
            .contains("> application forge-login: client secret discarded (never shown or stored) — managed by the customer: mint it with `thoryn clients rotate-secret $id --secret-file <path>` and store it in your secret manager")
        assertThat(errors.toString()).doesNotContain(secret).doesNotContain("DEPRECATED").doesNotContain("undelivered")
        assertThat(mapper.writeValueAsString(result.toStructured())).doesNotContain(secret)
        assertThat(mapper.writeValueAsString(plan.toStructured())).doesNotContain(secret)
    }

    @Test
    fun `a confidential application with no secretSink is customer-managed by default — created, the secret discarded, no grant, nothing undelivered`() {
        val file = parse(yaml())
        assertThat(file.resources.single().secretSink).isNull()
        assertThat(file.resources.single().effectiveSecretSink).isEqualTo(SecretTarget.CUSTOMER_MANAGED)
        assertCustomerManagedCreate(file)
    }

    @Test
    fun `secretSink customerManaged declared explicitly behaves exactly as the default`() {
        val file = parse(yaml(explicit))
        assertThat(file.resources.single().secretSink).isEqualTo(SecretTarget.CUSTOMER_MANAGED)
        assertThat(file.resources.single().secretSink!!.customerManaged).isTrue()
        assertThat(file.resources.single().secretSink!!.discardsMintedSecret).isTrue()
        assertCustomerManagedCreate(file)
    }

    @Test
    fun `a re-apply mints nothing and the sink line is a create's only`() {
        val file = parse(yaml(explicit))
        val e = engine()
        e.apply(file, e.plan(file, false), "acme", null)
        api.reset()
        val again = e.plan(file, false)
        val change = again.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.secretSink).isNull()
        assertThat(again.customerManaged).isZero()
        assertThat(again.hasChanges).isFalse()
        e.apply(file, again, "acme", null)
        assertThat(api.writes).isEmpty()
        assertThat(api.mintedSecrets).hasSize(1)
    }

    @Test
    fun `nothing is minted for a public or secret-less client, so no sink is defaulted for it`() {
        val file = parse(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: application, name: spa, spec: { displayName: SPA, clientType: public, redirectUris: ["http://127.0.0.1/callback"] } }
              - { kind: application, name: keyed, spec: { displayName: Keyed, clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://k.example/jwks" } }
              - { kind: application, name: shared, readOnly: true, spec: { displayName: Shared } }
              - { kind: role, name: ops, spec: { permissions: [] } }
            """.trimIndent(),
        )
        assertThat(file.resources.map { it.effectiveSecretSink }).containsOnlyNulls()
        val plan = engine().plan(file, false)
        assertThat(plan.changes.mapNotNull { it.secretSink }).isEmpty()
        assertThat(plan.customerManaged).isZero()
    }

    @Test
    fun `the file refuses a customerManaged sink with members, on a public client, on a secret-less client and on a read-only reference`() {
        val violations = assertThatThrownBy {
            parse(
                """
                apiVersion: thoryn.io/provision/v1
                resources:
                  - { kind: application, name: a, spec: { displayName: a }, secretSink: { kind: customerManaged, trust: pods } }
                  - { kind: application, name: b, spec: { displayName: b, clientType: public }, secretSink: { kind: customerManaged } }
                  - { kind: application, name: c, spec: { displayName: c, clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://k.example/jwks" }, secretSink: { kind: customerManaged } }
                  - { kind: application, name: d, readOnly: true, spec: { displayName: d }, secretSink: { kind: customerManaged } }
                  - { kind: environment, name: e, spec: { slug: e-sbx }, secretSink: { kind: customerManaged } }
                """.trimIndent(),
            )
        }.isInstanceOf(ProvisionException::class.java)
        violations.hasMessageContaining("resources[0] secretSink has unknown property 'trust'")
            .hasMessageContaining("resources[1] secretSink on a public client")
            .hasMessageContaining("resources[2] ${ProvisionFile.ERR_SECRET_SINK_WITHOUT_SECRET}")
            .hasMessageContaining("resources[3] a read-only reference cannot carry 'secretSink'")
            .hasMessageContaining("resources[4] secretSink is only supported on kind application")
    }

    @Test
    fun `the schema's customerManaged branch is exactly the kind, and the closed kind set carries it`() {
        val schema = YAMLMapper.builder().build().readTree(ProvisionFile::class.java.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE))
        val branches = schema["\$defs"]["resource"]["properties"][ProvisionFile.SECRET_SINK]["oneOf"].toList().associateBy { it["properties"]["kind"]["const"].asString() }
        assertThat(branches.keys).isEqualTo(ProvisionFile.SECRET_SINK_KINDS).contains("customerManaged")
        val branch = branches.getValue(ProvisionFile.SECRET_SINK_KIND_CUSTOMER_MANAGED)
        assertThat(branch["additionalProperties"].asBoolean()).isFalse()
        assertThat(branch["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.SECRET_SINK_CUSTOMER_MANAGED_KEYS)
        assertThat(branch["properties"].propertyNames().toList()).containsExactly("kind")
    }

    @Test
    fun `the CLI's plan prints the customer-managed line and summary, in the table and in json`() {
        val f = File(tempHome.toFile(), ".thoryn/provision.yaml").also { it.parentFile.mkdirs(); it.writeText(yaml()) }
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out)
            .contains("application  forge-login  create")
            .contains("application forge-login: secret: managed by the customer (apply discards the minted value; a person mints it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and stores it in your secret manager")
            .contains("1 client secret(s) managed by the customer")
            .doesNotContain("to deliver").doesNotContain("pulled at runtime").doesNotContain("shown once")
        assertThat(plan.err).doesNotContain("DEPRECATED")
        val json = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl(), "--output", "json")
        assertThat(json.out).contains("\"kind\" : \"customerManaged\"").contains("\"customerManaged\" : 1").contains("\"deliver\" : 0").contains("\"pull\" : 0")
            .contains("\"warnings\" : [ ]")
    }
}
