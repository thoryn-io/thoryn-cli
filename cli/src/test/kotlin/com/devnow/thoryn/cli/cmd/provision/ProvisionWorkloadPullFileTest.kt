package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.SecretTarget
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3921 — `secretSink: { kind: workloadPull, trust }` in the provisioning FILE: it parses to a [SecretTarget] that
 * delivers nowhere, is exactly `{ kind, trust }` with a resource-name `trust`, rides the generic sink rules (application
 * only, never a public client or a read-only reference), and — when the trust is declared in the same file — that trust
 * must be on the application's plane, a `kubernetes` trust, and carry `tenant:applications.write`. The schema's branch
 * pins the same members and grammar.
 */
class ProvisionWorkloadPullFileTest {

    private val yaml = YAMLMapper.builder().build()

    private fun doc(resources: String) = "apiVersion: thoryn.io/provision/v1\nresources:\n" + resources.trimIndent().prependIndent("  ")

    @Test
    fun `a workloadPull sink parses to a target that delivers nowhere and names its trust`() {
        val parsed = ProvisionFile.parse(
            doc(
                """
                - { kind: environment, name: sandbox, spec: { slug: forge-sandbox } }
                - { kind: workloadIdentityTrust, name: forge-pods, environment: sandbox, spec: { provider: kubernetes, kubernetes: { issuer: "https://k8s.example", namespace: forge }, scopes: [tenant:applications.write] } }
                - { kind: application, name: forge-login, environment: sandbox, spec: { displayName: "Forge login" }, secretSink: { kind: workloadPull, trust: forge-pods } }
                """,
            ).toByteArray(),
            "provision.yaml",
        )
        val sink = parsed.resources.single { it.kind == ProvisionFile.KIND_APPLICATION }.secretSink!!
        assertThat(sink).isEqualTo(SecretTarget(kind = ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL, trust = "forge-pods"))
        assertThat(sink.runtimePull).isTrue()
        assertThat(sink.label).isEqualTo("workloadPull by trust forge-pods")
        assertThat(sink.toStructured()).isEqualTo(mapOf("kind" to "workloadPull", "trust" to "forge-pods"))
        // The two delivering kinds are not runtime pulls.
        assertThat(SecretTarget(kind = "file", path = "x").runtimePull).isFalse()
    }

    @Test
    fun `a malformed workloadPull target, a public client and a read-only reference are rejected`() {
        val v = ProvisionFile.validate(
            yaml.readTree(
                doc(
                    """
                    - { kind: application, name: a, spec: { displayName: a }, secretSink: { kind: workloadPull } }
                    - { kind: application, name: b, spec: { displayName: b }, secretSink: { kind: workloadPull, trust: "Forge_Pods" } }
                    - { kind: application, name: c, spec: { displayName: c }, secretSink: { kind: workloadPull, trust: forge-pods, namespace: forge } }
                    - { kind: application, name: d, spec: { displayName: d, clientType: public }, secretSink: { kind: workloadPull, trust: forge-pods } }
                    - { kind: application, name: e, readOnly: true, spec: { displayName: e }, secretSink: { kind: workloadPull, trust: forge-pods } }
                    - { kind: application, name: f, spec: { displayName: f, clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://f.example/jwks" }, secretSink: { kind: workloadPull, trust: forge-pods } }
                    """,
                ),
            ),
        )
        assertThat(v).anyMatch { it.contains("resources[0] secretSink trust is required") }
        assertThat(v).anyMatch { it.contains("resources[1] secretSink trust 'Forge_Pods' must be the NAME of a workloadIdentityTrust") }
        assertThat(v).anyMatch { it.contains("resources[2] secretSink has unknown property 'namespace'") }
        assertThat(v).anyMatch { it.contains("resources[3] secretSink on a public client") }
        assertThat(v).anyMatch { it.contains("resources[4]") && it.contains("read-only reference cannot carry 'secretSink'") }
        assertThat(v).anyMatch { it.contains("resources[5]") && it.contains(ProvisionFile.ERR_SECRET_SINK_WITHOUT_SECRET) }
    }

    @Test
    fun `a trust declared in the file must be on the application's plane, a kubernetes trust, and carry the rotate scope`() {
        val v = ProvisionFile.validate(
            yaml.readTree(
                doc(
                    """
                    - { kind: environment, name: sandbox, spec: { slug: forge-sandbox } }
                    - { kind: workloadIdentityTrust, name: pods-prod, spec: { provider: kubernetes, kubernetes: { issuer: "https://k8s.example", namespace: forge, serviceAccount: proxy }, scopes: [tenant:applications.write], confirmProduction: true } }
                    - { kind: workloadIdentityTrust, name: ci-job, environment: sandbox, spec: { provider: github_actions, github: { repository: acme/forge }, scopes: [tenant:applications.write] } }
                    - { kind: workloadIdentityTrust, name: pods-ro, environment: sandbox, spec: { provider: kubernetes, kubernetes: { issuer: "https://k8s.example", namespace: forge }, scopes: [tenant:applications.read] } }
                    - { kind: workloadIdentityTrust, name: pods-ok, environment: sandbox, spec: { provider: kubernetes, kubernetes: { issuer: "https://k8s.example", namespace: forge }, scopes: [tenant:applications.write] } }
                    - { kind: application, name: other-plane, environment: sandbox, spec: { displayName: a }, secretSink: { kind: workloadPull, trust: pods-prod } }
                    - { kind: application, name: not-k8s, environment: sandbox, spec: { displayName: b }, secretSink: { kind: workloadPull, trust: ci-job } }
                    - { kind: application, name: no-scope, environment: sandbox, spec: { displayName: c }, secretSink: { kind: workloadPull, trust: pods-ro } }
                    - { kind: application, name: fine, environment: sandbox, spec: { displayName: d }, secretSink: { kind: workloadPull, trust: pods-ok } }
                    - { kind: application, name: live-only, environment: sandbox, spec: { displayName: e }, secretSink: { kind: workloadPull, trust: not-in-this-file } }
                    """,
                ),
            ),
        )
        assertThat(v).anyMatch { it.startsWith("resources[5] secretSink: ${ProvisionFile.ERR_WORKLOAD_PULL_TRUST_OTHER_PLANE}") && it.contains("the production plane") }
        assertThat(v).anyMatch { it.startsWith("resources[6] secretSink: ${ProvisionFile.ERR_WORKLOAD_PULL_TRUST_PROVIDER}") && it.contains("'github_actions'") }
        assertThat(v).anyMatch { it.startsWith("resources[7] secretSink: ${ProvisionFile.ERR_WORKLOAD_PULL_SCOPE_MISSING}") }
        // A well-formed trust, and a trust that is only live (the plan checks that one), raise nothing.
        assertThat(v).noneMatch { it.startsWith("resources[8]") || it.startsWith("resources[9]") }
        assertThat(v).hasSize(3)
    }

    @Test
    fun `the schema's workloadPull branch is exactly kind and trust, with the resource-name grammar`() {
        val schema = YAMLMapper.builder().build().readTree(ProvisionFile::class.java.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE))
        val branch = schema["\$defs"]["resource"]["properties"][ProvisionFile.SECRET_SINK]["oneOf"].toList()
            .single { it["properties"]["kind"]["const"].asString() == ProvisionFile.SECRET_SINK_KIND_WORKLOAD_PULL }
        assertThat(branch["additionalProperties"].asBoolean()).isFalse()
        assertThat(branch["required"].toList().map { it.asString() }.toSet()).isEqualTo(ProvisionFile.SECRET_SINK_WORKLOAD_PULL_KEYS)
        assertThat(branch["properties"]["trust"]["pattern"].asString()).isEqualTo(ProvisionFile.NAME_PATTERN.pattern)
    }
}
