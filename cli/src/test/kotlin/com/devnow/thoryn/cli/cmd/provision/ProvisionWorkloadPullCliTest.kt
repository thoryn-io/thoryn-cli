package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.SecretIo
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3921 — `thoryn provision` with `secretSink: { kind: workloadPull }`, run the way the reusable provisioning workflow
 * runs it: no `--secret-file`, no TTY, no kubeconfig. `plan` says who pulls the secret; `apply` creating the confidential
 * application exits 0 (where the same file without the sink is `undelivered_secrets`, exit 65), never runs `kubectl`, and
 * the minted value reaches neither stdout nor stderr.
 */
class ProvisionWorkloadPullCliTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val kubectl = FakeKubectl()

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        ProvisionCommand.kubectlRunner = { kubectl }
        api.seedTrust(
            null, "forge-pods", "kubernetes", listOf("tenant:applications.read", "tenant:applications.write"),
            mapOf("issuer" to "https://kubernetes.default.svc.cluster.local", "namespace" to "forge", "serviceAccount" to "forge-oauth2-proxy"),
        )
    }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private val wi: String get() = api.trusts.single()["clientId"].toString()

    private fun writeFile(sink: String): File = File(tempHome.toFile(), ".thoryn/provision.yaml").also {
        it.parentFile.mkdirs()
        it.writeText(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-login
                spec:
                  displayName: "Forge login"
                  grantTypes: ["authorization_code"]
                  redirectUris: ["https://forge.example/oauth2/callback"]
            """.trimIndent() + sink,
        )
    }

    private val pull = "\n    secretSink: { kind: workloadPull, trust: forge-pods }\n"

    @Test
    fun `plan prints who pulls the secret at runtime and writes nothing`() {
        val f = writeFile(pull)
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out)
            .contains("application  forge-login  create")
            .contains("application forge-login: secret: pulled at runtime by trust forge-pods (workload client $wi; apply discards the minted value)")
            .contains("application forge-login: grant + client:$wi manager")
            .contains("1 client secret(s) pulled at runtime")
            .doesNotContain("to deliver")
        assertThat(api.writes).isEmpty()

        val json = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl(), "--output", "json")
        assertThat(json.out).contains("\"kind\" : \"workloadPull\"").contains("\"workloadClientId\" : \"$wi\"").contains("\"pull\" : 1").contains("\"deliver\" : 0")
    }

    @Test
    fun `a CI apply with no secret channel creates the application and exits 0 — the same file without the sink exits 65`() {
        // The control: no sink, no --secret-file, no TTY ⇒ the secret is minted and lost, apply is red.
        val bare = runCli("provision", "apply", "--file", writeFile("\n").path, "--gateway", baseUrl(), "--yes")
        assertThat(bare.exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(bare.err).contains("undelivered_secrets")
        api.applications.clear(); api.mintedSecrets.clear(); api.grants.clear()

        val apply = runCli("provision", "apply", "--file", writeFile(pull).path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).isEqualTo(0)
        val id = api.applications.single()["clientId"].toString()
        val secret = api.mintedSecrets.getValue(id)
        assertThat(apply.err).doesNotContain("undelivered_secrets").doesNotContain(secret)
        assertThat(apply.out).doesNotContain(secret)
            .contains("client secret discarded (never shown or stored) — pulled at runtime by the pods of trust forge-pods")
            .contains("Applied. 1 resource(s) converged")
        assertThat(kubectl.calls).isEmpty()
        assertThat(api.grantsOn("application:$id")).contains("client:$wi manager")
    }
}
