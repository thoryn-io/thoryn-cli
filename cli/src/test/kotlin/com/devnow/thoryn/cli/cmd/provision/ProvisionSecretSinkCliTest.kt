package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.SecretIo
import com.devnow.thoryn.provision.ProvisionReceiptStore
import com.devnow.thoryn.provision.SecretTarget
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-3659 (ADR 2026-10-13 converge §5) — `secretSink:` end to end through `thoryn provision`: `plan` prints
 * where the secret will land and mints nothing; `apply` delivers a `kubernetesSecret` through a (fake) `kubectl`
 * with the value on stdin and NEVER on argv, never creating the namespace; a `file` sink is written owner-only
 * and not overwritten without `--force`; an unreachable sink falls back to `--secret-file`, and with nothing to
 * fall back to the client stays recorded and `apply` exits non-zero with `undelivered_secrets` and the recovery.
 */
class ProvisionSecretSinkCliTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val kubectl = FakeKubectl()

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        ProvisionCommand.kubectlRunner = { kubectl }
    }

    private fun writeFile(body: String): File =
        File(tempHome.toFile(), ".thoryn/provision.yaml").also { it.parentFile.mkdirs(); it.writeText(body) }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private fun k8sFile(): File = writeFile(
        """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-login
            spec:
              displayName: "Forge login"
              grantTypes: ["authorization_code"]
              redirectUris: ["https://forge.example/oauth2/callback"]
            secretSink:
              kind: kubernetesSecret
              namespace: forge
              name: forge-login
              key: client-secret
        """.trimIndent(),
    )

    private fun minted(): String = api.mintedSecrets.values.single()

    @Test
    fun `plan prints the intended delivery and reaches neither the API writes nor kubectl`() {
        val f = k8sFile()
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out)
            .contains("application  forge-login  create")
            .contains("a client secret will be minted and delivered to kubernetesSecret forge/forge-login key client-secret")
            .contains("application forge-login: deliver client secret → kubernetesSecret forge/forge-login key client-secret")
            .contains("1 client secret(s) to deliver")
        assertThat(api.writes).isEmpty()
        assertThat(api.mintedSecrets).isEmpty()
        assertThat(kubectl.calls).isEmpty()

        val json = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl(), "--output", "json")
        assertThat(json.exit).isEqualTo(0)
        assertThat(json.out).contains("\"secretSink\"").contains("\"namespace\" : \"forge\"").contains("\"deliver\" : 1")
    }

    @Test
    fun `apply writes the Kubernetes Secret through kubectl with the value on stdin, never on argv, and never creates the namespace`() {
        val f = k8sFile()
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).doesNotContain("could not deliver").doesNotContain("undelivered_secrets")
        assertThat(apply.exit).isEqualTo(0)
        val id = api.applications.single()["clientId"].toString()
        val secret = minted()
        // The cluster holds the value under the declared key …
        assertThat(kubectl.secrets).containsOnlyKeys("forge/forge-login")
        assertThat(kubectl.secrets.getValue("forge/forge-login")).containsExactly(java.util.Map.entry("client-secret", secret))
        // … the invocations are exactly the install-forge pattern, in order …
        assertThat(kubectl.invocations).containsExactly(
            "kubectl version --client",
            "kubectl get namespace forge -o name",
            "kubectl -n forge create secret generic forge-login --from-file=client-secret=/dev/stdin --dry-run=client -o yaml",
            "kubectl -n forge apply -f -",
        )
        // … the value was on the render's stdin and NOWHERE on argv …
        assertThat(kubectl.calls[2].second?.toString(Charsets.UTF_8)).isEqualTo(secret)
        assertThat(kubectl.allArgs).noneMatch { it.contains(secret) }
        // … and it never reached the console or the receipt.
        assertThat(apply.out).doesNotContain(secret).contains("client secret delivered → kubernetesSecret forge/forge-login key client-secret").contains("Applied. 1 resource(s) owned.")
        val receiptFile = File(f.parentFile, "provision.receipt.json")
        assertThat(receiptFile.readText()).doesNotContain(secret).contains(id)

        // A re-apply mints nothing and touches kubectl for nothing: a secret exists only on create.
        api.reset(); kubectl.calls.clear()
        val again = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(again.exit).isEqualTo(0)
        assertThat(api.writes).isEmpty()
        assertThat(kubectl.calls).isEmpty()
    }

    @Test
    fun `a missing namespace is a reason — the namespace is never created, the client is recorded, the exit is undelivered_secrets with the recovery`() {
        val f = k8sFile()
        kubectl.namespaces.clear()
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        val id = api.applications.single()["clientId"].toString()
        assertThat(apply.exit).isEqualTo(SecretIo.EXIT_NO_SECRET).isNotEqualTo(0)
        // The client exists and the receipt records it …
        assertThat(apply.out).contains("Applied. 1 resource(s) owned.")
        assertThat(ProvisionReceiptStore().read(File(f.parentFile, "provision.receipt.json"))!!.resources.single().id).isEqualTo(id)
        // … nothing was written to the cluster, and no namespace was created …
        assertThat(kubectl.secrets).isEmpty()
        assertThat(kubectl.invocations).noneMatch { it.contains("create namespace") }.noneMatch { it.contains("apply") }
        // … the error names the code, the resource, the sink, the reason and the recovery — never the value.
        assertThat(apply.err)
            .contains("could not deliver its client secret to kubernetesSecret forge/forge-login key client-secret (namespace 'forge' is not reachable")
            .contains("thoryn never creates a namespace")
            .contains("Error: undelivered_secrets")
            .contains("application/forge-login (clientId $id) → kubernetesSecret forge/forge-login key client-secret")
            .contains("mint a new secret by hand: thoryn clients rotate-secret $id --secret-file <path>")
            .doesNotContain("Apply stopped")
            .doesNotContain(minted())
        assertThat(apply.out).doesNotContain(minted())
    }

    @Test
    fun `an unreachable sink falls back to --secret-file, which then holds the value and the exit is zero`() {
        val f = k8sFile()
        kubectl.installed = false
        val fallback = File(tempHome.toFile(), "fallback.secret")
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes", "--secret-file", fallback.path)
        assertThat(apply.exit).isEqualTo(0)
        assertThat(fallback.readText().trim()).isEqualTo(minted())
        assertThat(apply.err).contains("kubectl is not installed or not on PATH").contains("written to").doesNotContain("undelivered_secrets").doesNotContain(minted())
        assertThat(apply.out).doesNotContain(minted())
    }

    @Test
    fun `a failed kubectl apply is a redacted reason, not a stopped apply`() {
        val f = k8sFile()
        kubectl.failApplyWith = "error: secrets \"forge-login\" is forbidden: User \"ci\" cannot patch resource \"secrets\" in API group \"\" in the namespace \"forge\""
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(api.applications).hasSize(1)
        assertThat(apply.err).contains("could not apply Secret forge/forge-login (error: secrets \"forge-login\" is forbidden").doesNotContain(minted())
        assertThat(CliDeclaredSecretSink.redact("value=${minted()} b64=${java.util.Base64.getEncoder().encodeToString(minted().toByteArray())}", minted()))
            .isEqualTo("value=[redacted] b64=[redacted]")
    }

    @Test
    fun `a file sink is written owner-only and is not overwritten without --force`() {
        val target = File(tempHome.toFile(), "secrets/forge-login.secret")
        val f = writeFile(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-login
                spec: { displayName: "Forge login", clientType: confidential, grantTypes: [client_credentials] }
                secretSink: { kind: file, path: "${target.path}" }
            """.trimIndent(),
        )
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).isEqualTo(0)
        assertThat(apply.err).doesNotContain("could not deliver").doesNotContain("undelivered_secrets")
        assertThat(target.readText().trim()).isEqualTo(minted())
        assertThat(Files.getPosixFilePermissions(target.toPath())).containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        assertThat(apply.out).contains("client secret delivered → file ${target.path}").doesNotContain(minted())
        assertThat(kubectl.calls).isEmpty()

        // The client is deleted out of band and re-created: the file is already there, so without --force the new
        // secret is NOT written over it — and with no fallback the exit says so.
        val first = minted()
        api.applications.clear(); api.reset(); api.mintedSecrets.clear()
        val refused = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(refused.exit).isEqualTo(SecretIo.EXIT_NO_SECRET)
        assertThat(target.readText().trim()).isEqualTo(first) // untouched
        assertThat(refused.err).contains("already exists — re-run with --force to overwrite it").contains("undelivered_secrets").doesNotContain(minted())

        // Recovery for the file sink is the same rotate-secret; but a fresh create WITH --force overwrites.
        api.applications.clear(); api.reset(); api.mintedSecrets.clear()
        val forced = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes", "--force")
        assertThat(forced.exit).isEqualTo(0)
        assertThat(target.readText().trim()).isEqualTo(minted()).isNotEqualTo(first)
    }

    @Test
    fun `the sink unit — unsupported kind and missing members answer reasons, never throw`() {
        val sink = CliDeclaredSecretSink(kubectl)
        assertThat(sink.deliver(SecretTarget("vaultKv", path = "x"), "c", "s")).contains("unsupported secretSink kind 'vaultKv'")
        assertThat(sink.deliver(SecretTarget("kubernetesSecret", namespace = null, name = "n", key = "k"), "c", "s")).isEqualTo("secretSink has no namespace")
        assertThat(sink.deliver(SecretTarget("file", path = null), "c", "s")).isEqualTo("secretSink has no path")
        assertThat(kubectl.calls).isEmpty()
    }
}
