package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * SSO-3921 — `config.secret-delivery`: the reusable workflow's apply job has no kubeconfig, no `--secret-file` and no TTY,
 * so a configured provisioning file whose application MINTS a secret on create passes only with
 * `secretSink: { kind: workloadPull }`. No sink, a `kubernetesSecret` sink and a `file` sink each fail naming the
 * application and the fix; a public or secret-less client, a read-only reference and a runtime pull pass; a file that does
 * not load is left to `provision plan` (no verdict from this rule).
 */
class WorkflowSecretDeliveryRuleTest {

    @TempDir
    lateinit var tmp: Path

    private fun check(provision: String): WorkflowCheck.RuleResult? {
        val root = tmp.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/provision.yaml").writeText("apiVersion: thoryn.io/provision/v1\nresources:\n" + provision.trimIndent().prependIndent("  "))
        File(root, ".thoryn/connection.json").writeText("{}")
        return WorkflowCheck.evaluate(STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.singleOrNull { it.id == "config.secret-delivery" }
    }

    private fun app(name: String, extra: String = "", spec: String = "") =
        "- { kind: application, name: $name, spec: { displayName: $name$spec }$extra }"

    @Test
    fun `a minting application without a sink fails — the CI apply would end in undelivered_secrets`() {
        val r = check(app("forge-login"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).contains("application forge-login mints a client secret on create and declares no secretSink").contains("exit 65")
        assertThat(r.fix).contains("secretSink: { kind: workloadPull, trust: <a kubernetes workloadIdentityTrust> }")
    }

    @Test
    fun `a kubernetesSecret sink and a file sink fail — no cluster to reach, and a runner that is gone`() {
        val r = check(
            app("k8s", extra = ", secretSink: { kind: kubernetesSecret, namespace: forge, name: login, key: client-secret }") + "\n" +
                app("onfile", extra = ", secretSink: { kind: file, path: .secrets/login }"),
        )!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).contains("application k8s delivers its secret to kubernetesSecret forge/login key client-secret — the apply job's runner has no kubeconfig")
            .contains("application onfile delivers its secret to file .secrets/login — the file lands on the runner and is gone when the job ends")
    }

    @Test
    fun `a runtime pull, a public client, a secret-less client and a read-only reference pass`() {
        val r = check(
            listOf(
                app("pulled", extra = ", secretSink: { kind: workloadPull, trust: forge-pods }"),
                app("spa", spec = ", clientType: public"),
                app("keyed", spec = ", clientAuthenticationMethods: [private_key_jwt], jwksUri: \"https://k.example/jwks\""),
                "- { kind: application, name: shared, readOnly: true, spec: { displayName: shared } }",
            ).joinToString("\n"),
        )!!
        assertThat(r.status).withFailMessage("%s", r.detail).isEqualTo(WorkflowCheck.Status.PASS)
    }

    @Test
    fun `a file that does not load gets no verdict from this rule`() {
        assertThat(check("- { kind: nonsense }")).isNull()
    }
}
