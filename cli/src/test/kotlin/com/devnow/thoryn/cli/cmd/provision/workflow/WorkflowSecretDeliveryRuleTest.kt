package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * SSO-3921 / SSO-3954 — `config.secret-delivery`: the reusable workflow's apply job has no kubeconfig, no `--secret-file` and
 * no TTY. Since SSO-3954 a configured provisioning file whose application MINTS a secret on create PASSES with no sink (the
 * customer manages the secret — the default) or with `secretSink: { kind: customerManaged }`, and the rule's detail is the
 * notice that explains it. A `kubernetesSecret` sink and a `file` sink each still fail naming the application and the fix
 * (which now says: drop the sink); a `workloadPull` sink passes but is reported deprecated; a public or secret-less client
 * and a read-only reference pass silently; a file that does not load fails as not checked (SSO-3970) — never a silent skip.
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
    fun `a minting application without a sink passes — the customer manages its secret — and the notice says what apply does`() {
        val r = check(app("forge-login"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail)
            .contains(".thoryn/provision.yaml application forge-login: its client secret is managed by the customer (no secretSink — the default) — apply discards the create's value; a person mints it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and stores it in your secret manager")
            .doesNotContain("exit 65").doesNotContain("undelivered")
        assertThat(r.fix).isNull()
    }

    @Test
    fun `an explicit customerManaged sink passes with the same notice, naming the declaration`() {
        val r = check(app("forge-login", extra = ", secretSink: { kind: customerManaged }"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains("application forge-login: its client secret is managed by the customer (secretSink customerManaged)")
    }

    @Test
    fun `a kubernetesSecret sink and a file sink fail — no cluster to reach, and a runner that is gone — and the fix is to drop the sink`() {
        val r = check(
            app("k8s", extra = ", secretSink: { kind: kubernetesSecret, namespace: forge, name: login, key: client-secret }") + "\n" +
                app("onfile", extra = ", secretSink: { kind: file, path: .secrets/login }"),
        )!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).contains("application k8s delivers its secret to kubernetesSecret forge/login key client-secret — the apply job's runner has no kubeconfig")
            .contains("application onfile delivers its secret to file .secrets/login — the file lands on the runner and is gone when the job ends")
        assertThat(r.fix).contains("drop the `secretSink:` — the default is `customerManaged`").contains("private_key_jwt").doesNotContain("workloadPull")
    }

    @Test
    fun `a workloadPull sink passes but is reported deprecated, naming SSO-3951 and SSO-3953`() {
        val r = check(app("pulled", extra = ", secretSink: { kind: workloadPull, trust: forge-pods }"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains("application pulled: secretSink workloadPull is DEPRECATED (product-owner decision SSO-3951").contains("SSO-3953 removes it").contains("the default is customerManaged")
    }

    @Test
    fun `a public client, a secret-less client and a read-only reference mint nothing and pass without a notice`() {
        val r = check(
            listOf(
                app("spa", spec = ", clientType: public"),
                app("keyed", spec = ", clientAuthenticationMethods: [private_key_jwt], jwksUri: \"https://k.example/jwks\""),
                "- { kind: application, name: shared, readOnly: true, spec: { displayName: shared } }",
            ).joinToString("\n"),
        )!!
        assertThat(r.status).withFailMessage("%s", r.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).isEqualTo("no application in the configured file(s) is minted a secret the job would have to deliver")
    }

    @Test
    fun `a file that does not load fails this rule as not checked — it is never skipped (SSO-3970)`() {
        val r = check("- { kind: nonsense }")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).isEqualTo("not checked: .thoryn/provision.yaml could not be loaded (see config.valid)")
        assertThat(r.fix).isEqualTo("make config.valid pass, then run the check again")
    }
}
