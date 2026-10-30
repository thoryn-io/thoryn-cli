package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * SSO-3962 (ADR 2026-10-25 §1 "Identity", §3) — `config.trust-scopes` follows the PART of the file. An APPLICATION file
 * needs `tenant:applications.read` + `tenant:access.read` to plan and `tenant:applications.write` to apply, and nothing
 * else: the check says so, names what a declared mechanism of the application's own object adds on top, and FAILS a
 * connection that declares a scope the file never needs (an app project's identity wider than its file — the blur the
 * parts remove). A tenant file is judged on the union of its kinds' scopes, as before.
 */
class WorkflowTrustScopesPartRuleTest {

    @TempDir
    lateinit var tmp: Path

    private val wi = "wi_44fdc26790a3ae28113bd2b6"

    private fun check(apiVersion: String, provision: String, scopes: List<String>): WorkflowCheck.RuleResult? {
        val root = tmp.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/provision.yaml").writeText("apiVersion: $apiVersion\nresources:\n" + provision.trimIndent().prependIndent("  "))
        File(root, ".thoryn/connection.json").writeText(
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "acme" },
              "auth": {
                "method": "workload_identity",
                "clientId": "$wi",
                "audience": "https://acme.auth.stg.thoryn.org",
                "scopes": [${scopes.joinToString(", ") { "\"$it\"" }}],
                "github": { "repository": "acme/web", "environment": "production" }
              }
            }
            """.trimIndent(),
        )
        return WorkflowCheck.evaluate(STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.singleOrNull { it.id == "config.trust-scopes" }
    }

    private val app = """
        - kind: application
          name: web
          spec: { displayName: Web, clientType: public, grantTypes: [authorization_code], redirectUris: ["https://web.example/callback"] }
    """
    private val three = listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read")

    @Test
    fun `an application file with exactly the three scopes passes, and the verdict says nothing else is needed`() {
        val r = check("thoryn.io/application/v1", app, three)!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail)
            .contains(".thoryn/provision.yaml needs to plan: tenant:applications.read tenant:access.read; to apply, also: tenant:applications.write")
            .contains("declares every one and nothing the file does not need")
            .contains("An application file (thoryn.io/application/v1) needs tenant:applications.read + tenant:access.read to plan and tenant:applications.write to apply, and nothing else.")
    }

    @Test
    fun `an application file whose connection declares a tenant-defining scope fails — the identity is wider than its file`() {
        val r = check("thoryn.io/application/v1", app, three + "tenant:users.read" + "tenant:users.write")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains(".thoryn/connection.json declares tenant:users.read tenant:users.write, which .thoryn/provision.yaml (an application file, thoryn.io/application/v1) never needs")
            .contains("the identity of an app project is wider than its file")
            .contains("Narrow the trust (`thoryn workload-identity trusts set-scopes`")
        assertThat(r.fix).contains("a scope an application file never needs comes OFF the trust and the connection")
    }

    @Test
    fun `what an application's own mechanism adds is named beyond the baseline — and a connection carrying it is not wider`() {
        val sandboxApp = """
            - kind: application
              name: web
              environment: dev
              spec: { displayName: Web, clientType: public, grantTypes: [authorization_code], redirectUris: ["https://web.example/callback"] }
        """
        val r = check("thoryn.io/application/v1", sandboxApp, three + "tenant:environments.read")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains("and nothing else — this file also asks for tenant:environments.read (application/web (resolve environment 'dev' to its id for the ownership check))")
    }

    /**
     * SSO-4086 (oauthy ADR 2026-10-30-ephemeral-sandbox-test-identities §2) — the starter's application trust holds the two
     * sandbox TOOL scopes for its own e2e (`tenant:environments.read` for the test inbox, `tenant:test-identities.write` for a
     * disposable test account) that no declared resource asks for. They are expected on an application trust — a PASS that
     * names them — while `tenant:users.write` beside them is still the identity being wider than its file.
     */
    @Test
    fun `an application file whose connection holds the sandbox tool scopes passes, and the verdict names them as expected`() {
        val r = check("thoryn.io/application/v1", app, three + "tenant:environments.read" + "tenant:test-identities.write")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail)
            .contains("declares every one and nothing the file does not need")
            .contains("It also declares tenant:environments.read tenant:test-identities.write — sandbox tool scope(s) for the application's own tests")
            .doesNotContain("wider than its file")
        val wider = check("thoryn.io/application/v1", app, three + "tenant:test-identities.write" + "tenant:users.write")!!
        assertThat(wider.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(wider.detail).contains("declares tenant:users.write, which .thoryn/provision.yaml (an application file, thoryn.io/application/v1) never needs")
    }

    @Test
    fun `an application file missing one of the three fails as before, with the part's ceiling stated`() {
        val r = check("thoryn.io/application/v1", app, three - "tenant:applications.write")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail).contains("needs tenant:applications.write to APPLY (application/web (create, update or remove it))")
    }

    @Test
    fun `a tenant file is judged on its kinds' union — extra scopes on its connection are not a finding`() {
        val role = """
            - kind: role
              name: editor
              spec: { permissions: [docs:write] }
        """
        val r = check("thoryn.io/tenant/v1", role, listOf("tenant:roles.read", "tenant:roles.write", "tenant:users.write", "tenant:idp.write"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains("needs to plan: tenant:roles.read; to apply, also: tenant:roles.write").doesNotContain("wider than its file").doesNotContain("An application file")
    }
}
