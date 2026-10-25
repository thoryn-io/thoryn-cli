package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures.STUB
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * SSO-3926 — `config.trust-scopes`: `thoryn provision workflow check` derives the scopes each configured provisioning file
 * needs and holds them against its connection's `auth.scopes` and the trust's plan profile the connection implies. The
 * acceptance case is thoryn-cicd's: a file declaring a `workloadIdentityTrust` with a connection lacking
 * `tenant:workload-identity.read` fails here, naming that scope and the plan profile — not as a `403` mid-plan.
 */
class WorkflowTrustScopesRuleTest {

    @TempDir
    lateinit var tmp: Path

    private val wi = "wi_44fdc26790a3ae28113bd2b6"

    private fun check(provision: String, scopes: List<String>, connection: String? = null): WorkflowCheck.RuleResult? {
        val root = tmp.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/provision.yaml").writeText("apiVersion: thoryn.io/provision/v1\nresources:\n" + provision.trimIndent().prependIndent("  "))
        File(root, ".thoryn/connection.json").writeText(
            connection ?: """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "workload_identity",
                "clientId": "$wi",
                "audience": "https://thoryn.auth.stg.thoryn.org",
                "scopes": [${scopes.joinToString(", ") { "\"$it\"" }}],
                "github": { "repository": "thoryn-cicd", "environment": "forge" }
              }
            }
            """.trimIndent(),
        )
        return WorkflowCheck.evaluate(STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.singleOrNull { it.id == "config.trust-scopes" }
    }

    /** thoryn-cicd's file, as run 39917407017 planned it: two pulled applications and the pods' kubernetes trusts. */
    private val cicd = """
        - kind: application
          name: forge-oauth2-proxy
          spec: { clientId: forge-oauth2-proxy, displayName: Forge, clientType: confidential, grantTypes: [authorization_code], redirectUris: ["https://forge.example/oauth2/callback"] }
          secretSink: { kind: workloadPull, trust: forge-oauth2-proxy-pod }
        - kind: workloadIdentityTrust
          name: forge-oauth2-proxy-pod
          spec: { provider: kubernetes, kubernetes: { issuer: "https://kubernetes.default.svc.cluster.local", namespace: forge, serviceAccount: forge-oauth2-proxy }, scopes: [tenant:applications.write], confirmProduction: true }
    """

    private val full = listOf(
        "tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:access.write",
        "tenant:workload-identity.read", "tenant:workload-identity.write",
    )

    @Test
    fun `a declared trust with a connection lacking workload-identity read fails, naming the scope and the plan profile`() {
        val r = check(cicd, full - "tenant:workload-identity.read")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains(".thoryn/provision.yaml needs tenant:workload-identity.read to PLAN")
            .contains("workloadIdentityTrust/forge-oauth2-proxy-pod (read its live state)")
            .contains("application/forge-oauth2-proxy (resolve secretSink.trust 'forge-oauth2-proxy-pod' by name)")
            .contains("add tenant:workload-identity.read to the plan profile of trust $wi")
            .doesNotContain("tenant:access.write")
        assertThat(r.fix).contains("plan profile")
    }

    @Test
    fun `a workloadPull sink with a connection lacking access write fails as an APPLY scope on the trust's apply profile`() {
        val r = check(cicd, full - "tenant:access.write")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains("needs tenant:access.write to APPLY")
            .contains("grant the workload client of trust 'forge-oauth2-proxy-pod' manager on it (secretSink workloadPull)")
            .contains("add tenant:access.write to the scopes of trust $wi (its apply profile)")
            .doesNotContain("plan profile of trust")
    }

    @Test
    fun `a declared trust's scopes are the applying identity's ceiling, and the write scope of each kind is named`() {
        val r = check(cicd, full - "tenant:workload-identity.write" - "tenant:applications.write")!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains("needs tenant:workload-identity.write to APPLY (workloadIdentityTrust/forge-oauth2-proxy-pod (create, update or remove it))")
            .contains("needs tenant:applications.write to APPLY")
            .contains("the hub's scope ceiling: only an identity holding tenant:applications.write may create a trust carrying it")
    }

    @Test
    fun `a connection carrying every needed scope passes, listing what the plan profile must carry`() {
        val r = check(cicd, full)!!
        assertThat(r.status).withFailMessage("%s", r.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail)
            .contains("needs to plan: tenant:applications.read tenant:access.read tenant:workload-identity.read")
            .contains("the plan profile of trust $wi must carry the plan scopes")
    }

    @Test
    fun `a file of confidential applications whose secrets the customer manages needs applications read and write plus access read only`() {
        // SSO-3954 — no sink (the default) and an explicit customerManaged sink: no trust is named, no grant is converged.
        val apps = """
            - kind: application
              name: forge-oauth2-proxy
              spec: { clientId: forge-oauth2-proxy, displayName: Forge, clientType: confidential, grantTypes: [authorization_code], redirectUris: ["https://forge.example/oauth2/callback"] }
            - kind: application
              name: forge-forgejo-login
              spec: { clientId: forge-forgejo-login, displayName: Forgejo, grantTypes: [authorization_code], redirectUris: ["https://forge.example/user/oauth2/thoryn/callback"] }
              secretSink: { kind: customerManaged }
        """
        val r = check(apps, listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read"))!!
        assertThat(r.status).withFailMessage("%s", r.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(r.detail).contains("needs to plan: tenant:applications.read tenant:access.read; to apply, also: tenant:applications.write")
        // The control: without access read the ownership check cannot be asked; without applications write nothing can be created.
        assertThat(check(apps, listOf("tenant:applications.read", "tenant:applications.write"))!!.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(check(apps, listOf("tenant:applications.read", "tenant:access.read"))!!.detail).contains("needs tenant:applications.write to APPLY")
    }

    @Test
    fun `the deprecated clients alias satisfies applications, and a read-only reference needs no write scope`() {
        val r = check(
            "- { kind: application, name: shared, readOnly: true, spec: { clientId: shared, displayName: shared } }",
            listOf("tenant:clients.read", "tenant:access.read"),
        )!!
        assertThat(r.status).withFailMessage("%s", r.detail).isEqualTo(WorkflowCheck.Status.PASS)
    }

    @Test
    fun `a connection that does not load gets no verdict from this rule`() {
        assertThat(check(cicd, full, connection = "{}")).isNull()
    }

    /** SSO-3941 — a file declaring a `role` needs `tenant:roles.read` to plan and `tenant:roles.write` to apply. */
    private val withRole = """
        - kind: role
          name: forge-maintainer
          spec: { permissions: ["forge:maintain"] }
    """

    @Test
    fun `a declared role with a connection lacking roles read fails as a PLAN scope on the plan profile`() {
        val r = check(withRole, listOf("tenant:roles.write"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains(".thoryn/provision.yaml needs tenant:roles.read to PLAN (role/forge-maintainer (read its live state))")
            .contains("add tenant:roles.read to the plan profile of trust $wi")
            // a role is not a platform access object — no ownership check, so no tenant:access.read
            .doesNotContain("tenant:access.read")
    }

    @Test
    fun `a declared role with a connection lacking roles write fails as an APPLY scope, and passes with both`() {
        val r = check(withRole, listOf("tenant:roles.read"))!!
        assertThat(r.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(r.detail)
            .contains("needs tenant:roles.write to APPLY (role/forge-maintainer (create, update or remove it))")
            .contains("add tenant:roles.write to the scopes of trust $wi (its apply profile)")
        val ok = check(withRole, listOf("tenant:roles.read", "tenant:roles.write"))!!
        assertThat(ok.status).withFailMessage("%s", ok.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(ok.detail).contains("needs to plan: tenant:roles.read; to apply, also: tenant:roles.write")
    }
}
