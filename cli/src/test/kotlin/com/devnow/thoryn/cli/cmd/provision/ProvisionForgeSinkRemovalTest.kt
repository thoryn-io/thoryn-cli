package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3954 — the forge's way out of the pod pull (SSO-3952 → SSO-3954 → thoryn-cicd follow-up), on thoryn-cicd's own
 * file shapes (`src/test/resources/provision/forge/`): the file WITH the two `workloadPull` sinks and the two `kubernetes`
 * trusts still converges, with the deprecation printed; the file WITHOUT them (no sink ⇒ customer-managed) plans NOOP for
 * everything it keeps, and — with `prune` and `destroy` off — leaves the live trusts AND the `manager` grants the sinks
 * converged exactly where they are: a person removes those (`thoryn access revoke`, `thoryn workload-identity trusts
 * delete`). `thoryn provision workflow check` passes the trimmed file on `config.secret-delivery` (with the notice) and
 * on `config.trust-scopes`, including with a connection narrowed to `tenant:applications.*`, `tenant:access.read` and
 * the role scopes (the workload-identity scopes and `tenant:access.write` are only the sinks' and the trusts' need).
 */
class ProvisionForgeSinkRemovalTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val errors = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun fixture(name: String): String = WorkflowFixtures.loadResource("/provision/forge/$name")
    private val withPull = ProvisionFile.parse(fixture("provision-with-pull.yaml").toByteArray(), ".thoryn/provision.yaml")
    private val trimmed = ProvisionFile.parse(fixture("provision-customer-managed.yaml").toByteArray(), ".thoryn/provision.yaml")

    private fun engine(): ProvisionEngine = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(errors),
    )

    private fun wiOf(trust: String): String = api.trusts.single { it["name"] == trust }["clientId"].toString()

    @Test
    fun `the forge's file with the sinks still converges — trusts created, manager granted, secrets discarded, the deprecation printed twice`() {
        val e = engine()
        val plan = e.plan(withPull, false)
        assertThat(plan.hasErrors).withFailMessage("%s", plan.errors.map { it.reason }).isFalse()
        assertThat(plan.runtimePulls).isEqualTo(2)
        assertThat(plan.customerManaged).isZero()
        assertThat(plan.warnings).containsExactly(
            "application forge-oauth2-proxy: ${ProvisionFile.WORKLOAD_PULL_DEPRECATION}",
            "application forge-forgejo-login: ${ProvisionFile.WORKLOAD_PULL_DEPRECATION}",
        )
        assertThat(errors.toString()).contains("! application forge-oauth2-proxy: secretSink workloadPull is DEPRECATED (product-owner decision SSO-3951")
        e.apply(withPull, plan, "thoryn", null)
        assertThat(api.trusts.map { it["name"] }).containsExactlyInAnyOrder("forge-oauth2-proxy-pod", "forge-forgejo-login-pod")
        assertThat(api.grantsOn("application:forge-oauth2-proxy")).containsExactly("client:${wiOf("forge-oauth2-proxy-pod")} manager")
        assertThat(api.grantsOn("application:forge-forgejo-login")).containsExactly("client:${wiOf("forge-forgejo-login-pod")} manager")
        assertThat(e.undeliveredSecrets).isEmpty()
        assertThat(api.mintedSecrets).containsOnlyKeys("forge-oauth2-proxy", "forge-forgejo-login")
        api.mintedSecrets.values.forEach { assertThat(console.toString() + errors.toString()).doesNotContain(it) }
    }

    @Test
    fun `dropping the sinks and the trusts from the file changes nothing live — the trusts and their manager grants stay for a person to remove`() {
        val e = engine()
        e.apply(withPull, e.plan(withPull, false), "thoryn", null)
        val proxyWi = wiOf("forge-oauth2-proxy-pod")
        val forgejoWi = wiOf("forge-forgejo-login-pod")
        api.reset(); errors.reset()

        val plan = e.plan(trimmed, prune = false)
        assertThat(plan.hasErrors).withFailMessage("%s", plan.errors.map { it.reason }).isFalse()
        assertThat(plan.changes.map { it.key to it.action }).containsExactlyInAnyOrder(
            "application/forge-oauth2-proxy" to ChangeAction.NOOP, "application/forge-forgejo-login" to ChangeAction.NOOP, "role/forge-maintainer" to ChangeAction.NOOP,
        )
        // No sink line at all: nothing is minted for an existing client, and a dropped trust is not a row (prune is off).
        assertThat(plan.changes.mapNotNull { it.secretSink }).isEmpty()
        assertThat(plan.removes).isEmpty()
        // The file declares no `grants:`, so it manages no grants: nothing is read as undeclared, nothing is revoked.
        assertThat(plan.changes.flatMap { it.grantRemoves + it.grantUndeclared }).isEmpty()
        assertThat(plan.grantChanges).isZero()
        assertThat(plan.hasChanges).isFalse()
        assertThat(plan.warnings).isEmpty()

        e.apply(trimmed, plan, "thoryn", null)
        assertThat(api.writes).isEmpty()
        assertThat(api.trusts.map { it["name"] }).containsExactlyInAnyOrder("forge-oauth2-proxy-pod", "forge-forgejo-login-pod")
        assertThat(api.grantsOn("application:forge-oauth2-proxy")).containsExactly("client:$proxyWi manager")
        assertThat(api.grantsOn("application:forge-forgejo-login")).containsExactly("client:$forgejoWi manager")
        assertThat(errors.toString()).doesNotContain("DEPRECATED")
        // Even `--prune` revokes nothing on the applications: the file declares no `grants:`, so it manages none — the
        // manager relations the sinks converged are a person's to revoke, whichever way the file is applied.
        val pruning = e.plan(trimmed, prune = true)
        assertThat(pruning.changes.filter { it.resource != null }.flatMap { it.grantRemoves + it.grantUndeclared }).isEmpty()
        assertThat(pruning.grantChanges).isZero()
    }

    @Test
    fun `provision workflow check passes the trimmed forge file — the lint says the customer manages both secrets`() {
        val root = tempHome.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/provision.yaml").writeText(fixture("provision-customer-managed.yaml"))
        File(root, ".thoryn/connection.json").writeText(fixture("connection.json"))
        val report = WorkflowCheck.evaluate(WorkflowFixtures.STUB, ".github/workflows/thoryn-provisioning.yml", root = root)
        val delivery = report.rules.single { it.id == "config.secret-delivery" }
        assertThat(delivery.status).withFailMessage("%s", delivery.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(delivery.detail)
            .contains(".thoryn/provision.yaml application forge-oauth2-proxy: its client secret is managed by the customer (no secretSink — the default) — apply discards the create's value; a person mints it with `thoryn clients rotate-secret <clientId> --secret-file <path>`")
            .contains("application forge-forgejo-login: its client secret is managed by the customer")
            .doesNotContain("DEPRECATED")
        val scopes = report.rules.single { it.id == "config.trust-scopes" }
        assertThat(scopes.status).withFailMessage("%s", scopes.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(report.ok).withFailMessage("%s", report.rules.filter { it.failed }).isTrue()
    }

    @Test
    fun `the trimmed forge file needs neither workload-identity scope nor access write — the narrowed connection passes, and the file with the sinks fails on it`() {
        val root = tempHome.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/connection.json").writeText(fixture("connection-narrowed.json"))
        File(root, ".thoryn/provision.yaml").writeText(fixture("provision-customer-managed.yaml"))
        val trimmedRule = WorkflowCheck.evaluate(WorkflowFixtures.STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.single { it.id == "config.trust-scopes" }
        assertThat(trimmedRule.status).withFailMessage("%s", trimmedRule.detail).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(trimmedRule.detail).contains("needs to plan: tenant:applications.read tenant:access.read tenant:roles.read; to apply, also: tenant:applications.write tenant:roles.write")

        // The control: the same connection cannot plan or apply the file that still names the trusts.
        File(root, ".thoryn/provision.yaml").writeText(fixture("provision-with-pull.yaml"))
        val pullRule = WorkflowCheck.evaluate(WorkflowFixtures.STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.single { it.id == "config.trust-scopes" }
        assertThat(pullRule.status).isEqualTo(WorkflowCheck.Status.FAIL)
        assertThat(pullRule.detail).contains("needs tenant:workload-identity.read to PLAN").contains("needs tenant:access.write to APPLY").contains("needs tenant:workload-identity.write to APPLY")
    }

    @Test
    fun `provision workflow check still passes the forge file with the sinks, reporting the deprecation`() {
        val root = tempHome.toFile()
        File(root, ".thoryn").mkdirs()
        File(root, ".thoryn/provision.yaml").writeText(fixture("provision-with-pull.yaml"))
        File(root, ".thoryn/connection.json").writeText(fixture("connection.json"))
        val delivery = WorkflowCheck.evaluate(WorkflowFixtures.STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.single { it.id == "config.secret-delivery" }
        assertThat(delivery.status).isEqualTo(WorkflowCheck.Status.PASS)
        assertThat(delivery.detail)
            .contains("application forge-oauth2-proxy: secretSink workloadPull is DEPRECATED (product-owner decision SSO-3951")
            .contains("application forge-forgejo-login: secretSink workloadPull is DEPRECATED")
            .contains("SSO-3953 removes it")
    }
}
