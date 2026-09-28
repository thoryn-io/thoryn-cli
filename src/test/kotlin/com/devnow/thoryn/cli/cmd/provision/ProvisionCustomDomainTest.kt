package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3413 / SSO-3414 — the `customDomain` provision kind against an in-memory product-api
 * ([FakeProductApi]'s custom-domain state machine, mounted on MockWebServer): the plan shows the DNS
 * records to publish in the stable `{type, name, value, ttl}` shape, apply claims and verifies, a re-run
 * converges and is idempotent, a missing entitlement names the OPERATOR step, a missing grant names the
 * grant, a suspended domain shows its release time, and only `--prune` (with `--confirm`) releases it.
 */
class ProvisionCustomDomainTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        env = { null },
        workspaceId = WORKSPACE_ID,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private val domainFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: customDomain
            spec: { host: auth.acme.com }
    """

    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?, prune: Boolean = false, confirm: String? = null): ProvisionReceipt {
        val e = engine()
        return e.apply(f, receipt, e.plan(f, receipt, prune), "acme", confirm) {}
    }

    @Suppress("UNCHECKED_CAST")
    private fun records(plan: ProvisionPlan): List<Map<String, Any?>> =
        ((plan.toStructured()["changes"] as List<Map<String, Any?>>).single()["customDomain"] as Map<String, Any?>)["records"] as List<Map<String, Any?>>

    // ── plan ─────────────────────────────────────────────────────────────────

    @Test
    fun `plan of an unclaimed domain is a create that shows the CNAME to publish in the stable record shape`() {
        val plan = engine().plan(file(domainFile), null, prune = false)

        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.reason).contains("claim auth.acme.com")
        assertThat(records(plan)).containsExactly(
            mapOf("type" to "CNAME", "name" to "auth.acme.com", "value" to "acme.auth.thoryn.io", "ttl" to 300),
        )
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `plan of a pending claim shows both records with their TTL and the issuer in use`() {
        api.domainHost = "auth.acme.com"; api.domainState = "PENDING"

        val plan = engine().plan(file(domainFile), null, prune = false)

        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        assertThat(records(plan).map { it.keys }).allSatisfy { assertThat(it).containsExactly("type", "name", "value", "ttl") }
        assertThat(records(plan).map { it["type"] }).containsExactly("TXT", "CNAME")
        assertThat(records(plan).first()["value"]).isEqualTo("thoryn-verify=tok-auth.acme.com")
        @Suppress("UNCHECKED_CAST")
        val details = (plan.toStructured()["changes"] as List<Map<String, Any?>>).single()["customDomain"] as Map<String, Any?>
        assertThat(details).containsEntry("state", "PENDING").containsEntry("issuer", "https://acme.auth.thoryn.io")
    }

    @Test
    fun `a record from a product-api that sends no ttl still carries the recommended ttl`() {
        api.domainHost = "auth.acme.com"; api.domainState = "PENDING"; api.domainTtl = null

        assertThat(records(engine().plan(file(domainFile), null, prune = false)).map { it["ttl"] }).containsOnly(300)
    }

    @Test
    fun `plan of a suspended domain names its release time`() {
        api.domainHost = "auth.acme.com"; api.domainState = "SUSPENDED"; api.domainReleaseAt = "2026-10-27T03:00:00Z"

        val change = engine().plan(file(domainFile), null, prune = false).changes.single()

        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.reason).contains("SUSPENDED").contains("released at 2026-10-27T03:00:00Z")
        assertThat(change.customDomain).containsEntry("releaseAt", "2026-10-27T03:00:00Z")
    }

    // ── apply ────────────────────────────────────────────────────────────────

    @Test
    fun `apply claims and verifies, and a re-run with the records published converges then issues no writes`() {
        // DNS not published yet: the claim succeeds, the verify reports the reason — not an apply failure.
        val first = apply(file(domainFile), null)
        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly("PUT /api/v1/custom-domain", "POST /api/v1/custom-domain/verify")
        assertThat(api.writes.first().body).containsEntry("domain", "auth.acme.com").containsEntry("acceptReSignIn", false)
        val owned = first.resources.single()
        assertThat(owned.key).isEqualTo("customDomain/customDomain")
        assertThat(owned.id).isEqualTo(WORKSPACE_ID)
        assertThat(owned.attributes).containsEntry("host", "auth.acme.com").containsEntry("state", "PENDING")
        assertThat(console.toString()).contains("_thoryn-verify.auth.acme.com").contains("TXT ownership record")

        // Records published: the re-run verifies (an update) and the domain is VERIFIED.
        api.dnsPublished = true; api.reset()
        val second = apply(file(domainFile), first)
        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly("POST /api/v1/custom-domain/verify")
        assertThat(second.resources.single().attributes).containsEntry("state", "VERIFIED")

        // Converged: nothing left to do.
        api.reset()
        val plan = engine().plan(file(domainFile), second, prune = false)
        assertThat(plan.hasChanges).isFalse()
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(file(domainFile), second)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an existing verified domain that the file did not create is adopted and never released`() {
        api.domainHost = "auth.acme.com"; api.domainState = "ACTIVE"

        val receipt = apply(file(domainFile), null)
        assertThat(receipt.resources.single().adopted).isTrue()
        assertThat(api.writes).isEmpty()

        val empty = file("""
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: other
                spec: { slug: other }
        """)
        apply(empty, receipt, prune = true, confirm = "acme")
        assertThat(api.writesTo("/api/v1/custom-domain")).isEmpty()
        assertThat(api.domainHost).isEqualTo("auth.acme.com")
    }

    @Test
    fun `acceptReSignIn is forwarded, and without it a workspace with production users gets the flag named`() {
        api.productionUsers = true

        assertThatThrownBy { apply(file(domainFile), null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("acceptReSignIn: true")

        api.reset()
        apply(file("""
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: customDomain
                spec: { host: auth.acme.com, acceptReSignIn: true }
        """), null)
        assertThat(api.writes.first().body).containsEntry("acceptReSignIn", true)
    }

    @Test
    fun `a workspace without the entitlement is planned with the operator step named and apply stops there`() {
        api.domainEntitled = false

        val change = engine().plan(file(domainFile), null, prune = false).changes.single()
        assertThat(change.reason).contains("NOT ENTITLED").contains("thoryn operator custom-domain entitle")

        assertThatThrownBy { apply(file(domainFile), null) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("OPERATOR step")
            .hasMessageContaining("thoryn operator custom-domain entitle <workspace>")
        assertThat(api.domainHost).isNull()
    }

    @Test
    fun `an identity without the custom-domain grant is told which grant a workspace admin must make`() {
        api.domainReachable = false

        assertThatThrownBy { engine().plan(file(domainFile), null, prune = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("thoryn access grant client:<client-id> manager custom_domain:<workspace-id>")
            .hasMessageContaining("scopes alone are not enough")
    }

    @Test
    fun `another domain already on the workspace is refused rather than silently moving the issuer`() {
        api.domainHost = "login.acme.com"; api.domainState = "ACTIVE"

        assertThatThrownBy { engine().plan(file(domainFile), null, prune = false) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("already has the custom domain 'login.acme.com'")
            .hasMessageContaining("thoryn domain remove")
    }

    // ── release ──────────────────────────────────────────────────────────────

    @Test
    fun `dropping the resource releases the domain only with --prune, and --prune needs the workspace confirmation`() {
        api.dnsPublished = true
        val owned = apply(file(domainFile), null)
        val without = file("""
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: keep
                spec: { slug: keep }
        """)

        // No --prune: the domain is skipped and stays.
        val skip = engine().plan(without, owned, prune = false)
        assertThat(skip.changes.single { it.kind == "customDomain" }.action).isEqualTo(ChangeAction.SKIP)
        api.reset()
        apply(without, owned)
        assertThat(api.writesTo("/api/v1/custom-domain")).isEmpty()
        assertThat(api.domainHost).isEqualTo("auth.acme.com")

        // --prune without --confirm: refused (the custom domain is on the production plane).
        val prunePlan = engine().plan(without, owned, prune = true)
        assertThat(prunePlan.removesOnProductionPlane).isTrue()
        assertThatThrownBy { engine().apply(without, owned, prunePlan, "acme", null) {} }
            .hasMessageContaining("--confirm")

        // --prune --confirm: released.
        api.reset()
        apply(without, owned, prune = true, confirm = "acme")
        assertThat(api.writesTo("/api/v1/custom-domain").map { it.method }).containsExactly("DELETE")
        assertThat(api.domainHost).isNull()
    }

    // ── grants + validation ──────────────────────────────────────────────────

    @Test
    fun `a grants block on the custom domain targets custom_domain of the workspace id`() {
        api.seedApplication(null, "config-ci", clientId = "config-ci")
        api.dnsPublished = true

        apply(file("""
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: customDomain
                spec: { host: auth.acme.com }
                grants:
                  - { subject: "client:config-ci", relation: manager }
        """), null)

        assertThat(api.grantsOn("custom_domain:$WORKSPACE_ID")).containsExactly("client:config-ci manager")
    }

    @Test
    fun `a customDomain inside an environment, or with an unknown spec key, is rejected by validation`() {
        assertThatThrownBy {
            file("""
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: customDomain
                    environment: staging
                    spec: { host: auth.acme.com }
            """)
        }.hasMessageContaining("belongs to the workspace, not an environment")
        assertThatThrownBy {
            file("""
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: customDomain
                    spec: { host: auth.acme.com, cname: x }
            """)
        }.hasMessageContaining("unknown property 'cname'")
        assertThatThrownBy {
            file("""
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: customDomain
                    spec: { acceptReSignIn: true }
            """)
        }.hasMessageContaining("spec.host is required")
    }

    private companion object {
        const val WORKSPACE_ID = "5d0c1b8e-7f3a-4e21-9c6d-2b4a8e1f3c70"
    }
}
