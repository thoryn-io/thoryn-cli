package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionReceipt
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3689 (ADR 2026-10-14 credential ladder rungs 1–2; ADR 2026-10-14 federated client authentication §11) — a
 * SECRET-LESS client in the engine: `clientAuthenticationMethods`, `jwksUri` / `jwks` and `federatedTrust` are sent on
 * create AND converged on update (the key location against the receipt — product-api's `ApplicationResponse` does not
 * render it); `federatedTrust` is a trust NAME resolved to the id in the client's own environment, with the trust
 * declared in the same file created FIRST; a missing or other-environment trust is `federated_trust_not_found`; no
 * secret is minted (or expected) for a `private_key_jwt` / `federated_assertion` client.
 */
class ProvisionSecretlessClientTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?): ProvisionReceipt {
        val e = engine()
        return e.apply(f, receipt, e.plan(f, receipt, false), "acme", null) {}
    }

    private val jwks = """{ keys: [ { kty: RSA, kid: k1, use: sig, alg: RS256, n: "n1", e: AQAB } ] }"""

    @Test
    fun `a private_key_jwt client is created with its methods and key URI, nothing is minted, and a changed key URI converges as one PATCH carrying only it`() {
        val byUri = """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: svc
                spec: { displayName: "Service", grantTypes: [client_credentials], clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://svc.acme.example/jwks.json" }
        """
        val e = engine()
        val plan = e.plan(file(byUri), null, false)
        assertThat(plan.changes.single().reason).doesNotContain("client secret will be minted") // rung 1: nothing to mint
        val first = apply(file(byUri), null)
        val create = api.writes.single { it.method == "POST" && it.path == "/api/v1/applications" }
        assertThat(create.body).containsEntry("clientAuthenticationMethods", listOf("private_key_jwt")).containsEntry("jwksUri", "https://svc.acme.example/jwks.json")
        assertThat(api.mintedSecrets).isEmpty()
        assertThat(e.undeliveredSecretDetails).isEmpty()
        // The receipt records the key LOCATION this file applied (never a key): the API does not render it, so this is what the next plan diffs against.
        assertThat(first.resources.single().attributes).containsEntry(ProvisionEngine.ATTR_JWKS_URI, "https://svc.acme.example/jwks.json")

        api.reset()
        assertThat(engine().plan(file(byUri), first, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(file(byUri), first)
        assertThat(api.writes).isEmpty()

        val rotated = file(byUri.replace("jwks.json", "jwks-v2.json"))
        val plan2 = engine().plan(rotated, first, false)
        assertThat(plan2.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        assertThat(plan2.changes.single().diff.keys).containsExactly("jwksUri")
        val second = apply(rotated, first)
        val patch = api.writes.single { it.method == "PATCH" }
        assertThat(patch.body).isEqualTo(mapOf("jwksUri" to "https://svc.acme.example/jwks-v2.json"))
        assertThat(second.resources.single().attributes).containsEntry(ProvisionEngine.ATTR_JWKS_URI, "https://svc.acme.example/jwks-v2.json")

        // A changed METHOD set converges too (today's create-time-only shape is gone).
        api.reset()
        val basic = file(byUri.replace("clientAuthenticationMethods: [private_key_jwt], jwksUri: \"https://svc.acme.example/jwks.json\"", "clientAuthenticationMethods: [client_secret_basic]"))
        val plan3 = engine().plan(basic, second, false)
        assertThat(plan3.changes.single().diff.keys).containsExactly("clientAuthenticationMethods")
        apply(basic, second)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("clientAuthenticationMethods" to listOf("client_secret_basic")))
    }

    @Test
    fun `an inline jwks is sent as the API's JSON text, the receipt records only the kids, and a rotated key converges`() {
        val inline = """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: svc
                spec: { displayName: "Service", clientAuthenticationMethods: [private_key_jwt], jwks: $jwks }
        """
        val first = apply(file(inline), null)
        val sent = api.writes.single { it.method == "POST" }.body["jwks"]
        assertThat(sent).isInstanceOf(String::class.java) // `CreateApplicationRequest.jwks` is a string
        assertThat(sent as String).contains("\"kid\":\"k1\"").contains("\"n\":\"n1\"")
        assertThat(first.resources.single().attributes).containsEntry(ProvisionEngine.ATTR_JWKS_KIDS, "k1").doesNotContainKey("jwks")
        assertThat(first.resources.single().attributes.values).noneMatch { it.contains("n1") }

        api.reset()
        assertThat(engine().plan(file(inline), first, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        val rotated = file(inline.replace("kid: k1", "kid: k2"))
        val plan = engine().plan(rotated, first, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.UPDATE)
        assertThat(plan.changes.single().diff).containsOnlyKeys("jwks")
        assertThat(plan.changes.single().diff["jwks"]).isEqualTo("[k1] → [k2]")
        val second = apply(rotated, first)
        assertThat(api.writes.single { it.method == "PATCH" }.body.keys).containsExactly("jwks")
        assertThat(second.resources.single().attributes).containsEntry(ProvisionEngine.ATTR_JWKS_KIDS, "k2")
    }

    @Test
    fun `an adopted client with a declared key location is sent it once — the API cannot say what it holds — and is a no-op afterwards`() {
        api.seedApplication(null, "Service", clientId = "svc")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: svc
                spec: { clientId: svc, displayName: "Service", clientAuthenticationMethods: [private_key_jwt], jwksUri: "https://svc.acme.example/jwks.json" }
            """,
        )
        val plan = engine().plan(f, null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.adopted).isTrue()
        assertThat(change.diff.keys).containsExactlyInAnyOrder("clientAuthenticationMethods", "jwksUri")
        assertThat(change.diff["jwksUri"]).startsWith("(not readable from the API — sent once to converge) →")
        val first = apply(f, null)
        assertThat(api.writes.single { it.method == "PATCH" }.body.keys).containsExactlyInAnyOrder("clientAuthenticationMethods", "jwksUri")
        api.reset()
        assertThat(engine().plan(f, first, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    private val federated = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: billing-web
            spec:
              displayName: "Billing web"
              redirectUris: ["https://billing.acme.example/cb"]
              grantTypes: [authorization_code, refresh_token]
              clientAuthenticationMethods: [federated_assertion]
              federatedTrust: billing-pods
          - kind: workloadIdentityTrust
            name: billing-pods
            spec:
              provider: kubernetes
              kubernetes: { issuer: "https://oidc.example/cluster", namespace: billing, serviceAccount: billing-web }
              scopes: [tenant:applications.read]
              confirmProduction: true
    """

    @Test
    fun `a federated_assertion client and its trust in one file — the trust is created first, the client carries the resolved trust id, nothing is minted, a rebind converges`() {
        val e = engine()
        val plan = e.plan(file(federated), null, false)
        // The trust converges BEFORE the client whatever the file's order; the plan names the pending binding.
        assertThat(plan.changes.map { it.kind to it.action }).containsExactly("workloadIdentityTrust" to ChangeAction.CREATE, "application" to ChangeAction.CREATE)
        assertThat(plan.changes.last().reason).doesNotContain("client secret will be minted")
        assertThat(plan.hasErrors).isFalse()

        val first = apply(file(federated), null)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/workload-identity/trusts", "POST /api/v1/applications")
        val trustId = first.resources.first { it.kind == "workloadIdentityTrust" }.id
        val appBody = api.writes.last().body
        assertThat(appBody).containsEntry("federatedTrust", trustId).containsEntry("clientAuthenticationMethods", listOf("federated_assertion"))
        assertThat(appBody).doesNotContainKey("jwks").doesNotContainKey("jwksUri")
        assertThat(api.mintedSecrets).isEmpty()
        assertThat(e.undeliveredSecretDetails).isEmpty()
        assertThat(api.applications.single()["federatedTrust"]).isEqualTo(trustId)

        api.reset()
        val again = engine().plan(file(federated), first, false)
        assertThat(again.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        apply(file(federated), first)
        assertThat(api.writes).isEmpty()

        // Rebinding to another (existing) trust converges: one PATCH carrying the new trust's id.
        val otherId = api.seedTrust(null, "billing-pods-blue", "kubernetes", pins = mapOf("issuer" to "https://oidc.example/blue", "namespace" to "billing", "serviceAccount" to "billing-web"))
        val rebound = file(federated.replace("federatedTrust: billing-pods", "federatedTrust: billing-pods-blue"))
        val plan3 = engine().plan(rebound, first, false)
        val app = plan3.changes.single { it.kind == "application" }
        assertThat(app.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(app.diff).containsOnlyKeys("federatedTrust")
        assertThat(app.diff["federatedTrust"]).isEqualTo("$trustId → $otherId")
        apply(rebound, first)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("federatedTrust" to otherId))
    }

    @Test
    fun `a federated client whose trust is live but not declared binds it by name, and a plan on an existing client shows the pending binding of a trust this apply creates`() {
        val liveId = api.seedTrust(null, "billing-pods", "kubernetes", pins = mapOf("issuer" to "https://oidc.example/cluster"))
        val onlyClient = file(federated.lines().takeWhile { !it.contains("kind: workloadIdentityTrust") }.joinToString("\n"))
        val first = apply(onlyClient, null)
        assertThat(api.writes.single().body["federatedTrust"]).isEqualTo(liveId)
        assertThat(first.resources.map { it.kind }).containsExactly("application")

        // The live client is bound to `billing-pods`; the file now binds it to a trust this same apply will create.
        api.reset()
        val f = file(federated.replace("federatedTrust: billing-pods", "federatedTrust: billing-pods-v2").replace("name: billing-pods", "name: billing-pods-v2"))
        val plan = engine().plan(f, first, false)
        val app = plan.changes.single { it.kind == "application" }
        assertThat(app.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(app.diff["federatedTrust"]).isEqualTo("$liveId → billing-pods-v2 ${ProvisionEngine.PENDING_TRUST_MARKER}")
        val second = apply(f, first)
        val newTrust = second.resources.first { it.kind == "workloadIdentityTrust" }.id
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/workload-identity/trusts", "PATCH /api/v1/applications/${first.resources.single().id}")
        assertThat(api.writes.last().body).isEqualTo(mapOf("federatedTrust" to newTrust))
    }

    @Test
    fun `federatedTrust naming a trust that does not exist, or one declared for another environment, is federated_trust_not_found and apply refuses the plan`() {
        api.seedEnvironment("staging")
        val missing = file(federated.lines().takeWhile { !it.contains("kind: workloadIdentityTrust") }.joinToString("\n"))
        val plan = engine().plan(missing, null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionEngine.ERROR_FEDERATED_TRUST_NOT_FOUND)
        assertThat(change.reason).contains("no workloadIdentityTrust named 'billing-pods' in the production plane")
        assertThatThrownBy { engine().apply(missing, null, plan, "acme", null) {} }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("nothing was written")
        assertThat(api.writes).isEmpty()

        // Declared, but for another environment: a login client binds a trust of its OWN environment.
        val elsewhere = file(
            federated.replace("          - kind: workloadIdentityTrust\n            name: billing-pods\n", "          - kind: workloadIdentityTrust\n            name: billing-pods\n            environment: staging\n")
                .replace("              confirmProduction: true\n", ""),
        )
        val plan2 = engine().plan(elsewhere, null, false)
        val app = plan2.changes.single { it.kind == "application" }
        assertThat(app.action).isEqualTo(ChangeAction.ERROR)
        assertThat(app.error).isEqualTo(ProvisionEngine.ERROR_FEDERATED_TRUST_NOT_FOUND)
        assertThat(app.reason).contains("declared in this file for environment 'staging'").contains("the application lives in the production plane")
        assertThat(plan2.changes.single { it.kind == "workloadIdentityTrust" }.action).isEqualTo(ChangeAction.CREATE) // the trust itself is fine
    }
}
