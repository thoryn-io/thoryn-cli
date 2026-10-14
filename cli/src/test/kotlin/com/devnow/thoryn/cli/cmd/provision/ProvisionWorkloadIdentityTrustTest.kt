package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.Access
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionFileRef
import com.devnow.thoryn.provision.ProvisionReceipt
import com.devnow.thoryn.provision.ProvisionReceiptStore
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.util.Base64

/**
 * SSO-3689 — `kind: workloadIdentityTrust` in the engine and the CLI: created with the API's body for each provider,
 * adopted by name (also on the API's `409 workload_identity_trust_name_taken`), never updated in place
 * (`workload_identity_trust_immutable` names the fix), removed only through `--prune` / `destroy` (clients first), the
 * receipt recording the `wi_` client and audience, the plan stating the scope ceiling (and refusing an overreach with
 * the hub's `scope_not_grantable` when the caller's scopes are known), `apply` PRINTING — never writing — the consumer's
 * `connection.json`, `import` rendering existing trusts, and the structural limit: a file cannot declare the trust its
 * own identity signs in with.
 */
class ProvisionWorkloadIdentityTrustTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine(callerScopes: Set<String>? = null, subject: String? = null) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject, callerScopes = callerScopes,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?, prune: Boolean = false, confirm: String? = null, e: ProvisionEngine = engine()): ProvisionReceipt =
        e.apply(f, receipt, e.plan(f, receipt, prune), "acme", confirm) {}

    private val threeProviders = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
          - kind: workloadIdentityTrust
            name: billing-ci
            environment: ci
            spec:
              provider: github_actions
              github: { repository: acme/billing, ownerId: 1234567, repositoryId: 7654321, environment: staging, ref: refs/heads/main, githubHostedRunnersOnly: true }
              scopes: [tenant:applications.read, tenant:applications.write]
          - kind: workloadIdentityTrust
            name: forge-main
            spec:
              provider: forgejo
              forgejo: { instanceUrl: "https://forge.example.org", owner: thoryn, ownerId: 7, repository: infra, repositoryId: 42, ref: refs/heads/main }
              scopes: [tenant:applications.write]
              confirmProduction: true
          - kind: workloadIdentityTrust
            name: billing-pods
            spec:
              provider: kubernetes
              kubernetes:
                issuer: "https://oidc.example/cluster"
                namespace: billing
                serviceAccount: billing-web
                jwks: { keys: [ { kty: RSA, kid: t10j6Z4K, use: sig, alg: RS256, n: "n1", e: AQAB } ] }
              scopes: [tenant:applications.read]
              confirmProduction: true
    """

    /** The sandbox + its GitHub trust alone. */
    private val githubOnly = threeProviders.lines().takeWhile { !it.contains("name: forge-main") }.dropLastWhile { it.trim() == "- kind: workloadIdentityTrust" }.joinToString("\n")

    @Test
    fun `trusts of all three providers are created with the API's body, the receipt records the wi_ client and audience, apply prints the connection file, and a second apply is a no-op`() {
        val first = apply(file(threeProviders), null)
        val posts = api.writes.filter { it.path == "/api/v1/workload-identity/trusts" }
        assertThat(posts).hasSize(3)
        val github = posts.first { it.body["provider"] == "github_actions" }
        assertThat(github.env).isEqualTo("ci-sbx")
        @Suppress("UNCHECKED_CAST")
        val githubPins = github.body["github"] as Map<String, Any?>
        // The file's `repository: owner/name` is the API's `owner` + `repository`; the pins ride as declared.
        assertThat(githubPins).containsEntry("owner", "acme").containsEntry("repository", "billing").containsEntry("ownerId", 1234567).containsEntry("repositoryId", 7654321)
            .containsEntry("environment", "staging").containsEntry("ref", "refs/heads/main").containsEntry("githubHostedRunnersOnly", true)
        assertThat(github.body).containsEntry("name", "billing-ci").containsEntry("scopes", listOf("tenant:applications.read", "tenant:applications.write")).doesNotContainKey("confirmProduction")
        val forgejo = posts.first { it.body["provider"] == "forgejo" }
        assertThat(forgejo.env).isNull()
        assertThat(forgejo.body["forgejo"]).isEqualTo(mapOf("instanceUrl" to "https://forge.example.org", "owner" to "thoryn", "ownerId" to 7, "repository" to "infra", "repositoryId" to 42, "ref" to "refs/heads/main"))
        assertThat(forgejo.body).containsEntry("confirmProduction", true)
        val kubernetes = posts.first { it.body["provider"] == "kubernetes" }
        @Suppress("UNCHECKED_CAST")
        val k8s = kubernetes.body["kubernetes"] as Map<String, Any?>
        assertThat(k8s).containsEntry("issuer", "https://oidc.example/cluster").containsEntry("namespace", "billing").containsEntry("serviceAccount", "billing-web")
        assertThat((k8s["jwks"] as Map<*, *>)["keys"]).isInstanceOf(List::class.java)

        // The receipt: id, the wi_ workload client, the audience, the provider — nothing else (a trust has no secret).
        val trusts = first.resources.filter { it.kind == "workloadIdentityTrust" }
        assertThat(trusts.map { it.name }).containsExactly("billing-ci", "forge-main", "billing-pods")
        trusts.forEach { t ->
            assertThat(t.id).startsWith("trust-")
            assertThat(t.attributes[ProvisionEngine.ATTR_CLIENT_ID]).startsWith("wi_")
            assertThat(t.attributes["audience"]).startsWith("https://acme.auth.thoryn.io")
            assertThat(t.adopted).isFalse()
        }
        assertThat(trusts.first { it.name == "billing-ci" }.environment).isEqualTo("ci-sbx")
        assertThat(trusts.first { it.name == "billing-ci" }.attributes["audience"]).isEqualTo("https://acme.auth.thoryn.io/ci-sbx")

        // apply PRINTS the consumer's connection.json (and never writes one).
        val out = console.toString()
        assertThat(out).contains("+ workloadIdentityTrust billing-ci: id=").contains("connection.json for the workload that signs in with this trust — not written by apply")
        assertThat(out).contains("\"method\" : \"workload_identity\"").contains("\"provider\" : \"github_actions\"").contains("\"clientId\" : \"${trusts[0].attributes["clientId"]}\"")
            .contains("\"audience\" : \"https://acme.auth.thoryn.io/ci-sbx\"").contains("\"owner\" : \"acme\"").contains("\"environment\" : \"staging\"")
        // The kubernetes document is the one `trusts create --provider kubernetes` prints (SSO-3684): the file token source + the cluster pins.
        assertThat(out).contains("\"provider\" : \"kubernetes\"").contains("\"tokenSource\" : {").contains("\"path\" : \"${ProvisionEngine.KUBERNETES_TOKEN_FILE}\"")
            .contains("\"namespace\" : \"billing\"").contains("\"serviceAccount\" : \"billing-web\"")
        assertThat(out).contains("a forgejo job presents its own Actions token") // the contract has no forgejo provider yet: `provider` left out
        assertThat(out).doesNotContain("\"n\" : \"n1\"") // never key material in the printed document
        assertThat(File(tempHome.toFile(), ".thoryn/connection.json")).doesNotExist()

        api.reset()
        val plan = engine().plan(file(threeProviders), first, false)
        assertThat(plan.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        assertThat(plan.changes.first { it.name == "billing-ci" }.trust).containsEntry("clientId", trusts[0].attributes["clientId"]).containsEntry("provider", "github_actions")
        apply(file(threeProviders), first)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an existing trust of the same name is adopted — on the plan, and on the API's 409 when the name is taken between lookup and create`() {
        api.seedTrust("ci-sbx", "billing-ci", pins = mapOf("owner" to "acme", "repository" to "billing", "ownerId" to 1234567L, "repositoryId" to 7654321L, "environment" to "staging", "ref" to "refs/heads/main", "githubHostedRunnersOnly" to true), scopes = listOf("tenant:applications.write", "tenant:applications.read"))
        api.seedEnvironment("ci-sbx")
        val one = file(githubOnly)
        val plan = engine().plan(one, null, false)
        val trust = plan.changes.single { it.kind == "workloadIdentityTrust" }
        assertThat(trust.action).isEqualTo(ChangeAction.ADOPT) // scopes compare as a set; every declared pin matches
        assertThat(trust.trust).containsEntry("clientId", api.trusts.single()["clientId"])
        val receipt = apply(one, null)
        assertThat(api.writes.filter { it.path.startsWith("/api/v1/workload-identity") }).isEmpty()
        val owned = receipt.resources.single { it.kind == "workloadIdentityTrust" }
        assertThat(owned.adopted).isTrue()
        assertThat(owned.attributes[ProvisionEngine.ATTR_CLIENT_ID]).isEqualTo(api.trusts.single()["clientId"])
        assertThat(console.toString()).contains("adopted (id ${owned.id})").contains("connection.json for the workload")
        // Adopted ⇒ destroy leaves it in place.
        engine().destroy(receipt, "acme") {}
        assertThat(api.trusts).hasSize(1)

        // The race: nothing live at plan time, the name taken by the time apply POSTs — adopted when it matches.
        api.trusts.clear(); api.reset(); console.reset()
        api.trustNameTakenOnce = true
        val raced = apply(one, null)
        assertThat(api.writes.count { it.method == "POST" && it.path == "/api/v1/workload-identity/trusts" }).isEqualTo(1)
        assertThat(raced.resources.single { it.kind == "workloadIdentityTrust" }.adopted).isTrue()
        assertThat(console.toString()).contains("the name was taken by a matching trust meanwhile — adopted")
    }

    @Test
    fun `a declared field that differs from the live trust is workload_identity_trust_immutable naming the fix, and apply refuses the plan`() {
        api.seedEnvironment("ci-sbx")
        val id = api.seedTrust("ci-sbx", "billing-ci", pins = mapOf("owner" to "acme", "repository" to "billing", "ownerId" to 1234567L, "repositoryId" to 7654321L, "environment" to "production", "ref" to "refs/heads/main", "githubHostedRunnersOnly" to true), scopes = listOf("tenant:applications.read", "tenant:applications.write"))
        val one = file(githubOnly)
        val plan = engine().plan(one, null, false)
        val trust = plan.changes.single { it.kind == "workloadIdentityTrust" }
        assertThat(trust.action).isEqualTo(ChangeAction.ERROR)
        assertThat(trust.error).isEqualTo(ProvisionEngine.ERROR_TRUST_IMMUTABLE)
        assertThat(trust.diff).containsOnlyKeys("github.environment")
        assertThat(trust.diff["github.environment"]).isEqualTo("production → staging")
        assertThat(trust.reason).contains("thoryn workload-identity trusts delete $id --environment ci-sbx")
        assertThat(plan.hasErrors).isTrue()
        assertThatThrownBy { engine().apply(one, null, plan, "acme", null) {} }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("nothing was written")
        assertThat(api.writes.filter { it.method != "GET" && it.path != "/api/v1/access/check" }).isEmpty()

        // Only DECLARED fields are compared: a file that leaves the runner rule and the ids out matches a trust that pins them.
        val loose = file(githubOnly.replace(", ownerId: 1234567, repositoryId: 7654321, environment: staging, ref: refs/heads/main, githubHostedRunnersOnly: true", ", environment: production"))
        assertThat(engine().plan(loose, null, false).changes.single { it.kind == "workloadIdentityTrust" }.action).isEqualTo(ChangeAction.ADOPT)
    }

    @Test
    fun `the scope ceiling — the plan refuses a trust whose scopes the applying identity does not hold, and the hub's 403 at apply names the fix`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: billing-ci
                spec: { provider: github_actions, github: { repository: acme/billing, environment: production }, scopes: [tenant:applications.write, tenant:users.write], confirmProduction: true }
            """,
        )
        // Known caller scopes: refused BEFORE any write, with the hub's own code and the scope named.
        val plan = engine(callerScopes = setOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read")).plan(f, null, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.ERROR)
        assertThat(plan.changes.single().error).isEqualTo(ProvisionEngine.ERROR_SCOPE_NOT_GRANTABLE)
        assertThat(plan.changes.single().reason).contains("does not hold tenant:users.write")
        // Every declared scope held: a plain create, the ceiling stated.
        val ok = engine(callerScopes = setOf("tenant:applications.write", "tenant:users.write")).plan(f, null, false).changes.single()
        assertThat(ok.action).isEqualTo(ChangeAction.CREATE)
        assertThat(ok.reason).contains("scope ceiling")
        // Unknown caller scopes: the plan states the ceiling and the hub enforces it — a 403 at apply names the fix.
        api.callerScopes = setOf("tenant:applications.write")
        val unknown = engine()
        val plan2 = unknown.plan(f, null, false)
        assertThat(plan2.changes.single().action).isEqualTo(ChangeAction.CREATE)
        assertThat(plan2.changes.single().reason).contains(ProvisionEngine.SCOPE_CEILING_NOTE.trim())
        assertThatThrownBy { unknown.apply(f, null, plan2, "acme", null) {} }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("scope_not_grantable")
            .hasMessageContaining("drop the scope from spec.scopes")
        assertThat(api.trusts).isEmpty()
    }

    @Test
    fun `removal only through --prune or destroy — clients before the trust they bind, production gated by --confirm`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: billing-pods
                spec: { provider: kubernetes, kubernetes: { issuer: "https://oidc.example/cluster", namespace: billing, serviceAccount: billing-web }, scopes: [tenant:applications.read], confirmProduction: true }
              - kind: application
                name: billing-web
                spec: { displayName: "Billing web", redirectUris: ["https://billing.acme.example/cb"], clientAuthenticationMethods: [federated_assertion], federatedTrust: billing-pods }
            """,
        )
        val first = apply(f, null)
        api.reset()
        // Dropped from the file without --prune: kept, flagged.
        val kept = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: application, name: other, spec: { displayName: Other, clientType: public } }")
        val noPrune = engine().plan(kept, first, false)
        assertThat(noPrune.changes.filter { it.action == ChangeAction.SKIP }.map { it.kind }).containsExactlyInAnyOrder("workloadIdentityTrust", "application")
        // With --prune, the production plane needs --confirm; the client goes before the trust it is bound to.
        val prune = engine().plan(kept, first, true)
        assertThat(prune.removes.map { it.kind }).containsExactly("application", "workloadIdentityTrust")
        assertThat(prune.removesOnProductionPlane).isTrue()
        assertThatThrownBy { engine().apply(kept, first, prune, "acme", null) {} }.hasMessageContaining("--confirm")
        apply(kept, first, prune = true, confirm = "acme")
        val deletes = api.writes.filter { it.method == "DELETE" }
        assertThat(deletes.map { it.path }).containsExactly("/api/v1/applications/${first.resources[1].id}", "/api/v1/workload-identity/trusts/${first.resources[0].id}")
        assertThat(deletes.last().confirm).isEqualTo("acme")
        assertThat(api.trusts).isEmpty()

        // destroy: clients before the trusts they bind even when the receipt recorded the CLIENT FIRST — an application
        // created by an earlier apply, bound to a trust a later apply added (a plain reversal would delete the trust first).
        api.reset()
        val clientFirst = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: billing-web
                spec: { displayName: "Billing web", redirectUris: ["https://billing.acme.example/cb"], clientType: public }
            """,
        )
        val earlier = apply(clientFirst, null)
        val later = apply(f, earlier)
        assertThat(later.resources.map { it.kind }).containsExactly("application", "workloadIdentityTrust")
        api.reset()
        val outcome = engine().destroy(later, "acme") {}
        assertThat(outcome.failures).isEmpty()
        assertThat(api.writes.filter { it.method == "DELETE" }.map { it.path.split('/')[3] }).containsExactly("applications", "workload-identity")
        // …and --prune from such a receipt removes in the same order.
        api.reset()
        val reapplied = apply(f, apply(clientFirst, null))
        api.reset()
        apply(kept, reapplied, prune = true, confirm = "acme")
        assertThat(api.writes.filter { it.method == "DELETE" }.map { it.path.split('/')[3] }).containsExactly("applications", "workload-identity")
    }

    @Test
    fun `the ownership gate is the environment's — no relation is access_not_owned, viewer only a readOnly reference, and a repository's own bootstrap trust is refused`() {
        api.callerIsAdmin = false
        api.caller = "client:repo"
        val envId = api.seedEnvironment("ci-sbx")
        val otherId = api.seedEnvironment("other")
        api.seedGrant("client:repo", "manager", "environment:$envId")
        api.seedGrant("client:repo", "viewer", "environment:$otherId")
        api.seedTrust("other", "shared-ci", pins = mapOf("owner" to "acme", "repository" to "shared"), scopes = listOf("tenant:applications.read"))
        val mine = """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: billing-ci
                environment: ci-sbx
                spec: { provider: github_actions, github: { repository: acme/billing }, scopes: [tenant:applications.read] }
        """
        assertThat(engine(subject = "client:repo").plan(file(mine), null, false).changes.single().action).isEqualTo(ChangeAction.CREATE)
        // The production plane: this identity does not manage the workspace.
        val production = file(mine.replace("                environment: ci-sbx\n", "").replace("scopes: [tenant:applications.read] }", "scopes: [tenant:applications.read], confirmProduction: true }").replace("repository: acme/billing }", "repository: acme/billing, environment: production }"))
        val refused = engine(subject = "client:repo").plan(production, null, false).changes.single()
        assertThat(refused.action).isEqualTo(ChangeAction.ERROR)
        assertThat(refused.error).isEqualTo(ProvisionEngine.ERROR_NOT_OWNED)
        assertThat(refused.reason).contains("requires `manager` on its environment workspace:${api.tenantId}")
        // Viewer on the environment: only a matching readOnly reference, never a write.
        val viewed = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: workloadIdentityTrust
                name: shared-ci
                environment: other
                spec: { provider: github_actions, github: { repository: acme/shared }, scopes: [tenant:applications.read] }
            """,
        )
        val asOwned = engine(subject = "client:repo").plan(viewed, null, false).changes.single()
        assertThat(asOwned.action).isEqualTo(ChangeAction.ERROR)
        assertThat(asOwned.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)
        assertThat(asOwned.reason).contains("declare the trust `readOnly: true`")
        val reference = engine(subject = "client:repo").plan(file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: workloadIdentityTrust, name: shared-ci, environment: other, readOnly: true, spec: { provider: github_actions, github: { repository: acme/shared }, scopes: [tenant:applications.read] } }"), null, false).changes.single()
        assertThat(reference.action).isEqualTo(ChangeAction.NOOP)
        assertThat(reference.readOnly).isTrue()
        assertThat(reference.access).isEqualTo(Access.VIEWER.label)

        // The structural limit: the trust whose wi_ client is the applying identity cannot be declared by the file it applies.
        api.seedTrust("ci-sbx", "billing-ci", pins = mapOf("owner" to "acme", "repository" to "billing"), scopes = listOf("tenant:applications.read"), clientId = "wi_self")
        val self = engine(subject = "client:wi_self").plan(file(mine), null, false).changes.single()
        assertThat(self.action).isEqualTo(ChangeAction.ERROR)
        assertThat(self.error).isEqualTo(ProvisionEngine.ERROR_TRUST_IS_SELF)
        assertThat(self.reason).contains("cannot declare its OWN bootstrap trust")
        // …while another identity with reach adopts that same trust as usual.
        assertThat(engine(subject = "client:repo").plan(file(mine), null, false).changes.single().action).isEqualTo(ChangeAction.ADOPT)
    }

    @Test
    fun `import renders existing trusts of every reachable plane, pages through the list, and skips the identity's own bootstrap trust`() {
        api.callerIsAdmin = false
        api.caller = "client:wi_me"
        val envId = api.seedEnvironment("ci-sbx")
        api.seedGrant("client:wi_me", "manager", "environment:$envId")
        api.seedGrant("client:wi_me", "manager", "workspace:${api.tenantId}")
        api.trustPageSize = 1
        api.seedTrust("ci-sbx", "repo-ci", pins = mapOf("owner" to "acme", "repository" to "repo", "ownerId" to 1L, "repositoryId" to 2L, "ref" to "refs/heads/main"), scopes = listOf("tenant:applications.read"), clientId = "wi_me")
        api.seedTrust("ci-sbx", "billing-ci", pins = mapOf("owner" to "acme", "repository" to "billing", "environment" to "staging", "githubHostedRunnersOnly" to true), scopes = listOf("tenant:applications.write", "tenant:applications.read"))
        api.seedTrust(null, "billing-pods", "kubernetes", pins = mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "billing", "serviceAccount" to "billing-web", "jwks" to mapOf("keys" to listOf(mapOf("kty" to "RSA", "kid" to "k9")))), scopes = listOf("tenant:applications.read"))
        api.seedTrust(null, "forge-main", "forgejo", pins = mapOf("instanceUrl" to "https://forge.example.org", "owner" to "thoryn", "ownerId" to 7L, "repository" to "infra", "repositoryId" to 42L, "ref" to "refs/heads/main"), scopes = listOf("tenant:applications.write"))

        val result = engine(subject = "client:wi_me").import(existing = null, receipt = null)
        val byKey = result.resources.filter { it.resource.kind == "workloadIdentityTrust" }.associateBy { it.resource.name }
        assertThat(byKey.keys).containsExactlyInAnyOrder("billing-ci", "billing-pods", "forge-main")
        assertThat(result.skipped).anyMatch { it.contains("workloadIdentityTrust:repo-ci") && it.contains("own bootstrap trust") }
        val ci = byKey.getValue("billing-ci")
        assertThat(ci.resource.environment).isEqualTo("ci-sbx")
        assertThat(ci.resource.spec).isEqualTo(mapOf("provider" to "github_actions", "github" to mapOf("repository" to "acme/billing", "environment" to "staging", "githubHostedRunnersOnly" to true), "scopes" to listOf("tenant:applications.write", "tenant:applications.read")))
        assertThat(ci.owned!!.adopted).isTrue()
        assertThat(ci.owned!!.attributes[ProvisionEngine.ATTR_CLIENT_ID]).startsWith("wi_")
        val pods = byKey.getValue("billing-pods")
        assertThat(pods.resource.environment).isNull()
        assertThat(pods.resource.spec).isEqualTo(mapOf("provider" to "kubernetes", "kubernetes" to mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "billing", "serviceAccount" to "billing-web"), "scopes" to listOf("tenant:applications.read"), "confirmProduction" to true))
        assertThat(pods.note).contains("inline public keys (kid k9)").contains("add spec.kubernetes.jwks by hand")
        assertThat(byKey.getValue("forge-main").resource.spec["forgejo"]).isEqualTo(mapOf("instanceUrl" to "https://forge.example.org", "owner" to "thoryn", "ownerId" to 7, "repository" to "infra", "repositoryId" to 42, "ref" to "refs/heads/main"))
        // The rendered entries round-trip: every imported trust is a no-op against what is live.
        val yaml = "apiVersion: thoryn.io/provision/v1\nresources:\n" + result.resources.filter { it.resource.kind == "workloadIdentityTrust" }.joinToString("") { e ->
            "  - { kind: workloadIdentityTrust, name: ${e.resource.name}${e.resource.environment?.let { ", environment: $it" } ?: ""}, spec: ${tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(e.resource.spec)} }\n"
        }
        val receipt = ProvisionReceipt(file = ProvisionFileRef("provision.yaml", "sha256:x"), appliedAt = "now", resources = result.resources.mapNotNull { it.owned }.filter { it.kind == "workloadIdentityTrust" })
        assertThat(engine(subject = "client:wi_me").plan(file(yaml), receipt, false).changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
    }

    // ── the CLI ──

    private fun jwt(scope: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString("""{"sub":"founder","scope":"$scope","tnt":"${api.tenantId}"}""".toByteArray())
        return "$header.$payload.sig"
    }

    @Test
    fun `thoryn provision plan shows a trust's workload client and apply prints its connection file and records the receipt — from the session's own scopes`() {
        seedTokens(Tokens(accessToken = jwt("tenant:applications.read tenant:applications.write tenant:workload-identity.read tenant:workload-identity.write tenant:access.read")))
        val dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        val f = File(dir, "provision.yaml").apply {
            writeText(
                """
                apiVersion: thoryn.io/provision/v1
                resources:
                  - kind: workloadIdentityTrust
                    name: billing-ci
                    spec: { provider: github_actions, github: { repository: acme/billing, environment: production }, scopes: [tenant:applications.write], confirmProduction: true }
                """.trimIndent() + "\n",
            )
        }
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.err).doesNotContain("Error")
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("workloadIdentityTrust  billing-ci").contains("create").contains("mints its wi_ workload client").contains("scope ceiling")
        assertThat(api.writes.filter { it.method != "GET" }).isEmpty()

        val applied = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(applied.err).doesNotContain("Error")
        assertThat(applied.exit).isEqualTo(0)
        val clientId = api.trusts.single()["clientId"].toString()
        assertThat(applied.out).contains("+ workloadIdentityTrust billing-ci: id=").contains("clientId=$clientId")
            .contains("connection.json for the workload that signs in with this trust — not written by apply").contains("\"clientId\" : \"$clientId\"").contains("\"workspace\"")
        val receipt = ProvisionReceiptStore().read(File(dir, "provision.receipt.json"))!!
        assertThat(receipt.resources.single().attributes).containsEntry(ProvisionEngine.ATTR_CLIENT_ID, clientId).containsKey("audience")
        assertThat(File(dir, "connection.json")).doesNotExist()

        val again = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(again.exit).isEqualTo(0)
        assertThat(again.out).contains("workloadIdentityTrust billing-ci: clientId $clientId audience https://acme.auth.thoryn.io (connection.json is printed by apply, never written)")
            .contains("0 to create, 0 to update, 0 to adopt, 0 to remove, 1 unchanged.")

        // The CLI hands the engine the session's scopes: a trust reaching beyond them is a red plan before any write.
        f.writeText(f.readText().replace("scopes: [tenant:applications.write]", "scopes: [tenant:applications.write, tenant:users.write]").replace("name: billing-ci", "name: billing-wide"))
        val red = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(red.exit).isNotEqualTo(0)
        assertThat(red.err).contains("scope_not_grantable").contains("does not hold tenant:users.write")
    }

    @Test
    fun `callerScopesOf reads the JWT scope claim, falls back to the token response, and is null for an opaque token`() {
        assertThat(ProvisionCommand.callerScopesOf(Tokens(accessToken = jwt("tenant:a.read tenant:b.write")))).containsExactlyInAnyOrder("tenant:a.read", "tenant:b.write")
        assertThat(ProvisionCommand.callerScopesOf(Tokens(accessToken = "opaque", scope = "tenant:a.read"))).containsExactly("tenant:a.read")
        assertThat(ProvisionCommand.callerScopesOf(Tokens(accessToken = "opaque"))).isNull()
    }
}
