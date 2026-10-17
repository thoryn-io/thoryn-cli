package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.Access
import com.devnow.thoryn.provision.AccessRefs
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.util.Base64

/**
 * SSO-3774 (oauthy ADR 2026-10-16 §4; story S3) — what a repository does with the trusts it OWNS, besides gating them:
 * a declared trust it cannot see is `access_not_reachable` with ONE fix item (`owner` on the trust by name), on the trust's
 * row and on the application naming it — never `federated_trust_not_found`; `import` lists the trusts it can see (owned
 * ⇒ an entry, viewed or owned elsewhere ⇒ `readOnly`); `--prune` and `destroy` remove owned trusts like owned
 * applications; and on a platform that predates trust objects (product-api before S1) everything is gated by the plane,
 * as before.
 */
class ProvisionTrustOwnedLifecycleTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val json = JsonMapper.builder().build()
    private val console = ByteArrayOutputStream()
    private val clientId = "wi_00000000000000000000beef"
    private val repo = "client:$clientId"
    private val other = "client:wi_00000000000000000000cafe"

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = repo
        FixRequests.environment = { key -> if (key.startsWith("GITHUB_")) null else com.devnow.thoryn.cli.auth.WorkloadIdentityFlow.runnerEnv(key) }
    }

    @AfterEach
    fun unmount() = FixRequests.resetEnvironmentForTest()

    private fun engine(subject: String? = repo) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private val pins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-starters", "environment" to "provision", "ref" to "refs/heads/main")

    private val starters = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: workloadIdentityTrust
            name: starters-ci
            spec: { provider: github_actions, github: { repository: thoryn-io/thoryn-starters, environment: provision, ref: refs/heads/main }, scopes: [tenant:applications.read], confirmProduction: true }
          - kind: application
            name: starters
            spec: { clientId: starters, displayName: Starters, redirectUris: ["https://starters.thoryn.io/cb"], clientAuthenticationMethods: [federated_assertion], federatedTrust: starters-ci }
    """

    /** A repository identity's plan-profile session (read scopes), as the reusable workflow signs in. */
    private fun session() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString("""{"client_id":"$clientId","scope":"tenant:applications.read tenant:workload-identity.read tenant:access.read","tnt":"${api.tenantId}"}""".toByteArray())
        seedTokens(
            Tokens(
                accessToken = "$header.$payload.sig", authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId,
                issuer = "https://thoryn.auth.stg.thoryn.org", gateway = baseUrl(), workspace = "thoryn", profile = Tokens.PROFILE_PLAN,
                jobEnvironment = "provision-plan", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    @Test
    fun `a declared trust the repository cannot see is access_not_reachable with one owner-by-name item — never federated_trust_not_found — and plans green once an admin grants it`() {
        api.environmentClaimFilter = true
        // The trust carries a write scope the PLAN session does not hold: the scope ceiling of a create that will not happen must not hide the verdict.
        val trustId = api.seedTrust(null, "starters-ci", pins = pins, scopes = listOf("tenant:applications.read", "tenant:applications.write"))
        api.seedApplication(null, "Starters", listOf("https://starters.thoryn.io/cb"), clientId = "starters")
        api.applications.single()["clientAuthenticationMethods"] = listOf("federated_assertion")
        api.applications.single()["federatedTrust"] = trustId
        api.seedGrant(repo, "owner", "application:starters")
        session()
        val path = File(tempHome.toFile(), "provision.yaml").apply { writeText(starters.trimIndent().replace("scopes: [tenant:applications.read]", "scopes: [tenant:applications.read, tenant:applications.write]") + "\n") }
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, stdout, err) = runCli("provision", "plan", "--file", path.path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(stdout + err).doesNotContain(ProvisionEngine.ERROR_FEDERATED_TRUST_NOT_FOUND + " —")
        assertThat(stdout).contains("${ProvisionEngine.ERROR_NOT_REACHABLE} — trust 'starters-ci' is declared in this file for the production plane but is not visible to this identity")
        val grant = "thoryn access grant $repo owner trust:${FixRequest.TRUST_ID_PLACEHOLDER}"
        assertThat(err).contains("  - owner on trust:starters-ci for $repo: ").contains("\n      $grant\n")
        val doc = json.readTree(Files.readString(out.toPath()))
        val item = doc["missing"].single() // the trust's row and the application's ask for the SAME right: one item
        assertThat(item["kind"].asString()).isEqualTo("owner")
        assertThat(item["object"].asString()).isEqualTo("trust:starters-ci")
        assertThat(item["cli"].asString()).isEqualTo(grant)
        assertThat(item["reason"].asString()).contains("named here by its NAME 'starters-ci' in the production plane")

        api.seedGrant(repo, "owner", "trust:$trustId")
        val (green, plan, _) = runCli("provision", "plan", "--file", path.path, "--gateway", baseUrl())
        assertThat(green).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(plan).doesNotContain(ProvisionEngine.ERROR_NOT_REACHABLE)
    }

    @Test
    fun `import lists the trusts it can see — owned as an entry, viewed or owned elsewhere as readOnly — and nothing it holds no relation on`() {
        val owned = api.seedTrust(null, "starters-ci", pins = pins)
        val viewed = api.seedTrust(null, "platform-ci", pins = pins + ("repository" to "platform"))
        api.seedTrust(null, "invisible-ci", pins = pins + ("repository" to "secret"))
        api.seedGrant(repo, "owner", "trust:$owned")
        api.seedGrant(repo, "viewer", "trust:$viewed")
        val sbx = api.seedEnvironment("ci-sbx")
        api.seedGrant(repo, "manager", "environment:$sbx")
        val foreign = api.seedTrust("ci-sbx", "foreign-ci", pins = mapOf("owner" to "acme", "repository" to "foreign"))
        api.seedGrant(other, "owner", "trust:$foreign")

        val result = engine().import(existing = null).resources.filter { it.resource.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }.associateBy { it.resource.name }

        assertThat(result.keys).containsExactlyInAnyOrder("starters-ci", "platform-ci", "foreign-ci")
        assertThat(result.getValue("starters-ci").resource.readOnly).isFalse()
        assertThat(result.getValue("starters-ci").access).isEqualTo(Access.MANAGER)
        assertThat(result.getValue("platform-ci").resource.readOnly).isTrue()
        assertThat(result.getValue("foreign-ci").resource.readOnly).isTrue()
        assertThat(result.getValue("foreign-ci").note).contains("owned by another repository")
    }

    @Test
    fun `--prune removes the trusts this identity OWNS that the file no longer declares — production behind --confirm — and leaves one it only manages`() {
        val owned = api.seedTrust(null, "retired-ci", pins = pins)
        api.seedGrant(repo, "owner", "trust:$owned")
        val sbx = api.seedEnvironment("ci-sbx")
        val managedOnly = api.seedTrust("ci-sbx", "pr-ci", pins = mapOf("owner" to "acme", "repository" to "pr"))
        api.seedGrant(repo, "manager", "trust:$managedOnly")
        assertThat(api.holds("environment:$sbx", "viewer")).isFalse()
        val kept = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: application, name: other, spec: { displayName: Other, clientType: public } }")
        api.callerIsAdmin = true // to create the declared application; ownership of the trusts is unchanged

        val e = engine()
        val plan = e.plan(kept, true)
        val removes = plan.removes.filter { it.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }
        assertThat(removes.map { it.name to it.liveId }).containsExactly("retired-ci" to owned)
        assertThat(removes.single().onProductionPlane).isTrue()
        e.apply(kept, plan, "thoryn", "thoryn")
        val delete = api.writes.single { it.method == "DELETE" }
        assertThat(delete.path).isEqualTo("/api/v1/workload-identity/trusts/$owned")
        assertThat(delete.confirm).isEqualTo("thoryn")
        assertThat(api.trusts.map { it["id"] }).containsExactly(managedOnly)
    }

    @Test
    fun `destroy removes a declared production trust its repository owns, and leaves one it does not — a person's destroy never removes a production trust`() {
        val id = api.seedTrust(null, "starters-ci", pins = pins)
        val f = file(starters.lines().takeWhile { !it.contains("kind: application") }.joinToString("\n"))
        api.seedGrant(repo, "manager", "trust:$id")
        val notOwned = engine().planDestroy(f).changes.single()
        assertThat(notOwned.action).isEqualTo(ChangeAction.SKIP)
        assertThat(notOwned.reason).contains("only by the repository that OWNS it")

        api.seedGrant(repo, "owner", "trust:$id")
        val owned = engine().planDestroy(f)
        assertThat(owned.removes.single().liveId).isEqualTo(id)
        engine().destroy(owned, "thoryn")
        assertThat(api.trusts).isEmpty()

        api.seedTrust(null, "starters-ci", pins = pins)
        api.callerIsAdmin = true
        api.caller = "member:founder"
        assertThat(engine(subject = "member:founder").planDestroy(f).changes.single().action).isEqualTo(ChangeAction.SKIP)
    }

    @Test
    fun `on a platform that predates trust objects the trust is gated by its plane alone — the 400 is never an error`() {
        api.trustObjects = false
        val sbx = api.seedEnvironment("ci-sbx")
        api.seedGrant(repo, "manager", "environment:$sbx")
        val legacyId = api.seedTrust("ci-sbx", "pr-ci", pins = mapOf("owner" to "acme", "repository" to "pr"))
        // oauthy PR #4151 — before S1 the trust response carries NO `owner` field (absent, not null); a stray owner tuple in
        // the store is invisible, so the plane manager converges it and nothing reads as another repository's.
        api.seedGrant(other, "owner", "trust:$legacyId")
        val sandbox = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: workloadIdentityTrust, name: pr-ci, environment: ci-sbx, spec: { provider: github_actions, github: { repository: acme/pr }, scopes: [tenant:applications.read] } }")
        val row = engine().plan(sandbox, true).changes.first()
        assertThat(row.action).isEqualTo(ChangeAction.NOOP)
        assertThat(row.access).isEqualTo(Access.MANAGER.label)
        assertThat(row.owner).isNull()
        assertThat(row.trust).doesNotContainKey("owner")

        // A production create from CI: no trust object to name, so the person's rule alone — never an owner-by-name item.
        val production = engine().plan(file(starters.lines().takeWhile { !it.contains("kind: application") }.joinToString("\n")), false).changes.single()
        assertThat(production.error).isEqualTo(ProvisionEngine.ERROR_TRUST_PRODUCTION_PERSON)
        assertThat(production.fix).isNull()
    }

    @Test
    fun `thoryn access accepts trust objects — a workspace admin hands a repository its trust with owner trust id`() {
        assertThat(AccessRefs.validate(repo, "owner", "trust:3f1c2a9e-7b1d-4c55-9b8e-1f0a2b3c4d5e")).isNull()
        assertThat(AccessRefs.OWNABLE_TYPES).contains("trust")
    }
}
