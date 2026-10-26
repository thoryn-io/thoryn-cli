package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ImportOptions
import com.devnow.thoryn.provision.PlaneRouting
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3990 (thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13.5) — `provision import` renders only what the target
 * file can carry and what the identity that plans and applies it can plan and apply:
 *
 *  - part-aware: a tenant file never receives `kind: application`, an application file never a tenant kind — each object
 *    left out is listed with the reason;
 *  - scope-aware: a kind the identity cannot read is listed as not imported, naming the scope, and is never read (no `403`
 *    aborts the run, and one the CLI could not anticipate is listed the same way); an entry it cannot write is `readOnly`;
 *  - `emailProvider` / `federationMember` always `readOnly`; production-plane users never imported (counted), sandbox test
 *    users imported; the repository's own trusts never imported; plane routing across configured files.
 */
class ProvisionImportPartAndScopeTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = "client:repo"
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedApplication("ci-sbx", "Loopback RP", listOf("http://127.0.0.1/callback"), clientId = "rp")
        api.applications.last()["clientType"] = "public"
        api.users += mutableMapOf("id" to "u-9", "email" to "tester@example.com", "emailVerified" to true, "status" to "active", "_env" to "ci-sbx")
        api.loginMethods["ci-sbx"] = listOf("password", "passkey")
        api.loginMethods[null] = listOf("password")
        api.seedGrant("client:repo", "manager", "environment:$envId")
        api.seedGrant("client:repo", "manager", "login_methods:production")
    }

    private fun engine(subject: String = "client:repo") = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject,
    )

    private fun tenantFile(vararg entries: String): ProvisionFile = ProvisionFile.parse(
        ("apiVersion: thoryn.io/tenant/v1\nresources:\n" + entries.joinToString("\n") { "  - $it" } + "\n").toByteArray(), "tenant.provision.yaml",
    )

    private val allScopes = setOf(
        "tenant:environments.read", "tenant:environments.write", "tenant:applications.read", "tenant:applications.write",
        "tenant:users.read", "tenant:users.write", "tenant:idp.read", "tenant:idp.write", "tenant:access.read",
        "tenant:federation.read", "tenant:federation.write", "tenant:email.read", "tenant:email.write",
    )

    @Test
    fun `a tenant file never receives kind application, and each application left out is listed with the reason`() {
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"))
        assertThat(result.resources.map { it.resource.kind }).doesNotContain(ProvisionFile.KIND_APPLICATION)
        assertThat(result.resources.map { it.resource.key }).contains("user/tester", "loginMethods/loginMethods")
        assertThat(result.skipped).anySatisfy { assertThat(it).startsWith("application:rp — not imported: a tenant file (thoryn.io/tenant/v1) does not carry kind application") }
        // Listed from the reach index alone: the application itself was never read.
        assertThat(api.requests).noneMatch { it.startsWith("GET /api/v1/applications/rp") }
    }

    @Test
    fun `an application file never receives a tenant kind, and lists every tenant object it left out`() {
        val appFile = ProvisionFile.parse(
            "apiVersion: thoryn.io/application/v1\nresources:\n  - { kind: application, name: other, spec: { clientId: other, displayName: Other } }\n".toByteArray(),
            "application.provision.yaml",
        )
        val result = engine().import(appFile)
        assertThat(result.resources.map { it.resource.kind }.toSet()).containsExactly(ProvisionFile.KIND_APPLICATION)
        assertThat(result.resources.map { it.liveId }).containsExactly("rp")
        assertThat(result.skipped)
            .anySatisfy { assertThat(it).startsWith("environment:$envId — not imported: an application file (thoryn.io/application/v1) carries only applications") }
            .anySatisfy { assertThat(it).startsWith("user:u-9 — not imported: an application file") }
            .anySatisfy { assertThat(it).startsWith("login_methods:ci-sbx — not imported: an application file") }
            .anySatisfy { assertThat(it).startsWith("role — not imported: an application file") }
    }

    @Test
    fun `a kind the identity cannot read is listed naming the scope and never read, so no 403 aborts the import`() {
        api.enforceScopeGates = true
        api.callerScopes = allScopes - "tenant:users.read" - "tenant:users.write"
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"), ImportOptions(part = ProvisionPart.TENANT, planScopes = api.callerScopes, applyScopes = api.callerScopes))
        assertThat(result.resources.map { it.resource.key }).doesNotContain("user/tester").contains("loginMethods/loginMethods")
        assertThat(result.skipped).anySatisfy { assertThat(it).startsWith("user — not imported: this identity does not hold tenant:users.read") }
        assertThat(api.requests).noneMatch { it.startsWith("GET /api/v1/users") }
    }

    @Test
    fun `a scope 403 the CLI could not anticipate is listed as not imported and the next kind still runs`() {
        api.enforceScopeGates = true
        api.callerScopes = allScopes - "tenant:users.read" - "tenant:environments.read"
        // planScopes unknown (an opaque token): every read is attempted, and the refused ones are listed.
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"))
        assertThat(result.skipped)
            .anySatisfy { assertThat(it).startsWith("user — not imported: product-api refused a read (HTTP 403) because the token does not carry tenant:users.read") }
            .anySatisfy { assertThat(it).startsWith("environment — not imported, nor any object in a sandbox: product-api refused the listing (HTTP 403) because the token does not carry tenant:environments.read") }
        // The production plane is still imported: its login methods.
        assertThat(result.resources.map { "${it.resource.key}@${it.resource.environment}" }).containsExactly("loginMethods/loginMethods@null")
    }

    @Test
    fun `without tenant access read and with scopes unknown, every access-object kind is listed and roles are still imported`() {
        api.seedRole(null, "editor", listOf("docs:write"))
        api.enforceScopeGates = true
        api.callerScopes = allScopes - "tenant:access.read" + "tenant:roles.read" + "tenant:roles.write"
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"))
        assertThat(result.resources.map { it.resource.key }).containsExactly("role/editor")
        assertThat(result.skipped)
            .anySatisfy { assertThat(it).isEqualTo("user — not imported: product-api refused a read (HTTP 403) because the token does not carry tenant:access.read; add it to the identity that plans this file (a workload identity trust's plan profile and scopes, and connection.json auth.scopes) to import it") }
            .anySatisfy { assertThat(it).startsWith("loginMethods — not imported: product-api refused a read (HTTP 403) because the token does not carry tenant:access.read") }
    }

    @Test
    fun `an entry whose write scope the identity lacks is rendered readOnly, naming the scope`() {
        val scopes = allScopes - "tenant:idp.write"
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"), ImportOptions(part = ProvisionPart.TENANT, planScopes = scopes, applyScopes = scopes))
        val methods = result.resources.filter { it.resource.kind == ProvisionFile.KIND_LOGIN_METHODS }
        assertThat(methods).hasSize(2).allSatisfy { assertThat(it.resource.readOnly).isTrue(); assertThat(it.note).contains("does not hold tenant:idp.write") }
        assertThat(result.resources.single { it.resource.key == "user/tester" }.resource.readOnly).isFalse()
    }

    @Test
    fun `emailProvider and federationMember are always readOnly, because their secrets are write-only`() {
        api.emailProviders["ci-sbx"] = mutableMapOf("providerType" to "smtp", "smtpHost" to "smtp.example.com", "smtpPort" to 587, "fromAddress" to "no-reply@example.com")
        api.federationMembers += mutableMapOf("id" to "fm-1", "providerType" to "oidc", "displayName" to "Corp IdP", "discoveryUrl" to "https://idp.example.com", "clientId" to "corp", "_env" to "ci-sbx")
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"), ImportOptions(planScopes = allScopes, applyScopes = allScopes))
        val email = result.resources.single { it.resource.kind == ProvisionFile.KIND_EMAIL_PROVIDER }
        val member = result.resources.single { it.resource.kind == ProvisionFile.KIND_FEDERATION_MEMBER }
        assertThat(email.resource.readOnly).isTrue()
        assertThat(email.note).contains("smtpPassword is write-only").contains("smtpPasswordEnv")
        assertThat(member.resource.readOnly).isTrue()
        assertThat(member.note).contains("clientSecret is write-only").contains("clientSecretEnv")
    }

    @Test
    fun `production-plane users are never imported and are counted, sandbox test users are imported`() {
        api.users += mutableMapOf("id" to "u-1", "email" to "alice@customer.example", "status" to "active", "_env" to null)
        api.users += mutableMapOf("id" to "u-2", "email" to "bob@customer.example", "status" to "active", "_env" to null)
        api.callerIsAdmin = true
        val result = engine().import(tenantFile("{ kind: environment, name: ci, spec: { slug: ci-sbx } }"))
        val users = result.resources.filter { it.resource.kind == ProvisionFile.KIND_USER }
        assertThat(users.map { it.resource.spec["email"] }).containsExactly("tester@example.com")
        assertThat(users.single().resource.environment).isEqualTo("ci")
        assertThat(result.skipped).anySatisfy { assertThat(it).startsWith("user — 2 production-plane user(s) not imported") }
        assertThat(result.skipped.joinToString()).doesNotContain("alice").doesNotContain("bob")
    }

    @Test
    fun `the repository's own trusts — every configured connection's — are never imported`() {
        api.callerIsAdmin = true
        api.seedTrust(null, "config-production", pins = mapOf("owner" to "acme", "repository" to "acme-config", "environment" to "production"))
        val productionClient = api.trusts.last()["clientId"].toString()
        api.seedTrust("ci-sbx", "config-sandbox", pins = mapOf("owner" to "acme", "repository" to "acme-config", "environment" to "sandbox"))
        val sandboxClient = api.trusts.last()["clientId"].toString()
        api.seedTrust("ci-sbx", "app-deploy", pins = mapOf("owner" to "acme", "repository" to "acme-app", "environment" to "sandbox"))
        // Signed in as the PRODUCTION trust; the sandbox trust is the repository's too, through its other connection.
        val result = engine(subject = "client:$productionClient").import(null, ImportOptions(ownTrustClients = setOf(productionClient, sandboxClient)))
        val trusts = result.resources.filter { it.resource.kind == ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST }.map { it.resource.name }
        assertThat(trusts).containsExactly("app-deploy")
        assertThat(result.skipped)
            .anySatisfy { assertThat(it).startsWith("workloadIdentityTrust:config-production — the trust this repository itself signs in with") }
            .anySatisfy { assertThat(it).startsWith("workloadIdentityTrust:config-sandbox — the trust this repository itself signs in with") }
    }

    @Test
    fun `plane routing sends a sandbox's objects to that sandbox's file and everything else to the production file`() {
        val prod = ".thoryn/environments/production/provision.yaml"
        val sbx = ".thoryn/environments/ci-sbx/provision.yaml"
        fun routing(target: String) = PlaneRouting(target, prod, mapOf("ci-sbx" to sbx))

        val toProduction = engine().import(null, ImportOptions(part = ProvisionPart.TENANT, routing = routing(prod)))
        assertThat(toProduction.resources.map { "${it.resource.key}@${it.resource.environment}" }).containsExactlyInAnyOrder("environment/ci-sbx@null", "loginMethods/loginMethods@null")
        assertThat(toProduction.skipped)
            .anySatisfy { assertThat(it).isEqualTo("user:u-9 — not imported into $prod: objects of environment 'ci-sbx' belong to $sbx (the file planned with that sandbox's connection)") }
            .anySatisfy { assertThat(it).startsWith("login_methods:ci-sbx — not imported into $prod: objects of environment 'ci-sbx' belong to $sbx") }

        val toSandbox = engine().import(null, ImportOptions(part = ProvisionPart.TENANT, routing = routing(sbx)))
        assertThat(toSandbox.resources.map { "${it.resource.key}@${it.resource.environment}" }).containsExactlyInAnyOrder("user/tester@ci-sbx", "loginMethods/loginMethods@ci-sbx")
        assertThat(toSandbox.skipped).anySatisfy { assertThat(it).isEqualTo("environment:ci-sbx — not imported into $sbx: objects of the production plane belong to $prod (the file planned with the production connection)") }

        // Every object landed in exactly one of the two files.
        val landed = (toProduction.resources + toSandbox.resources).map { it.liveId to it.resource.environment }
        assertThat(landed).doesNotHaveDuplicates().hasSize(4)
    }

    @Test
    fun `--part tenant on a file that does not exist writes a tenant file without applications`() {
        val fresh = File(tempHome.toFile(), "fresh/tenant.provision.yaml")
        val run = runCli("provision", "import", "--file", fresh.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(run.exit).isEqualTo(0)
        val written = ProvisionFile.load(fresh)
        assertThat(written.part).isEqualTo(ProvisionPart.TENANT)
        assertThat(written.resources.map { it.kind }).doesNotContain(ProvisionFile.KIND_APPLICATION).contains(ProvisionFile.KIND_ENVIRONMENT)
        assertThat(run.err).contains("skipped application:rp — not imported: a tenant file")

        val conflicting = runCli("provision", "import", "--file", fresh.path, "--gateway", baseUrl(), "--part", "application")
        assertThat(conflicting.exit).isNotEqualTo(0)
        assertThat(conflicting.err).contains("declares thoryn.io/tenant/v1")
    }
}
