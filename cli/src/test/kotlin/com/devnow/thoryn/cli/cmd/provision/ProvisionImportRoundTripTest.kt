package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowCheck
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowFixtures
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.util.Base64

/**
 * SSO-3990 — the guarantee `provision import` gives a config project (thoryn-provisioning ADR 2026-09-30, amendment
 * 2026-10-26 §13.1 step 4): what it writes plans as all `noop`, so merging the import pull request changes nothing.
 *
 *  - for EVERY kind it renders (all tenant kinds except `loginFlow`, which it lists, plus `application`), import → plan is
 *    all `noop` — including `role`, which import did not render before SSO-3990;
 *  - a fresh workspace imports nothing (its production users are counted, never imported);
 *  - `--for-workflow`, run as each configured file's own connection, writes files that pass `provision workflow check`'s
 *    `config.trust-scopes` and plan as all `noop` with that connection's plan profile.
 */
class ProvisionImportRoundTripTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private fun jwt(claims: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString(claims.toByteArray()) + ".sig"
    }

    /** A repository identity's plan-profile session as `thoryn login --connection` leaves it in a plan job. */
    private fun planSession(clientId: String, scopes: Collection<String>) {
        api.caller = "client:$clientId"
        api.callerScopes = scopes.toSet()
        seedTokens(
            Tokens(
                accessToken = jwt("""{"client_id":"$clientId","scope":"${scopes.joinToString(" ")}","tnt":"${api.tenantId}"}"""),
                authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId, issuer = "https://acme.auth.thoryn.io", gateway = baseUrl(),
                workspace = "acme", profile = Tokens.PROFILE_PLAN, jobEnvironment = "acme-production-plan", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    /** Every kind import renders, live in the fake: a founder (workspace admin) reaches all of it. */
    private fun seedEveryKind() {
        val envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedApplication("ci-sbx", "Loopback RP", listOf("http://127.0.0.1/callback"), clientId = "rp")
        api.applications.last()["clientType"] = "public"
        api.users += mutableMapOf("id" to "u-9", "email" to "tester@example.com", "emailVerified" to true, "status" to "active", "_env" to "ci-sbx")
        api.federationMembers += mutableMapOf("id" to "fm-1", "providerType" to "oidc", "displayName" to "Corp IdP", "discoveryUrl" to "https://idp.example.com", "clientId" to "corp", "_env" to "ci-sbx")
        api.emailProviders[null] = mutableMapOf("providerType" to "smtp", "smtpHost" to "smtp.example.com", "smtpPort" to 587, "fromAddress" to "no-reply@example.com", "enabled" to true)
        api.branding[null] = mutableMapOf("primaryColor" to "#112233")
        api.loginMethods["ci-sbx"] = listOf("password", "passkey")
        api.loginMethods[null] = listOf("password")
        api.activeFlow[null] = 3
        api.domainHost = "login.example.com"; api.domainState = "ACTIVE"; api.dnsPublished = true
        api.seedTrust("ci-sbx", "app-deploy", scopes = listOf("tenant:applications.read"), pins = mapOf("owner" to "acme", "repository" to "acme-app", "environment" to "sandbox"))
        api.seedRole(null, "editor", listOf("docs:write", "docs:read"), description = "Edits documents")
        api.seedRole("ci-sbx", "tester", emptyList())
        check(envId.isNotEmpty())
    }

    @Test
    fun `for every kind import renders, import then plan is all noop — and role is among them`() {
        seedEveryKind()
        val file = File(tempHome.toFile(), "every/provision.yaml")
        val imported = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl(), "--write")
        assertThat(imported.exit).withFailMessage(imported.err).isEqualTo(0)
        val written = ProvisionFile.load(file)
        assertThat(written.resources.map { it.kind }.toSet()).containsExactlyInAnyOrder(
            ProvisionFile.KIND_ENVIRONMENT, ProvisionFile.KIND_APPLICATION, ProvisionFile.KIND_USER, ProvisionFile.KIND_FEDERATION_MEMBER,
            ProvisionFile.KIND_EMAIL_PROVIDER, ProvisionFile.KIND_LOGIN_THEME, ProvisionFile.KIND_LOGIN_METHODS, ProvisionFile.KIND_CUSTOM_DOMAIN,
            ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST, ProvisionFile.KIND_ROLE,
        )
        // loginFlow is the one tenant kind it cannot render, and it says so.
        assertThat(imported.err).contains("skipped login_flow:production — a loginFlow is declared by its templateId")
        val roles = written.resources.filter { it.kind == ProvisionFile.KIND_ROLE }.associateBy { it.name }
        assertThat(roles.getValue("editor").spec).isEqualTo(mapOf("description" to "Edits documents", "permissions" to listOf("docs:read", "docs:write")))
        assertThat(roles.getValue("editor").environment).isNull()
        assertThat(roles.getValue("tester").spec).isEqualTo(mapOf("permissions" to emptyList<String>()))
        assertThat(roles.getValue("tester").environment).isEqualTo("ci-sbx")

        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).withFailMessage(plan.out + plan.err).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove, ${written.resources.size} unchanged.")
        assertThat(api.provisioningWrites).isEmpty()
    }

    @Test
    fun `a role is rendered readOnly when the identity cannot write roles, and still plans as noop`() {
        api.seedRole(null, "editor", listOf("docs:write"))
        api.enforceScopeGates = true
        val scopes = listOf("tenant:roles.read", "tenant:access.read", "tenant:environments.read")
        api.callerScopes = scopes.toSet()
        seedTokens(Tokens(accessToken = jwt("""{"sub":"founder","scope":"${scopes.joinToString(" ")}","tnt":"${api.tenantId}"}"""), gateway = baseUrl()))
        val file = File(tempHome.toFile(), "roles/tenant.provision.yaml")
        val imported = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(imported.exit).withFailMessage(imported.err).isEqualTo(0)
        val role = ProvisionFile.load(file).resources.single()
        assertThat(role.kind).isEqualTo(ProvisionFile.KIND_ROLE)
        assertThat(role.readOnly).isTrue()
        assertThat(imported.err).contains("note role editor: the identity that applies this file does not hold tenant:roles.write")
        val plan = runCli("provision", "plan", "--file", file.path, "--gateway", baseUrl())
        assertThat(plan.exit).withFailMessage(plan.out + plan.err).isEqualTo(0)
        assertThat(plan.out).contains("0 to create, 0 to update, 0 to remove, 1 unchanged.")
    }

    @Test
    fun `a fresh workspace imports nothing — its founder, a production-plane user, is counted and never imported`() {
        api.users += mutableMapOf("id" to "u-founder", "email" to "founder@acme.example", "status" to "active", "_env" to null)
        val file = File(tempHome.toFile(), "fresh/tenant.provision.yaml")
        val run = runCli("provision", "import", "--file", file.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(run.exit).isEqualTo(0)
        assertThat(run.out).contains("Nothing to import")
        assertThat(run.err.lines().filter { it.trimStart().startsWith("skipped") }).containsExactly(
            "  skipped user — 1 production-plane user(s) not imported: people who sign up are not configuration, and a git history cannot honour an erasure request (sandbox test users are imported)",
        )
        assertThat(file).doesNotExist()
    }

    private val wiProd = "wi_000000000000000000000p01"
    private val wiSbx = "wi_000000000000000000000s01"
    private val prodFile = ".thoryn/environments/production/provision.yaml"
    private val sbxFile = ".thoryn/environments/ci-sbx/provision.yaml"

    private fun connection(clientId: String, environment: String?, scopes: List<String>) = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "acme" },
          "auth": {
            "method": "workload_identity",
            "clientId": "$clientId",
            "audience": "https://acme.auth.thoryn.io${environment?.let { "/$it" } ?: ""}",
            "scopes": [${scopes.joinToString(", ") { "\"$it\"" }}],
            "github": { "repository": "acme-config", "environment": "acme-${environment ?: "production"}" }
          }
        }
    """.trimIndent() + "\n"

    @Test
    fun `--for-workflow imports each configured file as its own connection, and every file passes config trust-scopes and plans all noop`() {
        val envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        api.users += mutableMapOf("id" to "u-9", "email" to "tester@example.com", "emailVerified" to true, "status" to "active", "_env" to "ci-sbx")
        api.loginMethods["ci-sbx"] = listOf("password", "passkey")
        api.loginMethods[null] = listOf("password")
        api.seedRole(null, "editor", listOf("docs:write"))
        api.callerIsAdmin = false
        api.enforceScopeGates = true
        api.seedGrant("client:$wiProd", "owner", "environment:$envId") // the setup created the sandbox
        api.seedGrant("client:$wiProd", "manager", "login_methods:production")
        api.seedGrant("client:$wiSbx", "manager", "environment:$envId")

        val root = File(tempHome.toFile(), "acme-config")
        File(root, ".thoryn/environments/production").mkdirs()
        File(root, ".thoryn/environments/ci-sbx").mkdirs()
        File(root, ".thoryn/workflow.yaml").writeText(
            "apiVersion: thoryn.io/workflow/v1\nfiles:\n  - { file: $prodFile, connection: .thoryn/environments/production/connection.json }\n" +
                "  - { file: $sbxFile, connection: .thoryn/environments/ci-sbx/connection.json }\n",
        )
        // The production trust may plan the tenant's environments, login methods and roles, and write only environments.
        val prodScopes = listOf("tenant:environments.read", "tenant:environments.write", "tenant:idp.read", "tenant:access.read", "tenant:roles.read")
        val sbxScopes = listOf("tenant:environments.read", "tenant:users.read", "tenant:users.write", "tenant:idp.read", "tenant:idp.write", "tenant:access.read")
        File(root, ".thoryn/environments/production/connection.json").writeText(connection(wiProd, null, prodScopes))
        File(root, ".thoryn/environments/ci-sbx/connection.json").writeText(connection(wiSbx, "ci-sbx", sbxScopes))
        // What the setup pull request merged: the sandbox it created, nothing else.
        File(root, prodFile).writeText("apiVersion: thoryn.io/tenant/v1\nresources:\n  - { kind: environment, name: ci-sbx, spec: { slug: ci-sbx, displayName: \"CI sandbox\" } }\n")

        planSession(wiProd, prodScopes.filter { it.endsWith(".read") })
        val prod = runCli("provision", "import", "--for-workflow", prodFile, "--root", root.path, "--gateway", baseUrl(), "--write")
        assertThat(prod.exit).withFailMessage(prod.err).isEqualTo(0)
        assertThat(prod.err).doesNotContain("Warning: signed in as")
            .contains("skipped user — not imported: this identity does not hold tenant:users.read")
            .contains("skipped login_methods:ci-sbx — not imported into $prodFile: objects of environment 'ci-sbx' belong to $sbxFile")
        val prodResources = ProvisionFile.load(File(root, prodFile)).resources
        assertThat(prodResources.map { "${it.key} readOnly=${it.readOnly}" }).containsExactly(
            "environment/ci-sbx readOnly=false", "loginMethods/loginMethods readOnly=true", "role/editor readOnly=true",
        )

        planSession(wiSbx, sbxScopes.filter { it.endsWith(".read") })
        val sbx = runCli("provision", "import", "--for-workflow", sbxFile, "--root", root.path, "--gateway", baseUrl(), "--part", "tenant", "--write")
        assertThat(sbx.exit).withFailMessage(sbx.err).isEqualTo(0)
        assertThat(sbx.err).contains("skipped role — not imported: this identity does not hold tenant:roles.read")
            .contains("skipped environment:ci-sbx — not imported into $sbxFile: objects of the production plane belong to $prodFile")
        val sbxWritten = ProvisionFile.load(File(root, sbxFile))
        assertThat(sbxWritten.part).isEqualTo(ProvisionPart.TENANT)
        assertThat(sbxWritten.resources.map { "${it.key}@${it.environment} readOnly=${it.readOnly}" }).containsExactlyInAnyOrder(
            "user/tester@ci-sbx readOnly=false", "loginMethods/loginMethods@ci-sbx readOnly=false",
        )

        // config.trust-scopes, exactly as `thoryn provision workflow check` runs it, on the repository as imported.
        val rule = WorkflowCheck.evaluate(WorkflowFixtures.STUB, ".github/workflows/thoryn-provisioning.yml", root = root).rules.single { it.id == TrustScopes.RULE_ID }
        assertThat(rule.status).withFailMessage(rule.detail).isEqualTo(WorkflowCheck.Status.PASS)

        // Each file, planned by its own connection's plan profile: nothing to do.
        planSession(wiProd, prodScopes.filter { it.endsWith(".read") })
        val prodPlan = runCli("provision", "plan", "--file", File(root, prodFile).path, "--gateway", baseUrl())
        assertThat(prodPlan.exit).withFailMessage(prodPlan.out + prodPlan.err).isEqualTo(0)
        assertThat(prodPlan.out).contains("0 to create, 0 to update, 0 to remove, 3 unchanged.")
        planSession(wiSbx, sbxScopes.filter { it.endsWith(".read") })
        val sbxPlan = runCli("provision", "plan", "--file", File(root, sbxFile).path, "--gateway", baseUrl())
        assertThat(sbxPlan.exit).withFailMessage(sbxPlan.out + sbxPlan.err).isEqualTo(0)
        assertThat(sbxPlan.out).contains("0 to create, 0 to update, 0 to remove, 2 unchanged.")
        assertThat(api.provisioningWrites).isEmpty()
    }

    @Test
    fun `--for-workflow refuses a file the workflow does not configure, and two files on one plane`() {
        val root = File(tempHome.toFile(), "repo").apply { File(this, ".thoryn").mkdirs() }
        File(root, ".thoryn/a.json").writeText(connection(wiProd, null, listOf("tenant:roles.read")))
        File(root, ".thoryn/b.json").writeText(connection(wiSbx, null, listOf("tenant:roles.read")))
        File(root, ".thoryn/workflow.yaml").writeText("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - { file: .thoryn/a.yaml, connection: .thoryn/a.json }\n  - { file: .thoryn/b.yaml, connection: .thoryn/b.json }\n")
        val unknown = runCli("provision", "import", "--for-workflow", ".thoryn/c.yaml", "--root", root.path, "--gateway", baseUrl())
        assertThat(unknown.exit).isNotEqualTo(0)
        assertThat(unknown.err).contains(".thoryn/c.yaml is not a configured provisioning file").contains("configured: .thoryn/a.yaml, .thoryn/b.yaml")
        val ambiguous = runCli("provision", "import", "--for-workflow", ".thoryn/a.yaml", "--root", root.path, "--gateway", baseUrl())
        assertThat(ambiguous.exit).isNotEqualTo(0)
        assertThat(ambiguous.err).contains(".thoryn/a.yaml and .thoryn/b.yaml are all planned with a production-plane connection")
    }
}
