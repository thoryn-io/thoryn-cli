package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.util.Base64

/**
 * SSO-3962 (epic SSO-3960; oauthy ADR 2026-10-25 provisioning-is-tenant-and-applications) through the CLI: a file of one
 * part that declares a kind of the other is refused before any call (exit 64, naming both parts and the project the
 * declaration belongs in); a mixed `thoryn.io/provision/v1` file plans and applies with a `Warning:` on stderr naming
 * the part it should declare; `publishTo:` warns; the plan preflight states an application file's scope ceiling; and
 * `thoryn provision split` writes a mixed file as its tenant and application files.
 */
class ProvisionFilePartCommandTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private fun write(name: String, body: String): File =
        File(tempHome.toFile(), ".thoryn/$name").also { it.parentFile.mkdirs(); it.writeText(body.trimIndent() + "\n") }

    private val application = """
        - kind: application
          name: web
          spec: { displayName: Web, clientType: public, grantTypes: [authorization_code], redirectUris: ["https://web.example/callback"] }
    """
    private val role = """
        - kind: role
          name: editor
          spec: { permissions: [docs:write] }
    """

    private fun doc(apiVersion: String, vararg resources: String) = "apiVersion: $apiVersion\nresources:\n" + resources.joinToString("") { it.trimIndent().prependIndent("  ") + "\n" }

    @Test
    fun `an application file declaring a tenant kind is refused before any call, naming the parts and the config project`() {
        val f = write("application.yaml", doc(ProvisionFile.API_VERSION_APPLICATION, application, role))
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(plan.err)
            .contains("invalid provisioning file")
            .contains("`role` is tenant provisioning; this is an application file (thoryn.io/application/v1). Declare it in the workspace's config project")
        assertThat(api.requests).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a tenant file declaring an application is refused before any call, naming the parts and the app project`() {
        val f = write("tenant.yaml", doc(ProvisionFile.API_VERSION_TENANT, role, application))
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(apply.err).contains("`application` is application provisioning; this is a tenant file (thoryn.io/tenant/v1). Declare it in the application's own project")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a part file plans without a warning, a mixed file plans with the warning naming the part it should declare`() {
        val part = write("application.yaml", doc(ProvisionFile.API_VERSION_APPLICATION, application))
        val clean = runCli("provision", "plan", "--file", part.path, "--gateway", baseUrl())
        assertThat(clean.exit).withFailMessage("%s", clean.err).isEqualTo(0)
        assertThat(clean.err).doesNotContain("Warning")
        assertThat(clean.out).contains("application  web   create  not found by its converge key")

        val mixed = write("provision.yaml", doc(ProvisionFile.API_VERSION, application))
        val warned = runCli("provision", "plan", "--file", mixed.path, "--gateway", baseUrl())
        assertThat(warned.exit).withFailMessage("%s", warned.err).isEqualTo(0)
        assertThat(warned.err)
            .startsWith("Warning: ${mixed.path}: apiVersion thoryn.io/provision/v1 is deprecated (accepted for one more release")
            .contains("This file declares only application kinds — declare `apiVersion: thoryn.io/application/v1`.")
        // The warning never lands on stdout — `--output json` keeps its one document.
        val structured = runCli("provision", "plan", "--file", mixed.path, "--gateway", baseUrl(), "--output", "json")
        assertThat(structured.out).doesNotContain("Warning").startsWith("{")
        assertThat(structured.err).contains("Warning:")
    }

    @Test
    fun `publishTo warns as deprecated on plan and apply, and still publishes`() {
        val gh = FakeGhVariables()
        ProvisionCommand.ghRunner = { gh }
        val f = write(
            "application.yaml",
            doc(
                ProvisionFile.API_VERSION_APPLICATION,
                """
                - kind: application
                  name: billing-web
                  spec: { displayName: Billing, clientType: public, grantTypes: [authorization_code], redirectUris: ["https://billing.example/callback"] }
                  publishTo:
                    - { kind: githubActionsVariable, repository: acme/billing-web, environment: production, name: THORYN_PRODUCTION_CLIENT_ID }
                """,
            ),
        )
        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.exit).withFailMessage("%s", apply.err).isEqualTo(0)
        assertThat(apply.err)
            .contains("Warning: ${f.path}: publishTo is deprecated (accepted for one more release")
            .contains("creation slot").contains("Declared on: application/billing-web")
            .doesNotContain("apiVersion thoryn.io/provision/v1 is deprecated")
        assertThat(gh.calls).anyMatch { it.contains("THORYN_PRODUCTION_CLIENT_ID") }
    }

    @Test
    fun `the plan preflight of an application file states its ceiling — the three scopes, and nothing else`() {
        val wi = "wi_0000000000000000000ci0cd"
        val enc = Base64.getUrlEncoder().withoutPadding()
        val scope = "tenant:access.read"
        val token = enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." +
            enc.encodeToString("""{"client_id":"$wi","scope":"$scope","tnt":"${api.tenantId}"}""".toByteArray()) + ".sig"
        seedTokens(
            Tokens(
                accessToken = token, authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = wi, issuer = "https://thoryn.auth.stg.thoryn.org",
                gateway = baseUrl(), workspace = "thoryn", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
        val f = write("application.yaml", doc(ProvisionFile.API_VERSION_APPLICATION, application))
        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(plan.err)
            .contains("Error: config.trust-scopes — this session's token does not carry 1 scope(s)")
            .contains("tenant:applications.read — application/web (read its live state)")
            .contains("An application file (thoryn.io/application/v1) needs tenant:applications.read + tenant:access.read to plan and tenant:applications.write to apply, and nothing else.")
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `split writes a mixed file as a tenant file and an application file, leaves the source alone, and refuses to overwrite or to split a part file`() {
        val source = write(
            "provision.yaml",
            """
            # a hand-written header
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
              - kind: application
                name: rp
                environment: ci
                spec: { displayName: "RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
              - kind: user
                name: tester
                environment: "{{env.THORYN_ENVIRONMENT}}"
                spec: { email: tester@example.com, passwordEnv: TEST_USER_PASSWORD }
            """,
        )
        val before = source.readText()
        val split = runCli("provision", "split", "--file", source.path)
        assertThat(split.exit).withFailMessage("%s", split.err).isEqualTo(0)
        assertThat(split.out)
            .contains("tenant       ${File(source.parentFile, "tenant.provision.yaml").path}  (thoryn.io/tenant/v1): environment/ci, user/tester")
            .contains("application  ${File(source.parentFile, "application.provision.yaml").path}  (thoryn.io/application/v1): application/rp")
            .contains("was not changed; the outputs are re-rendered, so its comments are not carried over")
        assertThat(source.readText()).isEqualTo(before)

        val tenant = ProvisionFile.parse(File(source.parentFile, "tenant.provision.yaml").readBytes(), "tenant", env = null)
        assertThat(tenant.part).isEqualTo(ProvisionPart.TENANT)
        assertThat(tenant.warnings).isEmpty()
        assertThat(tenant.resources.map { it.key }).containsExactly("environment/ci", "user/tester")
        // Copied as written: the placeholder is not resolved, the secret stays an env-var name.
        assertThat(tenant.resources[1].environment).isEqualTo("{{env.THORYN_ENVIRONMENT}}")
        assertThat(tenant.resources[1].spec).containsEntry("passwordEnv", "TEST_USER_PASSWORD")
        val app = ProvisionFile.load(File(source.parentFile, "application.provision.yaml"))
        assertThat(app.part).isEqualTo(ProvisionPart.APPLICATION)
        assertThat(app.resources.single().key).isEqualTo("application/rp")
        assertThat(app.resources.single().environment).isEqualTo("ci")

        val again = runCli("provision", "split", "--file", source.path)
        assertThat(again.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(again.err).contains("already exists — move it aside, or re-run with --force")
        val forced = runCli("provision", "split", "--file", source.path, "--force")
        assertThat(forced.exit).isEqualTo(0)

        val part = runCli("provision", "split", "--file", File(source.parentFile, "application.provision.yaml").path)
        assertThat(part.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(part.err).contains("already declares apiVersion thoryn.io/application/v1 — an application file is one part; only a thoryn.io/provision/v1 (mixed) file is split")
    }

    @Test
    fun `split of a file with one part writes one file and says why the other is not written`() {
        val source = write("provision.yaml", doc(ProvisionFile.API_VERSION, application))
        val split = runCli("provision", "split", "--file", source.path, "--application-file", File(tempHome.toFile(), "out/app.yaml").path)
        assertThat(split.exit).withFailMessage("%s", split.err).isEqualTo(0)
        assertThat(split.out).contains("tenant       not written — the source declares no tenant kind")
        assertThat(File(source.parentFile, "tenant.provision.yaml")).doesNotExist()
        assertThat(ProvisionFile.load(File(tempHome.toFile(), "out/app.yaml")).part).isEqualTo(ProvisionPart.APPLICATION)
    }

    @Test
    fun `a fresh file written by import declares the part of its entries`() {
        assertThat(ProvisionYamlEdit.apiVersionFor(listOf("environment", "user", "role"))).isEqualTo(ProvisionFile.API_VERSION_TENANT)
        assertThat(ProvisionYamlEdit.apiVersionFor(listOf("application", "application"))).isEqualTo(ProvisionFile.API_VERSION_APPLICATION)
        assertThat(ProvisionYamlEdit.apiVersionFor(listOf("environment", "application"))).isEqualTo(ProvisionFile.API_VERSION)
        assertThat(ProvisionYamlEdit.fresh("  - kind: application\n", ProvisionFile.API_VERSION_APPLICATION)).startsWith("apiVersion: thoryn.io/application/v1\nresources:\n")
    }
}
