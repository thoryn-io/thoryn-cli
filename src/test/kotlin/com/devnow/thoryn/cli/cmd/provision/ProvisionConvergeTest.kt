package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3089 (epic SSO-3087) — converge semantics per resource kind: every declared resource is read
 * LIVE by its converge key before any write, so `apply` twice issues NO writes, a changed spec issues
 * exactly ONE update carrying only the changed fields, a resource deleted out of band is re-created,
 * and a resource that already exists is ADOPTED (managed, never deleted by destroy).
 */
class ProvisionConvergeTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine(env: Map<String, String> = emptyMap()) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        env = { env[it] },
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    /** apply → returns the receipt; the fake records writes. */
    private fun apply(f: ProvisionFile, receipt: ProvisionReceipt?, env: Map<String, String> = emptyMap(), prune: Boolean = false): ProvisionReceipt {
        val e = engine(env)
        return e.apply(f, receipt, e.plan(f, receipt, prune), "acme", null) {}
    }

    private val base = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
          - kind: application
            name: rp
            environment: ci
            spec: { displayName: "RP", clientType: public, redirectUris: ["http://127.0.0.1/callback"], scopes: [openid, profile] }
          - kind: user
            name: tester
            environment: ci
            spec: { email: tester@example.com, emailVerified: true }
          - kind: federationMember
            name: okta
            environment: ci
            spec: { providerType: okta, displayName: "Okta", discoveryUrl: "https://okta.example.com/.well-known/openid-configuration", clientId: "okta-cid" }
          - kind: emailProvider
            environment: ci
            spec: { smtpHost: smtp.example.com, smtpPort: 587, fromAddress: no-reply@example.com, smtpPasswordEnv: SMTP_PASSWORD }
          - kind: loginTheme
            environment: ci
            spec: { primaryColor: "#0f62fe", theme: dark }
          - kind: loginFlow
            environment: ci
            spec: { templateId: password-passkey }
    """

    @Test
    fun `apply twice issues no writes — every kind converges by its key`() {
        val f = file(base)
        val first = apply(f, null, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(first.resources.map { it.key }).containsExactly(
            "environment/ci", "application/rp", "user/tester", "federationMember/okta", "emailProvider/emailProvider", "loginTheme/loginTheme", "loginFlow/loginFlow",
        )
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly(
            "POST /api/v1/environments", "POST /api/v1/applications", "POST /api/v1/users", "POST /api/v1/federation-members",
            "PUT /api/v1/email-provider", "PUT /api/v1/login-experience/branding",
            "POST /api/v1/login-flows/templates/password-passkey/apply", "POST /api/v1/login-flows/activate",
        )
        // Dependants were created INSIDE the sandbox.
        assertThat(api.writes.drop(1).map { it.env }).allMatch { it == "ci-sbx" }
        assertThat(first.resources.none { it.adopted }).isTrue()

        api.reset()
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(f, first, false)
        assertThat(plan.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        assertThat(plan.hasChanges).isFalse()
        val second = apply(f, first, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes).isEmpty()
        assertThat(second.resources.map { it.id }).isEqualTo(first.resources.map { it.id })
    }

    @Test
    fun `a changed spec issues exactly one update carrying only the changed fields`() {
        val first = apply(file(base), null, mapOf("SMTP_PASSWORD" to "s3cret"))
        api.reset()
        val changed = file(
            base.replace("redirectUris: [\"http://127.0.0.1/callback\"]", "redirectUris: [\"http://127.0.0.1/cb2\"]")
                .replace("emailVerified: true", "emailVerified: false")
                .replace("displayName: \"CI sandbox\"", "displayName: \"CI sandbox v2\"")
                .replace("fromAddress: no-reply@example.com", "fromAddress: hello@example.com")
                .replace("primaryColor: \"#0f62fe\"", "primaryColor: \"#ff0000\"")
                .replace("clientId: \"okta-cid\"", "clientId: \"okta-cid-2\""),
        )
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(changed, first, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").diff.keys).containsExactly("redirectUris")
        assertThat(byKey.getValue("user/tester").diff.keys).containsExactly("emailVerified")
        assertThat(byKey.getValue("environment/ci").diff.keys).containsExactly("displayName")
        assertThat(byKey.getValue("emailProvider/emailProvider").diff.keys).containsExactly("fromAddress")
        assertThat(byKey.getValue("loginTheme/loginTheme").diff.keys).containsExactly("primaryColor")
        assertThat(byKey.getValue("federationMember/okta").diff.keys).containsExactly("clientId")
        assertThat(byKey.getValue("loginFlow/loginFlow").action).isEqualTo(ChangeAction.NOOP)

        val second = apply(changed, first, mapOf("SMTP_PASSWORD" to "s3cret"))
        val writes = api.writes.associateBy { it.method + " " + it.path }
        assertThat(writes.keys).containsExactlyInAnyOrder(
            "PATCH /api/v1/environments/${first.resources[0].id}",
            "PATCH /api/v1/applications/${first.resources[1].id}",
            "PATCH /api/v1/users/${first.resources[2].id}",
            "PATCH /api/v1/federation-members/${first.resources[3].id}",
            "PUT /api/v1/email-provider",
            "PUT /api/v1/login-experience/branding",
        )
        assertThat(writes.getValue("PATCH /api/v1/applications/${first.resources[1].id}").body.keys).containsExactly("redirectUris")
        assertThat(writes.getValue("PATCH /api/v1/users/${first.resources[2].id}").body).isEqualTo(mapOf("emailVerified" to false))
        // The write-only SMTP password rides along with the singleton PUT (it can never diff on its own).
        assertThat(writes.getValue("PUT /api/v1/email-provider").body).containsEntry("smtpPassword", "s3cret").containsEntry("fromAddress", "hello@example.com")
        assertThat(second.resources.map { it.id }).isEqualTo(first.resources.map { it.id })

        api.reset()
        apply(changed, second, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a resource deleted out of band is re-created, and an out-of-band login-flow change is re-applied`() {
        val f = file(base)
        val first = apply(f, null, mapOf("SMTP_PASSWORD" to "s3cret"))
        api.applications.clear()               // someone deleted the client in the console
        api.activeFlow["ci-sbx"] = 999        // someone activated another flow
        api.reset()
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(f, first, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.CREATE)
        assertThat(byKey.getValue("application/rp").reason).contains("no longer exists")
        assertThat(byKey.getValue("loginFlow/loginFlow").action).isEqualTo(ChangeAction.UPDATE)
        val second = apply(f, first, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly(
            "POST /api/v1/applications", "POST /api/v1/login-flows/templates/password-passkey/apply", "POST /api/v1/login-flows/activate",
        )
        assertThat(second.resources.first { it.kind == "application" }.id).isNotEqualTo(first.resources[1].id)
    }

    @Test
    fun `an existing resource is adopted by its key — converged, never deleted by destroy`() {
        api.seedEnvironment("ci-sbx", "CI sandbox")
        api.seedApplication("ci-sbx", "RP", listOf("http://127.0.0.1/old"))
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx, displayName: "CI sandbox" }
              - kind: application
                name: rp
                environment: ci
                spec: { displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
              - kind: user
                name: tester
                environment: ci
                spec: { email: tester@example.com, emailVerified: true }
            """,
        )
        val plan = engine().plan(f, null, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("environment/ci").action).isEqualTo(ChangeAction.ADOPT)
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").adopted).isTrue()
        assertThat(byKey.getValue("user/tester").action).isEqualTo(ChangeAction.CREATE)

        val receipt = apply(f, null)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("PATCH /api/v1/applications/app-2", "POST /api/v1/users")
        assertThat(receipt.resources.map { it.key to it.adopted }).containsExactly("environment/ci" to true, "application/rp" to true, "user/tester" to false)
        assertThat(console.toString()).contains("adopted")

        api.reset()
        val outcome = engine().destroy(receipt, "acme") {}
        assertThat(outcome.failures).isEmpty()
        // Only the user this file CREATED is deleted; the adopted env + app survive.
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/users/u-3")
        assertThat(api.environments).hasSize(1)
        assertThat(api.applications).hasSize(1)
        assertThat(outcome.remaining.resources).isEmpty()
    }

    @Test
    fun `prune never deletes an adopted resource and destroy still gates the production plane`() {
        api.seedApplication(null, "Web")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: web
                spec: { displayName: "Web", redirectUris: ["http://127.0.0.1/callback"] }
              - kind: user
                name: ops
                spec: { email: ops@example.com }
            """,
        )
        val receipt = apply(f, null)
        assertThat(receipt.resources.first { it.kind == "application" }.adopted).isTrue()
        api.reset()
        val dropped = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: user, name: ops, spec: { email: ops@example.com } }\n")
        val plan = engine().plan(dropped, receipt, prune = true)
        val app = plan.changes.first { it.kind == "application" }
        assertThat(app.action).isEqualTo(ChangeAction.SKIP)
        assertThat(app.reason).contains("adopted")
        val after = apply(dropped, receipt, prune = true)
        assertThat(api.writes).isEmpty()
        assertThat(after.resources.map { it.key }).containsExactly("user/ops")

        // The created user lives on the production plane → destroy needs the workspace confirmation.
        org.assertj.core.api.Assertions.assertThatThrownBy { engine().destroy(after, null) {} }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("PRODUCTION plane")
        engine().destroy(after, "acme") {}
        assertThat(api.writes.single().confirm).isEqualTo("acme")
    }

    @Test
    fun `an environment slug given as an env placeholder converges by its RESOLVED slug — twice is a no-op and adoption records the real slug`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: sandbox
                spec: { slug: "{{env.E2E_ENV_SLUG}}", displayName: "e2e sandbox" }
              - kind: application
                name: rp
                environment: sandbox
                spec: { displayName: "RP", redirectUris: ["http://127.0.0.1/callback"] }
            """,
        )
        val env = mapOf("E2E_ENV_SLUG" to "sbx-signin-42-1")
        val first = apply(f, null, env)
        assertThat(first.resources[0].attributes["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/environments", "POST /api/v1/applications")
        assertThat(api.writes[0].body["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(api.writes[1].env).isEqualTo("sbx-signin-42-1")

        // Second apply: the dependant is probed in the RESOLVED sandbox, so nothing is re-created.
        api.reset()
        assertThat(apply(f, first, env).resources.map { it.id }).isEqualTo(first.resources.map { it.id })
        assertThat(api.writes).isEmpty()

        // A leftover sandbox with that slug (no receipt) is adopted under its real slug, and the client inside it is found.
        api.reset()
        val plan = engine(env).plan(f, null, false)
        assertThat(plan.changes.map { it.action }).containsExactly(ChangeAction.ADOPT, ChangeAction.ADOPT)
        val adopted = apply(f, null, env)
        assertThat(api.writes).isEmpty()
        assertThat(adopted.resources[0].attributes["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(adopted.resources[0].adopted).isTrue()

        // The schema itself accepts the placeholder form and still rejects a malformed literal slug.
        val schema = tools.jackson.databind.json.JsonMapper.builder().build().readTree(javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)!!.readBytes())
        val pattern = Regex(schema["\$defs"]["resource"]["allOf"][0]["then"]["properties"]["spec"]["properties"]["slug"]["pattern"].asString())
        assertThat(pattern.matches("{{env.E2E_ENV_SLUG}}")).isTrue()
        assertThat(pattern.matches("sbx-signin-42-1")).isTrue()
        assertThat(pattern.matches("Bad_Slug")).isFalse()
    }
}
