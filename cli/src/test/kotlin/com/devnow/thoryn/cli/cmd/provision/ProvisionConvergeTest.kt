package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ApplyResult
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
 * and a resource that already exists is a no-op / update by its key (SSO-3715 — no adopt, no receipt).
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

    /** apply → returns what was applied; the fake records writes. */
    private fun apply(f: ProvisionFile, env: Map<String, String> = emptyMap(), prune: Boolean = false): ApplyResult {
        val e = engine(env)
        return e.apply(f, e.plan(f, prune), "acme", null)
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
        val first = apply(f, mapOf("SMTP_PASSWORD" to "s3cret"))
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
        assertThat(first.resources.map { it.action }).allMatch { it == ChangeAction.CREATE }

        api.reset()
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(f, false)
        assertThat(plan.changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        assertThat(plan.hasChanges).isFalse()
        val second = apply(f, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes).isEmpty()
        assertThat(second.resources.map { it.id }).isEqualTo(first.resources.map { it.id })
    }

    @Test
    fun `a changed spec issues exactly one update carrying only the changed fields`() {
        val first = apply(file(base), mapOf("SMTP_PASSWORD" to "s3cret"))
        api.reset()
        val changed = file(
            base.replace("redirectUris: [\"http://127.0.0.1/callback\"]", "redirectUris: [\"http://127.0.0.1/cb2\"]")
                .replace("emailVerified: true", "emailVerified: false")
                .replace("displayName: \"CI sandbox\"", "displayName: \"CI sandbox v2\"")
                .replace("fromAddress: no-reply@example.com", "fromAddress: hello@example.com")
                .replace("primaryColor: \"#0f62fe\"", "primaryColor: \"#ff0000\"")
                .replace("clientId: \"okta-cid\"", "clientId: \"okta-cid-2\""),
        )
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(changed, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").diff.keys).containsExactly("redirectUris")
        assertThat(byKey.getValue("user/tester").diff.keys).containsExactly("emailVerified")
        assertThat(byKey.getValue("environment/ci").diff.keys).containsExactly("displayName")
        assertThat(byKey.getValue("emailProvider/emailProvider").diff.keys).containsExactly("fromAddress")
        assertThat(byKey.getValue("loginTheme/loginTheme").diff.keys).containsExactly("primaryColor")
        assertThat(byKey.getValue("federationMember/okta").diff.keys).containsExactly("clientId")
        assertThat(byKey.getValue("loginFlow/loginFlow").action).isEqualTo(ChangeAction.NOOP)

        val second = apply(changed, mapOf("SMTP_PASSWORD" to "s3cret"))
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
        apply(changed, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a resource deleted out of band is re-created, and an out-of-band login-flow change is not detected — a loginFlow converges by existence`() {
        val f = file(base)
        val first = apply(f, mapOf("SMTP_PASSWORD" to "s3cret"))
        api.applications.clear()               // someone deleted the client in the console
        api.activeFlow["ci-sbx"] = 999        // someone activated another flow
        api.reset()
        val plan = engine(mapOf("SMTP_PASSWORD" to "s3cret")).plan(f, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.CREATE)
        assertThat(byKey.getValue("application/rp").reason).contains("not found by its converge key")
        // SSO-3715 — the active flow does not record its template and there is no ledger to remember a version by: an
        // active flow IS the match (the documented limit; `import` says the same), so a flow activated out of band stays.
        assertThat(byKey.getValue("loginFlow/loginFlow").action).isEqualTo(ChangeAction.NOOP)
        assertThat(byKey.getValue("loginFlow/loginFlow").liveId).isEqualTo("999")
        val second = apply(f, mapOf("SMTP_PASSWORD" to "s3cret"))
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/applications")
        assertThat(second.resources.first { it.kind == "application" }.id).isNotEqualTo(first.resources[1].id)
    }

    @Test
    fun `an existing resource converges by its key — a live match is a no-op or an update, and a founder's destroy removes what nobody owns`() {
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
        val plan = engine().plan(f, false)
        val byKey = plan.changes.associateBy { "${it.kind}/${it.name}" }
        assertThat(byKey.getValue("environment/ci").action).isEqualTo(ChangeAction.NOOP)
        assertThat(byKey.getValue("application/rp").action).isEqualTo(ChangeAction.UPDATE)
        assertThat(byKey.getValue("application/rp").reason).startsWith("exists — 1 field(s) differ")
        assertThat(byKey.getValue("user/tester").action).isEqualTo(ChangeAction.CREATE)

        val result = apply(f)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("PATCH /api/v1/applications/app-2", "POST /api/v1/users")
        assertThat(result.resources.map { it.key to it.action }).containsExactly("environment/ci" to ChangeAction.NOOP, "application/rp" to ChangeAction.UPDATE, "user/tester" to ChangeAction.CREATE)
        assertThat(console.toString()).doesNotContain("adopted")

        // SSO-3715 — destroy: the founder (a `member:`) manages the sandbox and the client, nobody owns them ⇒ both go; the
        // user is a non-ownable kind and goes WITH its sandbox (the hard-delete cascades; no call of its own).
        api.reset()
        val destroyPlan = engine().planDestroy(f)
        assertThat(destroyPlan.changes.map { it.key to it.action }).containsExactly("user/tester" to ChangeAction.SKIP, "application/rp" to ChangeAction.REMOVE, "environment/ci" to ChangeAction.REMOVE)
        assertThat(destroyPlan.changes.first { it.kind == "user" }.reason).contains("removed with its sandbox 'ci-sbx'")
        val outcome = engine().destroy(destroyPlan, "acme")
        assertThat(outcome.failures).isEmpty()
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/applications/app-2", "DELETE /api/v1/environments/env-1")
        assertThat(api.environments).isEmpty()
        assertThat(api.applications).isEmpty()
        assertThat(outcome.removed.map { it.key }).containsExactly("application/rp", "environment/ci")
    }

    @Test
    fun `a person's --prune removes nothing it does not own, a production-plane user is never removed, and a production removal needs the workspace confirmation`() {
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
        apply(f)
        api.reset()
        // SSO-3715 — dropped from the file: there is no ledger of "declared once", and a `member:` owns nothing on the
        // platform, so --prune has nothing to attribute to the file — one note row, no removal.
        val dropped = file("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: user, name: ops, spec: { email: ops@example.com } }\n")
        val plan = engine().plan(dropped, prune = true)
        assertThat(plan.removes).isEmpty()
        assertThat(plan.changes.single { it.kind == "prune" }.reason).contains("owns nothing on the platform")
        apply(dropped, prune = true)
        assertThat(api.writes).isEmpty()
        assertThat(api.applications).hasSize(1)

        // destroy: the production-plane user is a non-ownable kind — never removed, reported with its command; the client the
        // founder manages (nobody owns it) is removed, which needs the workspace confirmation.
        val destroy = engine().planDestroy(f)
        val user = destroy.changes.single { it.kind == "user" }
        assertThat(user.action).isEqualTo(ChangeAction.SKIP)
        assertThat(user.reason).contains("PRODUCTION plane")
        assertThat(user.byHand).contains("users")
        assertThat(destroy.removes.map { it.key }).containsExactly("application/web")
        assertThat(destroy.removesOnProductionPlane).isTrue()
        org.assertj.core.api.Assertions.assertThatThrownBy { engine().destroy(destroy, null) }
            .isInstanceOf(ProvisionException::class.java).hasMessageContaining("PRODUCTION plane")
        assertThat(api.writes).isEmpty()
        engine().destroy(destroy, "acme")
        assertThat(api.writes.single().path).startsWith("/api/v1/applications/")
        assertThat(api.writes.single().confirm).isEqualTo("acme")
        assertThat(api.users).hasSize(1)
    }

    @Test
    fun `an environment slug given as an env placeholder converges by its RESOLVED slug — twice is a no-op and a leftover sandbox is matched under its real slug`() {
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
        val first = apply(f, env)
        assertThat(first.resources[0].attributes["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("POST /api/v1/environments", "POST /api/v1/applications")
        assertThat(api.writes[0].body["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(api.writes[1].env).isEqualTo("sbx-signin-42-1")

        // Second apply: the dependant is probed in the RESOLVED sandbox, so nothing is re-created.
        api.reset()
        assertThat(apply(f, env).resources.map { it.id }).isEqualTo(first.resources.map { it.id })
        assertThat(api.writes).isEmpty()

        // A leftover sandbox with that slug is matched under its real slug, and the client inside it is found.
        api.reset()
        val plan = engine(env).plan(f, false)
        assertThat(plan.changes.map { it.action }).containsExactly(ChangeAction.NOOP, ChangeAction.NOOP)
        val matched = apply(f, env)
        assertThat(api.writes).isEmpty()
        assertThat(matched.resources[0].attributes["slug"]).isEqualTo("sbx-signin-42-1")
        assertThat(matched.resources[0].action).isEqualTo(ChangeAction.NOOP)

        // The schema itself accepts the placeholder form and still rejects a malformed literal slug.
        val schema = tools.jackson.databind.json.JsonMapper.builder().build().readTree(javaClass.getResourceAsStream(ProvisionFile.SCHEMA_RESOURCE)!!.readBytes())
        val pattern = Regex(schema["\$defs"]["resource"]["allOf"][0]["then"]["properties"]["spec"]["properties"]["slug"]["pattern"].asString())
        assertThat(pattern.matches("{{env.E2E_ENV_SLUG}}")).isTrue()
        assertThat(pattern.matches("sbx-signin-42-1")).isTrue()
        assertThat(pattern.matches("Bad_Slug")).isFalse()
    }

    @Test
    fun `loginMethods converges the sign-in allow-list as a set — PUT on create, no-op on reorder, reset on destroy`() {
        // SSO-3100 — the per-environment singleton behind `thoryn login-methods set | reset`.
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: ci
                spec: { slug: ci-sbx }
              - kind: loginMethods
                environment: ci
                spec: { methods: [password, magic_link, Passkey] }
            """,
        )
        val first = apply(f)
        assertThat(first.resources.map { it.key }).containsExactly("environment/ci", "loginMethods/loginMethods")
        val put = api.writes.single { it.path == "/api/v1/login-methods" }
        assertThat(put.method).isEqualTo("PUT")
        assertThat(put.env).isEqualTo("ci-sbx")
        // The FULL allow-list, normalised (trimmed + lower-cased), replaces whatever was stored.
        assertThat(put.body["methods"]).isEqualTo(listOf("password", "magic_link", "passkey"))
        assertThat(first.resources[1].attributes["methods"]).isEqualTo("password,magic_link,passkey")

        // Same set in a different order ⇒ no diff, no write (order is display-only).
        api.reset()
        val reordered = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, spec: { slug: ci-sbx } }
              - { kind: loginMethods, environment: ci, spec: { methods: [passkey, password, magic_link] } }
            """,
        )
        assertThat(engine().plan(reordered, false).changes.map { it.action }).allMatch { it == ChangeAction.NOOP }
        apply(reordered)
        assertThat(api.writes).isEmpty()

        // A different set ⇒ exactly one PUT carrying the new full list.
        val changed = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, spec: { slug: ci-sbx } }
              - { kind: loginMethods, environment: ci, spec: { methods: [password, magic_code] } }
            """,
        )
        val plan = engine().plan(changed, false)
        assertThat(plan.changes.first { it.kind == "loginMethods" }.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(plan.changes.first { it.kind == "loginMethods" }.diff.keys).containsExactly("methods")
        val second = apply(changed)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("PUT /api/v1/login-methods")
        assertThat(api.loginMethods["ci-sbx"]).isEqualTo(listOf("password", "magic_code"))

        // Reset out of band (stored ⇒ null) while owned ⇒ re-applied on the next apply.
        api.loginMethods.remove("ci-sbx")
        api.reset()
        apply(changed)
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("PUT /api/v1/login-methods")

        // destroy (SSO-3715): the singleton goes WITH its sandbox — the environment hard-delete cascades, no reset call of its own.
        api.reset()
        val plan2 = engine().planDestroy(changed)
        assertThat(plan2.changes.single { it.kind == "loginMethods" }.action).isEqualTo(ChangeAction.SKIP)
        assertThat(plan2.changes.single { it.kind == "loginMethods" }.reason).contains("removed with its sandbox")
        val outcome = engine().destroy(plan2, "acme")
        assertThat(outcome.failures).isEmpty()
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/environments/${second.resources[0].id}")
        assertThat(outcome.removed.map { it.key }).containsExactly("environment/ci")
    }

    @Test
    fun `an existing stored login-method policy is a no-op when it matches — and goes with its sandbox on destroy`() {
        api.seedEnvironment("ci-sbx")
        api.loginMethods["ci-sbx"] = listOf("password", "magic_link")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - { kind: environment, name: ci, spec: { slug: ci-sbx } }
              - { kind: loginMethods, environment: ci, spec: { methods: [magic_link, password] } }
            """,
        )
        val plan = engine().plan(f, false)
        assertThat(plan.changes.map { it.action }).containsExactly(ChangeAction.NOOP, ChangeAction.NOOP)
        val result = apply(f)
        assertThat(api.writes).isEmpty()
        assertThat(result.resources[1].action).isEqualTo(ChangeAction.NOOP)
        // SSO-3715 — the founder manages the sandbox and nobody owns it: destroy removes it, the policy with it (no reset call).
        engine().destroy(engine().planDestroy(f), "acme")
        assertThat(api.writes.map { it.method + " " + it.path }).containsExactly("DELETE /api/v1/environments/env-1")
    }
}
