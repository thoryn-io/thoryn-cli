package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.util.Base64

/**
 * SSO-3926 — `config.trust-scopes` at run time. thoryn-cicd's plan (run 39917407017, cli-v0.43.0) died mid-plan with
 * `workloadIdentityTrust/forge-oauth2-proxy-pod: could not read live state (HTTP 403: access_denied …)`: the repository
 * trust's plan profile lacked `tenant:workload-identity.read`. Now:
 *
 *  - `provision plan` holds the scopes the file needs to plan against the session's token BEFORE the first call, and names
 *    the scope and the profile to add it to (the trust's plan profile, for a plan-profile job);
 *  - a `403` that happens anyway (a token whose scopes the CLI cannot read) is rendered the same way, never as the generic
 *    "could not read live state (HTTP 403 …)";
 *  - `provision apply` holds the WRITES its plan makes against the token (here the `workloadPull` sink's `manager` grant,
 *    `tenant:access.write` — the SSO-3921 gap) before the first write, naming the trust's apply profile, and a write `403`
 *    is named the same way.
 *
 * The fake product-api enforces the controllers' scope gates ([FakeProductApi.enforceScopeGates]) from its own table, so
 * the `403` here is the one product-api answers, not one the engine expects.
 */
class ProvisionTrustScopesTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val wi = "wi_0000000000000000000ci0cd"

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.enforceScopeGates = true
    }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private val trustFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-login
            spec: { clientId: forge-login, displayName: "Forge login", grantTypes: [authorization_code], redirectUris: ["https://forge.example/oauth2/callback"] }
            secretSink: { kind: workloadPull, trust: forge-pod }
          - kind: workloadIdentityTrust
            name: forge-pod
            spec: { provider: kubernetes, kubernetes: { issuer: "https://oidc.example/cluster", namespace: forge, serviceAccount: forge-login }, scopes: [tenant:applications.write], confirmProduction: true }
    """

    private fun file(yaml: String): File = File(tempHome.toFile(), ".thoryn/provision.yaml").apply {
        parentFile.mkdirs()
        writeText(yaml.trimIndent() + "\n")
    }

    /** A repository identity's workload session; [scope] null ⇒ an opaque token whose scopes the CLI cannot read. */
    private fun session(profile: String, scope: String?) {
        val token = scope?.let {
            val enc = Base64.getUrlEncoder().withoutPadding()
            enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." +
                enc.encodeToString("""{"client_id":"$wi","scope":"$it","tnt":"${api.tenantId}"}""".toByteArray()) + ".sig"
        } ?: "opaque-token"
        seedTokens(
            Tokens(
                accessToken = token, authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = wi,
                issuer = "https://thoryn.auth.stg.thoryn.org", gateway = baseUrl(), workspace = "thoryn", profile = profile,
                jobEnvironment = if (profile == Tokens.PROFILE_PLAN) "forge-plan" else "forge", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    private val planProfile = "tenant:applications.read tenant:access.read"

    @Test
    fun `a plan-profile token without workload-identity read is refused before the first call, naming the scope and the trust's plan profile`() {
        api.callerScopes = planProfile.split(' ').toSet()
        session(Tokens.PROFILE_PLAN, planProfile)

        val plan = runCli("provision", "plan", "--file", file(trustFile).path, "--gateway", baseUrl())

        assertThat(plan.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(plan.err)
            .contains("Error: config.trust-scopes — this session's token does not carry 1 scope(s)")
            .contains("needs to plan:")
            .contains("tenant:workload-identity.read — application/forge-login (resolve secretSink.trust 'forge-pod' by name); workloadIdentityTrust/forge-pod (read its live state)")
            .contains("To fix: add tenant:workload-identity.read to the plan profile of trust $wi — the read-only scopes a job in GitHub environment 'forge-plan' is minted")
            .contains("Nothing was read or written.")
            .doesNotContain("HTTP 403")
        assertThat(api.requests).isEmpty()

        // The control: the same file plans once the profile carries it (the pod's trust exists, as it does for thoryn-cicd).
        api.seedTrust(null, "forge-pod", "kubernetes", listOf("tenant:applications.write"), mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "forge", "serviceAccount" to "forge-login"))
        val withRead = "$planProfile tenant:workload-identity.read"
        api.callerScopes = withRead.split(' ').toSet()
        session(Tokens.PROFILE_PLAN, withRead)
        val green = runCli("provision", "plan", "--file", file(trustFile).path, "--gateway", baseUrl())
        assertThat(green.err).doesNotContain("config.trust-scopes")
        assertThat(green.exit).withFailMessage("%s", green.err).isEqualTo(0)
        assertThat(api.requests).contains("GET /api/v1/workload-identity/trusts")
    }

    @Test
    fun `a 403 access_denied met mid-plan names the scope and the plan profile — never could not read live state (HTTP 403)`() {
        // The token's scopes are unreadable (opaque), so nothing is known up front: the API's own refusal is what is met.
        api.callerScopes = planProfile.split(' ').toSet()
        session(Tokens.PROFILE_PLAN, null)

        val plan = runCli("provision", "plan", "--file", file(trustFile).path, "--gateway", baseUrl())

        assertThat(plan.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(plan.err)
            .contains("Error: config.trust-scopes — ")
            .contains("product-api refused it (HTTP 403) because the token does not carry tenant:workload-identity.read")
            .contains("To fix: add tenant:workload-identity.read to the plan profile of trust $wi")
            .doesNotContain("could not read live state (HTTP 403")
        assertThat(api.requests).anyMatch { it.startsWith("GET /api/v1/workload-identity/trusts") }
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `every live read a plan makes names the scope its 403 was about — the kind's read, a sink's or binding's trust list, the ownership check`() {
        session(Tokens.PROFILE_PLAN, null)
        val app = "- { kind: application, name: a, spec: { displayName: A, clientType: public, redirectUris: [\"https://a.example/cb\"] } }"
        data class Case(val yaml: String, val held: Set<String>, val expected: String)
        val cases = listOf(
            Case(app, setOf("tenant:access.read"), "application/a: could not read live state: product-api refused it (HTTP 403) because the token does not carry tenant:applications.read"),
            Case(
                "- { kind: application, name: pulled, spec: { displayName: P, redirectUris: [\"https://p.example/cb\"] }, secretSink: { kind: workloadPull, trust: forge-pod } }",
                setOf("tenant:applications.read", "tenant:access.read"),
                "application/pulled: could not list the trusts of the production plane to resolve secretSink.trust 'forge-pod': product-api refused it (HTTP 403) because the token does not carry tenant:workload-identity.read",
            ),
            Case(
                "- { kind: application, name: bound, spec: { displayName: B, redirectUris: [\"https://b.example/cb\"], clientAuthenticationMethods: [federated_assertion], federatedTrust: forge-pod } }",
                setOf("tenant:applications.read", "tenant:access.read"),
                "application/bound: could not list the trusts of the production plane to resolve spec.federatedTrust 'forge-pod': product-api refused it (HTTP 403) because the token does not carry tenant:workload-identity.read",
            ),
            Case(
                "- { kind: customDomain, spec: { host: login.acme.example } }",
                setOf("tenant:access.read"),
                "customDomain/customDomain: could not read live state: product-api refused it (HTTP 403) because the token does not carry tenant:domains.read",
            ),
            Case(app, setOf("tenant:applications.read"), "could not check this identity's access — ownership is decided by the relation it holds on each resource (`POST /api/v1/access/check`): product-api refused it (HTTP 403) because the token does not carry tenant:access.read"),
        )
        cases.forEach { c ->
            api.callerScopes = c.held
            val plan = runCli("provision", "plan", "--file", file("apiVersion: thoryn.io/provision/v1\nresources:\n  ${c.yaml}").path, "--gateway", baseUrl())
            assertThat(plan.exit).withFailMessage("%s\n%s", c.yaml, plan.err).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
            assertThat(plan.err).withFailMessage("%s\n%s", c.yaml, plan.err).contains("Error: config.trust-scopes — ${c.expected}").contains("To fix: add ")
        }
    }

    @Test
    fun `apply names a write scope its plan needs — the workloadPull grant's access write — on the trust's apply profile, before any write`() {
        api.seedTrust(null, "forge-pod", "kubernetes", listOf("tenant:applications.write"), mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "forge", "serviceAccount" to "forge-login"))
        val applyProfile = "tenant:applications.read tenant:applications.write tenant:workload-identity.read tenant:workload-identity.write tenant:access.read"
        api.callerScopes = applyProfile.split(' ').toSet()
        session(Tokens.PROFILE_APPLY, applyProfile)

        val apply = runCli("provision", "apply", "--file", file(trustFile).path, "--gateway", baseUrl(), "--yes")

        assertThat(apply.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(apply.err)
            .contains("Error: config.trust-scopes — this session's token does not carry 1 scope(s)")
            .contains("needs to apply:")
            .contains("tenant:access.write — application/forge-login (converge 1 grant change(s))")
            .contains("To fix: add tenant:access.write to the scopes of trust $wi (its apply profile) and to auth.scopes of its connection.json")
            .contains("Nothing was changed.")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a write 403 met during apply names the kind's write scope on the apply profile`() {
        // Opaque token: no preflight, so the create meets the gate (the token holds no applications.write).
        api.callerScopes = setOf("tenant:applications.read", "tenant:access.read", "tenant:access.write")
        session(Tokens.PROFILE_APPLY, null)
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: spa
                spec: { displayName: SPA, clientType: public, redirectUris: ["https://spa.example/cb"] }
            """,
        )

        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")

        assertThat(apply.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(apply.err)
            .contains("Error: config.trust-scopes — application/spa: could not create it: product-api refused it (HTTP 403) because the token does not carry tenant:applications.write")
            .contains("To fix: add tenant:applications.write to the scopes of trust $wi (its apply profile)")
        assertThat(api.applications).isEmpty()
    }

    @Test
    fun `a grant write 403 met during apply names access write on the apply profile — the application stays`() {
        api.seedTrust(null, "forge-pod", "kubernetes", listOf("tenant:applications.write"), mapOf("issuer" to "https://oidc.example/cluster", "namespace" to "forge", "serviceAccount" to "forge-login"))
        api.callerScopes = setOf("tenant:applications.read", "tenant:applications.write", "tenant:workload-identity.read", "tenant:access.read")
        session(Tokens.PROFILE_APPLY, null)

        val apply = runCli("provision", "apply", "--file", file(trustFile).path, "--gateway", baseUrl(), "--yes")

        assertThat(apply.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(apply.err)
            .contains("Error: config.trust-scopes — application/forge-login: could not converge the grants on application:forge-login (grants are NOT converged): product-api refused it (HTTP 403) because the token does not carry tenant:access.write")
            .contains("To fix: add tenant:access.write to the scopes of trust $wi (its apply profile)")
        assertThat(api.applications.map { it["clientId"] }).containsExactly("forge-login")
    }

    @Test
    fun `a scope only some plans need never blocks up front — a converged sandbox application plans without environments read`() {
        // Resolving the sandbox's id is needed for a create in it (or indirect reach), not for a resource this identity manages.
        api.seedEnvironment("ci", "CI")
        api.seedApplication("ci", "RP", listOf("https://rp.example/cb"), clientId = "rp")
        val held = "tenant:applications.read tenant:access.read"
        api.callerScopes = held.split(' ').toSet()
        session(Tokens.PROFILE_PLAN, held)
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: rp
                environment: ci
                spec: { clientId: rp, displayName: RP, redirectUris: ["https://rp.example/cb"] }
            """,
        )

        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())

        assertThat(plan.err).doesNotContain("config.trust-scopes")
        assertThat(plan.exit).withFailMessage("%s", plan.err).isEqualTo(0)
        assertThat(api.requests).noneMatch { it.startsWith("GET /api/v1/environments") }
    }
}
