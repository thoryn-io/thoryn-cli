package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.util.Base64

/**
 * SSO-3766 / SSO-3767 / SSO-3770 — the refusals of the application settings, where a reader meets them:
 *  - `token_exchange_not_grantable` (SSO-3767) is PREDICTED by the plan: an identity that may converge an application but
 *    does not manage its environment cannot turn token exchange ON — a red row whose fix is `manager` on the environment
 *    (an item with its `thoryn access grant` command), or a note on the production plane; turning it off or re-declaring
 *    the stored value is never refused;
 *  - every code only the API can answer is surfaced at apply as `<resource>: <code> — <what to change>`, never as the
 *    "missing scope" every bare 403 would otherwise read as.
 */
class ProvisionApplicationSettingsRefusalTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val exchange = ProvisionFile.GRANT_TOKEN_EXCHANGE
    private val clientId = "wi_repo"
    private val subject = "client:$clientId"
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
    }

    private fun engine(subject: String? = this.subject) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    /** The portal application, in the sandbox unless [environment] is null, with [extra] appended to its spec. */
    private fun portal(extra: String, environment: String? = "ci-sbx") = file(
        "apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: portal\n" +
            (environment?.let { "    environment: $it\n" } ?: "") +
            "    spec:\n      clientId: portal\n      displayName: \"Acme Portal\"\n      redirectUris: [\"https://app.acme.example/cb\"]\n" +
            "      grantTypes: [authorization_code, refresh_token, \"$exchange\"]\n" +
            extra.trimIndent().prependIndent("      "),
    )

    /** The repository's CI identity OWNS the live portal application (so it manages it) and nothing else. */
    private fun repositoryOwnsPortal(env: String? = "ci-sbx", exchangeOn: Boolean = false) {
        api.callerIsAdmin = false
        api.caller = subject
        api.seedApplication(env, "Acme Portal", listOf("https://app.acme.example/cb"), clientId = "portal")
        api.applications.single()["grantTypes"] = listOf("authorization_code", "refresh_token", exchange)
        api.applications.single()["allowTokenExchange"] = exchangeOn
        api.seedGrant(subject, "owner", "application:portal")
    }

    // ── SSO-3767 — the plan gate ──

    @Test
    fun `turning token exchange on without manager on the environment is a red plan naming that right, and apply writes nothing`() {
        repositoryOwnsPortal()
        val f = portal("allowTokenExchange: true")

        val row = engine().plan(f, false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE)
        assertThat(row.reason).contains("managing the application alone is not enough").contains("environment:$envId")
        val fix = row.fix!!
        assertThat(fix.kind).isEqualTo(FixRequest.Kind.MANAGER)
        assertThat(fix.objectRef).isEqualTo("environment:$envId")
        assertThat(fix.cli).isEqualTo("thoryn access grant $subject manager environment:$envId")

        assertThatThrownBy { apply(f) }.isInstanceOf(ProvisionException::class.java).hasMessageContaining("nothing was written")
        assertThat(api.writes).isEmpty()

        // The right the row names is the right that fixes it.
        api.seedGrant(subject, "manager", "environment:$envId")
        val fixed = engine().plan(f, false).changes.single()
        assertThat(fixed.action).isEqualTo(ChangeAction.UPDATE)
        apply(f)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowTokenExchange" to true))
    }

    @Test
    fun `turning token exchange off, or re-declaring the stored value, is never refused for the identity that manages only the application`() {
        repositoryOwnsPortal(exchangeOn = true)
        val same = engine().plan(portal("allowTokenExchange: true"), false).changes.single()
        assertThat(same.action).isEqualTo(ChangeAction.NOOP)

        val off = portal("allowTokenExchange: false")
        assertThat(engine().plan(off, false).changes.single().action).isEqualTo(ChangeAction.UPDATE)
        apply(off)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowTokenExchange" to false))
    }

    @Test
    fun `on the production plane the right is the workspace's manager — a note, never a grant to a repository identity`() {
        repositoryOwnsPortal(env = null)
        val row = engine().plan(portal("allowTokenExchange: true", environment = null), false).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.ERROR)
        assertThat(row.error).isEqualTo(ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE)
        assertThat(row.fix).isNull()
        assertThat(row.fixNote).isEqualTo(ProvisionEngine.TOKEN_EXCHANGE_WORKSPACE_NOTE)
    }

    @Test
    fun `the red plan prints the To fix block with the grant command and writes it to the fix request`() {
        repositoryOwnsPortal()
        val enc = Base64.getUrlEncoder().withoutPadding()
        seedTokens(Tokens(accessToken = enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString("""{"client_id":"$clientId","tnt":"${api.tenantId}"}""".toByteArray()) + ".sig"))
        val dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        val path = File(dir, "provision.yaml").apply { writeText(portalYaml("allowTokenExchange: true")) }
        val request = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, _, err) = runCli("provision", "plan", "--file", path.path, "--gateway", baseUrl(), "--fix-request", request.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("! application portal: ${ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE}")
        assertThat(err).contains(FixRequest.OPTION_CLI_HEADING).contains("thoryn access grant $subject manager environment:$envId")
        assertThat(request.readText()).contains("\"kind\" : \"manager\"").contains("environment:$envId").contains(ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE)
    }

    private fun portalYaml(extra: String): String =
        "apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: portal\n    environment: ci-sbx\n" +
            "    spec:\n      clientId: portal\n      displayName: \"Acme Portal\"\n      redirectUris: [\"https://app.acme.example/cb\"]\n" +
            "      grantTypes: [authorization_code, refresh_token, \"$exchange\"]\n      $extra\n"

    // ── every API-only refusal, surfaced at apply ──

    @ParameterizedTest(name = "{1} ({0}) is surfaced as the resource, the code and what to change")
    @CsvSource(
        "403, token_exchange_not_grantable, manager",
        "400, token_exchange_requires_confidential_client, a public client cannot hold it",
        "400, token_exchange_grant_required, add it to spec.grantTypes",
        "400, unsupported_authorization_details_type, check the spelling",
        "403, authorization_details_type_not_permitted, platform home workspace",
        "400, session_lifetime_requires_sliding_window, refreshTokenSlidingWindow: true",
        "400, session_lifetime_below_refresh_ttl, refresh-token TTL",
        "400, token_ttl_out_of_range, spec.refreshTokenAbsoluteMaxTtlSeconds is outside the platform bounds (3600 – 7776000 seconds)",
        "400, session_exceeds_tenant_policy, cap of 86400 seconds",
    )
    fun `an API refusal of a setting names the resource, the code and the change — never a missing scope`(status: Int, code: String, hint: String) {
        apply(portal("refreshTokenSlidingWindow: true"))
        api.nextApplicationWriteProblem = Triple(status, code, mapOf("field" to "refreshTokenAbsoluteMaxTtlSeconds", "min" to 3600, "max" to if (code == "session_exceeds_tenant_policy") 86400 else 7776000))
        val drifted = portal(
            """
            refreshTokenSlidingWindow: true
            refreshTokenAbsoluteMaxTtlSeconds: 28800
            """,
        )

        assertThatThrownBy { apply(drifted) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageStartingWith("application/portal: $code — ")
            .hasMessageContaining(hint)
            .hasMessageNotContaining("scope")
    }

    @Test
    fun `a race past the plan gate still ends with the To fix block naming manager on the environment`() {
        apply(portal("allowTokenExchange: false")) // the founder created it
        api.nextApplicationWriteProblem = Triple(403, ProvisionFile.ERR_TOKEN_EXCHANGE_NOT_GRANTABLE, emptyMap())
        assertThatThrownBy { apply(portal("allowTokenExchange: true")) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining(FixRequest.OPTION_CLI_HEADING)
            .hasMessageContaining("thoryn access grant $subject manager environment:$envId")
    }

    @Test
    fun `the platform's own refusals — an unsupported type, the access-grant type outside the home workspace, the workspace session cap, the live refresh TTL, a live public client`() {
        apply(portal("allowedAuthorizationDetailTypes: []"))
        assertThatThrownBy { apply(portal("allowedAuthorizationDetailTypes: [made_up_type]")) }
            .hasMessageStartingWith("application/portal: ${ProvisionFile.ERR_UNSUPPORTED_AUTHORIZATION_DETAILS_TYPE} — ")
        assertThatThrownBy { apply(portal("allowedAuthorizationDetailTypes: [thoryn_access_grant]")) }
            .hasMessageStartingWith("application/portal: ${ProvisionFile.ERR_AUTHORIZATION_DETAILS_TYPE_NOT_PERMITTED} — ")
            .hasMessageContaining("no grant changes this")
        api.homeWorkspace = true
        apply(portal("allowedAuthorizationDetailTypes: [thoryn_access_grant]"))
        assertThat(api.applications.single()["allowedAuthorizationDetailTypes"]).isEqualTo(listOf("thoryn_access_grant"))

        api.refreshClipSeconds["ci-sbx"] = 86_400
        val tooLong = portal("refreshTokenSlidingWindow: true\nrefreshTokenAbsoluteMaxTtlSeconds: 172800")
        assertThatThrownBy { apply(tooLong) }
            .hasMessageStartingWith("application/portal: ${ProvisionFile.ERR_SESSION_EXCEEDS_TENANT_POLICY} — ")
            .hasMessageContaining("86400")

        api.applications.single()["refreshTokenTtlSeconds"] = 86_400
        assertThatThrownBy { apply(portal("refreshTokenSlidingWindow: true\nrefreshTokenAbsoluteMaxTtlSeconds: 28800")) }
            .hasMessageStartingWith("application/portal: ${ProvisionFile.ERR_SESSION_LIFETIME_BELOW_REFRESH_TTL} — ")

        api.applications.single()["clientType"] = "public"
        assertThatThrownBy { apply(portal("allowTokenExchange: true")) }
            .hasMessageStartingWith("application/portal: ${ProvisionFile.ERR_TOKEN_EXCHANGE_REQUIRES_CONFIDENTIAL_CLIENT} — ")
    }

    @Test
    fun `an apply that hits a setting refusal tells the CLI reader the code, not the scope to log in with`() {
        apply(portal("allowTokenExchange: false"))
        api.nextApplicationWriteProblem = Triple(403, ProvisionFile.ERR_AUTHORIZATION_DETAILS_TYPE_NOT_PERMITTED, emptyMap())
        val path = File(File(tempHome.toFile(), ".thoryn").apply { mkdirs() }, "provision.yaml").apply { writeText(portalYaml("allowedAuthorizationDetailTypes: [openid_credential]")) }

        val (exit, _, err) = runCli("provision", "apply", "--file", path.path, "--gateway", baseUrl(), "--yes")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Error: application/portal: ${ProvisionFile.ERR_AUTHORIZATION_DETAILS_TYPE_NOT_PERMITTED} — ")
        assertThat(err).doesNotContain("Required scope").doesNotContain("thoryn login --scope")
    }
}
