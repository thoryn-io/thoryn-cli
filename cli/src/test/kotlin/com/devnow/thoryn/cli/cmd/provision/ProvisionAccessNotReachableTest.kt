package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.FixRequest
import com.devnow.thoryn.provision.ProvisionEngine
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.File
import java.nio.file.Files
import java.util.Base64

/**
 * SSO-3722 — the SECOND live failure (thoryn-cicd run 38751887466): the plan job signed in under the plan profile, then
 * `provision plan` died BEFORE the ownership gate with `Error: application/forge-oauth2-proxy: could not read live state
 * (HTTP 404: unknown_environment — …)`, exit 2, no fix request. product-api's `EnvironmentClaimFilter` answers 404
 * `unknown_environment` not only for a missing environment but for one the caller has NO reach into (SSO-3118, the
 * 404-not-403 rule), so a brand-new repository identity with no relation on anything gets it on its very first read.
 *
 * The engine now treats that 404 as the missing-rights shape: a red row `access_not_reachable` whose fix is the exact
 * right — `manager` on a declared environment the identity cannot see, a note when the parent is the workspace —
 * rendered in the one "To fix" block and written to the fix request (`cli` filled) so the App's check run offers consent.
 *
 * SSO-3792 (absorbs SSO-3787; oauthy ADR 2026-10-17 §6) — a production application the file declares by a fixed
 * `clientId` is NO LONGER asked for as `owner`: a confined identity cannot tell absent from invisible, and `owner` on an
 * application that does not exist is the right PR 34's consent offered and product-api refused (`not_found`). It is a
 * creation slot (`creator`, `thoryn access reserve`); for an application that turns out to exist, the orchestrator's
 * callback answers `application_exists` with a follow-up `owner` consent (decision D1). See [ProvisionCreationSlotTest].
 */
class ProvisionAccessNotReachableTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val json = JsonMapper.builder().build()
    private val clientId = "wi_10a7b379c79f7d1353f5798d"
    private val subject = "client:$clientId"
    private lateinit var dir: File

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = subject
        // The platform's filter: no relation anywhere ⇒ every plane-scoped read is 404 unknown_environment.
        api.environmentClaimFilter = true
        api.seedEnvironment("forge", "Forge")
        api.seedApplication(null, "Forge oauth2-proxy", listOf("https://forge.example.com/oauth2/callback"), clientId = "forge-oauth2-proxy")
        // SSO-3722 — the runner's context through the seam, never the real environment (CI's own GITHUB_* would leak in).
        val runner = mapOf("GITHUB_REPOSITORY" to "thoryn-io/thoryn-cicd", "GITHUB_RUN_ID" to "38751887466")
        FixRequests.environment = { key -> if (key.startsWith("GITHUB_")) runner[key] else com.devnow.thoryn.cli.auth.WorkloadIdentityFlow.runnerEnv(key) }
        dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        session()
    }

    @AfterEach
    fun unmount() {
        FixRequests.resetEnvironmentForTest()
        System.clearProperty(FixRequest.CONSENT_URL_ENV)
    }

    /** The plan-profile session of a brand-new repository identity (a JWT without `sub`, read scopes only). */
    private fun session() {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString("""{"client_id":"$clientId","scope":"tenant:environments.read tenant:applications.read tenant:access.read","tnt":"${api.tenantId}"}""".toByteArray())
        seedTokens(
            Tokens(
                accessToken = "$header.$payload.sig", authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId,
                issuer = "https://thoryn.auth.stg.thoryn.org", gateway = baseUrl(), workspace = "thoryn", profile = Tokens.PROFILE_PLAN,
                jobEnvironment = "forge-plan", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    private fun file(yaml: String): File = File(dir, "provision.yaml").apply { writeText(yaml.trimIndent() + "\n") }

    private fun request(path: File): JsonNode = json.readTree(Files.readString(path.toPath()))

    /** The live file's shape: a production-plane application with a fixed clientId, no `environment:`. */
    private val fixedIdOnProduction = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-oauth2-proxy
            spec: { clientId: forge-oauth2-proxy, displayName: "Forge oauth2-proxy", redirectUris: ["https://forge.example.com/oauth2/callback"] }
    """

    @Test
    fun `a 404 on the first live read is a red access_not_reachable row with a creation slot as its fix — not "could not read live state", never owner`() {
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, stdout, err) = runCli("provision", "plan", "--file", file(fixedIdOnProduction).path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).doesNotContain("could not read live state")
        assertThat(stdout).contains("application").contains("forge-oauth2-proxy").contains("error")
            .contains("${ProvisionEngine.ERROR_NOT_REACHABLE} — the live read of application/forge-oauth2-proxy in the production plane was answered HTTP 404 (unknown_environment)")
        val reserve = "thoryn access reserve $subject application:forge-oauth2-proxy --environment production"
        assertThat(err)
            .contains("1 resource(s) failed the ownership check")
            .contains(FixRequest.OPTION_CLI_HEADING)
            .contains("  - creator on application:forge-oauth2-proxy in production for $subject: ${ProvisionEngine.ERROR_NOT_REACHABLE} — ")
            .contains("\n      $reserve\n")
            .contains("${FixRequest.OPTION_BROWSER_HEADING} ${FixRequest.NO_CONSENT_LINK_LINE}")
            .doesNotContain("owner application:forge-oauth2-proxy")
        val doc = request(out)
        val item = doc["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("creator")
        assertThat(item["object"].asString()).isEqualTo("application:forge-oauth2-proxy")
        assertThat(item["subject"].asString()).isEqualTo(subject)
        assertThat(item["environment"].asString()).isEqualTo("production")
        assertThat(item["cli"].asString()).isEqualTo(reserve)
        assertThat(item["reason"].asString()).startsWith("${ProvisionEngine.ERROR_NOT_REACHABLE} — ").contains("clientId: forge-oauth2-proxy")
        assertThat(doc["notes"].isEmpty).isTrue()
        assertThat(doc["options"]["cli"].asString()).contains(reserve)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a declared environment the identity cannot see is manager on that environment — a production create without a fixed id is a workspace note`() {
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: in-forge
                environment: forge
                spec: { displayName: "In forge", redirectUris: ["https://in.example.com/cb"] }
              - kind: user
                name: someone
                spec: { email: "someone@example.com", displayName: "Someone" }
            """,
        )
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, _, err) = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).doesNotContain("could not read live state")
        val grant = "thoryn access grant $subject manager environment:forge"
        assertThat(err).contains(grant).contains("  - user someone: ${ProvisionEngine.WORKSPACE_PARENT_NOTE}")
            .contains("! user someone: ${ProvisionEngine.ERROR_NOT_REACHABLE} — the live read of user/someone in the production plane was answered HTTP 404 (unknown_environment)")
        val doc = request(out)
        val item = doc["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("manager")
        assertThat(item["object"].asString()).isEqualTo("environment:forge")
        assertThat(item["cli"].asString()).isEqualTo(grant)
        assertThat(doc["notes"].toList().map { it.asString() }).singleElement().asString().startsWith("user someone: ").contains(ProvisionEngine.WORKSPACE_PARENT_NOTE)
    }

    @Test
    fun `with THORYN_CONSENT_URL the same red plan ends with the run's consent link — and apply refuses with the same request`() {
        System.setProperty(FixRequest.CONSENT_URL_ENV, "https://app.thoryn.io")
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, _, err) = runCli("provision", "apply", "--file", file(fixedIdOnProduction).path, "--gateway", baseUrl(), "--yes", "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val link = "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cicd/38751887466"
        assertThat(err).contains("${FixRequest.OPTION_BROWSER_HEADING} $link").contains("Nothing was changed.")
        assertThat(request(out)["options"]["consentUrl"].asString()).isEqualTo(link)
        assertThat(request(out)["missing"].single()["kind"].asString()).isEqualTo("creator")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `once the admin granted the right the same file plans green — the 404 was reach, not absence`() {
        api.seedGrant(subject, "owner", "application:forge-oauth2-proxy")

        val (exit, stdout, err) = runCli("provision", "plan", "--file", file(fixedIdOnProduction).path, "--gateway", baseUrl())

        assertThat(err).doesNotContain(ProvisionEngine.ERROR_NOT_REACHABLE).doesNotContain("To fix")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(stdout).contains("exists and matches")
    }
}
