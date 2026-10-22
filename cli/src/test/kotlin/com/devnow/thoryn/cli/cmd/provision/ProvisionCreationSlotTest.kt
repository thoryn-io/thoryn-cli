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
 * SSO-3792 (oauthy ADR 2026-10-17-consent-approved-application-creation-slots §6, decision D3; absorbs SSO-3787) — the
 * thoryn-cicd PR 34 shape: the file declares a PRODUCTION application (`forge-forgejo-login`, a fixed `clientId`) that
 * does not exist. The fix request used to ask for `owner` on it — a right on nothing, which the consent offered and
 * product-api refused with `not_found`. Now:
 *  - the engine asks for exactly ONE creation slot (`creator`, `thoryn access reserve …`), never `owner`;
 *  - with an unexpired slot this identity holds for that id on that plane, the plan shows "will create (reserved …)" and
 *    PASSES; on another plane, for another name, or expired, it stays red with the same item;
 *  - `apply` is the ordinary create with the explicit `clientId`: product-api consumes the slot, the repository owns it;
 *  - a sandbox create keeps `manager` on its environment; an application without a fixed id keeps the workspace note.
 */
class ProvisionCreationSlotTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val json = JsonMapper.builder().build()
    private val clientId = "wi_10a7b379c79f7d1353f5798d"
    private val subject = "client:$clientId"
    private val reserve = "thoryn access reserve $subject application:forge-forgejo-login --environment production"
    private lateinit var dir: File

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        api.callerIsAdmin = false
        api.caller = subject
        // The platform's filter: a brand-new repository identity reaches no plane at all (the PR 34 / run 38751887466 shape).
        api.environmentClaimFilter = true
        // The identity's own trust exists (so an admin's reservation can name its client).
        api.seedTrust(null, "thoryn-cicd", clientId = clientId)
        val runner = mapOf("GITHUB_REPOSITORY" to "thoryn-io/thoryn-cicd", "GITHUB_RUN_ID" to "38800000001")
        FixRequests.environment = { key -> if (key.startsWith("GITHUB_")) runner[key] else com.devnow.thoryn.cli.auth.WorkloadIdentityFlow.runnerEnv(key) }
        dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        session(Tokens.PROFILE_PLAN)
    }

    @AfterEach
    fun unmount() {
        FixRequests.resetEnvironmentForTest()
    }

    /** A workload-identity session of the repository identity: a JWT without `sub`, its `client_id`, the workspace's `tnt`. */
    private fun session(profile: String) {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val scope = if (profile == Tokens.PROFILE_PLAN) "tenant:environments.read tenant:applications.read tenant:access.read" else "tenant:environments.read tenant:applications.read tenant:applications.write tenant:access.read"
        val payload = enc.encodeToString("""{"client_id":"$clientId","scope":"$scope","tnt":"${api.tenantId}"}""".toByteArray())
        seedTokens(
            Tokens(
                accessToken = "$header.$payload.sig", authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId,
                issuer = "https://thoryn.auth.stg.thoryn.org", gateway = baseUrl(), workspace = "thoryn", profile = profile,
                jobEnvironment = if (profile == Tokens.PROFILE_PLAN) "forge-plan" else "forge", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    private fun file(yaml: String): File = File(dir, "provision.yaml").apply { writeText(yaml.trimIndent() + "\n") }

    private fun request(path: File): JsonNode = json.readTree(Files.readString(path.toPath()))

    private val out: File get() = File(tempHome.toFile(), "thoryn-provision-request.json")

    private fun plan(yaml: String): CliResult =
        runCli("provision", "plan", "--file", file(yaml).path, "--gateway", baseUrl(), "--fix-request", out.path)

    /** PR 34's file: a production application with a fixed clientId that does not exist yet. */
    private val declaredProductionApp = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-forgejo-login
            spec: { clientId: forge-forgejo-login, displayName: "Forgejo login", redirectUris: ["https://forge.example.com/user/oauth2/thoryn/callback"] }
    """

    @Test
    fun `the PR 34 shape — a declared production application on an unreachable plane — is exactly one creator item and no owner item`() {
        val (exit, _, err) = plan(declaredProductionApp)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val doc = request(out)
        val item = doc["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("creator")
        assertThat(item["object"].asString()).isEqualTo("application:forge-forgejo-login")
        assertThat(item["subject"].asString()).isEqualTo(subject)
        assertThat(item["environment"].asString()).isEqualTo("production")
        assertThat(item["cli"].asString()).isEqualTo(reserve)
        assertThat(item["reason"].asString()).startsWith("${ProvisionEngine.ERROR_NOT_REACHABLE} — ").contains("clientId: forge-forgejo-login")
        // SSO-3787 — never `owner` on an application that may not exist, never the workspace note in its place.
        assertThat(doc["missing"].toList().map { it["kind"].asString() }).doesNotContain("owner")
        assertThat(doc["notes"].isEmpty).isTrue()
        assertThat(err).contains("  - creator on application:forge-forgejo-login in production for $subject: ").contains("\n      $reserve\n")
            .doesNotContain("thoryn access grant")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `with the production plane visible, a create this identity may not make asks for a creation slot instead of the workspace note`() {
        api.environmentClaimFilter = false

        val (exit, _, err) = plan(declaredProductionApp)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val doc = request(out)
        val item = doc["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("creator")
        assertThat(item["cli"].asString()).isEqualTo(reserve)
        assertThat(item["reason"].asString()).startsWith("${ProvisionEngine.ERROR_NOT_OWNED} — ")
        assertThat(doc["notes"].isEmpty).isTrue()
        assertThat(err).doesNotContain(ProvisionEngine.WORKSPACE_PARENT_NOTE)
    }

    @Test
    fun `a production application without a fixed clientId keeps the workspace note, now saying to declare spec clientId — no item`() {
        api.environmentClaimFilter = false

        val (exit, _, _) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: no-id
                spec: { displayName: "No id", redirectUris: ["https://no-id.example.com/cb"] }
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val doc = request(out)
        assertThat(doc["missing"].isEmpty).isTrue()
        assertThat(doc["notes"].single().asString()).startsWith("application no-id: ")
            .contains(ProvisionEngine.WORKSPACE_PARENT_NOTE).contains(ProvisionEngine.DECLARE_CLIENT_ID_NOTE)
    }

    @Test
    fun `a sandbox create still asks for manager on its environment — never a creation slot (decision D3)`() {
        api.environmentClaimFilter = false
        val envId = api.seedEnvironment("forge", "Forge")

        val (exit, _, _) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: in-forge
                environment: forge
                spec: { clientId: in-forge, displayName: "In forge", redirectUris: ["https://in.example.com/cb"] }
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val item = request(out)["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("manager")
        assertThat(item["object"].asString()).isEqualTo("environment:$envId")
        assertThat(item["cli"].asString()).isEqualTo("thoryn access grant $subject manager environment:$envId")
    }

    @Test
    fun `an unreachable sandbox application with a fixed clientId asks for manager on that environment — not owner on something that may not exist`() {
        api.seedEnvironment("forge", "Forge")

        val (exit, _, _) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: in-forge
                environment: forge
                spec: { clientId: in-forge, displayName: "In forge", redirectUris: ["https://in.example.com/cb"] }
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val item = request(out)["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("manager")
        assertThat(item["object"].asString()).isEqualTo("environment:forge")
        assertThat(item["reason"].asString()).startsWith("${ProvisionEngine.ERROR_NOT_REACHABLE} — ")
    }

    @Test
    fun `with an unexpired slot this identity holds for that id on that plane, the create plans as reserved and the plan passes`() {
        api.seedSlot("forge-forgejo-login", subject)

        val (exit, stdout, err) = plan(declaredProductionApp)

        assertThat(err).doesNotContain("To fix").doesNotContain(ProvisionEngine.ERROR_NOT_REACHABLE)
        assertThat(exit).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(stdout).contains("forge-forgejo-login").contains("create")
            .contains("will create (reserved by a workspace admin; expires 2026-11-16T00:00:00Z)")
        assertThat(out).doesNotExist()
        assertThat(api.slotReads).isEqualTo(1)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `the reserved create carries its reservation in the plan's json — object, plane and expiry`() {
        api.seedSlot("forge-forgejo-login", subject)

        val (exit, stdout, _) = runCli("provision", "plan", "--file", file(declaredProductionApp).path, "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_OK)
        val row = json.readTree(stdout)["changes"].single()
        assertThat(row["action"].asString()).isEqualTo("create")
        assertThat(row["reservation"]["object"].asString()).isEqualTo("application:forge-forgejo-login")
        assertThat(row["reservation"]["environment"].asString()).isEqualTo("production")
        assertThat(row["reservation"]["expiresAt"].asString()).isEqualTo("2026-11-16T00:00:00Z")
    }

    @Test
    fun `a slot on another plane, for another name, held by another identity, or expired leaves the plan red with the creator item`() {
        api.seedEnvironment("forge", "Forge")
        val cases = listOf<Pair<String, () -> Unit>>(
            "another plane" to { api.seedSlot("forge-forgejo-login", subject, env = "forge") },
            "another name" to { api.seedSlot("forge-other", subject) },
            "another holder" to { api.seedSlot("forge-forgejo-login", "client:wi_someone_else") },
            "expired" to { api.seedSlot("forge-forgejo-login", subject, expired = true) },
        )
        cases.forEach { (label, seed) ->
            api.slots.clear(); out.delete()
            seed()

            val (exit, _, _) = plan(declaredProductionApp)

            assertThat(exit).describedAs(label).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
            val item = request(out)["missing"].single()
            assertThat(item["kind"].asString()).describedAs(label).isEqualTo("creator")
            assertThat(item["cli"].asString()).describedAs(label).isEqualTo(reserve)
            if (label == "expired") assertThat(item["reason"].asString()).contains("creation slot for it expired at 2026-08-31T00:00:00Z")
        }
    }

    @Test
    fun `a slot held by another identity never counts as this identity's, even when the listing carries it`() {
        api.slotListingUnfiltered = true
        api.seedSlot("forge-forgejo-login", "client:wi_someone_else")

        val (exit, _, _) = plan(declaredProductionApp)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(request(out)["missing"].single()["kind"].asString()).isEqualTo("creator")
    }

    @Test
    fun `an application on a plane the workspace does not list is a note — a production slot would not create it there`() {
        api.environmentClaimFilter = false

        val (exit, _, _) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: in-ghost
                environment: ghost
                spec: { clientId: in-ghost, displayName: "In ghost", redirectUris: ["https://ghost.example.com/cb"] }
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val doc = request(out)
        assertThat(doc["missing"].toList().map { it["kind"].asString() }).doesNotContain("creator")
        assertThat(doc["notes"].single().asString()).startsWith("application in-ghost: ").contains(ProvisionEngine.WORKSPACE_PARENT_NOTE)
    }

    @Test
    fun `apply under a slot creates the application with its explicit clientId, consumes the slot, and the repository owns it`() {
        api.seedSlot("forge-forgejo-login", subject)
        session(Tokens.PROFILE_APPLY)

        val (exit, stdout, err) = runCli("provision", "apply", "--file", file(declaredProductionApp).path, "--gateway", baseUrl(), "--yes", "--secret-file", File(tempHome.toFile(), "secret").path)

        assertThat(exit).describedAs(err).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(stdout).contains("+ application forge-forgejo-login: clientId=forge-forgejo-login")
        val create = api.writesTo("/api/v1/applications").single()
        assertThat(create.method).isEqualTo("POST")
        assertThat(create.env).isNull()
        assertThat(create.body["clientId"]).isEqualTo("forge-forgejo-login")
        assertThat(api.slots).isEmpty()
        assertThat(api.ownerOf("application:forge-forgejo-login")).isEqualTo(subject)
        // The next plan finds it and owns it: no slot needed, no item.
        session(Tokens.PROFILE_PLAN)
        val (again, _, againErr) = runCli("provision", "plan", "--file", file(declaredProductionApp).path, "--gateway", baseUrl())
        assertThat(againErr).doesNotContain("To fix")
        assertThat(again).isEqualTo(CommandSupport.EXIT_OK)
    }

    @Test
    fun `apply whose slot was released after the plan says the slot no longer admits the create — nothing was created`() {
        api.seedSlot("forge-forgejo-login", subject)
        api.releaseSlotsBeforeCreate = true
        session(Tokens.PROFILE_APPLY)

        val (exit, _, err) = runCli("provision", "apply", "--file", file(declaredProductionApp).path, "--gateway", baseUrl(), "--yes")

        assertThat(exit).isNotEqualTo(CommandSupport.EXIT_OK)
        assertThat(err).contains("application/forge-forgejo-login: the creation slot for application:forge-forgejo-login in production no longer admits this create (HTTP 404)")
            .contains("nothing was created").contains(reserve)
        assertThat(api.applications).isEmpty()
    }

    @Test
    fun `a slot never includes token exchange — the plan refuses allowTokenExchange under a slot before any write`() {
        api.seedSlot("forge-forgejo-login", subject)

        val (exit, _, err) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-forgejo-login
                spec:
                  clientId: forge-forgejo-login
                  displayName: "Forgejo login"
                  redirectUris: ["https://forge.example.com/cb"]
                  grantTypes: ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]
                  allowTokenExchange: true
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("token_exchange_not_grantable — application/forge-forgejo-login is to be created under a creation slot")
        val doc = request(out)
        assertThat(doc["missing"].isEmpty).isTrue()
        assertThat(doc["notes"].single().asString()).contains(ProvisionEngine.TOKEN_EXCHANGE_WORKSPACE_NOTE)
        assertThat(api.slots).hasSize(1)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a slot never includes token introspection — the plan refuses allowTokenIntrospection under a slot before any write`() {
        api.seedSlot("forge-forgejo-login", subject)

        val (exit, _, err) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-forgejo-login
                spec:
                  clientId: forge-forgejo-login
                  displayName: "Forgejo login"
                  redirectUris: ["https://forge.example.com/cb"]
                  allowTokenIntrospection: true
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("token_introspection_not_grantable — application/forge-forgejo-login is to be created under a creation slot")
            .doesNotContain("will create (reserved")
        val doc = request(out)
        assertThat(doc["missing"].isEmpty).isTrue()
        assertThat(doc["notes"].single().asString()).contains(ProvisionEngine.TOKEN_INTROSPECTION_WORKSPACE_NOTE)
        assertThat(api.slots).hasSize(1)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a platform from before creation slots answers 404 for the listing — read as no slots, and the plan still asks for one`() {
        api.slotsSupported = false

        val (exit, _, err) = plan(declaredProductionApp)

        assertThat(err).doesNotContain("could not")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(request(out)["missing"].single()["kind"].asString()).isEqualTo("creator")
    }

    @Test
    fun `the slot listing is read once per plan however many creates it decides`() {
        api.environmentClaimFilter = false
        api.seedSlot("forge-forgejo-login", subject)

        val (exit, _, _) = plan(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: forge-forgejo-login
                spec: { clientId: forge-forgejo-login, displayName: "Forgejo login", redirectUris: ["https://forge.example.com/user/oauth2/thoryn/callback"] }
              - kind: application
                name: forge-second
                spec: { clientId: forge-second, displayName: "Second", redirectUris: ["https://second.example.com/cb"] }
            """,
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(request(out)["missing"].single()["object"].asString()).isEqualTo("application:forge-second")
        assertThat(api.slotReads).isEqualTo(1)
    }

    @Test
    fun `a creator item renders the plane and its command is the one the hint quotes`() {
        val item = FixRequest.creator(subject, "forge-forgejo-login", "production", "access_not_owned — …")

        assertThat(item.cli).isEqualTo(reserve)
        assertThat(FixRequest.hint(item)).contains("`$reserve`")
        // Without web consent: under the SSO-3738 check-each-line warning, the item with its plane, then the command.
        assertThat(FixRequest.renderOption1Body(listOf(item)))
            .startsWith("  ${FixRequest.CHECK_EACH_LINE_WARNING}\n")
            .contains("\n  - creator on application:forge-forgejo-login in production for $subject: ")
            .endsWith("\n      $reserve")
    }

    @Test
    fun `with a consent link a creator item is listed with its plane under thoryn access approve — and no reserve line is printed`() {
        val hinted = "access_not_owned — creating it needs a creation slot (${FixRequest.hint(FixRequest.creator(subject, "forge-forgejo-login", "production", "x"))})"
        val item = FixRequest.creator(subject, "forge-forgejo-login", "production", hinted)
        val link = "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cicd/38751887466"

        val rendered = FixRequest.render(listOf(item), consentUrl = link)

        assertThat(rendered).contains("      thoryn access approve thoryn-io/thoryn-cicd/38751887466")
            .contains("  - creator on application:forge-forgejo-login in production for $subject: ")
            .contains(FixRequest.APPROVE_HINT)
            .doesNotContain("thoryn access reserve")
            .endsWith("${FixRequest.OPTION_BROWSER_HEADING} $link")
    }
}
