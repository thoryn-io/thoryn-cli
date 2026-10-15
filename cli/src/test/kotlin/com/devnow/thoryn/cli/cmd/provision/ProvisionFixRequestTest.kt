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
 * SSO-3710 (oauthy ADR 2026-10-15 §1) — `thoryn provision plan|apply --fix-request <file>`: a RED plan writes the fix
 * request — one item per `access_*` row that is a missing RIGHT (`owner` on an existing object the identity does not
 * own, `manager` on the parent environment of a refused create, `viewer` for a `readOnly` reference it cannot see; an
 * object another repository owns as `owner` with NO command), file-fix rows as notes, the repository and run from the
 * runner's variables, the trust resolved from the session when it may list trusts — and the SAME command strings on
 * stderr, rendered by the one function the file is rendered with. A green plan writes nothing; exit codes are unchanged.
 */
class ProvisionFixRequestTest : CommandTestBase() {

    private val api = FakeProductApi()
    /** Every path the CLI asked the API for (the fake records writes and checks, not reads). */
    private val paths = mutableListOf<String>()
    private val json = JsonMapper.builder().build()
    private val clientId = "wi_10a7b379c79f7d1353f5798d"
    private val subject = "client:$clientId"
    private lateinit var envId: String
    private lateinit var otherEnvId: String
    private lateinit var dir: File

    private val runnerVars = mapOf(
        "GITHUB_REPOSITORY" to "thoryn-io/thoryn-cli",
        "GITHUB_REPOSITORY_OWNER" to "thoryn-io",
        "GITHUB_REPOSITORY_OWNER_ID" to "229451779",
        "GITHUB_REPOSITORY_ID" to "1361536515",
        "GITHUB_RUN_ID" to "38547022158",
        "GITHUB_SHA" to "0123456789abcdef0123456789abcdef01234567",
    )

    @BeforeEach
    fun mount() {
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): okhttp3.mockwebserver.MockResponse {
                paths += request.path ?: "/"
                return api.dispatch(request)
            }
        }
        api.callerIsAdmin = false
        api.caller = subject
        envId = api.seedEnvironment("ci-sbx", "CI sandbox")
        otherEnvId = api.seedEnvironment("other", "Someone else's sandbox")
        api.seedApplication(null, "CLI login client", listOf("http://127.0.0.1/callback"), clientId = "cli")
        api.seedApplication(null, "Shared", listOf("https://shared.example.com/cb"), clientId = "shared")
        // Inside the managed sandbox (so this identity is its manager by containment) but OWNED by another repository.
        api.seedApplication("ci-sbx", "Taken", listOf("https://taken.example.com/cb"), clientId = "taken")
        api.seedGrant(subject, "manager", "environment:$envId")
        api.seedGrant(subject, "viewer", "application:shared")
        api.seedGrant("client:wi_other", "owner", "application:taken")
        runnerVars.forEach { (k, v) -> System.setProperty(k, v) }
        dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
    }

    @AfterEach
    fun unmount() {
        runnerVars.keys.forEach { System.clearProperty(it) }
        System.clearProperty(FixRequest.ENV)
    }

    /** A plan-profile workload-identity session: a JWT without `sub` (Spring AS names the principal after the client), read scopes only. */
    private fun session(scope: String = "tenant:environments.read tenant:applications.read tenant:access.read", issuer: String = "https://thoryn.auth.stg.thoryn.org") {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"none"}""".toByteArray())
        val payload = enc.encodeToString("""{"client_id":"$clientId","scope":"$scope","tnt":"${api.tenantId}"}""".toByteArray())
        seedTokens(
            Tokens(
                accessToken = "$header.$payload.sig", authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = clientId,
                issuer = issuer, gateway = baseUrl(), workspace = "thoryn", profile = Tokens.PROFILE_PLAN,
                jobEnvironment = "thoryn-provision-e2e-plan", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    private fun file(yaml: String): File = File(dir, "provision.yaml").apply { writeText(yaml.trimIndent() + "\n") }

    private fun request(path: File): JsonNode = json.readTree(Files.readString(path.toPath()))

    private val redFile = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: environment
            name: ci
            spec: { slug: ci-sbx, displayName: "CI sandbox" }
          - kind: application
            name: cli
            spec: { clientId: cli, displayName: "CLI login client", redirectUris: ["http://127.0.0.1/callback"] }
          - kind: application
            name: shared
            spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/cb"] }
          - kind: application
            name: taken
            environment: ci
            spec: { clientId: taken, displayName: "Taken", redirectUris: ["https://taken.example.com/cb"] }
          - kind: application
            name: intruder
            environment: other
            spec: { clientId: intruder, displayName: "Intruder", redirectUris: ["https://intruder.example.com/cb"] }
          - kind: user
            name: prod-user
            spec: { email: "someone@example.com", displayName: "Someone" }
    """

    @Test
    fun `a red plan writes the fix request — owner, owner-without-command, manager on the parent environment, a workspace-parent note — and prints the same commands`() {
        session()
        val out = File(tempHome.toFile(), "req/thoryn-provision-request.json")

        val (exit, _, err) = runCli("provision", "plan", "--file", file(redFile).path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out).exists()
        val doc = request(out)
        assertThat(doc["version"].asInt()).isEqualTo(1)
        assertThat(doc["workspace"].asString()).isEqualTo("thoryn")
        assertThat(doc["repository"]["owner"].asString()).isEqualTo("thoryn-io")
        assertThat(doc["repository"]["ownerId"].asLong()).isEqualTo(229451779L)
        assertThat(doc["repository"]["repository"].asString()).isEqualTo("thoryn-cli")
        assertThat(doc["repository"]["repositoryId"].asLong()).isEqualTo(1361536515L)
        assertThat(doc["run"]["id"].asLong()).isEqualTo(38547022158L)
        assertThat(doc["run"]["headSha"].asString()).isEqualTo("0123456789abcdef0123456789abcdef01234567")
        assertThat(doc["run"]["jobEnvironment"].asString()).isEqualTo("thoryn-provision-e2e-plan")
        assertThat(doc["file"]["path"].asString()).endsWith("provision.yaml")
        assertThat(doc["file"]["sha256"].asString()).matches("^sha256:[0-9a-f]{64}$")
        // The plan session holds no tenant:workload-identity.read: the trust is named by its client only — no API call was made.
        assertThat(doc["trust"]["clientId"].asString()).isEqualTo(clientId)
        assertThat(doc["trust"]["plane"].asString()).isEqualTo("production")
        assertThat(doc["trust"]["name"].isNull).isTrue()
        assertThat(doc["trust"]["id"].isNull).isTrue()
        assertThat(paths).noneMatch { it.startsWith("/api/v1/workload-identity/trusts") }

        val byObject = doc["missing"].toList().associateBy { it["object"].asString() }
        assertThat(byObject.keys).containsExactlyInAnyOrder("application:cli", "application:shared", "application:taken", "environment:$otherEnvId")
        // No relation on an existing object this file is to own ⇒ owner.
        assertThat(byObject.getValue("application:cli")["kind"].asString()).isEqualTo("owner")
        assertThat(byObject.getValue("application:cli")["subject"].asString()).isEqualTo(subject)
        assertThat(byObject.getValue("application:cli")["cli"].asString()).isEqualTo("thoryn access grant $subject owner application:cli")
        assertThat(byObject.getValue("application:cli")["reason"].asString()).startsWith("access_not_owned — ")
        // Viewer only, declared without readOnly ⇒ owner.
        assertThat(byObject.getValue("application:shared")["kind"].asString()).isEqualTo("owner")
        assertThat(byObject.getValue("application:shared")["cli"].asString()).isEqualTo("thoryn access grant $subject owner application:shared")
        assertThat(byObject.getValue("application:shared")["reason"].asString()).startsWith("access_read_only — ")
        // Owned by another repository ⇒ owner with NO command, and the other owner is not named.
        assertThat(byObject.getValue("application:taken")["kind"].asString()).isEqualTo("owner")
        assertThat(byObject.getValue("application:taken")["cli"].isNull).isTrue()
        assertThat(byObject.getValue("application:taken")["reason"].asString()).startsWith("access_owned_elsewhere — ").doesNotContain("wi_other")
        // A create in a sandbox this identity does not manage ⇒ manager on that environment.
        assertThat(byObject.getValue("environment:$otherEnvId")["kind"].asString()).isEqualTo("manager")
        assertThat(byObject.getValue("environment:$otherEnvId")["cli"].asString()).isEqualTo("thoryn access grant $subject manager environment:$otherEnvId")
        // A create whose parent is the WORKSPACE is never a right: a note, not an item.
        assertThat(doc["notes"].toList().map { it.asString() }).singleElement().asString()
            .startsWith("user prod-user: ").contains("`manager` on the workspace is never granted")

        // The terminal and the file say the same thing: every `cli` the file carries is printed, verbatim.
        doc["missing"].forEach { item -> item["cli"]?.takeUnless { it.isNull }?.let { assertThat(err).contains(it.asString()) } }
        assertThat(err).contains("Missing rights — what a workspace admin grants (4 item(s)):")
        assertThat(err).contains("Fix request written to ${out.path} (4 missing right(s), 1 note(s))")
        assertThat(err).doesNotContain("wi_other")
    }

    @Test
    fun `a readOnly reference the identity cannot see is a viewer item — a differing read-only reference is a note, not a right`() {
        session()
        api.seedGrant(subject, "viewer", "application:shared")
        val f = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: cli
                readOnly: true
                spec: { clientId: cli, displayName: "CLI login client", redirectUris: ["http://127.0.0.1/callback"] }
              - kind: application
                name: shared
                readOnly: true
                spec: { clientId: shared, displayName: "Shared", redirectUris: ["https://shared.example.com/CHANGED"] }
            """,
        )
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, _, _) = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val doc = request(out)
        val items = doc["missing"].toList()
        assertThat(items).hasSize(1)
        assertThat(items[0]["kind"].asString()).isEqualTo("viewer")
        assertThat(items[0]["object"].asString()).isEqualTo("application:cli")
        assertThat(items[0]["cli"].asString()).isEqualTo("thoryn access grant $subject viewer application:cli")
        assertThat(doc["notes"].toList().map { it.asString() }).singleElement().asString()
            .startsWith("application shared: ").isEqualTo("application shared: ${ProvisionEngine.FILE_FIX_NOTE}")
    }

    @Test
    fun `a session that may list trusts resolves the trust's name, id and apply environment into the request`() {
        session(scope = "tenant:environments.read tenant:applications.read tenant:access.read tenant:workload-identity.read")
        api.seedGrant(subject, "viewer", "workspace:${api.tenantId}")
        api.seedTrust(null, "decoy", clientId = "wi_000000000000000000000001")
        val trustId = api.seedTrust(
            null, "thoryn-cli-ci", clientId = clientId,
            pins = mapOf("owner" to "thoryn-io", "repository" to "thoryn-cli", "ownerId" to 229451779L, "repositoryId" to 1361536515L, "environment" to "thoryn-provision-e2e"),
        )
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")

        val (exit, _, _) = runCli("provision", "plan", "--file", file(redFile).path, "--gateway", baseUrl(), "--fix-request", out.path)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        val trust = request(out)["trust"]
        assertThat(trust["name"].asString()).isEqualTo("thoryn-cli-ci")
        assertThat(trust["id"].asString()).isEqualTo(trustId)
        assertThat(trust["applyEnvironment"].asString()).isEqualTo("thoryn-provision-e2e")
        assertThat(trust["clientId"].asString()).isEqualTo(clientId)
    }

    @Test
    fun `THORYN_FIX_REQUEST is the same switch as the flag, and apply writes the same request before refusing`() {
        session()
        val out = File(tempHome.toFile(), "from-env/thoryn-provision-request.json")
        System.setProperty(FixRequest.ENV, out.path)

        val (exit, _, err) = runCli("provision", "apply", "--file", file(redFile).path, "--gateway", baseUrl(), "--yes")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Nothing was changed.")
        assertThat(api.writes).isEmpty()
        val doc = request(out)
        assertThat(doc["missing"].toList().map { it["object"].asString() }).contains("application:cli", "environment:$otherEnvId")
        assertThat(doc["missing"].toList().map { it["cli"]?.takeUnless { n -> n.isNull }?.asString() }).contains("thoryn access grant $subject owner application:cli")
    }

    @Test
    fun `a green plan writes no request, and a red plan without --fix-request writes none either but still prints the commands`() {
        session()
        api.seedGrant(subject, "owner", "application:cli")
        val green = file(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: cli
                spec: { clientId: cli, displayName: "CLI login client", redirectUris: ["http://127.0.0.1/callback"] }
            """,
        )
        val out = File(tempHome.toFile(), "thoryn-provision-request.json")
        assertThat(runCli("provision", "plan", "--file", green.path, "--gateway", baseUrl(), "--fix-request", out.path).exit).isEqualTo(0)
        assertThat(out).doesNotExist()

        val (exit, _, err) = runCli("provision", "plan", "--file", file(redFile).path, "--gateway", baseUrl())
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out).doesNotExist()
        assertThat(err).contains("thoryn access grant $subject owner application:shared").contains("Missing rights — what a workspace admin grants (3 item(s)):")
        assertThat(err).doesNotContain("Fix request written")
    }
}
