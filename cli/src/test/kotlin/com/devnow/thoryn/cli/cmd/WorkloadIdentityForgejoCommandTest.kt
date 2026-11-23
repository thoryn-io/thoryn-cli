package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.cmd.connection.Connection
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

/**
 * SSO-4472 — `thoryn workload-identity trusts create --provider forgejo` (and `get`, `set-plan-profile`) against a
 * MockWebServer standing in for product-api's `/api/v1/workload-identity/trusts`: the `forgejo` pin body the hub expects
 * (product-api `forgejoCommand`: `instanceUrl`, `owner`, `ownerId`, `repository`, `repositoryId`, `ref`), the ids
 * looked up anonymously on the instance when omitted (a fake answers — never a real instance), what is refused before any
 * call, the plan profile with no environment, and the output a Forgejo job needs — on a neutral instance.
 */
class WorkloadIdentityForgejoCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private val lookups = CopyOnWriteArrayList<Triple<String, String, String>>()
    private var lookupAnswer: ForgejoRepositoryLookup.Result = ForgejoRepositoryLookup.Result.Found("acme", 7, "infra", 42)
    private lateinit var realLookup: (String, String, String) -> ForgejoRepositoryLookup.Result

    @BeforeEach
    fun fakeInstance() {
        realLookup = WorkloadIdentityCommand.forgejoLookup
        WorkloadIdentityCommand.forgejoLookup = { instance, owner, repository -> lookups += Triple(instance, owner, repository); lookupAnswer }
    }

    @AfterEach
    fun restore() {
        WorkloadIdentityCommand.forgejoLookup = realLookup
    }

    private fun create(vararg args: String) = runCli(
        "workload-identity", "trusts", "create", "--provider", "forgejo", "--name", "infra-ci",
        "--scope", "tenant:applications.read tenant:applications.write", "--gateway", baseUrl(), *args,
    )

    @Suppress("UNCHECKED_CAST")
    private fun postedBody(): Map<String, Any?> {
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/workload-identity/trusts")
        return parseJson(req.body.readUtf8())
    }

    @Test
    fun `create looks the ids up on the instance, sends the forgejo pin the hub expects, and prints the connection and the job`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-forgejo")))

        val (exit, out, err) = create("--instance", "https://codeberg.org/", "--repository", "Acme/Infra", "--ref", "refs/heads/main", "--plan", "--confirm-production")

        assertThat(exit).isEqualTo(0)
        assertThat(lookups).containsExactly(Triple("https://codeberg.org", "Acme", "Infra"))
        assertThat(err).contains("Looked up acme/infra on https://codeberg.org: owner id 7, repository id 42.")
        val body = postedBody()
        assertThat(body).containsEntry("name", "infra-ci").containsEntry("provider", "forgejo")
            .containsEntry("scopes", listOf("tenant:applications.read", "tenant:applications.write"))
            .containsEntry("confirmProduction", true)
            .containsEntry("plan", emptyMap<String, Any?>()) // a plan profile with derived scopes and NO environment
            .doesNotContainKey("github").doesNotContainKey("kubernetes")
        // The instance's canonical names (from the lookup), never the typed case; the ids as numbers.
        assertThat(body["forgejo"]).isEqualTo(
            mapOf("instanceUrl" to "https://codeberg.org", "owner" to "acme", "ownerId" to 7, "repository" to "infra", "repositoryId" to 42, "ref" to "refs/heads/main"),
        )

        assertThat(out).contains("Workload identity trust 'infra-ci' created")
            .contains("\"provider\": \"forgejo\"")
            .contains("\"forgejo\": { \"instanceUrl\": \"https://codeberg.org\", \"owner\": \"acme\", \"repository\": \"infra\", \"ownerId\": 7, \"repositoryId\": 42, \"ref\": \"refs/heads/main\" }")
            .contains("\"plan\": {")
            .contains("enable-openid-connect: true")
            .contains("never inside a reusable workflow")
            .contains("A workflow_dispatch on refs/heads/main applies")
            .contains("A push or schedule on refs/heads/main, and a pull request into main, plan: read-only tenant:applications.read.")
            .contains("authenticating proxy")
            .contains("controls the keys")
            .doesNotContain("id-token: write")
            .doesNotContain("tokenSource\": { \"kind\": \"github_actions\"")
    }

    @Test
    fun `the printed connection json is a valid forgejo connection the CLI signs in with`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-forgejo")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", "3a9c1e7b-5d2f-4b8a-9c6e-0f1d2e3a4b5c", "--connection", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val connection = Connection.parse(out.toByteArray())
        assertThat(connection.effectiveProvider).isEqualTo(Connection.PROVIDER_FORGEJO)
        assertThat(connection.forgejo!!.ref).isEqualTo("refs/heads/main")
        assertThat(connection.forgejo!!.repositoryId).isEqualTo(42)
        assertThat(connection.planScopes).containsExactly("tenant:applications.read")
        assertThat(connection.tokenFile).isNull()
    }

    @Test
    fun `given ids skip the lookup entirely — a private repository or a proxied API`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-forgejo")))

        val (exit, _, _) = create("--instance", "https://forge.example.org", "--repository", "acme/infra", "--owner-id", "7", "--repository-id", "42", "--ref", "refs/heads/main")

        assertThat(exit).isEqualTo(0)
        assertThat(lookups).isEmpty()
        @Suppress("UNCHECKED_CAST")
        val pin = postedBody()["forgejo"] as Map<String, Any?>
        assertThat(pin).containsEntry("ownerId", 7).containsEntry("repositoryId", 42).containsEntry("instanceUrl", "https://forge.example.org")
    }

    @Test
    fun `a failed lookup stops before any write and says to pass the ids`() {
        lookupAnswer = ForgejoRepositoryLookup.Result.Failed("https://codeberg.org has no public repository acme/infra (HTTP 404). Pass --owner-id and --repository-id: …")

        val (exit, _, err) = create("--instance", "https://codeberg.org", "--repository", "acme/infra", "--ref", "refs/heads/main")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("Error: https://codeberg.org has no public repository acme/infra").contains("--owner-id and --repository-id")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `what the API would refuse is refused first — no instance, a path, a production trust without a ref, other providers' flags`() {
        val noInstance = create("--repository", "acme/infra")
        assertThat(noInstance.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noInstance.err).contains("--instance <https url> is required for a forgejo trust").contains("https://codeberg.org")

        val path = create("--instance", "https://codeberg.org/acme", "--repository", "acme/infra")
        assertThat(path.err).contains("--instance must be the Forgejo instance's https origin with no path")
        val plainHttp = create("--instance", "http://codeberg.org", "--repository", "acme/infra")
        assertThat(plainHttp.err).contains("--instance must be the Forgejo instance's https origin")

        val production = create("--instance", "https://codeberg.org", "--repository", "acme/infra", "--confirm-production")
        assertThat(production.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(production.err).contains("production_requires_ref").contains("--ref refs/heads/main")

        val oneId = create("--instance", "https://codeberg.org", "--repository", "acme/infra", "--owner-id", "7")
        assertThat(oneId.err).contains("--owner-id and --repository-id go together")

        val github = create("--instance", "https://codeberg.org", "--repository", "acme/infra", "--github-environment", "prod", "--plan-environment", "plan")
        assertThat(github.err).contains("--github-environment, --plan-environment do not apply to --provider forgejo").contains("use --plan")

        val writePlan = create("--instance", "https://codeberg.org", "--repository", "acme/infra", "--plan-scope", "tenant:applications.write")
        assertThat(writePlan.err).contains("plan_scope_not_read_only")

        val forgejoOnGithub = runCli(
            "workload-identity", "trusts", "create", "--name", "n", "--repository", "acme/infra", "--instance", "https://codeberg.org",
            "--plan", "--scope", "tenant:x.read", "--gateway", baseUrl(),
        )
        assertThat(forgejoOnGithub.err).contains("--instance, --plan apply to --provider forgejo only")

        assertThat(lookups).isEmpty()
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `set-plan-profile on a Forgejo trust names no environment and posts the scopes alone`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-forgejo")))
        server.enqueue(jsonResponse(200, fixture("trust-created-forgejo")))

        val (exit, out, err) = runCli(
            "workload-identity", "trusts", "set-plan-profile", "3a9c1e7b-5d2f-4b8a-9c6e-0f1d2e3a4b5c", "--plan-scope", "tenant:applications.read", "--gateway", baseUrl(),
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        assertThat(server.takeRequest().method).isEqualTo("GET")
        val post = server.takeRequest()
        assertThat(post.path).isEqualTo("/api/v1/workload-identity/trusts/3a9c1e7b-5d2f-4b8a-9c6e-0f1d2e3a4b5c/plan-profile")
        assertThat(parseJson(post.body.readUtf8())).isEqualTo(mapOf("scopes" to listOf("tenant:applications.read")))
        assertThat(out).contains("a push or schedule on its ref, and a pull request into its branch, are minted tenant:applications.read only")
            .contains("trusts get 3a9c1e7b-5d2f-4b8a-9c6e-0f1d2e3a4b5c --connection")
    }

    @Test
    fun `list and get render the Forgejo pin, and the sign-in line carries no scope`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-forgejo")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", "3a9c1e7b-5d2f-4b8a-9c6e-0f1d2e3a4b5c", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("https://codeberg.org").contains("acme/infra").contains("owner 7 / repository 42").contains("refs/heads/main")
        val line = out.lines().first { it.trim().startsWith("thoryn login --workload-identity") }
        assertThat(line).contains("--client-id wi_5e4f3a2b1c0d9e8f7a6b5c4d").doesNotContain("--scope")
        assertThat(WorkloadIdentityCommand.row(tools.jackson.databind.json.JsonMapper.builder().build().readTree(fixture("trust-created-forgejo"))))
            .contains("forgejo", "https://codeberg.org acme/infra ref=refs/heads/main plan")
    }
}
