package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.provision.FixRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3710 (oauthy ADR 2026-10-15 §1) — `thoryn login --connection --fix-request <file>`: a WIF refusal that is
 * `invalid_client` AND whose only local mismatch is the GitHub environment (the job runs in `<env>-plan`, the trust pins
 * the apply environment and has no plan profile) writes the fix request with ONE `plan_profile` item — the exact
 * `thoryn workload-identity trusts set-plan-profile` command, `<trust-id>` because a refused sign-in holds no token —
 * the trust as the connection states it (the `wi_` client, the plane, the apply environment; name and id null), and the
 * repository / run from the job token's claims. Any other refusal shape writes nothing: today's diagnostic alone. The
 * same command is on stderr with or without the flag — one rendering — and the exit code is unchanged.
 */
class LoginConnectionFixRequestTest : CommandTestBase() {

    private val platform = WorkloadIdentityPlatform()
    private val json = JsonMapper.builder().build()
    private val clientId = "wi_10a7b379c79f7d1353f5798d"
    private val applyEnvironment = "thoryn-provision-e2e"
    private val planEnvironment = "thoryn-provision-e2e-plan"

    private fun audience() = baseUrl()

    @BeforeEach
    fun mount() {
        server.dispatcher = platform
        clearTokens()
        WorkloadIdentityPlatform.actAsRunner(baseUrl())
        CommandSupport.resetSessionHintForTest()
        platform.tokenResponses += WorkloadIdentityPlatform.json(401, """{"error":"invalid_client"}""")
    }

    @AfterEach
    fun unmount() {
        WorkloadIdentityPlatform.leaveRunner()
        System.clearProperty(FixRequest.ENV)
        System.clearProperty(FixRequest.CONSENT_URL_ENV)
    }

    private fun jobIn(environment: String?, repository: String = "thoryn-io/thoryn-cli") {
        platform.claims = { aud -> FakeJobTokens.claims(aud, repository = repository, repositoryId = "1361536515", ownerId = "229451779", environment = environment) }
    }

    private fun writeConnection(
        pins: String = """"github": { "owner": "thoryn-io", "repository": "thoryn-cli", "ownerId": 229451779, "repositoryId": 1361536515, "environment": "$applyEnvironment", "ref": "refs/heads/main" }""",
    ): Path {
        val file = tempHome.resolve("connection.json")
        Files.writeString(
            file,
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "thoryn" },
              "auth": {
                "method": "workload_identity",
                "clientId": "$clientId",
                "audience": "${audience()}",
                "scopes": ["tenant:environments.read", "tenant:environments.write"],
                $pins
              }
            }
            """.trimIndent(),
        )
        return file
    }

    private fun request(path: Path): JsonNode = json.readTree(Files.readString(path))

    private val expectedCommand = "thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment thoryn-provision-e2e-plan"

    @Test
    fun `an environment-only invalid_client writes the plan_profile request from the job's claims and the connection — and prints the same command`() {
        jobIn(planEnvironment)
        val out = tempHome.resolve("req/thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(FileTokenStore().read()).isNull()
        val doc = request(out)
        assertThat(doc["version"].asInt()).isEqualTo(1)
        assertThat(doc["workspace"].asString()).isEqualTo("thoryn")
        assertThat(doc["file"].isNull).isTrue()
        assertThat(doc["repository"]["owner"].asString()).isEqualTo("thoryn-io")
        assertThat(doc["repository"]["ownerId"].asLong()).isEqualTo(229451779L)
        assertThat(doc["repository"]["repository"].asString()).isEqualTo("thoryn-cli")
        assertThat(doc["repository"]["repositoryId"].asLong()).isEqualTo(1361536515L)
        assertThat(doc["run"]["id"].asLong()).isEqualTo(38547022158L)
        assertThat(doc["run"]["headSha"].asString()).isEqualTo("0123456789abcdef0123456789abcdef01234567")
        assertThat(doc["run"]["jobEnvironment"].asString()).isEqualTo(planEnvironment)
        // No token ⇒ no name, no id; the client and the pins are the connection's.
        assertThat(doc["trust"]["name"].isNull).isTrue()
        assertThat(doc["trust"]["id"].isNull).isTrue()
        assertThat(doc["trust"]["clientId"].asString()).isEqualTo(clientId)
        assertThat(doc["trust"]["plane"].asString()).isEqualTo("production")
        assertThat(doc["trust"]["applyEnvironment"].asString()).isEqualTo(applyEnvironment)
        val item = doc["missing"].single()
        assertThat(item["kind"].asString()).isEqualTo("plan_profile")
        assertThat(item["environment"].asString()).isEqualTo(planEnvironment)
        assertThat(item["object"].isNull).isTrue()
        assertThat(item["subject"].isNull).isTrue()
        assertThat(item["reason"].asString()).contains("'$planEnvironment'").contains("'$applyEnvironment'")
        assertThat(item["cli"].asString()).isEqualTo(expectedCommand)
        assertThat(doc["notes"].isEmpty).isTrue()
        // SSO-3723 — the two options as data: Option 1 is the printed body, Option 2 null without a configured base URL.
        assertThat(doc["options"]["cli"].asString()).contains(expectedCommand)
        assertThat(doc["options"]["consentUrl"].isNull).isTrue()
        // One rendering: the terminal carries the file's command, the resolver hint, and the write.
        assertThat(err)
            .contains("refused the workload identity exchange (HTTP 401: invalid_client)")
            .contains("environment: the trust pins GitHub environment '$applyEnvironment'; this job runs in '$planEnvironment'.")
            .contains(FixRequest.OPTION_CLI_HEADING)
            .contains("${FixRequest.OPTION_BROWSER_HEADING} ${FixRequest.NO_CONSENT_LINK_LINE}")
            .contains(expectedCommand)
            .contains("`${FixRequest.LIST_TRUSTS_COMMAND}`")
            .contains("Fix request written to $out")
            .doesNotContain(platform.jobTokens.single())
        assertThat(Files.readString(out)).doesNotContain(platform.jobTokens.single())
    }

    @Test
    fun `THORYN_FIX_REQUEST is the same switch as the flag`() {
        jobIn(planEnvironment)
        val out = tempHome.resolve("from-env/thoryn-provision-request.json")
        System.setProperty(FixRequest.ENV, out.toString())

        val (exit, _, _) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(request(out)["missing"].single()["cli"].asString()).isEqualTo(expectedCommand)
    }

    @Test
    fun `without --fix-request nothing is written, but the command is still printed`() {
        jobIn(planEnvironment)

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains(expectedCommand).doesNotContain("Fix request written")
        assertThat(Files.walk(tempHome).noneMatch { it.fileName.toString() == FixRequest.FILE_NAME }).isTrue()
    }

    // ── SSO-3722 — every refusal writes the request: a wrong pin, a missing `environment:`, an opaque refusal are NOTES ──

    @Test
    fun `a refusal with another mismatch too — a different repository — is a pin problem — no item, a note naming the trusts create command, the request still written`() {
        jobIn(planEnvironment, repository = "acme/billing")
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains("repository: the trust pins 'thoryn-io/thoryn-cli'; this job runs in 'acme/billing'.")
        assertThat(err).doesNotContain("set-plan-profile")
        val create = "thoryn workload-identity trusts create --name <name> --repository acme/billing --owner-id 229451779 --repository-id 1361536515 --github-environment $planEnvironment --ref refs/heads/main --scope \"tenant:environments.read tenant:environments.write\" --confirm-production"
        assertThat(err).contains(FixRequest.OPTION_CLI_HEADING).contains(create).contains("trusts get <id> --connection")
        val doc = request(out)
        assertThat(doc["missing"].isEmpty).isTrue()
        assertThat(doc["notes"].toList().map { it.asString() }).anyMatch { it.contains(create) }
        assertThat(doc["options"]["cli"].asString()).contains(create)
    }

    @Test
    fun `a job declaring no environment at all is refused for a missing pin — the note says which line to add to the job`() {
        jobIn(null)
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains("this job declares no `environment:`").doesNotContain("set-plan-profile")
        assertThat(err).contains("job: add `environment: $applyEnvironment` to the job")
        assertThat(request(out)["notes"].toList().map { it.asString() }).anyMatch { it == "job: add `environment: $applyEnvironment` to the job" }
    }

    @Test
    fun `a job in the apply environment refused invalid_client has no local difference — the note points at the audit log and the one re-create`() {
        jobIn(applyEnvironment)
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(err).contains("No difference found locally").contains(FixRequest.OPTION_CLI_HEADING)
            .contains("read the exact reason (field errorReason): `${com.devnow.thoryn.cli.auth.WorkloadIdentityDiagnostics.AUDIT_COMMAND}`")
            .contains("thoryn workload-identity trusts create --name <name> --repository thoryn-io/thoryn-cli")
        assertThat(request(out)["missing"].isEmpty).isTrue()
        assertThat(request(out)["notes"]).hasSize(2)
    }

    @Test
    fun `scope_outside_plan_profile from a connection that names the WRONG apply environment — the note says to paste the github block from trusts get --connection`() {
        // The connection says the apply environment IS the one this job runs in, so the CLI requests the scopes; the hub
        // disagrees (the trust's apply environment is another one) and matches the plan profile.
        jobIn(planEnvironment)
        platform.tokenResponses.clear()
        platform.tokenResponses += WorkloadIdentityPlatform.json(400, """{"error":"invalid_scope","error_description":"${com.devnow.thoryn.cli.auth.WorkloadIdentityDiagnostics.REASON_OUTSIDE_PLAN}"}""")
        val file = writeConnection(pins = """"github": { "owner": "thoryn-io", "repository": "thoryn-cli", "environment": "$planEnvironment" }""")
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", file.toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        assertThat(platform.exchanges.single()).containsKey("scope")
        assertThat(err)
            .contains("scope_outside_plan_profile")
            .contains("$file: auth.github.environment names '$planEnvironment' but the hub matched the PLAN profile for this job's environment '$planEnvironment'")
            .contains("paste the whole github block from `thoryn workload-identity trusts get <id> --connection`")
        assertThat(request(out)["notes"].toList().map { it.asString() }).anyMatch { it.contains("set auth.github.environment to the trust's APPLY environment") }
    }

    // ── SSO-3723 — Option 2, in the browser: the run's consent link, from configuration + the job's own context ──

    @Test
    fun `with THORYN_CONSENT_URL set the refusal prints the run's consent link and the request carries it`() {
        jobIn(planEnvironment)
        System.setProperty(FixRequest.CONSENT_URL_ENV, "https://app.thoryn.io/")
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (exit, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(exit).isEqualTo(LoginCommand.EXIT_WORKLOAD_IDENTITY_FAILED)
        val link = "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/38547022158"
        assertThat(err).contains("${FixRequest.OPTION_BROWSER_HEADING} $link").doesNotContain(FixRequest.NO_CONSENT_LINK_LINE)
        val doc = request(out)
        assertThat(doc["options"]["consentUrl"].asString()).isEqualTo(link)
        assertThat(doc["options"]["cli"].asString()).isEqualTo(expectedCommandBody(doc))
    }

    @Test
    fun `without THORYN_CONSENT_URL Option 2 says to run through the App — the request's consentUrl is null`() {
        jobIn(planEnvironment)
        val out = tempHome.resolve("thoryn-provision-request.json")

        val (_, _, err) = runCli("login", "--connection", writeConnection().toString(), "--fix-request", out.toString())

        assertThat(err).contains("${FixRequest.OPTION_BROWSER_HEADING} ${FixRequest.NO_CONSENT_LINK_LINE}").doesNotContain("/github/consent/run/")
        assertThat(request(out)["options"]["consentUrl"].isNull).isTrue()
    }

    /** Option 1's body as the request itself would render its items and notes — what `options.cli` must equal. */
    private fun expectedCommandBody(doc: JsonNode): String {
        val items = doc["missing"].toList().map {
            FixRequest.MissingRight(
                FixRequest.Kind.of(it["kind"].asString())!!, it["object"].takeUnless { n -> n.isNull }?.asString(), it["subject"].takeUnless { n -> n.isNull }?.asString(),
                it["environment"].takeUnless { n -> n.isNull }?.asString(), it["reason"].asString(), it["cli"].takeUnless { n -> n.isNull }?.asString(),
            )
        }
        return FixRequest.renderOption1Body(items, doc["notes"].toList().map { it.asString() })
    }
}
