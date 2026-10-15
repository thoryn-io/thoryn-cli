package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FakeJobTokens
import com.devnow.thoryn.cli.auth.JobIdentity
import com.devnow.thoryn.cli.auth.WorkloadProfile
import com.devnow.thoryn.cli.cmd.connection.Connection
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3722 — the connection.json `thoryn workload-identity trusts create` prints (and `trusts get <id> --connection`
 * prints again) is COMPLETE: exactly what `connection.schema.json` defines for the provider — `auth.provider` and the whole
 * `auth.github` block, `environment` (the APPLY environment) included. The snippet of thoryn-cicd run 38751382032 had
 * neither, so the committed file could not tell the plan job from the apply job and requested the apply scopes.
 * Conformance: the printed document validates against the schema, and fed to the profile selector with a plan-environment
 * claim it yields "plan / no scope requested".
 */
class WorkloadIdentityConnectionSnippetTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private val schema = JsonMapper.builder().build().readTree(javaClass.getResourceAsStream(Connection.SCHEMA_RESOURCE)!!.readBytes())

    /** The JSON block of the printed usage: the first `  {` after the "commit it" line up to its closing `  }`. */
    private fun snippetOf(out: String): String {
        val lines = out.lines()
        val from = lines.indexOfFirst { it.startsWith("Or commit it") }.also { assertThat(it).withFailMessage("no snippet marker in:\n%s", out).isGreaterThan(-1) }
        val open = lines.withIndex().first { (i, l) -> i > from && l == "  {" }.index
        val close = lines.withIndex().first { (i, l) -> i > open && l == "  }" }.index
        return lines.subList(open, close + 1).joinToString("\n")
    }

    @Test
    fun `trusts create prints the complete connection — provider and the whole github block — which validates and selects the plan profile for a plan job`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-plan")))

        val (exit, out, _) = runCli(
            "workload-identity", "trusts", "create", "--name", "thoryn-cli-ci", "--repository", "thoryn-io/thoryn-cli",
            "--owner-id", "229451779", "--repository-id", "1361536515", "--github-environment", "thoryn-provision-e2e",
            "--ref", "refs/heads/main", "--github-hosted-runners-only", "--scope", "tenant:environments.read tenant:environments.write",
            "--confirm-production", "--plan-environment", "thoryn-provision-e2e-plan", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        val snippet = snippetOf(out)
        val node = JsonMapper.builder().build().readTree(snippet)
        assertThat(Connection.validate(node)).isEmpty()
        val connection = Connection.parse(snippet.toByteArray(), "snippet")
        assertThat(connection.slug).isEqualTo("thoryn")
        assertThat(connection.provider).isEqualTo("github_actions")
        assertThat(connection.clientId).isEqualTo("wi_10a7b379c79f7d1353f5798d")
        assertThat(connection.audience).isEqualTo("https://thoryn.auth.stg.thoryn.org")
        assertThat(connection.scopes).containsExactly("tenant:environments.read", "tenant:environments.write", "tenant:applications.read", "tenant:applications.write", "tenant:access.read", "tenant:access.write")
        val github = connection.github!!
        assertThat(github.owner).isEqualTo("thoryn-io")
        assertThat(github.repository).isEqualTo("thoryn-cli")
        assertThat(github.ownerId).isEqualTo(229451779L)
        assertThat(github.repositoryId).isEqualTo(1361536515L)
        assertThat(github.environment).isEqualTo("thoryn-provision-e2e")
        assertThat(github.ref).isEqualTo("refs/heads/main")
        assertThat(github.githubHostedRunnersOnly).isTrue()
        // Every emitted github member is one the schema defines.
        val allowed = schema["properties"]["auth"]["properties"]["github"]["properties"].propertyNames().toSet()
        assertThat(node["auth"]["github"].propertyNames().toSet()).isSubsetOf(allowed)
        // Fed to the profile selector with a plan-environment claim: plan, no scope requested; the apply claim: apply.
        val planJob = JobIdentity.of(FakeJobTokens.token(connection.audience!!, environment = "thoryn-provision-e2e-plan"))
        assertThat(WorkloadProfile.select(planJob, github.environment)).isEqualTo(WorkloadProfile.PLAN)
        assertThat(WorkloadProfile.hubDecides(planJob, github.environment)).isFalse()
        assertThat(WorkloadProfile.select(JobIdentity.of(FakeJobTokens.token(connection.audience!!, environment = "thoryn-provision-e2e")), github.environment)).isEqualTo(WorkloadProfile.APPLY)
        // The snippet keeps its one-line nested blocks, so the usage text reads as before.
        assertThat(snippet).contains("\"workspace\": { \"slug\": \"thoryn\" }").contains("\"provider\": \"github_actions\"").contains("\"githubHostedRunnersOnly\": true")
        assertThat(out).contains("trusts get 7c2d9e4f-1a3b-4c5d-8e6f-9a0b1c2d3e4f --connection")
    }

    @Test
    fun `trusts get --connection prints ONLY the complete connection json, ready to paste`() {
        server.enqueue(jsonResponse(200, fixture("trust-created")))

        val (exit, out, err) = runCli("workload-identity", "trusts", "get", "5b0f6c1e-8c2a-4f5e-9f3d-2a1b0c9d8e7f", "--connection", "--gateway", baseUrl())

        assertThat(err).isEmpty()
        assertThat(exit).isEqualTo(0)
        val node = JsonMapper.builder().build().readTree(out)
        assertThat(Connection.validate(node)).isEmpty()
        val connection = Connection.parse(out.toByteArray(), "stdout")
        assertThat(connection.provider).isEqualTo("github_actions")
        assertThat(connection.github!!.environment).isEqualTo("thoryn-staging-wif")
        assertThat(connection.github!!.githubHostedRunnersOnly).isTrue()
        // `ref: null` in the API response is left out, never written as null.
        assertThat(out).doesNotContain("null").doesNotContain("Sign in from the workflow")
    }

    @Test
    fun `a kubernetes trust's connection carries provider, the file token source and only the schema's pins`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-kubernetes")))

        val (exit, out, _) = runCli("workload-identity", "trusts", "get", "k8s", "--connection", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val node = JsonMapper.builder().build().readTree(out)
        assertThat(Connection.validate(node)).isEmpty()
        val connection = Connection.parse(out.toByteArray(), "stdout")
        assertThat(connection.provider).isEqualTo("kubernetes")
        assertThat(connection.tokenFile).isEqualTo("/var/run/secrets/tokens/thoryn/token")
        assertThat(connection.kubernetes!!.namespace).isNotNull()
        assertThat(node["auth"]["kubernetes"].propertyNames().toSet()).isSubsetOf(setOf("issuer", "namespace", "serviceAccount"))
    }
}
