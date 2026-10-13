package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionReceipt
import com.devnow.thoryn.provision.ProvisionReceiptStore
import com.devnow.thoryn.provision.PublishTarget
import com.devnow.thoryn.provision.PublishedOutput
import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2) — `publishTo:` in the engine
 * and the CLI: an application's clientId is published through the [ProvisionEngine.OutputSink] AFTER the
 * resource is converged and recorded, on EVERY apply (an upsert); an unreachable target is
 * `publish_target_unreachable` raised after the client exists, naming the `gh variable set` to run by hand;
 * `plan` shows the pending publish and reaches no target; the receipt records what was published.
 */
class ProvisionPublishTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private val yaml = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: billing-web
            spec:
              displayName: "Billing web"
              clientType: public
              grantTypes: ["authorization_code"]
              redirectUris: ["https://billing.acme.example/callback"]
            publishTo:
              - kind: githubActionsVariable
                repository: acme/billing-web
                environment: production
                name: THORYN_PRODUCTION_CLIENT_ID
    """.trimIndent()

    private val file = ProvisionFile.parse(yaml.toByteArray(), "provision.yaml")
    private val target = PublishTarget("githubActionsVariable", "acme/billing-web", "production", "THORYN_PRODUCTION_CLIENT_ID")

    /** A sink that records every publish and answers what the test says (null ⇒ published). */
    private class RecordingSink(private val answer: (PublishTarget) -> String? = { null }) : ProvisionEngine.OutputSink {
        val calls = mutableListOf<Pair<PublishTarget, String>>()
        var onPublish: (String) -> Unit = {}
        override fun publish(target: PublishTarget, value: String): String? {
            calls += target to value
            onPublish(value)
            return answer(target)
        }
    }

    private fun engine(sink: ProvisionEngine.OutputSink?, console: ByteArrayOutputStream = ByteArrayOutputStream()): ProvisionEngine =
        if (sink == null) {
            ProvisionEngine(
                clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
                out = PrintStream(console), err = PrintStream(console),
            )
        } else {
            ProvisionEngine(
                clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
                out = PrintStream(console), err = PrintStream(console),
                outputSink = sink,
            )
        }

    // ── engine ──

    @Test
    fun `plan shows the pending publish as a line and reaches no target`() {
        val sink = RecordingSink()
        val plan = engine(sink).plan(file, null, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.publishTo).containsExactly(target)
        assertThat(change.reason).contains("publishes its id to 1 target(s)")
        assertThat(change.toStructured()["publishTo"]).isEqualTo(listOf(mapOf("kind" to "githubActionsVariable", "repository" to "acme/billing-web", "environment" to "production", "name" to "THORYN_PRODUCTION_CLIENT_ID")))
        assertThat(plan.publishes).isEqualTo(1)
        assertThat(sink.calls).isEmpty() // plan is read-only: nothing published
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `apply publishes the clientId AFTER the client is converged and recorded in the receipt`() {
        val console = ByteArrayOutputStream()
        val persisted = mutableListOf<ProvisionReceipt>()
        val sink = RecordingSink()
        var clientsAtPublish: List<Any?> = emptyList()
        var receiptIdsAtPublish: List<String> = emptyList()
        sink.onPublish = { value ->
            clientsAtPublish = api.applications.map { it["clientId"] }
            receiptIdsAtPublish = persisted.lastOrNull()?.resources?.map { it.id }.orEmpty()
            assertThat(value).isNotBlank()
        }
        val e = engine(sink, console)
        val receipt = e.apply(file, null, e.plan(file, null, false), "acme", null) { persisted += it }

        val id = receipt.resources.single().id
        assertThat(sink.calls).containsExactly(target to id)
        // Ordering: when the sink was called, the client already existed AND the receipt already carried its id.
        assertThat(clientsAtPublish).containsExactly(id)
        assertThat(receiptIdsAtPublish).containsExactly(id)
        // The receipt records what was published (where the id landed) — never a secret, there is none.
        assertThat(receipt.resources.single().published).containsExactly(PublishedOutput("githubActionsVariable", "acme/billing-web", "production", "THORYN_PRODUCTION_CLIENT_ID"))
        assertThat(jacksonObjectMapper().writeValueAsString(receipt)).contains("\"published\"").contains("THORYN_PRODUCTION_CLIENT_ID")
        assertThat(console.toString()).contains("published clientId=$id → githubActionsVariable acme/billing-web (environment production) THORYN_PRODUCTION_CLIENT_ID")
    }

    @Test
    fun `an unreachable target is publish_target_unreachable AFTER the client exists and is in the receipt, naming the by-hand command`() {
        val console = ByteArrayOutputStream()
        val persisted = mutableListOf<ProvisionReceipt>()
        val sink = RecordingSink { "repository acme/billing-web was not found" }
        val e = engine(sink, console)
        val thrown = assertThatThrownBy { e.apply(file, null, e.plan(file, null, false), "acme", null) { persisted += it } }
            .isInstanceOf(ProvisionEngine.PublishTargetUnreachableException::class.java)
            .hasMessageContaining(ProvisionEngine.ERROR_PUBLISH_UNREACHABLE)
            .hasMessageContaining("repository acme/billing-web was not found")
        // The client exists (converged before the publish was attempted) …
        val id = api.applications.single()["clientId"].toString()
        // … the receipt records its id, with nothing recorded as published …
        val last = persisted.last()
        assertThat(last.resources.single().id).isEqualTo(id)
        assertThat(last.resources.single().published).isEmpty()
        // … and the error names the one command a human runs, with the id from the receipt.
        thrown.hasMessageContaining("gh variable set THORYN_PRODUCTION_CLIENT_ID --body $id --repo acme/billing-web --env production")
        assertThat(console.toString()).contains("could not publish its clientId").contains("by hand: gh variable set THORYN_PRODUCTION_CLIENT_ID --body $id")
    }

    @Test
    fun `a re-apply issues no product-api write but publishes again — an upsert on every apply`() {
        val sink = RecordingSink()
        val e = engine(sink)
        val first = e.apply(file, null, e.plan(file, null, false), "acme", null) {}
        val id = first.resources.single().id
        api.reset()
        val plan = e.plan(file, first, false)
        assertThat(plan.changes.single().action).isEqualTo(ChangeAction.NOOP)
        assertThat(plan.hasChanges).isTrue() // the pending publish is what apply still does
        val second = e.apply(file, first, plan, "acme", null) {}
        assertThat(api.writes).isEmpty()
        assertThat(sink.calls).containsExactly(target to id, target to id)
        assertThat(second.resources.single().published).hasSize(1)
    }

    @Test
    fun `an engine without a publisher fails loud on a target instead of skipping it`() {
        val e = engine(null)
        assertThatThrownBy { e.apply(file, null, e.plan(file, null, false), "acme", null) {} }
            .isInstanceOf(ProvisionEngine.PublishTargetUnreachableException::class.java)
            .hasMessageContaining("no publisher is available")
        assertThat(api.applications).hasSize(1)
    }

    // ── CLI ──

    private fun writeFile(body: String): File =
        File(tempHome.toFile(), ".thoryn/provision.yaml").also { it.parentFile.mkdirs(); it.writeText(body) }

    @Test
    fun `plan prints where the id will land, apply publishes through gh, a re-apply upserts, an unreachable target exits non-zero after the client exists`() {
        val gh = FakeGhVariables()
        ProvisionCommand.ghRunner = { gh }
        val f = writeFile(yaml)

        val plan = runCli("provision", "plan", "--file", f.path, "--gateway", baseUrl())
        assertThat(plan.exit).isEqualTo(0)
        assertThat(plan.out).contains("application  billing-web  create").contains("application billing-web: publish clientId → githubActionsVariable acme/billing-web (environment production) THORYN_PRODUCTION_CLIENT_ID").contains("1 output(s) to publish")
        assertThat(gh.calls).isEmpty()

        val apply = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(apply.err).isEmpty()
        assertThat(apply.exit).isEqualTo(0)
        val id = api.applications.single()["clientId"].toString()
        assertThat(gh.variables).containsEntry("acme/billing-web@production:THORYN_PRODUCTION_CLIENT_ID", id)
        assertThat(gh.environments).contains("acme/billing-web/production") // created when absent
        val receipt = ProvisionReceiptStore().read(File(f.parentFile, "provision.receipt.json"))!!
        assertThat(receipt.resources.single().published.single().name).isEqualTo("THORYN_PRODUCTION_CLIENT_ID")

        // Re-apply: no product-api write, the variable is set again (upsert), the environment is not re-created.
        api.reset(); gh.calls.clear()
        val again = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(again.exit).isEqualTo(0)
        assertThat(api.writes).isEmpty()
        assertThat(gh.invocations).contains("gh variable set THORYN_PRODUCTION_CLIENT_ID --body $id --repo acme/billing-web --env production").noneMatch { it.contains("--method PUT") }

        // The gh account loses the repository: the client stays, the receipt stays, the exit is non-zero and names the fallback.
        gh.repos.clear()
        val lost = runCli("provision", "apply", "--file", f.path, "--gateway", baseUrl(), "--yes")
        assertThat(lost.exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR).isNotEqualTo(0)
        assertThat(lost.out).contains("Applied. 1 resource(s) owned.")
        assertThat(lost.err).contains("publish_target_unreachable").contains("gh variable set THORYN_PRODUCTION_CLIENT_ID --body $id --repo acme/billing-web --env production").doesNotContain("Apply stopped")
        assertThat(api.applications).hasSize(1)
        assertThat(ProvisionReceiptStore().read(File(f.parentFile, "provision.receipt.json"))!!.resources.single().id).isEqualTo(id)
    }
}
