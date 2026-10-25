package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.SecretTarget
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3659 (ADR 2026-10-13 converge §5; production-clients ADR §3 tier 3) — `secretSink:` in the engine: a
 * confidential application's minted secret is handed to the [ProvisionEngine.DeclaredSecretSink] IMMEDIATELY
 * AFTER the client is converged and recorded; a sink that answers a reason falls back to the generic
 * [ProvisionEngine.SecretSink]; when neither reaches, the client stays and `undelivered_secrets` names the
 * resource and the recovery; `plan` shows the intended delivery and mints nothing; the secret never appears in
 * the receipt, the plan, the console — or a sink's reason.
 *
 * The secret values here are the fake product-api's `minted-secret-<id>`; assertions are on sink calls, never
 * on an echoed secret.
 */
class ProvisionSecretSinkEngineTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private val yaml = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-login
            spec:
              displayName: "Forge login"
              clientType: confidential
              grantTypes: ["authorization_code"]
              redirectUris: ["https://forge.example/oauth2/callback"]
            secretSink:
              kind: kubernetesSecret
              namespace: forge
              name: forge-login
              key: client-secret
    """.trimIndent()

    private val file = ProvisionFile.parse(yaml.toByteArray(), "provision.yaml")
    private val target = SecretTarget(kind = "kubernetesSecret", namespace = "forge", name = "forge-login", key = "client-secret")

    /** A declared sink that records every delivery and answers what the test says (null ⇒ delivered). */
    private class RecordingDeclaredSink(private val answer: (SecretTarget) -> String? = { null }) : ProvisionEngine.DeclaredSecretSink {
        val calls = mutableListOf<Triple<SecretTarget, String, String>>()
        var onDeliver: (String, String) -> Unit = { _, _ -> }
        override fun deliver(target: SecretTarget, clientId: String, secret: String): String? {
            calls += Triple(target, clientId, secret)
            onDeliver(clientId, secret)
            return answer(target)
        }
    }

    /** The host's generic channel (`--secret-file` / TTY in the CLI), recording what reached it. */
    private class RecordingGenericSink(private val accept: Boolean = true) : ProvisionEngine.SecretSink {
        val calls = mutableListOf<Pair<String, String>>()
        override fun emit(clientId: String, secret: String): Boolean { calls += clientId to secret; return accept }
    }

    private fun engine(
        declared: ProvisionEngine.DeclaredSecretSink? = null,
        generic: ProvisionEngine.SecretSink = ProvisionEngine.SecretSink.undeliverable(),
        console: ByteArrayOutputStream = ByteArrayOutputStream(),
    ): ProvisionEngine {
        val clients = { slug: String? -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) }
        return if (declared == null) {
            ProvisionEngine(clients = clients, out = PrintStream(console), err = PrintStream(console), secretSink = generic)
        } else {
            ProvisionEngine(clients = clients, out = PrintStream(console), err = PrintStream(console), secretSink = generic, declaredSecretSink = declared)
        }
    }

    private fun mintedFor(clientId: String): String = api.mintedSecrets.getValue(clientId)

    @Test
    fun `plan shows the intended delivery as a line and mints nothing`() {
        val sink = RecordingDeclaredSink()
        val generic = RecordingGenericSink()
        val plan = engine(sink, generic).plan(file, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.secretSink).isEqualTo(target)
        assertThat(change.reason).contains("a client secret will be minted and delivered to kubernetesSecret forge/forge-login key client-secret")
        assertThat(change.toStructured()["secretSink"]).isEqualTo(mapOf("kind" to "kubernetesSecret", "namespace" to "forge", "name" to "forge-login", "key" to "client-secret"))
        assertThat(plan.deliveries).isEqualTo(1)
        assertThat(plan.toStructured()["summary"]).asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP).containsEntry("deliver", 1)
        // Read-only: nothing is created, nothing minted, no sink reached.
        assertThat(api.writes).isEmpty()
        assertThat(api.mintedSecrets).isEmpty()
        assertThat(sink.calls).isEmpty()
        assertThat(generic.calls).isEmpty()
    }

    @Test
    fun `a plan without a secretSink is customerManaged by default — discarded by apply, no delivery`() {
        // SSO-3954 — the default sink: the create's value is discarded, a person mints the real one.
        val plain = ProvisionFile.parse(yaml.substringBefore("secretSink:").toByteArray(), "provision.yaml")
        val plan = engine(RecordingDeclaredSink()).plan(plain, false)
        assertThat(plan.changes.single().secretSink).isEqualTo(SecretTarget.CUSTOMER_MANAGED)
        assertThat(plan.changes.single().reason).contains("minted and discarded — managed by the customer").doesNotContain("shown once")
        assertThat(plan.deliveries).isZero()
        assertThat(plan.customerManaged).isEqualTo(1)
    }

    @Test
    fun `apply delivers the minted secret to the declared sink AFTER the client is converged`() {
        val console = ByteArrayOutputStream()
        val sink = RecordingDeclaredSink()
        val generic = RecordingGenericSink()
        var liveAtDelivery: List<Any?> = emptyList()
        sink.onDeliver = { _, _ ->
            liveAtDelivery = api.applications.map { it["clientId"] }
        }
        val e = engine(sink, generic, console)
        val plan = e.plan(file, false)
        val receipt = e.apply(file, plan, "acme", null)

        val id = receipt.resources.single().id
        val secret = mintedFor(id)
        // Delivered exactly once, to the declared target, with the minted value — and the generic channel untouched.
        assertThat(sink.calls).containsExactly(Triple(target, id, secret))
        assertThat(generic.calls).isEmpty()
        assertThat(e.undeliveredSecrets).isEmpty()
        // ORDER: when the sink was reached, the client already existed.
        assertThat(liveAtDelivery).containsExactly(id)
        // The secret is nowhere but the sink call.
        val mapper = jacksonObjectMapper()
        assertThat(mapper.writeValueAsString(receipt.toStructured())).doesNotContain(secret)
        assertThat(mapper.writeValueAsString(plan.toStructured())).doesNotContain(secret)
        assertThat(console.toString()).doesNotContain(secret)
            .contains("application forge-login: clientId=$id (client secret minted)")
            .contains("client secret delivered → kubernetesSecret forge/forge-login key client-secret")
    }

    @Test
    fun `a declared sink that answers a reason falls back to the generic channel, and the reason is shown`() {
        val console = ByteArrayOutputStream()
        val sink = RecordingDeclaredSink { "namespace 'forge' is not reachable through the current kubectl context" }
        val generic = RecordingGenericSink()
        val e = engine(sink, generic, console)
        val receipt = e.apply(file, e.plan(file, false), "acme", null)
        val id = receipt.resources.single().id
        assertThat(sink.calls).hasSize(1)
        assertThat(generic.calls).containsExactly(id to mintedFor(id))
        assertThat(e.undeliveredSecrets).isEmpty()
        assertThat(console.toString())
            .contains("could not deliver its client secret to kubernetesSecret forge/forge-login key client-secret (namespace 'forge' is not reachable")
            .doesNotContain(ProvisionEngine.ERROR_UNDELIVERED_SECRETS)
            .doesNotContain(mintedFor(id))
    }

    @Test
    fun `a declared sink that throws is a reason, not a stopped apply`() {
        val console = ByteArrayOutputStream()
        val sink = RecordingDeclaredSink { throw IllegalStateException("kubectl exploded") }
        val generic = RecordingGenericSink()
        val e = engine(sink, generic, console)
        val receipt = e.apply(file, e.plan(file, false), "acme", null)
        assertThat(receipt.resources).hasSize(1)
        assertThat(api.applications).hasSize(1)
        assertThat(generic.calls).hasSize(1)
        assertThat(console.toString()).contains("(kubectl exploded)")
    }

    @Test
    fun `when neither sink reaches, the client stays and undelivered_secrets names the resource and the recovery`() {
        val console = ByteArrayOutputStream()
        // No delivery in this host (the engine default) and a generic channel that refuses (no --secret-file, no TTY).
        val e = engine(null, RecordingGenericSink(accept = false), console)
        val receipt = e.apply(file, e.plan(file, false), "acme", null)

        val id = receipt.resources.single().id
        assertThat(api.applications.single()["clientId"]).isEqualTo(id) // exists — and the apply output carries the id
        assertThat(e.undeliveredSecrets).containsExactly(id)
        val detail = e.undeliveredSecretDetails.single()
        assertThat(detail.resourceKey).isEqualTo("application/forge-login")
        assertThat(detail.clientId).isEqualTo(id)
        assertThat(detail.target).isEqualTo(target)
        assertThat(detail.reason).contains("no secret delivery is available in this context").doesNotContain(mintedFor(id))
        assertThat(detail.recovery).isEqualTo("thoryn clients rotate-secret $id --secret-file <path>")
        assertThat(console.toString())
            .contains("application forge-login: undelivered_secrets")
            .contains("thoryn clients rotate-secret $id --secret-file <path>")
            .doesNotContain(mintedFor(id))
        // A re-apply creates nothing, mints nothing, and reports nothing undelivered.
        api.reset()
        e.apply(file, e.plan(file, false), "acme", null)
        assertThat(api.writes).isEmpty()
        assertThat(e.undeliveredSecrets).isEmpty()
    }

    @Test
    fun `a sink reason that echoes the secret is redacted before it is printed or recorded`() {
        val console = ByteArrayOutputStream()
        var leaked = ""
        val sink = RecordingDeclaredSink { "kubectl said: $leaked" }
        sink.onDeliver = { _, secret -> leaked = secret }
        val e = engine(sink, RecordingGenericSink(accept = false), console)
        val receipt = e.apply(file, e.plan(file, false), "acme", null)
        val id = receipt.resources.single().id
        assertThat(leaked).isEqualTo(mintedFor(id)) // the fake sink really did put the value in its reason …
        assertThat(console.toString()).doesNotContain(mintedFor(id)).contains("kubectl said: [redacted]") // … and nothing shows it
        assertThat(e.undeliveredSecretDetails.single().reason).doesNotContain(mintedFor(id)).contains("[redacted]")
    }

    @Test
    fun `a public client with no secret and an application without a sink reach neither the delivery port nor the generic channel`() {
        val mixed = ProvisionFile.parse(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: application
                name: spa
                spec: { displayName: "SPA", clientType: public, redirectUris: ["http://127.0.0.1/callback"] }
              - kind: application
                name: worker
                spec: { displayName: "Worker", clientType: confidential, grantTypes: [client_credentials] }
            """.trimIndent().toByteArray(),
            "provision.yaml",
        )
        val sink = RecordingDeclaredSink()
        val generic = RecordingGenericSink()
        val e = engine(sink, generic)
        val receipt = e.apply(mixed, e.plan(mixed, false), "acme", null)
        val workerId = receipt.resources.first { it.name == "worker" }.id
        assertThat(sink.calls).isEmpty() // no secretSink declared ⇒ the declared port is never reached
        // SSO-3954 — nor the generic channel: the worker's secret is the customer's; apply discards the create's value.
        assertThat(generic.calls).isEmpty()
        assertThat(e.undeliveredSecrets).isEmpty()
        assertThat(api.mintedSecrets).containsOnlyKeys(workerId)
    }
}
