package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.SecretTarget
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.assertj.core.api.InstanceOfAssertFactories
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3921 (oauthy ADR 2026-10-14 credential ladder, rung 3 "runtime pull") — `secretSink: { kind: workloadPull, trust }`
 * in the engine, against the fake product-api: a CI apply that CREATES a confidential application discards the minted
 * secret (no sink, no generic channel, nothing undelivered), converges `manager` on the application for the named
 * `kubernetes` trust's `wi_` workload client (so its pod's `clients rotate-secret` is allowed), and a re-apply mints and
 * writes nothing. A trust that is missing, on another plane, not `kubernetes`, or without `tenant:applications.write` is a
 * red plan, refused before any write.
 */
class ProvisionWorkloadPullEngineTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private val k8sPins = mapOf("issuer" to "https://kubernetes.default.svc.cluster.local", "namespace" to "forge", "serviceAccount" to "forge-oauth2-proxy")

    private fun seedPodTrust(env: String? = null, provider: String = "kubernetes", scopes: List<String> = listOf("tenant:applications.read", "tenant:applications.write")): String {
        val pins = if (provider == "kubernetes") k8sPins else mapOf("owner" to "acme", "repository" to "forge")
        api.seedTrust(env, "forge-pods", provider, scopes, pins)
        return api.trusts.last()["clientId"].toString()
    }

    private fun yaml(environment: String? = null, extra: String = "") = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: forge-login
            ${environment?.let { "environment: $it" } ?: ""}
            spec:
              displayName: "Forge login"
              grantTypes: ["authorization_code"]
              redirectUris: ["https://forge.example/oauth2/callback"]
            secretSink:
              kind: workloadPull
              trust: forge-pods
    """.trimIndent() + extra

    private fun parse(text: String) = ProvisionFile.parse(text.toByteArray(), "provision.yaml")

    /** Records any delivery attempt: a runtime-pull secret must never reach one. */
    private class RecordingDeclaredSink : ProvisionEngine.DeclaredSecretSink {
        val calls = mutableListOf<String>()
        override fun deliver(target: SecretTarget, clientId: String, secret: String): String? { calls += clientId; return null }
    }

    /** The CI host's generic channel: no `--secret-file`, no TTY — it refuses, and records that it was asked. */
    private class RefusingGenericSink : ProvisionEngine.SecretSink {
        val calls = mutableListOf<String>()
        override fun emit(clientId: String, secret: String): Boolean { calls += clientId; return false }
    }

    private val declared = RecordingDeclaredSink()
    private val generic = RefusingGenericSink()
    private val console = ByteArrayOutputStream()

    private fun engine(): ProvisionEngine = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        secretSink = generic, declaredSecretSink = declared,
    )

    @Test
    fun `a CI apply that creates the application discards the secret, delivers nothing, and grants the pod's workload client manager`() {
        val wi = seedPodTrust()
        val file = parse(yaml())
        val e = engine()
        val plan = e.plan(file, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.reason).contains("a client secret will be minted and discarded — the pods of trust forge-pods mint their own at start")
        assertThat(change.secretSink).isEqualTo(SecretTarget(kind = "workloadPull", trust = "forge-pods"))
        assertThat(change.pullClientId).isEqualTo(wi)
        assertThat(change.grantAdds).containsExactly("client:$wi manager")
        assertThat(change.toStructured()["secretSink"]).isEqualTo(mapOf("kind" to "workloadPull", "trust" to "forge-pods", "workloadClientId" to wi))
        assertThat(plan.deliveries).isZero()
        assertThat(plan.runtimePulls).isEqualTo(1)
        assertThat(plan.toStructured()["summary"]).asInstanceOf(InstanceOfAssertFactories.MAP).containsEntry("pull", 1).containsEntry("deliver", 0)
        assertThat(api.writes).isEmpty()

        val result = e.apply(file, plan, "acme", null)
        val id = result.resources.single().id
        val secret = api.mintedSecrets.getValue(id)
        // Nothing was handed anywhere, so nothing is undelivered — the apply is green with no channel at all.
        assertThat(declared.calls).isEmpty()
        assertThat(generic.calls).isEmpty()
        assertThat(e.undeliveredSecrets).isEmpty()
        // The pod's workload client may rotate the secret: `manager` on the application.
        assertThat(api.grantsOn("application:$id")).contains("client:$wi manager")
        // The value is nowhere: not the console, the plan or the apply output.
        val mapper = jacksonObjectMapper()
        assertThat(console.toString()).doesNotContain(secret)
            .contains("client secret discarded (never shown or stored) — pulled at runtime by the pods of trust forge-pods")
            .contains("+ grant application forge-login: client:$wi manager on application:$id")
        assertThat(mapper.writeValueAsString(result.toStructured())).doesNotContain(secret)
        assertThat(mapper.writeValueAsString(plan.toStructured())).doesNotContain(secret)
    }

    @Test
    fun `a re-apply mints nothing, writes nothing, and still shows who pulls the secret`() {
        val wi = seedPodTrust()
        val file = parse(yaml())
        val e = engine()
        e.apply(file, e.plan(file, false), "acme", null)
        api.reset()

        val again = e.plan(file, false)
        val change = again.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.grantAdds).isEmpty()
        assertThat(change.secretSink?.runtimePull).isTrue()
        assertThat(change.pullClientId).isEqualTo(wi)
        assertThat(again.hasChanges).isFalse()
        e.apply(file, again, "acme", null)
        assertThat(api.writes).isEmpty()
        assertThat(api.mintedSecrets).hasSize(1)
    }

    @Test
    fun `the grant is converged on an application that already exists without it, and only that grant`() {
        val wi = seedPodTrust()
        val id = api.seedApplication(null, "Forge login", redirectUris = listOf("https://forge.example/oauth2/callback"))
        api.applications.single()["grantTypes"] = listOf("authorization_code")
        api.seedGrant("member:bob", "viewer", "application:$id")
        val file = parse(yaml())
        val e = engine()
        val plan = e.plan(file, prune = true)
        val change = plan.changes.single { it.kind == ProvisionFile.KIND_APPLICATION }
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.grantAdds).containsExactly("client:$wi manager")
        // The file declares no `grants:`: it does not manage the object's grants — nothing else is read as undeclared or revoked.
        assertThat(change.grantRemoves).isEmpty()
        assertThat(change.grantUndeclared).isEmpty()
        e.apply(file, plan, "acme", null)
        assertThat(api.grantsOn("application:$id")).containsExactlyInAnyOrder("member:bob viewer", "client:$wi manager")
        assertThat(api.mintedSecrets).isEmpty()
    }

    @Test
    fun `with a declared grants block the workload client's manager is part of it, so --prune never revokes it`() {
        val wi = seedPodTrust()
        val id = api.seedApplication(null, "Forge login", redirectUris = listOf("https://forge.example/oauth2/callback"))
        api.applications.single()["grantTypes"] = listOf("authorization_code")
        api.seedGrant("client:$wi", "manager", "application:$id")
        api.seedGrant("member:bob", "viewer", "application:$id")
        val file = parse(yaml().replace("    secretSink:", "    grants:\n      - { subject: \"member:alice\", relation: viewer }\n    secretSink:"))
        val plan = engine().plan(file, prune = true)
        val change = plan.changes.single { it.kind == ProvisionFile.KIND_APPLICATION }
        assertThat(change.grantAdds).containsExactly("member:alice viewer")
        assertThat(change.grantRemoves).containsExactly("member:bob viewer")
    }

    @Test
    fun `a trust declared in the same file is created first and its real workload client is granted`() {
        val file = parse(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: environment
                name: sandbox
                spec: { slug: forge-sandbox }
              - kind: workloadIdentityTrust
                name: forge-pods
                environment: sandbox
                spec:
                  provider: kubernetes
                  kubernetes: { issuer: "https://kubernetes.default.svc.cluster.local", namespace: forge, serviceAccount: forge-oauth2-proxy }
                  scopes: [tenant:applications.read, tenant:applications.write]
              - kind: application
                name: forge-login
                environment: sandbox
                spec:
                  displayName: "Forge login"
                  grantTypes: ["authorization_code"]
                  redirectUris: ["https://forge.example/oauth2/callback"]
                secretSink: { kind: workloadPull, trust: forge-pods }
            """.trimIndent(),
        )
        val e = engine()
        val plan = e.plan(file, false)
        val change = plan.changes.single { it.kind == ProvisionFile.KIND_APPLICATION }
        assertThat(change.action).isEqualTo(ChangeAction.CREATE)
        assertThat(change.pullClientId).isNull()
        assertThat(change.grantAdds).containsExactly("client:<wi_ client of trust forge-pods, created by this apply> manager")
        val result = e.apply(file, plan, "acme", null)
        val wi = api.trusts.single()["clientId"].toString()
        val id = result.resources.single { it.kind == ProvisionFile.KIND_APPLICATION }.id
        assertThat(api.grantsOn("application:$id")).contains("client:$wi manager")
        assertThat(api.grantsOn("application:$id")).noneMatch { it.contains("<") }
        assertThat(e.undeliveredSecrets).isEmpty()
        assertThat(generic.calls).isEmpty()
    }

    @Test
    fun `a trust that is not live in the application's plane is a red plan and apply writes nothing`() {
        api.seedEnvironment("forge-sandbox")
        seedPodTrust(env = null) // live on the PRODUCTION plane only
        val file = parse(yaml("forge-sandbox"))
        val e = engine()
        val plan = e.plan(file, false)
        val change = plan.changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionFile.ERR_WORKLOAD_PULL_TRUST_NOT_FOUND)
        assertThat(change.reason).contains("no workloadIdentityTrust named 'forge-pods' in environment 'forge-sandbox'")
        assertThat(change.fixNote).isEqualTo(ProvisionEngine.WORKLOAD_PULL_FILE_FIX_NOTE)
        assertThatThrownBy { e.apply(file, plan, "acme", null) }.isInstanceOf(ProvisionException::class.java)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a live trust that is not a kubernetes trust is refused — a CI job pulling a secret is the courier`() {
        seedPodTrust(provider = "github_actions")
        val change = engine().plan(parse(yaml()), false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionFile.ERR_WORKLOAD_PULL_TRUST_PROVIDER)
        assertThat(change.reason).contains("is a 'github_actions' trust")
    }

    @Test
    fun `a live trust without tenant applications write is refused — its pod could not rotate the secret`() {
        seedPodTrust(scopes = listOf("tenant:applications.read"))
        val change = engine().plan(parse(yaml()), false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.ERROR)
        assertThat(change.error).isEqualTo(ProvisionFile.ERR_WORKLOAD_PULL_SCOPE_MISSING)
        assertThat(change.reason).contains("does not carry tenant:applications.write")
    }
}
