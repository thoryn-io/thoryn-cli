package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3684 — [WorkloadIdentityDiagnostics] for a `kubernetes` trust: the pod's projected ServiceAccount token
 * is read for its `iss`, `sub` and `kubernetes.io` claims, judged against the cluster pins (never against
 * GitHub's issuer), and a legacy non-projected token is named as such.
 */
class WorkloadIdentityKubernetesDiagnosticsTest {

    private val audience = "https://thoryn.auth.stg.thoryn.org"
    private val binding = WorkloadIdentityBinding(
        clientId = "wi_9a8b7c6d5e4f3a2b1c0d9e8f",
        audience = audience,
        tokenEndpoint = "$audience/oauth2/token",
        scope = "tenant:applications.write",
        provider = "kubernetes",
    )

    private fun identity(namespace: String = "forge", serviceAccount: String = "forge-oauth2-proxy", projected: Boolean = true, aud: String = audience) =
        JobIdentity.of(FakeJobTokens.token(FakeJobTokens.kubernetesClaims(aud, namespace, serviceAccount, projected = projected)))

    private fun refused(identity: JobIdentity) =
        WorkloadIdentityException("refused", oauthError = "invalid_client", status = 401, jobIdentity = identity)

    @Test
    fun `a projected ServiceAccount token is read for its namespace and service account`() {
        val id = identity()
        assertThat(id.isKubernetes).isTrue()
        assertThat(id.issuer).isEqualTo(FakeJobTokens.KUBERNETES_ISSUER)
        assertThat(id.subject).isEqualTo("system:serviceaccount:forge:forge-oauth2-proxy")
        assertThat(id.audience).containsExactly(audience)
        assertThat(id.kubernetesNamespace).isEqualTo("forge")
        assertThat(id.kubernetesServiceAccount).isEqualTo("forge-oauth2-proxy")
        assertThat(id.repository).isNull()
    }

    @Test
    fun `a Kubernetes token is never judged against GitHub's issuer — with the provider given or inferred from the subject`() {
        assertThat(WorkloadIdentityDiagnostics.localMismatches(identity(), audience, null, provider = "kubernetes")).isEmpty()
        assertThat(WorkloadIdentityDiagnostics.localMismatches(identity(), audience, null, provider = null)).isEmpty()
        // The GitHub rules still apply to a GitHub token when no provider is named.
        val githubToken = JobIdentity.of(FakeJobTokens.token(audience))
        assertThat(WorkloadIdentityDiagnostics.localMismatches(githubToken.copy(issuer = "https://evil.example"), audience, null)).anyMatch { it.startsWith("iss:") }
    }

    @Test
    fun `the cluster pins name the field that differs — issuer, namespace, service account`() {
        val pins = KubernetesPins(issuer = "https://oidc.eks.eu-central-1.amazonaws.com/id/X", namespace = "forge", serviceAccount = "forge-oauth2-proxy")
        val mismatches = WorkloadIdentityDiagnostics.localMismatches(
            identity(namespace = "staging", serviceAccount = "other"), audience, null, provider = "kubernetes", kubernetesPins = pins,
        )
        assertThat(mismatches).anyMatch { it.startsWith("iss: the trust pins issuer 'https://oidc.eks.eu-central-1.amazonaws.com/id/X'") }
        assertThat(mismatches).anyMatch { it == "namespace: the trust pins 'forge'; this pod runs in 'staging'." }
        assertThat(mismatches).anyMatch { it == "serviceAccount: the trust pins 'forge-oauth2-proxy'; this pod runs as 'other'." }
        assertThat(
            WorkloadIdentityDiagnostics.localMismatches(identity(), audience, null, provider = "kubernetes", kubernetesPins = pins.copy(issuer = FakeJobTokens.KUBERNETES_ISSUER)),
        ).isEmpty()
    }

    @Test
    fun `a legacy Secret-based token (no kubernetes_io claim) and a wrong audience are named`() {
        val legacy = WorkloadIdentityDiagnostics.localMismatches(identity(projected = false), audience, null, provider = "kubernetes")
        assertThat(legacy).anyMatch { it.startsWith("kubernetes.io: the token carries no `kubernetes.io` claim") }

        val wrongAudience = WorkloadIdentityDiagnostics.localMismatches(identity(aud = "$audience/staging"), audience, null, provider = "kubernetes")
        assertThat(wrongAudience).anyMatch { it.startsWith("aud: the ServiceAccount token is for $audience/staging") && it.contains("projected volume's `audience:`") }
    }

    @Test
    fun `the report shows the pod block, the kubernetes pins hint and the kubernetes comparison line`() {
        val report = WorkloadIdentityDiagnostics.render(refused(identity()), binding)
        assertThat(report)
            .contains("This pod (claims of its projected ServiceAccount token; the token itself is not shown):")
            .contains("system:serviceaccount:forge:forge-oauth2-proxy")
            .contains("namespace            forge")
            .contains("service account      forge-oauth2-proxy")
            .contains("name the trust's pins in the connection's auth.kubernetes")
            .contains("issuer, namespace and service account must all match")
            .doesNotContain("GitHub OIDC token")
            .doesNotContain("repository_id")
        val pinned = WorkloadIdentityDiagnostics.render(refused(identity()), binding.copy(kubernetesPins = KubernetesPins(namespace = "forge")))
        assertThat(pinned).contains("No difference found locally against the pins the connection names.")
    }
}
