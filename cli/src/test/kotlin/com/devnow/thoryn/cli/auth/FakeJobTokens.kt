package com.devnow.thoryn.cli.auth

import tools.jackson.databind.json.JsonMapper
import java.util.Base64
import java.util.UUID

/**
 * SSO-3308 — builds GitHub-Actions-shaped job tokens for tests. The CLI never verifies a job token (the
 * platform does), it only reads its public claims for diagnostics, so an unsigned compact JWS with the
 * real claim names is a faithful stand-in. Every token carries a fresh `jti`, as GitHub's do.
 */
object FakeJobTokens {

    private val mapper = JsonMapper.builder().build()

    fun claims(
        audience: String,
        repository: String = "thoryn-io/thoryn-cli",
        repositoryId: String = "1044556677",
        ownerId: String = "187654321",
        ref: String = "refs/heads/main",
        environment: String? = null,
        eventName: String = "push",
        runnerEnvironment: String = "github-hosted",
    ): Map<String, Any?> = buildMap {
        put("iss", WorkloadIdentityFlow.GITHUB_ACTIONS_ISSUER)
        put("aud", audience)
        // GitHub's default `sub`: environment wins, then pull_request, then the ref.
        put("sub", "repo:$repository:" + when {
            environment != null -> "environment:$environment"
            eventName == "pull_request" -> "pull_request"
            else -> "ref:$ref"
        })
        put("jti", UUID.randomUUID().toString())
        put("repository", repository)
        put("repository_id", repositoryId)
        put("repository_owner", repository.substringBefore('/'))
        put("repository_owner_id", ownerId)
        put("ref", ref)
        environment?.let { put("environment", it) }
        put("event_name", eventName)
        put("runner_environment", runnerEnvironment)
        val now = System.currentTimeMillis() / 1000
        put("iat", now)
        put("exp", now + 300)
    }

    fun token(claims: Map<String, Any?>): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"RS256","typ":"JWT","kid":"test"}""".toByteArray())
        val payload = enc.encodeToString(mapper.writeValueAsBytes(claims))
        return "$header.$payload.c2lnbmF0dXJl"
    }

    fun token(audience: String, environment: String? = null): String = token(claims(audience, environment = environment))

    /** SSO-3684 — the public shape of a Kubernetes PROJECTED ServiceAccount token (k3s v1.31, RS256). */
    fun kubernetesClaims(
        audience: String,
        namespace: String = "forge",
        serviceAccount: String = "forge-oauth2-proxy",
        issuer: String = KUBERNETES_ISSUER,
        projected: Boolean = true,
    ): Map<String, Any?> = buildMap {
        put("iss", issuer)
        put("aud", listOf(audience))
        put("sub", "system:serviceaccount:$namespace:$serviceAccount")
        put("jti", UUID.randomUUID().toString())
        if (projected) {
            put(
                "kubernetes.io",
                mapOf(
                    "namespace" to namespace,
                    "serviceaccount" to mapOf("name" to serviceAccount, "uid" to "0c3b9e1a-6d2f-4b8e-9a1c-2d3e4f5a6b7c"),
                    "pod" to mapOf("name" to "$serviceAccount-7d9f8c6b5-xk2lp", "uid" to "9e8d7c6b-5a4f-4e3d-2c1b-0a9f8e7d6c5b"),
                ),
            )
        }
        val now = System.currentTimeMillis() / 1000
        put("iat", now)
        put("nbf", now)
        put("exp", now + 3600)
    }

    const val KUBERNETES_ISSUER: String = "https://kubernetes.default.svc.cluster.local"

    fun kubernetesToken(audience: String, namespace: String = "forge", serviceAccount: String = "forge-oauth2-proxy"): String =
        token(kubernetesClaims(audience, namespace, serviceAccount))
}
