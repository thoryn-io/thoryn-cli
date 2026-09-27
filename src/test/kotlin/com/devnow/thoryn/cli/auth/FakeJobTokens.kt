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
        put("sub", "repo:$repository:" + (environment?.let { "environment:$it" } ?: "ref:$ref"))
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
}
