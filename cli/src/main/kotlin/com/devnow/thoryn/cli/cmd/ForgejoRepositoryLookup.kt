package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.HttpSender
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-4472 — the immutable ids of a repository on a Forgejo instance, looked up ONCE when `thoryn workload-identity
 * trusts create --provider forgejo` was given only names: `GET <instance>/api/v1/repos/{owner}/{repo}` (Forgejo's
 * public REST API; `id` is the repository id, `owner.id` the owner id — the `repository_id` / `repository_owner_id`
 * claims of the instance's job tokens). The hub never calls a customer's instance for this (product-api: a forge may be
 * private), so the CLI asks from the caller's own machine.
 *
 * ANONYMOUS by design (product owner, 2026-11-23): no credential ever passes through this lookup. A private repository,
 * or an instance whose API an authenticating proxy gates (it answers a redirect, which is never followed), is a
 * [Result.Failed] that says to pass `--owner-id` and `--repository-id`, and where a signed-in browser shows them.
 * The canonical names the instance answers (`owner.login`, `name`) are what the trust pins.
 */
internal class ForgejoRepositoryLookup(private val sender: HttpSender = plainSender()) {

    sealed interface Result {
        data class Found(val owner: String, val ownerId: Long, val repository: String, val repositoryId: Long) : Result
        data class Failed(val message: String) : Result
    }

    fun lookup(instanceUrl: String, owner: String, repository: String): Result {
        val instance = instanceUrl.trim().trimEnd('/')
        val path = "/api/v1/repos/${encode(owner)}/${encode(repository)}"
        val url = "$instance$path"
        val fix = "Pass --owner-id and --repository-id: they are `owner.id` and `id` of GET $url, which a browser signed in to the instance shows."
        val request = try {
            HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .GET()
                .build()
        } catch (e: IllegalArgumentException) {
            return Result.Failed("'$url' is not a valid URL. $fix")
        }
        val response = try {
            sender.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (e: IOException) {
            return Result.Failed("could not reach $instance to look up $owner/$repository (${e.javaClass.simpleName}). $fix")
        }
        return when (val status = response.statusCode()) {
            200 -> parse(response.body(), owner, repository) ?: Result.Failed("$instance answered GET $path without a repository's `id` and `owner.id`. $fix")
            in 300..399 -> Result.Failed(
                "$instance redirected GET $path (HTTP $status) — an authenticating proxy in front of its API? The lookup is anonymous and never follows a redirect. $fix",
            )
            401, 403, 404 -> Result.Failed(
                "$instance has no public repository $owner/$repository (HTTP $status) — a private repository is not visible to the anonymous lookup. $fix",
            )
            else -> Result.Failed("$instance answered GET $path with HTTP $status. $fix")
        }
    }

    private fun parse(body: String?, owner: String, repository: String): Result.Found? {
        val root: JsonNode = runCatching { mapper.readTree(body ?: "") }.getOrNull()?.takeIf { it.isObject } ?: return null
        val repositoryId = root["id"]?.takeIf { it.isIntegralNumber }?.asLong()?.takeIf { it > 0 } ?: return null
        val ownerNode = root["owner"]?.takeIf { it.isObject } ?: return null
        val ownerId = ownerNode["id"]?.takeIf { it.isIntegralNumber }?.asLong()?.takeIf { it > 0 } ?: return null
        fun text(node: JsonNode, name: String): String? = node[name]?.takeIf { it.isString }?.asString()?.takeIf { it.isNotBlank() }
        return Result.Found(
            owner = text(ownerNode, "login") ?: text(ownerNode, "username") ?: owner,
            ownerId = ownerId,
            repository = text(root, "name") ?: repository,
            repositoryId = repositoryId,
        )
    }

    companion object {
        private val mapper: JsonMapper = JsonMapper.builder().build()

        private fun encode(segment: String): String = URLEncoder.encode(segment, Charsets.UTF_8).replace("+", "%20")

        /** A plain client: no cookies, no credentials, and — the JDK default — no redirect is followed. */
        private fun plainSender(): HttpSender {
            val client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
            return HttpSender { request, handler -> client.send(request, handler) }
        }
    }
}
