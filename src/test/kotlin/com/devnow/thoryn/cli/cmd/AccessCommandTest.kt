package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3113 (epic SSO-3108) — `thoryn access grant | revoke | list | mine` against a MockWebServer
 * standing in for the api-gateway → product-api `/api/v1/access` surface (the SSO-3112 contract).
 * Thin wrappers: the exact request shapes the product side is checked against, the ListEnvelope
 * (`data`, not `items`) rendering, the client-side ref grammar, and the RFC 9457 scope hint.
 */
class AccessCommandTest : CommandTestBase() {

    private val envId = "11111111-1111-1111-1111-111111111111"

    @Test
    fun `grant POSTs subject relation object and renders the created grant`() {
        server.enqueue(jsonResponse(201, """{"subject":"client:cli-ci","relation":"manager","object":"environment:$envId","createdAt":"2026-09-15T10:00:00Z"}"""))

        val (exit, out, _) = runCli("access", "grant", "client:cli-ci", "manager", "environment:$envId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("client:cli-ci").contains("manager").contains("environment:$envId")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/access/grants")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        assertThat(req.getHeader("X-Thoryn-Environment")).isNull()
        assertThat(parseJson(req.body.readUtf8())).isEqualTo(mapOf("subject" to "client:cli-ci", "relation" to "manager", "object" to "environment:$envId"))
    }

    @Test
    fun `grant is idempotent — a 200 for an existing grant still succeeds`() {
        server.enqueue(jsonResponse(200, """{"subject":"member:alice","relation":"viewer","object":"application:app-1","createdAt":"2026-09-15T10:00:00Z"}"""))

        val (exit, out, _) = runCli("access", "grant", "member:alice", "viewer", "application:app-1", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["object"]).isEqualTo("application:app-1")
    }

    @Test
    fun `revoke sends DELETE with the grant identified in the JSON body`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("access", "revoke", "client:cli-ci", "manager", "environment:$envId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Revoked: client:cli-ci manager environment:$envId")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("DELETE")
        assertThat(req.path).isEqualTo("/api/v1/access/grants")
        assertThat(req.getHeader("Content-Type")).startsWith("application/json")
        assertThat(parseJson(req.body.readUtf8())).isEqualTo(mapOf("subject" to "client:cli-ci", "relation" to "manager", "object" to "environment:$envId"))
    }

    @Test
    fun `list --object GETs the object's grants and renders the ListEnvelope data array`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"data":[
                     {"subject":"workspace:t-1#admin","relation":"manager","object":"environment:$envId","createdAt":"2026-09-01T00:00:00Z"},
                     {"subject":"client:cli-ci","relation":"manager","object":"environment:$envId","createdAt":"2026-09-15T10:00:00Z"}
                   ],"pagination":{"total":2,"nextCursor":null}}""",
            ),
        )

        val (exit, out, _) = runCli("access", "list", "--object", "environment:$envId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("subject").contains("workspace:t-1#admin").contains("client:cli-ci").contains("manager")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.path).isEqualTo("/api/v1/access/grants?object=environment%3A$envId")
    }

    @Test
    fun `list --subject GETs the subject's grants`() {
        server.enqueue(jsonResponse(200, """{"data":[{"subject":"client:cli-ci","relation":"manager","object":"environment:$envId","createdAt":"2026-09-15T10:00:00Z"}],"pagination":{}}"""))

        val (exit, out, _) = runCli("access", "list", "--subject", "client:cli-ci", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"data\"")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/access/grants?subject=client%3Acli-ci")
    }

    @Test
    fun `list without a filter is a usage error and sends nothing`() {
        val (exit, _, err) = runCli("access", "list", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("--object").contains("--subject")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `mine GETs the caller's objects with the type and relation filters and renders the refs`() {
        server.enqueue(jsonResponse(200, """{"data":["environment:$envId","environment:22222222-2222-2222-2222-222222222222"]}"""))

        val (exit, out, _) = runCli("access", "mine", "--type", "environment", "--relation", "manager", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("environment:$envId").contains("environment:22222222-2222-2222-2222-222222222222")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/access/mine?type=environment&relation=manager")
    }

    @Test
    fun `a malformed subject, relation or object is refused client-side before any request`() {
        val badSubject = runCli("access", "grant", "robot:cli-ci", "manager", "environment:$envId", "--gateway", baseUrl())
        assertThat(badSubject.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(badSubject.err).contains("subject type 'robot'").contains("member, client")

        val badRelation = runCli("access", "grant", "client:cli-ci", "owner", "environment:$envId", "--gateway", baseUrl())
        assertThat(badRelation.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(badRelation.err).contains("relation 'owner'")

        val badObject = runCli("access", "revoke", "client:cli-ci", "manager", "sandbox:$envId", "--gateway", baseUrl())
        assertThat(badObject.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(badObject.err).contains("object type 'sandbox'")

        val badMineType = runCli("access", "mine", "--type", "sandbox", "--gateway", baseUrl())
        assertThat(badMineType.exit).isEqualTo(CommandSupport.EXIT_USAGE)

        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a 403 insufficient_scope renders the required tenant access scope and the login hint`() {
        server.enqueue(jsonResponse(403, """{"type":"about:blank","status":403,"title":"Forbidden","errorCode":"insufficient_scope","detail":"missing scope"}"""))

        val (exit, _, err) = runCli("access", "grant", "client:cli-ci", "manager", "environment:$envId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("insufficient_scope").contains("Required scope: tenant:access.write").contains("--scope tenant:access.write")
    }

    @Test
    fun `access with no subcommand prints usage to stderr and exits 64`() {
        val (exit, _, err) = runCli("access")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("Usage: thoryn access").contains("grant").contains("revoke").contains("list").contains("mine")
    }

    @Test
    fun `not signed in exits 1 before any request`() {
        clearTokens()

        val (exit, _, err) = runCli("access", "mine", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("Not signed in")
        assertThat(server.requestCount).isZero()
    }
}
