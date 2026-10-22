package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3792 (oauthy ADR 2026-10-17 §2; product-api SSO-3789) — `thoryn access reserve | reservations | release` against a
 * MockWebServer standing in for `/api/v1/access/application-slots`: the exact request shapes, the plane defaulting to
 * `production`, the client-side grammar (a workload identity, an application), the ListEnvelope rendering with the
 * `--subject` filter, and the refusal hints (`application_exists`, `application_slot_held`, the opaque 404).
 */
class AccessReservationsCommandTest : CommandTestBase() {

    private val slot = """{"object":"application:forge-forgejo-login","subject":"client:wi_abc","environment":"production","createdAt":"2026-10-17T10:00:00Z","expiresAt":"2026-11-16T10:00:00Z","expired":false}"""

    @Test
    fun `reserve POSTs subject, object and the production plane by default, and renders the slot`() {
        server.enqueue(jsonResponse(201, slot))

        val (exit, out, _) = runCli("access", "reserve", "client:wi_abc", "application:forge-forgejo-login", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("application:forge-forgejo-login").contains("client:wi_abc").contains("production").contains("2026-11-16T10:00:00Z")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/access/application-slots")
        assertThat(req.getHeader("X-Thoryn-Environment")).isNull()
        assertThat(parseJson(req.body.readUtf8())).isEqualTo(mapOf("subject" to "client:wi_abc", "object" to "application:forge-forgejo-login", "environment" to "production"))
    }

    @Test
    fun `reserve sends the plane named by --environment, and a 200 for the same reservation still succeeds`() {
        server.enqueue(jsonResponse(200, slot.replace("\"production\"", "\"forge\"")))

        val (exit, out, _) = runCli("access", "reserve", "client:wi_abc", "application:forge-forgejo-login", "--environment", "forge", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)["environment"]).isEqualTo("forge")
        assertThat(parseJson(server.takeRequest().body.readUtf8())["environment"]).isEqualTo("forge")
    }

    @Test
    fun `reserve refuses a person subject and a non-application object before any request`() {
        val (exitMember, _, errMember) = runCli("access", "reserve", "member:alice", "application:x", "--gateway", baseUrl())
        val (exitObject, _, errObject) = runCli("access", "reserve", "client:wi_abc", "environment:env-1", "--gateway", baseUrl())

        assertThat(exitMember).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(errMember).contains("held by a workload identity")
        assertThat(exitObject).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(errObject).contains("a creation slot names an application")
        assertThat(server.requestCount).isEqualTo(0)
    }

    @Test
    fun `reserve on an existing application says to grant owner instead`() {
        server.enqueue(jsonResponse(409, """{"type":"about:blank","status":409,"title":"Conflict","errorCode":"application_exists","detail":"exists"}"""))

        val (exit, _, err) = runCli("access", "reserve", "client:wi_abc", "application:forge-oauth2-proxy", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Refused (application_exists)").contains("thoryn access grant client:wi_abc owner application:forge-oauth2-proxy")
    }

    @Test
    fun `reserve on a name another identity holds points at reservations and release`() {
        server.enqueue(jsonResponse(409, """{"type":"about:blank","status":409,"title":"Conflict","errorCode":"application_slot_held","detail":"held"}"""))

        val (exit, _, err) = runCli("access", "reserve", "client:wi_abc", "application:forge-forgejo-login", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Refused (application_slot_held)").contains("thoryn access reservations").contains("thoryn access release application:forge-forgejo-login")
    }

    @Test
    fun `reserve answered 404 explains the one opaque answer — admin, trust client, environment, or an older platform`() {
        server.enqueue(jsonResponse(404, """{"type":"about:blank","status":404,"title":"Not Found","errorCode":"not_found","detail":"No such application creation slot target in this workspace."}"""))

        val (exit, _, err) = runCli("access", "reserve", "client:wi_abc", "application:forge-forgejo-login", "--environment", "nope", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("workspace admin").contains("'nope'").contains("thoryn workload-identity trusts list")
    }

    @Test
    fun `reservations lists the slots, and --subject narrows the listing to one holder`() {
        val other = slot.replace("client:wi_abc", "client:wi_other").replace("forge-forgejo-login", "billing-web")
        server.enqueue(jsonResponse(200, """{"data":[$slot,$other],"pagination":{"total":2,"nextCursor":null}}"""))
        server.enqueue(jsonResponse(200, """{"data":[$slot,$other],"pagination":{"total":2,"nextCursor":null}}"""))

        val (exit, table, _) = runCli("access", "reservations", "--gateway", baseUrl())
        val (exitFiltered, filtered, _) = runCli("access", "reservations", "--subject", "client:wi_other", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(table).contains("application:forge-forgejo-login").contains("application:billing-web").contains("expiresAt")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/access/application-slots")
        assertThat(exitFiltered).isEqualTo(0)
        @Suppress("UNCHECKED_CAST")
        val data = parseJson(filtered)["data"] as List<Map<String, Any?>>
        assertThat(data.map { it["object"] }).containsExactly("application:billing-web")
    }

    @Test
    fun `release DELETEs the slot by client id and says so`() {
        server.enqueue(noContent())

        val (exit, out, _) = runCli("access", "release", "application:forge-forgejo-login", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Released: the creation slot for application:forge-forgejo-login")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("DELETE")
        assertThat(req.path).isEqualTo("/api/v1/access/application-slots/forge-forgejo-login")
    }

    @Test
    fun `release of a slot you neither hold nor may revoke is the opaque 404, explained`() {
        server.enqueue(jsonResponse(404, """{"type":"about:blank","status":404,"title":"Not Found","errorCode":"not_found","detail":"nope"}"""))

        val (exit, _, err) = runCli("access", "release", "application:forge-forgejo-login", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("no creation slot for application:forge-forgejo-login that you hold or may revoke")
    }
}
