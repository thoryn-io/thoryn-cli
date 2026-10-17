package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.provision.FixRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3774 — `thoryn access grant | revoke` on a workload-identity trust (`trust:<id>`, ownable since oauthy S1 SSO-3772 /
 * PR #4151): the object is accepted as typed, and the two refusals a workspace admin can meet are explained on stderr
 * (stdout stays the error document): `400 trust_self_management` (I6 — the subject is that trust's OWN `wi_`), and a `404`
 * on a `trust:` object (not in this workspace — or a product-api before S1, which answers a grant naming `trust:` with an
 * opaque `404 not_found`, where a trust is reached through its environment).
 */
class AccessCommandTrustTest : CommandTestBase() {

    private val trustId = "3f1c2a9e-7b1d-4c55-9b8e-1f0a2b3c4d5e"

    @Test
    fun `grant sends owner on a trust object unchanged — the founder's hand-over of a trust to its repository`() {
        server.enqueue(jsonResponse(201, """{"subject":"client:wi_repo","relation":"owner","object":"trust:$trustId","createdAt":"2026-10-17T10:00:00Z"}"""))

        val (exit, out, err) = runCli("access", "grant", "client:wi_repo", "owner", "trust:$trustId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("trust:$trustId")
        assertThat(err).doesNotContain("Refused").doesNotContain("Not found")
        assertThat(parseJson(server.takeRequest().body.readUtf8())).isEqualTo(mapOf("subject" to "client:wi_repo", "relation" to "owner", "object" to "trust:$trustId"))
    }

    @Test
    fun `400 trust_self_management says the subject is the trust's own workload client and whom to grant instead`() {
        server.enqueue(jsonResponse(400, """{"type":"about:blank","status":400,"title":"Bad Request","errorCode":"trust_self_management","detail":"refused"}"""))

        val (exit, out, err) = runCli("access", "grant", "client:wi_self", "owner", "trust:$trustId", "--gateway", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Refused (trust_self_management): client:wi_self is the workload client of trust:$trustId itself")
            .contains("never to the trust's own")
        assertThat(parseJson(out)["error"]).isEqualTo("trust_self_management") // stdout stays the one error document
    }

    @Test
    fun `a 404 on a trust object names both causes — not in this workspace, or a platform before trust objects — and a 404 elsewhere gets no trust hint`() {
        server.enqueue(jsonResponse(404, """{"type":"about:blank","status":404,"title":"Not Found","errorCode":"not_found","detail":"not found"}"""))

        val (exit, _, err) = runCli("access", "revoke", "client:wi_repo", "owner", "trust:$trustId", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("Not found: trust:$trustId is not a trust of this workspace").contains("`${FixRequest.LIST_TRUSTS_COMMAND}`")
            .contains("predates trust objects").contains("thoryn access grant client:wi_repo manager environment:<id>")

        server.enqueue(jsonResponse(404, """{"type":"about:blank","status":404,"title":"Not Found","errorCode":"not_found","detail":"not found"}"""))
        val (_, _, plain) = runCli("access", "grant", "client:wi_repo", "manager", "application:app-1", "--gateway", baseUrl())
        assertThat(plain).doesNotContain("predates trust objects")
    }
}
