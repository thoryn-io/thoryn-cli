package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-3282 — `thoryn devices revoke` on **this** machine finishes the job locally.
 *
 * ## The report
 *
 * The product owner ran `thoryn devices revoke Mac.home` on the machine they were sitting at. The
 * revoke succeeded, the CLI said "Signing in from it again registers a NEW device" — and every
 * `thoryn login` afterwards failed `400 invalid_grant`, because the key on disk had not changed and
 * a revoked key is refused for every grant (SSO-3228). The only way out was
 * `thoryn logout --rotate-key`, which nothing mentioned.
 *
 * So the command now does for this machine what it just told the hub to do: rotate the key, drop the
 * session that died with it, and say what happens next. For any OTHER machine it cannot — that
 * machine holds its own key — so the message names the command to run there instead of promising
 * something the CLI cannot deliver.
 *
 * ## Why the assertions are about the STORED key
 *
 * Not about the message. A wording change must not be able to make this pass while the key stays
 * put, because the stale key is the entire defect: the thumbprint before and after is the only thing
 * that says whether the machine can sign in again.
 */
class DevicesRevokeSelfTest : CommandTestBase() {

    @BeforeEach
    fun resetDpop() {
        // Drop any key cached by an earlier test class so this test's key lands in ITS sandboxed home.
        Dpop.resetForTest()
    }

    @AfterEach
    fun clearDpop() {
        Dpop.resetForTest()
    }

    /** `{devices:[…]}` as the hub sends it, with [selfJkt] standing in for this installation's key. */
    private fun listingWith(selfJkt: String): String = """
        {"devices":[
          {"id":"d-self","jkt":"$selfJkt","name":"Mac.home","registered":true,"clientId":"cli",
           "lastSeenAt":"2026-09-20T09:41:00Z","recentNetworks":["203.0.113"],"revokedAt":null},
          {"id":"d-other","jkt":"JKT-SOMEONE-ELSE","name":"ci-runner","registered":true,"clientId":"cli",
           "lastSeenAt":"2026-09-20T08:02:00Z","recentNetworks":["192.0.2"],"revokedAt":null}
        ]}
    """.trimIndent()

    private fun revokeResponse(id: String) =
        jsonResponse(200, """{"id":"$id","name":"x","revokedAt":"2026-09-21T07:05:00Z","revokedSessions":1}""")

    @Test
    fun `revoking THIS machine rotates its key and clears the session`() {
        val before = Dpop.session()!!.thumbprint
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test", deviceId = "d-self"))
        server.enqueue(jsonResponse(200, listingWith(before)))
        server.enqueue(revokeResponse("d-self"))

        val (exit, _, err) = runCli("devices", "revoke", "Mac.home", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // the list read that resolves the name
        assertThat(server.takeRequest().path).isEqualTo("/account/devices/d-self/revoke")

        // The defect, stated as an assertion: the key that the hub now refuses must not be the key
        // this installation still holds.
        Dpop.resetForTest()
        val after = Dpop.session()!!.thumbprint
        assertThat(after)
            .describedAs("a revoked key left in place is what made every later `thoryn login` fail")
            .isNotEqualTo(before)

        assertThat(FileTokenStore().read())
            .describedAs("the session was bound to the revoked key, so it is already dead — do not keep it")
            .isNull()

        assertThat(err)
            .describedAs("the person must be told what just happened to their own machine")
            .contains("this machine")
            .contains("thoryn login")
    }

    @Test
    fun `revoking ANOTHER machine leaves this installation's key and session alone`() {
        val before = Dpop.session()!!.thumbprint
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test", deviceId = "d-self"))
        server.enqueue(jsonResponse(200, listingWith(before)))
        server.enqueue(revokeResponse("d-other"))

        val (exit, _, err) = runCli("devices", "revoke", "ci-runner", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)

        Dpop.resetForTest()
        assertThat(Dpop.session()!!.thumbprint)
            .describedAs("revoking the CI runner must never sign this machine out — that is the whole point")
            .isEqualTo(before)
        assertThat(FileTokenStore().read()).isNotNull()

        assertThat(err)
            .describedAs(
                "the old message promised signing in again would register a new device; for the OTHER " +
                    "machine that is only true after it rotates its key, so say so",
            )
            .contains("--rotate-key")
    }

    @Test
    fun `a device the hub reports without a jkt falls back to the session's own device id`() {
        // An older hub, or a listing that omits the thumbprint: the session recorded which device
        // THIS installation registered at its last login, and that is the same fact by another route.
        val before = Dpop.session()!!.thumbprint
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test", deviceId = "d-self"))
        server.enqueue(
            jsonResponse(
                200,
                """{"devices":[{"id":"d-self","name":"Mac.home","registered":true,"revokedAt":null}]}""",
            ),
        )
        server.enqueue(revokeResponse("d-self"))

        runCli("devices", "revoke", "d-self", "--hub", baseUrl())

        Dpop.resetForTest()
        assertThat(Dpop.session()!!.thumbprint).isNotEqualTo(before)
    }
}
