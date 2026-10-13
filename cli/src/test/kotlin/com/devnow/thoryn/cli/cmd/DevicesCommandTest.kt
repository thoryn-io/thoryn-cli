package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3228 — `thoryn devices list|revoke`.
 *
 * The device surface lives on the hub (`/account/devices`), so `--hub` points at the MockWebServer.
 * Three things are worth pinning here: the CLI reads the hub's OWN envelope (`{devices:[…]}`, not
 * the customer-plane `{data,pagination}` — the SSO-3082 trap, where a list command that guessed its
 * envelope reported "nothing" against a working backend), a name resolves to an id before the
 * revoke is sent, and an ambiguous name is refused rather than guessed at.
 */
class DevicesCommandTest : CommandTestBase() {

    private val twoDevices = """
        {"devices":[
          {"id":"d-1","jkt":"JKT-1","name":"alice-mbp","registered":true,"clientId":"cli",
           "lastSeenAt":"2026-09-19T09:41:00Z","recentNetworks":["203.0.113","198.51.100"],"revokedAt":null},
          {"id":null,"jkt":"JKT-2","name":null,"registered":false,"clientId":"cli",
           "lastSeenAt":"2026-08-30T17:15:00Z","recentNetworks":["192.0.2"],"revokedAt":null}
        ]}
    """.trimIndent()

    @Test
    fun `list reads the hub's devices envelope and shows an unregistered key too`() {
        server.enqueue(jsonResponse(200, twoDevices))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("alice-mbp")
            .contains("203.0.113")
            // A key used but never registered is exactly what someone auditing their account needs
            // to see, so it is listed rather than hidden.
            .contains("(unregistered)")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/account/devices")
        assertThat(req.method).isEqualTo("GET")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `list renders json as a bare array a script can pipe into jq`() {
        server.enqueue(jsonResponse(200, twoDevices))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out.trim()).startsWith("[")
        assertThat(out).contains("\"jkt\"")
    }

    @Test
    fun `revoke by id posts straight to the device's revoke endpoint`() {
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(
            jsonResponse(
                200,
                """{"id":"d-1","jkt":"JKT-1","name":"alice-mbp","revokedAt":"2026-09-19T10:00:00Z","revokedSessions":2}""",
            ),
        )

        val (exit, out, err) = runCli("devices", "revoke", "d-1", "--reason", "stolen", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        server.takeRequest() // the list read that resolves the argument
        val revoke = server.takeRequest()
        assertThat(revoke.path).isEqualTo("/account/devices/d-1/revoke")
        assertThat(revoke.method).isEqualTo("POST")
        assertThat(revoke.body.readUtf8()).contains("stolen")
        assertThat(out).contains("revokedSessions")
        assertThat(err)
            .describedAs("the user must be told this is per-device and permanent for that key")
            .contains("other")
            .contains("NEW device")
    }

    @Test
    fun `revoke accepts the device name shown by list`() {
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(
            jsonResponse(200, """{"id":"d-1","jkt":"JKT-1","name":"alice-mbp","revokedAt":"…","revokedSessions":0}"""),
        )

        val (exit, _, _) = runCli("devices", "revoke", "alice-mbp", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        server.takeRequest()
        assertThat(server.takeRequest().path).isEqualTo("/account/devices/d-1/revoke")
    }

    @Test
    fun `an ambiguous name is refused rather than resolved to one of them`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"devices":[
                     {"id":"d-1","name":"laptop","registered":true,"lastSeenAt":"2026-09-19T09:41:00Z"},
                     {"id":"d-2","name":"laptop","registered":true,"lastSeenAt":"2026-09-01T09:41:00Z"}
                   ]}""".trimIndent(),
            ),
        )

        val (exit, _, err) = runCli("devices", "revoke", "laptop", "--hub", baseUrl())

        assertThat(exit)
            .describedAs("revoking the wrong machine signs someone out of a working one")
            .isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("More than one device").contains("d-1").contains("d-2")
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `an unknown name names the command that would show the real ones`() {
        server.enqueue(jsonResponse(200, twoDevices))

        val (exit, _, err) = runCli("devices", "revoke", "nope", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("thoryn devices list")
    }

    @Test
    fun `an unregistered key cannot be revoked individually, and the message says why`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"devices":[{"id":null,"name":"old-laptop","registered":false,"lastSeenAt":"2026-08-30T17:15:00Z"}]}""",
            ),
        )

        val (exit, _, err) = runCli("devices", "revoke", "old-laptop", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("never been registered")
    }

    // ── session state (SSO-3271) ──────────────────────────────────────────────

    private val withSessions = """
        {"devices":[
          {"id":"d-1","jkt":"JKT-1","name":"alice-mbp","registered":true,"clientId":"cli",
           "state":"signed_in",
           "sessions":{"active":2,"lastIssuedAt":"2026-09-19T09:41:00Z",
                       "refreshExpiresAt":"2026-10-19T09:41:00Z",
                       "workspaces":[{"tenantSlug":"acme","environmentSlug":"production","lastSeenAt":"2026-09-19T09:41:00Z"},
                                     {"tenantSlug":"acme","environmentSlug":"blue","lastSeenAt":"2026-09-18T09:41:00Z"}]},
           "lastSeenAt":"2026-09-19T09:41:00Z","recentNetworks":["203.0.113"],"revokedAt":null},
          {"id":"d-2","jkt":"JKT-2","name":"spare","registered":true,"clientId":"cli",
           "state":"idle","sessions":{"active":0,"lastIssuedAt":null,"refreshExpiresAt":null,"workspaces":[]},
           "lastSeenAt":"2026-09-02T11:00:00Z","recentNetworks":[],"revokedAt":null}
        ]}
    """.trimIndent()

    @Test
    fun `list shows the state, the live session count and the workspaces each one is in`() {
        server.enqueue(jsonResponse(200, withSessions))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("STATE").contains("SESSIONS").contains("WORKSPACES")
        assertThat(out).contains("signed_in").contains("acme/production").contains("acme/blue")
        assertThat(out)
            .describedAs("a registered machine holding nothing live is idle, not signed in")
            .contains("idle")
    }

    @Test
    fun `the json output carries the sessions object verbatim for a script to read`() {
        server.enqueue(jsonResponse(200, withSessions))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("\"state\"").contains("\"refreshExpiresAt\"").contains("\"tenantSlug\"")
    }

    @Test
    fun `an older hub that sends no session fields still lists, with the columns blank`() {
        // The SSO-3228 response shape, unchanged. A CLI that required the new fields would break
        // every user whose hub had not been upgraded yet — and a `state` GUESSED from `registered`
        // would be worse, since registration is not a session.
        server.enqueue(jsonResponse(200, twoDevices))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("alice-mbp")
        assertThat(out)
            .describedAs("no sessions reported reads as unknown, never as zero")
            .contains("-")
        assertThat(out)
            .describedAs("without `state` the old fields still answer registered / unregistered")
            .contains("registered")
        assertThat(out).doesNotContain("signed_in")
    }

    @Test
    fun `a null sessions object is read as absent, not as a present value`() {
        // `node["sessions"]` answers a NullNode for an explicit JSON null — not Kotlin's null. The
        // SSO-3228 version of this mistake made an unregistered key look revoked.
        server.enqueue(
            jsonResponse(
                200,
                """{"devices":[{"id":"d-1","name":"alice-mbp","registered":true,"state":null,"sessions":null,
                    "lastSeenAt":"2026-09-19T09:41:00Z"}]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("alice-mbp").contains("registered")
    }

    @Test
    fun `a revoked device reads revoked with no sessions`() {
        server.enqueue(
            jsonResponse(
                200,
                """{"devices":[{"id":"d-1","name":"old-laptop","registered":true,"state":"revoked",
                    "sessions":{"active":0,"workspaces":[]},"revokedAt":"2026-09-18T10:00:00Z",
                    "lastSeenAt":"2026-08-30T17:15:00Z"}]}""".trimIndent(),
            ),
        )

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("revoked")
    }

    // ── LAST SEEN (SSO-3275) ──────────────────────────────────────────────────

    /**
     * The released cli-v0.23.0 printed `LAST SEEN 1789848418` against staging: the hub declares
     * `DeviceView.lastSeenAt` as an `Instant`, and the CLI printed whatever that hub's Jackson put
     * on the wire. Which of the four shapes a given hub sends is not the CLI's to assume — so each
     * one is served here from the mock and must produce the same readable cell.
     */
    private fun oneDeviceLastSeen(lastSeenAt: String) = jsonResponse(
        200,
        """{"devices":[{"id":"d-1","jkt":"JKT-1","name":"alice-mbp","registered":true,"clientId":"cli",
            "state":"signed_in","lastSeenAt":$lastSeenAt,"recentNetworks":["203.0.113"],"revokedAt":null}]}
        """.trimIndent(),
    )

    @Test
    fun `last seen sent as epoch seconds is rendered as a timestamp and an age, not as the epoch`() {
        server.enqueue(oneDeviceLastSeen("1789848418"))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .describedAs("the SSO-3275 report: `LAST SEEN 1789848418` answers nobody's question")
            .doesNotContain("1789848418")
        assertThat(out).contains("2026-09-19T20:06:58Z").contains("ago")
    }

    @Test
    fun `last seen sent as epoch millis is rendered as the same moment`() {
        server.enqueue(oneDeviceLastSeen("1789848418000"))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("2026-09-19T20:06:58Z").doesNotContain("1789848418000")
    }

    @Test
    fun `last seen sent as seconds-with-nanos is rendered at seconds precision`() {
        server.enqueue(oneDeviceLastSeen("1789848418.123456789"))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("2026-09-19T20:06:58Z").doesNotContain("123456789")
    }

    @Test
    fun `last seen sent as an ISO instant keeps the instant and gains the age`() {
        server.enqueue(oneDeviceLastSeen(""""2026-09-19T09:41:00Z""""))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("2026-09-19T09:41:00Z (").contains("ago")
    }

    @Test
    fun `a device the hub reports no last-seen for reads as a dash, not as the epoch zero`() {
        server.enqueue(oneDeviceLastSeen("null"))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("alice-mbp").doesNotContain("1970-01-01")
    }

    @Test
    fun `the json output still carries the hub's own value, untouched by the table rendering`() {
        // The SSO-3082 rule: the CLI does not reshape a backend payload behind a script's back.
        server.enqueue(oneDeviceLastSeen("1789848418"))

        val (exit, out, _) = runCli("devices", "list", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("1789848418")
    }

    // ── revokedAt (SSO-3279) ──────────────────────────────────────────────────

    /**
     * SSO-3275 routed the LAST SEEN **column** through [com.devnow.thoryn.cli.output.Timestamps] and
     * left the revoke's own confirmation on `asString()`, so live against staging
     * `thoryn devices revoke Mac.home` answered `revokedAt = 1789896884`. Same hub field type, same
     * four wire shapes — and it is the line confirming an action the person has just taken, which
     * makes it the worst place on the surface to print an epoch.
     */
    private fun revokedAtResponse(revokedAt: String) = jsonResponse(
        200,
        """{"id":"d-1","jkt":"JKT-1","name":"alice-mbp","revokedAt":$revokedAt,"revokedSessions":2}""",
    )

    @Test
    fun `revoke renders revokedAt sent as an epoch as a timestamp and an age`() {
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(revokedAtResponse("1789896884"))

        val (exit, out, _) = runCli("devices", "revoke", "d-1", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .describedAs("the SSO-3279 report: `revokedAt = 1789896884`, seen live with cli-v0.24.0")
            .doesNotContain("1789896884")
        assertThat(out).contains("2026-09-20T09:34:44Z").contains("ago")
    }

    @Test
    fun `revoke renders revokedAt sent as an ISO instant as the same moment`() {
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(revokedAtResponse(""""2026-09-20T09:34:44Z""""))

        val (exit, out, _) = runCli("devices", "revoke", "d-1", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("2026-09-20T09:34:44Z").contains("ago")
    }

    @Test
    fun `revoke json keeps the hub's own revokedAt, untouched by the table rendering`() {
        // The SSO-3082 rule again: only the TABLE rendering is the CLI's to decide.
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(revokedAtResponse("1789896884"))

        val (exit, out, _) = runCli("devices", "revoke", "d-1", "--hub", baseUrl(), "--output", "json")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("1789896884")
    }

    @Test
    fun `revoke shows an unrecognised revokedAt verbatim rather than dropping it`() {
        server.enqueue(jsonResponse(200, twoDevices))
        server.enqueue(revokedAtResponse(""""last tuesday""""))

        val (exit, out, _) = runCli("devices", "revoke", "d-1", "--hub", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .describedAs("a hub's own value is shown even when the CLI cannot parse it — never guessed at")
            .contains("last tuesday")
    }

    @Test
    fun `not signed in is guidance, not a stack trace`() {
        clearTokens()

        val (exit, _, err) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("thoryn login")
    }
}
