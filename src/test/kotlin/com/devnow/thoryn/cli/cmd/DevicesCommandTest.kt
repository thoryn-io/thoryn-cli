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

    @Test
    fun `not signed in is guidance, not a stack trace`() {
        clearTokens()

        val (exit, _, err) = runCli("devices", "list", "--hub", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_NOT_SIGNED_IN)
        assertThat(err).contains("thoryn login")
    }
}
