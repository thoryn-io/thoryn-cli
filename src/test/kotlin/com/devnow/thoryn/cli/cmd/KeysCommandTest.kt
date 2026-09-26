package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Duration

/**
 * SSO-3369 — `thoryn keys rotate | rotations [list | get]` against a MockWebServer standing in for the
 * api-gateway → product-api `/api/v1/signing-keys/{kind}/rotations` surface (oathy SSO-3369).
 *
 * The response bodies under `src/test/resources/signing-keys/` are CAPTURED from product-api's real
 * `SigningKeyRotationController` (MockMvc over the real security chain, Postgres and Jackson), not
 * hand-written — the SSO-3082 lesson. `rotation-signin-done.json` is the captured DONE body with the
 * `kind` / `kid` a sign-in request carries (the same DTO and serializer).
 */
class KeysCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/signing-keys/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(fixture(name))

    // ── rotate ───────────────────────────────────────────────────────────────

    @Test
    fun `rotate --kind sign-in --yes posts the request and prints the new kid when the hub answers DONE`() {
        server.enqueue(jsonResponse(202, fixture("rotation-signin-done")))

        val (exit, out, _) = runCli("keys", "rotate", "--kind", "sign-in", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .contains("Rotation requested: f0b7070e-c4ad-4d65-8ad7-4c5fc235e293")
            .contains("DONE — new version 2, kid tenant-ws.fc4b3229-0e2e-4c41-a8f4-49f093141904-v2")
            .contains("keeps validating")
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/signing-keys/sign-in/rotations")
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer AT-test")
    }

    @Test
    fun `rotate --wait polls a pending request until it is DONE`() {
        server.enqueue(jsonResponse(202, fixture("rotation-pending")))
        server.enqueue(jsonResponse(200, fixture("rotation-pending")))
        server.enqueue(jsonResponse(200, fixture("rotation-done")))

        val (exit, out, _) = runCli(
            "keys", "rotate", "--kind", "security-events", "--environment", "production", "--wait",
            "--poll-interval", "0", "--yes", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Waiting for the key's rotator").contains("DONE — new version 3, kid v3:secevent-")
        val post = server.takeRequest()
        assertThat(post.path).isEqualTo("/api/v1/signing-keys/security-events/rotations")
        assertThat(post.getHeader("X-Thoryn-Environment")).isEqualTo("production")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/signing-keys/security-events/rotations/f0b7070e-c4ad-4d65-8ad7-4c5fc235e293")
        assertThat(server.takeRequest().method).isEqualTo("GET")
    }

    @Test
    fun `rotate --wait gives up at the timeout with the check-failed exit and how to follow it`() {
        repeat(3) { server.enqueue(jsonResponse(if (it == 0) 202 else 200, fixture("rotation-pending"))) }

        val (exit, _, err) = runCli(
            "keys", "rotate", "--kind", "security-events", "--wait", "--timeout", "0s",
            "--yes", "--gateway", baseUrl(),
        )

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(err).contains("Still PENDING").contains("thoryn keys rotations get f0b7070e-c4ad-4d65-8ad7-4c5fc235e293 --kind security-events")
    }

    @Test
    fun `rotate --json emits the request for scripts`() {
        server.enqueue(jsonResponse(202, fixture("rotation-pending")))

        val (exit, out, _) = runCli("keys", "rotate", "--kind", "security-events", "--yes", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)).containsEntry("state", "PENDING").containsEntry("kind", "security-events")
    }

    @Test
    fun `rotate without --yes and no terminal refuses and sends nothing`() {
        val (exit, _, err) = runCli("keys", "rotate", "--kind", "sign-in", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("re-run with --yes")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `an unknown or missing --kind is refused before any call`() {
        val (bad, _, badErr) = runCli("keys", "rotate", "--kind", "database", "--yes", "--gateway", baseUrl())
        val (missing, _, missingErr) = runCli("keys", "rotations", "list", "--gateway", baseUrl())

        assertThat(bad).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(badErr).contains("sign-in | security-events")
        assertThat(missing).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(missingErr).contains("--kind is required")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `a pending rotation is 409 with the request to follow`() {
        server.enqueue(problem(409, "problem-pending"))

        val (exit, _, err) = runCli("keys", "rotate", "--kind", "security-events", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("rotation_pending")
            .contains("thoryn keys rotations get f0b7070e-c4ad-4d65-8ad7-4c5fc235e293 --kind security-events")
    }

    @Test
    fun `the cooldown says when a new request is accepted`() {
        server.enqueue(problem(429, "problem-cooldown"))

        val (exit, _, err) = runCli("keys", "rotate", "--kind", "security-events", "--yes", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("rotation_cooldown").contains("accepted from 2026-09-26T06:22:07.045851Z")
    }

    @Test
    fun `a non-admin gets the 404 explained, and a missing scope names the scope to log in with`() {
        server.enqueue(problem(404, "problem-not-admin"))
        val (notAdmin, _, notAdminErr) = runCli("keys", "rotate", "--kind", "security-events", "--yes", "--gateway", baseUrl())
        assertThat(notAdmin).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(notAdminErr).contains("signing_key_not_found").contains("Only workspace admins can rotate keys")

        server.enqueue(problem(403, "problem-scope"))
        val (scope, _, scopeErr) = runCli("keys", "rotate", "--kind", "security-events", "--yes", "--gateway", baseUrl())
        assertThat(scope).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(scopeErr).contains("Required scope: tenant:keys.rotate")
    }

    // ── rotations ────────────────────────────────────────────────────────────

    @Test
    fun `rotations list shows the environment's requests`() {
        server.enqueue(jsonResponse(200, fixture("rotation-list")))

        val (exit, out, _) = runCli("keys", "rotations", "list", "--kind", "security-events", "--limit", "20", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("f0b7070e-c4ad-4d65-8ad7-4c5fc235e293").contains("DONE").contains("v3:secevent-")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/signing-keys/security-events/rotations?limit=20")
    }

    @Test
    fun `rotations without a subcommand lists too`() {
        server.enqueue(jsonResponse(200, fixture("rotation-list")))

        val (exit, out, _) = runCli("keys", "rotations", "--kind", "security-events", "--output", "yaml", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).containsPattern("state: \"?DONE")
    }

    @Test
    fun `rotations get shows one request, and an unknown id is explained`() {
        server.enqueue(jsonResponse(200, fixture("rotation-done")))
        val (exit, out, _) = runCli("keys", "rotations", "get", "f0b7070e-c4ad-4d65-8ad7-4c5fc235e293", "--kind", "security-events", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("keyVersion").contains("DONE — new version 3")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/signing-keys/security-events/rotations/f0b7070e-c4ad-4d65-8ad7-4c5fc235e293")

        server.enqueue(problem(404, "problem-request-not-found"))
        val (missing, _, err) = runCli("keys", "rotations", "get", "nope", "--kind", "sign-in", "--gateway", baseUrl())
        assertThat(missing).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("signing_key_rotation_not_found")
    }

    @Test
    fun `durations accept seconds, minutes, hours and ISO-8601`() {
        assertThat(KeysCommand.parseDuration("90s")).isEqualTo(Duration.ofSeconds(90))
        assertThat(KeysCommand.parseDuration("5m")).isEqualTo(Duration.ofMinutes(5))
        assertThat(KeysCommand.parseDuration("1h")).isEqualTo(Duration.ofHours(1))
        assertThat(KeysCommand.parseDuration("45")).isEqualTo(Duration.ofSeconds(45))
        assertThat(KeysCommand.parseDuration("PT2M")).isEqualTo(Duration.ofMinutes(2))
        assertThat(KeysCommand.parseDuration("soon")).isNull()
    }
}
