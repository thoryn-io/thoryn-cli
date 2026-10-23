package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.SessionEnd
import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * SSO-3928 — a person's CLI session that the hub ends, and the renewals that keep it alive.
 *
 * The report: a `thoryn login --workspace thoryn` session from 18:00 UTC failed at 07:19 the next
 * morning with "Could not renew your sign-in session (Hub returned 400: invalid_grant)". The hub's log
 * showed no CLI request overnight and none of its replay / lifetime / device lines: the session had
 * simply gone unused for longer than the `cli` client's 8 h idle window. Policy, not a defect — but the
 * line said neither that the session had ended nor why. These tests pin:
 *
 *  - the line names the reason the hub gives and the times the session's own tokens carry;
 *  - a renewal keeps every CLI-local field of the session (the device fields used to be dropped at the
 *    first renewal, 15 minutes in);
 *  - a renewal the token store cannot keep is reported, not swallowed — the refresh token it replaced
 *    is spent, so the NEXT command would otherwise fail with no explanation.
 */
class CommandSupportSessionEndTest : CommandTestBase() {

    private val now = Instant.parse("2026-10-23T07:19:00Z")
    private val signedIn = Instant.parse("2026-10-22T18:00:00Z")
    private val lastRenewed = Instant.parse("2026-10-22T18:31:00Z")
    private val originalClock = SessionEnd.clock

    @BeforeEach
    fun fixClock() {
        SessionEnd.clock = Clock.fixed(now, ZoneOffset.UTC)
    }

    @AfterEach
    fun restoreClock() {
        SessionEnd.clock = originalClock
    }

    private fun session() = Tokens(
        accessToken = jwt("""{"iat":${lastRenewed.epochSecond},"exp":${lastRenewed.epochSecond + 900}}"""),
        refreshToken = "RT-1",
        idToken = jwt("""{"auth_time":${signedIn.epochSecond}}"""),
        expiresAtEpochSecond = System.currentTimeMillis() / 1000 - 60,
        scope = "openid offline_access tenant:clients.read",
        issuer = baseUrl(),
        gateway = baseUrl(),
        clientId = "cli",
        workspace = "thoryn",
        deviceId = "dev-123",
        deviceName = "marks-laptop",
        platformIssuer = "https://auth.stg.thoryn.org",
    )

    @Test
    fun `a session ended for being idle says so, with its last renewal`() {
        seedTokens(session())
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant","error_description":"refresh_token_expired"}"""))

        val out = ByteArrayOutputStream()
        val renewed = CommandSupport.forceRefresh(PrintStream(out))

        assertThat(renewed).isNull()
        assertThat(out.toString().trim()).isEqualTo(
            "Your sign-in session has ended: it was not used within the hub's idle window " +
                "(last renewed 2026-10-22 18:31 UTC, 12 h 48 min ago). " +
                "Run `thoryn login --workspace thoryn` to sign in again.",
        )
        // The latched guidance is the same line, so `--output json` carries it as the hint.
        assertThat(CommandSupport.unrenewableSessionGuidance()).isEqualTo(out.toString().trim())
    }

    @Test
    fun `a session that reached its maximum lifetime says so, with its sign-in time`() {
        seedTokens(session())
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant","error_description":"session_lifetime_exceeded"}"""))

        val out = ByteArrayOutputStream()
        CommandSupport.forceRefresh(PrintStream(out))

        assertThat(out.toString())
            .contains("Your sign-in session has ended: it reached its maximum lifetime")
            .contains("signed in 2026-10-22 18:00 UTC, 13 h 19 min ago")
            .contains("thoryn login --workspace thoryn")
    }

    @Test
    fun `a renewal that fails for another reason keeps the neutral wording`() {
        // A 5xx did not end anything; "your session has ended" would be a false statement.
        seedTokens(session())
        server.enqueue(jsonResponse(503, """{"error":"temporarily_unavailable"}"""))

        val out = ByteArrayOutputStream()
        CommandSupport.forceRefresh(PrintStream(out))

        assertThat(out.toString())
            .contains("Could not renew your sign-in session (Hub returned 503: temporarily_unavailable)")
            .doesNotContain("has ended")
    }

    @Test
    fun `a renewal keeps every CLI-local field of the session`() {
        seedTokens(session())
        // The hub's response carries no id_token and no scope (RFC 6749 §5.1: scope omitted when unchanged).
        server.enqueue(jsonResponse(200, """{"access_token":"AT-2","refresh_token":"RT-2","token_type":"DPoP","expires_in":900}"""))

        val out = ByteArrayOutputStream()
        val renewed = CommandSupport.forceRefresh(PrintStream(out))!!

        val stored = FileTokenStore().read()!!
        assertThat(stored).isEqualTo(renewed)
        assertThat(stored.accessToken).isEqualTo("AT-2")
        assertThat(stored.refreshToken).isEqualTo("RT-2")
        assertThat(stored.tokenType).isEqualTo("DPoP")
        // Dropped at the first renewal before SSO-3928: `logout --rotate-key` could no longer revoke the device.
        assertThat(stored.deviceId).isEqualTo("dev-123")
        assertThat(stored.deviceName).isEqualTo("marks-laptop")
        // Kept when the response omits them, so the sign-in time and the scopes stay readable.
        assertThat(stored.idToken).isEqualTo(session().idToken)
        assertThat(stored.scope).isEqualTo("openid offline_access tenant:clients.read")
        // The session hosts, as before.
        assertThat(stored.issuer).isEqualTo(baseUrl())
        assertThat(stored.platformIssuer).isEqualTo("https://auth.stg.thoryn.org")
        assertThat(stored.workspace).isEqualTo("thoryn")
        assertThat(stored.clientId).isEqualTo("cli")
        assertThat(out.toString()).isEmpty()
    }

    @Test
    fun `a renewal the token store cannot keep is reported instead of swallowed`() {
        seedTokens(session())
        val file = tempHome.resolve(".config/thoryn/tokens.json")
        // Readable, not writable: the read succeeds, the write of the rotated token fails.
        Files.setPosixFilePermissions(file, setOf(PosixFilePermission.OWNER_READ))
        server.enqueue(jsonResponse(200, """{"access_token":"AT-2","refresh_token":"RT-2","token_type":"Bearer","expires_in":900}"""))

        val out = ByteArrayOutputStream()
        val renewed = try {
            CommandSupport.forceRefresh(PrintStream(out))
        } finally {
            Files.setPosixFilePermissions(file, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
        }

        // This command still has a working token…
        assertThat(renewed!!.accessToken).isEqualTo("AT-2")
        // …and the person is told the next one will not.
        assertThat(out.toString())
            .contains("Warning: the renewed sign-in session could not be saved")
            .contains("the next one will need `thoryn login --workspace thoryn`")
        assertThat(FileTokenStore().read()!!.refreshToken).isEqualTo("RT-1")
    }

    private fun jwt(payload: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
            enc.encodeToString(payload.toByteArray()) + ".sig"
    }
}
