package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.ThorynMain
import com.devnow.thoryn.cli.auth.Dpop
import com.devnow.thoryn.cli.auth.DpopCapability
import com.devnow.thoryn.cli.auth.ParCapability
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import picocli.CommandLine
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * SSO-3282 — `thoryn login` recovers from a refusal it used to die on, once.
 *
 * ## The report
 *
 * After the current machine's device was revoked, every `thoryn login` failed
 * `Sign-in failed: Hub returned 400: invalid_grant`. Running it again could never help: the key on
 * disk was the refused one, and nothing in the flow replaced it. The hub now names that case with a
 * stable `error_description` (SSO-3282, hub half), which is the signal this recovery keys on.
 *
 * ## Why the whole flow is retried, not just the redemption
 *
 * The authorize request binds `dpop_jkt` to the key on the way IN (RFC 9449 §10.1 / SSO-3221), so a
 * code obtained under the OLD key can only ever be redeemed by the old key. Re-redeeming the same
 * code with a fresh key would simply fail again. The test therefore asserts the thing that makes the
 * retry correct rather than merely present: the second authorize request carries a DIFFERENT
 * `dpop_jkt`, and it is the thumbprint the installation ends up holding.
 *
 * ## How the flow is driven
 *
 * This is the only test that runs the real loopback sign-in end to end, because the bug lives in the
 * seam between the authorize leg and the redemption leg and neither half shows it alone. The command
 * runs on its own thread; the test reads the authorize URL it prints, and plays the browser by
 * fetching its `redirect_uri` with a `code` and the matching `state`. PAR is switched off
 * ([ParCapability]) so the parameters — `dpop_jkt` among them — ride that URL where the test can
 * read them.
 */
class LoginRevokedDeviceRetryTest : CommandTestBase() {

    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    private var originalNoBrowser: String? = null

    @BeforeEach
    fun arrangeFlow() {
        Dpop.resetForTest()
        ParCapability.resetForTest()
        // Parameters on the authorize URL, so the test can read `dpop_jkt` off it.
        ParCapability.probe = { null }
        // The DPoP gate this flow asks before it will name a key at all.
        DpopCapability.probe = { true }
        originalNoBrowser = System.getProperty("THORYN_NO_BROWSER")
        // Never launch a real browser from a test run.
        System.setProperty("THORYN_NO_BROWSER", "1")
    }

    @AfterEach
    fun restore() {
        originalNoBrowser?.let { System.setProperty("THORYN_NO_BROWSER", it) }
            ?: System.clearProperty("THORYN_NO_BROWSER")
        ParCapability.resetForTest()
        Dpop.resetForTest()
    }

    private fun revokedDeviceRefusal() = jsonResponse(
        400,
        """{"error":"invalid_grant","error_description":"dpop_device_revoked",
           "error_uri":"https://thoryn.io/docs/guides/manage-your-cli-devices#a-revoked-device"}""",
    )

    private fun tokens() = jsonResponse(
        200,
        """{"access_token":"AT-new","refresh_token":"RT-new","token_type":"DPoP","expires_in":900,"scope":"openid"}""",
    )

    @Test
    fun `a revoked-device refusal rotates the key and signs in again under the new one`() {
        val before = Dpop.session()!!.thumbprint
        server.enqueue(revokedDeviceRefusal())
        server.enqueue(tokens())

        val run = runLogin(expectedAuthorizeRequests = 2)

        assertThat(run.exit).describedAs("stderr was: %s", run.err).isEqualTo(0)
        assertThat(run.authorizeJkts)
            .describedAs("both legs must have happened, or this proves nothing")
            .hasSize(2)

        val (first, second) = run.authorizeJkts
        assertThat(first)
            .describedAs("the first attempt is the one the hub refuses — it names the OLD key")
            .isEqualTo(before)
        assertThat(second)
            .describedAs(
                "the retry is only correct if it starts a NEW authorize under the NEW key: a code " +
                    "bound to the old `dpop_jkt` could never be redeemed by the rotated key",
            )
            .isNotEqualTo(first)

        Dpop.resetForTest()
        assertThat(Dpop.session()!!.thumbprint)
            .describedAs("and the key it signed in with is the key it kept")
            .isEqualTo(second)

        assertThat(run.err).contains("revoked")
        assertThat(server.requestCount).describedAs("exactly two redemptions — one retry, not a loop").isEqualTo(2)
    }

    @Test
    fun `an invalid_grant that is NOT a revoked device is reported, never retried`() {
        // The counterweight. A replayed or expired code answers the same CODE, and retrying it would
        // cost the person a second browser round trip and still fail — so the match is on the
        // description and on nothing else.
        server.enqueue(jsonResponse(400, """{"error":"invalid_grant"}"""))

        val run = runLogin(expectedAuthorizeRequests = 1)

        assertThat(run.exit).isNotEqualTo(0)
        assertThat(run.authorizeJkts).describedAs("no second authorize leg may be started").hasSize(1)
        assertThat(server.requestCount).isEqualTo(1)
        assertThat(run.err).contains("Sign-in failed").contains("invalid_grant")

        Dpop.resetForTest()
        assertThat(Dpop.session()!!.thumbprint)
            .describedAs("and the key is untouched — rotating on a guess would destroy a working identity")
            .isEqualTo(run.keyBefore)
    }

    // ── driving the flow ─────────────────────────────────────────────────────────────────────

    private class LoginRun(
        val exit: Int,
        val err: String,
        val authorizeJkts: List<String>,
        val keyBefore: String,
    )

    /**
     * Runs `thoryn login` against the MockWebServer, playing the browser for each authorize URL it
     * prints, and returns what happened.
     *
     * [expectedAuthorizeRequests] is how many authorize legs to serve before letting the command
     * finish; the watcher stops after that, so a flow that (wrongly) started a third would leave it
     * unserved and time out rather than pass quietly.
     */
    private fun runLogin(expectedAuthorizeRequests: Int): LoginRun {
        val keyBefore = Dpop.session()!!.thumbprint
        val transcript = StringBuffer()
        val err = ByteArrayOutputStream()
        val jkts = mutableListOf<String>()
        val done = CountDownLatch(1)
        var exit = -1

        val originalOut = System.out
        val originalErr = System.err
        val driver = thread(name = "sso3282-browser", isDaemon = true) {
            var served = 0
            val deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos()
            while (served < expectedAuthorizeRequests && System.nanoTime() < deadline && done.count > 0L) {
                val url = authorizeUrlAt(transcript.toString(), served)
                if (url == null) {
                    Thread.sleep(25)
                    continue
                }
                val params = queryOf(url)
                params["dpop_jkt"]?.let { synchronized(jkts) { jkts += it } }
                val redirect = params["redirect_uri"] ?: error("authorize URL carried no redirect_uri: $url")
                val state = params["state"].orEmpty()
                runCatching {
                    http.send(
                        HttpRequest.newBuilder(URI.create("$redirect?code=CODE-$served&state=$state"))
                            .timeout(Duration.ofSeconds(5)).GET().build(),
                        HttpResponse.BodyHandlers.ofString(),
                    )
                }
                served++
            }
        }

        try {
            System.setOut(PrintStream(tee(transcript), true, Charsets.UTF_8))
            System.setErr(PrintStream(err, true, Charsets.UTF_8))
            exit = CommandLine(ThorynMain()).execute("login", "--issuer", baseUrl(), "--workspace", "acme")
        } finally {
            done.countDown()
            System.setOut(originalOut)
            System.setErr(originalErr)
            driver.join(TimeUnit.SECONDS.toMillis(5))
        }
        return LoginRun(exit, err.toString(Charsets.UTF_8), synchronized(jkts) { jkts.toList() }, keyBefore)
    }

    /** An [OutputStream] the watcher thread can read while the command is still writing to it. */
    private fun tee(sink: StringBuffer): OutputStream = object : OutputStream() {
        override fun write(b: Int) {
            sink.append(b.toChar())
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            sink.append(String(b, off, len, Charsets.UTF_8))
        }
    }

    /**
     * The [index]-th authorize URL printed so far, or null if the command has not got there yet.
     *
     * Only counted once the line is COMPLETE (terminated by a newline) — the transcript is read
     * while it is being written, so a URL caught mid-write would be truncated and its `redirect_uri`
     * unusable.
     */
    private fun authorizeUrlAt(transcript: String, index: Int): String? =
        transcript.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("${baseUrl()}/oauth2/authorize") }
            .toList()
            // The last line has no terminator yet, so it may still be growing: never take it.
            .let { if (transcript.endsWith("\n")) it else it.dropLast(1) }
            .getOrNull(index)

    private fun queryOf(url: String): Map<String, String> =
        URI.create(url).rawQuery.orEmpty()
            .split('&')
            .filter { it.contains('=') }
            .associate { pair ->
                val (k, v) = pair.split('=', limit = 2)
                URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
            }
}
