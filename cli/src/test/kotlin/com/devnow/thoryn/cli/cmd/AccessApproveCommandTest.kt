package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3738 — `thoryn access approve <owner>/<repo>/<run_id> | <consent URL>`: the CLI entry point to the SAME hub
 * consent the check run's Option-2 link opens. It grants nothing and calls no API: it resolves one address and opens it
 * in the browser (an injected opener here — no real browser), or prints it to open on any device.
 *
 * Pinned: the argument grammar (good shapes, the URL form, injection attempts), the base-URL resolution order (argument
 * URL → `--consent-url` → `.thoryn/workflow.yaml` → the signed-in platform), the browser-vs-print delivery, and that no
 * HTTP request is made.
 */
class AccessApproveCommandTest : CommandTestBase() {

    private val opened = mutableListOf<String>()
    private var browserAvailable = true
    private lateinit var workDir: Path

    private val runRef = "thoryn-io/thoryn-cicd/38751887466"
    private val runPath = "/github/consent/run/thoryn-io/thoryn-cicd/38751887466"

    @BeforeEach
    fun setUpApprove() {
        workDir = Files.createDirectories(tempHome.resolve("work"))
        AccessApprove.opener = { url -> opened += url; browserAvailable }
        AccessApprove.workingDirectory = { workDir }
    }

    @AfterEach
    fun tearDownApprove() {
        AccessApprove.resetForTest()
    }

    private fun writeWorkflowConfig(dir: Path, consentUrl: String) {
        Files.createDirectories(dir.resolve(".thoryn"))
        Files.writeString(dir.resolve(".thoryn/workflow.yaml"), "apiVersion: thoryn.io/workflow/v1\nconsentUrl: \"$consentUrl\"\n")
    }

    private fun signInOn(platformIssuer: String?, issuer: String? = null) =
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test", issuer = issuer, platformIssuer = platformIssuer))

    // ── delivery ──

    @Test
    fun `it opens the run's by-run consent address in the browser and prints it — no API call, nothing granted`() {
        val (exit, out, _) = runCli("access", "approve", runRef, "--consent-url", "https://starters.stg.thoryn.org")

        assertThat(exit).isEqualTo(0)
        val url = "https://starters.stg.thoryn.org$runPath"
        assertThat(opened).containsExactly(url)
        assertThat(out).contains("Opening Thoryn's consent for run $runRef in your browser").contains("    $url").contains("This command granted nothing.")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `without a browser it prints the address to open on any device`() {
        browserAvailable = false

        val (exit, out, _) = runCli("access", "approve", runRef, "--consent-url", "https://starters.stg.thoryn.org")

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("open this URL on any device").contains("    https://starters.stg.thoryn.org$runPath").doesNotContain("Opening")
    }

    @Test
    fun `--no-browser never touches the opener and prints the address`() {
        val (exit, out, _) = runCli("access", "approve", runRef, "--consent-url", "https://starters.stg.thoryn.org", "--no-browser")

        assertThat(exit).isEqualTo(0)
        assertThat(opened).isEmpty()
        assertThat(out).contains("open this URL on any device").contains("https://starters.stg.thoryn.org$runPath")
    }

    // ── the URL form ──

    @Test
    fun `a consent URL as the argument is opened as rebuilt from its validated parts — and it outranks --consent-url`() {
        val (exit, out, err) = runCli(
            "access", "approve", "https://Starters.STG.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/38751887466/",
            "--consent-url", "https://other.example.org",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://starters.stg.thoryn.org$runPath")
        assertThat(out).contains("(consent address from the consent URL you passed)")
        assertThat(err).contains("--consent-url is ignored")
    }

    @Test
    fun `a consent URL under a path prefix and with a port keeps them`() {
        val (exit, _, _) = runCli("access", "approve", "https://consent.example.org:8443/thoryn$runPath")

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://consent.example.org:8443/thoryn$runPath")
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(
        strings = [
            "http://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1", // not https
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://evil.example@starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1", // user-info
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1?next=https://evil.example", // query
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1#frag", // fragment
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn%2Fcicd/1", // percent-encoding
            "https://starters.stg.thoryn.org/%2e%2e/github/consent/run/thoryn-io/thoryn-cicd/1",
            "https://starters.stg.thoryn.org/../github/consent/run/thoryn-io/thoryn-cicd/1", // dot segment in the prefix
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/../1", // dot segment as the repository
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1/extra", // trailing path
            "https://starters.stg.thoryn.org/github/consent/thoryn-io/thoryn-cicd/1", // not the by-run route
            "https://starters.stg.thoryn.org\\@evil.example/github/consent/run/thoryn-io/thoryn-cicd/1", // backslash host trick
            "https://starters.stg.thoryn.org:99999/github/consent/run/thoryn-io/thoryn-cicd/1", // port out of range
            "https://localhost/github/consent/run/thoryn-io/thoryn-cicd/1", // not a DNS name with a domain
            "https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/1\nhttps://evil.example", // smuggled line
            "https://starters.stg.thoryn.org/github/consent/run/-x/thoryn-cicd/1", // leading '-' owner
        ],
    )
    fun `a consent URL that is not exactly an https by-run address is refused — nothing is opened`(raw: String) {
        val (exit, _, err) = runCli("access", "approve", raw)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(opened).isEmpty()
        assertThat(err).startsWith("Error: ")
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(strings = ["thoryn-io/thoryn-cicd", "thoryn-io/thoryn-cicd/0", "evil.example/x/1", "thoryn-io/thoryn-cicd/1?x=1", "-o/r/1", "o/r/1/2"])
    fun `a by-run reference outside GitHub's grammar is refused before any base is resolved`(raw: String) {
        // `--` so a leading '-' reaches the command's own grammar instead of picocli's option parser.
        val (exit, _, err) = runCli("access", "approve", "--consent-url", "https://starters.stg.thoryn.org", "--", raw)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(opened).isEmpty()
        assertThat(err).contains("<owner>/<repository>/<run_id>")
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @ValueSource(
        strings = [
            "http://starters.stg.thoryn.org",
            "https://starters.stg.thoryn.org?x=1",
            "https://user@starters.stg.thoryn.org",
            "https://starters.stg.thoryn.org/a/../b",
            "starters.stg.thoryn.org",
        ],
    )
    fun `a --consent-url that is not an https base URL is refused`(raw: String) {
        val (exit, _, err) = runCli("access", "approve", runRef, "--consent-url", raw)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(opened).isEmpty()
        assertThat(err).contains("--consent-url").contains("not an https:// base URL")
    }

    @Test
    fun `a full consent link passed as --consent-url is refused with the hint to pass it as the argument`() {
        val (exit, _, err) = runCli("access", "approve", runRef, "--consent-url", "https://starters.stg.thoryn.org$runPath")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("is a full consent link — pass it as the argument instead")
    }

    // ── the base-URL resolution order ──

    @Test
    fun `--consent-url outranks the repository's workflow config and the signed-in platform`() {
        writeWorkflowConfig(workDir, "https://from-config.example.org")
        signInOn("https://auth.stg.thoryn.org")

        val (exit, out, _) = runCli("access", "approve", runRef, "--consent-url", "https://from-flag.example.org/")

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://from-flag.example.org$runPath")
        assertThat(out).contains("(consent address from --consent-url)")
    }

    @Test
    fun `inside the repository the workflow config's consentUrl outranks the signed-in platform — found from a subdirectory`() {
        writeWorkflowConfig(workDir, "https://from-config.example.org")
        signInOn("https://auth.stg.thoryn.org")
        AccessApprove.workingDirectory = { Files.createDirectories(workDir.resolve("cli/src/main")) }

        val (exit, out, _) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://from-config.example.org$runPath")
        assertThat(out).contains("(consent address from the repository's .thoryn/workflow.yaml consentUrl)")
    }

    @Test
    fun `the workflow config is not looked for above the repository root`() {
        writeWorkflowConfig(workDir, "https://outside-the-repo.example.org")
        val repo = Files.createDirectories(workDir.resolve("repo"))
        Files.createDirectories(repo.resolve(".git"))
        AccessApprove.workingDirectory = { repo }
        signInOn("https://auth.stg.thoryn.org")

        val (exit, _, _) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://starters.stg.thoryn.org$runPath")
    }

    @Test
    fun `an empty consentUrl in the workflow config falls through to the signed-in platform`() {
        writeWorkflowConfig(workDir, "")
        signInOn("https://auth.stg.thoryn.org")

        val (exit, out, _) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://starters.stg.thoryn.org$runPath")
        assertThat(out).contains("(consent address from your signed-in platform (starters.<platform domain>))")
    }

    @Test
    fun `the platform is derived from the session's base issuer, else from its workspace issuer`() {
        signInOn(platformIssuer = null, issuer = "https://acme.auth.example.org")

        val (exit, _, _) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(0)
        assertThat(opened).containsExactly("https://starters.example.org$runPath")
    }

    @Test
    fun `a platform that names no domain — a local hub — derives nothing and the error says how to pass the address`() {
        signInOn("http://localhost:54702")

        val (exit, _, err) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(opened).isEmpty()
        assertThat(err).contains("no consent address for $runRef").contains("--consent-url").contains("thoryn login")
    }

    @Test
    fun `with no session and no configuration it refuses with guidance`() {
        clearTokens()

        val (exit, _, err) = runCli("access", "approve", runRef)

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(opened).isEmpty()
        assertThat(err).contains("pass the consent URL from the check run")
    }

    @Test
    fun `startersBaseFor reads only an https base host with a recognised label`() {
        assertThat(AccessApprove.startersBaseFor(Tokens(accessToken = "x", platformIssuer = "https://auth.stg.thoryn.org"))).isEqualTo("https://starters.stg.thoryn.org")
        assertThat(AccessApprove.startersBaseFor(Tokens(accessToken = "x", platformIssuer = "https://hub.stg.thoryn.org/"))).isEqualTo("https://starters.stg.thoryn.org")
        assertThat(AccessApprove.startersBaseFor(Tokens(accessToken = "x", platformIssuer = "https://login.acme.com"))).isNull()
        assertThat(AccessApprove.startersBaseFor(Tokens(accessToken = "x", platformIssuer = "http://auth.stg.thoryn.org"))).isNull()
        assertThat(AccessApprove.startersBaseFor(null)).isNull()
    }
}
