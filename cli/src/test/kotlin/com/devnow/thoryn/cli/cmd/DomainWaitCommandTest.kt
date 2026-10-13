package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Duration
import java.time.Instant

/**
 * SSO-3414 — the machine-readable custom-domain output and the bounded `--wait` of `thoryn domain status`,
 * `thoryn domain verify` and `thoryn provision apply`, against [FakeProductApi]'s custom-domain state
 * machine on MockWebServer. Time is virtual: the wait's sleep advances a fake clock, so a 15-minute
 * timeout runs in milliseconds.
 */
class DomainWaitCommandTest : CommandTestBase() {

    private val api = FakeProductApi()
    private var now: Instant = Instant.parse("2026-09-28T12:00:00Z")
    private val sleeps = mutableListOf<Duration>()

    /** Runs before each virtual sleep — lets a test change the world between rounds (e.g. publish DNS). */
    private var onSleep: (Int) -> Unit = {}

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        DomainCommand.waitClock = { now }
        DomainCommand.waitSleeper = { d -> sleeps += d; now = now.plus(d); onSleep(sleeps.size) }
    }

    @AfterEach
    fun reset() = DomainCommand.resetForTest()

    private fun pending() { api.domainHost = "auth.acme.com"; api.domainState = "PENDING" }

    @Suppress("UNCHECKED_CAST")
    private fun records(json: Map<String, Any?>) = json["dnsRecords"] as List<Map<String, Any?>>

    // ── machine-readable records ─────────────────────────────────────────────

    @Test
    fun `status --json prints every record as type, name, value and ttl, plus the issuer in use`() {
        pending()

        val (exit, out, _) = runCli("domain", "status", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(records(json)).containsExactly(
            mapOf("type" to "TXT", "name" to "_thoryn-verify.auth.acme.com", "value" to "thoryn-verify=tok-auth.acme.com", "ttl" to 300),
            mapOf("type" to "CNAME", "name" to "auth.acme.com", "value" to "acme.auth.thoryn.io", "ttl" to 300),
        )
        assertThat(json).containsEntry("issuer", "https://acme.auth.thoryn.io").containsEntry("customIssuer", "https://auth.acme.com")
    }

    @Test
    fun `status --json adds the recommended ttl when product-api does not send one`() {
        pending(); api.domainTtl = null

        val json = parseJson(runCli("domain", "status", "--json", "--gateway", baseUrl()).out)

        assertThat(records(json).map { it["ttl"] }).containsOnly(300)
    }

    @Test
    fun `the table view lists the TTL next to each record`() {
        pending()

        val (_, out, _) = runCli("domain", "status", "--gateway", baseUrl())

        assertThat(out).contains("TTL").contains("_thoryn-verify.auth.acme.com").contains("300")
    }

    // ── --wait ───────────────────────────────────────────────────────────────

    @Test
    fun `verify --wait keeps verifying until the records are published and returns 0 once VERIFIED`() {
        pending()
        onSleep = { round -> if (round == 2) api.dnsPublished = true }

        val (exit, out, err) = runCli("domain", "verify", "--wait", "--until", "VERIFIED", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("auth.acme.com is VERIFIED")
        assertThat(err).contains("now PENDING").contains("next check in 20s")
        assertThat(api.writes.map { it.path }).containsOnly("/api/v1/custom-domain/verify").hasSize(3)
        assertThat(sleeps).containsOnly(Duration.ofSeconds(20))
    }

    @Test
    fun `verify --wait for ACTIVE waits past VERIFIED for the certificate`() {
        pending(); api.dnsPublished = true; api.activeAfterReads = 2

        val (exit, out, _) = runCli("domain", "verify", "--wait", "--interval", "5s", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("auth.acme.com is ACTIVE").contains("https://auth.acme.com")
        assertThat(sleeps).allSatisfy { assertThat(it).isEqualTo(Duration.ofSeconds(5)) }
    }

    @Test
    fun `a wait that times out fails with the status API's last-check reason and the records to fix`() {
        pending(); api.dnsFailureReason = "cname_mismatch"

        val (exit, _, err) = runCli("domain", "verify", "--wait", "--timeout", "1m", "--interval", "20s", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(err)
            .contains("timed out after 1m waiting for the custom domain to be ACTIVE")
            .contains("it is PENDING")
            .contains("the CNAME points somewhere other than the workspace's platform host")
            .contains("_thoryn-verify.auth.acme.com")
        assertThat(now).isBeforeOrEqualTo(Instant.parse("2026-09-28T12:01:00Z"))
    }

    @Test
    fun `status --wait only reads — it never verifies — and --json still prints the last status on a timeout`() {
        pending()

        val (exit, out, _) = runCli("domain", "status", "--wait", "--timeout", "40s", "--json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(api.writes).isEmpty()
        assertThat(parseJson(out)).containsEntry("state", "PENDING")
    }

    @Test
    fun `a wait with nothing claimed stops at once instead of polling until the timeout`() {
        val (exit, _, err) = runCli("domain", "status", "--wait", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(err).contains("no custom domain to wait for")
        assertThat(sleeps).isEmpty()
    }

    @Test
    fun `a wait on a workspace without the entitlement names the operator step`() {
        pending(); api.domainEntitled = false

        val (exit, _, err) = runCli("domain", "verify", "--wait", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_CHECK_FAILED)
        assertThat(err).contains("Thoryn OPERATOR step").contains("thoryn operator custom-domain entitle <workspace>")
    }

    @Test
    fun `the wait flags are refused without --wait and a bad duration is a usage error`() {
        assertThat(runCli("domain", "status", "--timeout", "5m", "--gateway", baseUrl()).exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(runCli("domain", "verify", "--wait", "--timeout", "soon", "--gateway", baseUrl()).exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(runCli("domain", "verify", "--wait", "--until", "PENDING", "--gateway", baseUrl()).exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(api.writes).isEmpty()
    }

    // ── provision apply --wait ───────────────────────────────────────────────

    private fun domainFile(): File = File(tempHome.toFile(), ".thoryn/provision.yaml").also {
        it.parentFile.mkdirs()
        it.writeText(
            """
            apiVersion: thoryn.io/provision/v1
            resources:
              - kind: customDomain
                spec: { host: auth.acme.com }
            """.trimIndent(),
        )
    }

    @Test
    fun `provision apply --wait claims, then blocks until VERIFIED, printing one JSON document`() {
        onSleep = { round -> if (round == 1) api.dnsPublished = true }

        val (exit, out, err) = runCli(
            "provision", "apply", "--file", domainFile().path, "--yes", "--wait", "--wait-until", "VERIFIED",
            "--output", "json", "--gateway", baseUrl(),
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val domain = json["customDomain"] as Map<String, Any?>
        assertThat(domain).containsEntry("state", "VERIFIED")
        assertThat(records(domain).map { it.keys }).allSatisfy { assertThat(it).containsExactly("type", "name", "value", "ttl") }
        assertThat(json).containsKey("apply")
    }

    @Test
    fun `provision apply --wait on a file without a customDomain is a usage error`() {
        val file = File(tempHome.toFile(), ".thoryn/other.yaml").also {
            it.parentFile.mkdirs()
            it.writeText("apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: environment\n    name: e\n    spec: { slug: e }\n")
        }

        val (exit, _, err) = runCli("provision", "apply", "--file", file.path, "--yes", "--wait", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("declares none")
    }
}
