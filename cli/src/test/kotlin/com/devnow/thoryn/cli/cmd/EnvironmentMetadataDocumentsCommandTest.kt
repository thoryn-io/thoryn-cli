package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-4345 (oauthy SSO-4335 / SSO-4338) — `thoryn env metadata-documents show|set` against [FakeProductApi] standing in
 * for product-api's `/api/v1/environments/{envId}/client-id-metadata-documents`: the slug → id resolution, `set`'s
 * read-change-write of the WHOLE policy (only the flags given change; a lifetime is sent only when given; an unchanged
 * policy is not written), the contradictory-flag refusals, and the widening write's step-up and person-only refusals in
 * words.
 */
class EnvironmentMetadataDocumentsCommandTest : CommandTestBase() {

    private val api = FakeProductApi()
    private lateinit var envId: String

    @BeforeEach
    fun mount() {
        server.dispatcher = api
        envId = api.seedEnvironment("staging")
        api.seedEnvironment("production", kind = "production")
    }

    private fun cli(vararg args: String) = runCli("env", "metadata-documents", *args, "--env", "staging", "--gateway", baseUrl())

    private fun puts() = api.writes.filter { it.method == "PUT" && it.path == "/api/v1/environments/$envId/client-id-metadata-documents" }

    private fun stored(enabled: Boolean, vararg hosts: String, refresh: Boolean = false) {
        api.metadataDocumentPolicies[envId] = mutableMapOf(
            "environmentId" to envId, "environment" to "staging", "enabled" to enabled, "allowedHosts" to hosts.toList(),
            "refreshTokensEnabled" to refresh, "refreshTokenTtlSeconds" to 259_200L, "refreshTokenAbsoluteMaxTtlSeconds" to 604_800L,
            "updatedAt" to "2026-11-08T10:00:00Z",
        )
    }

    @Test
    fun `show prints the environment's defaults`() {
        val (exit, out, err) = cli("show")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(out).contains("environment").contains("staging").contains("enabled").contains("false")
            .contains("(none)").contains("refreshTokens").contains("off").contains("72h").contains("7d")
            .contains("(never changed: the defaults)")
    }

    @Test
    fun `show --output json prints the policy as the API answers it`() {
        stored(true, "clients.example.com")

        val (exit, out, _) = cli("show", "--output", "json")

        assertThat(exit).isEqualTo(0)
        val json = parseJson(out)
        assertThat(json["enabled"]).isEqualTo(true)
        assertThat(json["allowedHosts"]).isEqualTo(listOf("clients.example.com"))
    }

    @Test
    fun `set --enable --add-host writes the whole policy and sends no lifetime it was not given`() {
        val (exit, out, err) = cli("set", "--enable", "--add-host", "Clients.Example.com")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(puts().single().body).isEqualTo(
            mapOf("enabled" to true, "allowedHosts" to listOf("clients.example.com"), "refreshTokensEnabled" to false),
        )
        assertThat(out).contains("clients.example.com")
    }

    @Test
    fun `--add-host keeps the hosts already allowed and --remove-host drops one`() {
        stored(true, "a.example.com", "b.example.com")

        val (exit, _, err) = cli("set", "--add-host", "c.example.com", "--remove-host", "a.example.com")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(puts().single().body["allowedHosts"]).isEqualTo(listOf("b.example.com", "c.example.com"))
        assertThat(puts().single().body["enabled"]).describedAs("an unmentioned part keeps its value").isEqualTo(true)
    }

    @Test
    fun `--hosts replaces the list, and an empty --hosts clears it`() {
        stored(false, "a.example.com", "b.example.com")

        val (replaced, _, _) = cli("set", "--hosts", "x.example.com,y.example.com")
        assertThat(replaced).isEqualTo(0)
        assertThat(puts().last().body["allowedHosts"]).isEqualTo(listOf("x.example.com", "y.example.com"))

        val (cleared, _, _) = cli("set", "--hosts", "")
        assertThat(cleared).isEqualTo(0)
        assertThat(puts().last().body["allowedHosts"]).isEqualTo(emptyList<String>())
    }

    @Test
    fun `refresh tokens and their lifetimes are sent in seconds`() {
        stored(true, "clients.example.com")

        val (exit, _, err) = cli("set", "--refresh-tokens", "on", "--refresh-idle", "PT24H", "--refresh-max", "P30D")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        val body = puts().single().body
        assertThat(body["refreshTokensEnabled"]).isEqualTo(true)
        assertThat((body["refreshTokenTtlSeconds"] as Number).toLong()).isEqualTo(86_400L)
        assertThat((body["refreshTokenAbsoluteMaxTtlSeconds"] as Number).toLong()).isEqualTo(2_592_000L)
    }

    @Test
    fun `a set that changes nothing is not written`() {
        stored(true, "clients.example.com")

        val (exit, _, err) = cli("set", "--enable", "--add-host", "clients.example.com", "--refresh-idle", "PT72H")

        assertThat(exit).isEqualTo(0)
        assertThat(err).contains("No change")
        assertThat(puts()).isEmpty()
    }

    @Test
    fun `contradictory or empty flags are refused before any call`() {
        listOf(
            arrayOf("set", "--enable", "--disable") to "contradict",
            arrayOf("set", "--hosts", "a.example.com", "--add-host", "b.example.com") to "cannot be combined",
            arrayOf("set") to "nothing to change",
            arrayOf("set", "--refresh-tokens", "maybe") to "on or off",
            arrayOf("set", "--refresh-idle", "72 hours") to "ISO-8601",
            arrayOf("set", "--refresh-idle", "PT30M") to "PT1H",
            arrayOf("set", "--refresh-idle", "P2D", "--refresh-max", "P1D") to "not be shorter",
        ).forEach { (args, message) ->
            val (exit, _, err) = cli(*args)
            assertThat(exit).describedAs(args.joinToString(" ")).isEqualTo(CommandSupport.EXIT_USAGE)
            assertThat(err).describedAs(args.joinToString(" ")).contains(message)
        }
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a widening write without a fresh passkey sign-in names the login to run, and nothing is stored`() {
        api.metadataDocumentWidening = "step_up"

        val (exit, _, err) = cli("set", "--enable", "--add-host", "clients.example.com")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
        assertThat(api.metadataDocumentPolicies).isEmpty()
    }

    @Test
    fun `a machine identity's widening write is told it is a person's act`() {
        api.metadataDocumentWidening = "machine"

        val (exit, _, err) = cli("set", "--refresh-tokens", "on")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("elevated_action_requires_person").contains("may only narrow")
    }

    @Test
    fun `narrowing needs no step-up`() {
        stored(true, "clients.example.com", refresh = true)
        api.metadataDocumentWidening = "step_up"

        val (exit, _, err) = cli("set", "--refresh-tokens", "off", "--disable")

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(puts()).hasSize(1)
    }

    @Test
    fun `an environment the caller does not manage is explained, and enabling without a host names the fix`() {
        api.metadataDocumentManages = { false }
        val (exit, _, err) = cli("show")
        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("not a manager of environment 'staging'")

        api.metadataDocumentManages = { true }
        val (exit2, _, err2) = cli("set", "--enable")
        assertThat(exit2).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err2).contains("allowed_hosts_required").contains("--add-host")
    }
}
