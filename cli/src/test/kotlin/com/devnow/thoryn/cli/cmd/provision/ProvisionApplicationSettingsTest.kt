package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ApplyResult
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3766 / SSO-3767 / SSO-3770 — the three application settings converge like every other rendered field: sent on
 * create, read back from the response, diffed only when DECLARED, and an update sends exactly the fields that differ. An
 * omitted setting keeps the live value; `allowedAuthorizationDetailTypes` converges as a SET whose declared list replaces
 * the live one (`[]` clears it). A second apply writes nothing.
 */
class ProvisionApplicationSettingsTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()
    private val exchange = ProvisionFile.GRANT_TOKEN_EXCHANGE

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    private val base = """
        apiVersion: thoryn.io/provision/v1
        resources:
          - kind: application
            name: portal
            spec:
              clientId: portal
              displayName: "Acme Portal"
              redirectUris: ["https://app.acme.example/cb"]
              grantTypes: [authorization_code, refresh_token, "$exchange"]
    """

    /** The portal application with [settings] (YAML lines) appended to its `spec`. */
    private fun portal(settings: String) = file(base.trimIndent() + "\n" + settings.trimIndent().prependIndent("      "))

    private val allFour = """
        allowTokenExchange: true
        allowedAuthorizationDetailTypes: [openid_credential]
        refreshTokenSlidingWindow: true
        refreshTokenAbsoluteMaxTtlSeconds: 28800
    """

    private fun live(): MutableMap<String, Any?> = api.applications.single { it["clientId"] == "portal" }

    @Test
    fun `a create sends every declared setting, and a second plan and apply are a no-op`() {
        val f = portal(allFour)
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.CREATE)
        apply(f)
        val create = api.writes.single { it.method == "POST" && it.path == "/api/v1/applications" }.body
        assertThat(create)
            .containsEntry("allowTokenExchange", true)
            .containsEntry("allowedAuthorizationDetailTypes", listOf("openid_credential"))
            .containsEntry("refreshTokenSlidingWindow", true)
            .containsEntry("refreshTokenAbsoluteMaxTtlSeconds", 28800)

        api.reset()
        val again = engine().plan(f, false).changes.single()
        assertThat(again.action).isEqualTo(ChangeAction.NOOP)
        assertThat(again.diff).isEmpty()
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `drift on each setting is detected and converged with exactly the differing fields, then the file is a no-op again`() {
        val f = portal(allFour)
        apply(f)
        // Changed out of band — the platform is the ledger, so the next plan reads it.
        live().putAll(
            mapOf(
                "allowTokenExchange" to false, "allowedAuthorizationDetailTypes" to emptyList<String>(),
                "refreshTokenSlidingWindow" to false, "refreshTokenAbsoluteMaxTtlSeconds" to 7_776_000,
            ),
        )
        api.reset()

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        // The four this file declares (SSO-3810 / SSO-3807 added two more settings it does not declare, so they are not diffed).
        assertThat(change.diff.keys).containsExactly(
            "allowTokenExchange", "allowedAuthorizationDetailTypes", "refreshTokenSlidingWindow", "refreshTokenAbsoluteMaxTtlSeconds",
        )
        assertThat(change.diff["allowTokenExchange"]).isEqualTo("false → true")
        assertThat(change.diff["refreshTokenAbsoluteMaxTtlSeconds"]).isEqualTo("7776000 → 28800")
        apply(f)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(
            mapOf(
                "allowTokenExchange" to true, "allowedAuthorizationDetailTypes" to listOf("openid_credential"),
                "refreshTokenSlidingWindow" to true, "refreshTokenAbsoluteMaxTtlSeconds" to 28800,
            ),
        )

        // One field drifts: only that one is sent.
        live()["refreshTokenAbsoluteMaxTtlSeconds"] = 43_200
        api.reset()
        val one = engine().plan(f, false).changes.single()
        assertThat(one.diff.keys).containsExactly("refreshTokenAbsoluteMaxTtlSeconds")
        apply(f)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("refreshTokenAbsoluteMaxTtlSeconds" to 28800))

        api.reset()
        assertThat(engine().plan(f, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `allowedAuthorizationDetailTypes converges as a set — order is not drift, a declared list replaces the live one, an empty list clears it`() {
        api.homeWorkspace = true // `thoryn_access_grant` is the home workspace's to declare
        apply(portal("allowedAuthorizationDetailTypes: [openid_credential, thoryn_access_grant]"))
        live()["allowedAuthorizationDetailTypes"] = listOf("thoryn_access_grant", "openid_credential")
        api.reset()
        assertThat(engine().plan(portal("allowedAuthorizationDetailTypes: [openid_credential, thoryn_access_grant]"), false).changes.single().action).isEqualTo(ChangeAction.NOOP)

        val narrowed = portal("allowedAuthorizationDetailTypes: [openid_credential]")
        assertThat(engine().plan(narrowed, false).changes.single().diff.keys).containsExactly("allowedAuthorizationDetailTypes")
        apply(narrowed)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowedAuthorizationDetailTypes" to listOf("openid_credential")))
        assertThat(live()["allowedAuthorizationDetailTypes"]).isEqualTo(listOf("openid_credential"))

        api.reset()
        val cleared = portal("allowedAuthorizationDetailTypes: []")
        val plan = engine().plan(cleared, false).changes.single()
        assertThat(plan.diff["allowedAuthorizationDetailTypes"]).isEqualTo("[openid_credential] → []")
        apply(cleared)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowedAuthorizationDetailTypes" to emptyList<String>()))
        api.reset()
        apply(cleared)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an omitted setting keeps the live value — no diff, no write, whatever the platform holds`() {
        apply(portal(allFour))
        live()["allowedAuthorizationDetailTypes"] = listOf("openid_credential")
        api.reset()

        val bare = portal("requireProofKey: true")
        val change = engine().plan(bare, false).changes.single()
        // The fixture's `requireProofKey` is not a rendered field: the plan sees nothing to converge.
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.diff.keys).doesNotContainAnyElementsOf(ProvisionFile.APPLICATION_SETTING_FIELDS)
        apply(bare)
        assertThat(api.writes).isEmpty()
        assertThat(live()).containsEntry("allowTokenExchange", true).containsEntry("refreshTokenSlidingWindow", true).containsEntry("refreshTokenAbsoluteMaxTtlSeconds", 28800)

        // A file that declares only SOME of the settings converges those, and leaves the rest as they are.
        live()["refreshTokenAbsoluteMaxTtlSeconds"] = 43_200
        val partial = portal("refreshTokenSlidingWindow: true")
        assertThat(engine().plan(partial, false).changes.single().action).isEqualTo(ChangeAction.NOOP)
        apply(partial)
        assertThat(api.writes).isEmpty()
        assertThat(live()["refreshTokenAbsoluteMaxTtlSeconds"]).isEqualTo(43_200)
    }

    @Test
    fun `turning token exchange off and turning the session window off are ordinary updates`() {
        apply(portal(allFour))
        api.reset()
        val off = portal(
            """
            allowTokenExchange: false
            refreshTokenSlidingWindow: false
            """,
        )
        val change = engine().plan(off, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff.keys).containsExactlyInAnyOrder("allowTokenExchange", "refreshTokenSlidingWindow")
        apply(off)
        assertThat(api.writes.single { it.method == "PATCH" }.body).isEqualTo(mapOf("allowTokenExchange" to false, "refreshTokenSlidingWindow" to false))
        api.reset()
        apply(off)
        assertThat(api.writes).isEmpty()
    }
}
