package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ChangeAction
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * SSO-3856 — a client's OPERATOR-PLANE scopes (`platform:` put there by an operator with `thoryn operator
 * platform-scopes`, `admin:`) are not a provisioning file's to converge (oathy ADR
 * `2026-10-19-operator-grants-platform-client-scopes.md` §3: the hub keeps a client's `platform:` scopes across a
 * customer-plane update and refuses them on every customer-plane grant). So the engine leaves them out of the
 * declared-vs-live comparison — otherwise every plan of such a client shows a change that applying can never make —
 * never imports them, and refuses a file that declares one.
 */
class ProvisionOperatorPlaneScopesTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() {
        server.dispatcher = api
    }

    private fun engine(subject: String? = null) = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId, subject = subject,
    )

    private fun file(yaml: String) = ProvisionFile.parse(yaml.trimIndent().toByteArray(), "provision.yaml")

    /** The provisioning service's machine client on the production plane, declaring [scopes]. */
    private fun machine(vararg scopes: String) = file(
        "apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: provisioning\n" +
            "    spec:\n      clientId: provisioning-m2m\n      displayName: \"Provisioning\"\n      clientType: confidential\n" +
            "      grantTypes: [client_credentials]\n      scopes: [${scopes.joinToString(", ")}]\n",
    )

    private fun live(): MutableMap<String, Any?> = api.applications.single { it["clientId"] == "provisioning-m2m" }

    @Test
    fun `an operator-granted platform scope on the live client is not a change`() {
        api.seedApplication(null, "Provisioning", emptyList(), clientId = "provisioning-m2m")
        live()["clientType"] = "confidential"
        live()["grantTypes"] = listOf("client_credentials")
        live()["scopes"] = listOf("tenant:github-connections.read", "platform:trusted-issuers.read", "platform:audit-events.append")

        val row = engine().plan(machine("tenant:github-connections.read"), false).changes.single()

        assertThat(row.action).isEqualTo(ChangeAction.NOOP)
        assertThat(row.diff).isEmpty()
    }

    @Test
    fun `an admin scope on the live client is ignored the same way`() {
        api.seedApplication(null, "Provisioning", emptyList(), clientId = "provisioning-m2m")
        live()["grantTypes"] = listOf("client_credentials")
        live()["scopes"] = listOf("tenant:github-connections.read", "admin:clients.platform-scopes")

        assertThat(engine().plan(machine("tenant:github-connections.read"), false).changes.single().action).isEqualTo(ChangeAction.NOOP)
    }

    @Test
    fun `real tenant scope drift still converges, and the diff names only what the file can change`() {
        api.seedApplication(null, "Provisioning", emptyList(), clientId = "provisioning-m2m")
        live()["grantTypes"] = listOf("client_credentials")
        live()["scopes"] = listOf("tenant:github-connections.read", "platform:github-installations.sync")

        val row = engine().plan(machine("tenant:github-connections.read", "tenant:github-connections.write"), false).changes.single()

        assertThat(row.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(row.diff.keys).containsExactly("scopes")
        assertThat(row.diff.getValue("scopes")).doesNotContain("platform:")
    }

    @Test
    fun `import never renders an operator-plane scope into a file`() {
        api.seedApplication(null, "Provisioning", emptyList(), clientId = "provisioning-m2m")
        live()["scopes"] = listOf("tenant:github-connections.read", "platform:trusted-issuers.read", "admin:clients.platform-scopes")
        api.seedGrant("client:repo", "manager", "application:provisioning-m2m")

        val imported = engine(subject = "client:repo").import(existing = null).resources.single { it.liveId == "provisioning-m2m" }

        assertThat(imported.resource.spec["scopes"]).isEqualTo(listOf("tenant:github-connections.read"))
    }

    @Test
    fun `a file declaring a platform or admin scope is refused, pointing at the operator path`() {
        for (scope in listOf("platform:trusted-issuers.read", "admin:clients.platform-scopes")) {
            assertThatThrownBy { machine("tenant:github-connections.read", scope) }
                .isInstanceOf(ProvisionException::class.java)
                .hasMessageContaining(ProvisionFile.ERR_RESERVED_SCOPE)
                .hasMessageContaining(scope)
                .hasMessageContaining("thoryn operator platform-scopes apply")
        }
    }

    @Test
    fun `the reserved namespaces are exactly platform and admin`() {
        assertThat(ProvisionFile.isReservedOperatorPlaneScope("platform:audit-events.append")).isTrue()
        assertThat(ProvisionFile.isReservedOperatorPlaneScope(" admin:custom-domains.read")).isTrue()
        assertThat(ProvisionFile.isReservedOperatorPlaneScope("tenant:applications.read")).isFalse()
        assertThat(ProvisionFile.isReservedOperatorPlaneScope("openid")).isFalse()
        assertThat(ProvisionFile.isReservedOperatorPlaneScope("platformish")).isFalse()
    }
}
