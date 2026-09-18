package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.AccessCommand
import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3090 (epic SSO-3087) — repo-level test binding THIS repo's committed provisioning file
 * (`.thoryn/provision.yaml`, the "what I own" half of `.thoryn/`) to the CLI that ships it:
 * the file must load through [ProvisionFile] (schema-conformant), declare exactly the CI fixtures the
 * provisioning Action expects (a sandbox + a loopback client INSIDE it; the only production-plane
 * resources are the CLI's own login client and the CI machine identity), carry no secret, and stay
 * within the scope set the sibling `connection.json` requests — so a change to either file that would
 * break the CI run fails here first.
 *
 * SSO-3113 (epic SSO-3108) adds the least-privilege half: the CI identity `cli-ci` is declared HERE,
 * holds exactly the scopes converging THIS file needs, and its whole reach is ONE grant — `manager` on
 * the `ci` sandbox. The file cannot silently widen that without failing this test.
 */
class CiProvisionFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    @Test
    fun `the committed provisioning file declares the CLI login client on the production plane plus the CI sandbox and its loopback client`() {
        assertThat(file.resources.map { it.key })
            .containsExactly("application/cli", "application/ci", "environment/ci", "application/loopback-rp")
        val env = file.environmentResource("ci")!!
        assertThat(env.spec["slug"]).isEqualTo("cli-ci")
        val rp = file.resources.single { it.key == "application/loopback-rp" }
        assertThat(rp.environment).isEqualTo("ci") // lives INSIDE the sandbox → destroy needs no production confirmation
        assertThat(rp.spec["clientType"]).isEqualTo("public")
        assertThat(rp.spec["redirectUris"]).isEqualTo(listOf("http://127.0.0.1/callback"))
        // SSO-3104 / SSO-3113 — the production plane holds exactly two resources: the CLI's own login
        // client (adopted, never deleted, by every apply whose receipt does not own it) and the CI
        // machine identity that signs those applies in.
        val production = file.resources.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT && it.environment == null }
        assertThat(production.map { it.key }).containsExactly("application/cli", "application/ci")
        val cli = production.single { it.key == "application/cli" }
        assertThat(cli.spec["clientId"]).isEqualTo(ThorynConfig.DEFAULT_CLIENT_ID)
        assertThat(cli.spec["clientType"]).isEqualTo("public")
        assertThat(cli.spec["grantTypes"]).isEqualTo(listOf("authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"))
        assertThat(cli.spec["redirectUris"]).isEqualTo(listOf("http://127.0.0.1/callback", "http://[::1]/callback"))
        assertThat(cli.spec["requireAuthorizationConsent"]).isEqualTo(false)
        // Everything a bare `thoryn login` requests is grantable by the client (else: invalid_scope loop).
        // SSO-3182 — and the two are now EXACTLY equal: the default login scope IS the client's registered
        // set, so no command is left un-authorized by a bare login and no login can over-request.
        val granted = (cli.spec["scopes"] as List<*>).map { it.toString() }.toSet()
        assertThat(granted).isEqualTo(ThorynConfig.DEFAULT_SCOPE.split(" ").toSet())
        // …and nothing the CLI can never ask for: the grant is exactly openid + offline_access + the
        // tenant scopes referenced anywhere in the CLI's own sources (a founder must hold each to grant it).
        val requestable = requestableTenantScopes()
        assertThat(granted - setOf("openid", "offline_access")).isEqualTo(requestable)
    }

    /** Every `tenant:<area>.<read|write>` literal under src/main (sources + bundled resources). */
    private fun requestableTenantScopes(): Set<String> {
        val root = File(locate(PROVISION_PATH).parentFile.parentFile, "src/main").walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "json" || it.extension == "yaml") }
        val pattern = Regex("tenant:[a-z-]+\\.(read|write)")
        return root.flatMap { f -> pattern.findAll(f.readText()).map { it.value } }.toSet()
    }

    @Test
    fun `the provisioning file carries no secret and needs no env var`() {
        file.resources.forEach { r ->
            assertThat(r.spec.keys).noneMatch { ProvisionFile.SECRET_KEY_PATTERN.containsMatchIn(it) }
            assertThat(r.spec.keys).noneMatch { it.endsWith("Env") }
            assertThat(r.spec.values.map { it.toString() }).noneMatch { it.contains("{{env.") }
        }
    }

    @Test
    fun `the connection contract's scopes cover every kind the provisioning file declares`() {
        val needed = file.resources.map { "tenant:${area(it.kind)}.write" }.toSet()
        assertThat(Connection.scopesWithinGrant(needed, connection.scopes.toSet()))
            .withFailMessage("provision.yaml needs %s but connection.json requests only %s", needed, connection.scopes)
            .isTrue()
    }

    @Test
    fun `the declared CI machine identity is a scope-confined client_credentials client on the production plane`() {
        val ci = file.resources.single { it.key == "application/ci" }
        assertThat(ci.environment).isNull() // the identity itself lives on the production plane, not inside its sandbox
        assertThat(ci.spec["clientId"]).isEqualTo(CI_CLIENT_ID)
        assertThat(ci.spec["clientType"]).isEqualTo("confidential") // client_credentials needs a secret
        assertThat(ci.spec["grantTypes"]).isEqualTo(listOf("client_credentials")) // no human at the keyboard
        assertThat(ci.spec.keys).doesNotContain("redirectUris", "postLogoutRedirectUris")
        // Exactly the scopes converging THIS file needs — no users, no federation, no email, no idp.
        val granted = (ci.spec["scopes"] as List<*>).map { it.toString() }.toSet()
        assertThat(granted)
            .withFailMessage("cli-ci holds %s but converging this file needs exactly %s", granted, scopesToConverge())
            .isEqualTo(scopesToConverge())
    }

    @Test
    fun `the CI identity's whole declared reach is manager on the sandbox — nothing workspace-wide`() {
        val reach = file.resources.flatMap { r ->
            (r.grants ?: emptyList()).filter { it.subject == "client:$CI_CLIENT_ID" }.map { "${r.key} ${it.relation}" }
        }
        // ONE grant, on the sandbox. Containment covers the loopback client inside it; creator-becomes-
        // manager covers the identity's own record — neither may be restated, nothing wider may appear.
        assertThat(reach).containsExactly("environment/ci manager")
        assertThat(file.resources.single { it.key == "application/ci" }.grants).isNull()
        assertThat(file.resources.single { it.key == "application/cli" }.grants).isNull()
        // …and the sandbox grants NOBODY else anything (a second subject here would widen CI's blast radius).
        assertThat(file.environmentResource("ci")!!.grants!!.map { it.label }).containsExactly("client:$CI_CLIENT_ID manager")
    }

    /** The product-api scope AREA a resource kind is managed through (`tenant:<area>.<read|write>`). */
    private fun area(kind: String): String = when (kind) {
        ProvisionFile.KIND_ENVIRONMENT -> "environments"
        ProvisionFile.KIND_APPLICATION -> "applications"
        ProvisionFile.KIND_USER -> "users"
        ProvisionFile.KIND_FEDERATION_MEMBER -> "federation"
        ProvisionFile.KIND_EMAIL_PROVIDER -> "email"
        else -> "idp"
    }

    /**
     * The LEAST-PRIVILEGE scope set an identity needs to converge this very file: read + write on every
     * declared kind's area (the plan reads before the apply writes), plus `tenant:access.*` when any
     * resource carries a `grants:` block (read to diff the live grants, write to converge them).
     */
    private fun scopesToConverge(): Set<String> =
        file.resources.flatMap { listOf("tenant:${area(it.kind)}.read", "tenant:${area(it.kind)}.write") }.toSet() +
            if (file.resources.any { it.grants != null }) setOf(AccessCommand.SCOPE_READ, AccessCommand.SCOPE_WRITE) else emptySet()

    private fun locate(relative: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("could not locate $relative from ${System.getProperty("user.dir")}")
    }

    companion object {
        private const val PROVISION_PATH = ".thoryn/provision.yaml"
        private const val CONNECTION_PATH = ".thoryn/connection.json"

        /** SSO-3113 — the fixed id of the least-privilege CI machine identity this file declares. */
        private const val CI_CLIENT_ID = "cli-ci"
    }
}
