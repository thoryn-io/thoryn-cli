package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.config.ThorynConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3090 (epic SSO-3087) — repo-level test binding THIS repo's committed provisioning file
 * (`.thoryn/provision.yaml`, the "what I own" half of `.thoryn/`) to the CLI that ships it:
 * the file must load through [ProvisionFile] (schema-conformant), declare exactly the CI fixtures the
 * provisioning Action expects (a sandbox + a loopback client INSIDE it, nothing on the production
 * plane), carry no secret, and stay within the scope set the sibling `connection.json` requests — so a
 * change to either file that would break the CI run fails here first.
 */
class CiProvisionFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    @Test
    fun `the committed provisioning file declares the CLI login client on the production plane plus the CI sandbox and its loopback client`() {
        assertThat(file.resources.map { it.key }).containsExactly("application/cli", "environment/ci", "application/loopback-rp")
        val env = file.environmentResource("ci")!!
        assertThat(env.spec["slug"]).isEqualTo("cli-ci")
        val rp = file.resources.single { it.key == "application/loopback-rp" }
        assertThat(rp.environment).isEqualTo("ci") // lives INSIDE the sandbox → destroy needs no production confirmation
        assertThat(rp.spec["clientType"]).isEqualTo("public")
        assertThat(rp.spec["redirectUris"]).isEqualTo(listOf("http://127.0.0.1/callback"))
        // SSO-3104 — the ONLY production-plane resource is the CLI's own login client, adopted (never
        // deleted) by every apply whose receipt does not own it, and pinned to the id the CLI signs in with.
        val production = file.resources.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT && it.environment == null }
        assertThat(production.map { it.key }).containsExactly("application/cli")
        val cli = production.single()
        assertThat(cli.spec["clientId"]).isEqualTo(ThorynConfig.DEFAULT_CLIENT_ID)
        assertThat(cli.spec["clientType"]).isEqualTo("public")
        assertThat(cli.spec["grantTypes"]).isEqualTo(listOf("authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"))
        assertThat(cli.spec["redirectUris"]).isEqualTo(listOf("http://127.0.0.1/callback", "http://[::1]/callback"))
        assertThat(cli.spec["requireAuthorizationConsent"]).isEqualTo(false)
        // Everything a bare `thoryn login` requests is grantable by the client (else: invalid_scope loop).
        val granted = (cli.spec["scopes"] as List<*>).map { it.toString() }.toSet()
        assertThat(granted).containsAll(ThorynConfig.DEFAULT_SCOPE.split(" "))
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
        val needed = file.resources.map { it.kind }.toSet().map { kind ->
            when (kind) {
                ProvisionFile.KIND_ENVIRONMENT -> "tenant:environments.write"
                ProvisionFile.KIND_APPLICATION -> "tenant:applications.write"
                ProvisionFile.KIND_USER -> "tenant:users.write"
                ProvisionFile.KIND_FEDERATION_MEMBER -> "tenant:federation.write"
                ProvisionFile.KIND_EMAIL_PROVIDER -> "tenant:email.write"
                else -> "tenant:idp.write"
            }
        }.toSet()
        assertThat(Connection.scopesWithinGrant(needed, connection.scopes.toSet()))
            .withFailMessage("provision.yaml needs %s but connection.json requests only %s", needed, connection.scopes)
            .isTrue()
    }

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
    }
}
