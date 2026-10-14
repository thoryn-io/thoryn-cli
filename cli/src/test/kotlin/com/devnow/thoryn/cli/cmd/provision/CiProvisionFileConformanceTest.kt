package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.CONNECTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.WORKLOAD_CLIENT_ID_PREFIX
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.scopesToConverge
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-3090 (epic SSO-3087) — repo-level test binding THIS repo's committed provisioning file
 * (`.thoryn/provision.yaml`, the "what I own" half of `.thoryn/`) to the CLI that ships it:
 * the file must load through [ProvisionFile] (schema-conformant), declare exactly the CI fixtures the
 * provisioning Action expects (a sandbox + a loopback client INSIDE it; the only production-plane
 * resource is the CLI's own login client), carry no secret, and stay within the scope set the sibling
 * `connection.json` requests — so a change to either file that would break the CI run fails here first.
 *
 * SSO-3113 (epic SSO-3108) added the least-privilege half; SSO-3690 (parent SSO-3659) moved the identity
 * itself OUT of the file: CI signs in as a GitHub Actions workload identity trust (no secret anywhere), so
 * the file declares NO confidential client and NO `client_credentials` grant any more — the credential
 * ladder's rung 4 ("courier: never", oauthy ADR 2026-10-14) is retired here. The trust is only REFERENCED:
 * its `wi_…` client is the ONE grant subject of the file, `manager` on the `ci` sandbox, and it must be the
 * very client `connection.json` signs in with. The file cannot silently widen that without failing here.
 */
class CiProvisionFileConformanceTest {

    private val file: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))
    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))

    @Test
    fun `the committed provisioning file declares the CLI login client on the production plane plus the CI sandbox and its loopback client`() {
        assertThat(file.resources.map { it.key })
            .containsExactly("application/cli", "environment/ci", "application/loopback-rp")
        val env = file.environmentResource("ci")!!
        assertThat(env.spec["slug"]).isEqualTo("cli-ci")
        val rp = file.resources.single { it.key == "application/loopback-rp" }
        assertThat(rp.environment).isEqualTo("ci") // lives INSIDE the sandbox → destroy needs no production confirmation
        assertThat(rp.spec["clientType"]).isEqualTo("public")
        assertThat(rp.spec["redirectUris"]).isEqualTo(listOf("http://127.0.0.1/callback"))
        // SSO-3104 / SSO-3690 — the production plane holds exactly ONE resource: the CLI's own login client
        // (adopted, never deleted, by every apply whose receipt does not own it). The CI identity that signs
        // those applies in is a workload identity trust — a product resource a founder creates once, not a
        // declared application.
        val production = file.resources.filter { it.kind != ProvisionFile.KIND_ENVIRONMENT && it.environment == null }
        assertThat(production.map { it.key }).containsExactly("application/cli")
        val cli = production.single()
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

    /**
     * Every `tenant:<area>.<read|write>` literal under the CLI's AND the engine's src/main (sources +
     * bundled resources; SSO-3662 made the repository a two-module reactor, so both roots are the CLI's
     * "own sources"), plus the action-verb scopes `tenant:keys.rotate` (SSO-3369) and `tenant:keys.retire`
     * (SSO-3396).
     */
    private fun requestableTenantScopes(): Set<String> {
        val repo = locate(PROVISION_PATH).parentFile.parentFile
        val roots = listOf("cli/src/main", "engine/src/main").map { File(repo, it) }
        check(roots.all { it.isDirectory }) { "expected the cli/ and engine/ module source roots under $repo" }
        val files = roots.asSequence().flatMap { it.walkTopDown() }
            .filter { it.isFile && (it.extension == "kt" || it.extension == "json" || it.extension == "yaml") }
        val pattern = Regex("tenant:[a-z-]+\\.(read|write|rotate|retire)")
        return files.flatMap { f -> pattern.findAll(f.readText()).map { it.value } }.toSet()
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
        val needed = file.resources.map { "tenant:${CiIdentityFixture.area(it.kind)}.write" }.toSet()
        assertThat(Connection.scopesWithinGrant(needed, connection.scopes.toSet()))
            .withFailMessage("provision.yaml needs %s but connection.json requests only %s", needed, connection.scopes)
            .isTrue()
    }

    /**
     * SSO-3690 — the ladder's rung 4 is retired in the repository that ships the ladder's tooling: the file
     * declares no identity whose credential would have to be carried anywhere. Every application is PUBLIC
     * (secret-less by construction) and none may obtain a token without a human (`client_credentials`).
     * Re-declaring a confidential CI client here is how the courier pattern would come back.
     */
    @Test
    fun `the provisioning file declares no secret-bearing identity — no confidential client, no client_credentials grant`() {
        val applications = file.resources.filter { it.kind == ProvisionFile.KIND_APPLICATION }
        assertThat(applications).isNotEmpty()
        applications.forEach { app ->
            assertThat(app.spec["clientType"])
                .withFailMessage("%s is not public — a confidential client needs a secret, and a secret needs a courier (SSO-3690)", app.key)
                .isEqualTo("public")
            @Suppress("UNCHECKED_CAST")
            val grantTypes = (app.spec["grantTypes"] as? List<Any?>).orEmpty().map { it.toString() }
            assertThat(grantTypes)
                .withFailMessage("%s grants client_credentials — a machine identity declared here would be a secret-bearing one (SSO-3690)", app.key)
                .doesNotContain("client_credentials")
        }
        // The retired identity by name: nothing in the file declares or targets `cli-ci` as a client any more.
        assertThat(applications.map { it.spec["clientId"]?.toString() }).doesNotContain(RETIRED_CI_CLIENT_ID)
    }

    /**
     * SSO-3113 / SSO-3690 — the CI identity's whole declared reach is `manager` on the sandbox, nothing
     * workspace-wide; and the identity IS the trust's client: the grant subject must be the very `wi_…` client
     * `connection.json` signs in with (both are pasted from one `trusts create`), never the retired `cli-ci`.
     */
    @Test
    fun `the CI identity's whole declared reach is manager on the sandbox — nothing workspace-wide`() {
        val subject = "client:${connection.clientId}"
        assertThat(connection.clientId).startsWith(WORKLOAD_CLIENT_ID_PREFIX)
        val reach = file.resources.flatMap { r ->
            (r.grants ?: emptyList()).filter { it.subject == subject }.map { "${r.key} ${it.relation}" }
        }
        // ONE grant, on the sandbox. Containment covers the loopback client inside it — nothing wider may appear.
        assertThat(reach).containsExactly("environment/ci manager")
        assertThat(file.resources.single { it.key == "application/cli" }.grants).isNull()
        assertThat(file.resources.single { it.key == "application/loopback-rp" }.grants).isNull()
        // …and the sandbox grants NOBODY else anything (a second subject here would widen CI's blast radius) —
        // in particular not the retired `client:cli-ci`.
        assertThat(file.environmentResource("ci")!!.grants!!.map { it.label }).containsExactly("$subject manager")
        assertThat(file.resources.flatMap { it.grants.orEmpty() }.map { it.subject }).doesNotContain("client:$RETIRED_CI_CLIENT_ID")
    }

    /**
     * SSO-3690 — with the trust declared in no committed file, `connection.json` is the one committed statement of
     * what the identity holds, and `scopesToConverge` is what converging THIS file needs: they must be EQUAL. Not a
     * subset — the trust is created from this exact list (`.thoryn/README.md`), so a scope here that the file does
     * not need is reach CI must not have, and a needed scope missing here is a failing apply.
     */
    @Test
    fun `the connection scopes are exactly the least-privilege set converging this file needs`() {
        val needed = scopesToConverge(file)
        assertThat(connection.scopes.toSet())
            .withFailMessage("connection.json requests %s but converging provision.yaml needs exactly %s", connection.scopes, needed)
            .isEqualTo(needed)
    }

    companion object {
        /** SSO-3113 → SSO-3690 — the fixed id of the retired secret-bearing CI machine client (removed once by the founder). */
        private const val RETIRED_CI_CLIENT_ID = "cli-ci"
    }
}
