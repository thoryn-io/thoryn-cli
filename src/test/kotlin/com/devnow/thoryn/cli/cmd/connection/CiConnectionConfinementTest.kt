package com.devnow.thoryn.cli.cmd.connection

import com.devnow.thoryn.cli.cmd.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.io.File

/**
 * SSO-2951 (epic SSO-2947) — repo-level **confinement** test binding THIS repo's committed connection
 * contract (`.thoryn/connection.json`) to the ADR's "scope ceiling" layer
 * (`2026-09-09-thoryn-cli-as-code-ci-connection-contract.md`): the CI credential can request only
 * scopes its machine client was actually granted, so `connection.scopes ⊆ the granted set`.
 *
 * **Source of the granted set (SSO-3113).** It is the `scopes` of the application the committed
 * `.thoryn/provision.yaml` declares under the very `clientId` the connection contract signs in with —
 * `cli-ci`. So the ceiling is read from the identity CI actually uses, and one file cannot drift from
 * the other. Until the S5 cut-over this compared against `/provision/ci-identity.json`, the bundled
 * spec of the retired `thoryn provision ci-identity` bootstrap (SSO-2952) — a DIFFERENT client from the
 * one `connection.json` named, so the two could disagree without failing anything.
 */
class CiConnectionConfinementTest {

    private val connection: Connection = Connection.load(locate(CONNECTION_PATH))
    private val provisionFile: ProvisionFile = ProvisionFile.load(locate(PROVISION_PATH))

    @Test
    fun `the committed connection loads and validates against the schema`() {
        // Connection.load throws ConnectionException on any schema violation, so a clean load is itself
        // the validation. Assert the load-bearing bindings the CI Action + bootstrap README depend on.
        assertThat(connection.slug).isEqualTo("thoryn")
        assertThat(connection.hubBaseUrlEnv).isEqualTo("THORYN_HUB")
        assertThat(connection.secretEnv).isEqualTo("THORYN_CLI_CI_CLIENT_SECRET")
        assertThat(connection.scopes).isNotEmpty()
    }

    @Test
    fun `the connection scopes are within the machine client's granted set`() {
        val granted = grantedMachineScopes()
        assertThat(Connection.scopesWithinGrant(connection.scopes.toSet(), granted))
            .withFailMessage(
                "connection scopes %s exceed the scopes .thoryn/provision.yaml declares for client '%s' %s — the CI " +
                    "credential cannot request a scope its machine client was not granted (ADR scope-ceiling layer).",
                connection.scopes,
                connection.clientId,
                connection.scopes,
                granted,
            )
            .isTrue()
    }

    /**
     * The scopes the committed provisioning file declares for the application whose `clientId` the
     * connection contract signs in with. Absent such a declaration the test FAILS rather than falling
     * back to a constant: a connection naming a client this repo does not provision is exactly the drift
     * this test exists to catch.
     */
    private fun grantedMachineScopes(): Set<String> {
        val declared = provisionFile.resources.firstOrNull { r ->
            r.kind == ProvisionFile.KIND_APPLICATION && r.spec["clientId"]?.toString() == connection.clientId
        } ?: error(
            "no application with clientId '${connection.clientId}' in $PROVISION_PATH — the connection contract " +
                "signs in as a client this repository does not declare.",
        )
        @Suppress("UNCHECKED_CAST")
        val scopes = (declared.spec["scopes"] as? List<Any?>).orEmpty().map { it.toString() }.toSet()
        check(scopes.isNotEmpty()) { "application '${connection.clientId}' declares no scopes in $PROVISION_PATH" }
        return scopes
    }

    private fun locate(relative: String): File {
        // Walk up from the forked test JVM's working directory (surefire runs from the module basedir,
        // but be robust to a different cwd).
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("could not locate $relative from ${System.getProperty("user.dir")}")
    }

    companion object {
        private const val CONNECTION_PATH = ".thoryn/connection.json"
        private const val PROVISION_PATH = ".thoryn/provision.yaml"
    }
}
