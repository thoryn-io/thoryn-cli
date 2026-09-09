package com.devnow.thoryn.cli.cmd.connection

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
 * **Source of the granted set.** The granted scope set is defined by the declarative `ci-identity`
 * provisioning spec (SSO-2952, `/provision/ci-identity.json`) that `thoryn provision ci-identity` mints
 * the CI machine client from. [grantedMachineScopes] reads that spec's `machineClient.scopes` from the
 * bundled resource, falling back to the documented [EXPECTED_MACHINE_SCOPES] constant only if the
 * resource is somehow absent — so the connection contract is asserted against the real grant the CLI
 * ships with. (SSO-2952 also corrected the scope names `tenant:env.*` → `tenant:environments.*`, the
 * authoritative catalog names.)
 */
class CiConnectionConfinementTest {

    private val connection: Connection = Connection.load(locateConnectionFile())

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
                "connection scopes %s exceed the ci-identity machine-client granted set %s — the CI credential " +
                    "cannot request a scope its machine client was not granted (ADR scope-ceiling layer).",
                connection.scopes,
                granted,
            )
            .isTrue()
    }

    /**
     * The granted scope set `thoryn provision ci-identity` (SSO-2952) mints the CI machine client with.
     * Read from the bundled `/provision/ci-identity.json` spec's `machineClient.scopes`; fall back to
     * the documented constant only if the resource is somehow absent on the classpath.
     */
    private fun grantedMachineScopes(): Set<String> {
        val stream = javaClass.getResourceAsStream(SPEC_RESOURCE)
            ?: return EXPECTED_MACHINE_SCOPES
        val root = JsonMapper.builder().build().readTree(stream.readBytes())
        val scopes = (root["machineClient"]?.get("scopes"))?.toList().orEmpty()
            .map { it.asString() }
            .toSet()
        return scopes.ifEmpty { EXPECTED_MACHINE_SCOPES }
    }

    private fun locateConnectionFile(): File {
        // Resolve `.thoryn/connection.json` by walking up from the forked test JVM's working directory
        // (surefire runs from the module basedir, but be robust to a different cwd).
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, CONNECTION_PATH)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("could not locate $CONNECTION_PATH from ${System.getProperty("user.dir")}")
    }

    companion object {
        private const val CONNECTION_PATH = ".thoryn/connection.json"

        /** Bundled resource of the SSO-2952 declarative ci-identity machine-client spec. */
        private const val SPEC_RESOURCE = "/provision/ci-identity.json"

        /**
         * The machine scope set `thoryn provision ci-identity` grants the CI client, per ADR
         * `2026-09-09-thoryn-cli-as-code-ci-connection-contract.md` §3 (with SSO-2952's `env.*` →
         * `environments.*` correction to the authoritative catalog names). Used as the granted ceiling
         * only if the spec resource is somehow absent from the classpath.
         */
        private val EXPECTED_MACHINE_SCOPES = setOf(
            "tenant:applications.write",
            "tenant:applications.read",
            "tenant:federation.write",
            "tenant:federation.read",
            "tenant:users.write",
            "tenant:users.read",
            "tenant:environments.write",
            "tenant:environments.read",
        )
    }
}
