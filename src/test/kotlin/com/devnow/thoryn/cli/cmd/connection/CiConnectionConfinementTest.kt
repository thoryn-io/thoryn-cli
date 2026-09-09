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
 * **Dependency handling.** The granted set is defined by the `provision-ci-identity` bootstrap recipe
 * (SSO-2950), which is NOT on `main` yet. So [grantedMachineScopes] reads the recipe's granted scopes
 * from the bundled recipe resource **if present on the classpath**, and otherwise asserts against the
 * documented [EXPECTED_MACHINE_SCOPES] constant. The test therefore passes on THIS branch (recipe
 * absent) AND stays correct once SSO-2950 lands (recipe present ⇒ the real grant is used).
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
                "connection scopes %s exceed the provision-ci-identity granted set %s — the CI credential " +
                    "cannot request a scope its machine client was not granted (ADR scope-ceiling layer).",
                connection.scopes,
                granted,
            )
            .isTrue()
    }

    /**
     * The granted scope set the `provision-ci-identity` recipe (SSO-2950) mints the CI machine client
     * with. Read from the bundled recipe resource when present; otherwise fall back to the documented
     * constant so this test is correct both before and after SSO-2950 merges.
     */
    private fun grantedMachineScopes(): Set<String> {
        val stream = javaClass.getResourceAsStream(RECIPE_RESOURCE)
            // TODO(SSO-2951): tighten to read the recipe resource once SSO-2950 merges (drop the fallback).
            ?: return EXPECTED_MACHINE_SCOPES
        val root = JsonMapper.builder().build().readTree(stream.readBytes())
        val scopes = root["steps"]?.toList().orEmpty()
            .filter { it["action"]?.asString() == CREATE_MACHINE_ACTION }
            .flatMap { (it["with"]?.get("scopes"))?.toList().orEmpty() }
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

        /** Bundled resource of the SSO-2950 bootstrap recipe (absent on this branch — see the class doc). */
        private const val RECIPE_RESOURCE = "/examples/recipes/provision-ci-identity/recipe.json"

        /** The allowlisted secret-bearing action the bootstrap recipe uses (ADR §3). */
        private const val CREATE_MACHINE_ACTION = "clients.createMachine"

        /**
         * The machine scope set `provision-ci-identity` grants the CI client, per ADR
         * `2026-09-09-thoryn-cli-as-code-ci-connection-contract.md` §3. Used as the granted ceiling
         * until the recipe resource is on the classpath (SSO-2950).
         */
        private val EXPECTED_MACHINE_SCOPES = setOf(
            "tenant:applications.write",
            "tenant:applications.read",
            "tenant:federation.write",
            "tenant:federation.read",
            "tenant:users.write",
            "tenant:users.read",
            "tenant:env.write",
            "tenant:env.read",
        )
    }
}
