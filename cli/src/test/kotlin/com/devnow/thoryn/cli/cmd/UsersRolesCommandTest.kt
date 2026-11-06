package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.cmd.provision.FakeProductApi
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * SSO-3941 — `thoryn users roles list | add | remove` against the fake product-api's `/api/v1/users/{sub}/roles` and
 * `/api/v1/roles`: a role is addressed by NAME (resolved to its id in the selected environment), `add` is re-runnable,
 * `remove` is idempotent, and an unknown role fails before any write, naming the roles that exist.
 */
class UsersRolesCommandTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val sub = "3852512e49b33fbe"

    @BeforeEach
    fun mount() { server.dispatcher = api }

    @Test
    fun `add resolves the role by name in the selected environment and assigns it by id`() {
        api.seedEnvironment("staging")
        api.seedRole(null, "forge-maintainer") // same name on the production plane — must not be picked
        val id = api.seedRole("staging", "forge-maintainer")

        val (exit, out, err) = runCli("users", "roles", "add", sub, "forge-maintainer", "--environment", "staging", "--gateway", baseUrl())

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(out).contains("Gave $sub the role forge-maintainer ($id)")
        val write = api.writes.single()
        assertThat("${write.method} ${write.path} ${write.env}").isEqualTo("POST /api/v1/users/$sub/roles staging")
        assertThat(write.body).isEqualTo(mapOf("roleId" to id))
        assertThat(api.userRoles).containsExactly(mutableMapOf<String, Any?>("userId" to sub, "roleId" to id))
    }

    @Test
    fun `add of a role the user already holds succeeds unchanged, and add by id works too`() {
        val id = api.seedRole(null, "forge-maintainer")
        assertThat(runCli("users", "roles", "add", sub, id, "--gateway", baseUrl()).exit).isEqualTo(0)

        val (exit, out, _) = runCli("users", "roles", "add", sub, "forge-maintainer", "--output", "json", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(0)
        assertThat(parseJson(out)).containsEntry("status", "unchanged").containsEntry("roleId", id)
        assertThat(api.userRoles).hasSize(1)
    }

    @Test
    fun `list shows the roles the user holds with their names`() {
        val id = api.seedRole(null, "forge-maintainer")
        api.seedRole(null, "unrelated")
        api.userRoles += mutableMapOf("userId" to sub, "roleId" to id)

        val (exit, out, _) = runCli("users", "roles", "list", sub, "--gateway", baseUrl())
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("forge-maintainer").contains(id).doesNotContain("unrelated")

        val json = runCli("users", "roles", "list", sub, "--output", "json", "--gateway", baseUrl())
        @Suppress("UNCHECKED_CAST")
        val roles = parseJson(json.out)["roles"] as List<Map<String, Any?>>
        assertThat(roles.map { it["role"] }).containsExactly("forge-maintainer")
    }

    @Test
    fun `remove takes the role away by name, and removing it again is still a success`() {
        val id = api.seedRole(null, "forge-maintainer")
        api.userRoles += mutableMapOf("userId" to sub, "roleId" to id)

        val (exit, out, _) = runCli("users", "roles", "remove", sub, "forge-maintainer", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(0)
        assertThat(out).contains("Removed the role forge-maintainer ($id) from $sub")
        assertThat(api.writes.single().let { "${it.method} ${it.path}" }).isEqualTo("DELETE /api/v1/users/$sub/roles/$id")
        assertThat(api.userRoles).isEmpty()

        assertThat(runCli("users", "roles", "remove", sub, "forge-maintainer", "--gateway", baseUrl()).exit).isEqualTo(0)
    }

    // ── SSO-4284 — address the user by email: the assignment goes to the subject their tokens carry ──

    @Test
    fun `add with --email assigns the role to the users subject, not their directory id`() {
        val id = api.seedRole(null, "pip-portal-reader")
        api.users += mutableMapOf("id" to "d236c669-8428-4a9a-a587-b7173d4be171", "subject" to sub, "email" to "mark@thoryn.io", "_env" to null)

        val (exit, out, err) = runCli("users", "roles", "add", "--email", "mark@thoryn.io", "pip-portal-reader", "--gateway", baseUrl())

        assertThat(exit).withFailMessage("%s", err).isEqualTo(0)
        assertThat(out).contains("Gave mark@thoryn.io (subject $sub) the role pip-portal-reader ($id)")
        assertThat(api.writes.single().let { "${it.method} ${it.path}" }).isEqualTo("POST /api/v1/users/$sub/roles")
    }

    @Test
    fun `add with --email for a user who has not signed in sends the directory id for product-api to resolve or refuse`() {
        api.seedRole(null, "pip-portal-reader")
        api.users += mutableMapOf("id" to "d236c669-8428-4a9a-a587-b7173d4be171", "email" to "new@thoryn.io", "_env" to null)

        runCli("users", "roles", "add", "--email", "new@thoryn.io", "pip-portal-reader", "--gateway", baseUrl())

        assertThat(api.writes.single().path).isEqualTo("/api/v1/users/d236c669-8428-4a9a-a587-b7173d4be171/roles")
    }

    @Test
    fun `list and remove accept --email too`() {
        val id = api.seedRole(null, "pip-portal-reader")
        api.users += mutableMapOf("id" to "d236c669-8428-4a9a-a587-b7173d4be171", "subject" to sub, "email" to "mark@thoryn.io", "_env" to null)
        api.userRoles += mutableMapOf("userId" to sub, "roleId" to id)

        val (listExit, listOut, _) = runCli("users", "roles", "list", "--email", "mark@thoryn.io", "--gateway", baseUrl())
        assertThat(listExit).isEqualTo(0)
        assertThat(listOut).contains("pip-portal-reader")

        val (exit, _, _) = runCli("users", "roles", "remove", "--email", "mark@thoryn.io", "pip-portal-reader", "--gateway", baseUrl())
        assertThat(exit).isEqualTo(0)
        assertThat(api.userRoles).isEmpty()
    }

    @Test
    fun `a user and --email together, or a missing role with --email, is a usage error before any call`() {
        api.seedRole(null, "pip-portal-reader")

        val both = runCli("users", "roles", "add", sub, "pip-portal-reader", "--email", "mark@thoryn.io", "--gateway", baseUrl())
        assertThat(both.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(both.err).contains("with --email, give only the role")

        val neither = runCli("users", "roles", "add", "pip-portal-reader", "--gateway", baseUrl())
        assertThat(neither.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(neither.err).contains("<user> <role>")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an unknown role fails before any write, naming the roles that do exist`() {
        api.seedRole(null, "forge-maintainer")

        val (exit, _, err) = runCli("users", "roles", "add", sub, "forge-maintainr", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("no role 'forge-maintainr' in the selected environment").contains("Roles there: forge-maintainer")
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a token without roles write is told which scope to sign in with`() {
        api.seedRole(null, "forge-maintainer")
        api.enforceScopeGates = true
        api.callerScopes = setOf("tenant:roles.read")

        val (exit, out, err) = runCli("users", "roles", "add", sub, "forge-maintainer", "--gateway", baseUrl())

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(out + err).contains("tenant:roles.write")
        assertThat(api.userRoles).isEmpty()
    }
}
