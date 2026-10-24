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
