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
 * SSO-3941 — `kind: role` converges an RBAC role of its environment through `/api/v1/roles`: by NAME, its permissions as a
 * SET of names (a permission the workspace lacks is created, workspace-wide), an omitted description kept. A second apply
 * writes nothing. A role is not a platform access object, so the plan asks no ownership check for it; like a `user` it is
 * never removed on the production plane by destroy.
 */
class ProvisionRoleTest : CommandTestBase() {

    private val api = FakeProductApi()
    private val console = ByteArrayOutputStream()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    private fun engine() = ProvisionEngine(
        clients = { slug -> ProductApiClient(gateway = baseUrl(), tokens = Tokens(accessToken = "AT-test"), environmentSlug = slug) },
        out = PrintStream(console), err = PrintStream(console),
        workspaceId = api.tenantId,
    )

    private fun file(resources: String) =
        ProvisionFile.parse(("apiVersion: thoryn.io/provision/v1\nresources:\n" + resources.trimIndent().prependIndent("  ")).toByteArray(), "provision.yaml")

    private fun apply(f: ProvisionFile): ApplyResult {
        val e = engine()
        return e.apply(f, e.plan(f, false), "acme", null)
    }

    private val maintainer = """
        - kind: role
          name: forge-maintainer
          environment: staging
          spec:
            description: "Maintains the forge"
            permissions: ["forge:maintain", "forge:read"]
    """

    @Test
    fun `a role is created with its permissions, creating only the missing workspace permission, and a second apply writes nothing`() {
        api.seedEnvironment("staging")
        val existing = api.permissionId("forge:read")
        val f = file(maintainer)

        val planned = engine().plan(f, false).changes.single()
        assertThat(planned.action).isEqualTo(ChangeAction.CREATE)
        apply(f)

        assertThat(api.writes.map { "${it.method} ${it.path} ${it.env}" }).containsExactly(
            "POST /api/v1/roles staging",
            "POST /api/v1/permissions staging",
            "PUT /api/v1/roles/${api.roles.single()["id"]}/permissions staging",
        )
        assertThat(api.writesTo("/api/v1/roles").first().body).isEqualTo(mapOf("name" to "forge-maintainer", "description" to "Maintains the forge"))
        assertThat(api.writesTo("/api/v1/permissions").single().body).isEqualTo(mapOf("name" to "forge:maintain"))
        val role = api.roles.single()
        assertThat(role["_env"]).isEqualTo("staging")
        assertThat(api.rolePermissionNames(role["id"].toString())).containsExactly("forge:maintain", "forge:read")
        assertThat(api.permissions.single { it["name"] == "forge:read" }["id"]).isEqualTo(existing)
        // Not a platform object: no ownership check was asked for it.
        assertThat(api.checks).isEmpty()

        api.reset()
        val again = engine().plan(f, false).changes.single()
        assertThat(again.action).isEqualTo(ChangeAction.NOOP)
        assertThat(again.liveId).isEqualTo(role["id"])
        apply(f)
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `drift in the permission set and description is converged with exactly what differs, and an omitted description is kept`() {
        api.seedEnvironment("staging")
        val id = api.seedRole("staging", "forge-maintainer", listOf("forge:read", "forge:admin"), description = "old")
        val f = file(maintainer)

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.UPDATE)
        assertThat(change.diff.keys).containsExactly("description", "permissions")
        assertThat(change.diff["permissions"]).isEqualTo("[forge:read,forge:admin] → [forge:maintain,forge:read]")
        apply(f)
        assertThat(api.writes.map { "${it.method} ${it.path}" }).containsExactly(
            "PATCH /api/v1/roles/$id",
            "POST /api/v1/permissions",
            "PUT /api/v1/roles/$id/permissions",
        )
        assertThat(api.rolePermissionNames(id)).containsExactlyInAnyOrder("forge:maintain", "forge:read")

        // Order is not drift; an omitted description keeps the live one.
        api.reset()
        val noDescription = file(
            """
            - kind: role
              name: forge-maintainer
              environment: staging
              spec: { permissions: ["forge:read", "forge:maintain"] }
            """,
        )
        assertThat(engine().plan(noDescription, false).changes.single().action).isEqualTo(ChangeAction.NOOP)

        // `[]` is declared, and takes every permission away.
        val none = file("- { kind: role, name: forge-maintainer, environment: staging, spec: { permissions: [] } }")
        val emptied = engine().plan(none, false).changes.single()
        assertThat(emptied.diff.keys).containsExactly("permissions")
        apply(none)
        assertThat(api.writes.single().body).isEqualTo(mapOf("permissionIds" to emptyList<String>()))
        assertThat(api.rolePermissionNames(id)).isEmpty()
    }

    @Test
    fun `the role is found by name across pages of the role list, and its permissions across pages too`() {
        api.rbacPageSize = 1
        api.seedRole(null, "other")
        api.seedRole(null, "another")
        val id = api.seedRole(null, "forge-maintainer", listOf("forge:maintain", "forge:read"))
        val f = file("- { kind: role, name: forge-maintainer, spec: { permissions: [\"forge:read\", \"forge:maintain\"] } }")

        val change = engine().plan(f, false).changes.single()
        assertThat(change.action).isEqualTo(ChangeAction.NOOP)
        assertThat(change.liveId).isEqualTo(id)
    }

    @Test
    fun `a read-only role must exist and match — never created, never written`() {
        val ref = "- { kind: role, name: shared, readOnly: true, spec: { permissions: [\"a:b\"] } }"
        val missing = engine().plan(file(ref), false).changes.single()
        assertThat(missing.action).isEqualTo(ChangeAction.ERROR)
        assertThat(missing.error).isEqualTo(ProvisionEngine.ERROR_READ_ONLY)

        api.seedRole(null, "shared", listOf("a:c"))
        val differs = engine().plan(file(ref), false).changes.single()
        assertThat(differs.action).isEqualTo(ChangeAction.ERROR)
        assertThat(differs.reason).contains("permissions")

        api.roles.single()["permissions"] = mutableListOf(api.permissionId("a:b"))
        val matches = engine().plan(file(ref), false).changes.single()
        assertThat(matches.action).isEqualTo(ChangeAction.NOOP)
        assertThat(matches.readOnly).isTrue()
        apply(file(ref))
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `destroy never removes a production-plane role, naming the call a person makes`() {
        val id = api.seedRole(null, "forge-maintainer", listOf("forge:maintain"))
        val f = file("- { kind: role, name: forge-maintainer, spec: { permissions: [\"forge:maintain\"] } }")

        val row = engine().planDestroy(f).changes.single()
        assertThat(row.action).isEqualTo(ChangeAction.SKIP)
        assertThat(row.reason).contains("PRODUCTION plane is never removed")
        assertThat(row.byHand).contains("DELETE /api/v1/roles/$id")
        engine().destroy(engine().planDestroy(f), "acme")
        assertThat(api.roles).hasSize(1)
    }

    @Test
    fun `the file refuses a reserved permission namespace, grants, unknown members and a missing permission list — and accepts forge-maintain`() {
        fun violations(spec: String, extra: String = "") = ProvisionFile.validate(
            tools.jackson.dataformat.yaml.YAMLMapper().readTree("apiVersion: thoryn.io/provision/v1\nresources:\n  - { kind: role, name: r, spec: $spec$extra }"),
        )
        assertThat(violations("{ permissions: [\"forge:maintain\", \"invoices:read\"] }")).isEmpty()
        assertThat(violations("{ permissions: [] }")).isEmpty()
        assertThat(violations("{ permissions: [\"tenant:roles.write\"] }")).anyMatch { it.contains("permission_name_reserved") }
        assertThat(violations("{ permissions: [\"Admin:all\"] }")).anyMatch { it.contains("permission_name_reserved") }
        assertThat(violations("{ permissions: [\"\"] }")).anyMatch { it.contains("non-empty permission name") }
        assertThat(violations("{ permissions: [\"a:b\", \"a:b\"] }")).anyMatch { it.contains("lists 'a:b' twice") }
        assertThat(violations("{ description: x }")).anyMatch { it.contains("spec.permissions is required") }
        assertThat(violations("{ permissions: [], scopes: [] }")).anyMatch { it.contains("unknown property 'scopes'") }
        assertThat(violations("{ permissions: [] }", ", grants: [ { subject: \"member:a\", relation: viewer } ]")).anyMatch { it.contains("cannot carry 'grants'") }
    }
}
