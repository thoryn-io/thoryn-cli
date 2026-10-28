package com.devnow.thoryn.provision

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-3962 (epic SSO-3960; oauthy ADR 2026-10-25 provisioning-is-tenant-and-applications) — a provisioning file belongs
 * to ONE part, declared by its `apiVersion`: `thoryn.io/tenant/v1` (what defines the tenant — the workspace's config
 * project) or `thoryn.io/application/v1` (how one client uses it — an app project). The engine refuses a kind from the
 * other part before any call, naming the file's part, the kind's part and the project the declaration belongs in. The
 * original `thoryn.io/provision/v1` keeps working for one release with a warning naming the part the file should declare
 * (or that it is two files), and `publishTo:` warns (ADR 2026-10-13 §2 superseded).
 */
class ProvisionFilePartTest {

    private val yaml = YAMLMapper()

    private fun doc(apiVersion: String, resources: String) =
        "apiVersion: $apiVersion\nresources:\n" + resources.trimIndent().prependIndent("  ")

    private fun violations(apiVersion: String, resources: String): List<String> = ProvisionFile.validate(yaml.readTree(doc(apiVersion, resources)))

    private fun parse(apiVersion: String, resources: String): ProvisionFile = ProvisionFile.parse(doc(apiVersion, resources).toByteArray(), "p.yaml")

    private val app = """
        - kind: application
          name: web
          spec: { displayName: Web, clientType: public, redirectUris: ["https://web.example/cb"] }
    """
    private val role = """
        - kind: role
          name: editor
          spec: { permissions: [docs:write] }
    """
    private val user = """
        - kind: user
          name: tester
          environment: dev
          spec: { email: tester@example.com }
    """

    @Test
    fun `the two parts partition the kind allowlist — every kind is in exactly one`() {
        assertThat(ProvisionFile.TENANT_KINDS intersect ProvisionFile.APPLICATION_KINDS).isEmpty()
        assertThat(ProvisionFile.TENANT_KINDS + ProvisionFile.APPLICATION_KINDS).isEqualTo(ProvisionFile.KINDS)
        assertThat(ProvisionFile.TENANT_KINDS).containsExactlyInAnyOrder(
            "environment", "federationMember", "user", "loginMethods", "loginFlow", "loginTheme", "emailProvider", "customDomain", "role", "workloadIdentityTrust", "emailTemplate",
        )
        assertThat(ProvisionFile.APPLICATION_KINDS).containsExactly("application")
        ProvisionFile.KINDS.forEach { kind -> assertThat(ProvisionPart.ofKind(kind)).withFailMessage("%s has no part", kind).isNotNull().isNotEqualTo(ProvisionPart.MIXED) }
        assertThat(ProvisionPart.of("thoryn.io/tenant/v1")).isEqualTo(ProvisionPart.TENANT)
        assertThat(ProvisionPart.of("thoryn.io/application/v1")).isEqualTo(ProvisionPart.APPLICATION)
        assertThat(ProvisionPart.of("thoryn.io/provision/v1")).isEqualTo(ProvisionPart.MIXED)
        assertThat(ProvisionPart.of("thoryn.io/other/v1")).isNull()
        assertThat(ProvisionFile.API_VERSIONS).containsExactly("thoryn.io/tenant/v1", "thoryn.io/application/v1", "thoryn.io/provision/v1")
    }

    @Test
    fun `an application file refuses a tenant kind, naming the kind's part, the file's part and the config project`() {
        val v = violations(ProvisionFile.API_VERSION_APPLICATION, app + role + user)
        assertThat(v).hasSize(2)
        assertThat(v[0]).isEqualTo(
            "resources[1] `role` is tenant provisioning; this is an application file (thoryn.io/application/v1). " +
                "Declare it in the workspace's config project (it defines the tenant, and an application is a user of the tenant).",
        )
        assertThat(v[1]).startsWith("resources[2] `user` is tenant provisioning; this is an application file (thoryn.io/application/v1). Declare it in the workspace's config project")
        assertThatThrownBy { parse(ProvisionFile.API_VERSION_APPLICATION, app + role) }
            .isInstanceOf(ProvisionException::class.java)
            .hasMessageContaining("`role` is tenant provisioning")
        // The control: the same application alone is a conformant application file.
        val file = parse(ProvisionFile.API_VERSION_APPLICATION, app)
        assertThat(file.part).isEqualTo(ProvisionPart.APPLICATION)
        assertThat(file.warnings).isEmpty()
    }

    @Test
    fun `a tenant file refuses an application, naming the kind's part, the file's part and the app project`() {
        val v = violations(ProvisionFile.API_VERSION_TENANT, role + app)
        assertThat(v).containsExactly(
            "resources[1] `application` is application provisioning; this is a tenant file (thoryn.io/tenant/v1). " +
                "Declare it in the application's own project (it is how one client uses the tenant, which the tenant's config project does not decide).",
        )
        val file = parse(ProvisionFile.API_VERSION_TENANT, role + user)
        assertThat(file.part).isEqualTo(ProvisionPart.TENANT)
        assertThat(file.warnings).isEmpty()
    }

    @Test
    fun `an apiVersion that is none of the three names them`() {
        val v = violations("thoryn.io/provisioning/v2", app)
        assertThat(v).anyMatch {
            it.contains("apiVersion must be 'thoryn.io/tenant/v1' (tenant provisioning: the workspace's config project) or 'thoryn.io/application/v1' (application provisioning: an app project)") &&
                it.contains("'thoryn.io/provision/v1' is accepted for one more release") && it.contains("(was 'thoryn.io/provisioning/v2')")
        }
    }

    @Test
    fun `a mixed file keeps working, with a warning that names the part it should declare`() {
        val tenantOnly = parse(ProvisionFile.API_VERSION, role + user)
        assertThat(tenantOnly.part).isEqualTo(ProvisionPart.MIXED)
        assertThat(tenantOnly.warnings).singleElement().asString()
            .contains("apiVersion thoryn.io/provision/v1 is deprecated (accepted for one more release")
            .contains("This file declares only tenant kinds — declare `apiVersion: thoryn.io/tenant/v1`.")
        val appOnly = parse(ProvisionFile.API_VERSION, app)
        assertThat(appOnly.warnings).singleElement().asString().contains("This file declares only application kinds — declare `apiVersion: thoryn.io/application/v1`.")
    }

    @Test
    fun `a mixed file declaring both parts is told which resources move where, and to split`() {
        val both = parse(ProvisionFile.API_VERSION, role + app + user)
        assertThat(both.warnings).singleElement().asString()
            .contains("This file declares BOTH: role/editor, user/tester are tenant provisioning (the config project) and application/web are application provisioning (the app project)")
            .contains("split it into two files (`thoryn provision split`)")
    }

    @Test
    fun `publishTo warns as deprecated, naming the resource, the creation slot and where the client goes — and still parses`() {
        val publishing = """
            - kind: application
              name: billing-web
              spec: { displayName: Billing, clientType: public, redirectUris: ["https://billing.example/cb"] }
              publishTo:
                - { kind: githubActionsVariable, repository: acme/billing-web, environment: production, name: THORYN_PRODUCTION_CLIENT_ID }
        """
        val file = parse(ProvisionFile.API_VERSION_APPLICATION, publishing)
        assertThat(file.publishing()).containsExactly("application/billing-web")
        assertThat(file.warnings).singleElement().asString()
            .startsWith("publishTo is deprecated (accepted for one more release")
            .contains("the application project owns its production client in every environment, created under a consent-approved creation slot")
            .contains("Declared on: application/billing-web")
            .contains("move the client to the app project's thoryn.io/application/v1 file and drop the block")
        // In a mixed file both warnings are carried, the format one first.
        val mixed = parse(ProvisionFile.API_VERSION, publishing)
        assertThat(mixed.warnings).hasSize(2)
        assertThat(mixed.warnings[0]).contains("apiVersion thoryn.io/provision/v1 is deprecated")
        assertThat(mixed.warnings[1]).startsWith("publishTo is deprecated")
    }

    private fun ProvisionFile.publishing() = resources.filter { it.publishTo.isNotEmpty() }.map { it.key }
}
