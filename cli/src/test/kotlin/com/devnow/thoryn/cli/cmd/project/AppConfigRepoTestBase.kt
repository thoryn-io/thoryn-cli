package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.provision.ProvisionFile
import org.junit.jupiter.api.BeforeEach
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-4079 — `thoryn project init app --config-repo`: a workspace with sandbox `dev`, the config repository `acme/platform` as
 * `thoryn project init config` leaves it (its `.thoryn/workflow.yaml`, a production section and a `dev` section, each with the
 * `connection.json` of the config repository's own trust on that plane) and those two trusts live in the workspace.
 */
abstract class AppConfigRepoTestBase : ProjectTestBase() {

    protected val json: JsonMapper = JsonMapper.builder().build()
    protected val productionFile: String = ProjectSeeds.CONFIG_PRODUCTION_PROVISION_FILE
    protected val sandboxFile: String = ".thoryn/environments/sandbox/provision.yaml"
    protected val url: String = "https://web.acme.example"
    protected val app: Array<String> = arrayOf("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")
    protected val withConfig: Array<String> = app + arrayOf("--config-repo", "acme/platform")

    /** The config repository's production section as `thoryn project init config` seeds it: a comment header and the sandbox environment. */
    protected val productionSection: String = """
        |# Seeded by `thoryn project init config` (SSO-3435) for acme/platform — the PRODUCTION section.
        |apiVersion: thoryn.io/tenant/v1
        |resources:
        |  # The workspace's sandbox, adopted by its slug.
        |  - kind: environment
        |    name: dev
        |    spec:
        |      slug: dev
        |      displayName: "Sandbox dev"
        |
    """.trimMargin()

    /** Its sandbox section: anchored on the sandbox it configures, under a name that is not the slug. */
    protected val sandboxSection: String = """
        |# Seeded by `thoryn project init config` (SSO-3435) for acme/platform — the SANDBOX section.
        |apiVersion: thoryn.io/tenant/v1
        |resources:
        |  - kind: environment
        |    name: dev-sandbox
        |    readOnly: true
        |    spec:
        |      slug: dev
        |
    """.trimMargin()

    protected var configRepoId: Long = 0

    @BeforeEach
    fun seedConfigRepository() {
        api.seedSandbox("dev")
        val repo = gh.seedRepo("acme/platform")
        configRepoId = gh.repoId("acme/platform")
        val pins = mapOf("owner" to "acme", "ownerId" to 900L, "repository" to "platform", "repositoryId" to configRepoId)
        api.trusts += configTrust("cfg-prod", "production", "wi_config_prod", pins + mapOf("environment" to "thoryn-production", "ref" to "refs/heads/main"))
        api.trusts += configTrust("cfg-dev", "dev", "wi_config_dev", pins)
        val ghRepo = GhRepository(configRepoId, 900L, "acme", "platform", "main", repo["html_url"] as String, true)
        gh.files["acme/platform"] = mutableMapOf(
            productionFile to productionSection,
            sandboxFile to sandboxSection,
            ".thoryn/environments/production/connection.json" to connectionOf(api.trusts.first { it["id"] == "cfg-prod" }, "production", true),
            ".thoryn/environments/sandbox/connection.json" to connectionOf(api.trusts.first { it["id"] == "cfg-dev" }, "dev", false),
            ProjectSeeds.WORKFLOW_CONFIG_PATH to ProjectSeeds.configWorkflowYaml(
                ghRepo,
                listOf(productionFile to ".thoryn/environments/production/connection.json", sandboxFile to ".thoryn/environments/sandbox/connection.json"),
            ),
        )
    }

    /** Publish the template's `.thoryn/production/declaration.json` (thoryn-starters SSO-4120); [edit] changes it first. */
    protected fun publishProductionDeclaration(edit: (MutableMap<String, Any?>) -> Unit = {}) {
        @Suppress("UNCHECKED_CAST")
        val tree = json.readValue(resource("production-declaration.json"), LinkedHashMap::class.java) as MutableMap<String, Any?>
        edit(tree)
        gh.productionDeclarations["thoryn-io/starter-express"] = json.writeValueAsString(tree)
    }

    private fun configTrust(id: String, env: String, clientId: String, github: Map<String, Any?>): MutableMap<String, Any?> = linkedMapOf(
        "id" to id, "environment" to env, "name" to "starter-${if (env == "production") "production" else "sandbox"}-$configRepoId",
        "provider" to "github_actions", "clientId" to clientId,
        // The production plane's audience is the workspace issuer itself; a sandbox's carries its slug.
        "audience" to if (env == "production") "https://acme.auth.stg.thoryn.org" else "https://acme.auth.stg.thoryn.org/$env",
        "github" to github, "scopes" to listOf("tenant:workload-identity.read", "tenant:workload-identity.write", "tenant:access.read"), "enabled" to true,
    )

    private fun connectionOf(trust: Map<String, Any?>, env: String, production: Boolean): String =
        ProjectSeeds.connectionJson("acme", json.valueToTree<JsonNode>(trust), env, production)

    // ── what the run left behind ──

    /** [path] on the config repository's proposal branch `thoryn/app-web`. */
    protected fun onBranch(path: String): String = gh.branches.getValue("acme/platform@thoryn/app-web").getValue(path)

    protected fun appTrust(env: String): Map<String, Any?> = api.trustsIn(env).single { it["name"].toString().endsWith("-${gh.repoId("acme/web")}") }

    @Suppress("UNCHECKED_CAST")
    protected fun steps(report: Map<String, Any?>): Map<String, String> =
        (report["steps"] as List<Map<String, Any?>>).groupBy { it["step"] as String }.mapValues { (_, v) -> v.joinToString(",") { it["status"] as String } }

    protected fun parsed(content: String, path: String) = ProvisionFile.parse(content.toByteArray(), path)
}
