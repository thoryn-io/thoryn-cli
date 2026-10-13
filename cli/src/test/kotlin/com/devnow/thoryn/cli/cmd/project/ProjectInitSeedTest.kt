package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.provision.ProvisionFile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3435 — the `.thoryn/` files `thoryn project init` SEEDS (oauthy ADR 2026-10-13, provisioning-as-code converge,
 * §3 and §6): per connection, a `workload_identity` `connection.json` that validates against the bundled schema, and a
 * starter `provision.yaml` the existing loader accepts — written to a clone, committed to a repository this run
 * creates (directly for an app project, through a pull request for a config project), never pushed to a repository
 * that already existed, and never overwriting a provisioning file that is already there.
 */
class ProjectInitSeedTest : ProjectTestBase() {

    private val json = JsonMapper.builder().build()
    private val config = arrayOf("project", "init", "config", "--reviewer", "alice", "--confirm-production")

    private fun connectionOf(path: Path): Connection {
        assertThat(Connection.validate(json.readTree(Files.readAllBytes(path)))).describedAs("schema violations of $path").isEmpty()
        return Connection.load(path.toFile())
    }

    @Test
    fun `app in a clone seeds a connection contract and a starter provisioning file that the loaders accept`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web")

        val (exit, out, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString(), "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val connection = connectionOf(dir.resolve(".thoryn/connection.json"))
        assertThat(connection.isWorkloadIdentity).isTrue()
        assertThat(connection.slug).isEqualTo("acme")
        assertThat(connection.clientId).isEqualTo("wi_client1")
        assertThat(connection.audience).isEqualTo("https://acme.auth.stg.thoryn.org/dev")
        assertThat(connection.tokenEndpoint).isNull() // the default {audience}/oauth2/token is not written
        assertThat(connection.secretEnvOrNull).isNull()
        assertThat(connection.scopes).isEqualTo(listOf("tenant:applications.read", "tenant:applications.write", "tenant:users.read", "tenant:users.write", "tenant:environments.read"))
        assertThat(connection.github!!.repositoryId).isEqualTo(gh.repoId("acme/web"))
        assertThat(connection.github!!.owner).isEqualTo("acme")
        assertThat(connection.github!!.environment).isNull()
        assertThat(connection.github!!.ref).isNull()

        val provision = ProvisionFile.load(dir.resolve(".thoryn/provision.yaml").toFile())
        val app = provision.resources.single()
        assertThat(app.kind).isEqualTo("application")
        assertThat(app.name).isEqualTo("web")
        assertThat(app.environment).isEqualTo("dev")
        assertThat(app.spec).containsEntry("displayName", "acme/web").containsEntry("clientType", "public")
            .containsEntry("redirectUris", listOf("http://localhost:3000/callback"))
        assertThat(Files.readString(dir.resolve(".thoryn/provision.yaml"))).contains("wi_client1").contains("never overwrites it")

        @Suppress("UNCHECKED_CAST")
        val provisioning = parseJson(out)["provisioning"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        assertThat((provisioning["files"] as List<Map<String, Any?>>).map { "${it["path"]}=${it["status"]}" })
            .containsExactly(".thoryn/connection.json=written", ".thoryn/provision.yaml=written")
        assertThat(provisioning["pullRequest"]).isNull()
    }

    @Test
    fun `config in a clone seeds one connection per section, production pinned to its GitHub environment and branch, and both starters`() {
        api.seedSandbox("qa")
        val dir = clone("acme/platform")

        val (exit, _, err) = runCli(*config, "--dir", dir.toString())

        assertThat(exit).describedAs(err).isEqualTo(0)
        val production = connectionOf(dir.resolve(".thoryn/environments/production/connection.json"))
        assertThat(production.clientId).isEqualTo("wi_client2")
        assertThat(production.scopes).isEqualTo(listOf("tenant:environments.read", "tenant:environments.write", "tenant:idp.read", "tenant:idp.write"))
        assertThat(production.github!!.environment).isEqualTo("thoryn-production")
        assertThat(production.github!!.ref).isEqualTo("refs/heads/main")
        val sandbox = connectionOf(dir.resolve(".thoryn/environments/sandbox/connection.json"))
        assertThat(sandbox.clientId).isEqualTo("wi_client1")
        assertThat(sandbox.audience).isEqualTo("https://acme.auth.stg.thoryn.org/qa")
        assertThat(sandbox.github!!.environment).isNull()

        // Production owns the workspace's sandbox (adopted by slug, named as it is); the sandbox section anchors on it by slug only.
        val productionFile = ProvisionFile.load(dir.resolve(".thoryn/environments/production/provision.yaml").toFile()).resources.single()
        assertThat(productionFile.kind).isEqualTo("environment")
        assertThat(productionFile.name).isEqualTo("qa")
        assertThat(productionFile.spec).containsEntry("slug", "qa").containsEntry("displayName", "Sandbox qa")
        val sandboxFile = ProvisionFile.load(dir.resolve(".thoryn/environments/sandbox/provision.yaml").toFile()).resources.single()
        assertThat(sandboxFile.kind).isEqualTo("environment")
        assertThat(sandboxFile.spec).containsOnlyKeys("slug").containsEntry("slug", "qa")
        // The template's placeholders at those paths did not win over the seeds.
        assertThat(Files.readString(dir.resolve(".thoryn/environments/sandbox/provision.yaml"))).contains("kind: environment")
    }

    @Test
    fun `app from a new repository commits both files to the default branch, and a new config repository proposes them in a pull request`() {
        api.seedSandbox("dev")

        val app = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--json")

        assertThat(app.exit).describedAs(app.err).isEqualTo(0)
        val main = gh.files.getValue("acme/web")
        assertThat(main).containsKeys(".thoryn/connection.json", ".thoryn/provision.yaml")
        assertThat(Connection.parse(main.getValue(".thoryn/connection.json").toByteArray()).clientId).isEqualTo("wi_client1")
        assertThat(ProvisionFile.parse(main.getValue(".thoryn/provision.yaml").toByteArray()).resources.single().kind).isEqualTo("application")
        @Suppress("UNCHECKED_CAST")
        val files = (parseJson(app.out)["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>
        assertThat(files.map { it["status"] }).containsOnly("committed")
        @Suppress("UNCHECKED_CAST")
        assertThat(parseJson(app.out)["nextSteps"] as List<String>).anyMatch { it.contains(".thoryn/connection.json and .thoryn/provision.yaml are committed on main") }

        val cfg = runCli(*config, "--repo", "acme/platform", "--json")

        assertThat(cfg.exit).describedAs(cfg.err).isEqualTo(0)
        assertThat(gh.files.getValue("acme/platform")).doesNotContainKey(".thoryn/environments/production/connection.json") // main is protected: untouched
        val branch = gh.branches.getValue("acme/platform@${ProjectSeeds.PROVISIONING_BRANCH}")
        assertThat(branch).containsKeys(
            ".thoryn/environments/sandbox/connection.json", ".thoryn/environments/sandbox/provision.yaml",
            ".thoryn/environments/production/connection.json", ".thoryn/environments/production/provision.yaml",
        )
        val production = Connection.parse(branch.getValue(".thoryn/environments/production/connection.json").toByteArray())
        assertThat(production.github!!.environment).isEqualTo("thoryn-production")
        assertThat(ProvisionFile.parse(branch.getValue(".thoryn/environments/production/provision.yaml").toByteArray()).resources.single().spec)
            .containsEntry("slug", "dev") // the only sandbox, so the config project's
        @Suppress("UNCHECKED_CAST")
        val provisioning = parseJson(cfg.out)["provisioning"] as Map<String, Any?>
        assertThat(provisioning["pullRequest"]).isEqualTo("https://github.com/acme/platform/pull/1")
        @Suppress("UNCHECKED_CAST")
        assertThat(parseJson(cfg.out)["nextSteps"] as List<String>).anyMatch { it.startsWith("Provisioning files pending review: https://github.com/acme/platform/pull/1") }
    }

    @Test
    fun `an existing provisioning file is kept, a foreign connection is a conflict, and this repository's own stale one is rewritten`() {
        api.seedSandbox("dev")
        val mine = "apiVersion: thoryn.io/provision/v1\nresources:\n  - kind: application\n    name: mine\n    spec: { displayName: Mine }\n"
        val kept = clone("acme/web", existing = mapOf(".thoryn/provision.yaml" to mine))
        val keptRun = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", kept.toString(), "--json")
        assertThat(keptRun.exit).describedAs(keptRun.err).isEqualTo(0)
        assertThat(Files.readString(kept.resolve(".thoryn/provision.yaml"))).isEqualTo(mine)
        @Suppress("UNCHECKED_CAST")
        val keptFiles = (parseJson(keptRun.out)["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>
        assertThat(keptFiles.first { it["path"] == ".thoryn/provision.yaml" }["status"]).isEqualTo("kept")
        assertThat(Files.exists(kept.resolve(".thoryn/connection.json"))).isTrue()

        val foreign = """{"apiVersion":"thoryn.io/connection/v1","workspace":{"slug":"acme"},"auth":{"method":"client_credentials","clientId":"cli-ci","secretEnv":"S","scopes":["tenant:applications.read"]}}"""
        val conflicting = clone("acme/web2", existing = mapOf(".thoryn/connection.json" to foreign))
        val writesBefore = api.writes.size
        val refused = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", conflicting.toString())
        assertThat(refused.exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(refused.err).contains("These files already exist with different content: .thoryn/connection.json")
        assertThat(api.writes).hasSize(writesBefore) // nothing changed, on either side
        assertThat(Files.readString(conflicting.resolve(".thoryn/connection.json"))).isEqualTo(foreign)
        val forced = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", conflicting.toString(), "--force")
        assertThat(forced.exit).describedAs(forced.err).isEqualTo(0)
        assertThat(connectionOf(conflicting.resolve(".thoryn/connection.json")).isWorkloadIdentity).isTrue()

        val ours = clone("acme/web3")
        Files.createDirectories(ours.resolve(".thoryn"))
        Files.writeString(
            ours.resolve(".thoryn/connection.json"),
            """{"apiVersion":"thoryn.io/connection/v1","workspace":{"slug":"acme"},"auth":{"method":"workload_identity","clientId":"wi_old",""" +
                """"audience":"https://acme.auth.stg.thoryn.org/dev","scopes":["tenant:applications.read"],"github":{"repositoryId":${gh.repoId("acme/web3")}}}}""",
        )
        val rewritten = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", ours.toString(), "--json")
        assertThat(rewritten.exit).describedAs(rewritten.err).isEqualTo(0) // no --force needed: it is this repository's own
        val now = connectionOf(ours.resolve(".thoryn/connection.json"))
        assertThat(now.clientId).startsWith("wi_client").isNotEqualTo("wi_old")
        @Suppress("UNCHECKED_CAST")
        val rewrittenFiles = (parseJson(rewritten.out)["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>
        assertThat(rewrittenFiles.first { it["path"] == ".thoryn/connection.json" }["status"]).isEqualTo("rewritten")
    }

    @Test
    fun `--repo on a repository that already existed adds no file and says how to add them`() {
        api.seedSandbox("dev")
        gh.seedRepo("acme/web")

        val (exit, out, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web", "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.files["acme/web"].orEmpty()).doesNotContainKeys(".thoryn/connection.json", ".thoryn/provision.yaml")
        assertThat(gh.mutations).noneMatch { it.contains("contents/") }
        @Suppress("UNCHECKED_CAST")
        val files = (parseJson(out)["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>
        assertThat(files.map { it["status"] }).containsOnly("not added")
        @Suppress("UNCHECKED_CAST")
        assertThat(parseJson(out)["nextSteps"] as List<String>).anyMatch { it.contains("its .thoryn/ connection.json + provision.yaml") && it.contains("inside the clone") }
    }
}
