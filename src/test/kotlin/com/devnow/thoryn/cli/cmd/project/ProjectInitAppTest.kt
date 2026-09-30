package com.devnow.thoryn.cli.cmd.project

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-3435 — `thoryn project init app`: an application project connected to one existing sandbox, from a new
 * repository (`--repo`) and from an existing clone, against a fake `gh` and a fake product-api.
 */
class ProjectInitAppTest : ProjectTestBase() {

    private val scopes = listOf(
        "tenant:applications.read", "tenant:applications.write", "tenant:users.read", "tenant:users.write", "tenant:environments.read",
    )

    @Test
    fun `app from a new repository creates it from the template, trusts the sandbox, grants, and sets the four variables`() {
        val envId = api.seedSandbox("dev")

        val (exit, out, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val repoId = gh.repoId("acme/web")
        assertThat(gh.invocations).containsExactly(
            "gh --version",
            "gh auth status",
            "gh api repos/thoryn-io/starter-express/contents/.thoryn/template.json",
            "gh api repos/acme/web",
            "gh api users/acme",
            "gh api --method POST repos/thoryn-io/starter-express/generate -f owner=acme -f name=web -F private=true -f description=Thoryn application project",
            "gh variable set THORYN_ISSUER --body https://auth.stg.thoryn.org --repo acme/web",
            "gh variable set THORYN_WORKSPACE --body acme --repo acme/web",
            "gh variable set THORYN_ENVIRONMENT --body dev --repo acme/web",
            "gh variable set THORYN_WIF_CLIENT_ID --body wi_client1 --repo acme/web",
        )
        val trust = api.trustsIn("dev").single()
        assertThat(trust["name"]).isEqualTo("starter-sandbox-$repoId")
        assertThat(trust["scopes"]).isEqualTo(scopes)
        @Suppress("UNCHECKED_CAST")
        val pins = trust["github"] as Map<String, Any?>
        assertThat(pins).containsEntry("owner", "acme").containsEntry("repository", "web").doesNotContainKeys("environment", "ref")
        assertThat((pins["repositoryId"] as Number).toLong()).isEqualTo(repoId)
        assertThat((pins["ownerId"] as Number).toLong()).isEqualTo(900L)
        assertThat(api.writes.first { it.path.endsWith("/trusts") }.body).doesNotContainKey("confirmProduction")
        assertThat(api.grants).containsExactly(mapOf("subject" to "client:wi_client1", "relation" to "manager", "object" to "environment:$envId"))
        assertThat(api.trusts).allMatch { it["environment"] == "dev" } // never production
        assertThat(out)
            .contains("Set up the app project acme/web for workspace acme")
            .contains("repository").contains("created").contains("acme/web (private) from thoryn-io/starter-express")
            .contains("starter-sandbox-$repoId → wi_client1")
            .contains("Next steps:").contains("gh repo clone acme/web").contains("gh run rerun")
    }

    @Test
    fun `app in an existing clone adds the template's files, commits nothing, and re-uses the repository`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web", existing = mapOf("src/app.js" to "console.log('mine')\n"))

        val (exit, out, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.invocations).contains(
            "gh repo view --json nameWithOwner",
            "gh api repos/acme/web",
            "gh api repos/thoryn-io/starter-express/tarball",
        ).noneMatch { it.contains("generate") }
        assertThat(Files.readString(dir.resolve(".thoryn/ci/gate.sh"))).contains("echo gate")
        assertThat(Files.getPosixFilePermissions(dir.resolve(".thoryn/ci/gate.sh"))).contains(PosixFilePermission.OWNER_EXECUTE)
        assertThat(Files.getPosixFilePermissions(dir.resolve("README.md"))).doesNotContain(PosixFilePermission.OWNER_EXECUTE)
        assertThat(Files.readString(dir.resolve(".thoryn/template.json"))).contains("thoryn.io/starter-template/v2")
        assertThat(Files.readString(dir.resolve("src/app.js"))).contains("mine") // untouched
        assertThat(gh.variables).containsEntry("acme/web:THORYN_ENVIRONMENT", "dev")
        assertThat(out).contains("5 added, 0 already identical").contains("git add .github .thoryn README.md && git commit")
    }

    @Test
    fun `re-running app converges without a second trust, grant or file write`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web")
        assertThat(runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString()).exit).isEqualTo(0)
        val writesAfterFirst = api.writes.size

        val (exit, out, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString(), "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.trusts).hasSize(1)
        assertThat(api.grants).hasSize(1)
        // The only product-api write of the re-run is the idempotent grant (200, already present).
        assertThat(api.writes.drop(writesAfterFirst).map { "${it.method} ${it.path}" }).containsExactly("POST /api/v1/access/grants")
        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        val connection = (report["connections"] as List<Map<String, Any?>>).single()
        assertThat(connection).containsEntry("adopted", true).containsEntry("clientId", "wi_client1")
        @Suppress("UNCHECKED_CAST")
        assertThat((report["files"] as Map<String, List<String>>)["added"]).isEmpty()
        assertThat(gh.variables).containsEntry("acme/web:THORYN_WIF_CLIENT_ID", "wi_client1")
    }

    @Test
    fun `a trust the server-side orchestrator made for the repository is adopted by its pins, whatever its name`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web")
        api.trusts += linkedMapOf(
            "id" to "trust-orch", "environment" to "dev", "name" to "starter-1a2b3c4d5e6f", "clientId" to "wi_orchestrated",
            "github" to mapOf("owner" to "acme", "repository" to "web", "repositoryId" to gh.repoId("acme/web"), "ownerId" to 900, "environment" to null, "ref" to null),
            "scopes" to scopes, "enabled" to true,
        )

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.trusts).hasSize(1)
        assertThat(gh.variables).containsEntry("acme/web:THORYN_WIF_CLIENT_ID", "wi_orchestrated")
    }

    @Test
    fun `a file that differs stops before any change, listing the conflicts`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web", existing = mapOf("README.md" to "# My app\n", ".github/workflows/ci.yml" to "name: CI\n"))

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("These files already exist with different content: README.md").contains("--force")
            .doesNotContain(".github/workflows/ci.yml,") // identical: not a conflict
        assertThat(api.writes).isEmpty()
        assertThat(gh.mutations).isEmpty()
        assertThat(Files.readString(dir.resolve("README.md"))).isEqualTo("# My app\n")
        assertThat(Files.exists(dir.resolve(".thoryn/ci/gate.sh"))).isFalse()

        // --force overwrites it.
        val forced = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString(), "--force")
        assertThat(forced.exit).describedAs(forced.err).isEqualTo(0)
        assertThat(Files.readString(dir.resolve("README.md"))).isEqualTo("# Express starter\n")
        assertThat(forced.out).contains("1 overwritten (--force)")
    }

    @Test
    fun `app with production is refused before anything is read or changed`() {
        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "production", "--repo", "acme/web")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(err).contains("never gets a production trust")
        assertThat(gh.calls).isEmpty()
        assertThat(api.requests).isEmpty()
    }

    @Test
    fun `app naming the production environment by another slug is refused by its kind`() {
        api.environments[0]["slug"] = "live"

        val (exit, out, _) = runCli("project", "init", "app", "--stack", "express", "--environment", "live", "--repo", "acme/web", "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(parseJson(out)).containsEntry("error", "production_refused").containsEntry("changed", false)
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an unknown sandbox or a stack without a template is refused`() {
        val missing = runCli("project", "init", "app", "--stack", "express", "--environment", "nope", "--repo", "acme/web")
        assertThat(missing.exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(missing.err).contains("No sandbox 'nope'")

        val stack = runCli("project", "init", "app", "--stack", "django", "--environment", "dev", "--repo", "acme/web")
        assertThat(stack.exit).isEqualTo(ProjectInit.EXIT_USAGE)
        assertThat(stack.err).contains("--stack must be one of express | spring-boot | aspnet-core")
        assertThat(api.writes).isEmpty()
        assertThat(gh.mutations).isEmpty()
    }

    @Test
    fun `a sandbox the caller does not manage is refused before any change`() {
        val envId = api.seedSandbox("dev")
        api.mine.remove("environment:$envId")

        val (exit, _, err) = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--repo", "acme/web")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        assertThat(err).contains("You do not manage sandbox 'dev'")
        assertThat(gh.calls).isEmpty()
    }
}
