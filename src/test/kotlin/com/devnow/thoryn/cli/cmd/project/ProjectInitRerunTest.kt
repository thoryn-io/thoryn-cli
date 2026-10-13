package com.devnow.thoryn.cli.cmd.project

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isRegularFile

/**
 * SSO-3435 — re-run safety DEMONSTRATED, not asserted: the same `thoryn project init` run twice makes NO write the
 * second time — not to product-api (trusts adopted, grants read and found), not to GitHub (the ruleset, the environment
 * protection and every variable are read first and left alone when already in shape), not to the working tree
 * (identical seeds skipped, an existing provisioning file kept).
 */
class ProjectInitRerunTest : ProjectTestBase() {

    private fun snapshot(dir: Path): Map<Path, Pair<List<Byte>, Long>> =
        Files.walk(dir).filter { it.isRegularFile() }.toList().associateWith { Files.readAllBytes(it).toList() to Files.getLastModifiedTime(it).toMillis() }

    @Test
    fun `a second app run in a clone writes nothing to product-api, GitHub or the working tree`() {
        api.seedSandbox("dev")
        val dir = clone("acme/web")
        val first = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())
        assertThat(first.exit).describedAs(first.err).isEqualTo(0)
        assertThat(first.out).startsWith("Set up the app project acme/web")
        val apiWrites = api.writes.size
        val ghMutations = gh.mutations.size
        val before = snapshot(dir)

        val second = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString(), "--json")

        assertThat(second.exit).describedAs(second.err).isEqualTo(0)
        assertThat(api.writes).describedAs("product-api writes of the second run: ${api.writes.drop(apiWrites)}").hasSize(apiWrites)
        assertThat(gh.mutations).describedAs("gh writes of the second run: ${gh.mutations.drop(ghMutations)}").hasSize(ghMutations)
        assertThat(snapshot(dir)).isEqualTo(before)
        val report = parseJson(second.out)
        @Suppress("UNCHECKED_CAST")
        val steps = (report["steps"] as List<Map<String, Any?>>).associate { it["step"] as String to it["status"] as String }
        assertThat(steps).containsEntry("workload-trust", "adopted").containsEntry("access", "existing")
            .containsEntry("variables", "unchanged").containsEntry("files", "unchanged").containsEntry("provisioning", "unchanged")
        @Suppress("UNCHECKED_CAST")
        assertThat((report["variables"] as List<Map<String, Any?>>).map { it["changed"] }).containsOnly(false)
        @Suppress("UNCHECKED_CAST")
        assertThat(((report["provisioning"] as Map<String, Any?>)["files"] as List<Map<String, Any?>>).map { it["status"] })
            .containsExactly("unchanged", "kept")

        val third = runCli("project", "init", "app", "--stack", "express", "--environment", "dev", "--dir", dir.toString())
        assertThat(third.out).startsWith("Checked the app project acme/web")
        assertThat(api.writes).hasSize(apiWrites)
        assertThat(gh.mutations).hasSize(ghMutations)
    }

    @Test
    fun `a second config run from --repo writes nothing on either side and names the still-open provisioning pull request`() {
        val base = arrayOf("project", "init", "config", "--reviewer", "alice", "--reviewer", "bob", "--confirm-production", "--repo", "acme/platform")
        val first = runCli(*base)
        assertThat(first.exit).describedAs(first.err).isEqualTo(0)
        val apiWrites = api.writes.size
        val ghMutations = gh.mutations.size
        val ghCalls = gh.calls.size
        val apiRequests = api.requests.size

        val second = runCli(*base, "--json")

        assertThat(second.exit).describedAs(second.err).isEqualTo(0)
        assertThat(api.writes).describedAs("product-api writes of the second run: ${api.writes.drop(apiWrites)}").hasSize(apiWrites)
        assertThat(gh.mutations).describedAs("gh writes of the second run: ${gh.mutations.drop(ghMutations)}").hasSize(ghMutations)
        val report = parseJson(second.out)
        @Suppress("UNCHECKED_CAST")
        val steps = (report["steps"] as List<Map<String, Any?>>).associate { it["step"] as String to it["status"] as String }
        assertThat(steps).containsEntry("repository", "existing").containsEntry("codeowners", "unchanged").containsEntry("ruleset", "in place")
            .containsEntry("protection", "in place").containsEntry("environments", "existing").containsEntry("workload-trust", "adopted")
            .containsEntry("access", "existing").containsEntry("variables", "unchanged").containsEntry("provisioning", "open") // the pull request is still open; nothing new on its branch
        @Suppress("UNCHECKED_CAST")
        assertThat((report["provisioning"] as Map<String, Any?>)["pullRequest"]).isEqualTo("https://github.com/acme/platform/pull/1")
        assertThat(gh.pulls.getValue("acme/platform")).hasSize(1)
        // The reads it did instead: the ruleset, the environment, the variables at both levels, and the grants.
        assertThat(gh.invocations.drop(ghCalls))
            .contains("gh api repos/acme/platform/rulesets/4200", "gh api repos/acme/platform/environments/thoryn-production")
            .contains("gh variable list --repo acme/platform --json name,value", "gh variable list --repo acme/platform --env thoryn-production --json name,value")
        assertThat(api.requests.drop(apiRequests)).contains("GET /api/v1/access/grants")

        val table = runCli(*base)
        assertThat(table.out).startsWith("Checked the config project acme/platform")
    }
}
