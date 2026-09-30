package com.devnow.thoryn.cli.cmd.project

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS

/**
 * SSO-3435 — the pieces under `thoryn project init`: the v2 template contract (the same rules as oauthy's
 * orchestrator), the tarball reader, and the real process runner behind [GhRunner].
 */
class ProjectBuildingBlocksTest {

    private fun resource(name: String): String = requireNotNull(javaClass.getResource("/project/$name")).readText()

    @Test
    fun `the published v2 declarations parse with their connections, scopes, grants and variable levels`() {
        val config = StarterTemplateManifest.parse(resource("template-config.json"), StarterTemplateManifest.KIND_CONFIG)
        assertThat(config.productionGithubEnvironment).isEqualTo("thoryn-production")
        assertThat(config.productionConnection!!.second.grant).isEqualTo(StarterTemplateManifest.Grant("manager", "workspace"))
        assertThat(config.sandboxConnection.second.environmentVariable).isEqualTo("THORYN_SANDBOX_ENVIRONMENT")
        assertThat(config.variables["THORYN_PRODUCTION_WIF_CLIENT_ID"]).isEqualTo(StarterTemplateManifest.Variable("environment", "thoryn-production"))

        val app = StarterTemplateManifest.parse(resource("template-express.json"), StarterTemplateManifest.KIND_APPLICATION)
        assertThat(app.productionConnection).isNull()
        assertThat(app.variables.keys).containsExactly("THORYN_ISSUER", "THORYN_WORKSPACE", "THORYN_ENVIRONMENT", "THORYN_WIF_CLIENT_ID")
    }

    @Test
    fun `a template of the other kind, a v1 declaration or an extra variable breaks the contract`() {
        assertThatThrownBy { StarterTemplateManifest.parse(resource("template-express.json"), StarterTemplateManifest.KIND_CONFIG) }
            .hasMessageContaining("kind is 'application', expected 'config'")
        assertThatThrownBy { StarterTemplateManifest.parse(resource("template-v1.json"), StarterTemplateManifest.KIND_APPLICATION) }
            .hasMessageContaining("unsupported apiVersion 'thoryn.io/starter-template/v1'")
        val extra = resource("template-express.json").replace(
            "\"variables\": {",
            "\"variables\": { \"THORYN_EXTRA\": { \"level\": \"repository\", \"description\": \"x\" },",
        )
        assertThatThrownBy { StarterTemplateManifest.parse(extra, StarterTemplateManifest.KIND_APPLICATION) }
            .hasMessageContaining("THORYN_EXTRA has no value")
    }

    @Test
    fun `the tarball reader strips GitHub's root directory, keeps the executable bit and skips the pax header`() {
        val tgz = ProjectTestBase.tarGz(
            "thoryn-io-starter-express-abc1234",
            mapOf("README.md" to ("hi\n" to false), ".thoryn/ci/gate.sh" to ("#!/bin/sh\n" to true)),
        )

        val entries = TemplateArchive.read(tgz).associateBy { it.path }

        assertThat(entries.keys).containsExactlyInAnyOrder("README.md", ".thoryn/ci/gate.sh")
        assertThat(entries.getValue(".thoryn/ci/gate.sh").executable).isTrue()
        assertThat(entries.getValue("README.md").executable).isFalse()
        assertThat(String(entries.getValue("README.md").bytes)).isEqualTo("hi\n")
    }

    @Test
    fun `a long path uses the ustar prefix, and a path that climbs out of the repository is refused`() {
        val long = "a".repeat(60) + "/" + "b".repeat(60) + "/file.txt"
        val entries = TemplateArchive.read(ProjectTestBase.tarGz("root", mapOf(long to ("x" to false))))
        assertThat(entries.single().path).isEqualTo(long)

        assertThatThrownBy { TemplateArchive.stripRoot("root/../../etc/passwd") }.hasMessageContaining("leaves the repository")
        assertThatThrownBy { TemplateArchive.stripRoot("/etc/passwd") }.hasMessageContaining("absolute path")
        assertThatThrownBy { TemplateArchive.read("not gzip".toByteArray()) }.isInstanceOf(TemplateArchive.ArchiveException::class.java)
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    fun `the process runner feeds stdin, captures stdout and reports a missing executable as not installed`() {
        val cat = ProcessGhRunner(executable = "cat").run(emptyList(), stdin = "piped".toByteArray())
        assertThat(cat.ok).isTrue()
        assertThat(cat.text).isEqualTo("piped")

        val failing = ProcessGhRunner(executable = "sh").run(listOf("-c", "echo 'gh: Not Found (HTTP 404)' >&2; exit 1"))
        assertThat(failing.ok).isFalse()
        assertThat(failing.httpStatus()).isEqualTo(404)

        assertThatThrownBy { ProcessGhRunner(executable = "thoryn-no-such-gh-binary").run(listOf("--version")) }
            .isInstanceOf(GhNotInstalledException::class.java)
    }

    @Test
    fun `token-shaped strings are redacted from anything gh wrote`() {
        val result = GhResult(1, ByteArray(0), "denied for ghp_0123456789abcdefABCDEF and github_pat_11ABCDEFG0123456789_abcdefghijklmnop")
        assertThat(result.reason()).doesNotContain("ghp_0123").doesNotContain("github_pat_11").contains("[redacted]")
    }

    @Test
    fun `trust names are deterministic per connection and repository`() {
        assertThat(ProjectInit.trustName("sandbox", 1044556677L)).isEqualTo("starter-sandbox-1044556677")
        assertThat(ProjectInit.trustName("production", 1044556677L)).isEqualTo("starter-production-1044556677")
        assertThat(ProjectInit.encodeId("a b@c")).isEqualTo("a%20b%40c")
    }
}
