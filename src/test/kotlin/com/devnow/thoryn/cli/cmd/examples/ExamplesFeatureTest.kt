package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.recipe.Recipe
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeCatalogException
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeExample
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * SSO-2880 — the examples framework after the in-process Kotlin RP was retired: the [NodeRelyingParty]
 * launcher's orchestration (node-missing / node-too-old / no-catalog error paths and the assembled
 * `node server.js` command + env), the [RecipeExample] rewiring onto that launcher, the per-example
 * state-store round-trip, and the registry. None of these tests shell out to a real `node` or open a
 * browser — every external effect is injected.
 */
class ExamplesFeatureTest {

    private val issuer = "https://acme.hub.stg.thoryn.org"
    private val clientId = "app-123"

    private val outBuf = ByteArrayOutputStream()
    private val errBuf = ByteArrayOutputStream()

    private fun ctx(state: ExampleStateStore = ExampleStateStore(dir = Files.createTempDirectory("ex"))): ExampleContext =
        ExampleContext(
            hub = "https://hub.stg.thoryn.org",
            gateway = "https://api.stg.thoryn.org",
            tokens = Tokens(accessToken = "session-token"),
            state = state,
            out = PrintStream(outBuf),
            err = PrintStream(errBuf),
        )

    private val err: String get() = errBuf.toString()
    private val out: String get() = outBuf.toString()

    // ── NodeRelyingParty: version parsing ──────────────────────────────────────────────────────────

    @Test
    fun `parseNodeMajor reads the major version from node --version output`() {
        assertThat(NodeRelyingParty.parseNodeMajor("v20.11.1")).isEqualTo(20)
        assertThat(NodeRelyingParty.parseNodeMajor("v18.0.0\n")).isEqualTo(18)
        assertThat(NodeRelyingParty.parseNodeMajor("not a version")).isNull()
    }

    // ── NodeRelyingParty: error paths (no child ever spawned) ──────────────────────────────────────

    @Test
    fun `run fails with an actionable message when node is not on the PATH`() {
        var spawned = false
        val rp = NodeRelyingParty(
            resolveAsset = { _, _ -> error("must not resolve the asset before checking node") },
            nodeMajorVersion = { null },
            startProcess = { spawned = true; FakeProcess() },
        )
        val code = rp.run(ctx(), issuer, clientId, "simple-signin")
        assertThat(code).isEqualTo(CommandSupport.EXIT_IO_ERROR)
        assertThat(spawned).isFalse()
        assertThat(err).contains("node", "Install Node")
    }

    @Test
    fun `run fails when the installed node is older than 18`() {
        val rp = NodeRelyingParty(
            resolveAsset = { _, _ -> error("must not resolve the asset when node is too old") },
            nodeMajorVersion = { 16 },
            startProcess = { FakeProcess() },
        )
        val code = rp.run(ctx(), issuer, clientId, "simple-signin")
        assertThat(code).isEqualTo(CommandSupport.EXIT_IO_ERROR)
        assertThat(err).contains("Node 18 or newer", "found Node 16")
    }

    @Test
    fun `run fails with a fetch-the-catalog message when the signed asset is unavailable`() {
        var spawned = false
        val rp = NodeRelyingParty(
            nodeMajorVersion = { 20 },
            resolveAsset = { _, _ -> throw RecipeCatalogException("no published catalog release") },
            startProcess = { spawned = true; FakeProcess() },
        )
        val code = rp.run(ctx(), issuer, clientId, "simple-signin")
        assertThat(code).isEqualTo(CommandSupport.EXIT_IO_ERROR)
        assertThat(spawned).isFalse()
        assertThat(err).contains("signed catalog", "thoryn examples update")
    }

    // ── NodeRelyingParty: happy-path command + env assembly ────────────────────────────────────────

    @Test
    fun `run launches node with the asset, wires the OIDC env, opens the browser, and stops the child`(@TempDir tmp: Path) {
        val serverJs = tmp.resolve("apps/loopback-rp/server.js")
        Files.createDirectories(serverJs.parent)
        Files.writeString(serverJs, "// loopback rp")

        var launch: NodeRelyingParty.Launch? = null
        var openedUrl: String? = null
        val process = FakeProcess()
        val rp = NodeRelyingParty(
            resolveAsset = { _, rel -> assertThat(rel).isEqualTo("apps/loopback-rp/server.js"); serverJs },
            nodeMajorVersion = { 20 },
            startProcess = { launch = it; process },
            openBrowser = { openedUrl = it; true },
            awaitDone = { /* non-interactive: return immediately */ },
            pickPort = { 45671 },
        )

        val code = rp.run(ctx(), "$issuer/", clientId, "simple-signin", scopes = "openid profile email")

        assertThat(code).isEqualTo(CommandSupport.EXIT_OK)
        val l = launch!!
        assertThat(l.command).containsExactly("node", serverJs.toAbsolutePath().toString())
        assertThat(l.workingDir).isEqualTo(serverJs.parent.toAbsolutePath().toFile())
        assertThat(l.url).isEqualTo("http://127.0.0.1:45671")
        assertThat(l.env)
            .containsEntry("THORYN_ISSUER", issuer) // trailing slash trimmed
            .containsEntry("THORYN_CLIENT_ID", clientId)
            .containsEntry("THORYN_SCOPE", "openid profile email")
            .containsEntry("PORT", "45671")
        assertThat(openedUrl).isEqualTo("http://127.0.0.1:45671")
        assertThat(process.destroyed).isTrue() // child is torn down when the user is done
    }

    @Test
    fun `run omits THORYN_SCOPE when the recipe does not declare scopes`(@TempDir tmp: Path) {
        val serverJs = tmp.resolve("apps/loopback-rp/server.js")
        Files.createDirectories(serverJs.parent)
        Files.writeString(serverJs, "// loopback rp")
        var launch: NodeRelyingParty.Launch? = null
        val rp = NodeRelyingParty(
            resolveAsset = { _, _ -> serverJs },
            nodeMajorVersion = { 20 },
            startProcess = { launch = it; FakeProcess() },
            openBrowser = { true },
            awaitDone = {},
            pickPort = { 40000 },
        )
        rp.run(ctx(), issuer, clientId, "simple-signin", scopes = null)
        assertThat(launch!!.env).doesNotContainKey("THORYN_SCOPE")
    }

    // ── RecipeExample rewiring onto the launcher ──────────────────────────────────────────────────

    @Test
    fun `RecipeExample run reports usage when no setup state is stored`(@TempDir tmp: Path) {
        val store = ExampleStateStore(dir = tmp)
        val example = RecipeExample(Recipe.load("simple-signin"))
        val code = example.run(ctx(store))
        assertThat(code).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(err).contains("No 'simple-signin' setup found")
    }

    @Test
    fun `RecipeExample run passes the stored issuer, client, recipe scopes, and asset dir to the launcher`(@TempDir tmp: Path) {
        val store = ExampleStateStore(dir = tmp)
        store.write(
            ExampleState(
                example = "simple-signin",
                workspaceSlug = "ex-abc",
                tenantId = "t-1",
                clientId = "client-xyz",
                tenantIssuer = "https://ex-abc.hub.stg.thoryn.org",
            ),
        )
        var captured: LaunchCall? = null
        // A launcher whose seams never touch node/network: its resolveAsset records what RecipeExample
        // asked for (the recipe id + the asset-relative path it derived from the recipe's assets.rp).
        val recorded = tmp.resolve("apps/loopback-rp/server.js")
        Files.createDirectories(recorded.parent)
        Files.writeString(recorded, "// rp")
        val recording = NodeRelyingParty(
            resolveAsset = { recipeId, rel -> captured = LaunchCall(recipeId, rel); recorded },
            nodeMajorVersion = { 20 },
            startProcess = { FakeProcess() },
            openBrowser = { true },
            awaitDone = {},
            pickPort = { 41000 },
        )
        val example = RecipeExample(Recipe.load("simple-signin"), relyingParty = recording)

        val code = example.run(ctx(store))

        assertThat(code).isEqualTo(CommandSupport.EXIT_OK)
        assertThat(captured).isNotNull
        assertThat(captured!!.recipeId).isEqualTo("simple-signin")
        // The recipe declares assets.rp = ./apps/loopback-rp; RecipeExample strips the ./ and appends server.js.
        assertThat(captured!!.relPath).isEqualTo("apps/loopback-rp/server.js")
    }

    // ── state store + registry ─────────────────────────────────────────────────────────────────────

    @Test
    fun `state store round-trips and clears`(@TempDir tmp: Path) {
        val store = ExampleStateStore(dir = tmp)
        assertThat(store.read("simple-signin")).isNull()

        store.write(ExampleState(example = "simple-signin", workspaceSlug = "ex-abc", clientId = "cid-1"))
        val read = store.read("simple-signin")
        assertThat(read).isNotNull
        assertThat(read!!.workspaceSlug).isEqualTo("ex-abc")
        assertThat(read.clientId).isEqualTo("cid-1")

        store.clear("simple-signin")
        assertThat(store.read("simple-signin")).isNull()
    }

    @Test
    fun `registry exposes the simple-signin example`() {
        assertThat(ExampleRegistry.byName("simple-signin")).isNotNull
        assertThat(ExampleRegistry.all().map { it.name }).contains("simple-signin")
        assertThat(ExampleRegistry.byName("nope")).isNull()
    }

    private data class LaunchCall(val recipeId: String, val relPath: String)

    /** A no-op [Process] stand-in so stop()/destroy() can be asserted without spawning `node`. */
    private class FakeProcess : Process() {
        var destroyed = false
        private val empty: InputStream = ByteArrayInputStream(ByteArray(0))
        override fun getOutputStream(): OutputStream = OutputStream.nullOutputStream()
        override fun getInputStream(): InputStream = empty
        override fun getErrorStream(): InputStream = empty
        override fun waitFor(): Int = 0
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true
        override fun exitValue(): Int = 0
        override fun destroy() { destroyed = true }
        override fun isAlive(): Boolean = !destroyed
    }
}
