package com.devnow.thoryn.cli.cmd.examples

import com.devnow.thoryn.cli.cmd.BrowserLauncher
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeCatalog
import com.devnow.thoryn.cli.cmd.examples.recipe.RecipeCatalogException
import java.io.File
import java.net.ServerSocket
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * SSO-2880 — launch the **Node** relying party that ships as a signed catalog asset
 * (`recipes/<id>/apps/loopback-rp/server.js`) rather than an in-process Kotlin RP. This makes the RP
 * logic live in exactly ONE place: the readable, zero-dependency Node app in the public
 * `thoryn-examples` repo (Part 1). The CLI's only job here is orchestration — obtain the *verified*
 * asset, spawn `node server.js`, open the browser, wait, and stop the child.
 *
 * This deliberately REQUIRES two things, and fails with an actionable message when either is missing
 * (there is no Kotlin-RP fallback any more — that is the point):
 *   1. **Node ≥ 18** on `PATH` (the asset is plain Node, no build step, no dependencies).
 *   2. The **verified signed catalog asset** on disk. It comes only from the Ed25519-verified catalog
 *      bundle (`RecipeCatalog`); the CLI never bundles its own copy of `server.js` (that would
 *      re-duplicate the RP — the very thing this change removes).
 *
 * The child receives the flow configuration by environment:
 *   `THORYN_ISSUER`    the tenant hub issuer to authenticate against.
 *   `THORYN_CLIENT_ID` the public loopback client the recipe registered.
 *   `THORYN_SCOPE`     the requested scopes (space-separated), when known from the recipe.
 *   `PORT`             the loopback port the RP binds; the CLI picks a free one and opens the browser
 *                      there. The registered redirect URI is loopback + port-agnostic (RFC 8252 /
 *                      SSO-2801), so the hub ignores the port at authorize time.
 *
 * Native-image note: this uses only `ProcessBuilder` + JDK APIs (no reflection, no bundled resource),
 * so the GraalVM image needs no new config — subprocess spawn works out of the box.
 */
internal class NodeRelyingParty(
    /** Resolve the verified `server.js` for a recipe; default fetches/verifies via [RecipeCatalog]. */
    private val resolveAsset: (recipeId: String, relPath: String) -> Path =
        { id, rel -> RecipeCatalog().ensureAsset(id, rel) },
    /** `node --version` major, or null when node is absent/unusable. */
    private val nodeMajorVersion: () -> Int? = ::probeNodeMajorVersion,
    /** Spawn the child. Seam so tests assert the assembled command/env without running node. */
    private val startProcess: (Launch) -> Process = ::spawn,
    private val openBrowser: (String) -> Boolean = BrowserLauncher::open,
    private val awaitDone: () -> Unit = Prompt::awaitEnter,
    private val pickPort: () -> Int = ::freeLoopbackPort,
) {

    /** The fully-assembled child launch — exposed so tests can assert it without spawning node. */
    data class Launch(
        val command: List<String>,
        val env: Map<String, String>,
        val workingDir: File,
        val url: String,
    )

    /**
     * Run the Node RP for a provisioned example. Reads the [tenantIssuer] + [clientId] the recipe
     * interpreter stored in [ExampleState]; resolves the asset for [recipeId] under [assetDir].
     */
    fun run(
        ctx: ExampleContext,
        tenantIssuer: String,
        clientId: String,
        recipeId: String,
        assetDir: String = DEFAULT_ASSET_DIR,
        scopes: String? = null,
    ): Int {
        // 1) Node must be present and recent enough.
        val version = nodeMajorVersion()
        if (version == null) {
            ctx.warn("This example runs a Node relying party, but `node` was not found on your PATH.")
            ctx.warn("Install Node $MIN_NODE_MAJOR or newer (https://nodejs.org), then re-run `thoryn examples run $recipeId`.")
            return CommandSupport.EXIT_IO_ERROR
        }
        if (version < MIN_NODE_MAJOR) {
            ctx.warn("This example needs Node $MIN_NODE_MAJOR or newer, but found Node $version.")
            ctx.warn("Upgrade Node (https://nodejs.org), then re-run `thoryn examples run $recipeId`.")
            return CommandSupport.EXIT_IO_ERROR
        }

        // 2) The relying party comes ONLY from the verified signed catalog.
        val serverJs = try {
            resolveAsset(recipeId, "$assetDir/$SERVER_ENTRY").toAbsolutePath()
        } catch (ex: RecipeCatalogException) {
            ctx.warn("The relying-party asset is not available from the signed catalog: ${ex.message}")
            ctx.warn("Run `thoryn examples update` first — it fetches and verifies the published catalog release —")
            ctx.warn("then re-run `thoryn examples run $recipeId`. (This needs Node $MIN_NODE_MAJOR+ and network access to fetch the catalog once.)")
            return CommandSupport.EXIT_IO_ERROR
        }

        val port = pickPort()
        val url = "http://127.0.0.1:$port"
        val env = buildMap {
            put("THORYN_ISSUER", tenantIssuer.trimEnd('/'))
            put("THORYN_CLIENT_ID", clientId)
            put("PORT", port.toString())
            scopes?.takeIf { it.isNotBlank() }?.let { put("THORYN_SCOPE", it) }
        }
        val launch = Launch(
            command = listOf(NODE_BIN, serverJs.toString()),
            env = env,
            workingDir = serverJs.parent.toFile(),
            url = url,
        )

        ctx.step(1, "Starting the Node relying party (node $version) at $url")
        ctx.info("Relying party (verified from the signed catalog): $serverJs")
        ctx.info("It authenticates against $tenantIssuer as client $clientId (loopback redirect $url/callback).")

        val process = try {
            startProcess(launch)
        } catch (ex: Exception) {
            ctx.warn("Could not start `node` (${CommandSupport.describeThrowable(ex)}).")
            return CommandSupport.EXIT_IO_ERROR
        }

        try {
            ctx.step(2, "Opening your browser. Register a new user, then sign in.")
            ctx.info("If it doesn't open, visit: $url")
            openBrowser(url)
            ctx.out.println()
            ctx.out.println("Sign in in your browser; the protected page shows your ID-token claims.")
            ctx.out.println("Press Enter here when you're done to shut down the local example app.")
            awaitDone()
            ctx.out.println("Local app stopped. When finished:  thoryn examples teardown $recipeId")
            return CommandSupport.EXIT_OK
        } finally {
            stop(process)
        }
    }

    /** Stop the child: ask nicely, then force after a short grace so we never leave an orphan. */
    private fun stop(process: Process) {
        if (!process.isAlive) return
        process.destroy()
        if (!process.waitFor(STOP_GRACE_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly()
        }
    }

    companion object {
        const val MIN_NODE_MAJOR = 18
        const val DEFAULT_ASSET_DIR = "apps/loopback-rp"
        const val SERVER_ENTRY = "server.js"
        private const val NODE_BIN = "node"
        private const val STOP_GRACE_SECONDS = 5L

        private fun spawn(launch: Launch): Process {
            val pb = ProcessBuilder(launch.command)
                .directory(launch.workingDir)
                // Stream the child's output so the user sees its "listening on…" line; leave the
                // parent's stdin free so the "press Enter" wait still works (do NOT inheritIO stdin).
                .redirectOutput(ProcessBuilder.Redirect.INHERIT)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
            pb.environment().putAll(launch.env)
            return pb.start()
        }

        private fun probeNodeMajorVersion(): Int? = try {
            val proc = ProcessBuilder(NODE_BIN, "--version").redirectErrorStream(true).start()
            val output = proc.inputStream.bufferedReader().use { it.readText() }
            if (!proc.waitFor(10, TimeUnit.SECONDS)) {
                proc.destroyForcibly()
                null
            } else if (proc.exitValue() != 0) {
                null
            } else {
                parseNodeMajor(output)
            }
        } catch (_: Exception) {
            null
        }

        /** Parse a `node --version` string (`v20.11.1`) to its major version (20). Null when unparseable. */
        fun parseNodeMajor(versionOutput: String): Int? =
            Regex("""v?(\d+)\.""").find(versionOutput.trim())?.groupValues?.get(1)?.toIntOrNull()

        private fun freeLoopbackPort(): Int = ServerSocket(0).use { it.localPort }
    }
}
