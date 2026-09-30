package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.zip.GZIPOutputStream

/**
 * SSO-3435 — shared fixture for the `thoryn project init` tests: a [FakeProjectApi] behind the MockWebServer, a
 * [FakeGh] injected as the `gh` runner, the published v2 templates (the thoryn-starters declarations, vendored
 * under `src/test/resources/project/`) with a small file set each, and a signed-in session on workspace `acme`.
 */
abstract class ProjectTestBase : CommandTestBase() {

    internal lateinit var api: FakeProjectApi
    internal lateinit var gh: FakeGh

    protected val accessToken: String = jwt(
        mapOf(
            "sub" to "user-mark",
            "tnt" to FakeProjectApi.TENANT_ID,
            "scope" to ALL_SCOPES,
        ),
    )

    @BeforeEach
    fun setUpProject() {
        api = FakeProjectApi()
        server.dispatcher = api
        gh = FakeGh()
        ProjectCommand.ghRunner = { gh }
        seedTokens(
            Tokens(
                accessToken = accessToken,
                refreshToken = "RT-test-refresh",
                scope = ALL_SCOPES,
                issuer = "https://acme.auth.stg.thoryn.org",
                platformIssuer = "https://auth.stg.thoryn.org",
                gateway = baseUrl(),
                workspace = "acme",
            ),
        )
        publishTemplate("thoryn-io/starter-express", resource("template-express.json"), APP_FILES)
        publishTemplate("thoryn-io/starter-config", resource("template-config.json"), CONFIG_FILES)
    }

    @AfterEach
    fun tearDownProject() {
        ProjectCommand.resetForTest()
    }

    protected fun resource(name: String): String =
        requireNotNull(javaClass.getResource("/project/$name")) { "missing fixture $name" }.readText()

    internal fun publishTemplate(fullName: String, declaration: String?, files: Map<String, Pair<String, Boolean>>) {
        gh.declarations[fullName] = declaration
        if (declaration != null) {
            gh.tarballs[fullName] = tarGz("${fullName.replace('/', '-')}-f82948f", files + (StarterTemplateManifest.PATH to (declaration to false)))
        }
    }

    /** A clone of [fullName] at `<tempHome>/<name>` (a `.git` directory, and `gh repo view` names it). */
    protected fun clone(fullName: String, existing: Map<String, String> = emptyMap()): Path {
        val dir = tempHome.resolve(fullName.substringAfter('/'))
        Files.createDirectories(dir.resolve(".git"))
        existing.forEach { (path, content) ->
            val target = dir.resolve(path)
            Files.createDirectories(target.parent)
            Files.writeString(target, content)
        }
        gh.clones[dir.toAbsolutePath().normalize()] = fullName
        if (fullName !in gh.repos) gh.seedRepo(fullName)
        return dir
    }

    /** Every string thoryn handed to gh (arguments and stdin) — for the no-credential assertions. */
    protected fun everythingSentToGh(): String = gh.calls.joinToString("\n") { it.args.joinToString(" ") + (it.stdin ?: "") }

    companion object {
        const val ALL_SCOPES: String =
            "openid offline_access tenant:applications.read tenant:applications.write tenant:users.read tenant:users.write " +
                "tenant:environments.read tenant:environments.write tenant:idp.read tenant:idp.write tenant:access.read " +
                "tenant:access.write tenant:workload-identity.read tenant:workload-identity.write"

        val APP_FILES: Map<String, Pair<String, Boolean>> = linkedMapOf(
            "README.md" to ("# Express starter\n" to false),
            ".github/workflows/ci.yml" to ("name: CI\n" to false),
            ".thoryn/ci/gate.sh" to ("#!/usr/bin/env bash\necho gate\n" to true),
            ".thoryn/provision.yaml" to ("apiVersion: thoryn.io/provision/v1\n" to false),
        )

        val CONFIG_FILES: Map<String, Pair<String, Boolean>> = linkedMapOf(
            "README.md" to ("# Config project\n" to false),
            ".github/workflows/thoryn.yml" to ("name: Thoryn\n" to false),
            ".thoryn/environments/production/provision.yaml" to ("apiVersion: thoryn.io/provision/v1\n" to false),
            ".thoryn/environments/sandbox/provision.yaml" to ("apiVersion: thoryn.io/provision/v1\n" to false),
        )

        fun jwt(claims: Map<String, Any?>): String {
            val enc = Base64.getUrlEncoder().withoutPadding()
            val payload = tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsBytes(claims)
            return enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString(payload) + ".c2ln"
        }

        /** A GitHub-shaped tarball: a pax global header, then every file under one `<root>/` directory. */
        fun tarGz(root: String, files: Map<String, Pair<String, Boolean>>): ByteArray {
            val bytes = ByteArrayOutputStream()
            GZIPOutputStream(bytes).use { gz ->
                val comment = "52 comment=f82948fecfe617725b9a1bf019a4bcea92d6012f\n".toByteArray()
                entry(gz, "pax_global_header", comment, 'g', 420)
                entry(gz, "$root/", ByteArray(0), '5', 493)
                files.forEach { (path, content) ->
                    entry(gz, "$root/$path", content.first.toByteArray(), '0', if (content.second) 493 else 420)
                }
                gz.write(ByteArray(1024))
            }
            return bytes.toByteArray()
        }

        private fun entry(out: java.io.OutputStream, name: String, data: ByteArray, type: Char, mode: Int) {
            val header = ByteArray(512)
            fun put(offset: Int, value: String) = value.toByteArray().copyInto(header, offset)
            val (prefix, short) = if (name.length > 100) name.substringBeforeLast('/', "") to name.substringAfterLast('/') else "" to name
            put(0, short)
            put(100, "%07o".format(mode) + "\u0000")
            put(108, "0000000\u0000")
            put(116, "0000000\u0000")
            put(124, "%011o".format(data.size) + "\u0000")
            put(136, "%011o".format(1759230000L) + "\u0000")
            put(148, "        ")
            header[156] = type.code.toByte()
            put(257, "ustar\u0000")
            put(263, "00")
            if (prefix.isNotEmpty()) put(345, prefix)
            val sum = header.sumOf { it.toInt() and 0xff }
            put(148, "%06o".format(sum) + "\u0000 ")
            out.write(header)
            out.write(data)
            val pad = (512 - data.size % 512) % 512
            out.write(ByteArray(pad))
        }
    }
}
