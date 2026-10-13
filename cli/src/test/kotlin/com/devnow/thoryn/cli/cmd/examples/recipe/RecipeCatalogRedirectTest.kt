package com.devnow.thoryn.cli.cmd.examples.recipe

import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlin.io.path.createTempDirectory

/**
 * SSO-2881 — regression guard: GitHub release-asset download URLs 302 to a signed storage host, so
 * [RecipeCatalog]'s HTTP client MUST follow redirects. The bug (Redirect.NEVER default) surfaced the
 * 302 as "download … returned HTTP 302" and broke every remote-catalog fetch. This test stands up a
 * local server whose catalog.zip asset URL 302s to the real bytes and asserts the download follows
 * the redirect — the run gets as far as signature verification (which fails on unsigned test bytes)
 * and never fails with an HTTP 302.
 */
class RecipeCatalogRedirectTest {

    private lateinit var server: HttpServer

    @AfterEach
    fun stop() {
        if (this::server.isInitialized) server.stop(0)
    }

    @Test
    fun `download follows the GitHub release-asset 302 redirect (SSO-2881)`() {
        server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"

        // The release metadata: catalog.zip's browser_download_url points at a 302 endpoint.
        server.createContext("/repos/o/r/releases/latest") { ex ->
            val json = """
                {"tag_name":"v-test","assets":[
                  {"name":"catalog.zip","browser_download_url":"$base/redir/catalog.zip"},
                  {"name":"catalog.zip.sig","browser_download_url":"$base/dl/catalog.zip.sig"}
                ]}
            """.trimIndent()
            respond(ex, 200, json.toByteArray(StandardCharsets.UTF_8))
        }
        // The asset URL 302s to storage — exactly what GitHub does.
        server.createContext("/redir/catalog.zip") { ex ->
            ex.responseHeaders.add("Location", "$base/dl/catalog.zip")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        // The redirect target: arbitrary bytes (not a validly signed catalog).
        server.createContext("/dl/catalog.zip") { ex -> respond(ex, 200, byteArrayOf(0x50, 0x4B, 3, 4)) }
        // A well-formed but wrong signature (valid base64 of 64 bytes), so decode passes and we reach verify.
        server.createContext("/dl/catalog.zip.sig") { ex ->
            respond(ex, 200, Base64.getEncoder().encode(ByteArray(64)))
        }
        server.start()

        val catalog = RecipeCatalog(apiBase = base, repo = "o/r", cacheDir = createTempDirectory("cat-redir"))

        // With the redirect fix the download succeeds and the failure is signature verification, NOT a 302.
        val ex = assertThrows<RecipeCatalogException> { catalog.update(null) }
        assertFalse(
            ex.message.orEmpty().contains("302"),
            "download must FOLLOW the release-asset 302, not surface it as an error (was: ${ex.message})",
        )
    }

    private fun respond(ex: com.sun.net.httpserver.HttpExchange, status: Int, body: ByteArray) {
        ex.sendResponseHeaders(status, body.size.toLong())
        ex.responseBody.use { it.write(body) }
    }
}
