package com.devnow.thoryn.cli.cmd.examples.recipe

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * SSO-2874 — the catalog fetcher downloads the signed release, VERIFIES the Ed25519 signature against
 * the pinned public key before using anything, then extracts the recipes. A bundle whose signature
 * does not verify (tampered, or a different key) is REFUSED with nothing extracted.
 */
class RecipeCatalogTest {

    @TempDir
    lateinit var cache: Path
    private lateinit var server: MockWebServer
    private val enc = Base64.getEncoder()

    private val keyPair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val publicSpkiB64: String = enc.encodeToString(keyPair.public.encoded)

    @BeforeEach fun setUp() { server = MockWebServer().also { it.start() } }
    @AfterEach fun tearDown() { server.shutdown() }

    private fun catalogZip(): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry("schema/recipe.schema.json"))
            zip.write("""{"title":"schema"}""".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("recipes/simple-signin/recipe.json"))
            zip.write("""{"id":"simple-signin","version":"1.2.0","summary":"Sign a user in."}""".toByteArray())
            zip.closeEntry()
        }
        return out.toByteArray()
    }

    private fun sign(bytes: ByteArray, kp: KeyPair = keyPair): ByteArray =
        Signature.getInstance("Ed25519").run { initSign(kp.private); update(bytes); sign() }

    private fun releaseJson(): String =
        """{"tag_name":"v1.2.0","assets":[
             {"name":"catalog.zip","browser_download_url":"${server.url("/dl/catalog.zip")}"},
             {"name":"catalog.zip.sig","browser_download_url":"${server.url("/dl/catalog.zip.sig")}"}
           ]}"""

    private fun catalog(pub: String = publicSpkiB64) = RecipeCatalog(
        apiBase = server.url("/").toString().trimEnd('/'),
        publicKeySpkiB64 = pub,
        cacheDir = cache,
    )

    @Test
    fun `fetches, verifies the signature, and extracts the catalog recipes`() {
        val zip = catalogZip()
        server.enqueue(MockResponse().setBody(releaseJson()).setHeader("Content-Type", "application/json"))
        server.enqueue(MockResponse().setBody(okio.Buffer().write(zip)))
        server.enqueue(MockResponse().setBody(enc.encodeToString(sign(zip))))

        val info = catalog().update(null)

        assertThat(info.tag).isEqualTo("v1.2.0")
        assertThat(info.recipes).anyMatch { it.id == "simple-signin" && it.version == "1.2.0" }
    }

    @Test
    fun `refuses a bundle whose signature does not verify against the pinned key`() {
        val zip = catalogZip()
        val wrongKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        server.enqueue(MockResponse().setBody(releaseJson()).setHeader("Content-Type", "application/json"))
        server.enqueue(MockResponse().setBody(okio.Buffer().write(zip)))
        server.enqueue(MockResponse().setBody(enc.encodeToString(sign(zip, wrongKey)))) // signed by the WRONG key

        assertThatThrownBy { catalog().update(null) }
            .isInstanceOf(RecipeCatalogException::class.java)
            .hasMessageContaining("did NOT verify")
    }

    @Test
    fun `refuses when the release has no signature asset`() {
        server.enqueue(
            MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("""{"tag_name":"v1","assets":[{"name":"catalog.zip","browser_download_url":"${server.url("/dl/catalog.zip")}"}]}"""),
        )
        assertThatThrownBy { catalog().update(null) }
            .isInstanceOf(RecipeCatalogException::class.java)
            .hasMessageContaining("unsigned")
    }
}
