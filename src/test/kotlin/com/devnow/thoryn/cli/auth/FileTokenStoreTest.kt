package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

class FileTokenStoreTest {

    @Test
    fun `read returns null when file is absent`(@TempDir dir: Path) {
        val store = FileTokenStore(dir.resolve("absent.json"))
        assertThat(store.read()).isNull()
    }

    @Test
    fun `write then read round-trips the tokens`(@TempDir dir: Path) {
        val store = FileTokenStore(dir.resolve("tokens.json"))
        val tokens = Tokens(
            accessToken = "access-1",
            refreshToken = "refresh-1",
            scope = "openid tenant:clients.read",
        )

        store.write(tokens)

        assertThat(store.read()).isEqualTo(tokens)
    }

    @Test
    fun `write sets POSIX 0600 permissions`(@TempDir dir: Path) {
        val path = dir.resolve("tokens.json")
        FileTokenStore(path).write(Tokens(accessToken = "a"))

        val supportsPosix = path.fileSystem.supportedFileAttributeViews().contains("posix")
        if (!supportsPosix) return // Windows — POSIX not applicable.

        val perms = Files.getPosixFilePermissions(path)
        assertThat(perms).containsExactlyInAnyOrder(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        )
    }

    @Test
    fun `delete removes the file`(@TempDir dir: Path) {
        val path = dir.resolve("tokens.json")
        val store = FileTokenStore(path)
        store.write(Tokens(accessToken = "a"))
        assertThat(Files.exists(path)).isTrue()

        store.delete()

        assertThat(Files.exists(path)).isFalse()
    }

    @Test
    fun `delete is a no-op when no file exists`(@TempDir dir: Path) {
        val store = FileTokenStore(dir.resolve("absent.json"))
        store.delete() // must not throw
    }

    @Test
    fun `read returns null on malformed JSON`(@TempDir dir: Path) {
        val path = dir.resolve("tokens.json")
        Files.writeString(path, "{ this is not valid json")
        val store = FileTokenStore(path)
        assertThat(store.read()).isNull()
    }

    /**
     * SSO-2956 — regression guard: the serialised [Tokens] JSON must carry every
     * persisted field by name and must NOT be an empty object. On the GraalVM
     * native binary a data class with no reflection metadata serialises to `{}`
     * (the login-then-"Not signed in" bug); this JVM guard pins the expected wire
     * shape so a dropped field name is caught cheaply, and pairs with the native
     * proof (`thoryn __diag token-roundtrip`) that the reflect-config entry works
     * in the native image, which a JVM test cannot observe.
     */
    @Test
    fun `serialised tokens JSON carries every field name and is not an empty object`(@TempDir dir: Path) {
        val path = dir.resolve("tokens.json")
        FileTokenStore(path).write(
            Tokens(
                accessToken = "access-1",
                refreshToken = "refresh-1",
                idToken = "id-1",
                tokenType = "Bearer",
                expiresAtEpochSecond = 1_900_000_000L,
                scope = "openid tenant:clients.read",
                issuer = "https://acme.hub.example.test",
                gateway = "https://api.example.test",
                authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                clientId = "client-1",
            ),
        )

        val json = Files.readString(path)

        assertThat(json.replace(Regex("\\s"), "")).isNotEqualTo("{}")
        assertThat(json).contains(
            "\"accessToken\"",
            "\"refreshToken\"",
            "\"idToken\"",
            "\"tokenType\"",
            "\"expiresAtEpochSecond\"",
            "\"scope\"",
            "\"issuer\"",
            "\"gateway\"",
            "\"authMode\"",
            "\"clientId\"",
        )
    }
}
