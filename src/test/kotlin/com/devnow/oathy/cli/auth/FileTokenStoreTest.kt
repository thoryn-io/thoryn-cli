package com.devnow.oathy.cli.auth

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
}
