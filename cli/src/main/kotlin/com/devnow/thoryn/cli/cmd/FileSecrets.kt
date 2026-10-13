package com.devnow.thoryn.cli.cmd

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission

/**
 * SSO-1552 — write a secret to a file with owner-only permissions.
 *
 * Mirrors [com.devnow.thoryn.cli.auth.FileTokenStore]'s `0600` handling: on
 * POSIX file systems the file is created `rw-------` so a secret written to
 * `--secret-file` is not group/world-readable. No-op chmod on Windows (ACL
 * based, not POSIX bits) — the file still gets written.
 */
internal object FileSecrets {

    /**
     * Write [content] (plus a trailing newline so the file is shell-friendly)
     * to [file], truncating any existing content, then tighten permissions to
     * owner-only on POSIX systems.
     */
    fun writeOwnerOnly(file: File, content: String) {
        val path = file.toPath()
        path.parent?.let { Files.createDirectories(it) }
        Files.writeString(
            path,
            content + "\n",
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
        applyOwnerOnlyPermissions(path)
    }

    private fun applyOwnerOnlyPermissions(path: Path) {
        val supportsPosix = path.fileSystem.supportedFileAttributeViews().contains("posix")
        if (!supportsPosix) return
        Files.setPosixFilePermissions(
            path,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        )
    }
}
