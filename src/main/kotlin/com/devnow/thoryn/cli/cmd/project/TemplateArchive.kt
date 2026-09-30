package com.devnow.thoryn.cli.cmd.project

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.zip.GZIPInputStream

/**
 * SSO-3435 — reads the template repository's tarball (`gh api repos/<owner>/<repo>/tarball`, the default
 * branch) into its regular files, so `thoryn project init` can add them to an existing clone.
 *
 * A minimal ustar/pax reader on the JDK's [GZIPInputStream] — no extra dependency, nothing reflective, safe
 * for the native image. It understands what GitHub's archives contain: a `pax_global_header` (skipped), pax
 * `x` headers and GNU `L` long names (the path of the next entry), the ustar `prefix` field, directories
 * (skipped) and regular files. Symbolic and hard links are skipped: a template never needs one, and writing
 * one into a customer's working tree is not something to do silently.
 *
 * GitHub prefixes every path with one `<owner>-<repo>-<sha>/` directory; it is stripped. A path that is
 * absolute or climbs out with `..` is refused, and the whole archive is capped at [MAX_TOTAL_BYTES].
 */
object TemplateArchive {

    /** One file of the template: its repository-relative path, content and whether git tracks it executable. */
    class Entry(val path: String, val bytes: ByteArray, val executable: Boolean)

    class ArchiveException(message: String) : RuntimeException(message)

    const val MAX_TOTAL_BYTES: Long = 64L * 1024 * 1024
    private const val BLOCK = 512

    fun read(tarGz: ByteArray): List<Entry> {
        val input = try {
            GZIPInputStream(ByteArrayInputStream(tarGz))
        } catch (ex: java.io.IOException) {
            throw ArchiveException("the template archive is not gzip data")
        }
        return input.use { readTar(it) }
    }

    private fun readTar(input: InputStream): List<Entry> {
        val entries = mutableListOf<Entry>()
        var total = 0L
        var nextPath: String? = null
        val header = ByteArray(BLOCK)
        while (true) {
            if (!readBlock(input, header)) break
            if (header.all { it == 0.toByte() }) break
            val size = parseSize(header)
            if (size < 0) throw ArchiveException("the template archive has an unreadable entry size")
            total += size
            if (total > MAX_TOTAL_BYTES) throw ArchiveException("the template archive is larger than $MAX_TOTAL_BYTES bytes")
            val type = header[156].toInt().toChar()
            val data = readData(input, size)
            when (type) {
                'g' -> Unit
                'x' -> nextPath = paxPath(data) ?: nextPath
                'L' -> nextPath = data.toString(Charsets.UTF_8).trimEnd('\u0000')
                '0', '\u0000', '7' -> {
                    val raw = nextPath ?: headerPath(header)
                    nextPath = null
                    val path = stripRoot(raw) ?: continue
                    val mode = octal(header, 100, 8)
                    entries += Entry(path, data, executable = mode and 0b001_000_000 != 0L)
                }
                else -> nextPath = null // directories, links, devices: not template files
            }
        }
        return entries
    }

    private fun headerPath(header: ByteArray): String {
        val name = cString(header, 0, 100)
        val ustar = cString(header, 257, 6).startsWith("ustar")
        val prefix = if (ustar) cString(header, 345, 155) else ""
        return if (prefix.isEmpty()) name else "$prefix/$name"
    }

    /** Drop GitHub's single top-level directory; null for the directory itself. Refuses unsafe paths. */
    internal fun stripRoot(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.startsWith("/") || trimmed.matches(Regex("^[A-Za-z]:.*"))) throw ArchiveException("the template archive has an absolute path")
        val parts = trimmed.split('/').filter { it.isNotEmpty() && it != "." }
        if (parts.any { it == ".." }) throw ArchiveException("the template archive has a path that leaves the repository")
        if (parts.size < 2) return null
        return parts.drop(1).joinToString("/")
    }

    private fun paxPath(data: ByteArray): String? {
        // Records: "<len> <key>=<value>\n"
        val text = data.toString(Charsets.UTF_8)
        var i = 0
        var path: String? = null
        while (i < text.length) {
            val space = text.indexOf(' ', i)
            if (space < 0) break
            val len = text.substring(i, space).toIntOrNull() ?: break
            if (len <= 0 || i + len > text.length) break
            val record = text.substring(space + 1, i + len).trimEnd('\n')
            val eq = record.indexOf('=')
            if (eq > 0 && record.substring(0, eq) == "path") path = record.substring(eq + 1)
            i += len
        }
        return path
    }

    private fun parseSize(header: ByteArray): Long {
        // GNU base-256 for large files: high bit of the first byte set.
        if (header[124].toInt() and 0x80 != 0) {
            var v = 0L
            for (k in 125 until 136) v = (v shl 8) or (header[k].toLong() and 0xff)
            return v
        }
        return octal(header, 124, 12)
    }

    private fun octal(header: ByteArray, offset: Int, length: Int): Long {
        val s = cString(header, offset, length).trim()
        if (s.isEmpty()) return 0
        return s.toLongOrNull(8) ?: -1
    }

    private fun cString(header: ByteArray, offset: Int, length: Int): String {
        var end = offset
        while (end < offset + length && header[end] != 0.toByte()) end++
        return String(header, offset, end - offset, Charsets.UTF_8)
    }

    private fun readBlock(input: InputStream, block: ByteArray): Boolean {
        var read = 0
        while (read < block.size) {
            val n = input.read(block, read, block.size - read)
            if (n < 0) {
                if (read == 0) return false
                throw ArchiveException("the template archive is truncated")
            }
            read += n
        }
        return true
    }

    private fun readData(input: InputStream, size: Long): ByteArray {
        val data = ByteArray(size.toInt())
        var read = 0
        while (read < data.size) {
            val n = input.read(data, read, data.size - read)
            if (n < 0) throw ArchiveException("the template archive is truncated")
            read += n
        }
        val padding = ((BLOCK - (size % BLOCK)) % BLOCK).toInt()
        var skipped = 0
        val sink = ByteArray(BLOCK)
        while (skipped < padding) {
            val n = input.read(sink, 0, padding - skipped)
            if (n < 0) throw ArchiveException("the template archive is truncated")
            skipped += n
        }
        return data
    }
}
