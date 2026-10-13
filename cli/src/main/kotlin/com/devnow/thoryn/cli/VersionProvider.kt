package com.devnow.thoryn.cli

import picocli.CommandLine.IVersionProvider
import java.util.Properties

/**
 * Supplies the string printed by `thoryn --version` (SSO-2953).
 *
 * The version is read at runtime from the build-filtered classpath resource
 * `version.properties`, into which Maven substitutes `${project.version}` — the
 * `${revision}` property in the POM. Local/dev builds fall back to the
 * `0.0.1-SNAPSHOT` default; the tag-driven release workflow injects the real
 * release version via `-Drevision=<version>`, so the released binary reports the
 * release rather than the SNAPSHOT default (the bug this replaces was a hardcoded
 * `version = ["thoryn 0.0.1-SNAPSHOT"]` literal on the @Command annotation).
 */
class VersionProvider : IVersionProvider {
    override fun getVersion(): Array<String> = arrayOf(render(readVersion()))

    companion object {
        private const val RESOURCE = "/version.properties"
        private const val KEY = "thoryn.version"

        /** Format the version line exactly as `--version` prints it. */
        fun render(version: String): String = "thoryn $version"

        /**
         * Read the build-stamped version from the classpath. Returns `"unknown"`
         * defensively when the resource is absent or was somehow not filtered
         * (i.e. still carries the literal `${...}` placeholder).
         */
        fun readVersion(): String {
            val raw = VersionProvider::class.java.getResourceAsStream(RESOURCE)?.use { stream ->
                Properties().apply { load(stream) }.getProperty(KEY)
            }
            return raw?.takeIf { it.isNotBlank() && !it.contains("\${") } ?: "unknown"
        }
    }
}
