package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.Tokens
import picocli.CommandLine.Command
import java.nio.file.Files
import java.util.concurrent.Callable

/**
 * `thoryn __diag ...` — SSO-2956. Hidden internal diagnostics, not part of the
 * customer-facing command surface (`hidden = true`, so it never appears in help
 * or completion). Harmless: it touches only a throwaway temp file it creates and
 * deletes, never the real token store or keychain, and writes only synthetic
 * (non-secret) values.
 *
 * Its reason to exist is the SSO-2956 bug class: a Kotlin data class that has no
 * native-image reflection metadata serialises to `{}`, which a plain JVM test
 * cannot catch (the JVM has full reflection). `token-roundtrip` exercises the
 * exact [FileTokenStore] write→read path against the **native binary**, so a
 * regression (a new persisted field, or a dropped reflect-config entry) surfaces
 * as a non-zero exit from the real artefact rather than as a silent empty file
 * in production.
 */
@Command(
    name = "__diag",
    description = ["Internal diagnostics (hidden)."],
    hidden = true,
    subcommands = [
        DiagCommand.TokenRoundtripSubcommand::class,
        DiagCommand.EmptyPostSubcommand::class,
    ],
)
class DiagCommand : Callable<Int> {
    override fun call(): Int {
        System.err.println("Usage: thoryn __diag <subcommand>  (subcommands: token-roundtrip, empty-post)")
        return CommandSupport.EXIT_USAGE
    }

    /**
     * `thoryn __diag token-roundtrip` — write a fully-populated synthetic [Tokens]
     * to a temp file via [FileTokenStore], read it back, and assert every field
     * survived. Prints the on-disk JSON. Exits 0 on success; non-zero if the JSON
     * is empty (`{}`) or any field failed to round-trip.
     */
    @Command(
        name = "token-roundtrip",
        description = ["Round-trip a synthetic Tokens through the file store and assert it is non-empty."],
        hidden = true,
    )
    class TokenRoundtripSubcommand : Callable<Int> {
        override fun call(): Int {
            val tmp = Files.createTempFile("thoryn-diag-tokens", ".json")
            try {
                val store = FileTokenStore(path = tmp)
                val original = Tokens(
                    accessToken = "diag-access-token",
                    refreshToken = "diag-refresh-token",
                    idToken = "diag-id-token",
                    tokenType = "Bearer",
                    expiresAtEpochSecond = 1_900_000_000L,
                    scope = "openid tenant:clients.read",
                    issuer = "https://acme.hub.example.test",
                    gateway = "https://api.example.test",
                    authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS,
                    clientId = "diag-client",
                )
                store.write(original)

                val onDisk = Files.readString(tmp)
                println("on-disk JSON (${onDisk.toByteArray().size} bytes): $onDisk")

                val roundTripped = store.read()
                println("read-back: $roundTripped")

                val problems = mutableListOf<String>()
                if (onDisk.replace(Regex("\\s"), "") == "{}") {
                    problems += "on-disk JSON serialised to an empty object '{}' — native reflection metadata is missing"
                }
                if (roundTripped == null) problems += "read-back returned null"
                if (roundTripped != null && roundTripped != original) {
                    problems += "read-back did not equal the original: $roundTripped"
                }
                // Belt-and-braces: assert a couple of field names actually made it to disk.
                for (field in listOf("accessToken", "refreshToken", "issuer", "clientId")) {
                    if (!onDisk.contains("\"$field\"")) problems += "field '$field' missing from on-disk JSON"
                }

                return if (problems.isEmpty()) {
                    println("OK: Tokens round-tripped with all fields present.")
                    CommandSupport.EXIT_OK
                } else {
                    problems.forEach { System.err.println("FAIL: $it") }
                    CommandSupport.EXIT_IO_ERROR
                }
            } finally {
                runCatching { Files.deleteIfExists(tmp) }
            }
        }
    }

    /**
     * `thoryn __diag empty-post` — SSO-2958. Exercise the exact body-less-POST
     * serialization path that crashed the native binary: serialise an empty
     * request body with the same jackson mapper [ProductApiClient] uses
     * ([ProductApiClient.defaultMapper], `kotlinModule` installed) and assert it
     * emits `{}` without throwing.
     *
     * Two representations are serialised:
     *  1. The **fix** — a Jackson `ObjectNode` (what [ProductApiClient.emptyBody]
     *     now sends). This must serialise to `{}` with no kotlin-reflection.
     *  2. The **old** raw `emptyMap()` (the `kotlin.collections.EmptyMap`
     *     singleton). Before the fix this threw
     *     `KotlinReflectionInternalError: Unresolved class: class kotlin.collections.EmptyMap`
     *     in the native image; with the SSO-2958 `reflect-config.json` entry it now
     *     serialises to `{}` too (defense in depth). A JVM run can't catch the
     *     native failure — this proof matters only on the native binary.
     *
     * Exits 0 when both emit `{}`; non-zero if either throws or emits something else.
     */
    @Command(
        name = "empty-post",
        description = ["Serialise an empty POST body with the ProductApiClient mapper and assert it emits {}."],
        hidden = true,
    )
    class EmptyPostSubcommand : Callable<Int> {
        override fun call(): Int {
            val mapper = ProductApiClient.defaultMapper()
            val problems = mutableListOf<String>()

            // (1) The fix: a Jackson ObjectNode — the representation ProductApiClient.emptyBody() now sends.
            val objectNodeJson = runCatching { mapper.writeValueAsString(mapper.createObjectNode()) }
                .onFailure { problems += "ObjectNode empty body threw ${it::class.qualifiedName}: ${it.message}" }
                .getOrNull()
            println("empty ObjectNode body -> ${objectNodeJson ?: "<threw>"}")
            if (objectNodeJson != null && objectNodeJson.replace(Regex("\\s"), "") != "{}") {
                problems += "ObjectNode empty body serialised to '$objectNodeJson', expected '{}'"
            }

            // (2) Defense-in-depth: the raw kotlin EmptyMap singleton that used to crash the native image.
            val emptyMapJson = runCatching { mapper.writeValueAsString(emptyMap<String, Any?>()) }
                .onFailure { problems += "kotlin.collections.EmptyMap threw ${it::class.qualifiedName}: ${it.message}" }
                .getOrNull()
            println("raw kotlin EmptyMap body -> ${emptyMapJson ?: "<threw>"}")
            if (emptyMapJson != null && emptyMapJson.replace(Regex("\\s"), "") != "{}") {
                problems += "kotlin EmptyMap serialised to '$emptyMapJson', expected '{}'"
            }

            return if (problems.isEmpty()) {
                println("OK: empty POST body serialises to {} without throwing.")
                CommandSupport.EXIT_OK
            } else {
                problems.forEach { System.err.println("FAIL: $it") }
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }
}
