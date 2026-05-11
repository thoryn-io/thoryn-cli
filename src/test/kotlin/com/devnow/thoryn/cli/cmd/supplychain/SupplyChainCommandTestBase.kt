package com.devnow.thoryn.cli.cmd.supplychain

import com.devnow.thoryn.cli.ThorynMain
import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.Tokens
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.io.TempDir
import picocli.CommandLine
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path

/**
 * Shared fixture for every `thoryn supply-chain ...` subcommand test.
 *
 * - Spins up a [MockWebServer] standing in for the api-gateway.
 * - Sandboxes the token store: rewires `user.home` to a JUnit @TempDir and
 *   forces the plaintext file store (`THORYN_CI_PLAINTEXT_TOKENS=1`) so we
 *   don't need a real OS keychain on CI.
 * - Pre-seeds a valid `tokens.json` with a known bearer.
 * - Captures stdout / stderr for assertions.
 */
abstract class SupplyChainCommandTestBase {

    @TempDir
    lateinit var tempHome: Path

    protected lateinit var gateway: MockWebServer
    private val originalUserHome = System.getProperty("user.home")
    private val originalEnvSeam = TokenStoreFactory.environment

    @BeforeEach
    fun setUpBase() {
        gateway = MockWebServer().also { it.start() }
        System.setProperty("user.home", tempHome.toString())
        TokenStoreFactory.environment = { key ->
            if (key == TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR) "1" else System.getenv(key)
        }
        // Pre-seed the token file so commands don't bail with "Not signed in".
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test"))
    }

    @AfterEach
    fun tearDownBase() {
        gateway.shutdown()
        System.setProperty("user.home", originalUserHome ?: "")
        TokenStoreFactory.environment = originalEnvSeam
    }

    protected fun clearTokens() {
        FileTokenStore().delete()
    }

    protected fun seedTokens(tokens: Tokens) {
        Files.createDirectories(tempHome.resolve(".config/thoryn"))
        FileTokenStore().write(tokens)
    }

    protected fun gatewayUrl(): String = gateway.url("/").toString().trimEnd('/')

    protected fun runCli(vararg args: String): CliResult {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val originalOut = System.out
        val originalErr = System.err
        try {
            System.setOut(PrintStream(out, true, Charsets.UTF_8))
            System.setErr(PrintStream(err, true, Charsets.UTF_8))
            val exit = CommandLine(ThorynMain()).execute(*args)
            return CliResult(exit, out.toString(Charsets.UTF_8), err.toString(Charsets.UTF_8))
        } finally {
            System.setOut(originalOut)
            System.setErr(originalErr)
        }
    }

    protected fun jsonResponse(status: Int, body: String): MockResponse =
        MockResponse()
            .setResponseCode(status)
            .setHeader("Content-Type", "application/json")
            .setBody(body)

    protected fun pdfResponse(bytes: ByteArray): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/pdf")
            .setBody(okio.Buffer().write(bytes))

    protected data class CliResult(val exit: Int, val out: String, val err: String)

    protected fun parseJson(s: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return JsonMapper.builder()
            .addModule(kotlinModule())
            .build()
            .readValue(s, Map::class.java) as Map<String, Any?>
    }
}
