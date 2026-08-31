package com.devnow.thoryn.cli.cmd

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
 * SSO-1552 — shared fixture for the tenant-configuration command tests
 * (`clients`, `federation`, `workspace`, `audit`).
 *
 * Test base for the tenant-config commands:
 *  - spins up a [MockWebServer] standing in for the api-gateway / hub;
 *  - sandboxes the token store to a JUnit @TempDir + forces the plaintext file
 *    store (`THORYN_CI_PLAINTEXT_TOKENS=1`) so no real OS keychain is needed;
 *  - pre-seeds a valid `tokens.json`;
 *  - captures stdout / stderr.
 */
abstract class CommandTestBase {

    @TempDir
    lateinit var tempHome: Path

    protected lateinit var server: MockWebServer
    private val originalUserHome = System.getProperty("user.home")
    private val originalEnvSeam = TokenStoreFactory.environment

    @BeforeEach
    fun setUpBase() {
        server = MockWebServer().also { it.start() }
        System.setProperty("user.home", tempHome.toString())
        TokenStoreFactory.environment = { key ->
            if (key == TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR) "1" else System.getenv(key)
        }
        seedTokens(Tokens(accessToken = "AT-test", refreshToken = "RT-test"))
    }

    @AfterEach
    fun tearDownBase() {
        server.shutdown()
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

    protected fun baseUrl(): String = server.url("/").toString().trimEnd('/')

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

    protected fun noContent(): MockResponse =
        MockResponse().setResponseCode(204)

    protected data class CliResult(val exit: Int, val out: String, val err: String)

    protected fun parseJson(s: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return JsonMapper.builder()
            .addModule(kotlinModule())
            .build()
            .readValue(s, Map::class.java) as Map<String, Any?>
    }
}
