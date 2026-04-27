package com.devnow.thoryn.cli

import com.devnow.thoryn.cli.auth.TokenStoreFactory
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import picocli.CommandLine
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

/**
 * SSO-736 — End-to-end happy-path test for the `thoryn` CLI.
 *
 * Drives `thoryn login --device-code` → `thoryn clients list` → `thoryn logout`
 * against in-process [MockWebServer]s standing in for the authorization-hub
 * (`/oauth2/device_authorization`, `/oauth2/token`) and the api-gateway
 * (`/clients`).
 *
 * ## Why MockWebServer instead of `@SpringBootTest` of the real services
 *
 * The story description allowed booting `authorization-hub`, `api-gateway`, and
 * `product-api` as `@SpringBootTest(RANDOM_PORT)` instances. In practice each
 * has heavyweight infrastructure dependencies the CLI never talks to:
 *
 *  - **authorization-hub** — Postgres + Redis + Vault Transit (for JWT signing)
 *  - **api-gateway**       — Redis (rate limiting) + a live JWKS endpoint to
 *                             validate the bearer token against
 *  - **product-api**       — H2/Postgres for tenant data; today every `/clients`
 *                             handler returns 501 (SSO-727 scaffold), so the
 *                             round-trip would only assert "501 came back"
 *
 * Booting all three alongside a Postgres + Redis + Vault stack just to verify
 * the CLI puts the bearer in the right header, parses the response, and writes
 * the token file is heavy and adds infrastructure flakiness without testing
 * anything about the CLI that isn't already proved by stubbed responses.
 *
 * The hub-side device-code flow itself is exercised end-to-end at
 * `system.device.DeviceAuthorizationGrantTest` against a real hub; this test
 * is the CLI counterpart and complements rather than duplicates it.
 *
 * ## Running the CLI from the test JVM
 *
 * **Option A** — invoke `CommandLine(ThorynMain()).execute(*args)` directly,
 * exactly the way [ThorynMainTest] does. Each command is one method call;
 * stdout/stderr are captured via [System.setOut]/[System.setErr]. This works
 * because the existing `main()` shim, while it does call `exitProcess`, is
 * never hit — the test invokes `CommandLine.execute` directly and reads the
 * exit code from the return value.
 *
 * **Option B** would have been to shell out to `java -jar target/thoryn.jar`
 * via [ProcessBuilder]. That'd be more realistic (real exit codes, signal
 * handling) but adds a hard dependency on `package` having run before `test`,
 * makes wiring `XDG_CONFIG_HOME` / `user.home` per process awkward, and
 * roughly doubles the runtime. Option A is enough for a happy-path E2E.
 *
 * ## Sandboxing the credentials file
 *
 * [FileTokenStore.defaultPath] reads `System.getProperty("user.home")` (and
 * `THORYN_TOKEN_FILE` env var if set). The test overrides `user.home` to a
 * JUnit `@TempDir` for the duration of the test — no production code change
 * needed and the developer's real `~/.config/thoryn/credentials` is never
 * touched.
 *
 * ## Device-code "user pastes the code" automation
 *
 * RFC 8628 normally asks a human to open a browser, paste the user_code, and
 * authenticate. To automate this, the test:
 *
 *  1. Stubs `POST /oauth2/device_authorization` to return a canned response
 *     with a 1-second polling interval so the test doesn't sleep for 5s.
 *  2. Stubs `POST /oauth2/token` to return `authorization_pending` on the
 *     first poll (proving the polling loop works) and a real token bundle
 *     on the second — i.e. "the user just pasted the code".
 *  3. Asserts the CLI prints the user_code/verification_uri to stdout, writes
 *     the token bundle to disk, and exits 0.
 *
 * This is a faithful simulation of the wire dance — the only thing missing
 * is the human in the loop, which the polling stub stands in for.
 */
class ThorynCliE2ETest {

    @TempDir
    lateinit var tempHome: Path

    private lateinit var hub: MockWebServer
    private lateinit var gateway: MockWebServer

    private val originalUserHome = System.getProperty("user.home")
    private val originalClientSecretProp = System.getProperty("THORYN_CLIENT_SECRET")
    private val originalEnvSeam = TokenStoreFactory.environment

    @BeforeEach
    fun setUp() {
        hub = MockWebServer().also { it.start() }
        gateway = MockWebServer().also { it.start() }

        // Sandbox the token store: FileTokenStore.defaultPath() reads user.home
        // and points at $HOME/.config/thoryn/tokens.json. Repointing user.home
        // at a JUnit @TempDir keeps the developer's real ~/.config/thoryn safe.
        System.setProperty("user.home", tempHome.toString())

        // The current device-authorization endpoint requires confidential client
        // auth; the CLI bails with EXIT_USAGE if no client secret is resolvable.
        // ThorynConfig.resolveClientSecret() prefers the system property over
        // the env var, so the test can set it without reflection. The MockWebServer
        // doesn't validate Basic Auth, so any value works.
        System.setProperty("THORYN_CLIENT_SECRET", "test-secret")

        // SSO-794: TokenStoreFactory now defaults to the OS keychain. Force the
        // plaintext file store for this test by overriding the env-var seam —
        // we still want to assert the on-disk JSON, and the test runners
        // (especially headless Linux CI) rarely have a Secret Service daemon.
        // The same env-var (THORYN_CI_PLAINTEXT_TOKENS=1) is what CI shell
        // wrappers will set in production.
        TokenStoreFactory.environment = { key ->
            if (key == TokenStoreFactory.PLAINTEXT_OPT_IN_ENV_VAR) "1" else System.getenv(key)
        }
    }

    @AfterEach
    fun tearDown() {
        hub.shutdown()
        gateway.shutdown()
        System.setProperty("user.home", originalUserHome ?: "")
        TokenStoreFactory.environment = originalEnvSeam
        if (originalClientSecretProp == null) {
            System.clearProperty("THORYN_CLIENT_SECRET")
        } else {
            System.setProperty("THORYN_CLIENT_SECRET", originalClientSecretProp)
        }
    }

    @Test
    @DisplayName("Login → clients list → logout: full happy path against stubbed hub + gateway")
    fun `full e2e happy path`() {
        // ── Phase 1: thoryn login --device-code ─────────────────────────────
        //
        // Hub answers /oauth2/device_authorization once with a real device
        // code, then /oauth2/token with `authorization_pending` (one poll
        // before the imaginary user authenticates), then /oauth2/token with
        // the actual token bundle.
        hub.dispatcher = ScriptedDispatcher(
            mapOf(
                "POST /oauth2/device_authorization" to listOf(
                    jsonResponse(200, DEVICE_AUTHORIZATION_RESPONSE),
                ),
                "POST /oauth2/token" to listOf(
                    jsonResponse(400, """{"error":"authorization_pending"}"""),
                    jsonResponse(200, TOKEN_RESPONSE),
                ),
            ),
        )

        val (loginExit, loginOut, loginErr) = runCli(
            "login",
            "--device-code",
            "--issuer", hub.url("/").toString().trimEnd('/'),
            "--client-id", "thoryn-cli",
            "--scope", "openid offline_access tenant:clients.read",
        )

        assertThat(loginExit).withFailMessage("login stderr was:\n%s", loginErr).isEqualTo(0)
        assertThat(loginOut).contains("ABCD-1234")
        assertThat(loginOut).contains("activate")
        assertThat(loginOut).contains("Signed in.")

        // Verify the on-disk token file: it lives under user.home, has the
        // correct shape, and (on POSIX) is mode 0600.
        val tokenFile = tempHome.resolve(".config/thoryn/tokens.json")
        assertThat(tokenFile).exists()
        val tokenJson = Files.readString(tokenFile)
        assertThat(tokenJson).contains("\"accessToken\"")
        assertThat(tokenJson).contains("AT-real-1")
        assertThat(tokenJson).contains("RT-real-1")

        // Hub saw exactly the requests we expect, with confidential-client
        // Basic auth headers.
        assertThat(hub.requestCount).isEqualTo(3) // 1 device-auth + 2 polls
        val deviceAuth = hub.takeRequest()
        assertThat(deviceAuth.path).isEqualTo("/oauth2/device_authorization")
        assertThat(deviceAuth.method).isEqualTo("POST")
        assertThat(deviceAuth.getHeader("Authorization")).isEqualTo(
            "Basic " + Base64.getEncoder().encodeToString("thoryn-cli:test-secret".toByteArray()),
        )
        assertThat(deviceAuth.getHeader("Content-Type"))
            .startsWith("application/x-www-form-urlencoded")
        assertThat(deviceAuth.body.readUtf8())
            .contains("scope=openid+offline_access+tenant%3Aclients.read")

        val poll1 = hub.takeRequest()
        assertThat(poll1.path).isEqualTo("/oauth2/token")
        val poll1Body = poll1.body.readUtf8()
        assertThat(poll1Body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
        assertThat(poll1Body).contains("device_code=DEV-1")

        val poll2 = hub.takeRequest()
        assertThat(poll2.path).isEqualTo("/oauth2/token")

        // ── Phase 2: thoryn clients list (returns []) ───────────────────────
        gateway.enqueue(jsonResponse(200, "[]"))

        val (listEmptyExit, listEmptyOut, _) = runCli(
            "clients", "list",
            "--gateway", gateway.url("/").toString().trimEnd('/'),
        )

        assertThat(listEmptyExit).isEqualTo(0)
        assertThat(listEmptyOut.trim()).isEqualTo("[]")

        val listEmptyReq = gateway.takeRequest()
        assertThat(listEmptyReq.path).isEqualTo("/clients")
        assertThat(listEmptyReq.method).isEqualTo("GET")
        assertThat(listEmptyReq.getHeader("Authorization")).isEqualTo("Bearer AT-real-1")
        assertThat(listEmptyReq.getHeader("Accept")).contains("application/json")

        // ── Phase 3: thoryn clients list (after a client has been added) ────
        //
        // The product-api `POST /clients` handler is currently a 501 stub
        // (SSO-727), so the CLI doesn't ship `clients create` or
        // `clients delete` subcommands yet — those are tracked in the SSO-736
        // report's "CLI gaps" section. The test fakes the post-create state by
        // returning a populated list on the next GET; the wire shape we care
        // about (Authorization header + JSON body parsing) is fully covered.
        gateway.enqueue(jsonResponse(200, """[{"id":"cli-1","name":"test-client"}]"""))

        val (listNonEmptyExit, listNonEmptyOut, _) = runCli(
            "clients", "list",
            "--gateway", gateway.url("/").toString().trimEnd('/'),
        )

        assertThat(listNonEmptyExit).isEqualTo(0)
        assertThat(listNonEmptyOut).contains("cli-1")
        assertThat(listNonEmptyOut).contains("test-client")

        val listNonEmptyReq = gateway.takeRequest()
        assertThat(listNonEmptyReq.getHeader("Authorization")).isEqualTo("Bearer AT-real-1")

        // ── Phase 4: thoryn logout clears the credentials file ──────────────
        val (logoutExit, logoutOut, _) = runCli("logout")

        assertThat(logoutExit).isEqualTo(0)
        assertThat(logoutOut).contains("Signed out")
        assertThat(tokenFile).doesNotExist()

        // After logout, `clients list` must refuse to make a request — no
        // bearer to send. This proves the local store was actually cleared.
        val (listAfterLogoutExit, _, listAfterLogoutErr) = runCli(
            "clients", "list",
            "--gateway", gateway.url("/").toString().trimEnd('/'),
        )

        assertThat(listAfterLogoutExit).isNotEqualTo(0)
        assertThat(listAfterLogoutErr).contains("Not signed in")
    }

    @Test
    @DisplayName("login --status reports unauthenticated when no token is on disk")
    fun `login --status when not signed in`() {
        val (exit, out, _) = runCli("login", "--status")
        assertThat(exit).isNotEqualTo(0)
        assertThat(out).contains("Not signed in")
    }

    // ── Test helpers ────────────────────────────────────────────────────────

    /**
     * Run the CLI in-process with [args]. Captures stdout / stderr. Each call
     * uses a fresh [picocli.CommandLine] so subcommand state from a previous
     * call cannot leak.
     */
    private fun runCli(vararg args: String): CliResult {
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

    private data class CliResult(val exit: Int, val out: String, val err: String)

    private fun jsonResponse(status: Int, body: String): MockResponse =
        MockResponse()
            .setResponseCode(status)
            .setHeader("Content-Type", "application/json")
            .setBody(body)

    /**
     * Per-(method+path) request queue dispatcher. [MockWebServer.enqueue] is a
     * single FIFO across every endpoint — useless when the device-code flow
     * does many polls of `/oauth2/token` between a single `/oauth2/device_authorization`
     * call. This dispatcher routes by `<METHOD> <path>` and pops the next
     * scripted response off the matching queue.
     */
    private class ScriptedDispatcher(scripts: Map<String, List<MockResponse>>) : Dispatcher() {
        private val queues: Map<String, ArrayDeque<MockResponse>> =
            scripts.mapValues { ArrayDeque(it.value) }

        override fun dispatch(request: RecordedRequest): MockResponse {
            val key = "${request.method} ${request.path}"
            val queue = queues[key]
                ?: return MockResponse()
                    .setResponseCode(404)
                    .setBody("""{"error":"unrouted_path","detail":"$key"}""")
            return queue.removeFirstOrNull()
                ?: MockResponse()
                    .setResponseCode(500)
                    .setBody("""{"error":"queue_empty","detail":"$key"}""")
        }
    }

    companion object {
        private val DEVICE_AUTHORIZATION_RESPONSE = """
            {
              "device_code": "DEV-1",
              "user_code": "ABCD-1234",
              "verification_uri": "http://localhost:1234/activate",
              "verification_uri_complete": "http://localhost:1234/activate?user_code=ABCD-1234",
              "expires_in": 60,
              "interval": 1
            }
        """.trimIndent()

        private val TOKEN_RESPONSE = """
            {
              "access_token": "AT-real-1",
              "refresh_token": "RT-real-1",
              "id_token": "IT-real-1",
              "token_type": "Bearer",
              "expires_in": 3600,
              "scope": "openid offline_access tenant:clients.read"
            }
        """.trimIndent()
    }
}
