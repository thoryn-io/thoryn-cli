package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.auth.FileTokenStore
import com.devnow.thoryn.cli.auth.TokenStore
import com.devnow.thoryn.cli.config.ThorynConfig
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.Callable

/**
 * `thoryn clients list` — read the access token from the local store and call
 * `GET /clients` on the gateway.
 *
 * Smoke test for the full chain CLI → gateway → product-api. Returns the raw
 * JSON body to stdout so it composes with `jq` etc.
 */
@Command(
    name = "clients",
    description = ["Manage OAuth clients in your tenant."],
    mixinStandardHelpOptions = true,
    subcommands = [ClientsCommand.ListSubcommand::class],
)
class ClientsCommand : Callable<Int> {

    override fun call(): Int {
        // Top-level `thoryn clients` with no subcommand — print usage and exit.
        System.err.println("Usage: thoryn clients <subcommand>")
        System.err.println("Subcommands: list")
        return 64
    }

    @Command(
        name = "list",
        description = ["List OAuth clients in your tenant."],
        mixinStandardHelpOptions = true,
    )
    class ListSubcommand : Callable<Int> {

        @Option(
            names = ["--gateway"],
            description = ["Override the gateway base URL (default: \${DEFAULT-VALUE})."],
            defaultValue = ThorynConfig.DEFAULT_GATEWAY,
        )
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        private val tokenStore: TokenStore = FileTokenStore()
        private val http: HttpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()

        override fun call(): Int {
            val tokens = tokenStore.read()
            if (tokens == null) {
                System.err.println("Not signed in. Run `thoryn login` first.")
                return 1
            }

            val request = HttpRequest.newBuilder()
                .uri(URI.create("${gateway.trimEnd('/')}/clients"))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer ${tokens.accessToken}")
                .header("Accept", "application/json")
                .GET()
                .build()

            return try {
                val response = http.send(request, HttpResponse.BodyHandlers.ofString())
                println(response.body())
                if (response.statusCode() in 200..299) 0 else 2
            } catch (e: Exception) {
                System.err.println("Request failed: ${e.message}")
                3
            }
        }
    }
}
