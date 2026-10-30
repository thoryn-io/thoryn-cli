package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.missingEnv
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.resolveIdOrNull
import com.devnow.thoryn.cli.cmd.EnvironmentCommand.Companion.selectedEnvSlug
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import java.io.File
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn env test-identity ...` (SSO-4086) — **ephemeral sandbox test identities**: the one account an application's
 * own CI identity may mint in the tenant (oauthy ADR `2026-10-30-ephemeral-sandbox-test-identities.md`). A disposable,
 * email-verified user with a synthetic `@sandbox.thoryn.invalid` address and a server-generated password that is returned
 * **once**, living `PT2H` by default (`PT5M`..`PT24H`), erased on expiry or on `revoke` — **in a sandbox only**. The
 * production plane is refused by the API (`403 not_a_sandbox`), which this command passes through unchanged: the
 * sandbox-only rule is the API's refusal, not the command's name (product owner, 2026-10-30).
 *
 * Under the `env` noun beside `thoryn env test-emails`, with the same environment resolution: `--env <slug>` or the
 * selected environment (`thoryn env use`), resolved to the environment's UUID for the path. A thin wrapper over
 * product-api's `/api/v1/environments/{envId}/test-identities` (SSO-4085, #4297). Scopes:
 * `tenant:test-identities.write` (create, revoke) and `tenant:test-identities.read` (list) — granted to the `cli` login
 * client by oauthy hub V216, so a workspace admin's own `thoryn login` holds them and can mint for a local run too.
 *
 * Subcommands:
 *  - `create [--env] [--lifetime PT2H] [--label <x>] [--output table|json|env|github-env]` — mint; prints the password ONCE
 *  - `list [--env]`   — the sandbox's identities, never a password
 *  - `revoke <id> [--env]` — erase now (idempotent on an expired identity)
 *
 * **The password leaves this process exactly once, in the output the user chose** ([CreateSub]): the human table prints
 * it with a one-line warning, `json` prints the response, `env` prints `export KEY=value` lines (the value shell-quoted),
 * `github-env` prints `::add-mask::<password>` FIRST and then appends the three variables to `$GITHUB_ENV`. It is never
 * echoed on `list` / `revoke`, never logged, and never part of an error message.
 *
 * **Not a provisioning kind.** A test identity is an imperative mint with an expiry, not a fact the tenant keeps true:
 * there is no `kind: testIdentity`, `provision import` never emits one, `provision plan` never diffs one (ADR §7).
 */
@Command(
    name = "test-identity",
    description = ["Mint, list and revoke disposable test accounts in a sandbox environment (never production)."],
    mixinStandardHelpOptions = true,
    subcommands = [
        EnvironmentTestIdentityCommand.CreateSub::class,
        EnvironmentTestIdentityCommand.ListSub::class,
        EnvironmentTestIdentityCommand.RevokeSub::class,
    ],
)
class EnvironmentTestIdentityCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn env test-identity <create|list|revoke>")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn env test-identity create [--env <slug>] [--lifetime PT2H] [--label <text>] [--output table|json|env|github-env]`. */
    @Command(
        name = "create",
        description = ["Mint a disposable test identity in a sandbox; its password is shown ONCE, in the output you choose."],
        mixinStandardHelpOptions = true,
    )
    class CreateSub : Callable<Int> {

        @Option(names = ["--env"], description = ["Environment slug — a sandbox (default: the selected environment; see `thoryn env use`)."])
        var env: String? = null

        @Option(names = ["--lifetime"], description = ["ISO-8601 duration the identity lives, PT5M..PT24H (default: PT2H; a local developer's day is PT24H)."])
        var lifetime: String? = null

        @Option(names = ["--label"], description = ["Up to 64 characters of letters, digits, '.', '_' or '-', shown in the list and the audit row (CI passes its run id)."])
        var label: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(
            names = ["--output"],
            description = [
                "Output format: table (default: a record plus the password with a warning) | json (the response) | " +
                    "env (`export THORYN_TEST_IDENTITY_ID=… THORYN_TEST_USER_EMAIL=… THORYN_TEST_USER_PASSWORD=…` for `eval`) | " +
                    "github-env (prints `::add-mask::<password>` first, then appends the three to \$GITHUB_ENV).",
            ],
        )
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = parseCreateOutput(outputRaw) ?: return CommandSupport.EXIT_USAGE
            // `github-env` fails BEFORE the mint when $GITHUB_ENV is not set: an identity minted and then lost would still
            // count against the sandbox's cap and its password would have nowhere to go.
            val githubEnv = if (format == CreateOutput.GITHUB_ENV) {
                environment("GITHUB_ENV")?.takeIf { it.isNotBlank() } ?: run {
                    System.err.println("Error: --output github-env appends to the file \$GITHUB_ENV names, and \$GITHUB_ENV is not set.")
                    System.err.println("GitHub Actions sets it on every step; outside Actions use --output env (for `eval`) or --output json.")
                    return CommandSupport.EXIT_USAGE
                }
            } else {
                null
            }
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val targetSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
            val envId = resolveIdOrNull(client, targetSlug, format.structured ?: OutputFormat.TABLE, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            val body = linkedMapOf<String, Any?>()
            lifetime?.trim()?.takeIf { it.isNotEmpty() }?.let { body["lifetime"] = it }
            label?.trim()?.takeIf { it.isNotEmpty() }?.let { body["label"] = it }
            return try {
                val minted = client.createTestIdentity(envId, body)
                when (format) {
                    CreateOutput.TABLE -> printMinted(minted, targetSlug)
                    CreateOutput.JSON -> Printers.json(minted)
                    CreateOutput.YAML -> Printers.yaml(minted)
                    CreateOutput.ENV -> printExports(minted)
                    CreateOutput.GITHUB_ENV -> {
                        val exit = appendToGithubEnv(minted, File(githubEnv!!))
                        if (exit != CommandSupport.EXIT_OK) return exit
                        System.out.println(
                            "Minted test identity ${minted["id"]?.asString()} (${minted["email"]?.asString()}) in environment '$targetSlug', " +
                                "expires ${minted["expiresAt"]?.asString()}; THORYN_TEST_IDENTITY_ID, THORYN_TEST_USER_EMAIL and " +
                                "THORYN_TEST_USER_PASSWORD appended to \$GITHUB_ENV (the password is masked in the job log).",
                        )
                    }
                }
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderProblem(format.structured ?: OutputFormat.TABLE, ex, SCOPE_WRITE, targetSlug)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** The human output: the record, then the password once, flagged as the one time it is shown. */
        private fun printMinted(minted: JsonNode, slug: String, out: PrintStream = System.out) {
            Printers.record(
                listOf(
                    "id" to minted["id"]?.asString(),
                    "email" to minted["email"]?.asString(),
                    "emailVerified" to (minted["emailVerified"]?.asBoolean() ?: true),
                    "environment" to (minted["environment"]?.asString() ?: slug),
                    "label" to minted["label"]?.asString(),
                    "createdAt" to minted["createdAt"]?.asString(),
                    "expiresAt" to minted["expiresAt"]?.asString(),
                    "mintedBy" to minted["mintedBy"]?.asString(),
                ),
                out,
            )
            out.println()
            out.println("Password (shown ONCE — it is not listed, not audited and not logged; copy it now):")
            out.println("  ${minted["password"]?.asString() ?: ""}")
        }

        /** `--output env`: three `export` lines, every value single-quoted for `eval "$(…)"`. */
        private fun printExports(minted: JsonNode, out: PrintStream = System.out) {
            variables(minted).forEach { (k, v) -> out.println("export $k=${shellQuote(v)}") }
        }

        /** `--output github-env`: the mask line FIRST (so the password never appears unmasked in the log), then the file. */
        private fun appendToGithubEnv(minted: JsonNode, file: File, out: PrintStream = System.out): Int {
            val password = minted["password"]?.asString().orEmpty()
            out.println("::add-mask::$password")
            out.flush()
            return try {
                file.appendText(variables(minted).joinToString("") { (k, v) -> githubEnvLine(k, v) })
                CommandSupport.EXIT_OK
            } catch (ex: Exception) {
                System.err.println("Error: could not append to \$GITHUB_ENV (${file.path}): ${ex.message ?: ex.javaClass.simpleName}")
                System.err.println("The identity ${minted["id"]?.asString()} was minted; revoke it with `thoryn env test-identity revoke ${minted["id"]?.asString()}`.")
                CommandSupport.EXIT_IO_ERROR
            }
        }
    }

    /** `thoryn env test-identity list [--env <slug>]` — live and expired-not-yet-purged identities; never a password. */
    @Command(name = "list", description = ["List a sandbox's test identities (live and expired-not-yet-purged); never shows a password."], mixinStandardHelpOptions = true)
    class ListSub : Callable<Int> {

        @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
        var env: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val targetSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
            val envId = resolveIdOrNull(client, targetSlug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            return try {
                val listed = client.listTestIdentities(envId)
                CommandSupport.emitList(format, withoutPasswords(listed), LIST_HEADERS, rowMapper = ::row)
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderProblem(format, ex, SCOPE_READ, targetSlug)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** `thoryn env test-identity revoke <id> [--env <slug>]` — erase the account now and sever its sessions. */
    @Command(name = "revoke", description = ["Revoke a test identity now: the account is erased and its sessions severed (idempotent on an expired one)."], mixinStandardHelpOptions = true)
    class RevokeSub : Callable<Int> {

        @Parameters(index = "0", description = ["Test-identity id (see `thoryn env test-identity list`, or THORYN_TEST_IDENTITY_ID from `create`)."])
        lateinit var id: String

        @Option(names = ["--env"], description = ["Environment slug (default: the selected environment; see `thoryn env use`)."])
        var env: String? = null

        @Option(names = ["--gateway"], defaultValue = ThorynConfig.DEFAULT_GATEWAY)
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        internal var store: SelectedWorkspaceStore = SelectedWorkspaceStore()

        override fun call(): Int {
            val format = CommandSupport.parseFormat(outputRaw) ?: return CommandSupport.EXIT_USAGE
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = CommandSupport.gatewayClient(gateway, tokens, applyEnvironment = false)
            val targetSlug = env?.trim()?.takeIf { it.isNotEmpty() } ?: selectedEnvSlug(store) ?: return missingEnv()
            val envId = resolveIdOrNull(client, targetSlug, format, gateway) ?: return CommandSupport.EXIT_HTTP_ERROR
            val target = id.trim()
            return try {
                client.revokeTestIdentity(envId, target)
                CommandSupport.emitValue(
                    format,
                    mapOf("id" to target, "environment" to targetSlug, "status" to "revoked"),
                    "Revoked test identity $target in environment '$targetSlug': the account is erased and its sessions are severed.",
                )
                CommandSupport.EXIT_OK
            } catch (ex: ProductApiException) {
                renderProblem(format, ex, SCOPE_WRITE, targetSlug)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }
    }

    /** The `create` output modes: the three structured ones plus the two secret-delivery shapes of ADR §7. */
    internal enum class CreateOutput(val structured: OutputFormat?) {
        TABLE(OutputFormat.TABLE),
        JSON(OutputFormat.JSON),
        YAML(OutputFormat.YAML),
        ENV(null),
        GITHUB_ENV(null),
    }

    companion object {
        const val SCOPE_READ: String = "tenant:test-identities.read"
        const val SCOPE_WRITE: String = "tenant:test-identities.write"

        /** The variable names the starters' `signin.spec.ts` / `provision.sh` read (ADR §7) — unchanged by the mint. */
        const val VAR_ID: String = "THORYN_TEST_IDENTITY_ID"
        const val VAR_EMAIL: String = "THORYN_TEST_USER_EMAIL"
        const val VAR_PASSWORD: String = "THORYN_TEST_USER_PASSWORD"

        /** Process-environment seam (`GITHUB_ENV`); tests point it at a temp file. */
        internal var environment: (String) -> String? = { System.getenv(it) }

        internal fun resetEnvironmentForTest() {
            environment = { System.getenv(it) }
        }

        internal val LIST_HEADERS: List<String> = listOf("id", "email", "label", "status", "expiresAt", "mintedBy")

        internal fun row(node: JsonNode): List<Any?> = listOf(
            node["id"]?.asString(),
            node["email"]?.asString(),
            node["label"]?.asString(),
            node["status"]?.asString(),
            node["expiresAt"]?.asString(),
            node["mintedBy"]?.asString(),
        )

        /** Parse `create`'s `--output`: the shared `table|json|yaml` plus `env` and `github-env`; null (with a message) on anything else. */
        internal fun parseCreateOutput(raw: String?, err: PrintStream = System.err): CreateOutput? = when (raw?.trim()?.lowercase()) {
            null, "", "table" -> CreateOutput.TABLE
            "json" -> CreateOutput.JSON
            "yaml", "yml" -> CreateOutput.YAML
            "env" -> CreateOutput.ENV
            "github-env" -> CreateOutput.GITHUB_ENV
            else -> {
                err.println("Error: --output must be one of table|json|yaml|env|github-env (was '$raw').")
                null
            }
        }

        /** The three variables, in the order they are written. */
        internal fun variables(minted: JsonNode): List<Pair<String, String>> = listOf(
            VAR_ID to minted["id"]?.asString().orEmpty(),
            VAR_EMAIL to minted["email"]?.asString().orEmpty(),
            VAR_PASSWORD to minted["password"]?.asString().orEmpty(),
        )

        /** POSIX single-quoting: safe for `eval` whatever the server put in the password (`'` becomes `'\''`). */
        internal fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

        /**
         * One `$GITHUB_ENV` entry: `KEY=value` on one line, or the heredoc form GitHub documents for a value that spans
         * lines (`KEY<<delimiter … delimiter`), with a delimiter the value cannot contain.
         */
        internal fun githubEnvLine(key: String, value: String): String {
            if ('\n' !in value && '\r' !in value) return "$key=$value\n"
            var delimiter = "THORYN_EOF"
            while (value.contains(delimiter)) delimiter += "_"
            return "$key<<$delimiter\n$value\n$delimiter\n"
        }

        /** The API never lists a password; the CLI strips one anyway, so a `--output json` of `list` cannot carry it even by a server fault. */
        internal fun withoutPasswords(listed: JsonNode): JsonNode {
            val items = listed["data"] ?: return listed
            if (items.isArray) items.forEach { (it as? tools.jackson.databind.node.ObjectNode)?.remove("password") }
            return listed
        }

        /**
         * Render a refusal of the test-identity surface: product-api's RFC 9457 `errorCode` mapped to a sentence that says
         * what to do (ADR §1's table), after the shared renderings (a scope `403` keeps `CommandSupport.renderError`'s
         * login hint; a step-up, a retired issuer and an unrenewable session keep theirs). The API's own `detail` is kept —
         * for `not_a_sandbox` it is passed through unchanged. Returns [CommandSupport.EXIT_HTTP_ERROR].
         */
        internal fun renderProblem(
            format: OutputFormat,
            ex: ProductApiException,
            requiredScope: String,
            slug: String,
            out: PrintStream = System.out,
            err: PrintStream = System.err,
        ): Int {
            val hint = hintFor(ex, slug)
            if (hint == null) return CommandSupport.renderError(format, ex, requiredScope = requiredScope, out = out, err = err)
            val structured = linkedMapOf<String, Any?>(
                "error" to (ex.errorCode ?: "unknown"),
                "errorDescription" to ex.errorDescription,
                "httpStatus" to ex.httpStatus,
                "hint" to hint,
            )
            ex.retryAfterSeconds?.let { structured["retryAfterSeconds"] = it }
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, out)
                OutputFormat.YAML -> Printers.yaml(structured, out)
                OutputFormat.TABLE -> {
                    val description = ex.errorDescription?.let { " — $it" } ?: ""
                    err.println("Error: ${ex.errorCode ?: "HTTP ${ex.httpStatus}"}$description")
                    err.println(hint)
                }
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }

        /** The sentence for each `errorCode` of ADR §1 (and product-api's upstream fault); null for a code another renderer owns. */
        internal fun hintFor(ex: ProductApiException, slug: String): String? {
            if (ex.isStepUpRequired || ex.isSessionUnrenewable || ex.isProductionConfirmationRequired || ex.isProductionConfirmationMismatch) return null
            return when (ex.errorCode) {
                "not_found" ->
                    "No such environment or test identity in this workspace — or your identity is not a manager of environment '$slug' " +
                        "(a relation you lack is answered as not found, never 403). Check `thoryn env list`, `thoryn env test-identity list --env $slug` " +
                        "and `thoryn access mine --type environment`."
                "environment_mismatch" ->
                    "This session's token is bound to another environment than '$slug' (a sandbox trust mints only in its own sandbox): " +
                        "sign in for '$slug', or pass the environment that token is for with --env."
                "not_a_sandbox" ->
                    "Test identities exist in a sandbox only; '$slug' is the production environment and no flag lifts that. " +
                        "Pick a sandbox: `thoryn env list`, then --env <slug> (or `thoryn env use <slug>`)."
                "invalid_lifetime" ->
                    "--lifetime is an ISO-8601 duration between PT5M and PT24H (default PT2H), e.g. --lifetime PT2H for a CI run or PT24H for a local day."
                "invalid_label" ->
                    "--label is 1 to 64 characters of letters, digits, '.', '_' or '-' (CI passes \"\$GITHUB_RUN_ID-\$GITHUB_RUN_ATTEMPT\")."
                "test_identity_cap_reached" ->
                    "Environment '$slug' holds its maximum of live test identities. Revoke one you no longer need " +
                        "(`thoryn env test-identity list --env $slug`, then `revoke <id> --env $slug`) or wait for an expiry; " +
                        "a CI teardown step running `revoke` under `if: always()` keeps the cap free."
                "test_identity_rate_limited" ->
                    "The mint rate for this client or for environment '$slug' is reached" +
                        (ex.retryAfterSeconds?.let { " — retry after $it second(s)" } ?: " — retry shortly") +
                        ". Reuse one identity per run rather than minting per test."
                "test_identity_expired" ->
                    "This test identity is past its expiresAt and will be purged within minutes; `revoke` it to erase it now, or mint a new one."
                "test_identity_limiter_unavailable" ->
                    "The sandbox's mint limiter is unavailable, so the mint is refused rather than left uncounted (fail-closed); retry in a moment."
                "facade_not_configured" ->
                    "This deployment has no identity facade configured for test identities; the platform operator must configure it before anyone can mint."
                "upstream_identity_error" ->
                    "identity-service could not be reached from product-api; retry, and ask the platform operator if it persists."
                else -> null
            }
        }
    }
}
