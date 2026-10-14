package com.devnow.thoryn.cli.cmd

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.api.ProductApiException
import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.devnow.thoryn.cli.auth.WorkloadIdentityFlow
import com.devnow.thoryn.cli.cmd.examples.Prompt
import com.devnow.thoryn.cli.config.ThorynConfig
import com.devnow.thoryn.cli.output.OutputFormat
import com.devnow.thoryn.cli.output.Printers
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.io.File
import java.io.PrintStream
import java.util.concurrent.Callable

/**
 * `thoryn workload-identity …` (SSO-3308, epic SSO-3304) — secret-less CI sign-in. A thin wrapper over
 * product-api's `/api/v1/workload-identity/trusts` (oathy SSO-3307) reached through the api-gateway.
 *
 * A **workload identity trust** lets one GitHub repository's Actions jobs sign in to an environment
 * without any stored secret: a job requests its own OIDC token for the trust's audience and exchanges it
 * (`thoryn login --workload-identity`) for a short-lived token carrying the trust's scopes. The trust pins
 * the repository by its immutable GitHub ids, optionally a GitHub environment, a ref and GitHub-hosted
 * runners only.
 *
 * SSO-3684 (parent SSO-3678, oathy #4095) — `--provider kubernetes`: the same trust for a **pod**. It pins
 * the cluster's OIDC issuer, the namespace and the service account; the pod's credential is its projected
 * ServiceAccount token (`iss` = the cluster, `sub` = `system:serviceaccount:<ns>:<sa>`, `aud` = the trust's
 * audience), read from a FILE by an init container (`thoryn login --connection …`, token source
 * `/var/run/secrets/tokens/thoryn/token`) which then pulls the application's client secret itself
 * (`thoryn clients rotate-secret <id> --secret-file /shared/client-secret`). A private cluster whose issuer
 * Thoryn cannot reach pins its PUBLIC key set inline (`--jwks-file`, the output of
 * `kubectl get --raw /openid/v1/jwks`); a production trust pins both the namespace and the service account.
 * The documented manifest is `examples/kubernetes/` in this repository.
 *
 * Subcommands (all under `trusts`):
 *  - `create --name <n> --repository <owner/repo> --scope <s>… [pins] [--confirm-production]` — POST
 *  - `create --provider kubernetes --name <n> --issuer <https url> [--namespace <ns> --service-account <sa>]
 *     [--jwks-file <path>] --scope <s>… [--confirm-production]`                               — POST
 *  - `list [--limit n] [--cursor c]`                                                         — GET
 *  - `get <id>`                                                                              — GET …/{id}
 *  - `delete <id> [--yes] [--confirm <workspace-slug>]`                                      — DELETE …/{id}
 *
 * The environment is the one `--environment <slug>` names, else the one `env use` selected (production
 * otherwise). Scopes: create/delete → `tenant:workload-identity.write`, list/get →
 * `tenant:workload-identity.read` (granted to the CLI's login clients by oathy hub V192; part of the
 * default `thoryn login` set). Writing needs the environment's `manager` relation, reading its `viewer`;
 * for anyone else the API answers 404. A trust can carry only `tenant:` scopes your own session holds.
 */
@Command(
    name = "workload-identity",
    description = [
        "Let GitHub Actions workflows — or Kubernetes pods — sign in without a stored secret (workload identity trusts).",
        "A job exchanges its own OIDC token (thoryn login --workload-identity); a pod its projected ServiceAccount token.",
    ],
    mixinStandardHelpOptions = true,
    subcommands = [WorkloadIdentityCommand.TrustsCommand::class],
)
class WorkloadIdentityCommand : Callable<Int> {

    override fun call(): Int {
        System.err.println("Usage: thoryn workload-identity trusts <subcommand>")
        System.err.println("Subcommands: trusts create | list | get <id> | delete <id>")
        return CommandSupport.EXIT_USAGE
    }

    /** `thoryn workload-identity trusts …` */
    @Command(
        name = "trusts",
        description = ["Manage the environment's workload identity trusts (one GitHub repository, or one Kubernetes service account, each)."],
        mixinStandardHelpOptions = true,
        subcommands = [CreateSubcommand::class, ListSubcommand::class, GetSubcommand::class, DeleteSubcommand::class],
    )
    class TrustsCommand : Callable<Int> {
        override fun call(): Int {
            System.err.println("Usage: thoryn workload-identity trusts <subcommand>")
            System.err.println("Subcommands: create | list | get <id> | delete <id>")
            return CommandSupport.EXIT_USAGE
        }
    }

    /** Options every `trusts` subcommand shares. */
    abstract class Base : Callable<Int> {
        @Option(names = ["--environment"], description = [UsersCommand.ENVIRONMENT_OPTION_DESC])
        var environment: String? = null

        @Option(
            names = ["--gateway"],
            description = ["Override the customer-plane gateway URL (default: the gateway recorded at `thoryn login`)."],
            defaultValue = ThorynConfig.DEFAULT_GATEWAY,
        )
        var gateway: String = ThorynConfig.DEFAULT_GATEWAY

        @Option(names = ["--output"], description = ["Output format: json|yaml|table (default: table)."])
        var outputRaw: String? = null

        @Option(names = ["--json"], description = ["Machine-readable output; shorthand for --output json."])
        var json: Boolean = false

        /** The scope the subcommand needs, for the `thoryn login --scope …` hint on a 403. */
        abstract val requiredScope: String

        override fun call(): Int {
            if (json && outputRaw != null && !outputRaw.equals("json", ignoreCase = true)) {
                System.err.println("Error: --json cannot be combined with --output $outputRaw.")
                return CommandSupport.EXIT_USAGE
            }
            val format = CommandSupport.parseFormat(if (json) "json" else outputRaw) ?: return CommandSupport.EXIT_USAGE
            val precheck = precheck()
            if (precheck != null) return precheck
            val tokens = CommandSupport.readTokens() ?: return CommandSupport.EXIT_NOT_SIGNED_IN
            gateway = CommandSupport.resolveGateway(gateway, tokens)
            val client = UsersCommand.clientFor(gateway, tokens, environment)
            return try {
                run(client, format)
            } catch (ex: ProductApiException) {
                renderTrustError(format, ex, requiredScope)
            } catch (ex: Exception) {
                CommandSupport.renderRequestFailure(ex, gateway)
            }
        }

        /** Local validation before any network call; a non-null exit code stops the command. */
        open fun precheck(): Int? = null

        abstract fun run(client: ProductApiClient, format: OutputFormat): Int
    }

    /** `thoryn workload-identity trusts create …` */
    @Command(
        name = "create",
        description = [
            "Trust one GitHub repository's Actions jobs — or (--provider kubernetes) the pods of one Kubernetes service",
            "account — to sign in to this environment without a secret. Prints the client id, audience and token",
            "endpoint, and a workflow snippet (GitHub) or the connection.json for the Thoryn init container (Kubernetes).",
        ],
        mixinStandardHelpOptions = true,
    )
    class CreateSubcommand : Base() {

        @Option(names = ["--name"], required = true, description = ["A label for the trust, unique in the environment."])
        lateinit var name: String

        @Option(
            names = ["--provider"],
            paramLabel = "<github_actions|kubernetes>",
            description = [
                "The workload identity provider: github_actions (default; pins a repository) or kubernetes (SSO-3684;",
                "pins a cluster's OIDC issuer, a namespace and a service account — the pod's projected ServiceAccount token).",
            ],
            defaultValue = PROVIDER_GITHUB_ACTIONS,
        )
        var provider: String = PROVIDER_GITHUB_ACTIONS

        @Option(
            names = ["--repository"],
            paramLabel = "<owner/repo>",
            description = ["github_actions: the GitHub repository whose jobs may sign in, e.g. acme/billing. Required."],
        )
        var repository: String? = null

        @Option(
            names = ["--issuer"],
            paramLabel = "<https url>",
            description = [
                "kubernetes: the cluster's exact OIDC issuer — the `iss` of its ServiceAccount tokens",
                "(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer). Required.",
            ],
        )
        var issuer: String? = null

        @Option(
            names = ["--namespace"],
            description = ["kubernetes: the namespace the pod must run in (kubernetes.io.namespace). Required for a production trust."],
        )
        var namespace: String? = null

        @Option(
            names = ["--service-account"],
            description = ["kubernetes: the service account the pod must run as (kubernetes.io.serviceaccount.name). Required for a production trust; needs --namespace."],
        )
        var serviceAccount: String? = null

        @Option(
            names = ["--jwks-file"],
            paramLabel = "<path>",
            description = [
                "kubernetes: the cluster's PUBLIC JWK Set, pinned inline for a cluster Thoryn cannot reach (a private k3s, …):",
                "the output of `kubectl get --raw /openid/v1/jwks`. Omit for an issuer Thoryn can reach (EKS, GKE, AKS).",
            ],
        )
        var jwksFile: File? = null

        @Option(
            names = ["--owner-id"],
            description = [
                "GitHub's immutable owner id (repository_owner_id). Give it with --repository-id for a private repository;",
                "for a public one both are looked up once when omitted.",
            ],
        )
        var ownerId: Long? = null

        @Option(names = ["--repository-id"], description = ["GitHub's immutable repository id (repository_id). Together with --owner-id."])
        var repositoryId: Long? = null

        @Option(
            names = ["--github-environment"],
            description = ["The GitHub environment the job must run in (exact). Required for a production trust."],
        )
        var githubEnvironment: String? = null

        @Option(names = ["--ref"], description = ["Only jobs on this exact ref, e.g. refs/heads/main."])
        var ref: String? = null

        @Option(names = ["--github-hosted-runners-only"], description = ["Only jobs on GitHub-hosted runners (not self-hosted)."])
        var githubHostedRunnersOnly: Boolean = false

        @Option(
            names = ["--scope"],
            required = true,
            description = [
                "A scope jobs may obtain (repeatable, or space/comma-separated): tenant: scopes your own session holds.",
            ],
        )
        var scopeArgs: List<String> = emptyList()

        @Option(
            names = ["--confirm-production"],
            description = ["Required to create a trust on the production plane (jobs then act on production)."],
        )
        var confirmProduction: Boolean = false

        override val requiredScope: String = SCOPE_WRITE

        private val owner: String get() = repository.orEmpty().trim().substringBefore('/')
        private val repo: String get() = repository.orEmpty().trim().substringAfter('/')

        private val isKubernetes: Boolean get() = provider.trim() == PROVIDER_KUBERNETES

        /** The requested scopes, split and de-duplicated in order. */
        internal val scopes: List<String>
            get() = scopeArgs.flatMap { it.split(' ', ',') }.map { it.trim() }.filter { it.isNotEmpty() }.distinct()

        /** SSO-3684 — the parsed `--jwks-file`, set by [precheck] so the file is read (and judged) once, before any call. */
        private var jwks: Map<String, Any?>? = null

        override fun precheck(): Int? {
            when (provider.trim()) {
                PROVIDER_GITHUB_ACTIONS -> precheckGithub()?.let { return it }
                PROVIDER_KUBERNETES -> precheckKubernetes()?.let { return it }
                else -> {
                    System.err.println("Error: --provider must be $PROVIDER_GITHUB_ACTIONS or $PROVIDER_KUBERNETES (was '$provider').")
                    return CommandSupport.EXIT_USAGE
                }
            }
            if (scopes.isEmpty()) {
                System.err.println("Error: give at least one --scope.")
                return CommandSupport.EXIT_USAGE
            }
            val foreign = scopes.filterNot { it.startsWith("tenant:") }
            if (foreign.isNotEmpty()) {
                System.err.println(
                    "Error: a trust can carry only workspace (tenant:) scopes — not ${foreign.joinToString()}.",
                )
                return CommandSupport.EXIT_USAGE
            }
            return null
        }

        private fun precheckGithub(): Int? {
            val kubernetesOnly = listOfNotNull(
                "--issuer".takeIf { issuer != null },
                "--namespace".takeIf { namespace != null },
                "--service-account".takeIf { serviceAccount != null },
                "--jwks-file".takeIf { jwksFile != null },
            )
            if (kubernetesOnly.isNotEmpty()) {
                System.err.println("Error: ${kubernetesOnly.joinToString(", ")} apply to --provider $PROVIDER_KUBERNETES only.")
                return CommandSupport.EXIT_USAGE
            }
            val repository = repository
            if (repository == null) {
                System.err.println("Error: --repository <owner>/<repo> is required for a $PROVIDER_GITHUB_ACTIONS trust.")
                return CommandSupport.EXIT_USAGE
            }
            val parts = repository.trim().split('/')
            if (parts.size != 2 || parts.any { it.isBlank() }) {
                System.err.println("Error: --repository must be <owner>/<repo> (was '$repository').")
                return CommandSupport.EXIT_USAGE
            }
            if ((ownerId == null) != (repositoryId == null)) {
                System.err.println("Error: --owner-id and --repository-id go together — give both, or neither for a public repository.")
                return CommandSupport.EXIT_USAGE
            }
            return null
        }

        /**
         * SSO-3684 — what the API would refuse for a `kubernetes` pin, refused here first: the GitHub-only flags,
         * a missing or non-https issuer, a service account without its namespace, a production trust (asserted by
         * `--confirm-production`) that does not pin both names (the API's `production_requires_service_account`),
         * and a `--jwks-file` that is not a JWK Set of public keys.
         */
        private fun precheckKubernetes(): Int? {
            val githubOnly = listOfNotNull(
                "--repository".takeIf { repository != null },
                "--owner-id".takeIf { ownerId != null },
                "--repository-id".takeIf { repositoryId != null },
                "--github-environment".takeIf { githubEnvironment != null },
                "--ref".takeIf { ref != null },
                "--github-hosted-runners-only".takeIf { githubHostedRunnersOnly },
            )
            if (githubOnly.isNotEmpty()) {
                System.err.println("Error: ${githubOnly.joinToString(", ")} apply to --provider $PROVIDER_GITHUB_ACTIONS only.")
                return CommandSupport.EXIT_USAGE
            }
            val issuer = issuer?.trim()?.takeIf { it.isNotEmpty() }
            if (issuer == null) {
                System.err.println(
                    "Error: --issuer <https url> is required for a $PROVIDER_KUBERNETES trust — the cluster's exact OIDC issuer " +
                        "(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer).",
                )
                return CommandSupport.EXIT_USAGE
            }
            if (!issuer.startsWith("https://") || runCatching { java.net.URI(issuer).host }.getOrNull().isNullOrBlank()) {
                System.err.println("Error: --issuer must be an absolute https URL (was '$issuer').")
                return CommandSupport.EXIT_USAGE
            }
            val ns = namespace?.trim()?.takeIf { it.isNotEmpty() }
            val sa = serviceAccount?.trim()?.takeIf { it.isNotEmpty() }
            if (sa != null && ns == null) {
                System.err.println("Error: --service-account needs --namespace (a service account is identified within its namespace).")
                return CommandSupport.EXIT_USAGE
            }
            if (confirmProduction && (ns == null || sa == null)) {
                System.err.println(
                    "Error: a production $PROVIDER_KUBERNETES trust must pin both --namespace and --service-account " +
                        "(production_requires_service_account): only the pods of that one service account may then act on production.",
                )
                return CommandSupport.EXIT_USAGE
            }
            jwksFile?.let { file ->
                jwks = readJwksFile(file) ?: return CommandSupport.EXIT_USAGE
            }
            return null
        }

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val pin: Pair<String, Map<String, Any?>> = if (isKubernetes) {
                "kubernetes" to mapOf(
                    "issuer" to issuer!!.trim(),
                    "namespace" to namespace?.trim()?.takeIf { it.isNotEmpty() },
                    "serviceAccount" to serviceAccount?.trim()?.takeIf { it.isNotEmpty() },
                    "jwks" to jwks,
                )
            } else {
                "github" to mapOf(
                    "owner" to owner,
                    "repository" to repo,
                    "ownerId" to ownerId,
                    "repositoryId" to repositoryId,
                    "environment" to githubEnvironment?.trim()?.takeIf { it.isNotEmpty() },
                    "ref" to ref?.trim()?.takeIf { it.isNotEmpty() },
                    "githubHostedRunnersOnly" to githubHostedRunnersOnly.takeIf { it },
                )
            }
            val body = client.createWorkloadIdentityTrust(
                mapOf(
                    "name" to name.trim(),
                    "provider" to provider.trim(),
                    pin,
                    "scopes" to scopes,
                    "confirmProduction" to confirmProduction.takeIf { it },
                ),
            )
            when (format) {
                OutputFormat.TABLE -> {
                    val out = System.out
                    out.println("Workload identity trust '${text(body, "name")}' created (id ${text(body, "id")}, environment ${text(body, "environment")}).")
                    out.println()
                    Printers.record(trustFields(body), out)
                    out.println()
                    if (isKubernetesTrust(body)) {
                        printKubernetesUsage(body, workspaceSlugHint(body), out)
                    } else {
                        printUsage(body, workspaceSlugHint(body), out)
                    }
                }
                else -> CommandSupport.emitRecord(format, body, ::trustFields)
            }
            return CommandSupport.EXIT_OK
        }

        /** The workspace slug for the connection snippet: from the audience's host, else the session's. */
        private fun workspaceSlugHint(body: JsonNode): String? =
            ThorynConfig.workspaceOfIssuer(text(body, "audience"))
                ?: runCatching { TokenStoreFactory.default().read() }.getOrNull()?.workspace
    }

    /** `thoryn workload-identity trusts list` */
    @Command(name = "list", description = ["List the environment's workload identity trusts."], mixinStandardHelpOptions = true)
    class ListSubcommand : Base() {
        @Option(names = ["--limit"], description = ["Maximum trusts to return."])
        var limit: Int? = null

        @Option(names = ["--cursor"], description = ["Continue a previous listing (the `pagination.cursor` it returned)."])
        var cursor: String? = null

        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.listWorkloadIdentityTrusts(limit, cursor)
            val items = body["data"]?.takeIf { it.isArray }?.toList() ?: (if (body.isArray) body.toList() else emptyList())
            if (format == OutputFormat.TABLE && items.isEmpty()) {
                System.out.println("No workload identity trusts in this environment.")
                System.out.println("Create one with: thoryn workload-identity trusts create --name <name> --repository <owner/repo> --scope <scope>")
                return CommandSupport.EXIT_OK
            }
            CommandSupport.emitList(format, body, LIST_HEADERS, ::row)
            if (format == OutputFormat.TABLE) {
                body["pagination"]?.get("cursor")?.takeUnless { it.isNull }?.asString()?.takeIf { it.isNotBlank() }?.let {
                    System.out.println("More: thoryn workload-identity trusts list --cursor $it")
                }
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn workload-identity trusts get <id>` */
    @Command(name = "get", description = ["Show one trust, and the sign-in line a workflow uses with it."], mixinStandardHelpOptions = true)
    class GetSubcommand : Base() {
        @Parameters(index = "0", paramLabel = "<id>", description = ["The trust id (from `trusts create` or `trusts list`)."])
        lateinit var id: String

        override val requiredScope: String = SCOPE_READ

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            val body = client.getWorkloadIdentityTrust(id.trim())
            when (format) {
                OutputFormat.TABLE -> {
                    Printers.record(trustFields(body), System.out)
                    System.out.println()
                    System.out.println("Sign in from the workflow with:")
                    System.out.println("    ${loginLine(body)}")
                }
                else -> CommandSupport.emitRecord(format, body, ::trustFields)
            }
            return CommandSupport.EXIT_OK
        }
    }

    /** `thoryn workload-identity trusts delete <id>` */
    @Command(
        name = "delete",
        description = ["Delete a trust. Its client stops authenticating at once; workflows using it can no longer sign in."],
        mixinStandardHelpOptions = true,
    )
    class DeleteSubcommand : Base() {
        @Parameters(index = "0", paramLabel = "<id>", description = ["The trust id."])
        lateinit var id: String

        @Option(names = ["--yes", "-y"], description = ["Skip the confirmation prompt (non-interactive use)."])
        var yes: Boolean = false

        @Option(names = ["--confirm"], paramLabel = "<workspace-slug>", description = [CommandSupport.CONFIRM_OPTION_DESC])
        var confirm: String? = null

        override val requiredScope: String = SCOPE_WRITE

        override fun precheck(): Int? {
            if (yes) return null
            if (Prompt.confirm("Delete workload identity trust ${id.trim()}? Workflows that sign in with it fail from now on.")) return null
            System.err.println(if (Prompt.interactive()) "Aborted." else "Refusing to delete without confirmation; re-run with --yes.")
            return CommandSupport.EXIT_USAGE
        }

        override fun run(client: ProductApiClient, format: OutputFormat): Int {
            client.deleteWorkloadIdentityTrust(id.trim(), confirm?.trim()?.takeIf { it.isNotEmpty() })
            CommandSupport.emitValue(format, mapOf("deleted" to true, "id" to id.trim()), "Workload identity trust ${id.trim()} deleted.")
            return CommandSupport.EXIT_OK
        }
    }

    companion object {
        const val SCOPE_READ: String = "tenant:workload-identity.read"
        const val SCOPE_WRITE: String = "tenant:workload-identity.write"
        const val PROVIDER_GITHUB_ACTIONS: String = "github_actions"

        /** SSO-3684 — the trust API's `provider` for a pod's projected ServiceAccount token (oathy SSO-3678). */
        const val PROVIDER_KUBERNETES: String = "kubernetes"

        /** SSO-3684 — where the documented manifest (`examples/kubernetes/`) mounts the projected token. */
        const val KUBERNETES_TOKEN_FILE: String = WorkloadIdentityFlow.DEFAULT_KUBERNETES_TOKEN_FILE

        internal val LIST_HEADERS: List<String> = listOf("id", "name", "provider", "clientId", "pins", "scopes")

        private val jsonMapper: JsonMapper = JsonMapper.builder().build()

        private fun text(node: JsonNode?, field: String): String? =
            node?.get(field)?.takeIf { it.isValueNode && !it.isNull }?.asString()?.takeIf { it.isNotBlank() }

        private fun scopesOf(body: JsonNode): List<String> =
            body["scopes"]?.takeIf { it.isArray }?.toList()?.mapNotNull { it.asString() }.orEmpty()

        /** SSO-3684 — true for a `kubernetes` trust (by `provider`, else by the pin block present). */
        internal fun isKubernetesTrust(body: JsonNode): Boolean =
            text(body, "provider") == PROVIDER_KUBERNETES || (text(body, "provider") == null && body["kubernetes"]?.isObject == true)

        /** The one-line pin summary of a trust: `owner/repo [env=…]` for GitHub, `issuer ns=… sa=…` for Kubernetes. */
        private fun pinsOf(node: JsonNode): String? {
            if (isKubernetesTrust(node)) {
                val k = node["kubernetes"]
                return listOfNotNull(
                    text(k, "issuer"),
                    text(k, "namespace")?.let { "ns=$it" },
                    text(k, "serviceAccount")?.let { "sa=$it" },
                ).joinToString(" ").ifEmpty { null }
            }
            val github = node["github"]
            return listOfNotNull(
                listOfNotNull(text(github, "owner"), text(github, "repository")).joinToString("/").ifEmpty { null },
                text(github, "environment")?.let { "env=$it" },
            ).joinToString(" ").ifEmpty { null }
        }

        internal fun row(node: JsonNode): List<Any?> = listOf(
            text(node, "id"),
            text(node, "name"),
            text(node, "provider") ?: if (isKubernetesTrust(node)) PROVIDER_KUBERNETES else PROVIDER_GITHUB_ACTIONS,
            text(node, "clientId"),
            pinsOf(node),
            scopesOf(node).joinToString(" "),
        )

        /**
         * SSO-3684 — read and judge a `--jwks-file`: a JSON object with a non-empty `keys` array of key objects,
         * each with a `kty`, none carrying a PRIVATE parameter (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) — the hub
         * refuses those too, but a private key must never leave the machine in the first place. Returns the key
         * set as plain data (what the trust body carries), or null after printing why not. Key material is public;
         * still, nothing of the file's CONTENT is echoed, only the path.
         */
        internal fun readJwksFile(file: File, err: PrintStream = System.err): Map<String, Any?>? {
            val root = try {
                jsonMapper.readTree(file.readBytes())
            } catch (e: Exception) {
                err.println("Error: --jwks-file '${file.path}' could not be read as JSON (${e.javaClass.simpleName}). Use the output of `kubectl get --raw /openid/v1/jwks` unchanged.")
                return null
            }
            val keys = root?.takeIf { it.isObject }?.get("keys")
            if (keys == null || !keys.isArray || keys.isEmpty) {
                err.println("Error: --jwks-file '${file.path}' is not a JWK Set: expected an object with a non-empty \"keys\" array (`kubectl get --raw /openid/v1/jwks`).")
                return null
            }
            keys.forEachIndexed { i, key ->
                if (!key.isObject || text(key, "kty") == null) {
                    err.println("Error: --jwks-file '${file.path}': keys[$i] is not a JWK (no \"kty\").")
                    return null
                }
                val private = JWK_PRIVATE_PARAMETERS.filter { key.has(it) }
                if (private.isNotEmpty()) {
                    err.println(
                        "Error: --jwks-file '${file.path}': keys[$i] carries private parameters (${private.joinToString()}). " +
                            "A trust pins the cluster's PUBLIC key set only — never upload a private key.",
                    )
                    return null
                }
            }
            @Suppress("UNCHECKED_CAST")
            return jsonMapper.convertValue(root, Map::class.java) as Map<String, Any?>
        }

        /** RFC 7518 §6 private key parameters (RSA / EC) plus a symmetric key's `k`. */
        private val JWK_PRIVATE_PARAMETERS: List<String> = listOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")

        /** The key/value view used by `get` and by `create`'s table output. */
        fun trustFields(body: JsonNode): List<Pair<String, Any?>> {
            val github = body["github"]
            val kubernetes = body["kubernetes"]
            val ids = listOfNotNull(text(github, "ownerId"), text(github, "repositoryId"))
            val inlineKeyIds = kubernetes?.get("inlineKeyIds")?.takeIf { it.isArray }?.toList()?.mapNotNull { it.asString() }.orEmpty()
            return listOf(
                "id" to text(body, "id"),
                "name" to text(body, "name"),
                "environment" to text(body, "environment"),
                "provider" to text(body, "provider"),
                "clientId" to text(body, "clientId"),
                "audience" to text(body, "audience"),
                "tokenEndpoint" to text(body, "tokenEndpoint"),
                "repository" to listOfNotNull(text(github, "owner"), text(github, "repository")).joinToString("/").ifEmpty { null },
                "githubIds" to ids.takeIf { it.size == 2 }?.let { "owner ${it[0]} / repository ${it[1]}" },
                "githubEnvironment" to text(github, "environment"),
                "ref" to text(github, "ref"),
                "githubHostedRunnersOnly" to github?.get("githubHostedRunnersOnly")?.takeUnless { it.isNull }?.asBoolean(),
                // SSO-3684 — the Kubernetes pin: the cluster, the names, and where its keys come from (never key material).
                "issuer" to text(kubernetes, "issuer"),
                "namespace" to text(kubernetes, "namespace"),
                "serviceAccount" to text(kubernetes, "serviceAccount"),
                "jwksUri" to text(kubernetes, "jwksUri"),
                "inlineKeyIds" to inlineKeyIds.takeIf { it.isNotEmpty() }?.joinToString(" "),
                "subjectPattern" to text(body, "subjectPattern"),
                "scopes" to scopesOf(body).joinToString(" ").ifEmpty { null },
                "enabled" to body["enabled"]?.takeUnless { it.isNull }?.asBoolean(),
                "createdBy" to text(body, "createdBy"),
                "createdAt" to text(body, "createdAt"),
            ).filter { it.second != null }
        }

        /** True when the trust's token endpoint is the default `{audience}/oauth2/token` (so it need not be passed). */
        private fun defaultTokenEndpoint(body: JsonNode): Boolean {
            val audience = text(body, "audience") ?: return true
            val endpoint = text(body, "tokenEndpoint") ?: return true
            return endpoint == WorkloadIdentityFlow.tokenEndpointFor(audience, null)
        }

        /**
         * The `thoryn login --workload-identity …` line a job runs for this trust — for a `kubernetes` trust with
         * `--token-file <the projected token>` (SSO-3684), since there is no runner to ask.
         */
        fun loginLine(body: JsonNode): String = buildString {
            append("thoryn login --workload-identity --client-id ${text(body, "clientId") ?: "<client-id>"}")
            append(" --audience ${text(body, "audience") ?: "<audience>"}")
            if (isKubernetesTrust(body)) append(" --token-file $KUBERNETES_TOKEN_FILE")
            if (!defaultTokenEndpoint(body)) append(" --token-endpoint ${text(body, "tokenEndpoint")}")
            scopesOf(body).takeIf { it.isNotEmpty() }?.let { append(" --scope \"${it.joinToString(" ")}\"") }
        }

        /**
         * SSO-3684 — the connection contract for a `kubernetes` trust: `provider: kubernetes`, the projected token as
         * `tokenSource: {kind: file, path: …}`, the trust's pins as `auth.kubernetes` (diagnostics only), and the
         * `connection.json` a pod's init container mounts at `/etc/thoryn/connection.json`.
         */
        fun kubernetesConnectionJson(body: JsonNode, workspaceSlug: String?): String {
            val k = body["kubernetes"]
            val scopes = scopesOf(body).joinToString(", ") { "\"$it\"" }
            val endpoint = if (defaultTokenEndpoint(body)) "" else ",\n    \"tokenEndpoint\": \"${text(body, "tokenEndpoint")}\""
            val pins = listOfNotNull(
                text(k, "issuer")?.let { "\"issuer\": \"$it\"" },
                text(k, "namespace")?.let { "\"namespace\": \"$it\"" },
                text(k, "serviceAccount")?.let { "\"serviceAccount\": \"$it\"" },
            )
            val pinsLine = if (pins.isEmpty()) "" else ",\n    \"kubernetes\": { ${pins.joinToString(", ")} }"
            return """
                |{
                |  "apiVersion": "thoryn.io/connection/v1",
                |  "workspace": { "slug": "${workspaceSlug ?: "<your-workspace>"}" },
                |  "auth": {
                |    "method": "workload_identity",
                |    "provider": "kubernetes",
                |    "clientId": "${text(body, "clientId")}",
                |    "audience": "${text(body, "audience")}"$endpoint,
                |    "tokenSource": { "kind": "file", "path": "$KUBERNETES_TOKEN_FILE" },
                |    "scopes": [$scopes]$pinsLine
                |  }
                |}
            """.trimMargin()
        }

        /** SSO-3684 — how a pod uses a `kubernetes` trust: the connection.json, the projected volume, the init container. */
        fun printKubernetesUsage(body: JsonNode, workspaceSlug: String?, out: PrintStream) {
            val k = body["kubernetes"]
            val audience = text(body, "audience") ?: "<audience>"
            val serviceAccount = text(k, "serviceAccount") ?: "<service-account>"
            out.println("Use it from a pod — there is no secret to store. The pod's init container signs in with the projected")
            out.println("ServiceAccount token and pulls the application's client secret itself:")
            out.println()
            out.println("1. Mount this as /etc/thoryn/connection.json (a ConfigMap; it holds no secret):")
            out.println()
            out.println(kubernetesConnectionJson(body, workspaceSlug).prependIndent("  "))
            out.println()
            out.println("2. Project the token for the trust's audience, and run the Thoryn init container:")
            out.println()
            out.println("  spec:")
            out.println("    serviceAccountName: $serviceAccount")
            out.println("    volumes:")
            out.println("      - name: thoryn-token")
            out.println("        projected:")
            out.println("          sources:")
            out.println("            - serviceAccountToken:")
            out.println("                path: token")
            out.println("                audience: $audience       # the trust's `audience`")
            out.println("                expirationSeconds: 3600")
            out.println("      - name: client-secret")
            out.println("        emptyDir: { medium: Memory }")
            out.println("    initContainers:")
            out.println("      - name: thoryn-client-secret")
            out.println("        image: ghcr.io/thoryn-io/thoryn-cli:latest")
            out.println("        # token source: $KUBERNETES_TOKEN_FILE")
            out.println("        command: [\"sh\", \"-c\", \"thoryn login --connection /etc/thoryn/connection.json &&")
            out.println("                   thoryn clients rotate-secret \$APP_CLIENT_ID --secret-file /shared/client-secret\"]")
            out.println("        volumeMounts:")
            out.println("          - { name: thoryn-token, mountPath: /var/run/secrets/tokens/thoryn, readOnly: true }")
            out.println("          - { name: client-secret, mountPath: /shared }")
            out.println()
            out.println("3. The application reads /shared/client-secret (e.g. oauth2-proxy --client-secret-file=/shared/client-secret).")
            out.println()
            out.println("The complete, documented manifest is examples/kubernetes/ in the thoryn-cli repository. The trust's scopes")
            out.println("need tenant:applications.write, and its client needs `manager` on the application whose secret it rotates")
            out.println("(thoryn access grant). Rotation is a pod restart: the previous secret stays valid for 24 hours.")
            k?.get("inlineKeyIds")?.takeIf { it.isArray && !it.isEmpty }?.let { ids ->
                out.println("Keys are pinned inline (kid ${ids.toList().mapNotNull { it.asString() }.joinToString(" ")}): when the cluster rotates its signing key, replace the trust's JWKS (delete and re-create the trust).")
            }
        }

        /** The ready-to-paste workflow job and the equivalent connection contract. */
        fun printUsage(body: JsonNode, workspaceSlug: String?, out: PrintStream) {
            val githubEnvironment = text(body["github"], "environment")
            out.println("Use it from a GitHub Actions job — there is no secret to store:")
            out.println()
            out.println("  jobs:")
            out.println("    deploy:")
            out.println("      runs-on: ubuntu-latest")
            githubEnvironment?.let { out.println("      environment: $it            # the trust pins this GitHub environment") }
            out.println("      permissions:")
            out.println("        contents: read")
            out.println("        id-token: write                # lets the job request its OIDC token")
            out.println("      steps:")
            out.println("        # … install the thoryn CLI …")
            out.println("        - run: ${loginLine(body)}")
            out.println()
            out.println("Or commit it as .thoryn/connection.json and run `thoryn login --connection .thoryn/connection.json`:")
            out.println()
            val scopes = scopesOf(body).joinToString(", ") { "\"$it\"" }
            val endpoint = if (defaultTokenEndpoint(body)) "" else ",\n      \"tokenEndpoint\": \"${text(body, "tokenEndpoint")}\""
            out.println(
                """
                |  {
                |    "apiVersion": "thoryn.io/connection/v1",
                |    "workspace": { "slug": "${workspaceSlug ?: "<your-workspace>"}" },
                |    "auth": {
                |      "method": "workload_identity",
                |      "clientId": "${text(body, "clientId")}",
                |      "audience": "${text(body, "audience")}"$endpoint,
                |      "scopes": [$scopes]
                |    }
                |  }
                """.trimMargin(),
            )
            out.println()
            out.println("Each job token works once and the token lasts at most 15 minutes; the CLI requests a fresh one as needed.")
        }

        /**
         * Error rendering with trust-specific guidance on top of [CommandSupport.renderError]. A
         * `403 scope_not_grantable` is not a missing scope of the CALLER's command — it is a trust scope the
         * caller does not hold — so it gets its own hint instead of the `thoryn login --scope` one. The
         * create body's `production_confirmation_required` means `--confirm-production`, not the
         * `--confirm <slug>` header guard of destructive actions.
         */
        fun renderTrustError(format: OutputFormat, ex: ProductApiException, requiredScope: String): Int {
            val hint = when (ex.errorCode) {
                "scope_not_grantable" ->
                    "A trust can carry only tenant: scopes your own session holds. Drop the scope, or sign in with it first."
                "invalid_scope" -> "A trust can carry only workspace (tenant:) scopes."
                "production_confirmation_required" ->
                    "This is the production plane: jobs using the trust act on production. Re-run with --confirm-production."
                "production_requires_environment" ->
                    "A production trust must pin a GitHub environment: add --github-environment <name>."
                "production_requires_service_account" ->
                    "A production kubernetes trust must pin both --namespace <ns> and --service-account <name>."
                "kubernetes_issuer_unreachable" ->
                    "Thoryn could not reach the cluster's issuer to fetch its keys (a private cluster?). Pin the public key set: " +
                        "kubectl get --raw /openid/v1/jwks > cluster-jwks.json, then re-run with --jwks-file cluster-jwks.json."
                "invalid_kubernetes_issuer" ->
                    "--issuer must be the cluster's exact https `iss` (kubectl get --raw /.well-known/openid-configuration | jq -r .issuer); " +
                        "for a private cluster add --jwks-file so nothing has to be reached."
                "invalid_kubernetes_jwks" ->
                    "--jwks-file must be a JWK Set of 1-8 RSA / EC PUBLIC keys with kids: use `kubectl get --raw /openid/v1/jwks` unchanged."
                "invalid_kubernetes_namespace", "invalid_kubernetes_service_account" ->
                    "Use the namespace and service account names exactly as `kubectl` shows them; a service account needs its namespace."
                "github_repository_not_found" ->
                    "GitHub has no public repository by that name. For a private repository pass --owner-id and --repository-id."
                "github_unavailable" -> "GitHub could not be reached to look up the repository ids. Retry, or pass --owner-id and --repository-id."
                "invalid_github_ids" -> "--owner-id and --repository-id go together: give both, or neither."
                "workload_identity_trust_name_taken" -> "Choose another --name, or delete the existing trust first."
                "workload_identity_trust_not_found" ->
                    "No such trust in this environment, or you cannot read it. List them with `thoryn workload-identity trusts list`."
                "environment_not_found" ->
                    "No such environment, or you cannot reach it. Check `thoryn env list`, or omit --environment."
                else -> null
            }
            val scopeHint = if (ex.errorCode in NOT_A_CALLER_SCOPE_PROBLEM) null else requiredScope
            val exit = if (ex.errorCode == "production_confirmation_required") {
                // Not the destructive-action header guard CommandSupport renders for this code.
                renderPlain(format, ex)
            } else {
                CommandSupport.renderError(format, ex, requiredScope = scopeHint)
            }
            if (hint != null && format == OutputFormat.TABLE) System.err.println(hint)
            return exit
        }

        private val NOT_A_CALLER_SCOPE_PROBLEM = setOf("scope_not_grantable", "invalid_scope")

        private fun renderPlain(format: OutputFormat, ex: ProductApiException): Int {
            val structured = linkedMapOf<String, Any?>(
                "error" to (ex.errorCode ?: "unknown"),
                "errorDescription" to ex.errorDescription,
                "httpStatus" to ex.httpStatus,
            )
            when (format) {
                OutputFormat.JSON -> Printers.json(structured, System.out)
                OutputFormat.YAML -> Printers.yaml(structured, System.out)
                OutputFormat.TABLE -> System.err.println("Error: ${ex.errorCode}${ex.errorDescription?.let { " — $it" } ?: ""}")
            }
            return CommandSupport.EXIT_HTTP_ERROR
        }
    }
}
