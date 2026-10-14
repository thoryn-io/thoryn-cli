package com.devnow.thoryn.cli.cmd

import okhttp3.mockwebserver.MockResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3684 (parent SSO-3678, oathy #4095) — `thoryn workload-identity trusts create --provider kubernetes`
 * against a MockWebServer standing in for product-api's `/api/v1/workload-identity/trusts`: the
 * `kubernetes` pin body (`issuer`, `namespace`, `serviceAccount`, the inline `jwks` from `--jwks-file`),
 * what is refused before any call (the production pins, a non-JWKS file, a private key, the GitHub-only
 * flags), the hub's `production_requires_service_account` hint, and the output a pod needs: the
 * connection.json with a FILE token source and the projected-volume / init-container snippet.
 */
class WorkloadIdentityKubernetesCommandTest : CommandTestBase() {

    private fun fixture(name: String): String =
        requireNotNull(javaClass.getResource("/workload-identity/$name.json")) { "missing fixture $name" }.readText()

    private fun problem(status: Int, name: String): MockResponse =
        MockResponse().setResponseCode(status).setHeader("Content-Type", "application/problem+json").setBody(fixture(name))

    private val issuer = "https://kubernetes.default.svc.cluster.local"

    private fun jwksFile(body: String = fixture("cluster-jwks")): Path =
        tempHome.resolve("cluster-jwks.json").also { Files.writeString(it, body) }

    private fun create(vararg args: String) = runCli(
        "workload-identity", "trusts", "create", "--provider", "kubernetes", "--name", "forge-oauth2-proxy",
        "--scope", "tenant:applications.write", "--gateway", baseUrl(), *args,
    )

    @Test
    fun `create --provider kubernetes sends the cluster pins and the inline JWKS, and prints the connection contract with a file token source`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-kubernetes")))

        val (exit, out, err) = create(
            "--issuer", issuer, "--namespace", "forge", "--service-account", "forge-oauth2-proxy",
            "--jwks-file", jwksFile().toString(), "--confirm-production",
        )

        assertThat(err).doesNotContain("Error")
        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.method).isEqualTo("POST")
        assertThat(req.path).isEqualTo("/api/v1/workload-identity/trusts")
        val body = parseJson(req.body.readUtf8())
        assertThat(body).containsEntry("name", "forge-oauth2-proxy")
            .containsEntry("provider", "kubernetes")
            .containsEntry("scopes", listOf("tenant:applications.write"))
            .containsEntry("confirmProduction", true)
            .doesNotContainKey("github")
        @Suppress("UNCHECKED_CAST")
        val kubernetes = body["kubernetes"] as Map<String, Any?>
        assertThat(kubernetes).containsEntry("issuer", issuer).containsEntry("namespace", "forge").containsEntry("serviceAccount", "forge-oauth2-proxy")
        @Suppress("UNCHECKED_CAST")
        val jwks = kubernetes["jwks"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val keys = jwks["keys"] as List<Map<String, Any?>>
        assertThat(keys).hasSize(1)
        assertThat(keys.single()).containsEntry("kid", "t10j6Z4K").containsEntry("kty", "RSA").containsEntry("e", "AQAB")

        assertThat(out)
            .contains("Workload identity trust 'forge-oauth2-proxy' created")
            .contains("wi_9a8b7c6d5e4f3a2b1c0d9e8f")
            .contains("inlineKeyIds")
            .contains("\"provider\": \"kubernetes\"")
            .contains("\"tokenSource\": { \"kind\": \"file\", \"path\": \"/var/run/secrets/tokens/thoryn/token\" }")
            .contains("\"kubernetes\": { \"issuer\": \"$issuer\", \"namespace\": \"forge\", \"serviceAccount\": \"forge-oauth2-proxy\" }")
            .contains("\"slug\": \"thoryn\"")
            .contains("serviceAccountName: forge-oauth2-proxy")
            .contains("audience: https://thoryn.auth.stg.thoryn.org")
            .contains("expirationSeconds: 3600")
            .contains("args: [\"login\", \"--connection\", \"/etc/thoryn/connection.json\"]")
            .contains("args: [\"clients\", \"rotate-secret\", \"\$(APP_CLIENT_ID)\", \"--secret-file\", \"/shared/client-secret\",")
            .contains("examples/kubernetes/")
            .doesNotContain("id-token: write")
    }

    /**
     * SSO-3687 — the snippet must run on the image this repository publishes: ghcr.io/thoryn-io/thoryn-cli is
     * distroless (no shell, so no `sh -c "login && rotate-secret"`), has no OS keychain (so every step needs
     * the explicit file-store opt-in, and the two steps share the session on a volume), and has no `:latest`
     * (a deployment pins by digest). Each of those, printed wrong, is a pod that never starts.
     */
    @Test
    fun `the printed init containers run on the published shell-less image - two steps sharing a session volume, pinned by digest`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-kubernetes")))

        val (exit, out, _) = create(
            "--issuer", issuer, "--namespace", "forge", "--service-account", "forge-oauth2-proxy",
            "--jwks-file", jwksFile().toString(), "--confirm-production",
        )

        assertThat(exit).isEqualTo(0)
        assertThat(out)
            .doesNotContain("\"sh\"")
            .doesNotContain("&&")
            .doesNotContain(":latest")
            .contains("image: ghcr.io/thoryn-io/thoryn-cli:<version>@sha256:<digest>")
            .contains("- name: thoryn-login")
            .contains("- name: thoryn-client-secret")
            .contains("- name: thoryn-connection")
            .contains("configMap: { name: thoryn-connection }")
            .contains("- { name: thoryn-connection, mountPath: /etc/thoryn, readOnly: true }")
            .contains("\"--confirm\", \"thoryn\"]")
            .contains("- { name: APP_CLIENT_ID, value: <the application whose secret the pod pulls> }")
        // Both steps carry the file-store opt-in and mount the shared session; the login step runs first.
        assertThat(Regex("""THORYN_CI_PLAINTEXT_TOKENS, value: "1"""").findAll(out).count()).isEqualTo(2)
        assertThat(Regex("""THORYN_TOKEN_FILE, value: /thoryn-session/tokens\.json""").findAll(out).count()).isEqualTo(2)
        assertThat(Regex("""- \{ name: thoryn-session, mountPath: /thoryn-session }""").findAll(out).count()).isEqualTo(2)
        assertThat(out.indexOf("- name: thoryn-login")).isLessThan(out.indexOf("- name: thoryn-client-secret"))
    }

    @Test
    fun `a sandbox trust may pin the namespace only, and without --jwks-file the body carries no jwks`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-kubernetes")))

        val (exit, _, _) = create("--issuer", "https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE", "--namespace", "forge", "--environment", "staging")

        assertThat(exit).isEqualTo(0)
        val req = server.takeRequest()
        assertThat(req.getHeader("X-Thoryn-Environment")).isEqualTo("staging")
        val body = parseJson(req.body.readUtf8())
        assertThat(body).doesNotContainKey("confirmProduction")
        @Suppress("UNCHECKED_CAST")
        val kubernetes = body["kubernetes"] as Map<String, Any?>
        assertThat(kubernetes).containsEntry("namespace", "forge").doesNotContainKeys("serviceAccount", "jwks")
    }

    @Test
    fun `a production trust (--confirm-production) without both pins is refused locally with the API's error name`() {
        val noServiceAccount = create("--issuer", issuer, "--namespace", "forge", "--confirm-production")
        assertThat(noServiceAccount.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noServiceAccount.err).contains("production_requires_service_account").contains("--service-account")

        val noPins = create("--issuer", issuer, "--confirm-production")
        assertThat(noPins.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noPins.err).contains("--namespace")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `the issuer is required and must be https, and a service account needs its namespace`() {
        val noIssuer = create("--namespace", "forge")
        assertThat(noIssuer.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noIssuer.err).contains("--issuer <https url> is required")

        val http = create("--issuer", "http://kubernetes.default.svc", "--namespace", "forge")
        assertThat(http.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(http.err).contains("--issuer must be an absolute https URL")

        val saOnly = create("--issuer", issuer, "--service-account", "forge-oauth2-proxy")
        assertThat(saOnly.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(saOnly.err).contains("--service-account needs --namespace")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `--jwks-file must be a JWK Set of PUBLIC keys — not JSON, no keys, or a private parameter are refused before any call`() {
        val notJson = create("--issuer", issuer, "--namespace", "forge", "--jwks-file", jwksFile("not json").toString())
        assertThat(notJson.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(notJson.err).contains("could not be read as JSON").contains("kubectl get --raw /openid/v1/jwks")

        val noKeys = create("--issuer", issuer, "--namespace", "forge", "--jwks-file", jwksFile("""{"issuer":"x"}""").toString())
        assertThat(noKeys.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(noKeys.err).contains("is not a JWK Set")

        val emptyKeys = create("--issuer", issuer, "--namespace", "forge", "--jwks-file", jwksFile("""{"keys":[]}""").toString())
        assertThat(emptyKeys.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(emptyKeys.err).contains("is not a JWK Set")

        val privateKey = create(
            "--issuer", issuer, "--namespace", "forge",
            "--jwks-file", jwksFile("""{"keys":[{"kty":"RSA","kid":"k","n":"AQ","e":"AQAB","d":"c2VjcmV0"}]}""").toString(),
        )
        assertThat(privateKey.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(privateKey.err).contains("private parameters (d)").doesNotContain("c2VjcmV0")

        val missing = create("--issuer", issuer, "--namespace", "forge", "--jwks-file", tempHome.resolve("nope.json").toString())
        assertThat(missing.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(missing.err).contains("could not be read")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `the GitHub flags are refused on a kubernetes trust, the Kubernetes flags on a GitHub trust, and an unknown provider is refused`() {
        val github = create("--issuer", issuer, "--namespace", "forge", "--repository", "acme/billing", "--ref", "refs/heads/main")
        assertThat(github.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(github.err).contains("--repository, --ref apply to --provider github_actions only")

        val kubernetes = runCli(
            "workload-identity", "trusts", "create", "--name", "n", "--repository", "acme/billing", "--namespace", "forge",
            "--scope", "tenant:x.read", "--gateway", baseUrl(),
        )
        assertThat(kubernetes.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(kubernetes.err).contains("--namespace apply to --provider kubernetes only")

        val bogus = runCli(
            "workload-identity", "trusts", "create", "--provider", "gitlab", "--name", "n", "--scope", "tenant:x.read", "--gateway", baseUrl(),
        )
        assertThat(bogus.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(bogus.err).contains("--provider must be github_actions or kubernetes")
        assertThat(server.requestCount).isZero()
    }

    @Test
    fun `400 production_requires_service_account from the API names the two pins to add`() {
        server.enqueue(problem(400, "problem-production-requires-service-account"))

        // The local check reads --confirm-production as the production assertion; a production plane reached
        // without it is the API's call, and its answer gets the same guidance.
        val (exit, _, err) = create("--issuer", issuer, "--namespace", "forge")

        assertThat(exit).isEqualTo(CommandSupport.EXIT_HTTP_ERROR)
        assertThat(err).contains("production_requires_service_account").contains("--namespace <ns> and --service-account <name>")
    }

    @Test
    fun `get and list render a kubernetes trust with its pins, and the sign-in line reads the projected token file`() {
        server.enqueue(jsonResponse(200, fixture("trust-created-kubernetes")))
        val get = runCli("workload-identity", "trusts", "get", "7c2e9d10-4a5b-4c6d-8e7f-1a2b3c4d5e6f", "--gateway", baseUrl())
        assertThat(get.exit).isEqualTo(0)
        assertThat(get.out)
            .contains("kubernetes")
            .contains("forge-oauth2-proxy")
            .contains("t10j6Z4K")
            .contains(
                "thoryn login --workload-identity --client-id wi_9a8b7c6d5e4f3a2b1c0d9e8f --audience https://thoryn.auth.stg.thoryn.org " +
                    "--token-file /var/run/secrets/tokens/thoryn/token --scope \"tenant:applications.write\"",
            )

        server.enqueue(jsonResponse(200, """{"data":[${fixture("trust-created-kubernetes")}],"pagination":{"cursor":null}}"""))
        val list = runCli("workload-identity", "trusts", "list", "--gateway", baseUrl())
        assertThat(list.exit).isEqualTo(0)
        assertThat(list.out).contains("kubernetes").contains("ns=forge sa=forge-oauth2-proxy").contains(issuer)
    }

    @Test
    fun `--json output carries the kubernetes pin fields and never the key material`() {
        server.enqueue(jsonResponse(201, fixture("trust-created-kubernetes")))

        val (exit, out, _) = create(
            "--issuer", issuer, "--namespace", "forge", "--service-account", "forge-oauth2-proxy",
            "--jwks-file", jwksFile().toString(), "--confirm-production", "--json",
        )

        assertThat(exit).isEqualTo(0)
        // --json is the API's record as it came (the stable machine contract), not the table view.
        val json = parseJson(out)
        assertThat(json).containsEntry("provider", "kubernetes").containsEntry("clientId", "wi_9a8b7c6d5e4f3a2b1c0d9e8f")
        @Suppress("UNCHECKED_CAST")
        val kubernetes = json["kubernetes"] as Map<String, Any?>
        assertThat(kubernetes).containsEntry("namespace", "forge").containsEntry("serviceAccount", "forge-oauth2-proxy")
            .containsEntry("inlineKeyIds", listOf("t10j6Z4K")).doesNotContainKey("jwks")
        assertThat(out).doesNotContain("AQAB")
    }
}
