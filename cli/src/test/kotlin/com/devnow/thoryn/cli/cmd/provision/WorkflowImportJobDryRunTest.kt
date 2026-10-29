package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.provision.workflow.ImportSummary
import com.devnow.thoryn.cli.cmd.provision.workflow.ProvisioningWorkflowContract
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File
import java.util.Base64

/**
 * SSO-3991 — a DRY RUN of the reusable workflow's `import` job (contract v2 §3), in process: the exact command sequence its
 * import step runs for one configured file — copy the committed file into the artifact directory, `provision import
 * --for-workflow <file> --config <config> --file <copy> --write --output json`, `provision plan --file <copy> --output json`,
 * then `provision workflow import-summary` — against the fake product API, signed in as the file's connection's plan
 * profile. GitHub Actions itself is not run (there is no harness for the reusable workflow); [jobCommands] pins that the
 * workflow file runs these same commands with these same flags, so the two cannot drift apart silently.
 *
 * The secret check: the fake API is seeded to RETURN secret-shaped fields (an SMTP password, a federation client secret, an
 * application client secret) — what a product-api regression would look like. The artifact must still carry none of them:
 * the CLI renders a fixed field list per kind, and the summary a fixed field list per entry.
 */
class WorkflowImportJobDryRunTest : CommandTestBase() {

    private val api = FakeProductApi()

    @BeforeEach
    fun mount() { server.dispatcher = api }

    @AfterEach
    fun resetSeams() { ProvisionCommand.resetForTest() }

    private val secret = "SECRET-dry-run-value"
    private val wiProd = "wi_000000000000000000000p01"
    private val file = ".thoryn/environments/production/provision.yaml"
    private val connectionPath = ".thoryn/environments/production/connection.json"
    private val sha = "89abcdef0123456789abcdef0123456789abcdef"
    private val scopes = listOf(
        "tenant:environments.read", "tenant:environments.write", "tenant:email.read", "tenant:federation.read", "tenant:idp.read",
        "tenant:roles.read", "tenant:roles.write", "tenant:access.read",
    )

    private fun jwt(claims: String): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        return enc.encodeToString("""{"alg":"none"}""".toByteArray()) + "." + enc.encodeToString(claims.toByteArray()) + ".sig"
    }

    /** What `thoryn login --connection` leaves behind in a job in the plan environment: the trust's read-only plan profile. */
    private fun planSession() {
        val read = scopes.filter { it.endsWith(".read") }
        api.caller = "client:$wiProd"
        api.callerScopes = read.toSet()
        seedTokens(
            Tokens(
                accessToken = jwt("""{"client_id":"$wiProd","scope":"${read.joinToString(" ")}","tnt":"${api.tenantId}"}"""),
                authMode = Tokens.AUTH_MODE_WORKLOAD_IDENTITY, clientId = wiProd, issuer = "https://acme.auth.thoryn.io", gateway = baseUrl(),
                workspace = "acme", profile = Tokens.PROFILE_PLAN, jobEnvironment = "acme-production-plan", expiresAtEpochSecond = System.currentTimeMillis() / 1000 + 600,
            ),
        )
    }

    private val committed = "apiVersion: thoryn.io/tenant/v1\nresources:\n  - { kind: environment, name: ci-sbx, spec: { slug: ci-sbx, displayName: \"CI sandbox\" } }\n"

    private fun repository(): File {
        val root = File(tempHome.toFile(), "acme-config")
        File(root, ".thoryn/environments/production").mkdirs()
        File(root, ".thoryn/workflow.yaml").writeText("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - { file: $file, connection: $connectionPath }\n")
        File(root, connectionPath).writeText(
            """
            {
              "apiVersion": "thoryn.io/connection/v1",
              "workspace": { "slug": "acme" },
              "auth": {
                "method": "workload_identity",
                "clientId": "$wiProd",
                "audience": "https://acme.auth.thoryn.io",
                "scopes": [${scopes.joinToString(", ") { "\"$it\"" }}],
                "github": { "repository": "acme-config", "environment": "acme-production" }
              }
            }
            """.trimIndent() + "\n",
        )
        File(root, file).writeText(committed)
        return root
    }

    private fun seedWorkspace() {
        api.seedEnvironment("ci-sbx", "CI sandbox")
        api.emailProviders[null] = mutableMapOf("providerType" to "smtp", "smtpHost" to "smtp.example.com", "smtpPort" to 587, "fromAddress" to "no-reply@example.com", "enabled" to true, "smtpPassword" to secret)
        api.federationMembers += mutableMapOf("id" to "fm-1", "providerType" to "oidc", "displayName" to "Corp IdP", "discoveryUrl" to "https://idp.example.com", "clientId" to "corp", "clientSecret" to secret, "_env" to null)
        api.seedRole(null, "editor", listOf("docs:write"), description = "Edits documents")
        api.seedApplication(null, "Portal", clientId = "portal")
        api.applications.last()["clientSecret"] = secret
    }

    @Test
    fun `the import job's commands produce exactly the configured file plus a summary, all noop, with no secret anywhere`() {
        seedWorkspace()
        val root = repository()
        val config = File(root, ".thoryn/workflow.yaml")
        val out = File(tempHome.toFile(), "runner-temp/thoryn-import")
        val work = File(tempHome.toFile(), "runner-temp/thoryn-import-work").also { it.mkdirs() }
        planSession()

        // cp "$file" "$out/$file"
        val copy = File(out, file).also { it.parentFile.mkdirs(); File(root, file).copyTo(it) }
        // provision import --for-workflow "$file" --config "$CONFIG" --file "$out/$file" --write --output json > "$work/$i.import.json"
        val imported = runCli("provision", "import", "--for-workflow", file, "--root", root.path, "--config", config.path, "--file", copy.path, "--write", "--output", "json", "--gateway", baseUrl())
        assertThat(imported.exit).withFailMessage(imported.err).isEqualTo(0)
        ImportSummary.importJson(work, 0).writeText(imported.out)
        // provision plan --file "$out/$file" --output json > "$work/$i.plan.json" || plan_exit=$?
        val plan = runCli("provision", "plan", "--file", copy.path, "--output", "json", "--gateway", baseUrl())
        ImportSummary.planJson(work, 0).writeText(plan.out)
        ImportSummary.planExit(work, 0).writeText("${plan.exit}\n")
        // provision workflow import-summary --artifact "$out" --work "$work" --head-sha "$HEAD_SHA" --config "$CONFIG"
        val summary = runCli("provision", "workflow", "import-summary", "--artifact", out.path, "--work", work.path, "--head-sha", sha, "--config", config.path, "--root", root.path)
        assertThat(summary.exit).withFailMessage(summary.err).isEqualTo(CommandSupport.EXIT_OK)

        // The checkout is untouched; the artifact is exactly the configured file and the summary.
        assertThat(File(root, file).readText()).isEqualTo(committed)
        assertThat(out.walkTopDown().filter { it.isFile }.map { it.relativeTo(out).path }.toList())
            .containsExactlyInAnyOrder(file, ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE)
        // No secret in any file of the artifact, nor in what the job prints.
        out.walkTopDown().filter { it.isFile }.forEach { assertThat(it.readText()).withFailMessage("%s carries a secret", it).doesNotContain(secret) }
        assertThat(imported.out + imported.err + plan.out + summary.out).doesNotContain(secret)

        @Suppress("UNCHECKED_CAST")
        val doc = YAMLMapper.builder().build().readValue(File(out, ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE), Map::class.java) as Map<String, Any?>
        assertThat(doc["headSha"]).isEqualTo(sha)
        @Suppress("UNCHECKED_CAST") val f = (doc["files"] as List<Map<String, Any?>>).single()
        assertThat(f["path"]).isEqualTo(file)
        assertThat(f["apiVersion"]).isEqualTo("thoryn.io/tenant/v1")
        @Suppress("UNCHECKED_CAST") val entries = (f["imported"] as List<Map<String, Any?>>).associateBy { "${it["kind"]}/${it["name"]}" }
        // The write-only-secret kinds are read-only, with the reason; the role is converged (the trust may write roles).
        assertThat(entries.getValue("emailProvider/emailProvider")["readOnly"]).isEqualTo(true)
        assertThat(entries.getValue("emailProvider/emailProvider")["note"] as String).isNotBlank()
        assertThat(entries.values.single { it["kind"] == "federationMember" }["readOnly"]).isEqualTo(true)
        assertThat(entries.getValue("role/editor")["readOnly"]).isEqualTo(false)
        // An application belongs to its app project: listed, never imported into a tenant file.
        @Suppress("UNCHECKED_CAST") val notImported = f["notImported"] as List<String>
        assertThat(notImported).anyMatch { it.contains("portal") || it.contains("application") }
        assertThat(entries.keys).noneMatch { it.startsWith("application/") }
        // The preview, by the same read-only identity: nothing to do.
        @Suppress("UNCHECKED_CAST") val preview = f["plan"] as Map<String, Any?>
        assertThat(preview["allNoop"]).withFailMessage("plan preview: %s\n%s", preview, plan.err).isEqualTo(true)
        assertThat(api.provisioningWrites).isEmpty()
        assertThat(summary.out).contains("## Thoryn configuration import").contains("### $file")
    }

    @Test
    fun `a committed bodyFile is staged beside the copy, a stored template is imported as a file, and the artifact carries the configured file plus the bodies it references`() {
        // SSO-4042 — the committed file already declares one template with its body as a file; the platform holds a second one.
        seedWorkspace()
        api.emailTemplates["magic_link:*"] = mutableMapOf("subject" to "Sign in", "bodyHtml" to "<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>\n")
        api.emailTemplates["password_reset:*"] = mutableMapOf("subject" to "Reset", "bodyHtml" to "<p><a href=\"{{resetUrl}}\">Reset</a></p>\n")
        val root = repository()
        val emails = ".thoryn/environments/production/emails"
        File(root, "$emails/magic_link.html").apply { parentFile.mkdirs() }.writeText("<p><a href=\"{{magicLinkUrl}}\">Sign in</a></p>\n")
        val withTemplate = committed + "  - { kind: emailTemplate, name: welcome, spec: { type: magic_link, subject: \"Sign in\", bodyFile: emails/magic_link.html } }\n"
        File(root, file).writeText(withTemplate)
        val config = File(root, ".thoryn/workflow.yaml")
        val out = File(tempHome.toFile(), "runner-temp/thoryn-import")
        val work = File(tempHome.toFile(), "runner-temp/thoryn-import-work").also { it.mkdirs() }
        planSession()

        // cp "$file" "$out/$file" — the job copies the configured file alone; the CLI stages the body files it names.
        val copy = File(out, file).also { it.parentFile.mkdirs(); File(root, file).copyTo(it) }
        val imported = runCli("provision", "import", "--for-workflow", file, "--root", root.path, "--config", config.path, "--file", copy.path, "--write", "--output", "json", "--gateway", baseUrl())
        assertThat(imported.exit).withFailMessage(imported.err).isEqualTo(0)
        ImportSummary.importJson(work, 0).writeText(imported.out)
        val plan = runCli("provision", "plan", "--file", copy.path, "--output", "json", "--gateway", baseUrl())
        ImportSummary.planJson(work, 0).writeText(plan.out)
        ImportSummary.planExit(work, 0).writeText("${plan.exit}\n")
        val summary = runCli("provision", "workflow", "import-summary", "--artifact", out.path, "--work", work.path, "--head-sha", sha, "--config", config.path, "--root", root.path)
        assertThat(summary.exit).withFailMessage(summary.err).isEqualTo(CommandSupport.EXIT_OK)

        // The checkout is untouched; the artifact holds the configured file, the staged body, the imported body and the summary.
        assertThat(File(root, file).readText()).isEqualTo(withTemplate)
        assertThat(File(root, emails).listFiles()!!.map { it.name }).containsExactly("magic_link.html")
        assertThat(out.walkTopDown().filter { it.isFile }.map { it.relativeTo(out).path }.toList())
            .containsExactlyInAnyOrder(file, "$emails/magic_link.html", "$emails/password_reset.html", ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE)
        assertThat(File(out, "$emails/password_reset.html").readText()).isEqualTo("<p><a href=\"{{resetUrl}}\">Reset</a></p>\n")
        assertThat(File(copy.path).readText()).contains("bodyFile: emails/password_reset.html").doesNotContain("<p>")

        @Suppress("UNCHECKED_CAST")
        val doc = YAMLMapper.builder().build().readValue(File(out, ProvisioningWorkflowContract.IMPORT_SUMMARY_FILE), Map::class.java) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST") val f = (doc["files"] as List<Map<String, Any?>>).single()
        assertThat(f["bodyFiles"]).isEqualTo(listOf("emails/magic_link.html", "emails/password_reset.html"))
        @Suppress("UNCHECKED_CAST") val entries = (f["imported"] as List<Map<String, Any?>>).associateBy { "${it["kind"]}/${it["name"]}" }
        // The plan profile holds tenant:idp.read only: the template is imported as a read-only reference, naming the write scope.
        assertThat(entries.getValue("emailTemplate/password-reset")["readOnly"]).isEqualTo(true)
        assertThat(entries.getValue("emailTemplate/password-reset")["note"] as String).contains("tenant:idp.write")
        @Suppress("UNCHECKED_CAST") val preview = f["plan"] as Map<String, Any?>
        assertThat(preview["allNoop"]).withFailMessage("plan preview: %s\n%s", preview, plan.err).isEqualTo(true)
        assertThat(api.provisioningWrites).isEmpty()
    }

    @Test
    fun `the job runs these same commands with these same flags`() {
        val text = CiIdentityFixture.locate(ProvisioningWorkflowContract.REUSABLE_WORKFLOW_PATH).readText()
        val job = text.substring(text.indexOf("\n  import:\n"))
        assertThat(job).contains("cp \"\$file\" \"\$out/\$file\"")
            .contains("java -jar thoryn.jar provision import --for-workflow \"\$file\" --config \"\$CONFIG\" --file \"\$out/\$file\" --write --output json > \"\$work/\$i.import.json\"")
            .contains("java -jar thoryn.jar provision plan --file \"\$out/\$file\" --output json > \"\$work/\$i.plan.json\"")
            .contains("echo \"\$plan_exit\" > \"\$work/\$i.plan.exit\"")
            .contains("java -jar thoryn.jar provision workflow import-summary --artifact \"\$out\" --work \"\$work\" --head-sha \"\$HEAD_SHA\" --config \"\$CONFIG\"")
        // The work files are the ones ImportSummary reads.
        val work = File("w")
        assertThat(ImportSummary.importJson(work, 0).name).isEqualTo("0.import.json")
        assertThat(ImportSummary.planJson(work, 0).name).isEqualTo("0.plan.json")
        assertThat(ImportSummary.planExit(work, 0).name).isEqualTo("0.plan.exit")
    }
}
