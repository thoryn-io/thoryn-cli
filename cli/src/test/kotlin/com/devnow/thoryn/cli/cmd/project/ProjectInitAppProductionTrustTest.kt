package com.devnow.thoryn.cli.cmd.project

import com.devnow.thoryn.cli.auth.Tokens
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-4079 (product-owner decisions D1–D3, 2026-11-03) — the app's PRODUCTION trust and its owner:
 *  - D2: with the template's `.thoryn/production/declaration.json` and `--config-repo`, the run protects the `production` GitHub
 *    environment, then creates the production trust as the person (repository ids + environment + default branch, exactly the
 *    application ceiling, no grant, no plan profile) and sets its variables there; a machine session is refused up front, a
 *    stale sign-in gets the passkey step-up fix;
 *  - D1: `owner` on each app trust goes to the config project's identity on that plane; a non-admin's refusal leaves it pending;
 *  - D3: without `--config-repo`, no production trust — and the output says why;
 *  - the creation slot the production apply needs is named either way.
 */
class ProjectInitAppProductionTrustTest : AppConfigRepoTestBase() {

    @Test
    fun `with the declaration and a config project the run protects production, creates the production trust, sets its variables and grants owner`() {
        publishProductionDeclaration()

        val (exit, out, err) = runCli(*withConfig, "--production-url", "$url/", "--reviewer", "alice", "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        val appId = gh.repoId("acme/web")
        // The GitHub environment `production`: deploys from main only, alice required (the fake plan is Enterprise).
        val env = gh.environments.getValue("acme/web/production")
        assertThat(env.custom).isTrue()
        assertThat(env.policies.map { it.second }).containsExactly("main")
        assertThat(env.reviewers).containsExactly(501L)
        // The production trust: pinned to the repository ids, the environment and the default branch; the ceiling; no plan, no grant.
        val trust = appTrust("production")
        assertThat(trust["name"]).isEqualTo("starter-production-$appId")
        assertThat(trust["scopes"]).isEqualTo(ProductionDeclaration.SCOPES)
        assertThat(trust).doesNotContainKey("plan")
        @Suppress("UNCHECKED_CAST")
        val pins = trust["github"] as Map<String, Any?>
        assertThat(pins).containsEntry("owner", "acme").containsEntry("repository", "web").containsEntry("environment", "production")
            .containsEntry("ref", "refs/heads/main")
        assertThat((pins["repositoryId"] as Number).toLong()).isEqualTo(appId)
        assertThat((pins["ownerId"] as Number).toLong()).isEqualTo(900L)
        val create = api.writes.first { it.path == "/api/v1/workload-identity/trusts" && it.env == "production" }
        assertThat(create.body).containsEntry("confirmProduction", true).doesNotContainKey("plan")
        // The protection came before any Thoryn write: the trust is the first write, and it is the production one.
        assertThat(api.writes.first()).isEqualTo(create)
        // No grant for the production trust's own client (the sandbox one keeps its manager grant).
        val prodClient = trust["clientId"] as String
        assertThat(api.grants).noneMatch { it["subject"] == "client:$prodClient" }
        // The variables, on the protected environment.
        assertThat(gh.variables).containsEntry("acme/web@production:THORYN_PRODUCTION_WIF_CLIENT_ID", prodClient)
            .containsEntry("acme/web@production:THORYN_PRODUCTION_URL", url)
        val protectedAt = gh.invocations.indexOf("gh api --method PUT repos/acme/web/environments/production --input -")
        val variableAt = gh.invocations.indexOfFirst { it.startsWith("gh variable set THORYN_PRODUCTION_WIF_CLIENT_ID") }
        assertThat(protectedAt).isNotNegative().isLessThan(variableAt)
        // D1: owner on each app trust for the config project's identity on that plane.
        val sandboxTrust = appTrust("dev")
        assertThat(api.grants).contains(
            mapOf("subject" to "client:wi_config_dev", "relation" to "owner", "object" to "trust:${sandboxTrust["id"]}"),
            mapOf("subject" to "client:wi_config_prod", "relation" to "owner", "object" to "trust:${trust["id"]}"),
        )
        val report = parseJson(out)
        assertThat(steps(report)).containsEntry("protection", "set").containsEntry("owner", "granted,granted")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["productionConnection"] as Map<String, Any?>).containsEntry("declared", true).containsEntry("clientId", prodClient)
            .containsEntry("trust", "starter-production-$appId").containsEntry("reason", null).containsEntry("productionUrl", url)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["productionEnvironment"] as Map<String, Any?>).containsEntry("githubEnvironment", "production")
            .containsEntry("deploymentBranch", "main").containsEntry("reviewersActive", true)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["creationSlot"] as Map<String, Any?>).containsEntry("object", "application:web-production").containsEntry("environment", "production")
            .containsEntry("subject", "client:$prodClient").containsEntry("status", "awaiting_admin")
            .containsEntry("command", "thoryn access reserve client:$prodClient application:web-production --environment production")
        @Suppress("UNCHECKED_CAST")
        val owners = report["owners"] as List<Map<String, Any?>>
        assertThat(owners.map { it["status"] }).containsExactly("granted", "granted")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["nextSteps"] as List<String>)
            .anyMatch { it.contains("thoryn access reserve client:$prodClient application:web-production --environment production") }
    }

    @Test
    fun `a non-admin's owner grant is refused - the run succeeds with owner pending and the fix named`() {
        publishProductionDeclaration()
        api.ownerRefused = true

        val (exit, out, err) = runCli(*withConfig, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.grants).noneMatch { it["relation"] == "owner" }
        val report = parseJson(out)
        assertThat(steps(report)).containsEntry("owner", "pending,pending").containsEntry("config-project", "pending review")
        @Suppress("UNCHECKED_CAST")
        val owners = report["owners"] as List<Map<String, Any?>>
        assertThat(owners).allMatch { it["status"] == "pending" && (it["note"] as String).contains("only a workspace admin sets an owner") }
        @Suppress("UNCHECKED_CAST")
        assertThat(report["nextSteps"] as List<String>).anyMatch {
            it.startsWith("Ownership pending") && it.contains("thoryn access approve") && it.contains("thoryn access grant client:wi_config_prod owner trust:")
        }
        // Everything else still happened: both trusts, the variables, the pull request.
        assertThat(api.trustsIn("production")).hasSize(2)
        assertThat(gh.pulls.getValue("acme/platform")).hasSize(1)
    }

    @Test
    fun `the sandbox trust's owner falls back to the config project's production identity when it has no trust in that sandbox`() {
        publishProductionDeclaration()
        api.trusts.removeIf { it["id"] == "cfg-dev" }

        val (exit, _, err) = runCli(*withConfig)

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.grants).contains(mapOf("subject" to "client:wi_config_prod", "relation" to "owner", "object" to "trust:${appTrust("dev")["id"]}"))
    }

    @Test
    fun `two config-repository trusts on a plane make the owner ambiguous - skipped with a note, never guessed`() {
        publishProductionDeclaration()
        api.trusts += LinkedHashMap(api.trusts.first { it["id"] == "cfg-prod" }).apply { put("id", "cfg-prod-2"); put("name", "another"); put("clientId", "wi_other") }

        val (exit, out, err) = runCli(*withConfig, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        @Suppress("UNCHECKED_CAST")
        val owners = parseJson(out)["owners"] as List<Map<String, Any?>>
        val production = owners.single { it["environment"] == "production" }
        assertThat(production).containsEntry("status", "skipped").containsEntry("subject", null)
        assertThat(production["note"] as String).contains("has 2 workload identity trusts in production")
        assertThat(api.grants).noneMatch { it["subject"] == "client:wi_other" }
    }

    @Test
    fun `without --config-repo no production trust is created, and the output says no config project owns it and names the slot`() {
        publishProductionDeclaration()

        val (exit, out, err) = runCli(*app, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(api.trustsIn("production").map { it["id"] }).containsExactly("cfg-prod") // only the config project's own
        assertThat(gh.environments).doesNotContainKey("acme/web/production")
        assertThat(gh.variables.keys).noneMatch { it.contains("@production:") }
        assertThat(api.grants).noneMatch { it["relation"] == "owner" }
        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["productionConnection"] as Map<String, Any?>).containsEntry("declared", true).containsEntry("trust", null)
            .containsEntry("reason", "no config project owns this repository's CI identity: re-run with --config-repo <owner/name>")
        @Suppress("UNCHECKED_CAST")
        assertThat(report["creationSlot"] as Map<String, Any?>).containsEntry("object", "application:web-production")
            .containsEntry("status", "awaiting_production_trust").containsEntry("command", null)
        @Suppress("UNCHECKED_CAST")
        val next = report["nextSteps"] as List<String>
        assertThat(next).anyMatch { it.startsWith("No config project owns this repository's CI identity") && it.contains("--config-repo <owner/name>") && it.contains("thoryn project init config") }
            .anyMatch { it.contains("creation slot for application:web-production") }
    }

    @Test
    fun `a template without the declaration gets no production trust, and the config repository only the sandbox trust - never a production client`() {
        val (exit, out, err) = runCli(*withConfig, "--json")

        assertThat(exit).describedAs(err).isEqualTo(0)
        assertThat(gh.invocations).contains("gh api repos/thoryn-io/starter-express/contents/${ProductionDeclaration.PATH}")
        assertThat(api.trustsIn("production").map { it["id"] }).containsExactly("cfg-prod")
        assertThat(gh.environments).doesNotContainKey("acme/web/production")
        assertThat(gh.branches.getValue("acme/platform@thoryn/app-web").getValue(productionFile)).isEqualTo(productionSection)
        val sandbox = onBranch(sandboxFile)
        assertThat(parsed(sandbox, sandboxFile).resources.map { it.kind }).containsExactly("environment", "workloadIdentityTrust")
        gh.branches.values.flatMap { it.values }.forEach { assertThat(it).doesNotContain("publishTo").doesNotContain("kind: application") }
        assertThat(api.grants).contains(mapOf("subject" to "client:wi_config_dev", "relation" to "owner", "object" to "trust:${appTrust("dev")["id"]}"))
        val report = parseJson(out)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["productionConnection"] as Map<String, Any?>).containsEntry("declared", false)
        @Suppress("UNCHECKED_CAST")
        assertThat(report["creationSlot"] as Map<String, Any?>).containsEntry("status", "awaiting_production_trust")
    }

    @Test
    fun `a machine session is refused before anything changes when the run would create the production trust`() {
        publishProductionDeclaration()
        seedTokens(Tokens(accessToken = accessToken, gateway = baseUrl(), workspace = "acme", authMode = Tokens.AUTH_MODE_CLIENT_CREDENTIALS, clientId = "cli-ci"))

        val (exit, out, _) = runCli(*withConfig, "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "person_required").containsEntry("changed", false)
        assertThat(body["hint"] as String).contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `a sign-in too old for the production trust stops with the passkey re-login, leaving nothing in Thoryn`() {
        publishProductionDeclaration()
        api.productionTrustStepUp = true

        val (exit, out, _) = runCli(*withConfig, "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_HTTP)
        val body = parseJson(out)
        assertThat(body).containsEntry("error", "insufficient_user_authentication").containsEntry("maxAge", 300)
        assertThat(body["errorDescription"] as String).contains("passkey sign-in from the last 5 minutes")
        assertThat(body["hint"] as String).contains("thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300")
            .contains("re-run: thoryn project init app")
        // The production trust is the first Thoryn write: nothing else was created there.
        assertThat(api.trusts.map { it["id"] }).containsExactlyInAnyOrder("cfg-prod", "cfg-dev")
        assertThat(api.grants).isEmpty()
    }

    @Test
    fun `a malformed declaration is starter_template_invalid and nothing changes`() {
        val wider = { d: MutableMap<String, Any?> ->
            @Suppress("UNCHECKED_CAST")
            val c = (d["connections"] as MutableMap<String, Any?>)["production"] as MutableMap<String, Any?>
            c["scopes"] = ProductionDeclaration.SCOPES + "tenant:users.read"
        }
        val granted = { d: MutableMap<String, Any?> ->
            @Suppress("UNCHECKED_CAST")
            val c = (d["connections"] as MutableMap<String, Any?>)["production"] as MutableMap<String, Any?>
            c["grant"] = mapOf("relation" to "manager", "on" to "environment")
        }
        listOf(wider to "must be exactly", granted to "declares a grant").forEach { (edit, why) ->
            publishProductionDeclaration(edit)
            val (exit, out, _) = runCli(*withConfig, "--json")
            assertThat(exit).isEqualTo(ProjectInit.EXIT_CHECK)
            val body = parseJson(out)
            assertThat(body).containsEntry("error", "starter_template_invalid").containsEntry("changed", false)
            assertThat(body["errorDescription"] as String).contains(ProductionDeclaration.PATH).contains(why)
        }
        gh.productionDeclarations["thoryn-io/starter-express"] = "{not json"
        assertThat(parseJson(runCli(*app, "--json").out)).containsEntry("error", "starter_template_invalid")
        assertThat(gh.mutations).isEmpty()
        assertThat(api.writes).isEmpty()
    }

    @Test
    fun `an unprotectable production environment stops before any Thoryn write`() {
        publishProductionDeclaration()
        gh.failProtectionWith = "gh: Must have admin rights to Repository. (HTTP 403)"

        val (exit, _, _) = runCli(*withConfig, "--json")

        assertThat(exit).isEqualTo(ProjectInit.EXIT_GH)
        assertThat(api.writes).isEmpty()
    }
}
