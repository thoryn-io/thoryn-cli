package com.devnow.thoryn.provision

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * SSO-3710 (oauthy ADR 2026-10-15 §1) — the fix request as DATA: the document shape against the bundled schema's
 * contract (`fix-request.schema.json` is the documented contract, this class is the runtime; they must agree — the
 * same hand-rolled drift guard the connection schema has), the mapping of a red plan's rows to items and notes, and
 * the ONE renderer whose `cli` strings the JSON and the terminal share.
 */
class FixRequestTest {

    private val json = JsonMapper.builder().build()
    private val schema: JsonNode = json.readTree(javaClass.getResourceAsStream(FixRequest.SCHEMA_RESOURCE)!!.readBytes())

    private val subject = "client:wi_10a7b379c79f7d1353f5798d"

    private fun request(items: List<FixRequest.MissingRight>, notes: List<String> = emptyList()) = FixRequest(
        cliVersion = "0.35.0",
        repository = FixRequest.Repository("thoryn-io", 229451779, "thoryn-cli", 1361536515),
        run = FixRequest.Run(38547022158, "0123456789abcdef0123456789abcdef01234567", "thoryn-provision-e2e-plan"),
        workspace = "thoryn",
        file = FixRequest.FileRef(".thoryn/provision.yaml", "sha256:" + "ab".repeat(32)),
        trust = FixRequest.Trust("thoryn-cli-ci", "production", "thoryn-provision-e2e", "d3ec5a8f-fdc5-4e20-acd3-bad167308fca", "wi_10a7b379c79f7d1353f5798d"),
        missing = items,
        notes = notes,
    )

    @Test
    fun `the document carries exactly the schema's properties, the item exactly the schema's, and the kinds are the schema's enum`() {
        val doc = json.readTree(request(listOf(FixRequest.owner(subject, "application:cli", "access_not_owned — …"))).toJson())
        val topLevel = schema["properties"].properties().map { it.key }.toSet()
        assertThat(doc.properties().map { it.key }.toSet()).isEqualTo(topLevel)
        val required: List<String> = schema["required"].toList().map { it.asString() }
        assertThat(required).containsExactlyInAnyOrder("version", "trust", "missing")
        assertThat(doc["version"].asInt()).isEqualTo(schema["properties"]["version"]["const"].asInt()).isEqualTo(FixRequest.VERSION)
        val itemKeys = schema["\$defs"]["missingRight"]["properties"].properties().map { it.key }.toSet()
        assertThat(doc["missing"][0].properties().map { it.key }.toSet()).isEqualTo(itemKeys)
        val itemRequired: List<String> = schema["\$defs"]["missingRight"]["required"].toList().map { it.asString() }
        assertThat(itemRequired).containsExactlyInAnyOrderElementsOf(itemKeys)
        val kinds: List<String> = schema["\$defs"]["missingRight"]["properties"]["kind"]["enum"].toList().map { it.asString() }
        val wires: List<String> = FixRequest.Kind.entries.map { it.wire }
        assertThat(wires).containsExactlyInAnyOrderElementsOf(kinds)
        val trustRequired: List<String> = schema["properties"]["trust"]["required"].toList().map { it.asString() }
        val trustKeys: List<String> = doc["trust"].properties().map { it.key }
        assertThat(trustRequired).containsExactlyInAnyOrderElementsOf(trustKeys)
        // The binding hints are present as the ADR example has them; a consumer discards them in favour of GitHub's record.
        assertThat(doc["repository"]["ownerId"].asLong()).isEqualTo(229451779L)
        assertThat(doc["run"]["jobEnvironment"].asString()).isEqualTo("thoryn-provision-e2e-plan")
        assertThat(doc["file"]["sha256"].asString()).matches("^sha256:[0-9a-f]{64}$")
    }

    @Test
    fun `an owner item's cli IS the grant command the prose hint quotes — one spelling`() {
        val item = FixRequest.owner(subject, "application:cli", "access_not_owned — this identity holds no relation on application:cli")
        assertThat(item.kind).isEqualTo(FixRequest.Kind.OWNER)
        assertThat(item.cli).isEqualTo("thoryn access grant client:wi_10a7b379c79f7d1353f5798d owner application:cli")
        assertThat(FixRequest.hint(item)).isEqualTo("a workspace admin grants it with `${item.cli}`")
        assertThat(FixRequest.render(listOf(item))).contains("  - owner on application:cli for $subject: ").contains("\n      ${item.cli}")
    }

    @Test
    fun `an unknown subject renders as a placeholder, never as an empty token`() {
        assertThat(FixRequest.grantCommand(null, "manager", "environment:env-1")).isEqualTo("thoryn access grant <subject> manager environment:env-1")
        assertThat(FixRequest.manager(null, "environment:env-1", "…").cli).contains("<subject>")
    }

    @Test
    fun `a plan_profile item names the job's environment and the set-plan-profile command — with the trust id placeholder and its resolver when unknown`() {
        val item = FixRequest.planProfile(null, null, "thoryn-provision-e2e-plan", "thoryn-provision-e2e")
        assertThat(item.kind).isEqualTo(FixRequest.Kind.PLAN_PROFILE)
        assertThat(item.objectRef).isNull()
        assertThat(item.subject).isNull()
        assertThat(item.environment).isEqualTo("thoryn-provision-e2e-plan")
        assertThat(item.reason).contains("'thoryn-provision-e2e-plan'").contains("apply environment 'thoryn-provision-e2e'").contains("environment_mismatch")
        assertThat(item.cli).isEqualTo("thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment thoryn-provision-e2e-plan")
        val rendered = FixRequest.render(listOf(item))
        assertThat(rendered)
            .contains("plan_profile on GitHub environment 'thoryn-provision-e2e-plan'")
            .contains(item.cli!!)
            .contains("`thoryn workload-identity trusts list`")

        val resolved = FixRequest.planProfile("thoryn-cli-ci", "d3ec5a8f-fdc5-4e20-acd3-bad167308fca", "thoryn-provision-e2e-plan", "thoryn-provision-e2e")
        assertThat(resolved.objectRef).isEqualTo("trust:thoryn-cli-ci")
        assertThat(resolved.cli).isEqualTo("thoryn workload-identity trusts set-plan-profile d3ec5a8f-fdc5-4e20-acd3-bad167308fca --plan-environment thoryn-provision-e2e-plan")
        assertThat(FixRequest.render(listOf(resolved))).doesNotContain("trusts list")
    }

    @Test
    fun `an object another repository owns is an owner item with NO command — shown, never performed`() {
        val item = FixRequest.ownedElsewhere(subject, "application:rp", "access_owned_elsewhere — application:rp is owned by another repository")
        assertThat(item.kind).isEqualTo(FixRequest.Kind.OWNER)
        assertThat(item.cli).isNull()
        assertThat(FixRequest.render(listOf(item))).contains("(no command runs for you: an admin decides")
        assertThat(json.readTree(request(listOf(item)).toJson())["missing"][0]["cli"].isNull).isTrue()
    }

    @Test
    fun `fromPlan takes every ERROR row with a fix as an item and every other ERROR row as a note — and nothing from a green row`() {
        val owner = FixRequest.owner(subject, "application:foreign", "access_not_owned — …")
        val plan = ProvisionPlan(
            listOf(
                PlannedChange("environment", "ci", ChangeAction.NOOP, "exists and matches", liveId = "env-1", access = "manager"),
                PlannedChange("application", "foreign", ChangeAction.ERROR, owner.reason, error = ProvisionEngine.ERROR_NOT_OWNED, fix = owner),
                PlannedChange("application", "shared", ChangeAction.ERROR, "access_read_only — read-only reference differs", error = ProvisionEngine.ERROR_READ_ONLY, fixNote = ProvisionEngine.FILE_FIX_NOTE),
                PlannedChange("workloadIdentityTrust", "me", ChangeAction.ERROR, "workload_identity_trust_is_self — …", error = ProvisionEngine.ERROR_TRUST_IS_SELF),
            ),
        )
        val (items, notes) = FixRequest.fromPlan(plan)
        assertThat(items).containsExactly(owner)
        assertThat(notes).containsExactly(
            "application shared: ${ProvisionEngine.FILE_FIX_NOTE}",
            "workloadIdentityTrust me: workload_identity_trust_is_self — …",
        )
        assertThat(FixRequest.render(emptyList())).isEmpty()
    }

    // ── SSO-3722 / SSO-3723 — one "To fix" block, two options ──

    private val link = "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/38547022158"

    @Test
    fun `without web consent Option 1 is the raw commands under the check-each-line warning, then the notes — Option 2 says how to get a link`() {
        val item = FixRequest.owner(subject, "application:cli", "access_not_owned — …")
        val rendered = FixRequest.render(listOf(item), listOf("application shared: a change to the file"), null)
        val lines = rendered.lines()
        assertThat(lines[0]).isEqualTo("To fix — Option 1, with the CLI (a workspace admin):")
        assertThat(lines[1]).isEqualTo("  ${FixRequest.CHECK_EACH_LINE_WARNING}")
        assertThat(rendered)
            .contains("\n  - owner on application:cli for $subject: access_not_owned — …\n      ${item.cli}\n")
            .contains("\n  - application shared: a change to the file\n")
            .doesNotContain("thoryn access approve")
        assertThat(lines.last()).isEqualTo("To fix — Option 2, in the browser: ${FixRequest.NO_CONSENT_LINK_LINE}")
        // A note alone is still a fix (a file edit): the block is printed for it — with no command, no warning.
        assertThat(FixRequest.render(emptyList(), listOf("connection.json: add auth.github.environment"), null))
            .startsWith(FixRequest.OPTION_CLI_HEADING).contains("  - connection.json: add auth.github.environment")
            .doesNotContain(FixRequest.CHECK_EACH_LINE_WARNING)
    }

    @Test
    fun `with web consent Option 1 is thoryn access approve for the run — the rights listed without their raw commands, the notes apart, the link last`() {
        val item = FixRequest.owner(subject, "application:cli", "access_not_owned — …")
        val plan = FixRequest.planProfile(null, null, "thoryn-provision-e2e-plan", "thoryn-provision-e2e")
        val rendered = FixRequest.render(listOf(item, plan), listOf("application shared: a change to the file"), link)
        val lines = rendered.lines()
        assertThat(lines[0]).isEqualTo(FixRequest.OPTION_CLI_HEADING)
        assertThat(lines[1]).isEqualTo("      thoryn access approve thoryn-io/thoryn-cli/38547022158")
        assertThat(lines[2]).isEqualTo("  ${FixRequest.APPROVE_EXPLANATION}")
        assertThat(rendered)
            .contains("\n  - owner on application:cli for $subject: access_not_owned — …\n")
            .contains("\n  - plan_profile on GitHub environment 'thoryn-provision-e2e-plan': ")
            .contains("\n  ${FixRequest.FILE_EDITS_HEADING}\n  - application shared: a change to the file\n")
            // The raw grant lines are NOT relayed when a consent exists: the consent re-checks them, a pasted line would not.
            .doesNotContain(item.cli!!)
            .doesNotContain(plan.cli!!)
            .doesNotContain("trusts list")
            .doesNotContain(FixRequest.CHECK_EACH_LINE_WARNING)
        assertThat(lines.last()).isEqualTo("To fix — Option 2, in the browser: $link")
    }

    @Test
    fun `a consent link with nothing the consent could grant keeps Option 1 as the file edits or the dispute — no approve command`() {
        val notesOnly = FixRequest.render(emptyList(), listOf("connection.json: add auth.github.environment"), link)
        assertThat(notesOnly).doesNotContain("thoryn access approve").contains("  - connection.json: add auth.github.environment")
        assertThat(notesOnly.lines().last()).isEqualTo("To fix — Option 2, in the browser: $link")
        val dispute = FixRequest.ownedElsewhere(subject, "application:rp", "access_owned_elsewhere — …")
        val disputeOnly = FixRequest.render(listOf(dispute), emptyList(), link)
        assertThat(disputeOnly).doesNotContain("thoryn access approve").contains("(no command runs for you: an admin decides")
        assertThat(FixRequest.approveRun(listOf(dispute), link)).isNull()
        assertThat(FixRequest.approveRun(listOf(FixRequest.owner(subject, "application:cli", "…")), "https://app.thoryn.io/not-a-run-link")).isNull()
    }

    @Test
    fun `the request's options carry Option 1 as data — the approve command with web consent, the warned body without`() {
        val item = FixRequest.manager(subject, "environment:env-1", "access_not_owned — …")
        val withConsent = json.readTree(request(listOf(item), notes = listOf("user x: a note")).copy(consentUrl = link).toJson())
        assertThat(withConsent["options"]["cli"].asString()).isEqualTo("thoryn access approve thoryn-io/thoryn-cli/38547022158")
        assertThat(withConsent["options"]["consentUrl"].asString()).isEqualTo(link)
        // Every item still carries its own command — the data a deployment without web consent relays.
        assertThat(withConsent["missing"][0]["cli"].asString()).isEqualTo(item.cli)
        val without = json.readTree(request(listOf(item), notes = listOf("user x: a note")).toJson())
        assertThat(without["options"]["cli"].asString()).isEqualTo(FixRequest.renderOption1Body(listOf(item), listOf("user x: a note")))
        assertThat(without["options"]["cli"].asString()).startsWith("  ${FixRequest.CHECK_EACH_LINE_WARNING}").contains(item.cli!!).contains("user x: a note")
        assertThat(without["options"]["consentUrl"].isNull).isTrue()
        val none = json.readTree(request(emptyList()).toJson())
        assertThat(none["options"]["cli"].isNull).isTrue()
        assertThat(none["options"]["consentUrl"].isNull).isTrue()
        assertThat(schema["properties"]["options"]["required"].toList().map { it.asString() }).containsExactlyInAnyOrder("cli", "consentUrl")
        // The document's shape did not change: still version 1.
        assertThat(withConsent["version"].asInt()).isEqualTo(1)
    }

    @Test
    fun `the consent link is built from the configured base URL and the run — never from a partial context`() {
        assertThat(FixRequest.consentUrl("https://app.thoryn.io/", "thoryn-io", "thoryn-cli", 38547022158)).isEqualTo(link)
        assertThat(FixRequest.consentUrl(null, "thoryn-io", "thoryn-cli", 38547022158)).isNull()
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", null, "thoryn-cli", 38547022158)).isNull()
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "thoryn-io", "", 38547022158)).isNull()
        assertThat(FixRequest.consentUrl("https://app.thoryn.io", "thoryn-io", "thoryn-cli", null)).isNull()
        assertThat(FixRequest.consentUrl("app.thoryn.io", "thoryn-io", "thoryn-cli", 1)).isNull()
        assertThat(link).matches(schema["properties"]["options"]["properties"]["consentUrl"]["pattern"].asString())
    }

    @Test
    fun `write lands pretty JSON with a trailing newline at the path, creating its directory`(@TempDir dir: Path) {
        val path = dir.resolve("nested/thoryn-provision-request.json")
        request(listOf(FixRequest.viewer(subject, "application:shared", "access_not_owned — …")), notes = listOf("application x: file fix")).write(path)
        val text = Files.readString(path)
        assertThat(text).endsWith("}\n").contains("\"kind\" : \"viewer\"")
        val doc = json.readTree(text)
        assertThat(doc["missing"][0]["cli"].asString()).isEqualTo("thoryn access grant $subject viewer application:shared")
        assertThat(doc["notes"][0].asString()).isEqualTo("application x: file fix")
    }
}
