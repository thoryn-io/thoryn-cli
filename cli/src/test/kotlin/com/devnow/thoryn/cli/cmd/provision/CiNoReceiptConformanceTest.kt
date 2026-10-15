package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.E2E_WORKFLOW_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.GITIGNORE_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.PROVISION_ACTION_PATH
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.RECEIPT_IGNORE_RULE
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.locate
import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture.repositoryRoot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.JsonNode
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File

/**
 * SSO-3717 (parent SSO-3304; oauthy ADR `2026-10-15-platform-is-the-ledger-no-committed-provisioning-receipt` §6) —
 * THIS repository has stopped committing a provisioning receipt and adopted the engine's SSO-3715 semantics. The
 * platform's `owner` relation is the ledger; nothing is written beside the file and nothing is committed back:
 *
 *  - no `<name>.receipt.json` exists under `.thoryn/` in the checkout, and `.gitignore` ignores every one again — SSO-3697's
 *    `!.thoryn/provision.receipt.json` exception is gone with the receipt pull request it served;
 *  - the composite Action (`.github/actions/provision`) has no `receipt` output and reads nothing from a receipt: the
 *    `environment` / `client-id` outputs come from `thoryn provision apply --output json` (`resources[]`), the apply
 *    document is exposed as `apply-result`, and the teardown runs `thoryn provision destroy --output json`, exposing its
 *    document as `destroy-result` (owner-gated; `--confirm` still forwarded);
 *  - `provision-e2e.yml` ASSERTS the destroy's scope from that document — exactly `application/loopback-rp` removed,
 *    `application/cli` and `environment/ci` left as `retained by the file` rows — the ADR's dogfood verification.
 *
 * [CiProvisionFileConformanceTest] pins the `retain: true` half in `provision.yaml`; this class pins the repository
 * around it. Every assertion here was watched failing against the SSO-3697 shape it replaces.
 */
class CiNoReceiptConformanceTest {

    private val root: File = repositoryRoot()
    private val yaml = YAMLMapper.builder().build()
    private val actionText = locate(PROVISION_ACTION_PATH).readText()
    private val action: JsonNode = yaml.readTree(actionText)
    private val e2eText = locate(E2E_WORKFLOW_PATH).readText()
    private val e2e: JsonNode = yaml.readTree(e2eText)

    private fun JsonNode.steps(): List<JsonNode> = this["steps"].toList()
    private fun JsonNode.run(): String = this["run"]?.asString() ?: ""

    @Test
    fun `no receipt is committed under thoryn and gitignore ignores every receipt again — no un-ignore exception`() {
        val receipts = File(root, ".thoryn").listFiles { f -> f.isFile && f.name.endsWith(".receipt.json") }!!.map { it.name }
        assertThat(receipts)
            .withFailMessage("%s sit(s) under .thoryn/ — the engine writes no receipt since SSO-3715 and the committed one was deleted by SSO-3717; delete it (an older CLI's leftover is git-ignored but must not sit beside the file either)", receipts)
            .isEmpty()
        val rules = locate(GITIGNORE_PATH).readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        assertThat(rules).withFailMessage(".gitignore must ignore every .thoryn/*.receipt.json (an older CLI still writes one)").contains(RECEIPT_IGNORE_RULE)
        val unignored = rules.filter { it.startsWith("!") && it.contains(".receipt.json") }
        assertThat(unignored)
            .withFailMessage("%s un-ignore(s) a receipt — SSO-3697's exception served the receipt pull request, which SSO-3717 removed; nothing is committed back", unignored)
            .isEmpty()
    }

    @Test
    fun `the composite Action has no receipt output and reads the ids from apply --output json`() {
        val outputs = action["outputs"].propertyNames().toList()
        assertThat(outputs).withFailMessage("the Action still exposes a `receipt` output — there is no receipt (SSO-3715)").doesNotContain("receipt")
        assertThat(outputs).contains("environment", "client-id", "issuer", "apply-result", "destroy-result")
        assertThat(action["outputs"]["apply-result"]["value"].asString()).isEqualTo("\${{ steps.apply.outputs.apply-result }}")
        assertThat(action["outputs"]["destroy-result"]["value"].asString()).isEqualTo("\${{ steps.destroy.outputs.destroy-result }}")

        val apply = action["runs"]["steps"].toList().single { it["id"]?.asString() == "apply" }
        val run = apply.run()
        assertThat(run).contains("provision apply --file \"\$FILE\" --yes --output json > \"\$result\"")
        // The ids come from the apply's own document, never from a file beside the provisioning file.
        assertThat(run).contains("[.resources[] | select(.kind==\"environment\") | (.attributes.slug // .environment // \"\")] | first // \"\"")
        assertThat(run).contains("[.resources[] | select(.kind==\"application\") | .id] | first // \"\"")
        assertThat(run).contains("echo \"apply-result=\$result\"")
        assertThat(run).doesNotContain("cat \"\$receipt\"").doesNotContain("test -f \"\$receipt\"").doesNotContain("echo \"receipt=")
        // A receipt turning up next to the file is an OLDER CLI — the step fails rather than letting it near a commit.
        assertThat(run).contains("if [ -f \"\$receipt\" ]; then").contains("exit 1")
        assertThat(run).contains("jq -e '.resources | type == \"array\"'")
    }

    @Test
    fun `the Action's teardown is the owner-gated destroy with its JSON document exposed, and still forwards --confirm`() {
        val destroy = action["runs"]["steps"].toList().single { it["id"]?.asString() == "destroy" }
        assertThat(destroy["if"].asString()).isEqualTo("always() && inputs.destroy == 'true'")
        val run = destroy.run()
        assertThat(run).contains("args=(provision destroy --file \"\$FILE\" --yes --output json)")
        assertThat(run).contains("[ -n \"\${CONFIRM:-}\" ] && args+=(--confirm \"\$CONFIRM\")")
        assertThat(run).contains("echo \"destroy-result=\$result\" >> \"\$GITHUB_OUTPUT\"")
        assertThat(run).contains("> \"\$result\"")
        // The teardown never deletes by hand and never reads a receipt: the engine decides from the platform's `owner`.
        assertThat(run).doesNotContain("receipt").doesNotContain("env delete").doesNotContain("clients delete")
        assertThat(actionText).doesNotContain("adopted resources")
    }

    @Test
    fun `provision-e2e asserts that destroy removed exactly the loopback client and retained cli and the sandbox`() {
        val job = e2e["jobs"]["provision"]
        val provision = job.steps().single { it["uses"]?.asString() == "./.github/actions/provision" }
        val assertion = job.steps().single { it["name"]?.asString()?.startsWith("Assert destroy removed exactly the per-run loopback client") == true }
        assertThat(assertion["if"].asString()).isEqualTo("inputs.destroy == 'true'")
        assertThat(assertion["env"]["DESTROY_RESULT"].asString()).isEqualTo("\${{ steps.provision.outputs.destroy-result }}")
        assertThat(assertion["env"]["EXPECTED_SANDBOX"].asString()).isEqualTo("\${{ steps.provision.outputs.environment }}")
        // It runs AFTER the Action (whose last step is the destroy) and before the identifiers are shown.
        assertThat(job.steps().indexOf(assertion)).isGreaterThan(job.steps().indexOf(provision))
        val run = assertion.run()
        // Exactly one removal, the loopback client, inside the sandbox …
        assertThat(run).contains("if [ \"\$removed_keys\" != \"application/loopback-rp\" ]; then")
        assertThat(run).contains("if [ \"\$loopback_env\" != \"\$EXPECTED_SANDBOX\" ]; then")
        // … and the two retained rows, each for the engine's own reason (ProvisionEngine.RETAINED), never merely "not owned".
        assertThat(run).contains("for key in application/cli environment/ci; do")
        assertThat(run).contains("startswith(\"retained by the file\")")
        assertThat(run).contains("jq -r '.retain // false'")
        assertThat(com.devnow.thoryn.provision.ProvisionEngine.RETAINED).startsWith("retained by the file")
        // Both outcomes of `destroy --output json` are read: {removed, skipped} and the nothing-to-remove plan {changes}.
        assertThat(run).contains(".removed // [.changes[]? | select(.action==\"remove\")]")
        assertThat(run).contains(".skipped // [.changes[]? | select(.action==\"skip\")]")
        // Nothing in the workflow reads a receipt any more.
        assertThat(e2eText).doesNotContain("outputs.receipt").doesNotContain("RECEIPT:")
        assertThat(e2eText).contains("outputs.apply-result").contains("outputs.destroy-result")
    }
}
