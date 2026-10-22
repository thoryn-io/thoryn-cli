package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.AccessCommand
import com.devnow.thoryn.provision.ProvisionFile
import java.io.File

/**
 * SSO-3690 / SSO-3697 / SSO-3705 (parent SSO-3659) — what the repo-level tests know about THIS repository's own CI
 * identity, shared by [CiProvisionFileConformanceTest] (`.thoryn/provision.yaml`), [CiTrustsFileConformanceTest]
 * (`.thoryn/trusts.provision.yaml`), [CiProvisioningWorkflowConformanceTest] (the App-dispatched workflow) and
 * [com.devnow.thoryn.cli.cmd.connection.CiConnectionConfinementTest] (`.thoryn/connection.json`).
 *
 * ONE GitHub Actions workload identity trust on the `thoryn` workspace's production plane, [TRUST_NAME]
 * `thoryn-cli-ci`: pinned to the REVIEWED environment [GITHUB_ENVIRONMENT], the six write-capable scopes
 * `connection.json` requests; the platform `owner` of `application:cli` (SSO-3697). The SAME identity plans every
 * pull request (SSO-3705 — SSO-3699 option B): the App's plan job runs in the UNPROTECTED environment
 * [PLAN_GITHUB_ENVIRONMENT] and the trust's plan profile (SSO-3700; declared as `spec.plan` in [TRUSTS_PROVISION_PATH]
 * by SSO-3704, scopes derived) mints it the `.read` scopes only there ([scopesToPlan]). There is no second trust and no
 * second `wi_` client — SSO-3697's second trust was never created, and its placeholder grant stopped provision-e2e run
 * 38547022158; [TWO_TRUST_RESIDUE] is what none of the committed files may mention again.
 *
 * The trust is DECLARED (SSO-3689 `kind: workloadIdentityTrust`) in [TRUSTS_PROVISION_PATH], a file a founder
 * applies — never CI: a production-plane trust is reached through the workspace, and a file cannot declare the
 * trust its own identity signs in with. These constants are the pins that file carries; the tests hold every
 * committed file and both workflows to them.
 */
internal object CiIdentityFixture {
    const val PROVISION_PATH = ".thoryn/provision.yaml"
    const val CONNECTION_PATH = ".thoryn/connection.json"
    const val E2E_WORKFLOW_PATH = ".github/workflows/provision-e2e.yml"

    /** SSO-3697 — the founder-applied trusts file and the App-dispatched workflow (since SSO-3719 a STUB calling [REUSABLE_WORKFLOW_PATH]). */
    const val TRUSTS_PROVISION_PATH = ".thoryn/trusts.provision.yaml"
    const val PROVISIONING_WORKFLOW_PATH = ".github/workflows/thoryn-provisioning.yml"
    const val PROVISION_ACTION_PATH = ".github/actions/provision/action.yml"

    /** SSO-3719 — the reusable workflow every stub calls (`on: workflow_call`), and the stub's committed run-time configuration. */
    const val REUSABLE_WORKFLOW_PATH = ".github/workflows/provisioning.yml"
    const val WORKFLOW_CONFIG_PATH = ".thoryn/workflow.yaml"

    /** SSO-3717 — the repository's `.gitignore`: every `<name>.receipt.json` under `.thoryn/` is ignored again (no committed receipt). */
    const val GITIGNORE_PATH = ".gitignore"
    const val RECEIPT_IGNORE_RULE = ".thoryn/*.receipt.json"

    /**
     * SSO-3704 — the two-trust shape's residue (SSO-3699 option B retired it): a second connection file, the second trust's
     * name, and the sign-in failure a plan job hit while the trust pinned only the reviewed environment. Once the one trust
     * carries its plan profile none of these is a current fact, and a committed file that still states one would send an
     * operator down the retired path — so no file under `.thoryn/` (prose included) and no workflow may mention them.
     */
    val TWO_TRUST_RESIDUE = listOf("connection.plan.json", "thoryn-cli-ci-plan", "environment_mismatch")

    /**
     * SSO-3705 — the committed DATA files under `.thoryn/` (prose — the README, YAML comment lines — is not scanned):
     * none may carry a paste-me placeholder, because there is nothing left to paste. A placeholder is a `wi_` followed
     * by anything but a hex digit (`wi_PASTE_…`, `wi_…`, `<wi_…>`), or a shouting marker word.
     */
    val THORYN_DATA_FILES = listOf(PROVISION_PATH, CONNECTION_PATH, TRUSTS_PROVISION_PATH, WORKFLOW_CONFIG_PATH)
    val PLACEHOLDER_PATTERN = Regex("wi_[^0-9a-f\\s\"'`]|PASTE|PLACEHOLDER|CHANGE_ME")

    /** The non-comment lines of a YAML/JSON data file (a line whose first non-blank character is `#` is prose). */
    fun dataLines(file: File): List<String> = file.readLines().filterNot { it.trimStart().startsWith("#") }

    /** The trust's client id prefix (oauthy SSO-3307 — a workload client is `wi_…`, `client_credentials` only). */
    const val WORKLOAD_CLIENT_ID_PREFIX = "wi_"

    /** GitHub's immutable ids of thoryn-io/thoryn-cli (`gh api repos/thoryn-io/thoryn-cli`), the D2 pins of the trust. */
    const val GITHUB_OWNER = "thoryn-io"
    const val GITHUB_REPOSITORY = "thoryn-cli"
    const val GITHUB_OWNER_ID = 229451779L
    const val GITHUB_REPOSITORY_ID = 1361536515L

    /** The trust's name on the API (its converge key in [TRUSTS_PROVISION_PATH]). */
    const val TRUST_NAME = "thoryn-cli-ci"

    /** A production-plane trust must pin a GitHub environment (D8); the e2e job and the App's apply job declare this REVIEWED one. */
    const val GITHUB_ENVIRONMENT = "thoryn-provision-e2e"

    /** SSO-3697 / SSO-3705 — the UNPROTECTED environment the App's plan job declares (`<reviewed>-plan`, Amendment 5); the plan profile's key. */
    const val PLAN_GITHUB_ENVIRONMENT = "thoryn-provision-e2e-plan"

    /** Only a dispatch on `main` may sign in — a pull request never can (the trust's `ref` pin). */
    const val GITHUB_REF = "refs/heads/main"

    /** The production-plane trust's audience: the `thoryn` workspace's issuer on shared staging (no `/{env}` path). */
    const val AUDIENCE = "https://thoryn.auth.stg.thoryn.org"

    /**
     * The thoryn-cli release the App-dispatched STUB pins the reusable workflow to (`uses: …/provisioning.yml@<release>`);
     * the reusable workflow then runs the `thoryn.jar` of that same release (`job.workflow_ref`). At least cli-v0.36.0: the
     * first release that ships the reusable workflow and `thoryn provision workflow check` (SSO-3719), on top of
     * cli-v0.35.0's fix request (SSO-3710) and cli-v0.34.0's plan-profile sign-in (SSO-3702). The tag is cut FROM the merge
     * that lands the reusable workflow, so the first App dispatch after that merge needs the tag to exist.
     */
    const val CLI_RELEASE = "cli-v0.43.0"

    /** The platform base issuer the workflow provisions against (the connection derives the workspace issuer from it). */
    const val PLATFORM_ISSUER = "https://auth.stg.thoryn.org"

    /** The product-api scope AREA a resource kind is managed through (`tenant:<area>.<read|write>`). */
    fun area(kind: String): String = when (kind) {
        ProvisionFile.KIND_ENVIRONMENT -> "environments"
        ProvisionFile.KIND_APPLICATION -> "applications"
        ProvisionFile.KIND_USER -> "users"
        ProvisionFile.KIND_FEDERATION_MEMBER -> "federation"
        ProvisionFile.KIND_EMAIL_PROVIDER -> "email"
        ProvisionFile.KIND_WORKLOAD_IDENTITY_TRUST -> "workload-identity"
        else -> "idp"
    }

    /**
     * The LEAST-PRIVILEGE scope set an identity needs to converge [file]: read + write on every declared kind's area
     * (the plan reads before the apply writes), plus `tenant:access.read` ALWAYS — SSO-3659: ownership is decided by
     * the identity's own reach (`POST /api/v1/access/check`) before any write — and `tenant:access.write` when any
     * resource carries a `grants:` block (to converge them). The trust holds EXACTLY this set, no more (nothing else
     * is needed) and no less (the apply would fail).
     */
    fun scopesToConverge(file: ProvisionFile): Set<String> =
        file.resources.flatMap { listOf("tenant:${area(it.kind)}.read", "tenant:${area(it.kind)}.write") }.toSet() +
            AccessCommand.SCOPE_READ +
            if (file.resources.any { it.grants != null }) setOf(AccessCommand.SCOPE_WRITE) else emptySet()

    /**
     * SSO-3697 / SSO-3705 (Amendment 5's rule) — the scope set a plan of [file] needs, which the hub's plan profile
     * mints the one identity in the `-plan` environment: the `.read` of every declared kind's area plus
     * `tenant:access.read` (the ownership gate and the `grants:` diff read it). No `.write` at all — scopes are the
     * ceiling, so a plan can never write whatever the YAML says. A strict subset of [scopesToConverge].
     */
    fun scopesToPlan(file: ProvisionFile): Set<String> =
        file.resources.map { "tenant:${area(it.kind)}.read" }.toSet() + AccessCommand.SCOPE_READ

    /** Walk up from the forked test JVM's working directory to the repository root holding [relative]. */
    fun locate(relative: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("could not locate $relative from ${System.getProperty("user.dir")}")
    }

    /** The repository root (the directory holding `.thoryn/`). */
    fun repositoryRoot(): File = locate(PROVISION_PATH).parentFile.parentFile
}
