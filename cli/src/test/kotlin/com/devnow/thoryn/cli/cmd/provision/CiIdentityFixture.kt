package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.AccessCommand
import com.devnow.thoryn.provision.ProvisionFile
import java.io.File

/**
 * SSO-3690 / SSO-3697 (parent SSO-3659) — what the repo-level tests know about THIS repository's own CI identities,
 * shared by [CiProvisionFileConformanceTest] (`.thoryn/provision.yaml`), [CiTrustsFileConformanceTest]
 * (`.thoryn/trusts.provision.yaml`), [CiProvisioningWorkflowConformanceTest] (the App-dispatched workflow),
 * [com.devnow.thoryn.cli.cmd.connection.CiConnectionConfinementTest] (`.thoryn/connection.json`) and
 * [com.devnow.thoryn.cli.cmd.connection.CiPlanConnectionConfinementTest] (`.thoryn/connection.plan.json`).
 *
 * TWO GitHub Actions workload identity trusts on the `thoryn` workspace's production plane (oauthy converge ADR
 * 2026-10-13, Amendment 5 — a dispatched run executes on `main` in both modes, so the GitHub ENVIRONMENT is the only
 * pin separating "may read" from "may write"):
 *
 *  - [TRUST_NAME] `thoryn-cli-ci` — the APPLY identity: pinned to the REVIEWED environment [GITHUB_ENVIRONMENT],
 *    the six write-capable scopes `connection.json` requests; the platform `owner` of `application:cli` (SSO-3697).
 *  - [PLAN_TRUST_NAME] `thoryn-cli-ci-plan` — the PLAN identity: pinned to the UNPROTECTED environment
 *    [PLAN_GITHUB_ENVIRONMENT], the `.read` scopes only ([scopesToPlan]) — it plans every pull request and can
 *    write nothing whatever the file says.
 *
 * Both are DECLARED (SSO-3689 `kind: workloadIdentityTrust`) in [TRUSTS_PROVISION_PATH], a file a founder applies —
 * never CI: a production-plane trust is reached through the workspace, and a file cannot declare the trust its own
 * identity signs in with. These constants are the pins that file carries; the tests hold every committed file and
 * both workflows to them.
 */
internal object CiIdentityFixture {
    const val PROVISION_PATH = ".thoryn/provision.yaml"
    const val CONNECTION_PATH = ".thoryn/connection.json"
    const val E2E_WORKFLOW_PATH = ".github/workflows/provision-e2e.yml"

    /** SSO-3697 — the read-only plan identity's contract, the founder-applied trusts file, the App-dispatched workflow. */
    const val PLAN_CONNECTION_PATH = ".thoryn/connection.plan.json"
    const val TRUSTS_PROVISION_PATH = ".thoryn/trusts.provision.yaml"
    const val PROVISIONING_WORKFLOW_PATH = ".github/workflows/thoryn-provisioning.yml"

    /** The trust's client id prefix (oauthy SSO-3307 — a workload client is `wi_…`, `client_credentials` only). */
    const val WORKLOAD_CLIENT_ID_PREFIX = "wi_"

    /** GitHub's immutable ids of thoryn-io/thoryn-cli (`gh api repos/thoryn-io/thoryn-cli`), the D2 pins of both trusts. */
    const val GITHUB_OWNER = "thoryn-io"
    const val GITHUB_REPOSITORY = "thoryn-cli"
    const val GITHUB_OWNER_ID = 229451779L
    const val GITHUB_REPOSITORY_ID = 1361536515L

    /** The apply trust's name on the API (its converge key in [TRUSTS_PROVISION_PATH]). */
    const val TRUST_NAME = "thoryn-cli-ci"

    /** A production-plane trust must pin a GitHub environment (D8); the e2e job and the App's apply job declare this REVIEWED one. */
    const val GITHUB_ENVIRONMENT = "thoryn-provision-e2e"

    /** SSO-3697 — the plan trust's name, and the UNPROTECTED environment the App's plan job declares (`<reviewed>-plan`, Amendment 5). */
    const val PLAN_TRUST_NAME = "thoryn-cli-ci-plan"
    const val PLAN_GITHUB_ENVIRONMENT = "thoryn-provision-e2e-plan"

    /** Only a dispatch on `main` may sign in — a pull request never can (both trusts' `ref` pin). */
    const val GITHUB_REF = "refs/heads/main"

    /** The production-plane trusts' audience: the `thoryn` workspace's issuer on shared staging (no `/{env}` path). */
    const val AUDIENCE = "https://thoryn.auth.stg.thoryn.org"

    /** The thoryn-cli release the App-dispatched workflow pins — its composite Action and `thoryn.jar`. */
    const val CLI_RELEASE = "cli-v0.33.0"

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
     * SSO-3697 (Amendment 5's rule) — the scope set the read-only PLAN identity needs to plan [file]: the `.read` of
     * every declared kind's area plus `tenant:access.read` (the ownership gate and the `grants:` diff read it). No
     * `.write` at all — scopes are the ceiling, so a plan can never write whatever the YAML says.
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
}
