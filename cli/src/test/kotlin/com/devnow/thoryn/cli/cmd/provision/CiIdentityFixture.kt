package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.AccessCommand
import com.devnow.thoryn.provision.ProvisionFile
import java.io.File

/**
 * SSO-3690 (parent SSO-3659) — what the repo-level tests know about THIS repository's own CI identity, shared by
 * [CiProvisionFileConformanceTest] (`.thoryn/provision.yaml`) and
 * [com.devnow.thoryn.cli.cmd.connection.CiConnectionConfinementTest] (`.thoryn/connection.json`).
 *
 * The identity is a GitHub Actions WORKLOAD IDENTITY TRUST (`thoryn-cli-ci`) on the `thoryn` workspace's
 * production plane — created once by a founder, never declared in a committed file (the engine has no trust kind
 * yet, SSO-3689), so the committed statement of what it holds is `connection.json` and the committed statement of
 * where it may reach is the one `grants:` block of `provision.yaml`. These constants are the pins a founder's
 * `thoryn workload-identity trusts create` must carry (see `.thoryn/README.md`); the tests hold the two files and
 * the e2e workflow to them.
 */
internal object CiIdentityFixture {
    const val PROVISION_PATH = ".thoryn/provision.yaml"
    const val CONNECTION_PATH = ".thoryn/connection.json"
    const val E2E_WORKFLOW_PATH = ".github/workflows/provision-e2e.yml"

    /** The trust's client id prefix (oauthy SSO-3307 — a workload client is `wi_…`, `client_credentials` only). */
    const val WORKLOAD_CLIENT_ID_PREFIX = "wi_"

    /** GitHub's immutable ids of thoryn-io/thoryn-cli (`gh api repos/thoryn-io/thoryn-cli`), the D2 pins of the trust. */
    const val GITHUB_OWNER = "thoryn-io"
    const val GITHUB_REPOSITORY = "thoryn-cli"
    const val GITHUB_OWNER_ID = 229451779L
    const val GITHUB_REPOSITORY_ID = 1361536515L

    /** A production-plane trust must pin a GitHub environment (D8); the e2e job declares this one. */
    const val GITHUB_ENVIRONMENT = "thoryn-provision-e2e"

    /** Only a dispatch on `main` may sign in — a pull request never can (the trust's `ref` pin). */
    const val GITHUB_REF = "refs/heads/main"

    /** The production-plane trust's audience: the `thoryn` workspace's issuer on shared staging (no `/{env}` path). */
    const val AUDIENCE = "https://thoryn.auth.stg.thoryn.org"

    /** The product-api scope AREA a resource kind is managed through (`tenant:<area>.<read|write>`). */
    fun area(kind: String): String = when (kind) {
        ProvisionFile.KIND_ENVIRONMENT -> "environments"
        ProvisionFile.KIND_APPLICATION -> "applications"
        ProvisionFile.KIND_USER -> "users"
        ProvisionFile.KIND_FEDERATION_MEMBER -> "federation"
        ProvisionFile.KIND_EMAIL_PROVIDER -> "email"
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
