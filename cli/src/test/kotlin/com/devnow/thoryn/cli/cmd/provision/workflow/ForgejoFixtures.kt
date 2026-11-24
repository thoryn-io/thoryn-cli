package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import java.io.File

/** SSO-4474 — the Forgejo documents the `forgejo.*` rule tests mutate, one property at a time. */
internal object ForgejoFixtures {

    /** Where the customer-facing example stub lives in this repository. */
    const val EXAMPLE_STUB_PATH = "examples/forgejo/thoryn-provisioning.yml"

    /** The example stub, exactly as the docs prescribe it. */
    val STUB: String get() = File(CiIdentityFixture.repositoryRoot(), EXAMPLE_STUB_PATH).readText()

    /** The action, as released. */
    val ACTION: String get() = File(CiIdentityFixture.repositoryRoot(), ProvisioningWorkflowContract.FORGEJO_ACTION_PATH).readText()

    const val CONFIG = "apiVersion: thoryn.io/workflow/v1\nprovider: forgejo\n"

    /** A production forgejo connection pinned to `refs/heads/main`, mirroring a derived plan profile. */
    fun connection(auth: String = "", plan: String = "\"plan\": {},", provider: String = "forgejo", ref: String = "refs/heads/main"): String = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "acme" },
          "auth": {
            "method": "workload_identity",
            "provider": "$provider",
            "clientId": "wi_5e4f3a2b1c0d9e8f7a6b5c4d",
            "audience": "https://acme.auth.thoryn.io",
            "scopes": ["tenant:roles.read", "tenant:roles.write", "tenant:access.read", "tenant:access.write"],
            $plan
            $auth
            ${if (provider == "forgejo") "\"forgejo\": { \"instanceUrl\": \"https://codeberg.org\", \"owner\": \"acme\", \"ownerId\": 7, \"repository\": \"infra\", \"repositoryId\": 42, \"ref\": \"$ref\" }" else "\"github\": { \"repository\": \"infra\", \"environment\": \"acme-production\" }"}
          }
        }
    """.trimIndent() + "\n"

    /** The stub with one fragment replaced. */
    fun stubWith(old: String, new: String): String {
        val stub = STUB
        check(stub.contains(old)) { "the example stub has no '$old'" }
        return stub.replace(old, new)
    }

    /** A repository under [dir] holding [stub] at the Forgejo path, the config, a tenant file and its connection. */
    fun repo(dir: File, stub: String = STUB, config: String = CONFIG, connection: String = connection()): File {
        fun write(path: String, text: String) = File(dir, path).also { it.parentFile.mkdirs(); it.writeText(text) }
        write(ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH, stub)
        write(WorkflowConfig.DEFAULT_PATH, config)
        write(WorkflowConfig.DEFAULT_FILE, WorkflowFixtures.TENANT_FILE)
        write(WorkflowConfig.DEFAULT_CONNECTION, connection)
        return dir
    }

    fun evaluate(dir: File, stub: String = STUB, config: String = CONFIG, connection: String = connection()): WorkflowCheck.Report {
        repo(dir, stub, config, connection)
        return WorkflowCheck.evaluate(stub, ProvisioningWorkflowContract.FORGEJO_WORKFLOW_PATH, root = dir)
    }
}
