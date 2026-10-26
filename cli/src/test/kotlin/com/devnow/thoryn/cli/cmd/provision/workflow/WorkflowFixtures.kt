package com.devnow.thoryn.cli.cmd.provision.workflow

/** SSO-3719 — the workflow documents the rule-engine tests mutate, one property at a time. */
internal object WorkflowFixtures {

    /** A stub exactly as `thoryn project init` / the README prescribe it. */
    val STUB = """
        name: Thoryn provisioning
        run-name: "Thoryn provisioning ${'$'}{{ inputs.mode }} ${'$'}{{ inputs.head_sha }} check-run:${'$'}{{ inputs.check_run_id }}"
        on:
          workflow_dispatch:
            inputs:
              mode:
                description: "plan or apply"
                required: true
                type: choice
                options: [plan, apply]
              head_sha:
                required: true
                type: string
              check_run_id:
                required: true
                type: string
              pr_number:
                required: false
                type: string
                default: ""
        concurrency:
          group: thoryn-provisioning-${'$'}{{ inputs.mode }}
          cancel-in-progress: false
        permissions: {}
        jobs:
          # thoryn-provisioning: apply-job
          provisioning:
            uses: thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0
            permissions:
              id-token: write
              checks: write
              contents: read
            with:
              mode: ${'$'}{{ inputs.mode }}
              head_sha: ${'$'}{{ inputs.head_sha }}
              check_run_id: ${'$'}{{ inputs.check_run_id }}
              pr_number: ${'$'}{{ inputs.pr_number }}
              plan-environment: acme-production-plan
              apply-environment: acme-production
              issuer: https://auth.thoryn.io
    """.trimIndent() + "\n"

    /** SSO-3970 — a tenant provisioning file that loads (the config project's part): one role. */
    const val TENANT_FILE = "apiVersion: thoryn.io/tenant/v1\nresources:\n  - { kind: role, name: editor, spec: { permissions: [docs:write] } }\n"

    /** SSO-3970 — a workload-identity connection that loads, carrying every scope a tenant file of [TENANT_FILE]'s shape needs. */
    val CONNECTION = """
        {
          "apiVersion": "thoryn.io/connection/v1",
          "workspace": { "slug": "acme" },
          "auth": {
            "method": "workload_identity",
            "clientId": "wi_44fdc26790a3ae28113bd2b6",
            "audience": "https://acme.auth.thoryn.io",
            "scopes": ["tenant:roles.read", "tenant:roles.write", "tenant:access.read", "tenant:access.write"],
            "github": { "repository": "acme-config", "environment": "acme-production" }
          }
        }
    """.trimIndent() + "\n"

    /** The same stub with one line replaced — the mutation every rule test is built from. */
    fun stubWith(old: String, new: String): String {
        check(STUB.contains(old)) { "fixture has no '$old'" }
        return STUB.replace(old, new)
    }

    fun loadResource(path: String): String =
        WorkflowFixtures::class.java.getResourceAsStream(path)?.readBytes()?.toString(Charsets.UTF_8) ?: error("missing test resource $path")

    /** Today's hand-written full workflow (the file the stub replaced), kept as the CUSTOM-shape fixture. */
    val FULL_CUSTOM: String get() = loadResource("/workflow/full-custom-workflow.yml")
}
