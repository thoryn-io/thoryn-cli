package com.devnow.thoryn.cli.cmd.provision.workflow

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3719 — `.thoryn/workflow.yaml`: the configuration surface IS the power the product owner asked for, so its grammar is
 * the contract: every legitimate knob parses to the effective configuration, every unknown key or ill-formed value is refused
 * with the key named, removals default off, and the bundled schema still encodes what the loader enforces.
 */
class WorkflowConfigTest {

    @Test
    fun `defaults — no file — plan and apply one file with the connection beside it, fix request on, no removals`() {
        val c = WorkflowConfig.defaults()
        assertThat(c.files).containsExactly(WorkflowConfig.FileEntry(".thoryn/provision.yaml", ".thoryn/connection.json"))
        assertThat(c.env).isEmpty()
        assertThat(c.fixRequest).isTrue()
        assertThat(c.prune).isFalse()
        assertThat(c.destroy).isFalse()
        assertThat(c.confirm).isNull()
        assertThat(c.provider).isEqualTo("github_actions")
        assertThat(c.source).isNull()
    }

    @Test
    fun `many files — a production file and sandbox files — each with its own connection, defaulting to the connection beside it`() {
        val c = WorkflowConfig.parse(
            """
            apiVersion: thoryn.io/workflow/v1
            files:
              - file: .thoryn/environments/production/provision.yaml
              - file: .thoryn/environments/sandbox/provision.yaml
                connection: .thoryn/environments/sandbox/connection.json
              - file: provision.yaml
            env:
              THORYN_ENVIRONMENT: sandbox
              THORYN_TENANT_HOST_LABEL: auth
            fixRequest: false
            apply:
              prune: true
              confirm: acme
              destroy: true
            """.trimIndent(), ".thoryn/workflow.yaml",
        )
        assertThat(c.files).containsExactly(
            WorkflowConfig.FileEntry(".thoryn/environments/production/provision.yaml", ".thoryn/environments/production/connection.json"),
            WorkflowConfig.FileEntry(".thoryn/environments/sandbox/provision.yaml", ".thoryn/environments/sandbox/connection.json"),
            WorkflowConfig.FileEntry("provision.yaml", "connection.json"),
        )
        assertThat(c.env).containsExactly(java.util.Map.entry("THORYN_ENVIRONMENT", "sandbox"), java.util.Map.entry("THORYN_TENANT_HOST_LABEL", "auth"))
        assertThat(c.fixRequest).isFalse()
        assertThat(c.prune).isTrue()
        assertThat(c.destroy).isTrue()
        assertThat(c.confirm).isEqualTo("acme")
        val structured = c.toStructured()
        assertThat(structured["apply"]).isEqualTo(linkedMapOf("prune" to true, "destroy" to true, "confirm" to "acme"))
        assertThat(structured["source"]).isEqualTo(".thoryn/workflow.yaml")
    }

    private fun errorsOf(yaml: String): String = try { WorkflowConfig.parse(yaml, "workflow.yaml"); "" } catch (ex: WorkflowConfigException) { ex.message!! }

    @Test
    fun `an unknown key is refused at every level, naming it — a knob that is not in the contract is a gap, not a script`() {
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nsteps:\n  - run: echo hi\n")).contains("unknown key 'steps'").contains("product gap")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: a.yaml\n    runner: x\n")).contains("files[0]: unknown key 'runner'")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\napply:\n  force: true\n")).contains("apply: unknown key 'force'")
    }

    @Test
    fun `each value's grammar is enforced`() {
        assertThat(errorsOf("files: []\n")).contains("apiVersion is required")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v2\n")).contains("apiVersion must be thoryn.io/workflow/v1")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfiles: []\n")).contains("files must be a non-empty list")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: /etc/passwd\n")).contains("files[0].file must be a relative path")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: ../other/provision.yaml\n")).contains("files[0].file must be a relative path")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfiles:\n  - file: a.yaml\n  - file: a.yaml\n")).contains("listed more than once")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nfixRequest: yes please\n")).contains("fixRequest must be true or false")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\napply:\n  prune: \"true\"\n")).contains("apply.prune must be true or false")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\napply:\n  confirm: Acme Corp\n")).contains("apply.confirm must be the workspace slug")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nprovider: forgejo\n")).contains("provider must be one of github_actions").contains("Forgejo").contains("product gap")
    }

    @Test
    fun `env is an allow-list of THORYN_ names — never a shell, never a workflow-owned variable, never a credential`() {
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  PATH: /tmp\n")).contains("env.PATH: only THORYN_* names")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_ISSUER: https://evil.example\n")).contains("env.THORYN_ISSUER is set by the reusable workflow itself").contains("with:")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_FIX_REQUEST: /tmp/x\n")).contains("env.THORYN_FIX_REQUEST is set by the reusable workflow")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_CLIENT_SECRET: hunter2\n")).contains("env.THORYN_CLIENT_SECRET looks like a credential")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_API_KEY: k\n")).contains("looks like a credential")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_ENVIRONMENT: |\n    a\n    b\n")).contains("single line")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_ENVIRONMENT: [a]\n")).contains("must be a scalar")
        // The legitimate case: a placeholder a provisioning file reads (SSO-3430), and a documented CLI knob.
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_ENVIRONMENT: sandbox\n  THORYN_NO_BROWSER: 1\n")).isEmpty()
    }

    @Test
    fun `the bundled schema encodes the constraints the loader enforces (drift guard)`() {
        val schema = JsonMapper.builder().build().readTree(javaClass.getResourceAsStream(WorkflowConfig.SCHEMA_RESOURCE)!!.readBytes())
        assertThat(schema["properties"]["apiVersion"]["const"].asString()).isEqualTo(WorkflowConfig.API_VERSION)
        assertThat(schema["additionalProperties"].asBoolean()).isFalse()
        assertThat(schema["properties"].propertyNames().toSet()).isEqualTo(setOf("apiVersion", "provider", "files", "env", "fixRequest", "consentUrl", "apply"))
        assertThat(schema["properties"]["consentUrl"]["default"].asString()).isEmpty()
        assertThat(schema["properties"]["provider"]["enum"].toList().map { it.asString() }).isEqualTo(WorkflowConfig.PROVIDERS)
        assertThat(schema["properties"]["files"]["minItems"].asInt()).isEqualTo(1)
        assertThat(schema["properties"]["files"]["items"]["additionalProperties"].asBoolean()).isFalse()
        assertThat(schema["properties"]["files"]["items"]["properties"].propertyNames().toSet()).isEqualTo(setOf("file", "connection"))
        assertThat(schema["properties"]["env"]["propertyNames"]["pattern"].asString()).isEqualTo(WorkflowConfig.ENV_NAME_GRAMMAR.pattern)
        assertThat(schema["properties"]["env"]["additionalProperties"]["maxLength"].asInt()).isEqualTo(WorkflowConfig.MAX_ENV_VALUE_LENGTH)
        assertThat(schema["properties"]["fixRequest"]["default"].asBoolean()).isTrue()
        val apply = schema["properties"]["apply"]
        assertThat(apply["additionalProperties"].asBoolean()).isFalse()
        assertThat(apply["properties"].propertyNames().toSet()).isEqualTo(setOf("prune", "destroy", "confirm"))
        assertThat(apply["properties"]["prune"]["default"].asBoolean()).isFalse()
        assertThat(apply["properties"]["destroy"]["default"].asBoolean()).isFalse()
    }

    // ── SSO-3723 — consentUrl: the browser option's base URL is configuration ──

    @Test
    fun `consentUrl parses as the consent base URL, trailing slash dropped, and rides on the config object the workflow reads`() {
        val c = WorkflowConfig.parse("apiVersion: thoryn.io/workflow/v1\nconsentUrl: https://app.thoryn.io/\n", ".thoryn/workflow.yaml")
        assertThat(c.consentUrl).isEqualTo("https://app.thoryn.io")
        assertThat(c.toStructured()["consentUrl"]).isEqualTo("https://app.thoryn.io")
        assertThat(WorkflowConfig.defaults().consentUrl).isNull()
        assertThat(WorkflowConfig.defaults().toStructured()["consentUrl"]).isEqualTo("")
        assertThat(WorkflowConfig.parse("apiVersion: thoryn.io/workflow/v1\nconsentUrl: \"\"\n").consentUrl).isNull()
    }

    @Test
    fun `consentUrl must be an https base URL without query or fragment, and THORYN_CONSENT_URL cannot be set through env`() {
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nconsentUrl: http://app.thoryn.io\n")).contains("consentUrl must be an https:// base URL")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nconsentUrl: https://app.thoryn.io/consent?x=1\n")).contains("consentUrl must be")
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nconsentUrl: https://app.thoryn.io/github/consent\n")).isEmpty()
        assertThat(errorsOf("apiVersion: thoryn.io/workflow/v1\nenv:\n  THORYN_CONSENT_URL: https://x.example\n")).contains("THORYN_CONSENT_URL is set by the reusable workflow itself")
    }
}
