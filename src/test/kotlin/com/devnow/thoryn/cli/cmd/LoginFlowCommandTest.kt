package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3065 — unit coverage for the pure `thoryn login-flow` helpers: `--stage id:TYPE:REQUIREMENT`
 * parsing (the shape the passkey example activates) and the output record fields.
 */
class LoginFlowCommandTest {

    private val mapper = JsonMapper.builder().build()

    @Test
    fun `parseStages builds ordered stage maps with an authenticator + uppercased requirement`() {
        val stages = LoginFlowCommand.parseStages(
            listOf("password:PASSWORD:REQUIRED", "passkey:passkey:required"),
        )
        assertThat(stages).isNotNull
        assertThat(stages!!).hasSize(2)
        assertThat(stages[0]).isEqualTo(
            mapOf("id" to "password", "authenticators" to listOf(mapOf("type" to "PASSWORD")), "requirement" to "REQUIRED"),
        )
        // Type + requirement are uppercased so lower-case input still yields the enum values.
        assertThat(stages[1]).isEqualTo(
            mapOf("id" to "passkey", "authenticators" to listOf(mapOf("type" to "PASSKEY")), "requirement" to "REQUIRED"),
        )
    }

    @Test
    fun `parseStages rejects a malformed entry and an unknown requirement`() {
        assertThat(LoginFlowCommand.parseStages(listOf("password:PASSWORD"))).isNull() // too few parts
        assertThat(LoginFlowCommand.parseStages(listOf("password:PASSWORD:MAYBE"))).isNull() // bad requirement
        assertThat(LoginFlowCommand.parseStages(listOf("::REQUIRED"))).isNull() // blank parts
    }

    @Test
    fun `loginFlowRecordFields summarises version, status and stages`() {
        val node = mapper.readTree(
            """
            {"version":3,"status":"ACTIVE","stages":[
              {"id":"password","authenticators":[{"type":"PASSWORD"}],"requirement":"REQUIRED"},
              {"id":"passkey","authenticators":[{"type":"PASSKEY"}],"requirement":"REQUIRED"}
            ]}
            """.trimIndent(),
        )
        val fields = LoginFlowCommand.loginFlowRecordFields(node).toMap()
        assertThat(fields["version"]).isEqualTo(3)
        assertThat(fields["status"]).isEqualTo("ACTIVE")
        assertThat(fields["stages"]).isEqualTo("password[PASSWORD]=REQUIRED, passkey[PASSKEY]=REQUIRED")
    }
}
