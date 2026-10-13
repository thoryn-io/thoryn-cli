package com.devnow.thoryn.cli.cmd

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3075 — unit coverage for the pure `thoryn login-methods` output record fields (the shape the
 * magic-code example reads back after enabling magic_code).
 */
class LoginMethodsCommandTest {

    private val mapper = JsonMapper.builder().build()

    @Test
    fun `loginMethodsRecordFields summarises stored, effective and supported`() {
        val node = mapper.readTree(
            """
            {"stored":["password","magic_link","magic_code"],
             "effective":["password","magic_link","magic_code"],
             "supported":["password","magic_link","magic_code","passkey","totp","sms"],
             "updatedAt":"2026-09-14T08:00:00Z"}
            """.trimIndent(),
        )
        val fields = LoginMethodsCommand.loginMethodsRecordFields(node).toMap()
        assertThat(fields["stored"]).isEqualTo("password, magic_link, magic_code")
        assertThat(fields["effective"]).isEqualTo("password, magic_link, magic_code")
        assertThat(fields["supported"]).isEqualTo("password, magic_link, magic_code, passkey, totp, sms")
        assertThat(fields["updatedAt"]).isEqualTo("2026-09-14T08:00:00Z")
    }

    @Test
    fun `an unconfigured tenant renders stored as default`() {
        val node = mapper.readTree(
            """{"stored":null,"effective":["password","magic_link"],"supported":["password","magic_link","magic_code"]}""",
        )
        val fields = LoginMethodsCommand.loginMethodsRecordFields(node).toMap()
        assertThat(fields["stored"]).isEqualTo("(default)")
        assertThat(fields["effective"]).isEqualTo("password, magic_link")
        assertThat(fields["updatedAt"]).isNull()
    }
}
