package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.CommandSupport
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.File

/**
 * SSO-4056 — `thoryn provision split` reads its source with the source's directory and gates each output from the
 * output's own directory, as `ProvisionFile.load` will read it, so an `emailTemplate`'s `spec.bodyFile` resolves. Before
 * the fix both parses had no directory and a mixed file naming a body file could not be split at all ("not read from a
 * file").
 *
 * Every assertion was watched failing against the reverted call sites (the control table in the PR).
 */
class ProvisionSplitBodyFileTest : CommandTestBase() {

    private val body = "<p>Hi {{displayName}}</p>\n<p><a href=\"{{resetUrl}}\">Reset</a></p>\n"

    /** A mixed file under `.thoryn/` with an emailTemplate naming `emails/password_reset.html` (written beside it) and an application. */
    private fun source(): File {
        val dir = File(tempHome.toFile(), ".thoryn").apply { mkdirs() }
        File(dir, "emails/password_reset.html").apply { parentFile.mkdirs() }.writeText(body)
        return File(dir, "provision.yaml").apply {
            writeText(
                "apiVersion: thoryn.io/provision/v1\nresources:\n" +
                    "  - { kind: emailTemplate, name: reset, spec: { type: password_reset, subject: \"Reset your password\", bodyFile: emails/password_reset.html } }\n" +
                    "  - { kind: application, name: web, spec: { displayName: Web, clientType: public, grantTypes: [authorization_code], redirectUris: [\"https://web.example/callback\"] } }\n",
            )
        }
    }

    @Test
    fun `a mixed file whose emailTemplate names a body file splits, and the tenant file loads with the body beside it`() {
        val source = source()
        val split = runCli("provision", "split", "--file", source.path)
        assertThat(split.exit).withFailMessage("%s", split.err).isEqualTo(0)

        val tenant = ProvisionFile.load(File(source.parentFile, "tenant.provision.yaml"))
        assertThat(tenant.part).isEqualTo(ProvisionPart.TENANT)
        assertThat(tenant.resources.single().spec).containsEntry("bodyFile", "emails/password_reset.html").containsEntry("body", body)
    }

    @Test
    fun `a tenant output written where the body file does not resolve is refused with the not-found reason, and nothing is written`() {
        val source = source()
        val elsewhere = File(tempHome.toFile(), "elsewhere/tenant.yaml")
        val split = runCli("provision", "split", "--file", source.path, "--tenant-file", elsewhere.path)
        assertThat(split.exit).isEqualTo(CommandSupport.EXIT_USAGE)
        assertThat(split.err).contains("spec.bodyFile 'emails/password_reset.html' not found (").doesNotContain("not read from a file")
        assertThat(elsewhere).doesNotExist()
        assertThat(File(source.parentFile, "application.provision.yaml")).doesNotExist()
    }
}
