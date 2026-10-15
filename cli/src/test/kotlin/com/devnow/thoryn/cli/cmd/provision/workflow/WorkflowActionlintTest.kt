package com.devnow.thoryn.cli.cmd.provision.workflow

import com.devnow.thoryn.cli.cmd.provision.CiIdentityFixture
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * SSO-3719 — `actionlint` over the stub and the reusable workflow, where the tool is installed (a developer machine with
 * `brew install actionlint`; CI's ubuntu-latest has none — the test is then SKIPPED and reported so, never green by
 * omission). It pins the two files the App and the stub rely on to a clean lint: `job.workflow_ref` is read through
 * `toJSON(job)` precisely so this stays clean on actionlint 1.7.x.
 */
class WorkflowActionlintTest {

    @Test
    fun `the stub and the reusable workflow are actionlint-clean`() {
        val actionlint = System.getenv("PATH").split(File.pathSeparator).map { File(it, "actionlint") }.firstOrNull { it.canExecute() }
        assumeTrue(actionlint != null, "actionlint is not on PATH — skipped (install it to run this check locally)")
        val root = CiIdentityFixture.repositoryRoot()
        val files = listOf(CiIdentityFixture.PROVISIONING_WORKFLOW_PATH, CiIdentityFixture.REUSABLE_WORKFLOW_PATH).map { File(root, it).path }
        val process = ProcessBuilder(listOf(actionlint!!.path) + files).directory(root).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        assertThat(process.waitFor(60, TimeUnit.SECONDS)).isTrue()
        assertThat(process.exitValue()).withFailMessage("actionlint reported:\n%s", output).isEqualTo(0)
    }
}
