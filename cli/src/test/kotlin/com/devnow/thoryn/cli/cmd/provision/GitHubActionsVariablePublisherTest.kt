package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.PublishTarget
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SSO-3668 — the CLI's [ProvisionEngine.OutputSink]: `gh variable set … --env` through the customer's own `gh`,
 * the environment created when absent and NEVER written when present, every failure answered as a reason (the
 * engine's `publish_target_unreachable`), never thrown.
 */
class GitHubActionsVariablePublisherTest {

    private val target = PublishTarget(ProvisionFile.PUBLISH_KIND_GITHUB_ACTIONS_VARIABLE, "acme/billing-web", "production", "THORYN_PRODUCTION_CLIENT_ID")

    @Test
    fun `an absent environment is created bare, then the variable is upserted on it`() {
        val gh = FakeGhVariables()
        val reason = GitHubActionsVariablePublisher(gh).publish(target, "client-123")
        assertThat(reason).isNull()
        assertThat(gh.invocations).containsExactly(
            "gh --version",
            "gh auth status",
            "gh api repos/acme/billing-web",
            "gh api repos/acme/billing-web/environments/production",
            "gh api --method PUT repos/acme/billing-web/environments/production",
            "gh variable set THORYN_PRODUCTION_CLIENT_ID --body client-123 --repo acme/billing-web --env production",
        )
        assertThat(gh.variables).containsExactly(java.util.Map.entry("acme/billing-web@production:THORYN_PRODUCTION_CLIENT_ID", "client-123"))
    }

    @Test
    fun `an existing environment is never written — only the variable is set`() {
        val gh = FakeGhVariables().apply { environments += "acme/billing-web/production" }
        val publisher = GitHubActionsVariablePublisher(gh)
        assertThat(publisher.publish(target, "client-123")).isNull()
        assertThat(gh.invocations).noneMatch { it.contains("--method PUT") }
        assertThat(gh.invocations.last()).isEqualTo("gh variable set THORYN_PRODUCTION_CLIENT_ID --body client-123 --repo acme/billing-web --env production")
        // A second publish through the same publisher checks gh once and upserts again.
        assertThat(publisher.publish(target, "client-456")).isNull()
        assertThat(gh.invocations.count { it == "gh auth status" }).isEqualTo(1)
        assertThat(gh.variables["acme/billing-web@production:THORYN_PRODUCTION_CLIENT_ID"]).isEqualTo("client-456")
    }

    @Test
    fun `a repository the gh account cannot see is a reason, not an exception, and nothing is written`() {
        val gh = FakeGhVariables()
        val reason = GitHubActionsVariablePublisher(gh).publish(target.copy(repository = "acme/elsewhere"), "client-123")
        assertThat(reason).contains("acme/elsewhere").contains("not found")
        assertThat(gh.invocations).noneMatch { it.startsWith("gh variable set") || it.contains("--method PUT") }
    }

    @Test
    fun `gh not signed in is a reason naming gh auth login, before any GitHub call`() {
        val gh = FakeGhVariables().apply { signedIn = false }
        val reason = GitHubActionsVariablePublisher(gh).publish(target, "client-123")
        assertThat(reason).contains("gh auth login")
        assertThat(gh.invocations).containsExactly("gh --version", "gh auth status")
    }

    @Test
    fun `a failing variable set is the reason gh gave, redacted`() {
        val gh = FakeGhVariables().apply {
            environments += "acme/billing-web/production"
            failVariablesWith = "gh: Resource not accessible by integration ghp_abcdefghijklmnopqrstuvwxyz0123456789 (HTTP 403)"
        }
        val reason = GitHubActionsVariablePublisher(gh).publish(target, "client-123")
        assertThat(reason).contains("Resource not accessible").contains("[redacted]").doesNotContain("ghp_abcdefgh")
    }

    @Test
    fun `an unknown target kind is refused by the publisher itself`() {
        val gh = FakeGhVariables()
        assertThat(GitHubActionsVariablePublisher(gh).publish(target.copy(kind = "forgejoVariable"), "x")).contains("forgejoVariable")
        assertThat(gh.calls).isEmpty()
    }
}
