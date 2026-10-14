package com.devnow.thoryn.cli

import com.devnow.thoryn.cli.auth.TokenStoreFactory
import com.github.javakeyring.BackendNotSupportedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import picocli.CommandLine
import picocli.CommandLine.Model.CommandSpec
import picocli.codegen.aot.graalvm.ReflectionConfigGenerator

/**
 * SSO-3687 — the native image's picocli reflection config must be complete when the BUILD HOST has no
 * OS keychain.
 *
 * The `native` profile runs picocli's [ReflectionConfigGenerator] over the command tree at build time
 * (cli/pom.xml, `generate-picocli-reflect-config`). The generator instantiates every command. A Linux
 * build host — a GitHub `ubuntu-24.04` runner, the container that builds the image — has no Secret
 * Service, so a command that opened the token store in its CONSTRUCTOR threw
 * `TokenStoreUnavailableException`, the generator aborted, and NO reflect-config.json was written. The
 * build still succeeded (exec:java does not fail on the generator's exit), and the shipped Linux binary
 * answered every subcommand with "Cannot instantiate …: the class has no constructor" — `--version`
 * worked, `login` / `clients` / `whoami` did not. Seen in cli-v0.32.0's linux-amd64 native leg and
 * reproduced by running a locally built binary in the container image.
 *
 * This runs the same generator over the same tree with the keychain made unavailable and no file-store
 * opt-in, exactly the build host's situation, and requires every command class in the tree to be in its
 * output.
 */
class NativeReflectionConfigWithoutKeychainTest {

    private val originalEnv = TokenStoreFactory.environment
    private val originalProvider = TokenStoreFactory.keychainProvider

    @BeforeEach
    fun simulateAKeychainlessLinuxBuildHost() {
        TokenStoreFactory.environment = { null }
        TokenStoreFactory.keychainProvider = { throw BackendNotSupportedException("No available keyring backend found") }
    }

    @AfterEach
    fun restoreSeams() {
        TokenStoreFactory.environment = originalEnv
        TokenStoreFactory.keychainProvider = originalProvider
    }

    @Test
    fun `the generated reflection config covers every command when the build host has no OS keychain`() {
        val root = CommandLine(ThorynMain()).commandSpec

        val config = ReflectionConfigGenerator.generateReflectionConfig(root)

        val commandClasses = commandTree(root).mapNotNull { it.userObject()?.javaClass?.name }.distinct()
        assertThat(commandClasses)
            .describedAs("the tree must include the commands the Thoryn init container runs")
            .contains(
                "com.devnow.thoryn.cli.cmd.LoginCommand",
                "com.devnow.thoryn.cli.cmd.LogoutCommand",
                "com.devnow.thoryn.cli.cmd.ClientsCommand\$RotateSecretSubcommand",
            )
        commandClasses.forEach { name ->
            assertThat(config).describedAs("reflect-config.json entry for $name").contains("\"name\" : \"$name\"")
        }
    }

    private fun commandTree(spec: CommandSpec): List<CommandSpec> =
        listOf(spec) + spec.subcommands().values.flatMap { commandTree(it.commandSpec) }
}
