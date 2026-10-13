package com.devnow.thoryn.provision

import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.junit.AnalyzeClasses
import com.tngtech.archunit.junit.ArchTest
import com.tngtech.archunit.lang.ArchRule
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses

/**
 * SSO-3662 — the library boundary of `io.thoryn:thoryn-provision-engine`, pinned at the bytecode level
 * (ADR 2026-10-13-provision-engine-shared-library). The engine is the module the thoryn CLI is built on
 * and the one any other in-process host converges a provisioning file with — a host that has no terminal
 * and no picocli; anything below would compile fine against the CLI and only fail inside such a host, at
 * runtime.
 *
 * Three rules, each the structural form of a sentence in the Story:
 *
 *  1. **No picocli** — the engine has no command-line surface; `ProvisionCommand` (CLI) is its front end.
 *  2. **No TTY** — nothing in the engine reads or probes a console: not `java.io.Console`, not
 *     `System.console()`, not Kotlin's `readLine` / `readln` (`kotlin.io.ConsoleKt`). A minted secret
 *     leaves ONLY through the [ProvisionEngine.SecretSink] the consumer supplies.
 *  3. **No CLI type** — nothing under `com.devnow.thoryn.cli..` is reachable from the engine; the engine
 *     reaches product-api only through the [ProvisionApi] port.
 *
 * `System.out` / `System.err` are deliberately NOT banned: the engine takes its report streams as
 * constructor parameters and only defaults them, which a non-CLI host overrides. Tests are excluded
 * from the import (a test may of course stub a console).
 *
 * Each rule was watched FAILING against a deliberate violation before it was trusted (SSO-3662 spike,
 * 2026-10-13): a `System.console()` call, a `picocli.CommandLine` reference with picocli on the
 * classpath, and a reference to an object in a `com.devnow.thoryn.cli` package. One blind spot, learnt
 * from a control that did NOT fire: a Kotlin `const val` is inlined at the use site, so a constant read
 * from another module leaves no bytecode dependency for ArchUnit (or any bytecode tool) to see. Rule 3
 * therefore catches types and calls, not inlined constants; the Maven module graph (the engine declares
 * no dependency on the CLI, so such a reference cannot compile) is the primary wall and this rule is
 * the alarm for a future pom change.
 */
@AnalyzeClasses(
    packages = ["com.devnow.thoryn.provision"],
    importOptions = [ImportOption.DoNotIncludeTests::class],
)
class ProvisionEngineLibraryBoundaryArchTest {

    @ArchTest
    val `the engine has no picocli surface`: ArchRule =
        noClasses()
            .should().dependOnClassesThat().resideInAPackage("picocli..")
            .because("the engine is a library the CLI is built on; picocli belongs to the CLI front end only (SSO-3662)")

    @ArchTest
    val `the engine never touches a console`: ArchRule =
        noClasses()
            .should().dependOnClassesThat().haveFullyQualifiedName("java.io.Console")
            .orShould().callMethod(System::class.java, "console")
            .orShould().dependOnClassesThat().haveFullyQualifiedName("kotlin.io.ConsoleKt")
            .because("a minted secret leaves the engine only through the consumer's SecretSink; a non-CLI host has no TTY (SSO-3662)")

    @ArchTest
    val `the engine depends on no CLI type`: ArchRule =
        noClasses()
            .should().dependOnClassesThat().resideInAPackage("com.devnow.thoryn.cli..")
            .because("the engine reaches product-api only through the ProvisionApi port; CLI types (session, token store, output formatting) stay in the CLI (SSO-3662)")
}
