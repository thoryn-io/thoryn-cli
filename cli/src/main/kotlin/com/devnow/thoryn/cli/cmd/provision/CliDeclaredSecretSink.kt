package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.FileSecrets
import com.devnow.thoryn.provision.ProvisionEngine
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.SecretTarget
import java.io.File
import java.util.Base64

/**
 * SSO-3659 (ADR 2026-10-13 converge §5; production-clients ADR §3 tier 3) — the CLI's
 * [ProvisionEngine.DeclaredSecretSink]: a minted client secret lands where it is CONSUMED. CLI side, not engine
 * side: it runs a process and writes a file.
 *
 * `kubernetesSecret` — through the operator's own `kubectl` ([KubectlRunner]), the `install-forge` pattern:
 *
 * | purpose | invocation | stdin |
 * |---|---|---|
 * | kubectl present? (once per apply) | `kubectl version --client` | — |
 * | the context reaches the cluster AND the namespace exists | `kubectl get namespace <ns> -o name` | — |
 * | render the Secret (nothing is sent to the cluster) | `kubectl -n <ns> create secret generic <name> --from-file=<key>=/dev/stdin --dry-run=client -o yaml` | **the secret value** |
 * | write it (create or replace the key's value) | `kubectl -n <ns> apply -f -` | the rendered manifest |
 *
 * The value is only ever on stdin — never on argv (the process list, shell history, an audit log of command
 * lines), never in an environment variable thoryn sets. **The namespace is never created**: it belongs to the
 * consumer's deployment; a missing one is a reason, not a `kubectl create namespace`.
 *
 * `file` — [FileSecrets.writeOwnerOnly] (`0600`); an EXISTING file is a reason unless `apply --force`.
 *
 * Every failure is answered as a REASON (the engine redacts the value from it, prints it, falls back to the
 * `--secret-file` / TTY channel and finally reports `undelivered_secrets`) — never thrown past the engine: an
 * unreachable sink must not cost the client its receipt entry. Nothing `kubectl` printed is shown except
 * through [KubectlResult.reason], and only after [redact].
 */
internal class CliDeclaredSecretSink(
    private val kubectl: KubectlRunner,
    /** `apply --force`: overwrite an existing `file` sink target. */
    private val overwriteFiles: Boolean = false,
) : ProvisionEngine.DeclaredSecretSink {

    /** `null` ⇒ kubectl is installed; else the reason it is not (checked once per sink). */
    private var unavailable: String? = null
    private var checked = false

    override fun deliver(target: SecretTarget, clientId: String, secret: String): String? = when (target.kind) {
        ProvisionFile.SECRET_SINK_KIND_KUBERNETES_SECRET -> kubernetesSecret(target, secret)
        ProvisionFile.SECRET_SINK_KIND_FILE -> file(target, secret)
        else -> "unsupported secretSink kind '${target.kind}'"
    }

    private fun kubernetesSecret(target: SecretTarget, secret: String): String? {
        val namespace = target.namespace ?: return "secretSink has no namespace"
        val name = target.name ?: return "secretSink has no name"
        val key = target.key ?: return "secretSink has no key"
        availability()?.let { return it }
        return try {
            // Reachability + existence in ONE read: a wrong context, an expired credential and a missing namespace
            // all answer here, before any value leaves this process. Never `create namespace`.
            val ns = kubectl.run(listOf("get", "namespace", namespace, "-o", "name"))
            if (!ns.ok) return "namespace '$namespace' is not reachable through the current kubectl context (${redact(ns.reason(), secret)}); thoryn never creates a namespace"
            val render = kubectl.run(
                listOf("-n", namespace, "create", "secret", "generic", name, "--from-file=$key=/dev/stdin", "--dry-run=client", "-o", "yaml"),
                stdin = secret.toByteArray(Charsets.UTF_8),
            )
            if (!render.ok) return "could not render Secret $namespace/$name (${redact(render.reason(), secret)})"
            val applied = kubectl.run(listOf("-n", namespace, "apply", "-f", "-"), stdin = render.stdout)
            if (!applied.ok) return "could not apply Secret $namespace/$name (${redact(applied.reason(), secret)})"
            null
        } catch (ex: KubectlNotInstalledException) {
            ex.message
        }
    }

    private fun file(target: SecretTarget, secret: String): String? {
        val path = target.path ?: return "secretSink has no path"
        val file = File(path)
        if (file.exists() && !overwriteFiles) return "file '${file.path}' already exists — re-run with --force to overwrite it"
        return try {
            FileSecrets.writeOwnerOnly(file, secret)
            null
        } catch (ex: Exception) {
            "could not write '${file.path}' (${redact(ex.message ?: ex.javaClass.simpleName, secret)})"
        }
    }

    private fun availability(): String? {
        if (!checked) {
            checked = true
            unavailable = try {
                if (kubectl.run(listOf("version", "--client")).ok) null else "kubectl is installed but `kubectl version --client` failed"
            } catch (ex: KubectlNotInstalledException) {
                ex.message
            }
        }
        return unavailable
    }

    companion object {
        /** Defence in depth: the value, and its base64 form (how a manifest carries it), never reach a message. */
        fun redact(text: String, secret: String): String =
            text.replace(secret, "[redacted]").replace(Base64.getEncoder().encodeToString(secret.toByteArray(Charsets.UTF_8)), "[redacted]")
    }
}
