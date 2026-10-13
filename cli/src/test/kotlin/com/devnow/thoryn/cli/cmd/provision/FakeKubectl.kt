package com.devnow.thoryn.cli.cmd.provision

import java.util.Base64

/**
 * SSO-3659 — a fake `kubectl` for the `kubernetesSecret` sink: exactly the invocations [CliDeclaredSecretSink]
 * makes (`version --client`, `get namespace`, the client-side `create secret … --dry-run=client -o yaml` render,
 * `apply -f -`), recorded WITH their stdin so a test asserts them — above all that no secret value is ever on
 * argv. An unexpected call fails loud. Never reaches a cluster.
 */
internal class FakeKubectl : KubectlRunner {

    /** Every invocation: its args and its stdin (null when none). */
    val calls = mutableListOf<Pair<List<String>, ByteArray?>>()
    var installed = true
    /** The namespaces that exist (and are reachable through the "context"). */
    val namespaces = mutableSetOf("forge")
    /** `namespace/name` → data key → DECODED value, as the cluster would hold it after `apply`. */
    val secrets = linkedMapOf<String, MutableMap<String, String>>()
    /** When set, `kubectl apply` fails with this stderr. */
    var failApplyWith: String? = null

    val invocations: List<String> get() = calls.map { "kubectl " + it.first.joinToString(" ") }
    /** Every argv token of every invocation — the assertion surface for "never on argv". */
    val allArgs: List<String> get() = calls.flatMap { it.first }

    override fun run(args: List<String>, stdin: ByteArray?): KubectlResult {
        if (!installed) throw KubectlNotInstalledException("kubectl is not installed or not on PATH")
        calls += args to stdin
        return when {
            args == listOf("version", "--client") -> ok("Client Version: v1.31.0 (fake)")
            args.take(2) == listOf("get", "namespace") -> {
                val ns = args[2]
                if (ns in namespaces) ok("namespace/$ns") else KubectlResult(1, ByteArray(0), "Error from server (NotFound): namespaces \"$ns\" not found")
            }
            args.size >= 2 && args[0] == "-n" && args.getOrNull(2) == "create" && args.getOrNull(3) == "secret" -> render(args, stdin)
            args.size == 5 && args[0] == "-n" && args[2] == "apply" && args[3] == "-f" && args[4] == "-" -> apply(args[1], stdin)
            args.firstOrNull() == "create" && args.getOrNull(1) == "namespace" -> KubectlResult(99, ByteArray(0), "FakeKubectl: thoryn must never create a namespace")
            else -> KubectlResult(99, ByteArray(0), "FakeKubectl: unexpected invocation ${args.joinToString(" ")}")
        }
    }

    /** `-n <ns> create secret generic <name> --from-file=<key>=/dev/stdin --dry-run=client -o yaml` with the value on stdin. */
    private fun render(args: List<String>, stdin: ByteArray?): KubectlResult {
        val expectedTail = listOf("--dry-run=client", "-o", "yaml")
        if (args.getOrNull(4) != "generic" || args.takeLast(3) != expectedTail) return KubectlResult(99, ByteArray(0), "FakeKubectl: not a client-side render: ${args.joinToString(" ")}")
        val fromFile = args[6].removePrefix("--from-file=")
        val key = fromFile.substringBefore('=')
        if (fromFile.substringAfter('=') != "/dev/stdin") return KubectlResult(99, ByteArray(0), "FakeKubectl: the value must come from /dev/stdin, got $fromFile")
        if (stdin == null || stdin.isEmpty()) return KubectlResult(1, ByteArray(0), "error: failed to read /dev/stdin: empty")
        val b64 = Base64.getEncoder().encodeToString(stdin)
        val manifest = "apiVersion: v1\ndata:\n  $key: $b64\nkind: Secret\nmetadata:\n  name: ${args[5]}\n  namespace: ${args[1]}\n"
        return ok(manifest)
    }

    private fun apply(namespace: String, stdin: ByteArray?): KubectlResult {
        failApplyWith?.let { return KubectlResult(1, ByteArray(0), it) }
        val manifest = stdin?.toString(Charsets.UTF_8) ?: return KubectlResult(1, ByteArray(0), "error: no objects passed to apply")
        val name = Regex("^  name: (\\S+)$", RegexOption.MULTILINE).find(manifest)!!.groupValues[1]
        // Only the `data:` block (the two-space-indented lines up to the next top-level key) holds values.
        val dataBlock = manifest.substringAfter("data:\n").substringBefore("\nkind:")
        val data = Regex("^  ([-._a-zA-Z0-9]+): (\\S+)$", RegexOption.MULTILINE).findAll(dataBlock)
            .associate { it.groupValues[1] to String(Base64.getDecoder().decode(it.groupValues[2]), Charsets.UTF_8) }
        secrets.getOrPut("$namespace/$name") { linkedMapOf() }.putAll(data)
        return ok("secret/$name configured")
    }

    private fun ok(text: String) = KubectlResult(0, text.toByteArray(), "")
}
