package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.provision.ProvisionException
import com.devnow.thoryn.provision.ProvisionFile
import com.devnow.thoryn.provision.ProvisionPart
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper
import java.io.File

/**
 * SSO-3962 (oauthy ADR 2026-10-25 provisioning-is-tenant-and-applications §3 "Migration") — `thoryn provision split`:
 * the one-time move from the mixed `thoryn.io/provision/v1` format to the two parts. A mixed file's `resources:` are
 * partitioned by the part each KIND belongs to ([ProvisionPart.ofKind]) and written as two files: a TENANT file
 * (`apiVersion: thoryn.io/tenant/v1`, for the workspace's config project) and an APPLICATION file
 * (`apiVersion: thoryn.io/application/v1`, for the app project). Each output is re-loaded through [ProvisionFile]
 * before anything is written, so the split can never leave an invalid file behind; a file whose resources all belong to
 * one part gets ONE output (the other is not written — nothing to put in it).
 *
 * The outputs are RE-RENDERED from the parsed tree, so the source file's comments are not carried over — the same
 * trade [ProvisionYamlEdit.converge] makes when it replaces an entry, and said so in the command's output. Nothing is
 * resolved: `{{env.NAME}}` placeholders and `environment:` references are copied as written, and a reference from an
 * application to a tenant resource of the same file (`environment: <name of an environment resource>`,
 * `secretSink.trust: <name of a trust>`) keeps working only as the SLUG / NAME of a live object, which is exactly how an
 * application file references what the tenant defines (ADR §4). The source file is never modified.
 */
internal object ProvisionSplit {

    private val yaml = YAMLMapper.builder().build()
    private val json = JsonMapper.builder().build()

    /** One written (or skipped) output of a split: its part, where it went, and how many resources it carries. */
    class Output(val part: ProvisionPart, val file: File, val resources: List<String>) {
        val written: Boolean get() = resources.isNotEmpty()
    }

    /**
     * Split [source] (a mixed file) into [tenantOut] and [applicationOut]. Refuses a file that is not mixed (a part file is
     * already split), an output that already exists (unless [overwrite]), and any output the loader would not accept.
     */
    fun split(source: File, tenantOut: File, applicationOut: File, overwrite: Boolean): List<Output> {
        if (!source.isFile) throw ProvisionException("provisioning file not found: ${source.path}")
        // `env = null`: `{{env.NAME}}` placeholders are copied as written, never resolved — a split is a move, not a run.
        val file = ProvisionFile.parse(source.readBytes(), source.path, yaml = !source.name.endsWith(".json", ignoreCase = true), env = null)
        if (file.part != ProvisionPart.MIXED) {
            val article = if (file.part == ProvisionPart.APPLICATION) "an" else "a"
            throw ProvisionException(
                "${source.path} already declares apiVersion ${file.part.apiVersion} — $article ${file.part.label} file is one part; only a " +
                    "${ProvisionFile.API_VERSION} (mixed) file is split",
            )
        }
        val root = yaml.readTree(source.readBytes())
        val resources = root["resources"].toList()
        val byPart = listOf(ProvisionPart.TENANT, ProvisionPart.APPLICATION).associateWith { part ->
            resources.filter { r -> ProvisionPart.ofKind(r["kind"].asString()) == part }
        }
        val outputs = listOf(
            Output(ProvisionPart.TENANT, tenantOut, byPart.getValue(ProvisionPart.TENANT).map { key(it) }),
            Output(ProvisionPart.APPLICATION, applicationOut, byPart.getValue(ProvisionPart.APPLICATION).map { key(it) }),
        )
        val rendered = outputs.filter { it.written }.associateWith { out -> render(out.part, byPart.getValue(out.part), source) }
        rendered.forEach { (out, content) ->
            if (out.file.canonicalPath == source.canonicalPath) throw ProvisionException("${out.file.path} is the source file — the split never modifies it; pass another path")
            if (out.file.exists() && !overwrite) throw ProvisionException("${out.file.path} already exists — move it aside, or re-run with --force to overwrite it")
            // The loader is the gate: an output it refuses is never written (and nothing else is either).
            ProvisionFile.parse(content.toByteArray(), out.file.path)
        }
        rendered.forEach { (out, content) ->
            out.file.absoluteFile.parentFile?.mkdirs()
            out.file.writeText(content)
        }
        return outputs
    }

    /** The file text of [part] carrying [resources]: a header comment naming the move, the `apiVersion`, the entries re-rendered. */
    private fun render(part: ProvisionPart, resources: List<JsonNode>, source: File): String {
        val header = buildString {
            appendLine("# ${part.label.replaceFirstChar { it.uppercase() }} provisioning (apiVersion ${part.apiVersion}) — written by `thoryn provision split` from ${source.path}.")
            appendLine("# ${ownerLine(part)}")
            appendLine("# The source file's comments are not carried over; nothing else was changed (`thoryn provision plan` on this file is the check).")
        }
        return header + ProvisionYamlEdit.fresh(ProvisionYamlEdit.fragment(json.createArrayNode().addAll(resources)), part.apiVersion)
    }

    private fun ownerLine(part: ProvisionPart): String = when (part) {
        ProvisionPart.TENANT -> "Converged by the workspace's ONE config project: what the tenant IS — environments, identity sources, users, sign-in, email, domain, roles, the app projects' trusts."
        else -> "Converged by the application's own project: how this client USES the tenant — it names the tenant's environments and roles, and defines none of them."
    }

    private fun key(r: JsonNode): String {
        val kind = r["kind"].asString()
        val name = r["name"]?.takeIf { it.isTextual() }?.asString()?.takeIf { it.isNotBlank() } ?: kind
        return "$kind/$name"
    }
}
