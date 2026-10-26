package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.connection.Connection
import com.devnow.thoryn.cli.cmd.connection.ConnectionException
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfig
import com.devnow.thoryn.cli.cmd.provision.workflow.WorkflowConfigException
import com.devnow.thoryn.provision.ImportOptions
import com.devnow.thoryn.provision.PlaneRouting
import com.devnow.thoryn.provision.ProvisionPart
import java.io.File

/**
 * SSO-3990 — `thoryn provision import --for-workflow <file>`: one configured provisioning file of `.thoryn/workflow.yaml`, with
 * everything its import is bounded by (thoryn-provisioning ADR 2026-09-30, amendment 2026-10-26 §13.3):
 *
 *  - the file's own CONNECTION — its `auth.scopes` are the scopes the file is applied with (an entry this identity could not
 *    write is rendered `readOnly: true`) and, narrowed by the session's token, the scopes it is planned with (a kind it could
 *    not read is listed, never read) — exactly what `config.trust-scopes` holds the written file to;
 *  - PLANE ROUTING over every configured file: a sandbox's objects go to the file whose connection is that sandbox's
 *    (`auth.environment`), everything else to the one file planned with a production-plane connection;
 *  - the repository's OWN TRUSTS — every configured workload-identity connection's client — which no file declares.
 *
 * Resolved from the committed configuration only, never from the workspace: the same repository gives the same answer in CI
 * and on a laptop.
 */
internal class WorkflowImportTarget private constructor(
    /** The configured file, as `.thoryn/workflow.yaml` lists it (repository-relative). */
    val file: String,
    /** Its connection, as listed. */
    val connectionPath: String,
    val connection: Connection,
    private val routing: PlaneRouting,
    private val ownTrustClients: Set<String>,
) {
    /** The engine options for this file, for a session whose token carries [tokenScopes] (null ⇒ unknown). */
    fun options(part: ProvisionPart, tokenScopes: Set<String>?): ImportOptions {
        val declared = connection.scopes.toSet()
        return ImportOptions(
            part = part,
            // A plan job is minted its plan profile — a subset of the connection's scopes; a person's broader session is
            // narrowed to them, so a laptop import renders what the workflow's own import would.
            planScopes = tokenScopes?.filter { it in declared }?.toSet() ?: declared,
            applyScopes = declared,
            routing = routing,
            ownTrustClients = ownTrustClients,
        )
    }

    companion object {
        /**
         * Read [config] (absent ⇒ the built-in default: one file, `.thoryn/provision.yaml`, with `.thoryn/connection.json`),
         * find [file] among its `files`, and load every configured connection (paths relative to [root]). Every problem is
         * a [WorkflowImportException] naming the path and the fix.
         */
        fun resolve(root: File, config: File, configDisplay: String, file: String): WorkflowImportTarget {
            val workflow = try {
                WorkflowConfig.load(config, configDisplay)
            } catch (ex: WorkflowConfigException) {
                throw WorkflowImportException(ex.message ?: "$configDisplay does not load")
            }
            val wanted = normalize(file)
            val entry = workflow.files.firstOrNull { normalize(it.file) == wanted } ?: throw WorkflowImportException(
                "$file is not a configured provisioning file of ${workflow.source ?: "${WorkflowConfig.DEFAULT_PATH} (absent — the default)"}; configured: " +
                    workflow.files.joinToString(", ") { it.file },
            )
            val connections = workflow.files.map { it.connection }.distinct().associateWith { path ->
                val f = File(root, path)
                if (!f.isFile) throw WorkflowImportException("$path (the connection of a configured file) is not in the repository under ${root.path}")
                try {
                    Connection.parse(f.readBytes(), path)
                } catch (ex: ConnectionException) {
                    throw WorkflowImportException(ex.message ?: "$path does not load")
                }
            }
            val byPlane = workflow.files.groupBy { planeOf(connections.getValue(it.connection)) }
            byPlane.forEach { (plane, entries) ->
                val paths = entries.map { it.file }.distinct()
                if (paths.size > 1) {
                    throw WorkflowImportException(
                        "${paths.joinToString(" and ")} are all planned with a ${plane?.let { "sandbox '$it'" } ?: "production-plane"} connection — plane routing " +
                            "needs one file per plane, so an object of that plane would have no single home; give each its own connection environment",
                    )
                }
            }
            val routing = PlaneRouting(
                target = entry.file,
                productionFile = byPlane[null]?.first()?.file,
                sandboxFiles = byPlane.filterKeys { it != null }.map { (plane, entries) -> plane!! to entries.first().file }.toMap(),
            )
            val ownTrusts = connections.values.filter { it.isWorkloadIdentity }.map { it.clientId }.toSet()
            return WorkflowImportTarget(entry.file, entry.connection, connections.getValue(entry.connection), routing, ownTrusts)
        }

        private fun normalize(path: String): String = File(path).normalize().path.removePrefix("./")

        /**
         * The plane a connection signs in to: its sandbox slug (`auth.environment`, or the one `/{environment}` path segment an
         * explicit `auth.audience` carries — the seeds write one or the other), or null for the production plane.
         */
        fun planeOf(connection: Connection): String? = connection.environment ?: connection.audience?.let { audience ->
            runCatching { java.net.URI(audience).path }.getOrNull()?.trim('/')?.takeIf { it.isNotEmpty() && Connection.SLUG_PATTERN.matches(it) }
        }
    }
}

internal class WorkflowImportException(message: String) : RuntimeException(message)
