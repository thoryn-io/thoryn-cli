package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.api.ProductApiClient
import com.devnow.thoryn.cli.cmd.SecretIo
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.kotlinModule
import java.io.File

/** SSO-2952 — a machine-client bootstrap could not be provisioned (bad spec shape, or a create failure). */
internal class MachineClientProvisionException(message: String) : RuntimeException(message)

/**
 * SSO-2952 (epic SSO-2947) — the declarative machine-client spec (DATA, not code), loaded from a
 * bundled JSON resource under `/provision/`. It describes the confidential `client_credentials` client
 * `thoryn provision ci-identity` mints — its display name, client type, grant types, and the granted
 * scope set — so the scope list lives in one authoritative, versioned file rather than hardcoded in
 * Kotlin (the same file `CiConnectionConfinementTest` reads to bound the CI connection contract).
 */
internal data class MachineClientSpec(
    val displayName: String?,
    val clientType: String,
    val grantTypes: List<String>,
    val scopes: List<String>,
) {
    companion object {
        /** The bundled `ci-identity` bootstrap spec — the CI machine identity's grant. */
        const val CI_IDENTITY_RESOURCE = "/provision/ci-identity.json"

        private val mapper = JsonMapper.builder().addModule(kotlinModule()).build()

        fun ciIdentity(): MachineClientSpec = load(CI_IDENTITY_RESOURCE)

        /** Load a bundled machine-client spec resource, reading its `machineClient` object. */
        fun load(resource: String): MachineClientSpec {
            val bytes = MachineClientSpec::class.java.getResourceAsStream(resource)?.use { it.readBytes() }
                ?: throw MachineClientProvisionException("no bundled provisioning spec '$resource'")
            val root = mapper.readTree(bytes)
            val mc = root["machineClient"]?.takeIf { !it.isNull }
                ?: throw MachineClientProvisionException("provisioning spec '$resource' has no 'machineClient' object")
            return MachineClientSpec(
                displayName = mc["displayName"]?.takeIf { !it.isNull }?.asString()?.takeIf { it.isNotBlank() },
                clientType = mc["clientType"]?.takeIf { !it.isNull }?.asString()?.trim().orEmpty().ifEmpty { "confidential" },
                grantTypes = stringList(mc["grantTypes"]),
                scopes = stringList(mc["scopes"]),
            )
        }

        internal fun stringList(value: JsonNode?): List<String> =
            if (value != null && value.isArray) value.mapNotNull { it.asString() } else emptyList()
    }
}

/** SSO-2952 — the outcome of a machine-client mint: the non-secret shape only (never the secret). */
internal data class MachineClientResult(
    val clientId: String,
    val grantedScopes: List<String>,
    /** Whether the one-shot secret was delivered through the [MachineClientProvisioner.SecretSink]. */
    val secretDelivered: Boolean,
)

/**
 * SSO-2952 (epic SSO-2947) — the shared mint logic behind `thoryn provision ci-identity`. It creates a
 * confidential `client_credentials` machine client through the SUPPORTED product workflow — the SAME
 * product-api `POST /api/v1/applications` call `thoryn clients create` makes (`tenant:applications.write`)
 * — and routes the ONE server-minted `client_secret` through the CLI's [SecretIo] channel via
 * [secretSink] (a `--secret-file` / guarded stdout), exactly as `thoryn clients create` does.
 *
 * **Secret-safety (the ADR-2026-09-09 boundary, now an operator command rather than a recipe action).**
 * The minted secret exits EXCLUSIVELY through [secretSink]; it is NEVER logged, placed on argv, or
 * returned in [MachineClientResult] — the result carries only the non-secret shape (`clientId` +
 * granted `scopes`). Relocating this off the example-recipe surface keeps every recipe receipt
 * structurally secret-free.
 */
internal class MachineClientProvisioner(
    private val client: ProductApiClient,
    private val secretSink: SecretSink,
) {
    fun provision(spec: MachineClientSpec): MachineClientResult {
        // Re-check the machine-client shape (the spec is DATA that could be hand-edited): a machine
        // identity is confidential + client_credentials, never a public (secret-less) client.
        if (spec.clientType != "confidential") {
            throw MachineClientProvisionException("a machine client must be 'confidential' (was '${spec.clientType}')")
        }
        if ("client_credentials" !in spec.grantTypes) {
            throw MachineClientProvisionException(
                "a machine client must include the 'client_credentials' grant (was ${spec.grantTypes})",
            )
        }

        val body = linkedMapOf<String, Any?>("clientType" to spec.clientType, "grantTypes" to spec.grantTypes)
        spec.displayName?.let { body["displayName"] = it }
        if (spec.scopes.isNotEmpty()) body["scopes"] = spec.scopes

        val app = client.createApplication(body)
        val clientId = (app["clientId"] ?: app["client_id"])?.takeIf { !it.isNull }?.asString()
            ?: throw MachineClientProvisionException("machine-client create returned no clientId")
        // Prefer the granted scopes echoed by the server; fall back to what the spec requested.
        val grantedScopes = MachineClientSpec.stringList(app["scopes"]).ifEmpty { spec.scopes }

        // Route the ONE minted secret through the sink and NOWHERE else — never a local field, log, or
        // the returned result.
        val secret = (app["clientSecret"] ?: app["client_secret"])?.takeIf { !it.isNull }?.asString()
        val delivered = if (!secret.isNullOrEmpty()) secretSink.emit(clientId, secret) else true
        return MachineClientResult(clientId = clientId, grantedScopes = grantedScopes, secretDelivered = delivered)
    }

    /**
     * The single channel a minted `client_secret` leaves through. [emit] returns `true` when the secret
     * was delivered, `false` when it was refused (e.g. no `--secret-file` and a non-interactive stdout)
     * — the command then exits non-zero so the operator notices the credential was not surfaced.
     */
    fun interface SecretSink {
        fun emit(clientId: String, secret: String): Boolean

        companion object {
            /**
             * The production sink over [SecretIo], mirroring `thoryn clients create` exactly: write to
             * [secretFile] when given, else print to an interactive TTY (with a WARN) and REFUSE a
             * non-interactive pipe unless [forceStdout]. The secret never touches argv or a log.
             */
            fun toSecretIo(secretFile: File?, forceStdout: Boolean): SecretSink = SecretSink { _, secret ->
                SecretIo.emitSecret(
                    label = "CI machine client secret",
                    secret = secret,
                    secretFile = secretFile,
                    forceStdout = forceStdout,
                )
            }
        }
    }
}
