package com.devnow.thoryn.cli.cmd.provision

import com.devnow.thoryn.cli.cmd.SecretIo
import com.devnow.thoryn.provision.ProvisionEngine
import java.io.File

/**
 * SSO-3113 / SSO-3662 — the CLI's [ProvisionEngine.SecretSink]: the production sink over [SecretIo],
 * exactly as `thoryn clients create`. This is the ONE place the provisioning flow touches a TTY, and it
 * lives in the CLI on purpose — the engine library ships no sink that reads a console or writes a file;
 * a `secretSink:` delivery kind (ADR 2026-10-13 §5) is another implementation of the same interface.
 */
internal object CliSecretSink {
    /**
     * Write to [secretFile] when given, else print to an interactive TTY (with a WARN) and REFUSE a
     * non-interactive pipe unless [forceStdout]. A file receives the FIRST secret; a second confidential
     * application in the same apply is written next to it as `<secret-file>.<clientId>` so nothing is
     * overwritten.
     */
    fun toSecretIo(secretFile: File?, forceStdout: Boolean): ProvisionEngine.SecretSink {
        var delivered = 0
        return ProvisionEngine.SecretSink { clientId, secret ->
            val target = if (secretFile != null && delivered > 0) File(secretFile.path + "." + clientId) else secretFile
            SecretIo.emitSecret(
                label = "client secret for application $clientId",
                secret = secret,
                secretFile = target,
                forceStdout = forceStdout,
            ).also { if (it) delivered++ }
        }
    }
}
