package com.devnow.thoryn.cli.auth

import com.sun.jna.Pointer
import java.io.PrintStream
import java.time.Instant

/**
 * SSO-3227 — **where this installation's DPoP key comes from**, as one seam with three
 * implementations. [DpopKeyProviders.select] picks the strongest the machine supports; everything
 * above it ([Dpop], [DpopSession]) is indifferent to which one won.
 *
 * A provider answers two questions and performs one action:
 *  - [status] — can I serve a key right now, and if not, *why not* in words a user can act on?
 *    Cheap, never prompts, never creates anything.
 *  - [load] — give me the key, creating one if [provision] and none exists yet.
 *  - [delete] — discard it (`thoryn logout --rotate-key`).
 */
internal interface DpopKeyProvider {

    val keyClass: DpopKeyClass

    /** Cheap, side-effect-free capability check. Must not prompt and must not create a key. */
    fun status(): ProviderStatus

    /**
     * Load the installation's key, or create one when [provision] is set and none exists. Providers
     * only create on an explicit provisioning pass (`thoryn login`) so a routine command can never
     * silently rotate the key a live token is bound to.
     */
    fun load(provision: Boolean): DpopKey

    /** Discard the stored key. Returns true when one was present. */
    fun delete(): Boolean
}

/** Whether a provider can serve a key, and the reason when it cannot. */
internal sealed interface ProviderStatus {

    /** A key exists and can be loaded now. */
    data object Ready : ProviderStatus

    /** No key yet, but this provider could create one on the next `thoryn login`. */
    data object Provisionable : ProviderStatus

    /** Not usable on this machine, for [reason] (user-facing, one line, no jargon dead-ends). */
    data class Unavailable(val reason: String) : ProviderStatus
}

// ── 1. Secure element ────────────────────────────────────────────────────────────────────────────

/**
 * SSO-3227 — the **secure-element** provider: a non-exportable key in the platform's secure hardware,
 * gated on user presence.
 *
 * Today this dispatches to exactly one backend, macOS / Secure Enclave ([SecureEnclave]). Windows
 * (TPM via `MS_PLATFORM_CRYPTO_PROVIDER` / NCrypt) and Linux (TPM2 via `tpm2-pkcs11`) are named in the
 * story and are **deliberately not stubbed into existence here** — a backend that cannot be built or
 * exercised on the machine doing the work would be a claim, not an implementation. They report
 * [SecureElementUnavailable.NOT_SUPPORTED] and are tracked as their own sub-tasks of SSO-3227; the
 * seam they will slot into is this class, and nothing above it has to change when they land.
 */
internal class SecureElementDpopKeyProvider(
    private val applicationTag: String = SecureEnclave.APPLICATION_TAG,
    private val interactive: () -> Boolean = { Tty.interactive() },
    private val clock: () -> Instant = { Instant.now() },
) : DpopKeyProvider {

    override val keyClass: DpopKeyClass = DpopKeyClass.SECURE_ELEMENT

    override fun status(): ProviderStatus {
        if (!SecureEnclave.isMacOs()) return ProviderStatus.Unavailable(SecureElementUnavailable.NOT_SUPPORTED)
        // Presence cannot be proven without a human, so a hardware key is unusable in CI even when the
        // enclave is right there. Checked before any native call: cheap, and it keeps CI off this path.
        if (!interactive()) return ProviderStatus.Unavailable(SecureElementUnavailable.NON_INTERACTIVE)
        return try {
            if (SecureEnclave.findKey(applicationTag) != null) ProviderStatus.Ready else ProviderStatus.Provisionable
        } catch (e: Exception) {
            ProviderStatus.Unavailable(e.message ?: SecureElementUnavailable.NOT_SUPPORTED)
        }
    }

    override fun load(provision: Boolean): DpopKey {
        val existing = SecureEnclave.findKey(applicationTag)
        val keyRef: Pointer = when {
            existing != null -> existing
            provision -> SecureEnclave.createKey(applicationTag)
            else -> throw SecureElementException("no Secure Enclave key for this installation yet", null)
        }
        val publicKey = DpopKey.publicKeyFromX963(SecureEnclave.publicPoint(keyRef))
        return DpopKey.hardware(
            signer = SecureEnclaveSigner(keyRef),
            publicKey = publicKey,
            createdAt = clock(),
            keyClass = DpopKeyClass.SECURE_ELEMENT,
        )
    }

    override fun delete(): Boolean =
        if (!SecureEnclave.isMacOs()) false else runCatching { SecureEnclave.deleteKey(applicationTag) }.getOrDefault(false)
}

/**
 * The [DpopSigner] for a secure-element key: it holds an opaque OS handle, never key material, and
 * every call is an authorization request the user has to satisfy.
 *
 * The presence *cadence* lives here rather than in [SecureEnclave] because this is the object whose
 * lifetime matches "one command": [Dpop] caches the [DpopKey] for the process, so all the proofs a
 * command mints go through this one instance and one key handle. [UserPresence.announceIfDue] fires
 * at most once per process, before the first signature — never per request, which is the rule the
 * story sets.
 */
internal class SecureEnclaveSigner(
    private val keyRef: Pointer,
    private val err: PrintStream = System.err,
) : DpopSigner {

    override fun signDer(signingInput: ByteArray): ByteArray {
        UserPresence.announceIfDue(err)
        val signature = SecureEnclave.sign(keyRef, signingInput)
        // Only a signature the enclave actually produced proves presence was satisfied.
        UserPresence.recordVerified()
        return signature
    }
}

// ── 2. Software keychain ─────────────────────────────────────────────────────────────────────────

/**
 * SSO-3227 — the **software keychain** provider: exactly the SSO-3199 behaviour, now behind the seam.
 * A P-256 key generated in this process and sealed in the OS keychain (or, under the explicit CI
 * opt-in, a 0600 file). This is the fallback wherever no secure element is usable, and it remains the
 * class most installations run with.
 */
internal class SoftwareKeychainDpopKeyProvider(
    private val storeProvider: () -> DpopKeyStore = { DpopKeyStoreFactory.default() },
    private val clock: () -> Instant = { Instant.now() },
) : DpopKeyProvider {

    override val keyClass: DpopKeyClass = DpopKeyClass.SOFTWARE_KEYCHAIN

    /**
     * Resolved once per provider instance. [DpopKeyStoreFactory.default] is not free of side effects —
     * it logs a WARNING under the CI plaintext opt-in — and the ladder calls [status] then [load] on
     * the same rung, which would emit that warning twice per command.
     */
    private val store: DpopKeyStore by lazy { storeProvider() }

    override fun status(): ProviderStatus = try {
        store
        ProviderStatus.Ready
    } catch (e: Exception) {
        ProviderStatus.Unavailable(e.message ?: "no secure key store is available on this machine")
    }

    /**
     * [provision] is not consulted: unlike a hardware key, generating a software key is free and
     * side-effect-free, and SSO-3199 already generated one on first use from any command. Keeping
     * that avoids a behaviour change for the overwhelmingly common path.
     */
    override fun load(provision: Boolean): DpopKey {
        val stored = store.read()
        if (stored != null) {
            runCatching { DpopKey.fromStored(stored) }.getOrNull()?.let { return it }
        }
        return DpopKey.generate(clock()).also { store.write(it.toStored()) }
    }

    override fun delete(): Boolean {
        val target = runCatching { store }.getOrNull() ?: return false
        val had = runCatching { target.read() }.getOrNull() != null
        runCatching { target.delete() }
        return had
    }
}

// ── 3. Ephemeral ─────────────────────────────────────────────────────────────────────────────────

/**
 * SSO-3227 — the **ephemeral** provider: an in-memory key, the state a machine is in when it has
 * neither a secure element nor a usable keychain.
 *
 * It exists so that state has a *name* — `thoryn whoami` can say "ephemeral — no secure store on this
 * machine" instead of silently reporting nothing. It is **not** a way to keep sending proofs: a
 * `cnf.jkt` minted at login has to still be provable on the next command, and a key that dies with
 * the process cannot do that. Binding a token to one would break every subsequent invocation, which
 * is strictly worse than the pre-SSO-3199 wire shape. [Dpop] therefore refuses to mint proofs from a
 * non-persistent class and sends none, exactly as SSO-3199 did — see [DpopKeyClass.persistent].
 */
internal class EphemeralDpopKeyProvider(
    private val clock: () -> Instant = { Instant.now() },
) : DpopKeyProvider {

    override val keyClass: DpopKeyClass = DpopKeyClass.EPHEMERAL

    private val key: DpopKey by lazy { DpopKey.generate(clock()) }

    override fun status(): ProviderStatus = ProviderStatus.Ready

    override fun load(provision: Boolean): DpopKey = key

    override fun delete(): Boolean = false
}

// ── Selection ────────────────────────────────────────────────────────────────────────────────────

/**
 * SSO-3227 — picks the strongest provider that can actually **hand over a key**, and says why each
 * stronger option was passed over.
 *
 * Order is fixed and is the security ladder: secure element → software keychain → ephemeral.
 *
 * ## Why this resolves by loading, not merely by asking
 *
 * An earlier shape of this chose a rung from [DpopKeyProvider.status] alone and committed to it. That
 * is wrong in two ways that both matter on a real Mac:
 *
 *  - A machine with a Secure Enclave but no key yet reports [ProviderStatus.Provisionable]. On a
 *    routine (non-login) command there is nothing to load, so committing to that rung would send
 *    **no proof at all** — a silent regression on exactly the machines the feature is meant to help.
 *  - Creating the key can fail for a reason no cheap check can see: macOS refuses to *persist* a
 *    Secure Enclave key unless the binary carries a keychain-access-group entitlement
 *    (`errSecMissingEntitlement`), and that only surfaces when you try.
 *
 * So a rung that cannot produce a key — for either reason — is recorded as skipped and the ladder
 * continues. The class this reports is therefore the class of the key that will actually sign, which
 * is the only answer worth printing: `whoami` claiming hardware protection that is not in force would
 * be worse than saying nothing.
 *
 * Non-persistent rungs are never loaded from: a key that dies with the process cannot honour a
 * `cnf.jkt` minted at login (see [DpopKeyClass.EPHEMERAL]). Falling off the end of the ladder yields
 * a null [Resolution.key], which the caller renders as "no proof" — the pre-SSO-3199 wire shape.
 */
internal object DpopKeyProviders {

    /**
     * The key that will sign, its class, and the one-line reason each stronger class was passed over.
     * [key] is null when no persistent key could be had at all.
     */
    internal data class Resolution(
        val key: DpopKey?,
        val keyClass: DpopKeyClass,
        /** `keyClass -> why it was skipped`, strongest first. Surfaced by `whoami` / `status`. */
        val skipped: List<Pair<DpopKeyClass, String>>,
    )

    /** Test seam — substitute the whole ladder's outcome. */
    internal var override: (() -> Resolution)? = null

    fun defaultLadder(): List<DpopKeyProvider> = listOf(
        SecureElementDpopKeyProvider(),
        SoftwareKeychainDpopKeyProvider(),
        EphemeralDpopKeyProvider(),
    )

    fun resolve(
        candidates: List<DpopKeyProvider> = defaultLadder(),
        provision: Boolean = false,
    ): Resolution {
        override?.let { return it() }
        val skipped = mutableListOf<Pair<DpopKeyClass, String>>()
        for (candidate in candidates) {
            when (val status = candidate.status()) {
                is ProviderStatus.Unavailable -> {
                    skipped += candidate.keyClass to status.reason
                    continue
                }
                else -> Unit
            }
            if (!candidate.keyClass.persistent) {
                skipped += candidate.keyClass to candidate.keyClass.description
                continue
            }
            try {
                return Resolution(candidate.load(provision), candidate.keyClass, skipped.toList())
            } catch (e: Exception) {
                // Could not produce a key — not provisioned yet on a non-login command, or the OS
                // refused to store one. Either way this rung is not in force; try the next.
                skipped += candidate.keyClass to (e.message ?: e.javaClass.simpleName)
            }
        }
        return Resolution(null, DpopKeyClass.EPHEMERAL, skipped.toList())
    }

    internal fun resetForTest() {
        override = null
    }
}
