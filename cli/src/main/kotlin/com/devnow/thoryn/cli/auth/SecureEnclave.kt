package com.devnow.thoryn.cli.auth

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference

/**
 * SSO-3227 — **the macOS Secure Enclave backend for the CLI's DPoP key**, bound straight to
 * `Security.framework` / `CoreFoundation` through JNA.
 *
 * ## Why JNA and not the FFM API
 *
 * The obvious modern route is `java.lang.foreign` (Project Panama). It is **not available to this
 * project**: FFM was finalised in **JDK 22**, and thoryn-cli compiles and ships on **JDK 21**
 * (`maven.compiler.release=21` in the pom; `.github/workflows/release.yml` builds every native image
 * with `graalvm/setup-graalvm` at `java-version: "21"`). Using it would mean moving the whole build —
 * and every release binary — to a newer JDK, which is a separate decision with its own blast radius,
 * not a detail of this story.
 *
 * JNA is the right tool here anyway, and costs nothing new: `net.java.dev.jna:jna` is **already a
 * compile-scope dependency** (via `com.github.javakeyring:java-keyring`), it is **already wired into
 * the native image** (`native-image.properties` initialises `com.sun.jna` at run time and
 * `resource-config.json` ships `libjnidispatch`), and java-keyring's own macOS backend **already calls
 * `Security.framework` this exact way** in the shipped binary. So the pattern is proven in this
 * artefact rather than newly introduced. **No new dependency, no external binary, no runtime
 * download** — the three things this change was not allowed to add.
 *
 * ## What the key actually is
 *
 * A P-256 key pair generated *inside* the Secure Enclave (`kSecAttrTokenIDSecureEnclave`), persisted
 * as a keychain item under [applicationTag], and guarded by a `SecAccessControl` carrying
 * `kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence` against
 * `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Consequences, which are the point of the story:
 *
 * - the private key **never exists outside the enclave** — there is no PKCS#8 to steal, and
 *   `SecKeyCopyExternalRepresentation` on the private half fails by design;
 * - **every signature needs a human** — Touch ID, Watch, or the login password;
 * - the key is **device-bound** and never syncs to iCloud Keychain.
 *
 * ## Known blocker on released binaries — read before debugging
 *
 * Creating a **permanent** Secure Enclave key requires the calling binary to be code-signed with a
 * keychain-access-group entitlement. Verified on this hardware (2026-09-19, macOS 15 / Apple silicon):
 * an unsigned process creates the enclave key fine but fails to persist it, with
 * `errSecMissingEntitlement (-34018)`, message *"failed to add key to keychain"*. The released
 * `thoryn` binaries are not code-signed or notarised today, so this backend will report itself
 * unavailable there and the CLI will use the software keychain key. Code-signing + entitling the
 * macOS binary is tracked as a follow-up sub-task of SSO-3227 and is the prerequisite that switches
 * this on. [SecureElementUnavailable.MISSING_ENTITLEMENT] is the precise signal.
 */
internal object SecureEnclave {

    /** Keychain `kSecAttrApplicationTag` for the CLI's DPoP key. One key per installation. */
    const val APPLICATION_TAG: String = "io.thoryn.cli.dpop.v1"

    /** `errSecMissingEntitlement` — the binary is not signed with a keychain-access-group entitlement. */
    const val ERR_SEC_MISSING_ENTITLEMENT: Long = -34018

    /** `errSecUserCanceled` — the user dismissed the presence prompt. */
    const val ERR_SEC_USER_CANCELED: Long = -128

    /** `errSecAuthFailed` — presence was attempted and not satisfied. */
    const val ERR_SEC_AUTH_FAILED: Long = -25293

    fun isMacOs(): Boolean = System.getProperty("os.name").orEmpty().startsWith("Mac")

    // ── JNA surface ──────────────────────────────────────────────────────────────────────────────

    internal interface CoreFoundationLib : Library {
        fun CFDictionaryCreate(
            allocator: Pointer?,
            keys: Array<Pointer>,
            values: Array<Pointer>,
            numValues: Long,
            keyCallBacks: Pointer,
            valueCallBacks: Pointer,
        ): Pointer?

        fun CFNumberCreate(allocator: Pointer?, theType: Int, valuePtr: Pointer): Pointer?
        fun CFDataCreate(allocator: Pointer?, bytes: ByteArray, length: Long): Pointer?
        fun CFDataGetBytePtr(data: Pointer): Pointer?
        fun CFDataGetLength(data: Pointer): Long
        fun CFErrorGetCode(error: Pointer): Long
        fun CFRelease(cf: Pointer)
    }

    internal interface SecurityLib : Library {
        fun SecAccessControlCreateWithFlags(
            allocator: Pointer?,
            protection: Pointer,
            flags: Long,
            error: PointerByReference,
        ): Pointer?

        fun SecKeyCreateRandomKey(parameters: Pointer, error: PointerByReference): Pointer?
        fun SecKeyCopyPublicKey(key: Pointer): Pointer?
        fun SecKeyCopyExternalRepresentation(key: Pointer, error: PointerByReference): Pointer?
        fun SecKeyCreateSignature(key: Pointer, algorithm: Pointer, dataToSign: Pointer, error: PointerByReference): Pointer?
        fun SecItemCopyMatching(query: Pointer, result: PointerByReference): Int
        fun SecItemDelete(query: Pointer): Int
    }

    private val cf: CoreFoundationLib by lazy { Native.load("CoreFoundation", CoreFoundationLib::class.java) }
    private val sec: SecurityLib by lazy { Native.load("Security", SecurityLib::class.java) }
    private val cfLibrary: NativeLibrary by lazy { NativeLibrary.getInstance("CoreFoundation") }
    private val secLibrary: NativeLibrary by lazy { NativeLibrary.getInstance("Security") }

    /**
     * Read one of the framework's global `CFStringRef` constants (`kSecAttrKeyType`, …). These are
     * exported *data* symbols holding a pointer, so the address has to be dereferenced once.
     */
    private fun constant(library: NativeLibrary, name: String): Pointer =
        library.getGlobalVariableAddress(name).getPointer(0)

    /** The dictionary callback tables are exported as structs — the address itself is the argument. */
    private fun structAddress(library: NativeLibrary, name: String): Pointer =
        library.getGlobalVariableAddress(name)

    // ── Operations ───────────────────────────────────────────────────────────────────────────────

    /**
     * The existing Secure Enclave key for this installation, or null when none is stored. Cheap, and
     * **never prompts**: obtaining a `SecKeyRef` is not a use of the private key, only signing is.
     */
    fun findKey(applicationTag: String = APPLICATION_TAG): Pointer? = withArena { arena ->
        val query = arena.dictionary(
            constant(secLibrary, "kSecClass") to constant(secLibrary, "kSecClassKey"),
            constant(secLibrary, "kSecAttrApplicationTag") to arena.data(applicationTag.toByteArray()),
            constant(secLibrary, "kSecAttrKeyType") to constant(secLibrary, "kSecAttrKeyTypeECSECPrimeRandom"),
            constant(secLibrary, "kSecReturnRef") to constant(cfLibrary, "kCFBooleanTrue"),
        )
        val out = PointerByReference()
        // errSecSuccess == 0; anything else (notably errSecItemNotFound, -25300) means "no key".
        if (sec.SecItemCopyMatching(query, out) == 0) out.value else null
    }

    /**
     * Generate the installation's Secure Enclave key: non-exportable, presence-gated, device-bound,
     * and persisted in the keychain under [applicationTag].
     *
     * @throws SecureElementException carrying the `OSStatus`, so the caller can tell the expected
     *   "this binary is not entitled to store one" ([ERR_SEC_MISSING_ENTITLEMENT], degrade quietly to
     *   the software key) from a genuine fault.
     */
    fun createKey(applicationTag: String = APPLICATION_TAG): Pointer = withArena { arena ->
        val error = PointerByReference()
        val access = sec.SecAccessControlCreateWithFlags(
            null,
            constant(secLibrary, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"),
            PRIVATE_KEY_USAGE or USER_PRESENCE,
            error,
        ) ?: throw SecureElementException("could not build the key's access control", codeOf(error))
        arena.own(access)

        val privateAttrs = arena.dictionary(
            constant(secLibrary, "kSecAttrIsPermanent") to constant(cfLibrary, "kCFBooleanTrue"),
            constant(secLibrary, "kSecAttrApplicationTag") to arena.data(applicationTag.toByteArray()),
            constant(secLibrary, "kSecAttrAccessControl") to access,
        )

        val parameters = arena.dictionary(
            constant(secLibrary, "kSecAttrKeyType") to constant(secLibrary, "kSecAttrKeyTypeECSECPrimeRandom"),
            constant(secLibrary, "kSecAttrKeySizeInBits") to arena.number(256),
            constant(secLibrary, "kSecAttrTokenID") to constant(secLibrary, "kSecAttrTokenIDSecureEnclave"),
            constant(secLibrary, "kSecPrivateKeyAttrs") to privateAttrs,
        )

        val genError = PointerByReference()
        sec.SecKeyCreateRandomKey(parameters, genError)
            ?: throw SecureElementException(
                "the Secure Enclave key could not be created or stored",
                codeOf(genError),
            )
    }

    /** Delete the installation's Secure Enclave key. Returns true when one was present. */
    fun deleteKey(applicationTag: String = APPLICATION_TAG): Boolean = withArena { arena ->
        val query = arena.dictionary(
            constant(secLibrary, "kSecClass") to constant(secLibrary, "kSecClassKey"),
            constant(secLibrary, "kSecAttrApplicationTag") to arena.data(applicationTag.toByteArray()),
            constant(secLibrary, "kSecAttrKeyType") to constant(secLibrary, "kSecAttrKeyTypeECSECPrimeRandom"),
        )
        sec.SecItemDelete(query) == 0
    }

    /**
     * The key's public half as an ANSI X9.63 uncompressed point (`0x04 || X || Y`, 65 bytes) — the
     * only external representation a Secure Enclave key has, and the *public* one.
     */
    fun publicPoint(keyRef: Pointer): ByteArray = withArena { arena ->
        val publicKey = sec.SecKeyCopyPublicKey(keyRef)
            ?: throw SecureElementException("the Secure Enclave key has no readable public half", null)
        arena.own(publicKey)
        val error = PointerByReference()
        val representation = sec.SecKeyCopyExternalRepresentation(publicKey, error)
            ?: throw SecureElementException("the public key could not be exported", codeOf(error))
        arena.own(representation)
        bytesOf(representation)
    }

    /**
     * Sign [data] with the enclave key — **this is the call that raises the user-presence prompt**,
     * and the only operation that uses the private key.
     *
     * Uses `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`: the enclave hashes the message itself
     * and returns an ASN.1 DER ECDSA signature, the same shape the JDK produces, so
     * [DpopKey.signCompact]'s DER → JOSE conversion serves both paths unchanged.
     */
    fun sign(keyRef: Pointer, data: ByteArray): ByteArray = withArena { arena ->
        val message = arena.data(data)
        val error = PointerByReference()
        val signature = sec.SecKeyCreateSignature(
            keyRef,
            constant(secLibrary, "kSecKeyAlgorithmECDSASignatureMessageX962SHA256"),
            message,
            error,
        ) ?: throw SecureElementException("the Secure Enclave refused to sign", codeOf(error))
        arena.own(signature)
        bytesOf(signature)
    }

    // ── CoreFoundation helpers ───────────────────────────────────────────────────────────────────

    private fun codeOf(error: PointerByReference): Long? =
        error.value?.let { runCatching { cf.CFErrorGetCode(it) }.getOrNull() }

    private fun bytesOf(cfData: Pointer): ByteArray {
        val length = cf.CFDataGetLength(cfData)
        if (length <= 0) return ByteArray(0)
        val bytes = cf.CFDataGetBytePtr(cfData) ?: return ByteArray(0)
        return bytes.getByteArray(0, length.toInt())
    }

    /**
     * A scope that owns every CoreFoundation object created inside it and `CFRelease`s them on the way
     * out. CF is manually reference-counted and JNA gives us no finaliser, so without this every
     * invocation would leak a handful of dictionaries — small, but this code runs in a long-lived
     * `thoryn examples` loop too.
     *
     * Objects obtained from *global constants* are NOT owned: they are framework-owned singletons and
     * releasing one would over-release it.
     */
    private class Arena {
        private val owned = ArrayList<Pointer>()

        fun <T : Pointer> own(pointer: T): T = pointer.also { owned += it }

        fun data(bytes: ByteArray): Pointer =
            own(SecureEnclave.cf.CFDataCreate(null, bytes, bytes.size.toLong()) ?: error("CFDataCreate returned null"))

        fun number(value: Int): Pointer {
            val memory = Memory(4).also { it.setInt(0, value) }
            held += memory
            return own(
                SecureEnclave.cf.CFNumberCreate(null, KCF_NUMBER_INT_TYPE, memory)
                    ?: error("CFNumberCreate returned null"),
            )
        }

        fun dictionary(vararg entries: Pair<Pointer, Pointer>): Pointer {
            val keys = Array(entries.size) { entries[it].first }
            val values = Array(entries.size) { entries[it].second }
            return own(
                SecureEnclave.cf.CFDictionaryCreate(
                    null,
                    keys,
                    values,
                    entries.size.toLong(),
                    structAddress(SecureEnclave.cfLibrary, "kCFTypeDictionaryKeyCallBacks"),
                    structAddress(SecureEnclave.cfLibrary, "kCFTypeDictionaryValueCallBacks"),
                ) ?: error("CFDictionaryCreate returned null"),
            )
        }

        /** Keeps JNA [Memory] alive for as long as the CF object that reads it. */
        private val held = ArrayList<Memory>()

        fun release() {
            // Reverse order: a dictionary is released before the values it retained.
            owned.asReversed().forEach { runCatching { SecureEnclave.cf.CFRelease(it) } }
            owned.clear()
            held.clear()
        }
    }

    /**
     * Run [block] in an [Arena], releasing everything it created afterwards. A `SecKeyRef` the caller
     * keeps (the key handle itself) is deliberately NOT arena-owned — it outlives the call.
     */
    private fun <T> withArena(block: (Arena) -> T): T {
        val arena = Arena()
        return try {
            block(arena)
        } finally {
            arena.release()
        }
    }

    /** `kSecAccessControlPrivateKeyUsage` — the key may be used for signing. */
    private const val PRIVATE_KEY_USAGE: Long = 1L shl 30

    /** `kSecAccessControlUserPresence` — biometry, Watch, or the device password, OS's choice. */
    private const val USER_PRESENCE: Long = 1L shl 0

    /** `kCFNumberIntType`. */
    private const val KCF_NUMBER_INT_TYPE: Int = 9
}

/** A Security.framework call failed; [osStatus] is the `OSStatus` / `CFError` code when there was one. */
internal class SecureElementException(message: String, val osStatus: Long?) :
    RuntimeException(if (osStatus == null) message else "$message (OSStatus $osStatus)")

/** Why the secure-element provider is not in play, in words a user can act on. */
internal object SecureElementUnavailable {

    const val NOT_SUPPORTED: String = "this platform has no supported secure element"

    const val MISSING_ENTITLEMENT: String =
        "macOS refused to store a Secure Enclave key because this binary is not code-signed with a " +
            "keychain-access-group entitlement (OSStatus -34018)"

    const val NON_INTERACTIVE: String =
        "no interactive terminal — a hardware key requires user presence, which cannot be proven here"
}
