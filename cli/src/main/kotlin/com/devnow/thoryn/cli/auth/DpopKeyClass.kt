package com.devnow.thoryn.cli.auth

/**
 * SSO-3227 — **where the installation's DPoP private key lives, and what that buys you.**
 *
 * SSO-3199 shipped one answer: a software P-256 key in the OS keychain. That stops *token* theft —
 * a stolen access token is useless without a proof signed by the key — but it does not stop malware
 * running as the user, which can simply ask the keychain to sign proofs for it. A non-exportable key
 * in the platform secure element, gated on user presence, is the structural answer: the private key
 * never exists outside the secure hardware, and a signature requires a human.
 *
 * The three classes below are the whole ladder. [DpopKeyProviders.select] picks the strongest one the
 * machine actually supports, and `thoryn whoami` / `thoryn status` report which one is in force — so
 * the security property a session actually has is visible rather than assumed.
 *
 * @property wireValue the value carried in the proof's optional `key_class` header (telemetry only —
 *   it is self-asserted by the client and MUST NOT be trusted by any server; see [DpopSession.proof]).
 * @property persistent whether a key of this class survives the process. A DPoP binding is minted at
 *   login (`cnf.jkt`) and has to still be provable on the next command, so a **non-persistent class
 *   cannot be used to mint proofs at all** — see [EphemeralDpopKeyProvider].
 */
enum class DpopKeyClass(
    val wireValue: String,
    val persistent: Boolean,
    /** One line for `whoami` / `status`, phrased as the guarantee the user actually gets. */
    val description: String,
) {

    /**
     * Non-exportable key inside the platform secure element (Apple Secure Enclave, Windows TPM via
     * the platform crypto provider, Linux TPM2), with a user-presence requirement on every signing
     * authorization. The private key material never enters process memory.
     */
    SECURE_ELEMENT(
        wireValue = "secure_element",
        persistent = true,
        description = "non-exportable hardware key with user presence",
    ),

    /**
     * Software P-256 key sealed in the OS keychain — the SSO-3199 behaviour, and the fallback on any
     * machine without a usable secure element. Protects against token theft; does not protect against
     * malware running as the signed-in user.
     */
    SOFTWARE_KEYCHAIN(
        wireValue = "software_keychain",
        persistent = true,
        description = "software key in the OS keychain",
    ),

    /**
     * In-memory key with no persistence — the state a machine is in when it has neither a secure
     * element nor a usable keychain (the SSO-3199 "keychain-less degrade"). Named so that `whoami`
     * can say what is going on, **not** so proofs can be minted from it: a key that dies with the
     * process cannot honour a `cnf.jkt` minted at login, and binding a token to one would break every
     * subsequent command. The CLI therefore sends no proof at all in this state, exactly as it did
     * before SSO-3227.
     */
    EPHEMERAL(
        wireValue = "ephemeral",
        persistent = false,
        description = "in-memory only — no secure store on this machine",
    ),
}
