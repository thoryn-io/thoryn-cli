package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.time.Instant

/**
 * SSO-3227 — **provider selection, the degrade rules, and the presence cadence.**
 *
 * The real Secure Enclave cannot be driven from a test JVM (it needs a code-signed binary and a human
 * fingerprint), so the hardware backend is exercised behind [DpopKeyProvider] — which is exactly what
 * the abstraction is for. What is pinned here is the decision-making that surrounds it, because that
 * is where a mistake would silently downgrade every installation's security or, worse, hang a CI job
 * on a prompt nobody can answer.
 */
class DpopKeyProviderTest {

    @BeforeEach
    @AfterEach
    fun reset() {
        Dpop.resetForTest()
        Tty.resetForTest()
        UserPresence.resetForTest()
        DpopKeyProviders.resetForTest()
    }

    /** A stand-in for a rung of the ladder, with a programmable [ProviderStatus]. */
    private class FakeProvider(
        override val keyClass: DpopKeyClass,
        private val status: ProviderStatus,
        private val key: DpopKey = DpopKey.generate(),
    ) : DpopKeyProvider {
        var loadedWithProvision: Boolean? = null
        var deleted = false
        override fun status(): ProviderStatus = status
        override fun load(provision: Boolean): DpopKey = key.also { loadedWithProvision = provision }
        override fun delete(): Boolean {
            deleted = true
            return true
        }
    }

    // ── selection: strongest usable rung wins ────────────────────────────────

    @Test
    fun `resolution prefers the secure element when it is ready`() {
        val secureElement = FakeProvider(DpopKeyClass.SECURE_ELEMENT, ProviderStatus.Ready)
        val software = FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)

        val resolution = DpopKeyProviders.resolve(listOf(secureElement, software, EphemeralDpopKeyProvider()))

        assertThat(resolution.keyClass).isEqualTo(DpopKeyClass.SECURE_ELEMENT)
        assertThat(resolution.key).isNotNull()
        assertThat(resolution.skipped).isEmpty()
    }

    @Test
    fun `a secure element that cannot yet hand over a key falls through rather than sending no proof`() {
        // The trap this pins: a Mac with an enclave but no key yet answers Provisionable, and a routine
        // (non-login) command has nothing to load. Committing to that rung on the STATUS answer alone
        // would send no proof at all — a silent regression on exactly the machines the feature helps.
        val secureElement = object : DpopKeyProvider {
            override val keyClass = DpopKeyClass.SECURE_ELEMENT
            override fun status() = ProviderStatus.Provisionable
            override fun load(provision: Boolean): DpopKey =
                if (provision) DpopKey.generate() else throw SecureElementException("no key yet", null)
            override fun delete() = false
        }
        val software = FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)

        val routine = DpopKeyProviders.resolve(listOf(secureElement, software), provision = false)
        val login = DpopKeyProviders.resolve(listOf(secureElement, software), provision = true)

        assertThat(routine.keyClass).isEqualTo(DpopKeyClass.SOFTWARE_KEYCHAIN)
        assertThat(routine.key).isNotNull()
        assertThat(routine.skipped).containsExactly(DpopKeyClass.SECURE_ELEMENT to "no key yet")
        // …and the login pass, which IS allowed to create, reaches the hardware rung.
        assertThat(login.keyClass).isEqualTo(DpopKeyClass.SECURE_ELEMENT)
    }

    @Test
    fun `a secure element the OS refuses to store falls back and records the reason verbatim`() {
        // The real macOS failure: the binary is not code-signed with a keychain-access-group
        // entitlement, so persisting the enclave key returns errSecMissingEntitlement. No cheap status
        // check can see that — it only surfaces on the attempt — so the fall-through has to happen on
        // the LOAD, and the reason has to reach the user unedited.
        val secureElement = object : DpopKeyProvider {
            override val keyClass = DpopKeyClass.SECURE_ELEMENT
            override fun status() = ProviderStatus.Provisionable
            override fun load(provision: Boolean): DpopKey =
                throw SecureElementException(SecureElementUnavailable.MISSING_ENTITLEMENT, -34018)
            override fun delete() = false
        }

        val resolution = DpopKeyProviders.resolve(
            listOf(secureElement, FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)),
            provision = true,
        )

        assertThat(resolution.keyClass).isEqualTo(DpopKeyClass.SOFTWARE_KEYCHAIN)
        assertThat(resolution.skipped.single().second)
            .contains(SecureElementUnavailable.MISSING_ENTITLEMENT)
            .contains("-34018")
    }

    @Test
    fun `resolution falls back to the software keychain and records why the secure element was skipped`() {
        val resolution = DpopKeyProviders.resolve(
            listOf(
                FakeProvider(
                    DpopKeyClass.SECURE_ELEMENT,
                    ProviderStatus.Unavailable(SecureElementUnavailable.MISSING_ENTITLEMENT),
                ),
                FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready),
            ),
        )

        assertThat(resolution.keyClass).isEqualTo(DpopKeyClass.SOFTWARE_KEYCHAIN)
        assertThat(resolution.skipped).containsExactly(
            DpopKeyClass.SECURE_ELEMENT to SecureElementUnavailable.MISSING_ENTITLEMENT,
        )
    }

    @Test
    fun `resolution ends with no key at all when nothing persistent is usable`() {
        val resolution = DpopKeyProviders.resolve(
            listOf(
                FakeProvider(DpopKeyClass.SECURE_ELEMENT, ProviderStatus.Unavailable("no enclave")),
                FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Unavailable("no keychain")),
                EphemeralDpopKeyProvider(),
            ),
        )

        assertThat(resolution.keyClass).isEqualTo(DpopKeyClass.EPHEMERAL)
        // The ephemeral rung is never loaded FROM — a key that dies with the process cannot honour a
        // `cnf.jkt` minted at login, so the honest answer is "no key", not "a key you cannot reuse".
        assertThat(resolution.key).isNull()
        assertThat(resolution.skipped).hasSize(3)
    }

    // ── the degrade rules ────────────────────────────────────────────────────

    @Test
    fun `a non-interactive invocation never selects the secure element`() {
        // The whole point: a CI runner cannot answer a fingerprint prompt, so the hardware rung must
        // refuse itself BEFORE any native call rather than hanging a pipeline on a dialog.
        Tty.override = false

        val status = SecureElementDpopKeyProvider(interactive = { Tty.interactive() }).status()

        assertThat(status).isEqualTo(ProviderStatus.Unavailable(SecureElementUnavailable.NON_INTERACTIVE))
    }

    @Test
    fun `CI=true makes the invocation non-interactive even with a terminal attached`() {
        Tty.override = null
        Tty.environment = { name -> if (name == "CI") "true" else null }

        assertThat(Tty.interactive()).isFalse()
    }

    @Test
    fun `THORYN_NON_INTERACTIVE makes the invocation non-interactive`() {
        Tty.override = null
        Tty.environment = { name -> if (name == Tty.NON_INTERACTIVE_ENV_VAR) "1" else null }

        assertThat(Tty.interactive()).isFalse()
    }

    @Test
    fun `an ephemeral key mints no proof at all, degrading to the pre-DPoP wire shape`() {
        // A key that dies with the process cannot honour a `cnf.jkt` minted at login on the NEXT
        // command, so binding a token to it is strictly worse than not binding. The CLI must send
        // nothing rather than something unprovable.
        val err = ByteArrayOutputStream()
        Dpop.ladder = { listOf(EphemeralDpopKeyProvider()) }

        val session = Dpop.session(PrintStream(err))

        assertThat(session).isNull()
        assertThat(err.toString()).contains("without a DPoP proof")
    }

    @Test
    fun `the key class is reported as null when no persistent key can be had`() {
        Dpop.ladder = { listOf(EphemeralDpopKeyProvider()) }

        assertThat(Dpop.keyClass()).isNull()
    }

    @Test
    fun `the reported class is the class of the key that will actually sign`() {
        // Reporting the ladder's OPINION rather than the loaded key would let `whoami` claim hardware
        // protection that is not in force — the exact misconception this feature exists to remove.
        val secureElement = object : DpopKeyProvider {
            override val keyClass = DpopKeyClass.SECURE_ELEMENT
            override fun status() = ProviderStatus.Provisionable
            override fun load(provision: Boolean): DpopKey = throw SecureElementException("not entitled", -34018)
            override fun delete() = false
        }
        Dpop.ladder = { listOf(secureElement, FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)) }

        assertThat(Dpop.keyClass()).isEqualTo(DpopKeyClass.SOFTWARE_KEYCHAIN)
    }

    // ── provisioning only on login ───────────────────────────────────────────

    @Test
    fun `a routine command loads without provisioning, so it can never create a hardware key`() {
        val provider = FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)
        Dpop.ladder = { listOf(provider) }

        Dpop.session()

        assertThat(provider.loadedWithProvision).isFalse()
    }

    @Test
    fun `the login path provisions`() {
        val provider = FakeProvider(DpopKeyClass.SECURE_ELEMENT, ProviderStatus.Provisionable)
        Dpop.ladder = { listOf(provider) }

        Dpop.session(provision = true)

        assertThat(provider.loadedWithProvision).isTrue()
    }

    @Test
    fun `an already-loaded session is not re-provisioned mid-command`() {
        // "Do not silently rotate mid-session": once a command is signing with a key, a later call in
        // the SAME process must keep that key — the live token is bound to its thumbprint.
        val provider = FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)
        Dpop.ladder = { listOf(provider) }

        val first = Dpop.session(provision = true)!!.thumbprint
        val second = Dpop.session()!!.thumbprint
        val third = Dpop.session(provision = true)!!.thumbprint

        assertThat(second).isEqualTo(first)
        assertThat(third).isEqualTo(first)
    }

    @Test
    fun `rotate deletes every rung, not only the selected one`() {
        // A migrated machine holds both a hardware and an older software key; `--rotate-key` after a
        // lost laptop has to leave nothing behind, whichever rung happens to be selected today.
        val secureElement = FakeProvider(DpopKeyClass.SECURE_ELEMENT, ProviderStatus.Ready)
        val software = FakeProvider(DpopKeyClass.SOFTWARE_KEYCHAIN, ProviderStatus.Ready)
        Dpop.ladder = { listOf(secureElement, software) }

        assertThat(Dpop.rotate()).isTrue()

        assertThat(secureElement.deleted).isTrue()
        assertThat(software.deleted).isTrue()
    }

    // ── presence cadence ─────────────────────────────────────────────────────

    @Test
    fun `presence is announced once per process, never per request`() {
        val err = ByteArrayOutputStream()
        withPresenceFile {
            repeat(5) { UserPresence.announceIfDue(PrintStream(err)) }
        }

        assertThat(err.toString().lines().filter { it.isNotBlank() }).hasSize(1)
    }

    @Test
    fun `presence is not re-announced inside the idle window`() {
        val err = ByteArrayOutputStream()
        withPresenceFile {
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000) }
            UserPresence.recordVerified()
            // Five minutes later — well inside the 15-minute default.
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000 + 300) }

            assertThat(UserPresence.withinIdleWindow()).isTrue()
            UserPresence.announceIfDue(PrintStream(err))
        }

        assertThat(err.toString()).isEmpty()
    }

    @Test
    fun `presence is announced again once the idle window has lapsed`() {
        val err = ByteArrayOutputStream()
        withPresenceFile {
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000) }
            UserPresence.recordVerified()
            // Sixteen minutes later — past the 15-minute default.
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000 + 16 * 60) }

            assertThat(UserPresence.withinIdleWindow()).isFalse()
            UserPresence.announceIfDue(PrintStream(err))
        }

        assertThat(err.toString()).contains("Confirm your presence")
    }

    @Test
    fun `the idle window is configurable and defaults to 15 minutes`() {
        UserPresence.environment = { null }
        assertThat(UserPresence.idleWindow().toMinutes()).isEqualTo(UserPresence.DEFAULT_IDLE_MINUTES)

        UserPresence.environment = { name -> if (name == UserPresence.IDLE_MINUTES_ENV_VAR) "45" else null }
        assertThat(UserPresence.idleWindow().toMinutes()).isEqualTo(45)
    }

    @Test
    fun `a malformed idle window falls back to the default instead of failing the command`() {
        UserPresence.environment = { name -> if (name == UserPresence.IDLE_MINUTES_ENV_VAR) "soon-ish" else null }

        assertThat(UserPresence.idleWindow().toMinutes()).isEqualTo(UserPresence.DEFAULT_IDLE_MINUTES)
    }

    @Test
    fun `a clock that moved backwards is not read as still-fresh presence`() {
        withPresenceFile {
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000) }
            UserPresence.recordVerified()
            // NTP step / VM restore: "now" is before the recorded stamp.
            UserPresence.clock = { Instant.ofEpochSecond(1_700_000_000 - 600) }

            assertThat(UserPresence.withinIdleWindow()).isFalse()
        }
    }

    /** Run [block] with the presence timestamp redirected into a scratch file. */
    private fun withPresenceFile(block: () -> Unit) {
        val file = Files.createTempFile("thoryn-presence", "").also { Files.delete(it) }
        val previous = UserPresence.environment
        UserPresence.environment = { name ->
            if (name == UserPresence.STATE_FILE_ENV_VAR) file.toString() else previous(name)
        }
        try {
            block()
        } finally {
            Files.deleteIfExists(file)
        }
    }
}
