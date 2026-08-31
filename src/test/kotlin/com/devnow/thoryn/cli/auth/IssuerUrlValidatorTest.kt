package com.devnow.thoryn.cli.auth

import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

/**
 * Unit tests for [IssuerUrlValidator] — SSO-1145.
 *
 * Covers the four acceptance cases and the two rejection cases described in
 * the pentest finding (http:// for non-loopback hosts in device-code flow).
 */
class IssuerUrlValidatorTest {

    @Test
    fun `https issuer for public host is allowed`() {
        assertThatCode { IssuerUrlValidator.validate("https://hub.thoryn.org", devMode = false) }
            .doesNotThrowAnyException()
    }

    @Test
    fun `http issuer for 127_0_0_1 is allowed`() {
        assertThatCode { IssuerUrlValidator.validate("http://127.0.0.1:8080", devMode = false) }
            .doesNotThrowAnyException()
    }

    @Test
    fun `http issuer for localhost is allowed`() {
        assertThatCode { IssuerUrlValidator.validate("http://localhost:54702", devMode = false) }
            .doesNotThrowAnyException()
    }

    @Test
    fun `http issuer for IPv6 loopback is allowed`() {
        assertThatCode { IssuerUrlValidator.validate("http://[::1]:8080", devMode = false) }
            .doesNotThrowAnyException()
    }

    @Test
    fun `http issuer for non-loopback host is rejected`() {
        assertThatThrownBy { IssuerUrlValidator.validate("http://evil.com", devMode = false) }
            .isInstanceOf(IssuerUrlValidationException::class.java)
            .hasMessageContaining("loopback")
    }

    @Test
    fun `http issuer for non-loopback host is allowed when devMode is true`() {
        // devMode bypasses the loopback guard; a WARN is printed to stderr but
        // no exception is thrown.
        assertThatCode { IssuerUrlValidator.validate("http://evil.com", devMode = true) }
            .doesNotThrowAnyException()
    }

    @Test
    fun `unsupported scheme is rejected`() {
        assertThatThrownBy { IssuerUrlValidator.validate("ftp://hub.thoryn.org", devMode = false) }
            .isInstanceOf(IssuerUrlValidationException::class.java)
            .hasMessageContaining("ftp")
    }

    @Test
    fun `issuer with trailing slash is normalised before parsing`() {
        // trimEnd('/') must happen before URI.create so the path doesn't confuse
        // the host extraction — this tests the defensive normalisation path.
        assertThatCode { IssuerUrlValidator.validate("https://hub.thoryn.org/", devMode = false) }
            .doesNotThrowAnyException()
    }
}
