package com.devnow.thoryn.cli.cmd.operator

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** SSO-3356 — operator calls go only to a private address of the hub (`/admin` is on no public host). */
class OperatorHubTargetTest {

    @Test
    fun `the port-forward and in-cluster Service addresses are accepted`() {
        for (url in listOf(
            "http://localhost:18080",
            "http://127.0.0.1:18080",
            "http://[::1]:18080",
            "http://thoryn-hub:8080",
            "http://thoryn-hub.thoryn.svc.cluster.local:8080",
        )) {
            assertThat(OperatorHubTarget.refusal(url)).describedAs(url).isNull()
        }
    }

    @Test
    fun `public hosts, private-range IPs, paths and non-http schemes are refused`() {
        for (url in listOf(
            "https://hub.stg.thoryn.org",
            "https://thoryn.auth.stg.thoryn.org",
            "https://auth.acme.com",
            "http://10.0.0.5:8080",
            "http://localhost:18080/admin",
            "ftp://localhost",
            "not a url",
        )) {
            assertThat(OperatorHubTarget.refusal(url)).describedAs(url).isNotNull()
        }
    }
}
