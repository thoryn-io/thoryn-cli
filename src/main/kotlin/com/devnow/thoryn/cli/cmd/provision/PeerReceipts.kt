package com.devnow.thoryn.cli.cmd.provision

import tools.jackson.module.kotlin.jacksonObjectMapper
import tools.jackson.module.kotlin.readValue
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * SSO-3659 (ADR 2026-10-13 §1, "one owning repository per resource") — loads the committed receipts of
 * OTHER repositories so `plan` / `apply` / `import` can refuse to converge a resource one of them already
 * owns. A locator is a local path (a sibling checkout, a monorepo) or an `https://` URL (a raw file on the
 * forge); anything else is refused. The CLI-side half of the guard: the engine only ever sees the parsed
 * [ProvisionReceipt]s. The hub's client row carries no owner tag, so the guard knows exactly the receipts
 * it is handed and no others — a repository nobody names is not checked against.
 */
internal object PeerReceipts {

    private val mapper = jacksonObjectMapper()
    private val http: HttpClient by lazy { HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build() }

    /** Parse every locator; a receipt that cannot be read or parsed is a [ProvisionException] (fail closed, never silently fewer peers). */
    fun load(locators: List<String>): List<ProvisionReceipt> = locators.map { load(it.trim()) }

    fun load(locator: String): ProvisionReceipt {
        if (locator.isBlank()) throw ProvisionException("--peer-receipt must name a path or an https:// URL")
        val bytes = when {
            locator.startsWith("https://", ignoreCase = true) -> fetch(locator)
            locator.contains("://") -> throw ProvisionException("--peer-receipt '$locator': only a local path or an https:// URL is accepted")
            else -> {
                val f = File(locator)
                if (!f.isFile) throw ProvisionException("--peer-receipt '$locator': no such file")
                f.readBytes()
            }
        }
        return try {
            mapper.readValue<ProvisionReceipt>(bytes)
        } catch (e: Exception) {
            throw ProvisionException("--peer-receipt '$locator' is not a provisioning receipt: ${e.message}")
        }
    }

    private fun fetch(url: String): ByteArray {
        val request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).GET().build()
        val response = try {
            http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        } catch (e: Exception) {
            throw ProvisionException("--peer-receipt '$url' could not be fetched: ${e.message}")
        }
        if (response.statusCode() !in 200..299) throw ProvisionException("--peer-receipt '$url' answered HTTP ${response.statusCode()}")
        return response.body()
    }
}
