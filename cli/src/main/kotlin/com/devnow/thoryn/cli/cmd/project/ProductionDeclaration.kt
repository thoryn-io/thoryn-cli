package com.devnow.thoryn.cli.cmd.project

import tools.jackson.core.JacksonException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-4079 — an application template's PRODUCTION connection, `.thoryn/production/declaration.json` (thoryn-io/thoryn-starters
 * SSO-4120). It has the shape of a `.thoryn/template.json` connection and its variables, and lives beside template.json on
 * purpose: every released CLI refuses an application template.json with a production connection ("exactly one
 * non-production connection"), and that rule stays — the production trust is not the creation flow's own connection, it is
 * the one the workspace's CONFIG project declares and owns (oauthy ADR 2026-10-25 decision 3).
 *
 * The contract, checked here before anything is created (anything else is a [StarterTemplateManifest.TemplateException]):
 *  - one connection, `production`: `production: true`, `clientIdVariable: THORYN_PRODUCTION_WIF_CLIENT_ID`, a `.thoryn/` YAML
 *    `provisionFile`, scopes EXACTLY the application ceiling ([SCOPES]) — and NO `grant` (the production trust is granted
 *    nothing: a creation slot a workspace admin approves lets it create its one client) and no `environmentVariable`;
 *  - exactly two variables, both on the same GitHub environment: [CLIENT_ID_VARIABLE] (the trust's `wi_` client) and
 *    [URL_VARIABLE] (where the app runs; the developer's value).
 */
data class ProductionDeclaration(
    val connection: String,
    val clientIdVariable: String,
    val provisionFile: String,
    val scopes: List<String>,
    /** The GitHub environment both variables live in, and the one the production trust pins (`production`). */
    val githubEnvironment: String,
) {
    companion object {
        const val PATH: String = ".thoryn/production/declaration.json"
        const val CONNECTION: String = "production"
        const val CLIENT_ID_VARIABLE: String = StarterTemplateManifest.THORYN_PRODUCTION_WIF_CLIENT_ID
        const val URL_VARIABLE: String = "THORYN_PRODUCTION_URL"

        /** The application ceiling of oauthy ADR 2026-10-25: what an application's production identity may hold — nothing more. */
        val SCOPES: List<String> = listOf("tenant:applications.read", "tenant:applications.write", "tenant:access.read")

        private val TOP_LEVEL = setOf("\$schema", "description", "variables", "connections")
        private val VARIABLE_KEYS = setOf("level", "environment", "description")
        private val CONNECTION_KEYS = setOf("description", "production", "clientIdVariable", "provisionFile", "scopes")
        private val PROVISION_FILE = Regex("^\\.thoryn/[A-Za-z0-9._/-]+\\.ya?ml$")
        private val json: JsonMapper = JsonMapper.builder().build()

        /** Parses and validates [raw]; throws [StarterTemplateManifest.TemplateException] naming what breaks the contract. */
        fun parse(raw: String): ProductionDeclaration {
            fun fail(message: String): Nothing = throw StarterTemplateManifest.TemplateException("$PATH: $message")
            if (raw.toByteArray().size > StarterTemplateManifest.MAX_BYTES) fail("larger than ${StarterTemplateManifest.MAX_BYTES} bytes")
            val root: JsonNode = try {
                json.readTree(raw)
            } catch (ex: JacksonException) {
                fail("not JSON")
            }
            if (!root.isObject) fail("not a JSON object")
            root.propertyNames().firstOrNull { it !in TOP_LEVEL }?.let { fail("unknown property '$it'") }

            val variables = root.path("variables")
            if (!variables.isObject) fail("'variables' must be an object")
            val names = variables.propertyNames().toSet()
            if (names != setOf(CLIENT_ID_VARIABLE, URL_VARIABLE)) fail("the variables must be exactly $CLIENT_ID_VARIABLE and $URL_VARIABLE — found ${names.sorted()}")
            val environments = names.map { name ->
                val v = variables.path(name)
                if (!v.isObject) fail("variables.$name must be an object")
                v.propertyNames().firstOrNull { it !in VARIABLE_KEYS }?.let { fail("variables.$name has an unknown property '$it'") }
                if (v.path("level").asString("") != StarterTemplateManifest.LEVEL_ENVIRONMENT) fail("variables.$name must be environment-level")
                val env = v.path("environment")
                if (!env.isString || !StarterTemplateManifest.GITHUB_ENVIRONMENT.matches(env.asString())) fail("variables.$name.environment must name a GitHub environment")
                env.asString()
            }.toSet()
            val githubEnvironment = environments.singleOrNull() ?: fail("both variables must live in the same GitHub environment — found ${environments.sorted()}")

            val connections = root.path("connections")
            if (!connections.isObject || connections.propertyNames().toList() != listOf(CONNECTION)) {
                fail("'connections' must declare exactly one connection, '$CONNECTION'")
            }
            val c = connections.path(CONNECTION)
            if (!c.isObject) fail("connections.$CONNECTION must be an object")
            if (c.has("grant")) fail("connections.$CONNECTION declares a grant; the production trust is granted nothing (a creation slot covers its one client)")
            if (c.has("environmentVariable")) fail("connections.$CONNECTION names no sandbox (environmentVariable): production is the workspace's own plane")
            c.propertyNames().firstOrNull { it !in CONNECTION_KEYS }?.let { fail("connections.$CONNECTION has an unknown property '$it'") }
            if (!c.path("production").isBoolean || !c.path("production").asBoolean()) fail("connections.$CONNECTION must say production: true")
            val clientIdVariable = c.path("clientIdVariable").asString("")
            if (clientIdVariable != CLIENT_ID_VARIABLE) fail("connections.$CONNECTION.clientIdVariable must be $CLIENT_ID_VARIABLE")
            val provisionFile = c.path("provisionFile").asString("")
            if (!PROVISION_FILE.matches(provisionFile) || ".." in provisionFile) fail("connections.$CONNECTION.provisionFile is not a .thoryn YAML file")
            val scopesNode = c.path("scopes")
            if (!scopesNode.isArray) fail("connections.$CONNECTION.scopes must be a list")
            val scopes = scopesNode.toList().map { if (it.isString) it.asString() else fail("connections.$CONNECTION.scopes holds a non-string") }
            if (scopes.size != SCOPES.size || scopes.toSet() != SCOPES.toSet()) {
                fail("connections.$CONNECTION.scopes must be exactly ${SCOPES.joinToString(", ")} (the application ceiling) — found ${scopes.joinToString(", ").ifEmpty { "none" }}")
            }
            return ProductionDeclaration(CONNECTION, clientIdVariable, provisionFile, scopes, githubEnvironment)
        }
    }
}
