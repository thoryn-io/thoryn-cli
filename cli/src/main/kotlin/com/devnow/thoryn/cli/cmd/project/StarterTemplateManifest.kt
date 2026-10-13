package com.devnow.thoryn.cli.cmd.project

import tools.jackson.core.JacksonException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-3435 — a starter template's declaration, `.thoryn/template.json`, schema `thoryn.io/starter-template/v2`
 * (published by thoryn-io/thoryn-starters as `schemas/template.schema.json`, SSO-3428).
 *
 * The SAME contract, and the same defensive checks, as oauthy's starter orchestrator
 * (`servers/starter-orchestrator/…/template/StarterTemplateManifest.kt`, SSO-3310): a CLI-created project and
 * an App-created project are set up from one declaration, so both paths must accept and refuse the same
 * templates. It names (a) the Actions variables to set and the level each lives at, and (b) one entry per
 * CONNECTION — one workload identity trust — with its exact scopes, whether it is the production connection,
 * the variables carrying its client id and sandbox slug, and the access grant its client needs.
 *
 * Anything outside the contract is a [TemplateException], raised before anything is created.
 */
data class StarterTemplateManifest(
    val kind: String,
    /** The GitHub environment the production connection pins (config templates). */
    val productionGithubEnvironment: String?,
    val variables: Map<String, Variable>,
    /** Keyed by connection name, in declaration order. */
    val connections: Map<String, Connection>,
) {
    data class Variable(val level: String, val environment: String?)

    data class Grant(val relation: String, val on: String)

    data class Connection(
        val production: Boolean,
        val clientIdVariable: String,
        val environmentVariable: String?,
        val provisionFile: String,
        val scopes: List<String>,
        val grant: Grant,
    )

    class TemplateException(message: String) : RuntimeException(message)

    /** The one non-production connection. */
    val sandboxConnection: Pair<String, Connection> get() = connections.entries.single { !it.value.production }.toPair()

    /** The production connection (config templates), or null. */
    val productionConnection: Pair<String, Connection>? get() = connections.entries.singleOrNull { it.value.production }?.toPair()

    companion object {
        const val PATH: String = ".thoryn/template.json"
        const val API_VERSION: String = "thoryn.io/starter-template/v2"
        const val KIND_APPLICATION: String = "application"
        const val KIND_CONFIG: String = "config"
        const val LEVEL_REPOSITORY: String = "repository"
        const val LEVEL_ENVIRONMENT: String = "environment"
        const val GRANT_ON_ENVIRONMENT: String = "environment"
        const val GRANT_ON_WORKSPACE: String = "workspace"

        const val THORYN_ISSUER: String = "THORYN_ISSUER"
        const val THORYN_WORKSPACE: String = "THORYN_WORKSPACE"
        const val THORYN_ENVIRONMENT: String = "THORYN_ENVIRONMENT"
        const val THORYN_WIF_CLIENT_ID: String = "THORYN_WIF_CLIENT_ID"
        const val THORYN_SANDBOX_ENVIRONMENT: String = "THORYN_SANDBOX_ENVIRONMENT"
        const val THORYN_SANDBOX_WIF_CLIENT_ID: String = "THORYN_SANDBOX_WIF_CLIENT_ID"
        const val THORYN_PRODUCTION_WIF_CLIENT_ID: String = "THORYN_PRODUCTION_WIF_CLIENT_ID"

        /** Application template: all repository-level. */
        val APPLICATION_VARIABLES: Map<String, String> = linkedMapOf(
            THORYN_ISSUER to LEVEL_REPOSITORY,
            THORYN_WORKSPACE to LEVEL_REPOSITORY,
            THORYN_ENVIRONMENT to LEVEL_REPOSITORY,
            THORYN_WIF_CLIENT_ID to LEVEL_REPOSITORY,
        )

        /** Config template: four repository-level, the production client id on the production GitHub environment. */
        val CONFIG_VARIABLES: Map<String, String> = linkedMapOf(
            THORYN_ISSUER to LEVEL_REPOSITORY,
            THORYN_WORKSPACE to LEVEL_REPOSITORY,
            THORYN_SANDBOX_ENVIRONMENT to LEVEL_REPOSITORY,
            THORYN_SANDBOX_WIF_CLIENT_ID to LEVEL_REPOSITORY,
            THORYN_PRODUCTION_WIF_CLIENT_ID to LEVEL_ENVIRONMENT,
        )

        const val MAX_BYTES: Int = 64 * 1024
        private const val MAX_SCOPES = 32

        private val TOP_LEVEL = setOf("apiVersion", "kind", "description", "github", "variables", "connections")
        private val VARIABLE_KEYS = setOf("level", "environment", "description")
        private val CONNECTION_KEYS = setOf("description", "production", "clientIdVariable", "environmentVariable", "provisionFile", "scopes", "grant")
        private val GRANT_KEYS = setOf("relation", "on")

        private val VARIABLE_NAME = Regex("^THORYN_[A-Z0-9_]+$")
        private val CONNECTION_NAME = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
        private val SCOPE = Regex("^tenant:[a-z-]+\\.[a-z-]+$")
        private val PROVISION_FILE = Regex("^\\.thoryn/[A-Za-z0-9._/-]+\\.ya?ml$")

        /** A GitHub environment name. */
        val GITHUB_ENVIRONMENT: Regex = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

        private val json: JsonMapper = JsonMapper.builder().build()

        /** The `apiVersion` [raw] declares, or null when it cannot be read — for a precise "not v2" message. */
        fun apiVersionOf(raw: String): String? = runCatching { json.readTree(raw).path("apiVersion").takeIf { it.isString }?.asString() }.getOrNull()

        /** Parses and validates [raw] as the declaration of a [expectedKind] template. */
        fun parse(raw: String, expectedKind: String): StarterTemplateManifest {
            if (raw.toByteArray().size > MAX_BYTES) throw TemplateException("the declaration is larger than $MAX_BYTES bytes")
            val root: JsonNode = try {
                json.readTree(raw)
            } catch (ex: JacksonException) {
                throw TemplateException("the declaration is not JSON")
            }
            if (!root.isObject) throw TemplateException("the declaration is not a JSON object")
            val apiVersion = string(root, "apiVersion", "apiVersion")
            if (apiVersion != API_VERSION) throw TemplateException("unsupported apiVersion '$apiVersion' (expected $API_VERSION)")
            onlyKeys(root, TOP_LEVEL, "the declaration")
            val kind = string(root, "kind", "kind")
            if (kind != expectedKind) throw TemplateException("the template's kind is '$kind', expected '$expectedKind'")
            nonEmptyString(root, "description", "description")

            val githubNode = root.path("github")
            val productionEnvironment = if (githubNode.isMissingNode) {
                null
            } else {
                if (!githubNode.isObject) throw TemplateException("'github' must be an object")
                onlyKeys(githubNode, setOf("productionEnvironment"), "github")
                githubNode.path("productionEnvironment").takeIf { !it.isMissingNode }?.let {
                    if (!it.isString || !GITHUB_ENVIRONMENT.matches(it.asString())) {
                        throw TemplateException("github.productionEnvironment must name a GitHub environment")
                    }
                    it.asString()
                }
            }
            if (kind == KIND_CONFIG && productionEnvironment == null) throw TemplateException("a config template needs github.productionEnvironment")

            val variables = variables(root.path("variables"))
            val connections = connections(root.path("connections"))

            val production = connections.values.count { it.production }
            val nonProduction = connections.values.count { !it.production }
            if (kind == KIND_APPLICATION && (production != 0 || nonProduction != 1)) {
                throw TemplateException("an application template must declare exactly one non-production connection")
            }
            if (kind == KIND_CONFIG && (production != 1 || nonProduction != 1)) {
                throw TemplateException("a config template must declare exactly one production and one non-production connection")
            }
            variables.forEach { (name, v) ->
                if (v.level == LEVEL_ENVIRONMENT && v.environment != productionEnvironment) {
                    throw TemplateException("variable $name lives in GitHub environment '${v.environment}', which is not github.productionEnvironment")
                }
            }

            val supplied = mutableSetOf(THORYN_ISSUER, THORYN_WORKSPACE)
            connections.forEach { (name, c) ->
                if (c.clientIdVariable !in variables) throw TemplateException("connections.$name.clientIdVariable is not a declared variable")
                supplied += c.clientIdVariable
                c.environmentVariable?.let {
                    if (it !in variables) throw TemplateException("connections.$name.environmentVariable is not a declared variable")
                    supplied += it
                }
                if (c.production && variables.getValue(c.clientIdVariable).level != LEVEL_ENVIRONMENT) {
                    throw TemplateException("the production connection's client id must be an environment-level variable")
                }
            }
            variables.keys.firstOrNull { it !in supplied }?.let { throw TemplateException("variable $it has no value the creation flow can supply") }
            val contract = if (kind == KIND_CONFIG) CONFIG_VARIABLES else APPLICATION_VARIABLES
            if (variables.mapValues { it.value.level } != contract) {
                throw TemplateException("the declared variables must be exactly ${contract.entries.joinToString()} — found ${variables.mapValues { it.value.level }}")
            }
            return StarterTemplateManifest(kind, productionEnvironment, variables, connections)
        }

        private fun variables(node: JsonNode): Map<String, Variable> {
            if (!node.isObject || node.isEmpty) throw TemplateException("'variables' must be a non-empty object")
            val out = LinkedHashMap<String, Variable>()
            node.propertyNames().forEach { name ->
                if (!VARIABLE_NAME.matches(name)) throw TemplateException("variable name '$name' is not THORYN_…")
                val v = node.path(name)
                if (!v.isObject) throw TemplateException("variables.$name must be an object")
                onlyKeys(v, VARIABLE_KEYS, "variables.$name")
                nonEmptyString(v, "description", "variables.$name.description")
                val level = string(v, "level", "variables.$name.level")
                val environmentNode = v.path("environment")
                val environment = when (level) {
                    LEVEL_REPOSITORY -> {
                        if (!environmentNode.isMissingNode) throw TemplateException("variables.$name is repository-level and names no environment")
                        null
                    }
                    LEVEL_ENVIRONMENT -> {
                        if (!environmentNode.isString || !GITHUB_ENVIRONMENT.matches(environmentNode.asString())) {
                            throw TemplateException("variables.$name.environment must name a GitHub environment")
                        }
                        environmentNode.asString()
                    }
                    else -> throw TemplateException("variables.$name.level must be 'repository' or 'environment'")
                }
                out[name] = Variable(level, environment)
            }
            return out
        }

        private fun connections(node: JsonNode): Map<String, Connection> {
            if (!node.isObject || node.isEmpty) throw TemplateException("'connections' must be a non-empty object")
            val out = LinkedHashMap<String, Connection>()
            node.propertyNames().forEach { name ->
                if (!CONNECTION_NAME.matches(name)) throw TemplateException("connection name '$name' is not a slug")
                val c = node.path(name)
                if (!c.isObject) throw TemplateException("connections.$name must be an object")
                onlyKeys(c, CONNECTION_KEYS, "connections.$name")
                nonEmptyString(c, "description", "connections.$name.description")
                val productionNode = c.path("production")
                if (!productionNode.isBoolean) throw TemplateException("connections.$name.production must be a boolean")
                val production = productionNode.asBoolean()
                val clientIdVariable = string(c, "clientIdVariable", "connections.$name.clientIdVariable")
                if (!VARIABLE_NAME.matches(clientIdVariable)) throw TemplateException("connections.$name.clientIdVariable is not THORYN_…")
                val environmentVariable = c.path("environmentVariable").takeIf { !it.isMissingNode }?.let {
                    if (!it.isString || !VARIABLE_NAME.matches(it.asString())) throw TemplateException("connections.$name.environmentVariable is not THORYN_…")
                    it.asString()
                }
                if (production && environmentVariable != null) throw TemplateException("the production connection names no sandbox environment variable")
                if (!production && environmentVariable == null) throw TemplateException("connections.$name needs an environmentVariable")
                val provisionFile = string(c, "provisionFile", "connections.$name.provisionFile")
                if (!PROVISION_FILE.matches(provisionFile) || ".." in provisionFile) throw TemplateException("connections.$name.provisionFile is not a .thoryn YAML file")
                val scopesNode = c.path("scopes")
                if (!scopesNode.isArray || scopesNode.size() == 0 || scopesNode.size() > MAX_SCOPES) {
                    throw TemplateException("connections.$name.scopes must list 1-$MAX_SCOPES scopes")
                }
                val scopes = (0 until scopesNode.size()).map { i ->
                    val s = scopesNode.get(i)
                    if (!s.isString || !SCOPE.matches(s.asString())) throw TemplateException("connections.$name.scopes[$i] is not a workspace scope")
                    s.asString()
                }
                if (scopes.distinct().size != scopes.size) throw TemplateException("connections.$name.scopes has duplicates")
                val grantNode = c.path("grant")
                if (!grantNode.isObject) throw TemplateException("connections.$name.grant must be an object")
                onlyKeys(grantNode, GRANT_KEYS, "connections.$name.grant")
                val relation = string(grantNode, "relation", "connections.$name.grant.relation")
                if (relation != "manager" && relation != "viewer") throw TemplateException("connections.$name.grant.relation must be manager or viewer")
                val on = string(grantNode, "on", "connections.$name.grant.on")
                if (on != GRANT_ON_ENVIRONMENT && on != GRANT_ON_WORKSPACE) throw TemplateException("connections.$name.grant.on must be environment or workspace")
                if (!production && on != GRANT_ON_ENVIRONMENT) throw TemplateException("a non-production connection's grant is on its environment")
                out[name] = Connection(production, clientIdVariable, environmentVariable, provisionFile, scopes, Grant(relation, on))
            }
            return out
        }

        private fun onlyKeys(node: JsonNode, allowed: Set<String>, where: String) {
            node.propertyNames().firstOrNull { it !in allowed }?.let { throw TemplateException("$where has an unknown property '$it'") }
        }

        private fun string(node: JsonNode, field: String, where: String): String {
            val n = node.path(field)
            if (!n.isString) throw TemplateException("$where must be a string")
            return n.asString()
        }

        private fun nonEmptyString(node: JsonNode, field: String, where: String) {
            if (string(node, field, where).isBlank()) throw TemplateException("$where must not be empty")
        }
    }
}
