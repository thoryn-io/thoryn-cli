package com.devnow.thoryn.cli.cmd.examples.recipe

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.yaml.YAMLMapper

/**
 * SSO-2873 — drift guard: the shipped `recipe.json` (what the CLI runtime reads — no YAML parser in
 * the native image) MUST equal the authored `recipe.yaml` (the source of truth). Regenerate with
 * `python3 -c "import yaml,json; print(json.dumps(yaml.safe_load(open('…/recipe.yaml')),indent=2))" > …/recipe.json`.
 */
class RecipeJsonDriftTest {

    private fun resource(path: String): String =
        javaClass.getResourceAsStream(path)?.readBytes()?.toString(Charsets.UTF_8)
            ?: error("missing resource $path")

    @Test
    fun `simple-signin recipe json matches recipe yaml`() {
        assertJsonMatchesYaml("simple-signin")
    }

    /** SSO-2944 — the workspace-less `ci-signin` recipe follows the same authored-YAML / shipped-JSON drift guard. */
    @Test
    fun `ci-signin recipe json matches recipe yaml`() {
        assertJsonMatchesYaml("ci-signin")
    }

    /** SSO-2950 — the founder-run `provision-ci-identity` bootstrap recipe follows the same drift guard. */
    @Test
    fun `provision-ci-identity recipe json matches recipe yaml`() {
        assertJsonMatchesYaml("provision-ci-identity")
    }

    private fun assertJsonMatchesYaml(id: String) {
        val yaml = YAMLMapper().readTree(resource("/examples/recipes/$id/recipe.yaml"))
        val json = JsonMapper.builder().build().readTree(resource("/examples/recipes/$id/recipe.json"))
        assertThat(json).isEqualTo(yaml)
    }
}
