package com.devnow.thoryn.cli.cmd.examples.recipe

import com.devnow.thoryn.cli.auth.Tokens
import com.devnow.thoryn.cli.cmd.CommandTestBase
import com.devnow.thoryn.cli.cmd.examples.ExampleContext
import com.devnow.thoryn.cli.cmd.examples.ExampleState
import com.devnow.thoryn.cli.cmd.examples.ExampleStateStore
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper

/**
 * SSO-2873 — the recipe interpreter applies `simple-signin` end-to-end against the REAL product-API
 * wire shape (a MockWebServer standing in for the hub + gateway), and tears it down. Proves the
 * declarative recipe drives the same calls the compiled example made: create workspace → register
 * tenant → create the app under the workspace (with the provisioning token) → verify it is active.
 */
class RecipeInterpreterTest : CommandTestBase() {

    private fun context(): ExampleContext {
        val base = Tokens(accessToken = "AT-test", refreshToken = "RT", issuer = baseUrl(), gateway = baseUrl())
        seedTokens(base)
        return ExampleContext(
            hub = baseUrl(),
            gateway = baseUrl(),
            tokens = base,
            state = ExampleStateStore(dir = tempHome.resolve("examples-state")),
        )
    }

    @Test
    fun `applies simple-signin end to end via the real product APIs`() {
        val ctx = context()
        // 1) createWorkspace → returns a provisioning token (so no token-exchange on the tenant calls)
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        // 2) registerTenant (best-effort)
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        // 3) applications.create (under the workspace)
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
        // 4) SSO-2908 — identity.registerUser → POST /api/v1/users (a verified, sign-in-able user)
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","emailVerified":true,"status":"ACTIVE"}"""))
        // 5) verify applications.get
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))
        // 6) SSO-2878 — best-effort platform attestation of the receipt.
        server.enqueue(jsonResponse(200, """{"kid":"receipt-attestation-t-1-local-v1","signature":"h..s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup()
        val state = run.state

        assertThat(state.example).isEqualTo("simple-signin")
        assertThat(state.tenantId).isEqualTo("t-1")
        assertThat(state.clientId).isEqualTo("app-9")
        assertThat(state.workspaceSlug).startsWith("ex-signin-")

        // SSO-2875 — the run produced a receipt recording exactly what was provisioned.
        val receipt = run.receipt
        assertThat(receipt.recipe.id).isEqualTo("simple-signin")
        assertThat(receipt.recipe.digest).startsWith("sha256:")
        assertThat(receipt.workspace.tenantId).isEqualTo("t-1")
        assertThat(receipt.resources).anyMatch { it.kind == "application" && it.id == "app-9" }
        // SSO-2908 — the provisioned sign-in-able user is recorded on the receipt too.
        assertThat(receipt.resources).anyMatch { it.kind == "user" && it.id == "usr-7" }
        assertThat(receipt.verify).anyMatch { it.assert == "applications.get" && it.passed }
        // SSO-2878 — the platform-signed attestation was folded into the receipt.
        assertThat(receipt.attestation).isNotNull
        assertThat(receipt.attestation!!.kid).isEqualTo("receipt-attestation-t-1-local-v1")

        // SSO-2897 — the run recorded the post-logout redirect URI on the application resource.
        assertThat(receipt.resources)
            .anyMatch { it.kind == "application" && it.attributes["postLogoutRedirectUri"] == "http://127.0.0.1/" }

        assertThat(server.takeRequest().path).isEqualTo("/account/workspace")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/tenants")
        val appReq = server.takeRequest()
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        assertThat(appReq.method).isEqualTo("POST")
        // The app is created UNDER the workspace, authenticated with the provisioning token.
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        // SSO-2897 — the recipe's postLogoutRedirectUris is forwarded verbatim to product-api's
        // create-application request (which persists it on the hub RegisteredClient for RP-Initiated Logout).
        assertThat(appReq.body.readUtf8())
            .contains("\"postLogoutRedirectUris\"")
            .contains("http://127.0.0.1/")
        // SSO-2908 — the registerUser step posts the CreateUserRequest to product-api, under the workspace.
        val userReq = server.takeRequest()
        assertThat(userReq.method).isEqualTo("POST")
        assertThat(userReq.path).isEqualTo("/api/v1/users")
        assertThat(userReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        assertThat(userReq.body.readUtf8())
            .contains("\"email\":\"ex-signin-")
            .contains("\"password\":\"Example-Signin-Pw1!\"")
            .contains("\"emailVerified\":true")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-9")
    }

    @Test
    fun `identity registerUser provisions a user via product-api and records it on the receipt`() {
        val ctx = context()
        val recipeJson = """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "register-user-test",
              "version": "1.0.0",
              "summary": "provision a sign-in-able user",
              "steps": [
                { "id": "ws", "action": "hub.createWorkspace",
                  "with": { "slug": "ex-signin-{{generate.slug8}}", "displayName": "T" } },
                { "id": "user", "action": "identity.registerUser",
                  "with": { "email": "[email protected]", "password": "S3cret-pw", "emailVerified": true } }
              ]
            }
        """.trimIndent()
        val recipe = Recipe(JsonMapper.builder().build().readTree(recipeJson))

        // 1) createWorkspace → provisioning token (so the create-user call skips token-exchange)
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        // 2) identity.registerUser → POST /api/v1/users returns the created UserResponse
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","emailVerified":true,"status":"ACTIVE"}"""))
        // 3) best-effort platform attestation of the receipt
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(ctx, recipe, trustPropagationBudgetMs = 2_000).setup()

        // The user is recorded on the receipt (parity with the app/workspace capture).
        assertThat(run.receipt.resources)
            .anyMatch { it.kind == "user" && it.id == "usr-7" && it.attributes["email"] == "[email protected]" }

        server.takeRequest() // createWorkspace
        val userReq = server.takeRequest()
        assertThat(userReq.method).isEqualTo("POST")
        assertThat(userReq.path).isEqualTo("/api/v1/users")
        // Created UNDER the workspace, authenticated with the provisioning token.
        assertThat(userReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        // The recipe's `with` map is forwarded verbatim: a password (sign-in-able) + verified email.
        val body = userReq.body.readUtf8()
        assertThat(body)
            .contains("\"email\":\"[email protected]\"")
            .contains("\"password\":\"S3cret-pw\"")
            .contains("\"emailVerified\":true")
    }

    @Test
    fun `tenant configureEmailProvider PUTs the merge-upsert body and records a password-free receipt`() {
        val ctx = context()
        val recipeJson = """
            {
              "apiVersion": "thoryn.io/examples/v1",
              "id": "configure-email-test",
              "version": "1.0.0",
              "summary": "configure a BYO-SMTP provider",
              "params": [
                { "name": "smtpPassword", "prompt": "SMTP password", "default": "s3cr3t-smtp", "secret": true }
              ],
              "steps": [
                { "id": "ws", "action": "hub.createWorkspace",
                  "with": { "slug": "ex-signin-{{generate.slug8}}", "displayName": "T" } },
                { "id": "email", "action": "tenant.configureEmailProvider",
                  "with": { "enabled": true, "smtpHost": "smtp.example.com", "smtpPort": 587,
                            "smtpUsername": "mailer", "smtpPassword": "{{smtpPassword}}",
                            "transportSecurity": "starttls", "fromAddress": "[email protected]" } }
              ]
            }
        """.trimIndent()
        val recipe = Recipe(JsonMapper.builder().build().readTree(recipeJson))

        // 1) createWorkspace → provisioning token (so the email-provider call skips token-exchange)
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        // 2) tenant.configureEmailProvider → PUT /api/v1/email-provider returns the saved state (never a password)
        server.enqueue(
            jsonResponse(
                200,
                """{"providerType":"byo_smtp","enabled":true,"configured":true,"smtpHost":"smtp.example.com",
                    "smtpPort":587,"smtpUsername":"mailer","hasPassword":true,"transportSecurity":"starttls",
                    "fromAddress":"[email protected]","fromName":null,"replyTo":null,
                    "supportedProviderTypes":["byo_smtp"],"supportedTransportSecurity":["none","starttls","tls"],
                    "configVersion":1,"updatedAt":"2026-09-01T10:00:00Z"}""".trimIndent(),
            ),
        )
        // 3) best-effort platform attestation of the receipt
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(ctx, recipe, trustPropagationBudgetMs = 2_000).setup()

        // The provider is recorded on the receipt — the non-secret shape only, NEVER the password.
        val providerRef = run.receipt.resources.firstOrNull { it.kind == "emailProvider" }
        assertThat(providerRef).isNotNull
        assertThat(providerRef!!.id).isEqualTo("byo_smtp")
        assertThat(providerRef.attributes["configVersion"]).isEqualTo("1")
        assertThat(providerRef.attributes["smtpHost"]).isEqualTo("smtp.example.com")
        assertThat(providerRef.attributes).doesNotContainKey("smtpPassword")

        server.takeRequest() // createWorkspace
        val emailReq = server.takeRequest()
        assertThat(emailReq.method).isEqualTo("PUT")
        assertThat(emailReq.path).isEqualTo("/api/v1/email-provider")
        // Created UNDER the workspace, authenticated with the provisioning token.
        assertThat(emailReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        // The recipe's `with` map is forwarded verbatim, with the {{smtpPassword}} param resolved.
        val body = emailReq.body.readUtf8()
        assertThat(body)
            .contains("\"smtpHost\":\"smtp.example.com\"")
            .contains("\"enabled\":true")
            .contains("\"smtpPassword\":\"s3cr3t-smtp\"")
    }

    @Test
    fun `simple-signin configure-email-provider PUTs a typed BYO-SMTP body when smtp params are set`() {
        val ctx = context()
        // The example-e2e passes real SMTP params via --set; here as interpreter overrides.
        val overrides = mapOf(
            "smtpHost" to "smtp.sink.local",
            "smtpPort" to "1025",
            "smtpUsername" to "mailer",
            "smtpPassword" to "sink-pw",
            "smtpTransport" to "none",
            "smtpAllowInsecure" to "true",
            "smtpFromAddress" to "[email protected]",
        )
        // ws → tenant → app → user → email PUT → verify GET → attest
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","status":"ACTIVE"}"""))
        server.enqueue(
            jsonResponse(
                200,
                """{"providerType":"byo_smtp","enabled":true,"configured":true,"smtpHost":"smtp.sink.local",
                    "smtpPort":1025,"smtpUsername":"mailer","hasPassword":true,"transportSecurity":"none",
                    "insecureTransportAcknowledged":true,"fromAddress":"[email protected]","fromName":null,"replyTo":null,
                    "supportedProviderTypes":["byo_smtp"],"supportedTransportSecurity":["none","starttls","tls"],
                    "configVersion":1,"updatedAt":"2026-09-01T10:00:00Z"}""".trimIndent(),
            ),
        )
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(
            ctx, Recipe.load("simple-signin"), overrides = overrides, trustPropagationBudgetMs = 2_000,
        ).setup()

        // The provider is recorded on the receipt — the non-secret shape only, NEVER the password.
        val providerRef = run.receipt.resources.firstOrNull { it.kind == "emailProvider" }
        assertThat(providerRef).isNotNull
        assertThat(providerRef!!.id).isEqualTo("byo_smtp")
        assertThat(providerRef.attributes["smtpHost"]).isEqualTo("smtp.sink.local")
        assertThat(providerRef.attributes).doesNotContainKey("smtpPassword")
        // The password never appears anywhere on the receipt.
        assertThat(run.receipt.resources.flatMap { it.attributes.values }).doesNotContain("sink-pw")

        server.takeRequest() // createWorkspace
        server.takeRequest() // registerTenant
        server.takeRequest() // applications.create
        server.takeRequest() // identity.registerUser
        val emailReq = server.takeRequest()
        assertThat(emailReq.method).isEqualTo("PUT")
        assertThat(emailReq.path).isEqualTo("/api/v1/email-provider")
        assertThat(emailReq.getHeader("Authorization")).isEqualTo("Bearer PT-1")
        val body = emailReq.body.readUtf8()
        // String params coerced to the JSON types PutEmailProviderRequest expects.
        assertThat(body)
            .contains("\"smtpHost\":\"smtp.sink.local\"")
            .contains("\"smtpPort\":1025")                       // string "1025" → JSON int
            .contains("\"allowInsecureTransport\":true")          // string "true" → JSON boolean
            .contains("\"enabled\":true")                         // literal "true" → JSON boolean
            .contains("\"transportSecurity\":\"none\"")
            .contains("\"smtpPassword\":\"sink-pw\"")
        // The port/booleans are NOT sent as strings.
        assertThat(body)
            .doesNotContain("\"smtpPort\":\"1025\"")
            .doesNotContain("\"allowInsecureTransport\":\"true\"")
    }

    @Test
    fun `simple-signin configure-email-provider is a no-op when smtpHost is empty`() {
        val ctx = context()
        // No smtp overrides → smtpHost defaults to "" → the email step must skip the PUT entirely.
        // ws → tenant → app → user → verify GET → attest (NO email PUT enqueued).
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"srv-ignored","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","status":"ACTIVE"}"""))
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"active"}"""))
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup()

        // No BYO-SMTP was configured — nothing recorded on the receipt for it.
        assertThat(run.receipt.resources).noneMatch { it.kind == "emailProvider" }

        server.takeRequest() // createWorkspace
        server.takeRequest() // registerTenant
        server.takeRequest() // applications.create
        server.takeRequest() // identity.registerUser
        // The very next request is the verify GET — proving the email step issued NO PUT.
        val next = server.takeRequest()
        assertThat(next.method).isEqualTo("GET")
        assertThat(next.path).isEqualTo("/api/v1/applications/app-9")
    }

    @Test
    fun `a failed verify assertion surfaces as a RecipeException`() {
        val ctx = context()
        server.enqueue(jsonResponse(201, """{"tenantId":"t-1","slug":"x","provisioningToken":"PT-1"}"""))
        server.enqueue(jsonResponse(200, """{"ok":true}"""))
        server.enqueue(jsonResponse(201, """{"clientId":"app-9"}"""))
        // SSO-2908 — identity.registerUser step runs before verify.
        server.enqueue(jsonResponse(201, """{"id":"usr-7","email":"[email protected]","status":"ACTIVE"}"""))
        // verify expects status=active, but the app comes back suspended.
        server.enqueue(jsonResponse(200, """{"clientId":"app-9","status":"suspended"}"""))

        val ex = runCatching { RecipeInterpreter(ctx, Recipe.load("simple-signin"), trustPropagationBudgetMs = 2_000).setup() }
            .exceptionOrNull()
        assertThat(ex).isInstanceOf(RecipeException::class.java)
        assertThat(ex!!.message).contains("status").contains("active").contains("suspended")
    }

    @Test
    fun `ci-signin provisions the app with the callers own token and creates no workspace`() {
        // SSO-2944 — the workspace-less recipe operates inside a STANDING workspace the caller's API key
        // already owns. There is NO hub.createWorkspace step, so the interpreter authenticates every
        // tenant-scoped call with the caller's own bearer (AT-test) — no provisioning token, no exchange.
        val ctx = context()
        // 1) applications.create (under the standing workspace, with the caller's own token)
        server.enqueue(jsonResponse(201, """{"clientId":"app-ci","status":"active"}"""))
        // 2) verify applications.get
        server.enqueue(jsonResponse(200, """{"clientId":"app-ci","status":"active"}"""))
        // 3) best-effort platform attestation of the receipt
        server.enqueue(jsonResponse(200, """{"kid":"k","signature":"s","canonicalPayload":"e30","attestedAt":"2026-01-01T00:00:00Z"}"""))

        val run = RecipeInterpreter(
            ctx,
            Recipe.load("ci-signin"),
            overrides = mapOf("workspaceSlug" to "ci-standing"),
            trustPropagationBudgetMs = 2_000,
        ).setup()

        assertThat(run.state.example).isEqualTo("ci-signin")
        assertThat(run.state.clientId).isEqualTo("app-ci")
        // The standing slug flows into the state (and the derived tenant issuer) without a create step.
        assertThat(run.state.workspaceSlug).isEqualTo("ci-standing")
        assertThat(run.state.tenantId).isNull()
        assertThat(run.receipt.resources).anyMatch { it.kind == "application" && it.id == "app-ci" }
        assertThat(run.receipt.workspace.slug).isEqualTo("ci-standing")

        // The FIRST request is the app create — no /account/workspace call precedes it.
        val appReq = server.takeRequest()
        assertThat(appReq.method).isEqualTo("POST")
        assertThat(appReq.path).isEqualTo("/api/v1/applications")
        // Authenticated with the caller's OWN token — NOT a provisioning token, NOT an exchanged token.
        assertThat(appReq.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        assertThat(server.takeRequest().path).isEqualTo("/api/v1/applications/app-ci")
    }

    @Test
    fun `ci-signin teardown deletes only the app and touches no workspace`() {
        // SSO-2944 — teardown removes only the ephemeral app; the standing workspace survives. It uses
        // the caller's own token (workspace-less recipe), so there is no token-exchange first.
        val ctx = context()
        val state = ExampleState(example = "ci-signin", workspaceSlug = "ci-standing", clientId = "app-ci")
        server.enqueue(noContent())

        RecipeInterpreter(ctx, Recipe.load("ci-signin")).teardown(state)

        val del = server.takeRequest()
        assertThat(del.method).isEqualTo("DELETE")
        assertThat(del.path).isEqualTo("/api/v1/applications/app-ci")
        assertThat(del.getHeader("Authorization")).isEqualTo("Bearer AT-test")
        // No further requests — no hub.deleteWorkspace, no token exchange.
        assertThat(server.requestCount).isEqualTo(1)
    }

    @Test
    fun `teardown deletes the app then hard-deletes the workspace`() {
        val ctx = context()
        val state = ExampleState(
            example = "simple-signin",
            workspaceSlug = "ex-signin-abc12345",
            tenantId = "t-1",
            clientId = "app-9",
        )
        // teardown re-enters the workspace via token-exchange (no provisioning token persisted), then
        // deletes the app, then hard-deletes the workspace (SSO-2901 — stop the ex-signin-* tenant sprawl).
        server.enqueue(jsonResponse(200, """{"access_token":"switched","token_type":"Bearer","expires_in":900}"""))
        server.enqueue(noContent())
        server.enqueue(jsonResponse(202, """{"tenantId":"t-1","slug":"ex-signin-abc12345","archived":true}"""))

        RecipeInterpreter(ctx, Recipe.load("simple-signin")).teardown(state)

        server.takeRequest() // the token exchange
        // Child-first: the app is deleted BEFORE the workspace it lives in.
        val del = server.takeRequest()
        assertThat(del.method).isEqualTo("DELETE")
        assertThat(del.path).isEqualTo("/api/v1/applications/app-9")
        // Then the workspace hard-delete on the HUB surface, name-confirmation guarded by the slug.
        val hardDelete = server.takeRequest()
        assertThat(hardDelete.method).isEqualTo("POST")
        assertThat(hardDelete.path).isEqualTo("/account/workspace/t-1/hard-delete")
        assertThat(hardDelete.getHeader("X-Thoryn-Confirm")).isEqualTo("ex-signin-abc12345")
    }
}
