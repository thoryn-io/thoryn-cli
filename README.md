# thoryn — Thoryn customer-plane CLI

`thoryn` is the Thoryn customer-plane CLI. It runs the same OAuth flow
the web console runs, stores tokens in the OS keychain, and calls the
gateway endpoints that back the console's tenant-admin surfaces.

Built with picocli + GraalVM native image per
ADR 2026-04-25-customer-plane-product-api § 4 / § 8 / and RFC 8252 § 7.3 +
RFC 7636 + RFC 8628.

> **Standalone repo (SSO-2935).** This CLI lives in its own repository
> (`thoryn-io/thoryn-cli`), carved out of the `oathy` monorepo with its git
> history preserved. It builds on its own — no oathy checkout required. The
> user-facing product docs are published from oathy's `docs/` to
> thoryn.org/docs; this README is the developer-facing entry point.

## Install

Releases are cut by tagging `cli-v*` (SSO-2936). The `release` workflow
(`.github/workflows/release.yml`) builds the GraalVM native binaries and the
`thoryn.jar` fat jar and attaches them to the matching
[GitHub Release](https://github.com/thoryn-io/thoryn-cli/releases). The
`thoryn.jar` is always published; the native binaries are **best-effort per
runner availability** — an unavailable platform runner (e.g. GitHub's retiring
Intel-macOS runner) is tolerated, so a given platform's binary may be absent from
a release rather than blocking it.

**Homebrew** — the repo doubles as its own tap:

```bash
brew tap thoryn-io/thoryn-cli
brew install thoryn
thoryn --version
```

`brew install thoryn` pulls the prebuilt native binary for your OS/arch from the
latest `cli-v*` release; the release workflow bumps `Formula/thoryn.rb` (version +
per-binary `sha256`) on every tag.

**Direct download** — grab a native binary from the release assets
(`thoryn-darwin-arm64`, `thoryn-darwin-amd64`, `thoryn-linux-amd64`,
`thoryn-linux-arm64`, `thoryn-windows-amd64.exe` — whichever were produced for
that release; see the best-effort note above), `chmod +x`, and put it on `PATH`.
The `thoryn.jar` fat jar is always attached (`java -jar thoryn.jar ...`); it is
the stable asset name the `thoryn-examples` conformance CI consumes.

## Command tree

```
thoryn login                                 # Auth code + PKCE (loopback) or --device-code
thoryn login --client-credentials [--client-id <id>] # SSO-1553/2941 — non-interactive API key (CI); THORYN_API_KEY=<id>:<secret>, auto re-mints on expiry
thoryn login --status
thoryn logout

# Tenant configuration (SSO-1552) — thin wrappers over product-api via the gateway.
thoryn clients list                          # OAuth clients (product-api /api/v1/applications)
thoryn clients get <clientId>
thoryn clients create --display-name <n> --redirect-uri <uri> [--scope <s>]... \
                      [--client-type confidential|public] [--secret-file <path>]
thoryn clients update <clientId> [--display-name <n>] [--redirect-uri <uri>]... [--scope <s>]...
thoryn clients rotate-secret <clientId> [--secret-file <path>] [--confirm <workspace-slug>]
thoryn clients delete <clientId> [--confirm <workspace-slug>]

thoryn federation list                       # Federation members (product-api /federation-members)
thoryn federation create --provider-type oidc --display-name <n> \
                         --discovery-url <url> --client-id <id> [--secret-file <path>] \
                         [--provider-config k=v]... [--claim-mapping k=v]...
thoryn federation delete <memberId> [--confirm <workspace-slug>]

thoryn workspace list                        # Workspaces (hub /account/workspaces)
thoryn workspace create --slug <slug> --display-name <name>
thoryn workspace switch <slug>               # prints the `thoryn login --issuer <tenant-hub>` line
thoryn workspace archive <slug> --confirm <slug>   # SSO-2831 — archive (reversible); name-confirmed
thoryn workspace reactivate <slug>           # SSO-2831 — clear the archive flag

# Environments (SSO-2870) — select & manage the sandboxes + production of your workspace.
# The customer plane is environment-scoped: a client/user created in a sandbox is invisible
# to a request that resolves to a different environment. `env use` records the target and every
# later command rides it as `X-Thoryn-Environment` — so `clients list` finally hits the right one.
thoryn env list                              # environments (product-api /api/v1/environments); marks the active one
thoryn env use <slug>                        # target an environment (e.g. a sandbox) for subsequent commands
thoryn env create <slug> --name <name>       # create a sandbox
thoryn env rename <slug> --name <name>       # rename (display name only; slug immutable)
thoryn env suspend <slug> [--confirm <slug>] # suspend a sandbox (production cannot be suspended)
thoryn env reactivate <slug>                 # clear a sandbox suspension
thoryn env delete <id> --confirm <slug>      # hard-delete a sandbox (irreversible; confirm = its own slug)

# Sandbox test inbox (SSO-3026) — a sandbox SUPPRESSES real transactional email and captures it here,
# so you can complete a sandbox email flow (verification, …) without a real mailbox. Read-only.
thoryn env test-emails list [--env <slug>] [--to <email>] [--channel <ch>] [--limit <n>]
thoryn env test-emails get <email-id> [--env <slug>]   # one email, incl. its actionLink (e.g. the verify URL)

# Hosted-login branding (SSO-3037) — the look of the hosted sign-in / register screens end users see,
# per SELECTED ENVIRONMENT (thoryn env use). Rendered as CSS custom properties; server-validated
# (hex colors, radius 0-64, theme enum, https logo) + WCAG-AA contrast-guarded. Needs tenant:idp.*.
thoryn branding get                                    # effective values + which fields are overridden
thoryn branding set [--primary-color '#2563eb'] [--background-color '#fff'] \
                    [--logo-url https://…] [--border-radius-px 8] [--theme light|dark|auto]
# SSO-3038 — additionally set allowlisted --thoryn-* CSS variables (repeatable --var KEY=VALUE):
thoryn branding set --var --thoryn-accent=#7c3aed --var --thoryn-font-family='Inter, sans-serif'
#   allowed: --thoryn-accent, --thoryn-text, --thoryn-muted, --thoryn-font-family (colors hex +
#   WCAG-AA contrast-guarded; font a safe stack). An empty value clears one: --var --thoryn-accent=
# set MERGES (unspecified fields + CSS vars keep their stored value); pass an empty value to clear an
# override, e.g. `thoryn branding set --logo-url ""` drops the custom logo back to the platform default.

# Tenant seeding (SSO-1553) — one-shot, zero-interaction provisioner for CI.
thoryn tenant seed --non-interactive --secret-dir <dir> \
                   [--clients <N>] [--skip-federation] \
                   [--tenant-id <uuid> --slug <slug>] [--gateway <url>]

thoryn audit query [--from <ts>] [--to <ts>] [--event-type <t>] [--actor <sub>] [--limit <n>]

thoryn audit-replay <receipt.json>           # SSO-940b — offline replay tool

# Runnable examples (SSO-2830) — provision a real config in your own account and see it work.
thoryn examples list
thoryn examples setup    <name>              # e.g. simple-signin
thoryn examples run      <name>              # opens your browser
thoryn examples teardown <name>
thoryn examples receipt  <name>              # SSO-2875 — show the receipt setup wrote (what it provisioned)
thoryn examples verify   <name>              # SSO-2875 — re-check the provisioned config still matches (+ attestation signature, SSO-2878)
thoryn examples catalog  [--remote] [--tag]  # SSO-2874 — list recipes (bundled, or --remote from the signed public release)
thoryn examples update   [--tag]             # SSO-2874 — fetch + verify (Ed25519) + cache the public recipe catalog
thoryn examples apply    <name> [--set k=v]… [--environment <slug>] [--yes]   # SSO-2876 — guided: prompt params + env, dry-run, confirm, provision
thoryn examples share    <name> [--output <file>]   # SSO-2876 — export the secret-free receipt (notes if platform-signed)

# Operator provisioning (SSO-2952) — bootstrap the CI machine identity (founder-run, once).
thoryn provision ci-identity [--secret-file <path>] [--force-stdout] [--gateway <url>]   # mint the confidential client_credentials machine client; secret shown once via SecretIo
```

> The supply-chain / verifiable-credential command tree was **removed** when the
> CLI was relocated into oauthy as a Hub-only tool (SSO-2817); those commands
> belong to the VC product (`thoryn-vc-broker`), not the customer-plane CLI.

Every tenant-config leaf (`clients`, `federation`, `workspace`, `audit`)
accepts `--output {table,json,yaml}` (default `table`). Errors go to stderr
with a non-zero exit code; on `--output json` errors emit structured JSON on
stdout.

The tenant-config commands are **thin wrappers**: all business logic lives in
product-api (the single source of truth). The CLI only marshals the request,
attaches the bearer, and renders the response.

### Production destructive-action confirmation (SSO-2413)

Destructive actions on a **production** workspace are gated by product-api's
`ProductionConfirmationInterceptor`. Since the CLI calls the gateway directly
with a bearer (no BFF to mediate), it must send the confirmation itself:
`--confirm <your-workspace-slug>` on `clients delete`, `clients rotate-secret`,
and `federation delete` sets the `X-Thoryn-Confirm` header. When it is absent on
a production workspace the server answers `428 production_confirmation_required`
and the CLI prints a re-run hint; a wrong value answers
`422 production_confirmation_mismatch`. **Sandbox / non-production actions are
ungated** — no `--confirm` needed there.

 - `clients` targets product-api's `/api/v1/applications` surface — the same
   contract the web console uses (so the CLI and console never diverge), and
   the only client surface that carries secret rotation.
 - `federation` targets product-api's `/federation-members` surface; the
   `oidc` provider type (SSO-1548) attaches Thoryn's own identity-service or
   any generic OIDC provider with no external IdP.
 - `workspace` targets the hub's `/account/workspace[s]` surface (NOT behind
   the gateway); `create` also registers the new tenant in product-api.
 - `audit query` targets product-api's `/audit/events` surface
   (`tenant:audit.read`).

## Secret-safety (SSO-1552)

Client and federation secrets are shown once and **never** pass through `argv`
or land in shell history:

 - **Secrets you supply** (a federation member's `clientSecret`, a
   service-account secret for `login --client-credentials`, the seed's upstream
   federation secret) are read from a no-echo terminal prompt, a
   `--secret-file` / `--client-secret-file` / `--federation-secret-file`, or an
   env var (`THORYN_CLIENT_SECRET`, `THORYN_FEDERATION_SECRET`). There is
   deliberately **no `--client-secret <value>` / `--federation-secret <value>`
   flag** — a secret on the command line leaks into `~/.zsh_history`, `ps aux`,
   and any command-line-capturing audit log.
 - **Secrets the server mints** (a created client's secret, a rotated secret)
   are written to `--secret-file <path>` (owner-only `0600`), or printed to an
   interactive TTY with a one-line `WARNING`. Printing to a **non-interactive**
   stdout (a pipe or file redirect) is refused unless you pass `--force-stdout`,
   so `thoryn clients create | tee` cannot silently capture the secret. TTY
   detection uses `Console.isTerminal()`; when it can't be confirmed (older JVM,
   CI) the safe default is to refuse and ask for `--secret-file`.
 - Tokens are stored in the OS keychain (see below), never in `argv`.

## Authentication

```bash
# Default scopes (SSO-1552): openid offline_access plus the tenant-config set
# (tenant:applications.{read,write}, tenant:federation.{read,write},
# tenant:audit.read, tenant:environments.{read,write}, tenant:email.{read,write},
# tenant:idp.{read,write}) so `clients`, `federation`, `audit`, `env` (SSO-2870),
# `workspace email-provider`, and `branding` (SSO-3037) work out of the box.
# `workspace` rides on SCOPE_openid (the hub /account surface). The hub drops any
# scope the tenant admin doesn't actually hold.
thoryn login

# Grab the whole tenant-config scope set explicitly.
thoryn login --scope all-tenant-config

# Headless (no browser).
export THORYN_CLIENT_SECRET=...
thoryn login --device-code
```

The wildcard `all-tenant-config` expands client-side per `ScopeRegistry.kt`
to the literal tenant-config scope set. The hub does NOT understand the
wildcard — it's a CLI ergonomic.

When a command rejects with `insufficient_scope`, the CLI prints the
exact `thoryn login --scope <required>` line to fix it.

## Non-interactive auth & tenant seeding (SSO-1553 / API-key SSO-2941)

For CI / automation there is a fully non-interactive path — no browser, no
second device:

```bash
# Service-account / API-key login (RFC 6749 §4.4 client-credentials). Credentials
# from env, NEVER argv. --issuer MUST be the tenant subdomain so the hub mints `tnt`.

# SSO-2941 — single-knob API key: one secret carries id + secret as "<id>:<secret>".
export THORYN_API_KEY="ci-bot:$CI_SERVICE_ACCOUNT_SECRET"
thoryn login --client-credentials \
  --issuer https://acme.hub.stg.thoryn.org \
  --scope "tenant:applications.write tenant:federation.write"

# Or split form — --client-id + THORYN_CLIENT_SECRET (or --client-secret-file <path>):
export THORYN_CLIENT_SECRET="$CI_SERVICE_ACCOUNT_SECRET"
thoryn login --client-credentials --client-id ci-bot \
  --issuer https://acme.hub.stg.thoryn.org \
  --scope "tenant:applications.write tenant:federation.write"

# One-shot tenant seed: sample OAuth clients + identity-service federation member.
export THORYN_FEDERATION_SECRET="$CI_IDENTITY_SERVICE_SECRET"
thoryn tenant seed --non-interactive --secret-dir ./seed-secrets \
  --clients 2 --gateway https://api.identity.stg.thoryn.org
```

`tenant seed` is a thin orchestration over the SAME product-api endpoints the
`clients` / `federation` / `workspace` commands use (so the audit trail and
validation are identical) — it does not call any new server endpoint:

 - `POST /api/v1/applications` × `--clients` (default 2). Each minted secret is
   written to a `0600` file under `--secret-dir`, never to a pipe.
 - `POST /federation-members` (`providerType=oidc`) for the identity-service
   member, unless `--skip-federation`.
 - `POST /tenants` first, when `--tenant-id` + `--slug` are supplied (the
   tnt-exempt product-api bootstrap, SSO-912). Creating a brand-new **hub**
   workspace is a user/OpenID flow — use `thoryn workspace create` for that.

A client-credentials token carries no user; its `tnt` claim is minted by the hub
from the tenant subdomain the token is requested against. Point `--issuer` at
`https://<slug>.hub.<env>.thoryn.org` or product-api rejects the seed with `401
missing_tnt_claim`.

**Re-mint on expiry (SSO-2941).** A client-credentials token has no refresh token
(RFC 6749 §4.4.3), so instead of the refresh-token grant the CLI re-mints a fresh
token when the stored one nears expiry (or on a `401`), re-running the same grant
with the stored client id and the secret still in the environment
(`THORYN_API_KEY` / `THORYN_CLIENT_SECRET`). The secret is **never persisted** —
only the short-lived access token, the (public) client id, and an auth-mode marker
are stored — so re-mint works for the whole life of a CI job where the secret env
var is set. If the secret is no longer in the environment, re-mint prints a hint and
the operator re-runs `thoryn login --client-credentials`.

Full user docs: `docs/modules/ROOT/pages/cli/non-interactive-automation.adoc`.

## Token storage

Tokens are stored in the OS keychain per ADR 2026-04-25 §4 — macOS
Keychain, Linux Secret Service, Windows Credential Manager.

For CI / headless environments without a keychain backend, opt into the
plaintext fallback explicitly:

```bash
export THORYN_CI_PLAINTEXT_TOKENS=1
thoryn login --device-code
```

The fallback writes a chmod-0600 JSON file to
`~/.config/thoryn/tokens.json` (Linux/macOS) or
`%APPDATA%/thoryn/tokens.json` (Windows). Override the path with
`THORYN_TOKEN_FILE=/path/to/tokens.json`.

## Session endpoints (SSO-2827)

`thoryn login` records the hub issuer (`--issuer`) and the customer-plane
gateway alongside the token, so the other commands default to them — you do
**not** need to repeat `--hub` / `--gateway` on every call after signing in:

```bash
thoryn login --issuer https://acme.hub.stg.thoryn.org   # records hub + gateway for the session
thoryn workspace list                                    # uses the session hub, no --hub needed
thoryn clients list                                      # uses the session gateway, no --gateway needed
```

The gateway is derived from the hub host (`hub.<env>` → `api.<env>`); for a
non-standard topology set it explicitly at login with `--gateway <url>`. An
explicit `--hub` / `--gateway` on any command still overrides the session.

## Examples (SSO-2830)

`thoryn examples` provisions a real, in-boundary configuration in **your own
account** using only supported product workflows (never DB seeds or demo
endpoints — the product-boundary rule), lets you see the real interaction, and
tears down what it created. Each example has three explicit steps so you can
inspect your account state between them:

```bash
thoryn examples list
thoryn examples setup simple-signin      # create a dedicated example workspace + a loopback OAuth app
thoryn examples run   simple-signin      # opens your browser — register a user, sign in, land on a protected page
thoryn examples teardown simple-signin   # remove what setup created (best-effort)
```

**`simple-signin`** creates a dedicated workspace (via the real
`workspace create` workflow, which attaches the tenant's identity provider) and
a public **loopback** OAuth client, then `run` launches the **Node relying
party** that ships as a signed catalog asset (`recipes/simple-signin/apps/loopback-rp/server.js`
in the public `thoryn-examples` repo — a readable, zero-dependency Node OIDC
Authorization-Code + PKCE app) and opens your browser. You register a new user and
sign in on the real hosted screens and land on the protected page, which shows your
ID-token claims. Nothing is added to oathy's deployed services — the app runs only
for the duration of `run`.

**`ci-signin`** (SSO-2944) is the **workspace-less** sibling: it provisions an
**ephemeral loopback OAuth client inside a workspace you already own** (no
`hub.createWorkspace` / `hub.deleteWorkspace`) and tears down only that client. It
exists because a customer-plane `client_credentials` API key is tenant-scoped and
cannot create workspaces, so CI (the provisioning Action below) targets a standing
workspace. Apply it with the standing slug:
`thoryn examples apply ci-signin --set workspaceSlug=<your-standing-slug> --yes`.

`run` therefore **requires Node 18+** on your `PATH` and the **verified signed
catalog** on disk (the RP code lives in exactly one place — the Node asset — not
baked into the CLI). If Node is missing, or the catalog has not been fetched, `run`
fails with an actionable message: fetch + verify the catalog once with
`thoryn examples update`, install Node 18+, then re-run. (The catalog is Ed25519-signed;
the CLI refuses an unsigned or tampered bundle.)

**Teardown is partial by design.** It deletes the OAuth client it created, but
there is no customer-plane API yet to delete the example workspace or the user
you registered (tracked as **SSO-2831** — archive/delete a workspace with a
name-confirmation guard); those artifacts remain in your account until that
lands. A `--headless` mode that drives register + sign-in programmatically is a
planned follow-up (it needs privileged provisioning credentials).

## Provisioning GitHub Action (SSO-2938 → SSO-2944)

`.github/actions/provision` is a reusable **composite Action** that configures the
product as a real customer against **shared staging**, using ONLY the product APIs
via this CLI and a signed recipe (no DB seeding, no demo endpoints — the
product-boundary rule applied to CI).

**The pivot (SSO-2944).** CI authenticates with a **customer-plane
`client_credentials` API key the operator mints themselves** — not a seeded platform
client. Such a key is **tenant-scoped** (bound to one workspace via its `tnt` claim)
and **cannot create workspaces** (workspace-create needs a machine scope a tenant
admin can't delegate — the SSO-2943 gap). So the Action no longer creates a fresh
workspace per run; it provisions an **ephemeral OAuth client inside a STANDING
workspace** the operator owns, and deletes only that client on exit. It:

1. **builds the CLI from source** (`./mvnw -q -DskipTests package` → `target/thoryn.jar`;
   switches to a `gh release download --pattern thoryn.jar` once a `cli-v*` release
   exists, SSO-2936),
2. **signs in non-interactively** with the tenant-scoped client-credentials API key at
   the **per-tenant issuer** `https://<slug>.hub.<env>` (derived from the hub base +
   `workspace-slug`; the shared `api.<env>` gateway is set explicitly), credential from
   `THORYN_API_KEY=<client-id>:<client-secret>` (never echoed, never an argv flag),
3. **provisions** with the workspace-less recipe
   `thoryn examples apply ci-signin --set workspaceSlug=<slug> --yes` — an ephemeral
   public loopback OAuth client registered UNDER the standing workspace with the
   caller's own bearer (no `hub.createWorkspace`, no token-exchange),
4. **exposes** `workspace-slug` / `client-id` / `issuer` as Action outputs (read from
   the run's receipt), and
5. **deletes the ephemeral client on exit** in an `if: always()` step
   (`thoryn examples teardown ci-signin` → `applications.delete` only; the standing
   workspace and standing user are never touched), so a failed run leaks nothing.

The demo caller is `.github/workflows/provision-e2e.yml` (manual `workflow_dispatch`).

### CI provisioning setup (one-time, per environment)

The Action assumes a **standing workspace**, a **standing test user**, and a
**tenant-scoped API key** already exist. Create them once as a tenant admin (the
commands below target staging; adjust the issuer for another environment):

```bash
# 0) Sign in interactively as a tenant admin (authorization-code + PKCE, opens a browser).
thoryn login --issuer https://hub.stg.thoryn.org

# 1) Create the STANDING workspace the CI runs will provision into (skip if it exists).
thoryn workspace create --slug ci-standing --display-name "CI Standing Workspace"

# 2) Enter it, so the following resources are created UNDER that tenant.
thoryn workspace switch ci-standing

# 3) Mint the CUSTOMER-PLANE client_credentials API key, scoped to exactly what the
#    recipe needs. The secret is written to a file (never printed to the CI log).
#    NOTE (SSO-2943 friction): `clients create` REQUIRES --redirect-uri even for a
#    machine (client_credentials) client that never redirects — pass a throwaway.
thoryn clients create \
  --display-name "CI provisioning key (ci-standing)" \
  --client-type confidential \
  --grant-type client_credentials \
  --scope tenant:applications.write \
  --scope tenant:applications.read \
  --redirect-uri https://ci.invalid/unused \
  --secret-file ci-key.secret
# → prints the client-id; the secret is in ci-key.secret. Set the repo secret:
#   THORYN_API_KEY = "<client-id>:<contents of ci-key.secret>"
```

**Standing test user** — there is no `thoryn users create` command yet (another
SSO-2943 gap), so create the standing sign-in user through the product API with your
tenant-admin bearer (or the console's Users screen). Against the standing tenant:

```bash
# $ADMIN_BEARER = a tenant-admin access token for the STANDING tenant (carrying
# tenant:users.write). Obtain it from your interactive session; it must have iss
# https://ci-standing.hub.stg.thoryn.org (the standing tenant), i.e. minted after the
# `workspace switch ci-standing` above.
curl -sS -X POST https://api.stg.thoryn.org/api/v1/users \
  -H "Authorization: Bearer $ADMIN_BEARER" \
  -H "Content-Type: application/json" \
  -H "X-Thoryn-Environment: production" \
  -d '{"email":"[email protected]","password":"<strong-password>",
       "givenName":"CI","familyName":"Tester","emailVerified":true}'
```

Then, in the thoryn-cli repo's **Actions secrets/vars**:

- secret `THORYN_API_KEY` = `<client-id>:<client-secret>` from step 3,
- (the standing workspace slug is passed as the workflow's `workspace-slug` input).

**SSO-2943 gaps to close / validate live** (this story is CLI-only and does NOT touch
oauthy):

- Confirm the hub **issues a usable tenant-scoped token** for a customer-plane
  `client_credentials` client registered in a non-default tenant, authenticating at
  `https://<slug>.hub.<env>` — the whole design turns on this. If it is refused, the
  fallback is a product-API-minted machine credential; record the gap on SSO-2943.
- `thoryn clients create` requires `--redirect-uri` even for a `client_credentials`
  client — a throwaway works, but it is friction worth removing.
- There is no `thoryn users create`; the standing user is created via product-API
  `POST /api/v1/users` (or the console) until a CLI verb exists.

Live validation is **pending operator setup** — the standing workspace + key don't
exist yet, so the flow is validated locally only (build, unit tests, recipe/YAML
parse, `--help` of every invoked command).

## Build

Requires a JDK 21+ on `PATH`. The Maven wrapper (`./mvnw`) pins Maven, so no
system Maven install is needed.

```bash
# Compile + tests
./mvnw test

# Shaded fat jar (run via java -jar)
./mvnw -DskipTests package
java -jar target/thoryn.jar login --status

# GraalVM native image (SSO-733; per-OS/arch matrix on CI).
# Requires GRAALVM_HOME (or JAVA_HOME) to point at a GraalVM distribution
# with `native-image` installed.
./mvnw -Pnative -DskipTests package
./target/thoryn workspace list --hub https://hub.stg.thoryn.org
```

## Module layout

```
thoryn-cli/
├── pom.xml
├── README.md                                                # this file
└── src/
    ├── main/kotlin/com/devnow/thoryn/cli/
    │   ├── ThorynMain.kt                                    # picocli root
    │   ├── auth/
    │   │   ├── DeviceCodeFlow.kt                            # RFC 8628
    │   │   ├── ClientCredentialsFlow.kt                     # SSO-1553 RFC 6749 §4.4 (non-interactive)
    │   │   ├── LoopbackRedirectServer.kt                    # RFC 8252 §7.3
    │   │   ├── PkceUtil.kt                                  # RFC 7636
    │   │   ├── TokenStore.kt + KeychainTokenStore.kt        # ADR 2026-04-25 §4
    │   │   ├── Tokens.kt
    │   │   └── ScopeRegistry.kt                             # SSO-959 scope wildcards
    │   ├── api/
    │   │   └── ProductApiClient.kt                          # SSO-959 typed HTTP client
    │   ├── cmd/
    │   │   ├── LoginCommand.kt + LogoutCommand.kt
    │   │   ├── CommandSupport.kt                            # SSO-1552 shared token/output/error helpers
    │   │   ├── SecretIo.kt + FileSecrets.kt                 # SSO-1552 secret-safety (no-echo / --secret-file)
    │   │   ├── ClientsCommand.kt                            # SSO-1552 clients CRUD + rotate-secret
    │   │   ├── FederationCommand.kt                         # SSO-1552 federation list/create/delete
    │   │   ├── WorkspaceCommand.kt                          # SSO-1552 workspace create/list/switch
    │   │   ├── TenantCommand.kt                             # SSO-1553 tenant seed (non-interactive provisioner)
    │   │   ├── SelectedWorkspaceStore.kt                    # SSO-1552 records the switched-into workspace
    │   │   ├── AuditCommand.kt                              # SSO-1552 audit query (config + auth events)
    │   │   └── AuditReplayCommand.kt                        # SSO-940b
    │   ├── config/
    │   │   └── ThorynConfig.kt                              # per-env defaults
    │   └── output/
    │       ├── OutputFormat.kt                              # SSO-959 --output enum
    │       ├── Printers.kt                                  # SSO-959 table/json/yaml
    │       └── YamlWriter.kt                                # SSO-959 hand-rolled YAML
    ├── main/resources/META-INF/native-image/                # GraalVM hints
    └── test/kotlin/com/devnow/thoryn/cli/                   # MockWebServer + picocli tests
```

## Native-image notes

* Reflection metadata for picocli's `@Command`-annotated classes is
  generated by `picocli-codegen` during `process-classes`. New subcommand
  classes are picked up automatically; no manual `reflect-config.json`
  changes needed.
* `java-keyring` + `JNA` reflection lives in
  `src/main/resources/META-INF/native-image/com.devnow.thoryn.cli/`.
* All subcommands use only `java.net.http.HttpClient` + Jackson 3 + picocli,
  all of which are already native-image-ready.

## Related

* `docs/modules/ROOT/pages/cli/index.adoc` — top-level user docs
* `docs/modules/ROOT/pages/cli/tenant-configuration.adoc` — SSO-1552 clients/federation/workspace/audit
* `docs/modules/ROOT/pages/cli/non-interactive-automation.adoc` — SSO-1553 client-credentials + tenant seed
* ADR `adrs/2026-04-25-customer-plane-product-api.md`
