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

# Directory users (SSO-3081) — the users of your workspace (product-api /api/v1/users), honouring the
# SELECTED environment (thoryn env use); with none selected, the production plane. Suspending a user
# refuses their next sign-in (the hosted login shows the suspended notice, not the generic error).
thoryn users list [--email <email>] [--status <ACTIVE|SUSPENDED>] [--limit <n>] [--environment <slug>]
thoryn users suspend (<id> | --email <email>) [--confirm <workspace-slug>] [--environment <slug>]  # production plane needs --confirm
thoryn users reactivate (<id> | --email <email>) [--environment <slug>]                            # clear a suspension
# --environment targets a plane directly (rides X-Thoryn-Environment) for a client-credentials/CI
# session that hasn't run `workspace switch` + `env use` (SSO-3068); e.g. `--environment production`.

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
                                             # SSO-3100 — a recipe with `provision: ./provision.yaml` converges that provisioning file FIRST
                                             # (same engine as `provision apply`; a re-apply is a no-op), then runs its extra steps; `teardown` destroys it last
thoryn examples share    <name> [--output <file>]   # SSO-2876 — export the secret-free receipt (notes if platform-signed)

# Operator provisioning (SSO-2952) — bootstrap the CI machine identity (founder-run, once).
thoryn provision ci-identity [--secret-file <path>] [--force-stdout] [--gateway <url>]   # mint the confidential client_credentials machine client; secret shown once via SecretIo

# Provisioning-as-code (SSO-3088, epic SSO-3087) — converge the DESIRED STATE in .thoryn/provision.yaml
# (resources with a stable `name`: environment, application, user, federationMember, and the
# per-environment singletons emailProvider / loginTheme / loginFlow / loginMethods — the last, SSO-3100,
# is the sign-in METHOD allow-list `login-methods set` writes; destroy resets it). The receipt next to the file
# (<name>.receipt.json) is the ownership ledger. SSO-3089: every resource is read LIVE by its converge
# key before any write (env slug, app displayName within its env, user email, member displayName, the
# singletons by existence): equal ⇒ no-op, different ⇒ update with only the changed fields, existing
# but unmanaged ⇒ adopted (converged from then on, NEVER deleted by destroy/--prune), deleted out of
# band ⇒ re-created. Apply twice issues no writes. Secrets never enter the file — name the env var (`passwordEnv`,
# `smtpPasswordEnv`, `clientSecretEnv`) or use `{{env.NAME}}`; they are resolved at apply and never
# recorded. Production-plane removals need `--confirm <workspace-slug>` (the SSO-2413 gate).
thoryn provision plan    [--file <path>] [--prune]                                  # read-only: what apply would create / remove
thoryn provision apply   [--file <path>] [--prune] [--confirm <ws>] [--yes]        # converge; environments first, dependants into them
thoryn provision destroy [--file <path>|--receipt <path>] [--confirm <ws>] [--yes] # remove everything owned, child-first (sandbox hard-delete cascades)
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

**`ci-signin`** (SSO-2944) was the **workspace-less** sibling CI used to provision an
ephemeral loopback client inside a standing workspace. **Retired for CI use by SSO-3090** —
this repo's own CI now converges `.thoryn/provision.yaml` with `thoryn provision apply`
(see below). The bundled recipe stays shipped only until the `thoryn-examples`
conformance workflow moves to provisioning files (SSO-3091); do not build on it.

**Recipes reference a provisioning file (SSO-3100, epic SSO-3087).** The provisioning file
(`provision.yaml`, schema `src/main/resources/provision/provision.schema.json`) is **leading**
for all the infrastructure a normal end user configures — environment (incl. a throwaway
sandbox), application, demo user, sign-in methods (`loginMethods`), look-and-feel
(`loginTheme`), `loginFlow`, `emailProvider`, `federationMember`. A recipe is the
**orchestration file** on top. In the product owner's words: *the provision file is about how to get
Thoryn up and running; the recipe file is about how to get an example configured — the extra steps beyond
the provisioning.* The recipe names its provisioning file under `provision:
./provision.yaml` (shipped next to `recipe.json` in the signed catalog bundle and in the
bundled resources) and carries only what is extra to *run* the example — params, any
extra `steps`, `verify`, `assets`. `steps` is optional when `provision` is set.

```yaml
apiVersion: thoryn.io/examples/v1
id: sandbox-signin
version: 1.0.0
summary: Sign in on a throwaway sandbox provisioned from provision.yaml.
provision: ./provision.yaml          # environment + application + user + loginMethods live here
params:
  - { name: workspaceSlug, prompt: "Standing workspace slug" }
  - { name: envSlug, prompt: "Sandbox slug", default: "sbx-{{generate.slug8}}" }
  - { name: demoPassword, prompt: "Demo user password", secret: true }
verify:
  - assert: applications.get
    id: "{{provision.application.rp.clientId}}"   # provisioned resources are addressable
    expect: { status: active }
```

`thoryn examples apply` (and `setup`) **provisions first**: it plans + applies the file with
the same converge engine as `thoryn provision apply` (create / update / adopt by converge
key — a re-apply issues no writes, a leftover sandbox is adopted by its slug), then runs the
recipe's own steps and `verify`. The file's `{{env.NAME}}` placeholders and `<key>Env` secret
references resolve **first from the recipe's params** (so `passwordEnv: demoPassword` reads the
`secret: true` param, `slug: "{{env.envSlug}}"` reads `envSlug`) and **then from the process
environment**; secret values never reach a file or receipt. The recipe's **`params` section is
overridable by the example that runs it**, and a local `apply` **asks for each param**: a param
takes `--set`, else the **process env var of its own name** (`export envSlug=…`,
`export demoPassword=…` — the channel CI uses; a secret never rides on argv; either skips the
prompt), else the interactive prompt (a `secret: true` param is read without echo and its default
is never shown), else the recipe default — a generated secret default is revealed **once** after
apply so you can sign in with it (SSO-3102). What the file owns is exposed to
the recipe as `{{provision.<kind>.<name>.id}}` (plus `.slug` for an environment, `.email` for
a user, `.clientId` / `.redirectUri` for an application, `.methods` for `loginMethods`), the
first `environment` resource becomes the environment later steps and `examples run` target,
and every resource lands on the recipe receipt. The provisioning receipt itself is written
next to the example state (`~/.config/thoryn/examples/<name>.provision.receipt.json`) after
every successful write. `thoryn examples teardown` runs the recipe's own teardown actions and
**then destroys** the provisioned resources child-first (adopted ones are left in place); a
failed removal keeps the state + receipt so a re-run can retry. A recipe that creates its own
workspace (`hub.createWorkspace`) cannot also carry a provisioning file — the file targets the
caller's standing workspace. Recipes without `provision` behave exactly as before.

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

## Provisioning GitHub Action (SSO-2938 → SSO-2944 → SSO-3090)

`.github/actions/provision` is a reusable **composite Action** that configures the
product as a real customer against **shared staging**, using ONLY the product APIs
via this CLI and the two committed `.thoryn/` files (no DB seeding, no demo endpoints,
no imperative sign-in or provisioning — the product-boundary rule applied to CI).

**thoryn-cli is the reference consumer (SSO-3090).** A repository binds itself to
Thoryn with one folder, and this repo's own CI runs exactly that:

| File | Declares | Verb |
|---|---|---|
| `.thoryn/connection.json` | **who I am** — workspace slug, client id, the *name* of the secret env var, the scope set (SSO-2948) | `thoryn login --connection` |
| `.thoryn/provision.yaml` | **what I own** — desired-state resources: a sandbox environment + a loopback OAuth client (SSO-3088) | `thoryn provision plan / apply / destroy` |

The Action:

1. **downloads the released CLI** (`gh release download --pattern thoryn.jar` from the
   latest `cli-v*`, or the `cli-version` input) — it needs **cli-v0.11.0+**, the first
   release carrying `thoryn provision apply`, and fails loud on an older jar,
2. **signs in non-interactively** from the connection contract
   (`thoryn login --connection .thoryn/connection.json`); the secret arrives ONLY as the
   env var the contract names (`THORYN_CLI_CI_CLIENT_SECRET`), never on argv,
3. **converges the provisioning file** — `thoryn provision plan` (logged) then
   `thoryn provision apply --file .thoryn/provision.yaml --yes`: a sandbox `cli-ci` inside
   the `thoryn` workspace and a public loopback client in it. Apply twice issues no writes;
   a sandbox left by a failed run is **adopted** by its slug, never duplicated (SSO-3089),
4. **exposes** `workspace-slug` / `environment` / `client-id` / `issuer` / `receipt` as
   outputs, read from the secret-free receipt the CLI writes next to the file, and
5. **destroys on exit** (`thoryn provision destroy --file … --yes`, `if: always()`,
   disable with `destroy: "false"`): child-first, the sandbox hard-delete cascades the
   client; adopted resources and the standing workspace are never touched.

The demo caller is `.github/workflows/provision-e2e.yml` (manual `workflow_dispatch`).

**Consume it from another repository** (a `thoryn-examples` scenario, a customer
pipeline): check out *your* repo, then `uses: thoryn-io/thoryn-cli/.github/actions/provision@main`
with `client-secret`, `connection` and `file` pointing at *your* `.thoryn/` files (paths
resolve in the caller's workspace). The `secret-env` input must equal the env-var name
your `connection.json` declares in `auth.secretEnv`.

### CI provisioning setup (one-time)

Everything the run needs is either committed or minted once by a founder:

```bash
# 0) Sign in interactively as a founder of the `thoryn` workspace (authorization-code + PKCE).
thoryn login --issuer https://hub.stg.thoryn.org
thoryn workspace switch thoryn

# 1) Mint the CI machine client (SSO-2952). The secret is shown ONCE, via SecretIo.
thoryn provision ci-identity --secret-file ci.secret

# 2) Paste the printed clientId into .thoryn/connection.json (auth.clientId) and commit.
# 3) Set the GitHub secret THORYN_CLI_CI_CLIENT_SECRET to the contents of ci.secret; shred ci.secret.
# 4) Dispatch provision-e2e — it converges .thoryn/provision.yaml and destroys it on exit.
```

No standing test user and no standing sandbox are needed any more: the provisioning file
creates (or adopts) the sandbox and the client per run.

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
