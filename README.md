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
thoryn login --workspace <slug> [--issuer https://hub.<env>]  # Auth code + PKCE (loopback) or --device-code — ON your workspace (SSO-3104)
thoryn login --client-credentials [--client-id <id>] # SSO-1553/2941 — non-interactive API key (CI); THORYN_API_KEY=<id>:<secret>, auto re-mints on expiry
thoryn login --status
thoryn logout [--rotate-key]                 # SSO-3199 — --rotate-key also discards this machine's DPoP key
thoryn whoami                                # SSO-2860/3199/3228 — identity, scopes, expiry, the DPoP key thumbprint + this device's name
thoryn devices list                          # SSO-3228 — the machines signed in to your account, with each key's recent networks
thoryn devices revoke <id|name> [--reason r] # Ends THAT machine's sessions and refuses its key; your other devices keep working

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
thoryn provision plan    [--file <path>] [--prune]                                  # read-only: what apply would create / remove (+ grant changes)
thoryn provision apply   [--file <path>] [--prune] [--confirm <ws>] [--yes] \
                         [--secret-file <path>] [--force-stdout]                   # converge; environments first, dependants into them.
                                             # SSO-3113 — a confidential application it CREATES gets a one-time client secret, delivered via
                                             # SecretIo (--secret-file, or an interactive TTY; a pipe is refused unless --force-stdout); undeliverable
                                             # ⇒ the client is still recorded, exit 65, `thoryn clients rotate-secret <id>` named. A resource's
                                             # `grants:` block is converged with it (see "Least-privilege access grants").
thoryn provision destroy [--file <path>|--receipt <path>] [--confirm <ws>] [--yes] # remove everything owned, child-first (sandbox hard-delete cascades)

# Least-privilege access grants (SSO-3113, epic SSO-3108) — who may manage / view which resource.
# Thin wrappers over product-api /api/v1/access (the SSO-3112 contract). Subjects: member:<sub> | client:<clientId>;
# objects: workspace:<tenantId> | environment:<id> | application:<clientId> | user:<id> | federation_member:<id> |
# email_provider:<envSlug> | login_theme:<envSlug> | login_flow:<envSlug> | login_methods:<envSlug>; relations: manager | viewer.
# Scopes: tenant:access.read (list, mine) / tenant:access.write (grant, revoke).
thoryn access grant  <subject> <relation> <object>   # POST   /api/v1/access/grants  (idempotent: 201, or 200 when it already exists)
thoryn access revoke <subject> <relation> <object>   # DELETE /api/v1/access/grants  (grant identified in the JSON body; 204)
thoryn access list   [--object <ref>] [--subject <ref>]   # GET /api/v1/access/grants?object=…|subject=…
thoryn access mine   [--type <objectType>] [--relation <relation>]   # GET /api/v1/access/mine — the objects YOU hold a relation on
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

### Least-privilege access grants (SSO-3113, epic SSO-3108)

A **grant** is `subject → relation → object`: `client:cli-ci manager environment:<id>` says the
machine client `cli-ci` may manage that one sandbox and nothing else. It is the unit a
**least-privilege CI identity** is confined with — instead of a machine client holding every
`tenant:*` scope across the whole workspace, it is made `manager` of exactly the sandbox it
provisions. Two surfaces, one grammar:

- **`thoryn access grant | revoke | list | mine`** — imperative, for a founder wiring things up
  or inspecting who can reach what. `list` needs `--object` and/or `--subject`; `mine` answers
  for the session's own subject (`{ "data": [ "environment:<id>", … ] }`).
- **`grants:` on a resource in `provision.yaml`** — declarative, converged by `provision apply`
  like any other field. The **object is implicit** (it derives from the receipt id the resource
  resolves to — `environment:<id>`, `application:<clientId>`, `user:<id>`,
  `federation_member:<id>`, and the per-environment singletons by their env slug —
  `email_provider:<envSlug>`, `login_theme:…`, `login_flow:…`, `login_methods:…`), so a file can
  never grant on an object it does not own:

  ```yaml
  - kind: environment
    name: ci
    spec: { slug: cli-ci, displayName: "thoryn-cli CI sandbox" }
    grants:
      - { subject: "client:cli-ci", relation: manager }   # the CI identity manages ONLY this sandbox
  ```

  After the resource exists (create / adopt / update / even a no-op), `apply` lists the object's
  grants (`GET /api/v1/access/grants?object=…`), **POSTs the missing ones and DELETEs the ones the
  file no longer declares — on that object only**. Grants on objects the file does not own are
  never touched, and the workspace admin userset (`workspace:<id>#admin`) is never revoked. Omit
  `grants:` to leave an object's grants unmanaged; `grants: []` declares none. `plan` prints the
  grant diff (`grant + client:cli-ci manager`) and counts it. A session without
  `tenant:access.write` **fails closed** with the scope named — the resource itself is already
  recorded in the receipt by then, so nothing is lost; re-run after `thoryn login --scope
  tenant:access.write` (or after granting the CI client that scope).

Since SSO-3182 the two scopes are part of the DEFAULT `thoryn login` scope set (the default set is
exactly the `cli` login client's registered scopes in `.thoryn/provision.yaml`, which the product side
deployed to the hub under SSO-3112), so a bare `thoryn login --workspace <slug>` can converge a file
with `grants:` — no hand-typed `--scope` list.

### A provisioned confidential client's secret (SSO-3113)

A confidential `application` (product-api's default `clientType`; a `client_credentials` machine
identity) is minted a **one-time `client_secret`** on create. `provision apply` routes it through
the same `SecretIo` channel as `thoryn clients create`: written to `--secret-file <path>`
(owner-only `0600`; a second confidential client in the same apply lands at `<path>.<clientId>`),
or printed to an interactive TTY with a `WARNING`; a non-interactive stdout is refused unless
`--force-stdout`. The secret never enters the receipt, the plan, or a log — receipts stay
secret-free by construction. If it cannot be delivered the client is **still created and
recorded** (it exists), and `apply` exits **65** naming
`thoryn clients rotate-secret <clientId> --secret-file <path>` to mint a fresh one. `plan` marks
such a create with `(a client secret will be minted and shown once)`.

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

### Which platform? (SSO-3182)

The CLI has **no built-in hub** — it never defaults to `localhost`. `thoryn login` resolves the hub
BASE URL (`https://hub.<env>`) in this order:

1. `--issuer <url>`;
2. the `THORYN_HUB` environment variable;
3. the hub of your previous sign-in on this machine (so after the first `--issuer` login,
   `thoryn login --workspace <slug>` alone reaches the same platform);
4. a production hub baked into the release — **not set yet** (the production domain is a product
   decision; `ThorynConfig.PLATFORM_HUB`).

With none of them the command exits 65 and tells you how to name one — it does not dial anything.

```bash
thoryn login --workspace thoryn --issuer https://hub.stg.thoryn.org   # Thoryn staging
export THORYN_HUB=https://hub.stg.thoryn.org && thoryn login --workspace thoryn
thoryn login --workspace dev --issuer http://localhost:54702          # a hub on your own machine
```

```bash
# Default scopes (SSO-3182): EXACTLY the `cli` login client's registered set — openid,
# offline_access and the whole tenant-config surface (applications, clients, users,
# federation, audit, environments, email, idp, access). A bare login therefore authorizes
# `clients`, `federation`, `audit`, `env`, `workspace email-provider`, `branding`, `access`
# and `provision apply` (including a file's `grants:` block) with no --scope list.
# `workspace` rides on SCOPE_openid (the hub /account surface). The hub mints only the
# scopes the signing-in admin actually holds.
# SSO-3104 — sign-in is always ON A WORKSPACE (`https://<slug>.hub.<env>`, client `cli`,
# provisioned in the `thoryn` workspace by this repo's .thoryn/provision.yaml); the shared
# default tenant is not a sign-in target. `--workspace` or `export THORYN_WORKSPACE=<slug>`.
thoryn login --workspace thoryn --issuer https://hub.stg.thoryn.org

# Grab the whole tenant-config scope set explicitly.
thoryn login --workspace thoryn --scope all-tenant-config

# Headless (no browser).
thoryn login --workspace thoryn --device-code
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

The **DPoP key** (below) follows the same rules and the same opt-in: a second
keychain entry (service `thoryn`, account `dpop-key`), or `dpop-key.json` beside
the token file under the CI fallback (`THORYN_DPOP_KEY_FILE` overrides the path).
Without a keychain and without the opt-in the CLI refuses to write the private
key in plaintext and simply sends no DPoP proof.

## Sender-constrained tokens (DPoP, SSO-3199)

The CLI proves possession of a private key on every token request and every API
call, per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449). An access token
the hub binds to that key (`cnf.jkt`) is useless to anyone who steals the token
alone — which is the residual risk refresh-token rotation cannot close (RFC 9700
§2.2.2 accepts *either* rotation *or* sender-constraining; Thoryn ships both).

**What happens, concretely.**

* On first use the CLI generates a **per-installation** EC P-256 (ES256) key pair
  and stores the private key in the same secure store as your tokens. It is never
  printed, never written to a receipt, and never leaves the machine — only the
  public JWK travels, inside the proof.
* **Only against a platform that advertises DPoP** (SSO-3221). Before attaching a
  proof to a token request the CLI reads the hub's
  `/.well-known/openid-configuration` and looks for a non-empty
  `dpop_signing_alg_values_supported` — the field RFC 9449 §5.1 defines as the
  advertisement of DPoP support. One small `GET`, memoised per hub for the life
  of the process, and only on a command that reaches the token endpoint. No
  advertisement — or an unreachable hub — means no proof, which is exactly the
  wire shape of a CLI that had never heard of DPoP.
* Every request to `/oauth2/token` (login code redemption, `refresh_token`, the
  workspace-switch exchange, device-code polling, client-credentials) and every
  hub / gateway API call then carries a freshly signed `DPoP:` proof JWT
  (`typ: dpop+jwt`, `jwk`, `htm`, `htu`, `iat`, `jti`, plus `ath` when a bound
  token is presented).
* If a server demands a nonce (`use_dpop_nonce`, RFC 9449 §8) the CLI caches the
  `DPoP-Nonce` per origin and retries the request once, automatically.
* The token is presented as `Authorization: DPoP <token>` **only when the hub
  answered `token_type: DPoP`**; otherwise it stays `Bearer`.

> **Why the capability check exists.** `cli-v0.20.0` shipped the proof without
> one, on the argument that the presentation scheme is server-driven so nothing
> changes until the hub flips the `cli` client. That was true of the CLI and
> wrong about the hub: Spring Authorization Server binds the token and answers
> `token_type: DPoP` **as soon as a valid proof arrives**, whatever the client's
> `dpop_required` flag says. So the CLI's own proof flipped the answer, the CLI
> faithfully followed its own flip, and it began presenting `DPoP <token>` to
> resource servers that did not accept the scheme — every customer-plane call
> answered `401`, and every scheduled thoryn-examples run went red from
> 2026-09-19 04:23 UTC. The hub half of SSO-3221 stops binding unless the client
> opted in; this check is the redundant client half, because a released binary
> outlives any single platform version.

```bash
thoryn whoami --output table
# …
# dpopKeyThumbprint  9mS2kYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4IZcOC
# dpopBound          no (bearer token — the hub does not bind this client's tokens yet)
```

Once the hub marks the `cli` client `dpop_required` and binds `cnf.jkt`,
`dpopBound` reads `yes (cnf.jkt matches this installation's key)`. A `MISMATCH`
means the stored token belongs to another installation (or the key was rotated
since it was issued) — run `thoryn login` again.

### Devices (SSO-3228)

The key stays on the machine, so it stands in for the machine. When a login
produces a **bound** token, the CLI registers that key as a named **device** —
hostname by default, `thoryn login --device-name "alice work laptop"` to choose:

```bash
thoryn devices list
# NAME         ID    CLIENT  LAST SEEN             NETWORKS                STATUS
# alice-mbp    d-1   cli     2026-09-19T09:41:00Z  203.0.113, 198.51.100   active
# (unregistered)  -  cli     2026-08-30T17:15:00Z  192.0.2                 unregistered

thoryn devices revoke alice-mbp --reason "left on a train"
```

Revoking ends **that machine's** sessions and refuses its key from then on; every
other machine you are signed in on keeps working. It cannot be undone for that
key — signing in from that machine again generates a new key and registers a new
device. The networks are coarse prefixes (IPv4 /24, IPv6 /48), the same record
the platform's own per-key anomaly signals read.

Registration never fails a sign-in: against a hub that does not have the endpoint,
or when the token is not bound, the CLI notes it on stderr and you are signed in
regardless — `thoryn devices list` simply shows that key as unregistered.

**Rotating the key.** `thoryn logout` keeps the key by default: on its own it
authorises nothing, and keeping it means your next login re-binds to the same
`jkt`. `thoryn logout --rotate-key` discards it, so the next login generates a
new one and every token bound to the old thumbprint stops working — the right
move when handing the machine on or if the key may have leaked.

**Hub-side flip.** Requiring proofs is the *other half* of SSO-3199 and lives in
`oathy` (step 2): flip `dpop_required=true` on the `cli` client and require
`cnf.jkt`-bound tokens at product-api / api-gateway. It is deliberately a
separate, later change so CLIs released before it keep working; the minimum CLI
version for the flip is the first `cli-v*` release containing this feature.

### Key classes — where the private key lives (SSO-3227)

DPoP stops **token** theft: a stolen access token is useless without a proof
signed by your key. It does not, on its own, stop malware running as you on your
own workstation — that can simply ask the keychain to sign proofs. The answer is
a key the keychain cannot hand over and a signature that needs a human. The CLI
now picks the strongest option the machine actually supports and **tells you
which one it got**:

| class | where the private key lives | what it buys |
|---|---|---|
| `secure_element` | Apple Secure Enclave (macOS) | non-exportable — the key material never exists outside the secure hardware — and every signature requires user presence (Touch ID, Watch, or your password) |
| `software_keychain` | OS keychain (the SSO-3199 behaviour) | protects against token theft; a process running as you can still ask the keychain to sign |
| `ephemeral` | process memory only | nothing — see below |

```bash
thoryn whoami --output table
# …
# dpopKeyThumbprint  9mS2kYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4IZcOC
# dpopKeyClass       software_keychain — software key in the OS keychain (secure_element unavailable: …)
# dpopBound          yes (cnf.jkt matches this installation's key)
```

`thoryn status` reports `dpopKeyClass` too. When the CLI falls back, the line
carries **why** the stronger class was passed over — that reason is the half you
can act on.

**`ephemeral` never sends a proof.** A key that dies with the process cannot
honour a `cnf.jkt` minted at login on your *next* command, so binding a token to
one would break every subsequent invocation. On a machine with neither a secure
element nor a usable keychain the CLI therefore sends **no** proof at all — the
pre-SSO-3199 wire shape — and says so once. The class exists so `whoami` can
name that state rather than report nothing.

**Presence prompts: once per session, not per request.** All the proofs one
command mints (a token request plus its API calls) go through one key handle, so
a command asks at most once. Across commands the CLI keeps a timestamp of the
last presence-backed signature and stays quiet inside an idle window — 15 minutes
by default, `THORYN_DPOP_PRESENCE_IDLE_MINUTES` to change it — after which it
prints one line explaining the prompt you are about to see. Note the honest
boundary: *macOS* decides when LocalAuthentication actually shows its dialog, and
because each `thoryn` invocation is a separate short-lived process, the only
supported way to widen OS-side reuse (an `LAContext`) cannot outlive one command
either. Cross-process presence reuse needs a resident agent and is a follow-up.

**Never in CI.** A hardware key is refused outright when there is no interactive
terminal — `CI` is set, `THORYN_NON_INTERACTIVE` is set, or stdin/stderr are not
TTYs — because a pipeline cannot answer a fingerprint prompt. The CLI degrades to
the software keychain with a one-line notice rather than hanging on a dialog
nobody will see. (The check is `isatty(3)`, not `System.console() != null`: since
JDK 19 the latter returns non-null on a pipe, and `Console.isTerminal()` — the
correct API — is JDK 22, while this project ships on JDK 21.)

**Migration is on login, never mid-session.** An existing software key keeps
working untouched. Only `thoryn login` is allowed to *create* a hardware key, so
a session already signing with a software key keeps the key its live token is
bound to, and the upgrade lands on the next sign-in. `thoryn logout
--rotate-key` deletes the key of **every** class, plus the presence timestamp —
a migrated machine can hold both, and "rotate" has to mean nothing survives.

**Per-OS status, honestly.**

* **macOS — implemented.** Secure Enclave P-256 via `Security.framework`
  (`kSecAttrTokenIDSecureEnclave`, `SecAccessControlCreateWithFlags` with
  `kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence`, signing
  through `SecKeyCreateSignature`), bound with JNA — already a dependency, already
  in the native image, already how the keychain backend calls the same framework.
  **It does not engage in a released binary yet:** persisting a Secure Enclave key
  needs the calling binary to be code-signed with a keychain-access-group
  entitlement, and the published `thoryn` binaries are not signed or notarised.
  Without it macOS returns `errSecMissingEntitlement (-34018)` on the *store*
  step, the CLI reports that as the skip reason, and you get the software key.
  Code-signing the macOS binary is the follow-up that switches this on.
* **Windows / Linux — not built.** TPM via the Windows Hello platform crypto
  provider, and TPM2 via `tpm2-pkcs11`, are the intended backends. They are not
  stubbed in: neither can be built or exercised on the machine this was written
  on, and a backend that has never run is a claim rather than an implementation.
  They report `this platform has no supported secure element` and slot into the
  same `DpopKeyProvider` seam when they land, with nothing above it changing.

**`key_class` on the wire is telemetry only.** The proof header carries a
`key_class` hint so the platform can see how much of the fleet is hardware-backed.
It is **self-asserted by the client and must never be trusted**: any server making
an authorization decision on it would be trusting an attacker-chosen string. It
was verified to be safe to send against Spring Authorization Server's real proof
parser (`DPoPProofJwtDecoderFactory`) before being added.

## Session endpoints (SSO-2827)

`thoryn login` records the hub issuer (`--issuer`) and the customer-plane
gateway alongside the token, so the other commands default to them — you do
**not** need to repeat `--hub` / `--gateway` on every call after signing in:

```bash
thoryn login --workspace acme --issuer https://hub.stg.thoryn.org  # records hub + gateway for the session
thoryn workspace list                                              # uses the session hub, no --hub needed
thoryn clients list                                                # uses the session gateway, no --gateway needed
```

The session also remembers the WORKSPACE it signed in on, so when it can no longer be renewed the CLI
prints the exact line to fix it (`Run \`thoryn login --workspace acme\``) instead of a bare `HTTP 401`.

The gateway is derived from the hub host (`hub.<env>` → `api.<env>`); for a
non-standard topology set it explicitly at login with `--gateway <url>`. An
explicit `--hub` / `--gateway` on any command still overrides the session.

## Session renewal (SSO-2834 / SSO-2861 / SSO-3182)

The access token lives ~15 minutes. When a session carries a refresh token (interactive logins ask for
`offline_access`), the CLI renews it transparently — proactively near expiry and reactively on a `401`
— **before** a command runs and before a `workspace switch` token exchange, so a switched workspace
never outlives the home session. A client-credentials / API-key session has no refresh token by
design (RFC 6749 §4.4.3) and is re-minted from `THORYN_API_KEY` / `THORYN_CLIENT_SECRET`.

When renewal is impossible the CLI now says so, once, with the exact command:

```
Your sign-in session has expired and carries no refresh token, so it cannot be renewed.
Run `thoryn login --workspace thoryn` to sign in again.
```

**Caveat (hub-side).** The authorization server issues **no refresh token to a public client on the
authorization-code grant** (Spring Authorization Server's `OAuth2RefreshTokenGenerator`), and the CLI's
`cli` login client is a public RFC 8252 native client. A loopback `thoryn login` session therefore ends
at the access-token expiry today; `thoryn login --device-code` sessions do receive a refresh token and
renew. The CLI prints a note right after a sign-in that received none. Making public-client
authorization-code logins refreshable (rotation + replay detection, OAuth 2.1 §4.3.1) is a hub change.

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

The former **`ci-signin`** recipe (SSO-2944, the workspace-less CI sibling) is **retired**
(SSO-3092): this repo's own CI converges `.thoryn/provision.yaml` with `thoryn provision apply`
(see below), and the `thoryn-examples` scenarios provision through their recipes' `provision:`
file. A recipe that needs a throwaway environment inside the workspace you signed in to declares
it in its provisioning file instead.

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
# 0) Sign in interactively as an admin of the `thoryn` workspace (authorization-code + PKCE). The
#    default scope set already covers every scope the provisioning file grants (SSO-3182); the hub
#    only lets you grant what you hold.
thoryn login --workspace thoryn --issuer https://hub.stg.thoryn.org

# 1) Apply. The declared confidential client is created and its secret delivered ONCE, via SecretIo.
#    (SSO-3113 retired the imperative `provision ci-identity` bootstrap: the identity is a resource.)
thoryn provision apply --file .thoryn/provision.yaml --secret-file ci.secret

# 2) Set the GitHub secret named by auth.secretEnv to the contents of ci.secret; shred ci.secret.
# 3) Dispatch provision-e2e — it converges .thoryn/provision.yaml, asserts the CI identity is confined,
#    and removes what the run created on exit (the sandbox is a long-lived fixture and stays).
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
    │   │   ├── DpopKey.kt + DpopKeyStore.kt                 # SSO-3199 RFC 9449 installation key (ES256)
    │   │   ├── DpopSession.kt                               # SSO-3199 proof JWTs + DPoP-Nonce retry
    │   │   ├── DpopCapability.kt                            # SSO-3221 send proofs only where discovery advertises DPoP
    │   │   ├── Tokens.kt
    │   │   └── ScopeRegistry.kt                             # SSO-959 scope wildcards
    │   ├── api/
    │   │   └── ProductApiClient.kt                          # SSO-959 typed HTTP client
    │   ├── cmd/
    │   │   ├── LoginCommand.kt + LogoutCommand.kt
    │   │   ├── CommandSupport.kt                            # SSO-1552 shared token/output/error helpers
    │   │   ├── SecretIo.kt + FileSecrets.kt                 # SSO-1552 secret-safety (no-echo / --secret-file)
    │   │   ├── AccessCommand.kt                             # SSO-3113 `access grant|revoke|list|mine` (least-privilege grants)
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
* DPoP (SSO-3199) adds no dependency: the proof is signed with the JDK's own
  `KeyPairGenerator("EC")` / `Signature("SHA256withECDSA")`. Key *generation* is
  the one new JCA surface (verification via `SHA256withECDSA` already shipped in
  `Es256JwsVerifier`); `StoredDpopKey` is registered in `reflect-config.json`
  alongside `Tokens` so the keychain payload (de)serialises in the native image.

## Related

* `docs/modules/ROOT/pages/cli/index.adoc` — top-level user docs
* `docs/modules/ROOT/pages/cli/tenant-configuration.adoc` — SSO-1552 clients/federation/workspace/audit
* `docs/modules/ROOT/pages/cli/non-interactive-automation.adoc` — SSO-1553 client-credentials + tenant seed
* ADR `adrs/2026-04-25-customer-plane-product-api.md`
