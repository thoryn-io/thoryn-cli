# thoryn — Thoryn customer-plane CLI

`thoryn` is the Thoryn customer-plane CLI. It runs the same OAuth flow
the web console runs, stores tokens in the OS keychain, and calls the
gateway endpoints that back the console's tenant-admin surfaces.

Built with picocli + GraalVM native image per
ADR 2026-04-25-customer-plane-product-api § 4 / § 8 / and RFC 8252 § 7.3 +
RFC 7636 + RFC 8628.

> **Authoritative docs live in Antora**: see `docs/modules/ROOT/pages/cli/`
> for the user-facing pages — this README is the developer-facing entry
> point.

## Command tree

```
thoryn login                                 # Auth code + PKCE (loopback) or --device-code
thoryn login --client-credentials --client-id <id>   # SSO-1553 — non-interactive (CI/automation)
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
# tenant:audit.read, tenant:environments.{read,write}) so `clients`, `federation`,
# `audit`, and `env` (SSO-2870) work out of the box. `workspace` rides on
# SCOPE_openid (the hub /account surface). The hub drops any scope the tenant
# admin doesn't actually hold.
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

## Non-interactive auth & tenant seeding (SSO-1553)

For CI / automation there is a fully non-interactive path — no browser, no
second device:

```bash
# Service-account login (RFC 6749 §4.4 client-credentials). Secret from env,
# NEVER argv. --issuer MUST be the tenant subdomain so the hub mints `tnt`.
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

## Build

```bash
# Compile + tests
./mvnw -pl tools/cli test

# Shaded fat jar (run via java -jar)
./mvnw -pl tools/cli package
java -jar tools/cli/target/thoryn.jar login --status

# GraalVM native image (SSO-733; per-OS/arch matrix on CI)
./mvnw -pl tools/cli -Pnative -DskipTests package
./tools/cli/target/thoryn workspace list --hub https://hub.stg.thoryn.org
```

## Module layout

```
tools/cli/
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
