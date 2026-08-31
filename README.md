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

# Tenant seeding (SSO-1553) — one-shot, zero-interaction provisioner for CI.
thoryn tenant seed --non-interactive --secret-dir <dir> \
                   [--clients <N>] [--skip-federation] \
                   [--tenant-id <uuid> --slug <slug>] [--gateway <url>]

thoryn audit query [--from <ts>] [--to <ts>] [--event-type <t>] [--actor <sub>] [--limit <n>]

thoryn audit-replay <receipt.json>           # SSO-940b — offline replay tool

thoryn supply-chain credential-types catalog # SSO-1593 — adopt platform credential types
thoryn supply-chain credential-types list
thoryn supply-chain credential-types enable <slug> [--name --description --background-color --text-color --logo-uri]
thoryn supply-chain credential-types disable <slug>

thoryn supply-chain trust-registry list      # SSO-954 / SSO-959 — Trust Registry
thoryn supply-chain trust-registry preview
thoryn supply-chain trust-registry add
thoryn supply-chain trust-registry remove

thoryn supply-chain policy list              # SSO-955 / SSO-959 — Verification policy
thoryn supply-chain policy show
thoryn supply-chain policy set

thoryn supply-chain audit search             # SSO-956 / SSO-959 — Walletless audit log
thoryn supply-chain audit get <auditRowId>
thoryn supply-chain audit receipt <id>           # JSON receipt to stdout (or `-o file`)
thoryn supply-chain audit receipt <id> --pdf     # Binary PDF/A-3 to stdout
thoryn supply-chain audit replay <auditRowId>    # alias for `thoryn audit-replay`

thoryn supply-chain issuer-bridge list       # SSO-957 / SSO-959 — Issuer-bridge ops
thoryn supply-chain issuer-bridge show <bridgeId>
thoryn supply-chain issuer-bridge credentials --bridge-id <id> ...
thoryn supply-chain issuer-bridge revoke --bridge-id <id> --credential-id <cid> --reason "..."
thoryn supply-chain issuer-bridge rotate-key --bridge-id <id> --step <step>

thoryn supply-chain chain receive     --bridge-id <id> --parent-jws <...>   # SSO-970 — chain-of-custody
thoryn supply-chain chain issue       --bridge-id <id> --parent <urn> --action processed_combined ...
thoryn supply-chain chain split       --bridge-id <id> --parent <urn> --template <id> --count <N> --output-zip <file>
thoryn supply-chain chain walk        <leaf-urn> [--depth 5]
thoryn supply-chain chain revoke      <urn> --reason "..." [--dry-run]
thoryn supply-chain chain descendants <urn> [--holder] [--depth 5]
```

Every `supply-chain` leaf and every tenant-config leaf (`clients`,
`federation`, `workspace`, `audit`) accepts `--output {table,json,yaml}`
(default `table`). Errors go to stderr with non-zero exit code; on
`--output json` errors emit structured JSON on stdout.

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
# tenant:audit.read) so `clients`, `federation`, and `audit` work out of the
# box. `workspace` rides on SCOPE_openid (the hub /account surface). The hub
# drops any scope the tenant admin doesn't actually hold.
oathy login

# Grab the whole tenant-config scope set explicitly.
oathy login --scope all-tenant-config

# Headless (no browser).
export THORYN_CLIENT_SECRET=...
oathy login --device-code

# Grab every supply-chain scope in one shot.
oathy login --scope all-supply-chain

# Single supply-chain scope.
oathy login --scope tenant:supply-chain.trust-registry.write

# Multiple, comma-separated.
oathy login --scope tenant:supply-chain.audit.read,tenant:supply-chain.policy.read
```

The wildcard `all-supply-chain` expands client-side per
`ScopeRegistry.kt` to the literal supply-chain scope set. The hub does
NOT understand the wildcard — it's a CLI ergonomic.

When a command rejects with `insufficient_scope`, the CLI prints the
exact `oathy login --scope <required>` line to fix it.

## Non-interactive auth & tenant seeding (SSO-1553)

For CI / automation there is a fully non-interactive path — no browser, no
second device:

```bash
# Service-account login (RFC 6749 §4.4 client-credentials). Secret from env,
# NEVER argv. --issuer MUST be the tenant subdomain so the hub mints `tnt`.
export THORYN_CLIENT_SECRET="$CI_SERVICE_ACCOUNT_SECRET"
oathy login --client-credentials --client-id ci-bot \
  --issuer https://acme.hub.stg.thoryn.org \
  --scope "tenant:applications.write tenant:federation.write"

# One-shot tenant seed: sample OAuth clients + identity-service federation member.
export THORYN_FEDERATION_SECRET="$CI_IDENTITY_SERVICE_SECRET"
oathy tenant seed --non-interactive --secret-dir ./seed-secrets \
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
   workspace is a user/OpenID flow — use `oathy workspace create` for that.

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
oathy login --device-code
```

The fallback writes a chmod-0600 JSON file to
`~/.config/thoryn/tokens.json` (Linux/macOS) or
`%APPDATA%/thoryn/tokens.json` (Windows). Override the path with
`THORYN_TOKEN_FILE=/path/to/tokens.json`.

## Build

```bash
# Compile + tests
./mvnw -pl tools/cli test

# Shaded fat jar (run via java -jar)
./mvnw -pl tools/cli package
java -jar tools/cli/target/thoryn.jar supply-chain trust-registry list \
    --credential-class FSISustainabilityCertification

# GraalVM native image (SSO-733; per-OS/arch matrix on CI)
./mvnw -pl tools/cli -Pnative -DskipTests package
./tools/cli/target/thoryn supply-chain trust-registry list \
    --credential-class FSISustainabilityCertification
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
    │   │   ├── AuditReplayCommand.kt                        # SSO-940b
    │   │   └── supplychain/                                 # SSO-959 command tree
    │   │       ├── SupplyChainCommand.kt                    # parent
    │   │       ├── SupplyChainCommandSupport.kt             # shared helpers
    │   │       ├── TrustRegistryCommand.kt                  # SSO-954
    │   │       ├── PolicyCommand.kt                         # SSO-955
    │   │       ├── AuditCommand.kt                          # SSO-956
    │   │       ├── IssuerBridgeCommand.kt                   # SSO-957
    │   │       └── chain/                                   # SSO-970 chain-of-custody
    │   │           ├── ChainCommand.kt                      # parent
    │   │           ├── ChainTreeRenderer.kt                 # ASCII DAG tree
    │   │           ├── ReceiveCommand.kt                    # SSO-962
    │   │           ├── IssueCommand.kt                      # SSO-962 combine
    │   │           ├── SplitCommand.kt                      # SSO-962 split + SSO-963
    │   │           ├── WalkCommand.kt                       # SSO-964
    │   │           ├── RevokeCommand.kt                     # SSO-965
    │   │           └── DescendantsCommand.kt                # SSO-965 / SSO-967
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
* New supply-chain subcommands use only `java.net.http.HttpClient` +
  Jackson 3 + picocli, all of which are already native-image-ready.

## Related

* `docs/modules/ROOT/pages/cli/index.adoc` — top-level user docs
* `docs/modules/ROOT/pages/cli/tenant-configuration.adoc` — SSO-1552 clients/federation/workspace/audit
* `docs/modules/ROOT/pages/cli/non-interactive-automation.adoc` — SSO-1553 client-credentials + tenant seed
* `docs/modules/ROOT/pages/cli/supply-chain.adoc` — SSO-959 user docs
* `docs/modules/ROOT/pages/cli/supply-chain-chain.adoc` — SSO-970 chain-of-custody user docs
* ADR `adrs/2026-04-25-customer-plane-product-api.md`
* ADR `adrs/2026-05-10-supply-chain-self-service-namespacing.md`
* ADR `adrs/2026-05-11-credential-chain-of-custody-with-fan-in-and-split.md`
