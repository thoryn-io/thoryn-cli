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
thoryn login --status
thoryn logout
thoryn clients list                          # Workforce-era smoke test
thoryn audit-replay <receipt.json>           # SSO-940b — offline replay tool

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

Every `supply-chain` leaf accepts `--output {table,json,yaml}` (default
`table`). Errors go to stderr with non-zero exit code; on `--output json`
errors emit structured JSON on stdout.

## Authentication

```bash
# Default: workforce-era scopes (openid offline_access + tenant:clients.read
# + tenant:users.read).
oathy login

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
    │   │   ├── LoopbackRedirectServer.kt                    # RFC 8252 §7.3
    │   │   ├── PkceUtil.kt                                  # RFC 7636
    │   │   ├── TokenStore.kt + KeychainTokenStore.kt        # ADR 2026-04-25 §4
    │   │   ├── Tokens.kt
    │   │   └── ScopeRegistry.kt                             # SSO-959 scope wildcards
    │   ├── api/
    │   │   └── ProductApiClient.kt                          # SSO-959 typed HTTP client
    │   ├── cmd/
    │   │   ├── LoginCommand.kt + LogoutCommand.kt
    │   │   ├── ClientsCommand.kt                            # workforce-era
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
* `docs/modules/ROOT/pages/cli/supply-chain.adoc` — SSO-959 user docs
* `docs/modules/ROOT/pages/cli/supply-chain-chain.adoc` — SSO-970 chain-of-custody user docs
* ADR `adrs/2026-04-25-customer-plane-product-api.md`
* ADR `adrs/2026-05-10-supply-chain-self-service-namespacing.md`
* ADR `adrs/2026-05-11-credential-chain-of-custody-with-fan-in-and-split.md`
