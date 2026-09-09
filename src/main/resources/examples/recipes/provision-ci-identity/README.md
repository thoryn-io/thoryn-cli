# `provision-ci-identity` recipe (founder-run bootstrap)

A declarative Thoryn recipe that **mints the CI's own confidential `client_credentials` machine
client** through the customer plane — the same product workflow a real customer follows to create a
CI credential (recipes are data, not code; the CLI is the only executor, dispatching on a closed
action allowlist).

It is the **as-code machine-client bootstrap** of epic SSO-2947
([ADR 2026-09-09](https://github.com/thoryn-io/oauthy/blob/main/adrs/2026-09-09-thoryn-cli-as-code-ci-connection-contract.md)).
A **founder runs it once**, interactively, to provision the identity that the CLI's connection
contract (SSO-2948, `thoryn login --connection`) then binds to on every CI run.

```
thoryn examples apply provision-ci-identity --secret-file ci.secret
```

## What it provisions

1. **A confidential `client_credentials` machine client** (`clients.createMachine`) — the same
   product-api `POST /api/v1/applications` call `thoryn clients create` makes, granting the broad
   machine scope set the CI identity needs:
   `tenant:applications.write/read`, `tenant:federation.write/read`, `tenant:users.write/read`,
   `tenant:env.write/read`.

That's it. No workspace, no user — a founder runs this signed into the standing `thoryn` workspace
via browser OIDC, so the client is minted under that workspace's `tnt`.

## The security boundary (why this recipe needed an ADR)

`clients.createMachine` is the **only** allowlisted recipe action permitted to surface a secret.
Extending recipes to create a secret-bearing client changes the recipe trust model — recipes were
**data producing secret-free receipts** ([ADR 2026-09-05](https://github.com/thoryn-io/oauthy/blob/main/adrs/2026-09-05-recipe-receipt-attestation-trust-model.md)).
This recipe preserves that invariant:

- The minted `client_secret` exits **exclusively** through the CLI's `SecretIo` channel — a
  `--secret-file` (owner-only), or a guarded/interactive stdout (a WARN on a TTY; **refused** on a
  non-interactive pipe unless `--force-stdout`) — exactly as `thoryn clients create`.
- The **receipt records only the non-secret shape**: the `clientId` and the granted scopes. The
  secret is **never** written to the receipt, a step output (`{{...}}`), a log, or argv.

## End-to-end flow

- **Once (founder, interactive):** sign in to the `thoryn` workspace via browser OIDC →
  `thoryn examples apply provision-ci-identity --secret-file ci.secret` → paste the printed
  `clientId` into `.thoryn/connection.json` (commit it — a client id is not a secret), paste the
  secret from `ci.secret` into the `THORYN_CLI_CI_CLIENT_SECRET` GitHub secret, then `shred ci.secret`.
- **Every CI run:** `thoryn login --connection .thoryn/connection.json` → a tenant-scoped token with
  exactly the declared scopes → recipes run.

## Parameters

| Param     | Required | Meaning                                                                    |
|-----------|----------|----------------------------------------------------------------------------|
| `appName` | no       | Display name for the CI machine client (cosmetic; the `clientId` is server-generated). Defaults to `Thoryn CLI CI machine identity`. |

## Rotation, not teardown

There is deliberately **no teardown**: the machine client is a **standing** credential. Rotate its
secret with `thoryn clients rotate-secret <clientId>` (24h graceful overlap) rather than
deleting and re-creating it. If the standing privilege in the primary workspace is uncomfortable,
bind the connection contract to a dedicated `thoryn-cli-ci` workspace instead (the documented escape
hatch in the ADR).
