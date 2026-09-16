# `.thoryn/` — this repo's as-code binding to Thoryn (SSO-2951 + SSO-3090)

One folder, two halves, both **data** (schema-validated by the CLI), both committed. This repo is
the **reference consumer** of the very verbs it ships: a customer binds a repository to Thoryn with
the same two files and the same commands.

| File | Declares | Schema | Verb |
|---|---|---|---|
| `connection.json` | **who I am** — the `thoryn` workspace, the CI machine client id, the *name* of the env var carrying its secret, the exact scope set | `src/main/resources/examples/connection.schema.json` (SSO-2948) | `thoryn login --connection .thoryn/connection.json` |
| `provision.yaml` | **what I own** — the desired state: the CLI's own login client `cli` and the least-privilege CI identity `cli-ci` in the `thoryn` workspace (SSO-3104 / SSO-3113), plus a sandbox environment `cli-ci` with a public loopback OAuth client inside it | `src/main/resources/provision/provision.schema.json` (SSO-3088) | `thoryn provision plan / apply / destroy --file .thoryn/provision.yaml` |

The provisioning Action (`.github/actions/provision`) runs, in order:

```bash
thoryn login --connection .thoryn/connection.json      # who I am
thoryn provision plan   --file .thoryn/provision.yaml  # what would change (read-only)
thoryn provision apply  --file .thoryn/provision.yaml --yes   # converge — twice = no writes
# … the job uses the outputs (environment, client-id, issuer) …
thoryn provision destroy --file .thoryn/provision.yaml --yes  # child-first; sandbox hard-delete cascades
```

The receipt (`provision.receipt.json`, written next to the file, git-ignored) is the ownership
ledger: `destroy` removes only what it records, and a resource that already existed when `apply`
ran is **adopted** (converged, never deleted). No secret ever lives in either file — `connection.json`
carries only the env-var *name*, and `provision.yaml` needs none (a file that did would use
`passwordEnv` / `{{env.NAME}}`).

## The CLI's own login client lives here too (SSO-3104)

`thoryn login --workspace <slug>` signs in with the public PKCE client **`cli`**, which this file
declares on the `thoryn` workspace's **production plane** (fixed `clientId: cli`, loopback redirects,
device-code grant, the tenant-config scope set, first-party) — the platform's shared default tenant
no longer hosts it. A founder creates it **once** as a real customer would:

```bash
# a thoryn workspace admin, requesting every scope the file grants the client (the hub can only let
# you grant what your own session holds — SSO-1028's intersection rule)
thoryn login --workspace thoryn --scope "openid offline_access tenant:applications.read tenant:applications.write tenant:clients.read tenant:users.read tenant:users.write tenant:federation.read tenant:federation.write tenant:audit.read tenant:environments.read tenant:environments.write tenant:email.read tenant:email.write tenant:idp.read tenant:idp.write tenant:access.read tenant:access.write"
thoryn provision plan  --file .thoryn/provision.yaml
thoryn provision apply --file .thoryn/provision.yaml --yes
```

Every later `apply` — CI signs in as the CI machine client, whose receipt does not own `cli` — **adopts**
it by its fixed id and converges its non-secret shape; adopted resources are never removed by
`destroy`, so CI cannot delete the client it depends on. Rotating it is editing this file.

## Least-privilege CI identity — declared, not yet in use (SSO-3113, step 1 of 2)

Today `connection.json` still signs CI in as `app-63a0f52f-3d6`: a **workspace-wide** machine client,
minted imperatively by `thoryn provision ci-identity`, whose eight scopes (`applications` +
`federation` + `users` + `environments`, read+write) reach every environment of the `thoryn`
workspace — not just the `cli-ci` sandbox it provisions. Epic SSO-3108 narrows that to a client that
is `manager` of exactly one sandbox.

**What this step does.** `provision.yaml` now DECLARES that client, `cli-ci`, next to the `cli` login
client on the workspace's production plane:

- a confidential `client_credentials` application, no redirect URIs, no human-facing grant;
- six scopes — `tenant:environments.{read,write}` + `tenant:applications.{read,write}` (the kinds
  this file declares) + `tenant:access.{read,write}` (the `grants:` block: read to plan the diff,
  write to converge it). **No** `tenant:users.*`, **no** `tenant:federation.*` — the file declares
  no `user` and no `federationMember`, so the identity gets no reach over either;
- one grant, `client:cli-ci manager` on the `ci` **environment**. That is its whole declared reach.
  The loopback client inside the sandbox is covered by containment, and a machine client manages its
  own record by creation, so neither is restated as a grant. `CiProvisionFileConformanceTest` pins
  both the scope set (derived from the file's own kinds) and that single grant, so the file cannot
  silently hand CI workspace-wide reach again.

**What this step deliberately does NOT do.** `connection.json` is untouched — CI still signs in as
`app-63a0f52f-3d6` with its eight scopes. `thoryn provision ci-identity`,
`src/main/resources/provision/ci-identity.json` and `MachineClientProvisioner` are untouched. Nothing
about the running CI changes: `provision-e2e` is `workflow_dispatch`-only and no push/PR workflow in
this repo consumes these files, so merging this step converges nothing by itself.

### The cut-over (two steps)

**Step 1 — this change.** `cli-ci` is declared. Merging it is inert until a founder applies the file.

**Step 2 — a founder mints the secret, then a follow-up PR switches CI over.**

```bash
# a `thoryn` workspace admin, requesting every scope the file grants — the hub can only let you grant
# what your own session holds (SSO-1028's intersection rule), and the default scope set carries no
# tenant:access.*, so ask for it explicitly (it needs the product side, SSO-3112, deployed).
thoryn login --workspace thoryn --scope "openid offline_access tenant:applications.read tenant:applications.write tenant:clients.read tenant:users.read tenant:users.write tenant:federation.read tenant:federation.write tenant:audit.read tenant:environments.read tenant:environments.write tenant:email.read tenant:email.write tenant:idp.read tenant:idp.write tenant:access.read tenant:access.write"
thoryn provision plan  --file .thoryn/provision.yaml
thoryn provision apply --file .thoryn/provision.yaml --secret-file ci.secret   # cli-v0.14.0 or newer
```

`apply` creates `cli-ci`, delivers its ONE-TIME secret to `ci.secret` through the `SecretIo` channel
(never stdout, never argv, never the receipt), and converges the sandbox grant. Then:

1. Set the `THORYN_CLI_CI_CLIENT_SECRET` repository secret (the name `auth.secretEnv` declares) to the
   contents of `ci.secret`, and `shred ci.secret`.
2. Open the follow-up PR that flips `connection.json` to `clientId: cli-ci` with the six scopes above,
   and retires `app-63a0f52f-3d6`, `thoryn provision ci-identity`, `ci-identity.json` and
   `MachineClientProvisioner` — the imperative bootstrap the declared resource replaces.

> **The interim window.** Between step 1 and step 2 the file declares a `grants:` block that the OLD
> identity cannot converge: `app-63a0f52f-3d6` holds no `tenant:access.*`, so a manual `provision-e2e`
> dispatch would **fail closed** on it ("this session lacks the 'tenant:access.read' scope") — by
> design, not silently. Run step 2's founder `apply` before dispatching `provision-e2e` again. Nothing
> automatic is affected: that workflow only runs on `workflow_dispatch`.

## One-time bootstrap (founder, run once) — the imperative path, superseded by the declared `cli-ci`

This is how `app-63a0f52f-3d6`, the identity `connection.json` names **today**, was minted. It stays
documented (and the command stays shipped) until step 2 above proves the declared `cli-ci` cut-over;
for a NEW repository, declare the machine client in `provision.yaml` instead and mint it with
`provision apply --secret-file`. Per ADR
`2026-09-09-thoryn-cli-as-code-ci-connection-contract.md` (in `thoryn-io/oauthy`):

1. Sign in to the `thoryn` workspace interactively (browser OIDC):
   `thoryn login --workspace thoryn --issuer https://hub.stg.thoryn.org`.
2. Mint the CI machine client via the dedicated operator command (SSO-2952), which routes the secret
   through the `SecretIo` channel (`--secret-file`, never stdout/argv):
   `thoryn provision ci-identity --secret-file ci.secret`.
3. **Paste the printed `clientId`** into `auth.clientId` in `connection.json` and commit.
4. **Set the GitHub Actions secret** `THORYN_CLI_CI_CLIENT_SECRET` (the name in `auth.secretEnv`) to
   the contents of `ci.secret`, then `shred ci.secret`.

After that, every CI run is the four commands above.

## Why the scopes are what they are

`auth.scopes` is the **machine set** — today still the workspace-wide eight (`applications` +
`federation` + `users` + `environments`, read+write); after step 2 the six least-privilege scopes the
declared `cli-ci` holds. The hub grants a client-credentials token **only** the scopes requested, so
this list is both the ceiling and the floor. It must stay a **subset** of what
`thoryn provision ci-identity` grants the client (the declarative spec
`src/main/resources/provision/ci-identity.json`) — `CiConnectionConfinementTest` asserts exactly that
— and it must **cover every resource kind `provision.yaml` declares** (`environment` →
`tenant:environments.write`, `application` → `tenant:applications.write`) —
`CiProvisionFileConformanceTest` asserts that (SSO-3090). The same test pins the `cli` login client's
scope list to **exactly** the tenant scopes the CLI's sources reference — which is why
`tenant:access.read` / `tenant:access.write` (SSO-3113) appear on it — and, since SSO-3113, pins the
declared `cli-ci` client's scope set to exactly what converging this file needs.

## Confinement

The credential is confined three ways, all server-side: the client's `tnt` claim locks it to the
`thoryn` workspace (cross-tenant → 404); the hub mints only the requested scopes; and the provisioning
file's `kind` allowlist bounds what `apply` can express. After step 2 there is a fourth, the one epic
SSO-3108 adds: the identity is `manager` of the `ci` sandbox only, so product-api refuses anything it
does not manage (404, never 403). Everything CI creates is **environment-scoped** (inside the `cli-ci`
sandbox), so `destroy` needs no production-plane confirmation — the two production-plane resources,
the `cli` login client and the `cli-ci` identity itself, are adopted by CI, never owned or removed. Rotate the
secret with `thoryn clients rotate-secret` (24h graceful overlap). To isolate CI blast radius entirely,
bind the contract to a dedicated `thoryn-cli-ci` workspace instead — change `workspace.slug` and
re-bootstrap.

> A leaked `cli-ci` sandbox (a run that failed before `destroy`) is adopted — not duplicated — by the
> next `apply`, and adopted resources are never auto-deleted: remove it by hand with
> `thoryn env delete <id> --confirm cli-ci` if it should go.
