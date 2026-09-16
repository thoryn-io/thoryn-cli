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

## Least-privilege CI identity (SSO-3113, epic SSO-3108)

CI signs in as `cli-ci`: a confidential `client_credentials` client on the `thoryn` workspace's
production plane, declared in `provision.yaml` like any other application and **confined to the one
sandbox it provisions**. It replaced `app-63a0f52f-3d6`, a workspace-wide machine client minted by the
now-retired `thoryn provision ci-identity`, whose eight scopes (`applications` + `federation` + `users`
+ `environments`, read+write) reached every environment of the workspace — including the `cli` login
client every `thoryn login --workspace thoryn` depends on.

What confines it:

- **Six scopes** — `tenant:environments.{read,write}` + `tenant:applications.{read,write}` (the kinds
  this file declares) + `tenant:access.{read,write}` (the `grants:` block: read to plan the diff, write
  to converge it). **No** `tenant:users.*`, **no** `tenant:federation.*` — the file declares no `user`
  and no `federationMember`, so the identity gets no reach over either.
- **One grant** — `client:cli-ci manager` on the `ci` **environment**. That is its whole declared reach.
  The loopback client inside the sandbox is covered by containment, and a machine client manages its own
  record by creation, so neither is restated as a grant.
- **Scopes are the ceiling, the grant is the gate.** A scope says which API it may call; the grant says
  which object it may touch. `DELETE /api/v1/environments/<some other sandbox>` answers `404` however
  many scopes the token carries (ADR `2026-09-15-platform-resource-authorization-on-fga.md` §8).

`CiProvisionFileConformanceTest` pins the scope set (recomputed from the file's own kinds) and that
single grant, so the file cannot silently hand CI workspace-wide reach again;
`CiConnectionConfinementTest` pins `connection.json`'s scopes to the scopes this file declares for the
very `clientId` it signs in with, so the two files cannot drift.

### Minting it in a new repository

There is no bootstrap command any more — the identity is a declared resource, so `apply` mints it:

```bash
# A workspace admin, requesting every scope the file grants: the hub can only let you grant what your
# own session holds (SSO-1028's intersection rule).
thoryn login --workspace thoryn --scope "<the scopes your provision.yaml declares, plus tenant:access.read tenant:access.write>"
thoryn provision plan  --file .thoryn/provision.yaml
thoryn provision apply --file .thoryn/provision.yaml --secret-file ci.secret   # cli-v0.15.0 or newer
```

`apply` creates the client, delivers its ONE-TIME secret to `ci.secret` through the `SecretIo` channel
(never stdout, never argv, never the receipt), and converges the grants. Then set the repository secret
named by `auth.secretEnv` to its contents and `shred ci.secret`. Every later `apply` **adopts** the
client by its fixed `clientId`, so CI can never delete the identity it signs in with.

## Why the scopes are what they are

`auth.scopes` is the **machine set** — the six least-privilege scopes the declared `cli-ci` holds. The
hub grants a client-credentials token **only** the scopes requested, so this list is both the ceiling
and the floor. It must stay a **subset** of the scopes `provision.yaml` declares for the client
`auth.clientId` names — `CiConnectionConfinementTest` asserts exactly that — and it must **cover every
resource kind `provision.yaml` declares** (`environment` →
`tenant:environments.write`, `application` → `tenant:applications.write`) —
`CiProvisionFileConformanceTest` asserts that (SSO-3090). The same test pins the `cli` login client's
scope list to **exactly** the tenant scopes the CLI's sources reference — which is why
`tenant:access.read` / `tenant:access.write` (SSO-3113) appear on it — and, since SSO-3113, pins the
declared `cli-ci` client's scope set to exactly what converging this file needs.

## Confinement

The credential is confined four ways, all server-side: the client's `tnt` claim locks it to the
`thoryn` workspace (cross-tenant → 404); the hub mints only the requested scopes; the provisioning
file's `kind` allowlist bounds what `apply` can express; and — the one epic SSO-3108 adds — the
identity is `manager` of the `ci` sandbox only, so product-api refuses anything it does not manage
(404, never 403). Everything CI creates is **environment-scoped** (inside the `cli-ci`
sandbox), so `destroy` needs no production-plane confirmation — the two production-plane resources,
the `cli` login client and the `cli-ci` identity itself, are adopted by CI, never owned or removed. Rotate the
secret with `thoryn clients rotate-secret` (24h graceful overlap). To isolate CI blast radius entirely,
bind the contract to a dedicated `thoryn-cli-ci` workspace instead — change `workspace.slug` and
re-bootstrap.

> A leaked `cli-ci` sandbox (a run that failed before `destroy`) is adopted — not duplicated — by the
> next `apply`, and adopted resources are never auto-deleted: remove it by hand with
> `thoryn env delete <id> --confirm cli-ci` if it should go.
