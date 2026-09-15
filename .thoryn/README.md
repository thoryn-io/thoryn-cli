# `.thoryn/` — this repo's as-code binding to Thoryn (SSO-2951 + SSO-3090)

One folder, two halves, both **data** (schema-validated by the CLI), both committed. This repo is
the **reference consumer** of the very verbs it ships: a customer binds a repository to Thoryn with
the same two files and the same commands.

| File | Declares | Schema | Verb |
|---|---|---|---|
| `connection.json` | **who I am** — the `thoryn` workspace, the CI machine client id, the *name* of the env var carrying its secret, the exact scope set | `src/main/resources/examples/connection.schema.json` (SSO-2948) | `thoryn login --connection .thoryn/connection.json` |
| `provision.yaml` | **what I own** — the desired state: the CLI's own login client `cli` in the `thoryn` workspace (SSO-3104), plus a sandbox environment `cli-ci` with a public loopback OAuth client inside it | `src/main/resources/provision/provision.schema.json` (SSO-3088) | `thoryn provision plan / apply / destroy --file .thoryn/provision.yaml` |

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

## Least-privilege CI identity (coming with SSO-3113 / SSO-3112 — not yet cut over)

Today the CI identity `connection.json` names is a **workspace-wide** machine client: its scope set
(`applications` + `federation` + `users` + `environments`, read+write) reaches every environment of
the `thoryn` workspace, not just the `cli-ci` sandbox it provisions. Epic SSO-3108 narrows that to
**least privilege**: a machine client that is `manager` of exactly one sandbox.

What has shipped in the CLI (SSO-3113, this repo): `thoryn access grant | revoke | list | mine`,
a `grants:` block on any resource of a provisioning file (converged with the resource — the object
derives from the receipt id, e.g. `client:cli-ci manager` on the `ci` environment ⇒
`environment:<id>`), and `provision apply --secret-file` delivering a provisioned confidential
client's one-time secret through the `SecretIo` channel (never the receipt). The `cli` login client
below now also lists `tenant:access.read` / `tenant:access.write`.

What has **not** happened yet, deliberately: this file does not declare a `cli-ci` machine client,
`connection.json` is unchanged, and `thoryn provision ci-identity` is untouched. Those are the
cut-over steps and they wait for the product side (**SSO-3112** — the `/api/v1/access` API and the
two `tenant:access.*` scopes) to deploy: a founder must hold `tenant:access.*` to re-apply this
file with them, and a `grants:` block needs the API to converge against. Until then, `apply` with
a session lacking `tenant:access.write` fails closed on a `grants:` block (the resource itself is
still recorded), and the extra `cli` scopes above are grantable only once the hub knows them.

## One-time bootstrap (founder, run once)

The machine client the contract names does not exist until a **founder** mints it once, through the
customer plane, the same way a real customer would — no DB seed, no shortcut. Per ADR
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

`auth.scopes` is the **machine set** (`applications` + `federation` + `users` + `environments`,
read+write). The hub grants a client-credentials token **only** the scopes requested, so this list is
both the ceiling and the floor. It must stay a **subset** of what `thoryn provision ci-identity` grants
the client (the declarative spec `src/main/resources/provision/ci-identity.json`) —
`CiConnectionConfinementTest` asserts exactly that — and it must **cover every resource kind
`provision.yaml` declares** (`environment` → `tenant:environments.write`, `application` →
`tenant:applications.write`) — `CiProvisionFileConformanceTest` asserts that (SSO-3090). The same
test pins the `cli` login client's scope list to **exactly** the tenant scopes the CLI's sources
reference — which is why `tenant:access.read` / `tenant:access.write` (SSO-3113) appear on it.

## Confinement

The credential is confined three ways, all server-side: the client's `tnt` claim locks it to the
`thoryn` workspace (cross-tenant → 404); the hub mints only the requested scopes; and the provisioning
file's `kind` allowlist bounds what `apply` can express. Everything CI creates is **environment-
scoped** (inside the `cli-ci` sandbox), so `destroy` needs no production-plane confirmation — the one
production-plane resource, the `cli` login client, is adopted by CI, never owned or removed. Rotate the
secret with `thoryn clients rotate-secret` (24h graceful overlap). To isolate CI blast radius entirely,
bind the contract to a dedicated `thoryn-cli-ci` workspace instead — change `workspace.slug` and
re-bootstrap.

> A leaked `cli-ci` sandbox (a run that failed before `destroy`) is adopted — not duplicated — by the
> next `apply`, and adopted resources are never auto-deleted: remove it by hand with
> `thoryn env delete <id> --confirm cli-ci` if it should go.
