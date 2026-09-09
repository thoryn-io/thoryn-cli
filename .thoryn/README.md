# `.thoryn/connection.json` — this repo's CI sign-in contract (SSO-2951)

`connection.json` is the **connection contract** (schema: `src/main/resources/examples/connection.schema.json`,
SSO-2948) that binds **this repo's CI** to the `thoryn` workspace. The provisioning Action
(`.github/actions/provision`) signs in with a single, declarative step:

```bash
thoryn login --connection .thoryn/connection.json
```

The CLI derives the per-tenant issuer (`https://thoryn.hub.<env>`), the gateway, and the requested
scopes **from this file** — the imperative bash sign-in it replaced is gone. It is **data, not code**:
the secret is NEVER in this file, only the *name* of the env var that carries it (`auth.secretEnv`).

## One-time bootstrap (founder, run once)

The machine client this contract names does not exist until a **founder** mints it once, through the
customer plane, the same way a real customer would — no DB seed, no shortcut. Per ADR
`2026-09-09-thoryn-cli-as-code-ci-connection-contract.md` (fetch it from `thoryn-io/oauthy`):

1. Sign in to the `thoryn` workspace interactively (browser OIDC):
   `thoryn login --issuer https://hub.stg.thoryn.org` then `thoryn workspace switch thoryn`.
2. Mint the CI machine client via the dedicated operator command (SSO-2952), which routes the secret
   through the `SecretIo` channel (`--secret-file`, never stdout/argv):
   `thoryn provision ci-identity --secret-file ci.secret`.
3. **Paste the printed `clientId`** into `auth.clientId` below — it currently ships the marker
   **`REPLACE_AFTER_BOOTSTRAP`** — and commit.
4. **Set the GitHub Actions secret** `THORYN_CLI_CI_CLIENT_SECRET` (the name in `auth.secretEnv`) to
   the contents of `ci.secret`, then `shred ci.secret`.

After that, every CI run just does `thoryn login --connection .thoryn/connection.json`.

## Why the scopes are what they are

`auth.scopes` is the **machine set** (`applications` + `federation` + `users` + `environments`,
read+write). The hub grants a client-credentials token **only** the scopes requested, so this list is
both the ceiling and the floor. It must stay a **subset** of what `thoryn provision ci-identity` grants
the client (the declarative spec `src/main/resources/provision/ci-identity.json`) —
`CiConnectionConfinementTest` asserts exactly that (`Connection.scopesWithinGrant`).

## Confinement

The credential is confined three ways, all server-side: the client's `tnt` claim locks it to the
`thoryn` workspace (cross-tenant → 404); the hub mints only the requested scopes; and any recipe it
runs is bound to the closed action allowlist. Rotate the secret with
`thoryn clients rotate-secret` (24h graceful overlap). To isolate CI blast radius entirely, bind this
contract to a dedicated `thoryn-cli-ci` workspace instead — change `workspace.slug` and re-bootstrap.

> A fuller operator walkthrough is SSO-2949 (docs). This note is the minimum to make the bootstrap
> reproducible.
