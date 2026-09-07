# `simple-signin` example

A declarative Thoryn example recipe the CLI applies to **your own account** using only supported
product workflows (recipes are data, not code — the CLI is the only executor, dispatching on a closed
action allowlist). It provisions everything a relying party needs to take a user from sign-up through
login to a protected page:

1. **A dedicated workspace** (`hub.createWorkspace`) — a fresh `ex-signin-*` tenant, with the tenant's
   default identity provider auto-attached.
2. **A product-api tenant registration** (`productApi.registerTenant`) — best-effort, idempotent.
3. **A public loopback OAuth client** (`applications.create`) — authorization-code + PKCE, redirecting
   to `http://127.0.0.1/callback`, with an OIDC RP-Initiated-Logout post-logout redirect URI.
4. **A verified, sign-in-able user** (`identity.registerUser`, SSO-2908) — the piece that makes a full
   sign-up → login → protected-page journey runnable end to end.

## The provisioned user

The `user` step registers a tenant user through the supported product API
(`POST /api/v1/users`, `tenant:users.write`). The `with` fields map 1:1 to product-api's
`CreateUserRequest`:

| Field           | Value                          | Why                                                              |
|-----------------|--------------------------------|------------------------------------------------------------------|
| `email`         | `{{workspaceSlug}}@example.com`| Tied to the fresh per-run workspace slug, so it never collides.  |
| `password`      | `Example-Signin-Pw1!`          | Sets an initial credential so the user can **sign in immediately**. |
| `givenName`     | `Demo`                         | Profile name.                                                    |
| `familyName`    | `User`                         | Profile name.                                                    |
| `emailVerified` | `true`                         | Marks the account **verified** — no email round-trip needed.     |

Together, `password` + `emailVerified: true` yield an account that can complete the OAuth
authorization-code login on the first try. The published password value is an example only — rotate it
before any real use.

## Teardown

Teardown runs child-first: delete the app (`applications.delete`), then hard-delete the workspace
(`hub.deleteWorkspace`). The user rides on the workspace hard-delete — purging the tenant removes its
users — so there is no separate user-delete step (SSO-2901 stops the `ex-signin-*` tenant sprawl).
