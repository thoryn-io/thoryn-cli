# `ci-signin` example (workspace-less)

A declarative Thoryn example recipe that provisions an **ephemeral public loopback OAuth client
inside a workspace you already own** — using only supported product workflows (recipes are data, not
code; the CLI is the only executor, dispatching on a closed action allowlist).

It is the **workspace-less sibling of `simple-signin`**. Where `simple-signin` creates a fresh
`ex-signin-*` workspace per run (and hard-deletes it on teardown), `ci-signin` creates **nothing but
the OAuth client** and tears down **only** that client. It exists for one reason:

> A customer-plane `client_credentials` API key is **tenant-scoped** — bound to one workspace via its
> `tnt` claim — and **cannot create workspaces** (workspace-create needs a machine scope a tenant
> admin cannot delegate; see SSO-2943). So CI provisions an ephemeral app inside a **standing**
> workspace the operator owns, rather than minting a fresh workspace each run.

## What it provisions

1. **A public loopback OAuth client** (`applications.create`) — authorization-code + PKCE, redirecting
   to `http://127.0.0.1/callback`, with an OIDC RP-Initiated-Logout post-logout redirect URI.
2. **A read-back check** (`applications.get`) — asserts the client is `active`.

That's it. No workspace, no user, no email provider.

## How the interpreter authenticates

Because this recipe has **no `hub.createWorkspace` step**, the interpreter (SSO-2944) authenticates the
`applications.create` / `.get` / `.delete` calls with **the caller's own tenant-scoped bearer**
directly — there is no provisioning token to prefer (nothing created a workspace) and no RFC 8693
token-exchange to a just-created tenant. The caller's API key is already `tnt`-scoped to the standing
workspace, so the app is created under it.

## Parameters

| Param           | Required | Meaning                                                                 |
|-----------------|----------|-------------------------------------------------------------------------|
| `workspaceSlug` | **yes**  | The slug of the **standing** workspace your API key is scoped to (NOT created). CI passes `--set workspaceSlug=<slug>`; the guided `apply` prompts for it. |
| `appName`       | no       | Display name for the ephemeral client. Defaults to `CI Sign-in App <random>`. |

## The standing test user

`ci-signin` does **not** register a user. The recipe schema has no identity user-**delete** teardown
action, so a per-run user would leak in the standing workspace. Instead, the operator creates a
**standing test user once** (see the repo README / the provisioning Action's setup notes), and the
downstream sign-in step drives the loopback client against that user.

## Teardown

Teardown deletes only the app (`applications.delete`). The standing workspace and the standing user
are the operator's and survive every run.
