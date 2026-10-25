# thoryn — Thoryn customer-plane CLI

`thoryn` is the Thoryn customer-plane CLI. It runs the same OAuth flow
the web console runs, stores tokens in the OS keychain, and calls the
gateway endpoints that back the console's tenant-admin surfaces.

Built with picocli + GraalVM native image per
ADR 2026-04-25-customer-plane-product-api § 4 / § 8 / and RFC 8252 § 7.3 +
RFC 7636 + RFC 8628.

> **Standalone repo (SSO-2935).** This CLI lives in its own repository
> (`thoryn-io/thoryn-cli`), carved out of the `oathy` monorepo with its git
> history preserved. It builds on its own — no oathy checkout required. The
> user-facing product docs are published from oathy's `docs/` to
> thoryn.org/docs; this README is the developer-facing entry point.

## Install

Releases are cut by tagging `cli-v*` (SSO-2936). The `release` workflow
(`.github/workflows/release.yml`) builds the GraalVM native binaries and the
`thoryn.jar` fat jar and attaches them to the matching
[GitHub Release](https://github.com/thoryn-io/thoryn-cli/releases). The
`thoryn.jar` is always published; the native binaries are **best-effort per
runner availability** — an unavailable platform runner (e.g. GitHub's retiring
Intel-macOS runner) is tolerated, so a given platform's binary may be absent from
a release rather than blocking it.

**Homebrew** — the repo doubles as its own tap:

```bash
brew tap thoryn-io/thoryn-cli
brew install thoryn
thoryn --version
```

`brew install thoryn` pulls the prebuilt native binary for your OS/arch from the
latest `cli-v*` release; the release workflow bumps `Formula/thoryn.rb` (version +
per-binary `sha256`) on every tag.

**Direct download** — grab a native binary from the release assets
(`thoryn-darwin-arm64`, `thoryn-darwin-amd64`, `thoryn-linux-amd64`,
`thoryn-linux-arm64`, `thoryn-windows-amd64.exe` — whichever were produced for
that release; see the best-effort note above), `chmod +x`, and put it on `PATH`.
The `thoryn.jar` fat jar is always attached (`java -jar thoryn.jar ...`); it is
the stable asset name the `thoryn-examples` conformance CI consumes.

**Container image** (SSO-3687) — every `cli-v*` release also publishes the Linux native binaries as
a public, signed, multi-arch (`linux/amd64`, `linux/arm64`) image:

```
ghcr.io/thoryn-io/thoryn-cli:<version>        e.g. :0.33.0 — one per release
ghcr.io/thoryn-io/thoryn-cli:<major>.<minor>  e.g. :0.33   — moves to the newest patch
```

There is **no `:latest`**. The image's main use is the Thoryn init container (below), which receives
a client secret — so **pin it by digest**, with the version beside it for the reader:

```
image: ghcr.io/thoryn-io/thoryn-cli:<version>@sha256:<digest>
```

A digest exists only once a release has pushed it; look it up (any of these, no credential needed):

```bash
docker buildx imagetools inspect ghcr.io/thoryn-io/thoryn-cli:<version>   # "Digest:" line (the multi-arch index)
crane digest ghcr.io/thoryn-io/thoryn-cli:<version>
```

— or read it from the release run's summary, which prints the exact `…:<version>@sha256:…` reference
it pushed. Verify the signature (cosign keyless, signed by this repository's release workflow) before
you pin it:

```bash
cosign verify ghcr.io/thoryn-io/thoryn-cli@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/thoryn-io/thoryn-cli/\.github/workflows/release\.yml@refs/(tags/cli-v.+|heads/main)$'
```

The image also carries a BuildKit SBOM and SLSA provenance attestation
(`docker buildx imagetools inspect ghcr.io/thoryn-io/thoryn-cli:<version> --format '{{ json .SBOM }}'`).
It is `gcr.io/distroless/cc-debian12:nonroot` (pinned by digest) plus the `thoryn` binary: no shell,
uid/gid `65532`, `ENTRYPOINT ["/usr/local/bin/thoryn"]` — so a manifest passes the CLI's arguments as
`args:`. It has no OS keychain, so every invocation needs the explicit file-store opt-in
(`THORYN_CI_PLAINTEXT_TOKENS=1` + `THORYN_TOKEN_FILE=<path on a volume>`; see
[Token storage](#token-storage)). The `Dockerfile` explains the base-image choice; `release.yml`'s
`image` job builds, smoke-runs, pushes, signs, and then **fails unless an anonymous client can pull
what it pushed** (`scripts/release/check-anonymous-pull.sh`).

**The Thoryn init container — DEPRECATED (SSO-3951, 2026-10-25; removed by SSO-3953).** An application in
Kubernetes used to fetch its own client secret with its projected ServiceAccount token (oauthy ADR
`2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull`, rung 3; the trust is `thoryn workload-identity
trusts create --provider kubernetes`). The product owner withdrew that path: Thoryn owns the secret's lifecycle
(mint, show once, rotate with the 24 h overlap, revoke, audit), **the customer owns delivery** — a person mints the
secret (`thoryn clients rotate-secret <clientId> --secret-file <path>`) and stores it in the customer's secret manager
or an operator-created Kubernetes Secret the pod mounts (see "Where a minted secret goes" below). The shape below
still works and is kept for the record only; the image has no shell to chain `login && rotate-secret`, so it is **two
init containers** that share the CLI's session on a RAM volume only they mount:

```yaml
spec:
  serviceAccountName: forge-oauth2-proxy            # the trust's --service-account
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532                                # the secret file is written 0600 — the app reads it as the same uid
    runAsGroup: 65532
  volumes:
    - name: thoryn-token                            # the projected ServiceAccount token = the pod's credential
      projected:
        sources:
          - serviceAccountToken: { path: token, audience: <the trust's audience>, expirationSeconds: 3600 }
    - name: thoryn-connection
      configMap: { name: thoryn-connection }        # connection.json, as `trusts create` printed it
    - name: thoryn-session                          # the CLI session between the two steps; never mounted by the app
      emptyDir: { medium: Memory }
    - name: client-secret
      emptyDir: { medium: Memory }
  initContainers:
    - name: thoryn-login
      image: ghcr.io/thoryn-io/thoryn-cli:<version>@sha256:<digest>
      args: ["login", "--connection", "/etc/thoryn/connection.json"]
      env: &thoryn-session-env
        - { name: THORYN_CI_PLAINTEXT_TOKENS, value: "1" }        # no keychain in a container: explicit file-store opt-in
        - { name: THORYN_TOKEN_FILE, value: /thoryn-session/tokens.json }
      securityContext: &thoryn-hardening
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      volumeMounts:
        - { name: thoryn-token, mountPath: /var/run/secrets/tokens/thoryn, readOnly: true }
        - { name: thoryn-connection, mountPath: /etc/thoryn, readOnly: true }
        - { name: thoryn-session, mountPath: /thoryn-session }
    - name: thoryn-client-secret
      image: ghcr.io/thoryn-io/thoryn-cli:<version>@sha256:<digest>
      # --confirm: rotating a PRODUCTION application's secret needs the workspace slug (SSO-2413).
      args: ["clients", "rotate-secret", "<APP_CLIENT_ID>", "--secret-file", "/shared/client-secret", "--confirm", "<workspace-slug>"]
      env: *thoryn-session-env
      securityContext: *thoryn-hardening
      volumeMounts:
        - { name: thoryn-session, mountPath: /thoryn-session }
        - { name: client-secret, mountPath: /shared }
  containers:
    - name: oauth2-proxy
      args: ["--client-secret-file=/shared/client-secret", …]
      volumeMounts:
        - { name: client-secret, mountPath: /shared, readOnly: true }
```

The session the two steps share is a 15-minute workload-identity token (and its DPoP key) on a RAM
volume the application container never mounts; it dies with the pod. Rotation is a pod restart — the
previous secret stays valid for 24 hours. The image logs one `WARNING: Using plaintext file token
store…` line per step; that is the explicit opt-in above being announced, not a fault.

## Command tree

```
thoryn login --workspace <slug> [--issuer https://auth.<env>]  # Auth code + PKCE (loopback) or --device-code — ON your workspace (SSO-3104), and selects it (SSO-3927)
thoryn login --client-credentials [--client-id <id>] # SSO-1553/2941 — non-interactive API key (CI); THORYN_API_KEY=<id>:<secret>, auto re-mints on expiry
thoryn login --workload-identity --client-id <wi_…> --audience <aud> [--scope s]  # SSO-3308 — GitHub Actions job, NO secret (id-token: write); renews with a fresh job token
thoryn login --connection <file> [--fix-request <path>]  # SSO-2948 — sign in from a connection contract; SSO-3702/3722 — the profile is decided from the job's
                                             # environment claim vs auth.github.environment (apply / plan / "decided by the hub" when the connection names none);
                                             # SSO-3710/3722 — EVERY refusal ends with "To fix" (two options) and writes the fix request (env THORYN_FIX_REQUEST, SSO-3723 THORYN_CONSENT_URL)
thoryn login --status
thoryn logout [--rotate-key]                 # SSO-3199 — --rotate-key also discards this machine's DPoP key
thoryn whoami [--check]                      # SSO-2860/3199/3228 — identity, scopes, expiry, DPoP key + device (--check: this device's server-side state)
thoryn devices list                          # SSO-3228/3271 — your machines: state, live sessions, workspaces, recent networks
thoryn devices revoke <id|name> [--reason r] # Ends THAT machine's sessions and refuses its key; your other devices keep working

# Tenant configuration (SSO-1552) — thin wrappers over product-api via the gateway.
thoryn clients list                          # OAuth clients (product-api /api/v1/applications)
thoryn clients get <clientId>
thoryn clients create --display-name <n> --redirect-uri <uri> [--scope <s>]... \
                      [--client-type confidential|public] [--secret-file <path>]
thoryn clients update <clientId> [--display-name <n>] [--redirect-uri <uri>]... [--scope <s>]...
thoryn clients rotate-secret <clientId> [--secret-file <path>] [--confirm <workspace-slug>]
thoryn clients secret-state <clientId>       # SSO-3957 — is a previous secret still working, until when, and can you rotate now (from when)
thoryn clients delete <clientId> [--confirm <workspace-slug>]
thoryn clients registration-token [--software-id <id>] [--ttl <seconds>] [--out-file <path>]
                                             # SSO-3683 — a single-use RFC 7591 token a THIRD PARTY redeems at your
                                             # registration_endpoint; shown once (SecretIo). See "Register a third-party client".

thoryn federation list                       # Federation members (product-api /federation-members)
thoryn federation create --provider-type oidc --display-name <n> \
                         --discovery-url <url> --client-id <id> [--secret-file <path>] \
                         [--provider-config k=v]... [--claim-mapping k=v]...
thoryn federation delete <memberId> [--confirm <workspace-slug>]

thoryn workspace list                        # Workspaces (hub /account/workspaces)
thoryn workspace create --slug <slug> --display-name <name>
thoryn workspace switch <slug>               # select ANOTHER workspace you belong to; later commands exchange into it per call (login --workspace already selects its own: base token, no exchange — SSO-3692/3927)
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
thoryn env delete <id> --confirm <slug>      # hard-delete a sandbox (irreversible; confirm = its own slug)

# Directory users (SSO-3081) — the users of your workspace (product-api /api/v1/users), honouring the
# SELECTED environment (thoryn env use); with none selected, the production plane. Suspending a user
# refuses their next sign-in (the hosted login shows the suspended notice, not the generic error).
thoryn users list [--email <email>] [--status <ACTIVE|SUSPENDED>] [--limit <n>] [--environment <slug>]
thoryn users suspend (<id> | --email <email>) [--confirm <workspace-slug>] [--environment <slug>]  # production plane needs --confirm
thoryn users reactivate (<id> | --email <email>) [--environment <slug>]                            # clear a suspension
# SSO-3941 — the RBAC roles a person holds in the selected environment (product-api /api/v1/users/{sub}/roles;
# tenant:roles.read / tenant:roles.write). <user> is the person's SUBJECT (the `sub` claim of their tokens — what an
# assignment is keyed on, not the directory id); <role> is the role's name (as declared with `kind: role`) or its id.
# A bare `thoryn login` requests tenant:roles.read/.write (the `cli` login client carries them once the platform has
# granted them to it — the SSO-2278 grant order); the hub mints them only to an admin who holds them.
thoryn users roles list   <user> [--environment <slug>] [--output json|yaml|table]
thoryn users roles add    <user> <role> [--environment <slug>]       # already held ⇒ success, "unchanged"
thoryn users roles remove <user> <role> [--environment <slug>]       # idempotent; no --confirm (the API does not gate it)
# --environment targets a plane directly (rides X-Thoryn-Environment) for a client-credentials/CI
# session that hasn't run `workspace switch` + `env use` (SSO-3068); e.g. `--environment production`.

# Sandbox test inbox (SSO-3026) — a sandbox SUPPRESSES real transactional email and captures it here,
# so you can complete a sandbox email flow (verification, …) without a real mailbox. Read-only.
thoryn env test-emails list [--env <slug>] [--to <email>] [--channel <ch>] [--limit <n>]
thoryn env test-emails get <email-id> [--env <slug>]   # one email, incl. its actionLink (e.g. the verify URL)

# Hosted-login branding (SSO-3037) — the look of the hosted sign-in / register screens end users see,
# per SELECTED ENVIRONMENT (thoryn env use). Rendered as CSS custom properties; server-validated
# (hex colors, radius 0-64, theme enum, https logo) + WCAG-AA contrast-guarded. Needs tenant:idp.*.
thoryn branding get                                    # effective values + which fields are overridden
thoryn branding set [--primary-color '#2563eb'] [--background-color '#fff'] \
                    [--logo-url https://…] [--border-radius-px 8] [--theme light|dark|auto]
# SSO-3038 — additionally set allowlisted --thoryn-* CSS variables (repeatable --var KEY=VALUE):
thoryn branding set --var --thoryn-accent=#7c3aed --var --thoryn-font-family='Inter, sans-serif'
#   allowed: --thoryn-accent, --thoryn-text, --thoryn-muted, --thoryn-font-family (colors hex +
#   WCAG-AA contrast-guarded; font a safe stack). An empty value clears one: --var --thoryn-accent=
# set MERGES (unspecified fields + CSS vars keep their stored value); pass an empty value to clear an
# override, e.g. `thoryn branding set --logo-url ""` drops the custom logo back to the platform default.

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
                                             # SSO-3100 — a recipe with `provision: ./provision.yaml` converges that provisioning file FIRST
                                             # (same engine as `provision apply`; a re-apply is a no-op), then runs its extra steps; `teardown` destroys it last
thoryn examples share    <name> [--output <file>]   # SSO-2876 — export the secret-free receipt (notes if platform-signed)

# Operator provisioning (SSO-2952) — bootstrap the CI machine identity (founder-run, once).

# Provisioning-as-code (SSO-3088, epic SSO-3087) — converge the DESIRED STATE in .thoryn/provision.yaml
# (resources with a stable `name`: environment, application, user, federationMember, and the
# per-environment singletons emailProvider / loginTheme / loginFlow / loginMethods — the last, SSO-3100,
# is the sign-in METHOD allow-list `login-methods set` writes; destroy resets it — and, SSO-3413, the
# workspace-level singleton customDomain: plan shows the DNS records, apply claims + verifies, only
# --prune/destroy with --confirm release it). SSO-3715 (ADR 2026-10-15 platform-is-the-ledger): THERE IS
# NO RECEIPT — nothing is written beside the file, committed or cached; plan / apply / destroy / import read
# live state only, and `apply --output json` / `plan --output json` carry the resolved ids (`resources[]`:
# {kind, name, id, environment, action}). SSO-3089: every resource is read LIVE by its converge key before
# any write (env slug; app `clientId` when declared, else displayName within its env — TWO live matches are
# the red row converge_key_ambiguous, never a third copy; user email; member displayName; trusts by name;
# the singletons by existence): equal ⇒ no-op, different ⇒ update with only the changed fields, deleted out
# of band ⇒ re-created; "adopt" is gone — the first apply of an existing resource is not an event. Apply
# twice issues no writes. What destroy / --prune may REMOVE is the platform's `owner` relation: a `client:`
# identity (a repository's wi_) removes only what it OWNS (manager alone never lets automation delete), a
# person removes what they manage and nobody owns, non-ownable kinds (user, federationMember, the
# singletons, a trust) go WITH their sandbox and are never removed on the production plane (reported with
# the command a person runs), environments go last and only when owned; `retain: true` keeps a resource
# regardless (shown as "retained"). `--prune` removes what the identity OWNS and the file no longer
# declares, and revokes undeclared grants on the declared objects it may delete (never the owner tuple, a
# workspace userset or itself). See "Ownership is decided by your identity's reach" below.
# Secrets never enter the file — name the env var (`passwordEnv`,
# `smtpPasswordEnv`, `clientSecretEnv`) or use `{{env.NAME}}`; they are resolved at apply and never
# recorded. Production-plane removals need `--confirm <workspace-slug>` (the SSO-2413 gate).
# SSO-3430: a resource's `environment:` may also be `{{env.NAME}}` (e.g. "{{env.THORYN_ENVIRONMENT}}", how an
# unrendered starter repository names its sandbox from a CI variable); it is resolved when the file is read,
# and an unset variable is an error for plan and apply alike.
# SSO-3659 (ADR 2026-10-13 §1/§2): ownership is decided by the signed-in identity's platform reach — plan and apply
# gate every resource on the relation it holds (`manager` ⇒ converge; `viewer` ⇒ only a matching `readOnly: true`
# reference; none ⇒ access_not_owned). SSO-3673: asked PER OBJECT (`POST /api/v1/access/check`), and a resource the
# platform's `owner` relation gives to another repository is access_owned_elsewhere unless declared `readOnly: true`.
# A failed gate is a RED plan (exit 1) and apply refuses before writing. See "Ownership is decided by your
# identity's reach" below.
# SSO-3668 (ADR 2026-10-13 production-clients-declared-in-the-config-project §2): an application's `publishTo:` targets
# receive its clientId AFTER apply converged it, on EVERY apply (an upsert) — `kind: githubActionsVariable` is
# `gh variable set <NAME> --body <clientId> --repo <owner/name> --env <environment>` through your own `gh` login.
# plan prints the pending publish as a line; an unreachable target is `publish_target_unreachable` AFTER the client
# exists, naming the one `gh variable set` to run by hand. See "Publishing an application's
# client id to the repository that deploys it" below.
# SSO-3954 (oauthy ADR 2026-10-14 amended 2026-10-25, SSO-3951 — Thoryn owns the secret lifecycle, the customer owns
# delivery): a confidential application WITHOUT a `secretSink:` — or with `secretSink: { kind: customerManaged }` — is
# created and its one-time secret DISCARDED (never shown, written or granted to anyone); a person mints the real one with
# `thoryn clients rotate-secret <id> --secret-file <path>` and stores it in the customer's secret manager. plan prints
# `secret: managed by the customer (…)`. The way a CI apply (no kubeconfig, no TTY) creates a confidential application.
# SSO-3659 (ADR 2026-10-13 converge §5): an OPERATOR's apply can instead deliver — `kind: kubernetesSecret` (your own
# `kubectl`, value on stdin, namespace never created) or `kind: file` (owner-only, no overwrite without --force) — right
# after apply recorded the client. Nothing reaches ⇒ exit 65 `undelivered_secrets` naming the rotate-secret recovery.
# See "Where a minted secret goes" below.
# SSO-3921 (rung 3) — DEPRECATED since SSO-3951, removed by SSO-3953: `secretSink: { kind: workloadPull, trust: <name> }`
# discards the minted value and converges `manager` on the application for the named kubernetes trust's wi_ client, whose
# pod mints its own secret at start. Still converged; every plan and apply prints the deprecation.
# SSO-3689 (ADR 2026-10-14 credential ladder; ADR 2026-10-14 federated client authentication): an application declares HOW it
# authenticates — `clientAuthenticationMethods: [private_key_jwt]` with `jwksUri` or an inline public `jwks` (rung 1), or
# `[federated_assertion]` with `federatedTrust: <trust name>` (rung 2: the pod's / job's platform token IS the client
# credential; nothing is minted) — converged on update too; `client_secret_post` is not declarable. New kind
# `workloadIdentityTrust` (provider github_actions | forgejo | kubernetes + that provider's pins, scopes, confirmProduction):
# converged by name (also on the API's 409), its pins never updated in place (workload_identity_trust_immutable) — its
# SCOPES are (SSO-3925: narrowing from CI, widening a person's passkey act) — removed only
# with its sandbox; the plan shows the wi_ client + audience; apply PRINTS the consumer's connection.json, never
# writes it. See "Secretless clients" and "Declaring a workload-identity trust" below.
# SSO-3766 / SSO-3767 / SSO-3770 (oauthy SSO-3759 / SSO-3758 / SSO-3762): an application also declares
# `allowedAuthorizationDetailTypes` (RFC 9396; a set — the list replaces, [] clears), `allowTokenExchange` (RFC 8693;
# turning it ON needs `manager` on the environment — else the red row token_exchange_not_grantable naming that
# right) and the session lifetime `refreshTokenSlidingWindow` + `refreshTokenAbsoluteMaxTtlSeconds`. Converged on
# update; an omitted setting keeps the live value. See "Application settings" below.
# SSO-3810 / SSO-3807 (oauthy): also `allowTokenIntrospection` (RFC 7662; turning it ON needs `manager` on the
# environment — else token_introspection_not_grantable), `accessTokenFormat` (self-contained | reference) and the
# DPoP rungs `dpopAllowed` / `dpopRequired` (SSO-3811).
# SSO-3941: new kind `role` — an RBAC role of its environment, converged by name with its FULL permission set (a
# permission the workspace lacks is created); and an application's `tokenClaims: { sources: [permissions] }` — which claim
# sources the hub adds to its tokens (`{ enabled: false }` switches it off; omitted keeps the live toggle). See "Roles and
# claims in the token" below.
# SSO-3945 (oauthy SSO-3943): `tokenClaims.roleMapping` — role name → the value the application receives in its `roles`
# claim (source `roles`). Sent with EVERY PUT; omitted means NO mapping, so the plan shows a live one as removed.
thoryn provision plan    [--file <path>] [--prune] [--fix-request <path>]  # read-only: what apply would create / remove (+ grant changes, pending publishes); exit 1 on an ownership error
                                             # SSO-3710 — --fix-request (env THORYN_FIX_REQUEST): a red plan also writes thoryn-provision-request.json — every missing RIGHT
                                             # (owner / manager / viewer) with the exact `thoryn access grant` command a workspace admin runs; a workflow uploads it
                                             # SSO-3792 — a declared PRODUCTION application (fixed clientId) this identity may not create is a `creator` item
                                             # (`thoryn access reserve …`); with an unexpired slot it holds the row reads "will create (reserved …)" and passes
                                             # SSO-3738 — with web consent the log's Option 1 is `thoryn access approve <owner>/<repo>/<run_id>`, not the raw lines
thoryn provision apply   [--file <path>] [--prune] [--confirm <ws>] [--yes] [--fix-request <path>] \
                         [--secret-file <path>] [--force-stdout] [--force] \
                         [--wait [--wait-until ACTIVE|VERIFIED] [--wait-timeout 15m] [--wait-interval 20s]]
thoryn provision import  [--file <path>] [--write]                       # SSO-3659 — the inverse of plan: render what this identity may reach as
                                             # provision.yaml entries (manager ⇒ an entry the file converges; viewer or owned by another repository ⇒ `readOnly: true`); --write appends them (the file only)
                                             # converge; environments first, dependants into them.
                                             # SSO-3414 — --wait blocks until the file's customDomain is ACTIVE (or VERIFIED), verifying each round.
                                             # SSO-3113 / SSO-3954 — a confidential application it CREATES gets a one-time client secret: DISCARDED by
                                             # default (the customer manages it — `thoryn clients rotate-secret <id> --secret-file <path>` by a person,
                                             # stored in your secret manager), or delivered to a declared kubernetesSecret / file sink, with
                                             # SecretIo (--secret-file, or an interactive TTY; a pipe is refused unless --force-stdout) as that sink's
                                             # fallback; undeliverable ⇒ the client is still recorded, exit 65, the rotate-secret recovery named.
                                             # A resource's `grants:` block is converged with it (see "Least-privilege access grants").
thoryn provision destroy [--file <path>] [--confirm <ws>] [--yes] # remove what the file declares AND this identity may remove (owner-gated), child-first; prints the destroy plan first
# SSO-3962 (oauthy ADR 2026-10-25): provisioning is TWO PARTS, declared by `apiVersion` — `thoryn.io/tenant/v1` (what the
# tenant IS; the workspace's ONE config project) and `thoryn.io/application/v1` (how ONE client uses it; an app project).
# A kind from the other part is refused before any call; the mixed `thoryn.io/provision/v1` warns for one release.
# See "Two file parts — tenant and application" below.
thoryn provision split   [--file <path>] [--tenant-file <path>] [--application-file <path>] [--force]   # a mixed file → tenant.provision.yaml + application.provision.yaml beside it; the source is left alone
thoryn provision workflow check [--file <stub>] [--config <.thoryn/workflow.yaml>] [--root <dir>] [--output json]
                                             # SSO-3719 — lint the App-dispatched STUB (.github/workflows/thoryn-provisioning.yml) and .thoryn/workflow.yaml
                                             # against the provisioning workflow contract: every rule PASS/FAIL with its fix + the EFFECTIVE configuration;
                                             # exit 0 / 4. The reusable workflow runs it (--output json) and acts on its `config`. See "Configure the
                                             # provisioning workflow" below.

# Least-privilege access grants (SSO-3113, epic SSO-3108) — who may manage / view which resource.
# Thin wrappers over product-api /api/v1/access (the SSO-3112 contract). Subjects: member:<sub> | client:<clientId>;
# objects: workspace:<tenantId> | environment:<id> | application:<clientId> | user:<id> | federation_member:<id> |
# email_provider:<envSlug> | login_theme:<envSlug> | login_flow:<envSlug> | login_methods:<envSlug> |
# custom_domain:<tenantId> (SSO-3413 — how a workspace admin lets ONE machine client manage the custom domain) |
# trust:<trustId> (SSO-3774 — a workload-identity trust; `owner trust:<id>` hands a repository the trust its app signs in with);
# relations: manager | viewer | owner (owner: a workspace admin, one client: per application / environment / trust).
# Scopes: tenant:access.read (list, mine) / tenant:access.write (grant, revoke).
thoryn access grant  <subject> <relation> <object>   # POST   /api/v1/access/grants  (idempotent: 201, or 200 when it already exists)
thoryn access revoke <subject> <relation> <object>   # DELETE /api/v1/access/grants  (grant identified in the JSON body; 204)
thoryn access list   [--object <ref>] [--subject <ref>]   # GET /api/v1/access/grants?object=…|subject=…
thoryn access mine   [--type <objectType>] [--relation <relation>]   # GET /api/v1/access/mine — the objects YOU hold a relation on
# SSO-3738 — Option 1 of a red provisioning check: open Thoryn's consent for the rights that run asks for. No API call,
# grants nothing itself; a workspace admin approves on the hub's consent screen (see "thoryn access approve" below).
thoryn access approve <owner>/<repository>/<run_id> [--consent-url <base>] [--no-browser]
thoryn access approve https://starters.<your Thoryn domain>/github/consent/run/<owner>/<repository>/<run_id>

# Application creation slots (SSO-3792; oauthy ADR 2026-10-17, product-api SSO-3789) — a workspace admin approves that ONE
# workload identity creates ONE named application on ONE plane, once, within 30 days. The repository's own apply then
# creates it (POST /api/v1/applications with its clientId) and owns it. See "Creation slots" below.
thoryn access reserve <client:wi_…> application:<clientId> [--environment <slug>]   # POST /api/v1/access/application-slots (admins; plane defaults to production)
thoryn access reservations [--subject <client:wi_…>]   # GET /api/v1/access/application-slots — an admin sees all, anyone else its own
thoryn access release application:<clientId>          # DELETE /api/v1/access/application-slots/{clientId} — the holder releases, an admin revokes

# Custom domain (SSO-3303, epic SSO-3290) — serve the workspace's sign-in (and its token issuer) on a host
# you own, e.g. auth.acme.com. One per workspace; workspace admins, and machine clients an admin granted
# `manager` on custom_domain:<tenantId> (SSO-3413) — everyone else gets 404. Needs the feature enabled for
# the workspace by Thoryn (else 403 entitlement_required).
# Scopes: tenant:domains.read (status) / tenant:domains.write (add, verify, remove).
thoryn domain add <host> [--accept-re-sign-in]   # PUT    /api/v1/custom-domain — prints the TXT + CNAME records to create
thoryn domain status [--wait …]                  # GET    /api/v1/custom-domain — state, records, issuer, certificate, last check, release countdown when SUSPENDED
thoryn domain verify [--wait …]                  # POST   /api/v1/custom-domain/verify — exit 4 while the DNS does not prove it yet
                                                 # SSO-3414 — --wait [--until ACTIVE|VERIFIED] [--timeout 15m] [--interval 20s]: block until reached;
                                                 # exit 4 with the last-check reason on a timeout. --json records: {type, name, value, ttl}
thoryn domain remove [--yes]                     # DELETE /api/v1/custom-domain — asks for confirmation unless --yes

# On-demand signing-key rotation (SSO-3369) — a new version of one of the SELECTED environment's keys
# (suspected leak, own schedule). --kind sign-in (token signing key; the hub rotates at once) |
# security-events (SSF / webhook / DSAR / veto signing key; its rotator acts within ~2 minutes).
# Workspace admins only (others get 404). Scopes: tenant:keys.rotate (rotate) / tenant:keys.read (rotations).
thoryn keys rotate --kind <kind> [--environment e] [--wait] [--timeout 5m] [--yes]   # POST /api/v1/signing-keys/{kind}/rotations
thoryn keys rotations [list] --kind <kind> [--limit n] [--cursor c]                   # GET  /api/v1/signing-keys/{kind}/rotations
thoryn keys rotations get <id> --kind <kind>                                          # GET  /api/v1/signing-keys/{kind}/rotations/{id}
# Retire a LEAKED key (SSO-3396): every version up to --through-version (default: the signing version)
# stops verifying at once; cannot be undone. Needs tenant:keys.retire and a passkey sign-in ≤ 5 minutes:
#   thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300
thoryn keys retire --kind <kind> [--environment e] [--through-version n] [--wait] [--yes]  # POST /api/v1/signing-keys/{kind}/retirements
thoryn keys retirements [list] --kind <kind> [--limit n] [--cursor c]                      # GET  /api/v1/signing-keys/{kind}/retirements
thoryn keys retirements get <id> --kind <kind>                                             # GET  /api/v1/signing-keys/{kind}/retirements/{id}

# Workload identity trusts (SSO-3308, epic SSO-3304) — let ONE GitHub repository's Actions jobs sign in
# to an environment with NO stored secret (`thoryn login --workload-identity`). Environment managers only
# (others get 404). Scopes: tenant:workload-identity.read (list, get) / tenant:workload-identity.write (create, delete).
# SSO-3684 — `--provider kubernetes`: the same for the PODS of one Kubernetes service account (their projected
# ServiceAccount token is the credential; read from a FILE by the Thoryn init container, see examples/kubernetes/).
thoryn workload-identity trusts create --name <n> --repository <owner/repo> --scope <tenant:…> [--environment e]
    [--owner-id n --repository-id n] [--github-environment <gh-env>] [--ref <ref>] [--github-hosted-runners-only] [--confirm-production]
    [--plan-environment <gh-env> [--plan-scope <tenant:…read>…]]   # SSO-3702: the PLAN profile — a second GitHub environment minted
                                                                   # read-only scopes (derived: the .read members of --scope) — one trust, one wi_
thoryn workload-identity trusts create --provider kubernetes --name <n> --issuer <https url> --scope <tenant:…> [--environment e]
    [--namespace <ns> [--service-account <sa>]] [--jwks-file <cluster-jwks.json>] [--confirm-production]   # production: both pins
thoryn workload-identity trusts set-plan-profile <id> --plan-environment <gh-env> [--plan-scope <tenant:…read>…]   # POST …/{id}/plan-profile
                                                                   # the ONE additive mutation: adds the plan profile, keeps the wi_ client (409 once set)
thoryn workload-identity trusts set-scopes <id|name> [--scope <tenant:…>…] [--plan-scope <tenant:…read>…]   # PUT …/{id}/scopes (SSO-3925)
                                                                   # scopes changed IN PLACE: same id, same wi_ client, no connection.json or owner moves.
                                                                   # Removing: needs nothing more. ADDING: a person with a passkey sign-in from the last
                                                                   # 5 min (403 step-up → `thoryn login --acr-values urn:thoryn:acr:phishing_resistant
                                                                   # --max-age 300`); a workload identity never (elevated_action_requires_person)
thoryn workload-identity trusts list [--limit n] [--cursor c]         # GET    /api/v1/workload-identity/trusts
thoryn workload-identity trusts get <id> [--connection]               # GET    /api/v1/workload-identity/trusts/{id} (+ the sign-in line); --connection: ONLY the
                                                                      # complete connection.json (SSO-3722 — provider + the whole github/kubernetes block), to paste
thoryn workload-identity trusts delete <id> [--yes] [--confirm <slug>] # DELETE /api/v1/workload-identity/trusts/{id}

# Project repositories (SSO-3435, epic SSO-3304) — set up a GitHub repository that manages your workspace
# (config) or connects one application (app), with your OWN gh CLI and no GitHub App. See "Project repositories".
thoryn project init config [--repo owner/name] [--sandbox <slug>] --reviewer <login>… --confirm-production
thoryn project init app --stack express|spring-boot|aspnet-core --environment <sandbox> [--repo owner/name]
                        [--config-repo owner/name --production-url https://…]   # + the production client, as a PR on the config repo
    # without --repo: works on the clone in the current directory (or --dir); [--force] [--public] [--template owner/repo]

# Operator plane (SSO-3356) — Thoryn staff / self-managed platform operators only. Passkey sign-in on the
# `thoryn` home with client thoryn-operator, stored APART from `thoryn login`; calls go to the hub's /admin
# surface over a kubectl port-forward (never a public host). See "Operator commands" below.
thoryn operator login [--issuer <base>] [--status]            # passkey sign-in → admin:custom-domains.manage/.read
thoryn operator logout                                         # forget the operator session only
thoryn operator custom-domain entitle <workspace> [--hub-url u] # PUT /admin/tenants/{slug}/custom-domain/entitlement {"entitled":true}
thoryn operator custom-domain revoke  <workspace> [--hub-url u] # … {"entitled":false} (an existing domain stays)
thoryn operator custom-domain status  <workspace> [--hub-url u] # GET /admin/tenants/{slug}/custom-domain
# SSO-3856 — platform: scopes on machine clients of the platform home workspace (needs the operator scope
# admin:clients.platform-scopes, requested only when used: thoryn operator login --scope "openid admin:clients.platform-scopes").
thoryn operator platform-scopes get    <clientId>                       # GET    /admin/platform-clients/{clientId}/scopes
thoryn operator platform-scopes grant  <clientId> <scope> [--reason r] [--ticket t]   # PUT    …/scopes/{scope} (idempotent)
thoryn operator platform-scopes revoke <clientId> <scope> [--reason r] [--ticket t]   # DELETE …/scopes/{scope} (idempotent)
thoryn operator platform-scopes plan   [-f .thoryn/platform-scopes.yaml]  # read each declared client, print the plan; writes nothing
thoryn operator platform-scopes apply  [-f .thoryn/platform-scopes.yaml] [--dry-run]  # plan, then grant missing + revoke extra
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

### Rotation state (SSO-3957)

`thoryn clients rotate-secret` mints a new secret and keeps the previous one working for a
**24 h overlap** so a deployment can switch over without a gap. The response says so once, at
rotation time; the overlap is a *state* you may need to look at later — from another machine,
after the terminal is gone, or when a rotation is refused. `thoryn clients secret-state` reads it
from the server (`GET /api/v1/applications/{clientId}/secrets/state`, `tenant:applications.read`):

```bash
thoryn clients secret-state 7f1c…
#   previousSecretId    = 9b2e…
#   previousExpiresAt   = 2026-06-10T10:00:00Z (in 23h 41m)
#   rotationAvailable   = false
#   rotationAvailableAt = 2026-06-10T10:00:00Z (in 23h 41m)
# A rotation is in flight: the previous secret keeps working until 2026-06-10T10:00:00Z (in 23h 41m). The next rotation is allowed from then.

thoryn clients secret-state 7f1c…            # once the window has closed
#   previousSecretId    = -
#   previousExpiresAt   = -
#   rotationAvailable   = true
#   rotationAvailableAt = -
# No rotation is in flight: only the current secret works, and you can rotate now.
```

Four fields, straight from the server: `previousSecretId` / `previousExpiresAt` (the secret still
validating after the last rotation and when it stops; both `null` when none is), `rotationAvailable`
(whether a new rotation may start right now) and `rotationAvailableAt` (the earliest moment it may;
`null` when it may now). `--output json|yaml` prints exactly that body; the table adds each time's
age and the one-line reading.

**One rotation at a time.** While the window is open the server refuses a second rotation with
`409 rotation_in_flight`. The CLI renders that as the state it is rather than a bare error — the
time the next rotation is allowed (from the 409's own hint when product-api could read it from the
hub, otherwise by reading `secret-state` for you), the fact that the previous secret keeps working
until then, and where the incident path is:

```bash
thoryn clients rotate-secret 7f1c…
# Error: rotation_in_flight — A rotation is already in flight for this client. The next rotation is available at 2026-06-10T10:00:00Z.
# The previous secret keeps working until 2026-06-10T10:00:00Z (in 23h 41m). The next rotation is allowed from then.
# To end the previous secret now, or to replace a lost new secret, see "Rotation state" in the thoryn CLI README (incident paths, SSO-3956).
# ⇒ exit 2 (the server refused the call — the same code every non-2xx answer has always had)
```

With `--output json` the same arrives as `{"error":"rotation_in_flight","httpStatus":409,
"rotationAvailableAt":"2026-06-10T10:00:00Z","hint":"…"}`, so a script can wait for the time
instead of parsing prose.

**Incident paths — ending the previous secret early, replacing a lost new secret.** A 409 is the
normal case: wait for the window, or read `secret-state` to see how long. Two situations cannot
wait: the previous secret is known to have leaked and must stop working *now*, or the new secret
was lost before it reached the deployment and a replacement is needed inside the window. Those are
server-side capabilities **being built under SSO-3956** (oauthy); this CLI will grow commands for
them once that API exists and does not claim them yet. Until then the CLI has no command that ends
the previous secret early or re-mints inside the window: a lost new secret means waiting for the
window and rotating again, and a leaked previous secret is an incident for as long as the window
says it still works. `rotate-secret` on a production workspace still needs `--confirm` (see above);
`secret-state` is a read and needs nothing beyond `tenant:applications.read`.

### Register a third-party client (Dynamic Client Registration, SSO-3683)

A vendor integrating Thoryn SSO for your workspace does not need a console session or this CLI:
RFC 7591 Dynamic Client Registration lets *their* software register its own OAuth client at your
workspace's `registration_endpoint`. What they need from you is a single-use **Initial Access
Token** (oauthy ADR `2026-10-14-dynamic-client-registration-for-third-parties`, trust model (b)):

```bash
thoryn env use staging                       # the token is pinned to the SELECTED environment
thoryn clients registration-token --software-id com.vendor.crm --ttl 3600 --out-file iat.txt
# registration_endpoint  https://acme.auth.thoryn.io/staging/oauth2/register
# expires_at             2026-10-14T12:00:00Z
# Initial access token written to /…/iat.txt (shown once; not retrievable later).
```

Hand the vendor the token (out of band — it is a credential) together with the printed
`registration_endpoint`. Their software redeems it **once**, within the TTL, with no other
credential:

```bash
curl -sS -X POST "$REGISTRATION_ENDPOINT" \
  -H "Authorization: Bearer $(cat iat.txt)" \
  -H "Content-Type: application/json" \
  -d '{
        "client_name": "Vendor CRM",
        "redirect_uris": ["https://crm.vendor.example/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid profile",
        "software_id": "com.vendor.crm"
      }'
```

The `201` response carries `client_id`, the one-time `client_secret`, and a
`registration_access_token` + `registration_client_uri` for RFC 7592 reads/updates later.

What the token binds (enforced by the hub at redemption, not by this CLI):

 - **your workspace and environment** — a token minted on `staging` cannot create a production
   client, whichever surface it is presented to (`401 invalid_token` on a mismatch);
 - **your own scopes** — the registered client may request only `tenant:*` scopes *you* held when
   you minted (the same transitive-grant rule as `clients create`); `openid`/`profile`/… are not
   affected;
 - **`--software-id`**, when given — a registration carrying a different `software_id` is refused
   (`400 invalid_client_metadata`), so a leaked token cannot register unrelated software;
 - **one hour at most** (`--ttl` ≤ 3600), **single use**.

Secret-safety is the `SecretIo` contract `clients create` uses: the token goes to `--out-file`
(owner-only `0600`) or an interactive TTY with a WARN, never to a non-TTY stdout without
`--force-stdout`, and `--output json` strips it. Scope: `tenant:applications.write` (you must also
be allowed to create applications in the selected environment — otherwise `404`, exactly as
`clients create`). The mint is rate-limited per workspace (`429 rate_limited`).

### Custom domain (SSO-3303, epic SSO-3290)

`thoryn domain …` manages the workspace's one custom domain through product-api's
`/api/v1/custom-domain` (the workspace is always the one you are signed in to):

```bash
thoryn domain add auth.acme.com          # claim → PENDING; prints the two DNS records:
#   TXT    _thoryn-verify.auth.acme.com   thoryn-verify=<challenge>    (proves ownership)
#   CNAME  auth.acme.com                  <workspace>.auth.thoryn.io    (routes to the workspace)
thoryn domain verify                     # PENDING/SUSPENDED → VERIFIED once both records resolve
thoryn domain status                     # PENDING → VERIFIED → ACTIVE; SUSPENDED if a daily re-check fails
thoryn domain remove --yes
```

- Once the domain is `ACTIVE`, the workspace's platform host answers `410 issuer_retired` and names the new
  issuer (SSO-3415). A sign-in whose issuer the CLI derives from the workspace slug — `--workspace`, a
  `--connection` contract, a derived workload-identity audience — follows it **once** and prints
  `Workspace 'acme' now signs in at https://auth.acme.com …`, so application projects need no change when
  the domain goes live. Only `https` on a plain DNS name, with the same `/<environment>` path, is followed;
  a successor that is itself retired is refused. An issuer or `--audience` you named yourself is never
  swapped: the refusal names the platform's successor and you choose.
- A custom domain **changes the workspace's issuer** once it is `ACTIVE`. If the workspace already has
  production users, `add` is refused (`production_users_present`) until you pass `--accept-re-sign-in`;
  the acceptance is recorded and audited.
- Apex domains, IP addresses and Thoryn's own domains are refused (`domain_not_allowed`): use a
  subdomain such as `auth.<your-domain>` and point it at the platform host with the CNAME.
- `verify` exits `4` (not `2`) while the DNS does not prove the claim yet (`verification_failed`,
  with `reason` `txt_record_missing` / `cname_missing` / `cname_mismatch`), so a script can poll it.
- An unverified claim expires after 7 days (`claim_expired`); claim again for a new TXT value.
- A `SUSPENDED` domain keeps its certificate for 30 days (product-api `suspension.releaseAt`, oathy
  SSO-3371); verifying again before then brings it straight back. `status` shows the release time and a
  countdown (SSO-3399):
  `Released: 2026-10-26 03:00 UTC (in 28 days) — verify again before then to keep it; after that the domain goes back to PENDING and must be verified again with a new TXT record.`
  Once that time has passed it says `release pending`; a server that predates SSO-3371 sends no
  `releaseAt` and the line is omitted. `--output json|yaml` carries `suspension.releaseAt` as-is.
- Every subcommand accepts `--output json|yaml|table`; `--json` is shorthand for `--output json`.
  SSO-3414: `dnsRecords` are always `{type, name, value, ttl}` (a product-api that sends no `ttl` gets the
  recommended `300`), and `issuer` is the issuer the workspace mints on right now — the value to export
  for your applications (a sandbox appends `/<environment>`).
- SSO-3414 — `status --wait` / `verify --wait` block until the domain is `ACTIVE` (`--until VERIFIED` to
  stop earlier), bounded by `--timeout` (default 15m), checking every `--interval` (default 20s).
  `verify --wait` verifies each round; `status --wait` only reads (the platform re-checks a pending claim
  every 15 minutes). A timeout exits `4` with the last-check reason; no domain, an expired claim, a
  workspace without the entitlement or no access stop at once.
- SSO-3413 — as code: a `customDomain` resource in `.thoryn/provision.yaml`
  (`spec: { host: auth.acme.com, acceptReSignIn: false }`, workspace-level, no `environment`).
  `provision plan` shows the records (`--output json` → `changes[].customDomain.records`), `apply`
  claims and verifies (a failing DNS proof is reported, not an error; re-run or `--wait` converges), and
  the domain is released only by `--prune` / `destroy` with `--confirm <workspace-slug>`. A machine
  identity needs `tenant:domains.*` AND an explicit grant from a workspace admin:
  `thoryn access grant client:<id> manager custom_domain:<tenantId>`. Enabling custom domains for the
  workspace stays a Thoryn operator step (`thoryn operator custom-domain entitle <workspace>`).
- The scopes are part of the default `thoryn login` set. They are granted to the `cli` client by oathy
  hub V181, which must be deployed before a CLI release that requests them.

Full walkthrough: `docs/content/guides/custom-domain.mdx` in oathy (published at thoryn.org/docs).

### On-demand signing-key rotation (SSO-3369)

`thoryn keys …` asks for a new version of one of the selected environment's signing keys through
product-api's `/api/v1/signing-keys/{kind}/rotations`. The API only records the request; the identity
that already rotates the key on schedule carries it out.

```bash
thoryn keys rotate --kind sign-in --environment production --wait
# Rotation requested: 5b0f…  (sign-in, production)
# DONE — new version 3, kid tenant-ws.<workspace id>-v3. The previous version stays published, …
thoryn keys rotate --kind security-events --wait          # PENDING → DONE within about two minutes
thoryn keys rotations list --kind security-events         # the environment's requests, newest first
thoryn keys rotations get <id> --kind security-events
```

- **What changes.** New tokens (`sign-in`) or security events (`security-events`) are signed with the new
  version. The previous version stays published in the JWKS, so what it signed keeps validating;
  relying parties that look keys up by `kid` and refetch the JWKS on an unknown `kid` need no change.
- `rotate` asks for confirmation (it refuses without a terminal unless `--yes`). `--wait` follows the
  request until it is `DONE` or `FAILED` (`--timeout`, default `5m`); it exits `4` on `FAILED` or when the
  timeout passes while still `PENDING`.
- One request per key at a time (`409 rotation_pending` names the pending request) and a one-hour
  cooldown after a request (`429 rotation_cooldown` says when). `404 signing_key_not_found` means you
  are not an admin of the workspace (or the environment is not one you can reach).
- `--environment <slug>` targets an environment directly; otherwise the one `thoryn env use` selected.
- Every subcommand accepts `--output json|yaml|table`; `--json` is shorthand for `--output json`.
- The scopes are part of the default `thoryn login` set. They are granted to the `cli` client by oathy
  hub V183, which must be deployed before a CLI release that requests them.

#### Retiring a leaked key (SSO-3396)

Rotating keeps the previous version published, so a token forged with a **leaked** version would still
verify. `thoryn keys retire` retires it instead: every version up to `--through-version` (default: the
version signing now, and every older one) stops verifying at once; the signing version is rotated first
when needed, so signing continues. It cannot be undone.

```bash
thoryn login --acr-values urn:thoryn:acr:phishing_resistant --max-age 300   # passkey step-up (RFC 9470)
thoryn keys retire --kind sign-in --environment production                  # asks you to confirm the consequences
thoryn keys retire --kind security-events --through-version 2 --wait        # PENDING → DONE within about two minutes
thoryn keys retirements list --kind sign-in
```

- **Consequences.** `sign-in`: every ID token, access token, session and refresh token the retired versions
  signed stops working; relying parties must sign their users in again. `security-events`: receivers can no
  longer verify security events those versions signed. Ask your relying parties to fetch the JWKS again.
- Without a recent passkey sign-in the API answers an RFC 9470 step-up challenge; the CLI prints the exact
  `thoryn login --acr-values … --max-age …` line to run. `--acr-values` / `--max-age` apply to the
  interactive sign-in only.
- `tenant:keys.retire` is part of the default `thoryn login` set. It is granted to the `cli` client by oathy
  hub V189, which must be deployed before a CLI release that requests it.

Full walkthrough: `docs/content/guides/rotate-signing-keys.mdx` in oathy (published at thoryn.org/docs).

### Workload identity — CI sign-in with no secret (SSO-3308, epic SSO-3304)

A **workload identity trust** lets one GitHub repository's Actions jobs sign in to an environment
without any stored secret. The job asks GitHub for its own short-lived OIDC token, for the trust's
audience, and the CLI exchanges it for a workspace token (at most 15 minutes, no refresh token) carrying
the trust's scopes. The trust pins the repository by its immutable GitHub ids (a repository deleted and
re-created under the same name does not match), and optionally a GitHub environment, an exact ref, and
GitHub-hosted runners only.

```bash
# An environment manager creates the trust (once). The ids are looked up for a public repository;
# pass --owner-id and --repository-id for a private one.
thoryn workload-identity trusts create --environment staging --name billing-ci \
  --repository acme/billing --github-environment staging --scope tenant:applications.write
# → prints the clientId (wi_…), audience and token endpoint, a job snippet and the COMPLETE connection.json.
thoryn workload-identity trusts get <id> --connection      # SSO-3722 — prints that connection.json again, alone, to paste
```

In the workflow — the job needs `permissions: id-token: write` and nothing else:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: staging          # when the trust pins it
    permissions:
      contents: read
      id-token: write             # lets the job request its OIDC token
    steps:
      - run: thoryn login --workload-identity --client-id wi_3f0c9a1b2d4e5f6a7b8c9d0e --audience https://acme.auth.thoryn.io/staging --scope tenant:applications.write
      - run: thoryn provision apply --file .thoryn/provision.yaml --yes
```

Or commit the binding as a connection contract and run `thoryn login --connection .thoryn/connection.json`
(the provisioning Action does this; leave its `client-secret` input empty). **Commit it complete** — `trusts create`
prints it, `trusts get <id> --connection` prints it again, and it carries `auth.provider` and the **whole**
`auth.github` block exactly as `connection.schema.json` defines it (SSO-3722; a snippet without `provider` and
`github` is what made the `forge-plan` job of thoryn-cicd run 38751382032 request the apply scopes):

```json
{
  "apiVersion": "thoryn.io/connection/v1",
  "workspace": { "slug": "acme" },
  "auth": {
    "method": "workload_identity",
    "provider": "github_actions",
    "clientId": "wi_3f0c9a1b2d4e5f6a7b8c9d0e",
    "audience": "https://acme.auth.thoryn.io/staging",
    "scopes": ["tenant:applications.write"],
    "github": { "owner": "acme", "repository": "billing", "ownerId": 11, "repositoryId": 22, "environment": "staging", "ref": "refs/heads/main", "githubHostedRunnersOnly": true }
  }
}
```

- `audience` is the trust's audience **exactly** (the workspace issuer, plus `/<environment>` for a
  sandbox, or the custom domain when one is active). Omit it and give `"environment": "<slug>"` to have the
  CLI derive it from `workspace.slug` and `THORYN_ISSUER`; when the workspace's custom domain is active, the
  derived audience's platform host names the custom-domain issuer and the CLI uses that (SSO-3415). `tokenEndpoint` (default `<audience>/oauth2/token`)
  must be on the audience's origin — the CLI never sends a job token anywhere else.
- `github` grants nothing: it lets the CLI name the field that differs when a sign-in is refused, and its
  `environment` is the **apply environment the profile selector reads** (below). Without it the CLI cannot tell a
  plan job from an apply job and leaves the profile to the hub.
- **A job token works once.** Every exchange — including the automatic renewal when a later command finds
  the 15-minute token expired — requests a fresh one from the runner. A workload session renews only inside
  the job that signed in.
- **Refusals.** The platform answers every mismatch with the same `401 invalid_client` and records the
  reason only in the workspace audit log. The CLI prints what it sent, the job's own identity (the public
  claims of its token — never the token) and any difference it can see:

```text
Sign-in failed: the platform refused the workload identity exchange (HTTP 401: invalid_client).
The platform does not say which check failed. The exact reason is in the workspace audit log
(event workload_identity.exchange_failed, field errorReason); a workspace admin can read it with:
    thoryn audit query --event-type workload_identity.exchange_failed

Sent:
  client id            wi_3f0c9a1b2d4e5f6a7b8c9d0e
  audience             https://thoryn.auth.stg.thoryn.org/cli-wif
  token endpoint       https://thoryn.auth.stg.thoryn.org/cli-wif/oauth2/token
  scope                tenant:environments.read

This job (claims of its GitHub OIDC token; the token itself is not shown):
  sub                  repo:thoryn-io/thoryn-cli:pull_request
  repository           thoryn-io/thoryn-cli
  repository_id        1044556677
  repository_owner_id  187654321
  ref                  refs/pull/97/merge
  environment          (none)
  event_name           pull_request
  runner_environment   github-hosted

Differences found locally:
  - environment: the trust pins GitHub environment 'thoryn-staging-wif'; this job declares no `environment:` (add `environment: thoryn-staging-wif` to the job).

Compare the job above with the trust (`thoryn workload-identity trusts get <id>`): its client id, audience, repository ids, GitHub environment, ref and runner pin must all match, and it must live in the environment the audience names.

To fix — Option 1, with the CLI (a workspace admin):
  - job: add `environment: thoryn-staging-wif` to the job
To fix — Option 2, in the browser: Run through the Thoryn GitHub App to get a browser link.
```

**Every refusal ends with that `To fix` block** (SSO-3722 / SSO-3723; see "A red check names its fix" below): a
missing `permissions: id-token: write`, a pin that differs (with the one `thoryn workload-identity trusts create …`
that pins the trust to this job's own claims, then `trusts get <id> --connection` to paste), a scope outside the
profile (which line of `connection.json` to change), a token endpoint that could not be reached. With
`--fix-request` / `THORYN_FIX_REQUEST` the same text is written to the fix request — every refusal, not only the
plan-profile gap.

- A trust can carry only `tenant:` scopes your own session holds (`403 scope_not_grantable` otherwise). A
  production trust needs `--github-environment` and `--confirm-production`; `pull_request` and
  `pull_request_target` jobs are refused there.
- A trust with `tenant:workload-identity.write` lets its workflow create further trusts — grant it only
  deliberately.
- The `tenant:workload-identity.*` scopes are part of the default `thoryn login` set. They are granted to
  the `cli` client by oathy hub V192, which must be deployed before a CLI release that requests them.

#### One trust, two profiles — the plan job (SSO-3702; SSO-3699 option B)

A repository that provisions **production** from code runs two kinds of job on the **same `main`**: a
read-only **plan** on every pull request and a reviewed **apply** on merge (oauthy converge ADR Amendment 5).
A dispatched run executes on the default branch either way, so the GitHub **environment** is the only
thing that separates "may read" from "may write" — and until SSO-3702 that meant two trusts, two `wi_`
clients, two connection files and a plan identity the ownership gate could not tell from a foreign
repository (`owned_elsewhere` on the repository's own plan). Oauthy ADR
`2026-10-14-plan-identity-and-resource-ownership` (accepted, option B) collapses that into **ONE trust with
two scope profiles**:

- the **apply profile** — `--github-environment` (the reviewed environment) with the trust's `--scope` set;
- an optional **plan profile** — `--plan-environment` (a second, **unprotected** GitHub environment, e.g.
  `<apply>-plan`, so it runs on every pull request) whose jobs the hub mints **read-only scopes only**: the
  `.read` members of `--scope`, derived by the hub, or an explicit `--plan-scope` subset (each a
  `tenant:<area>.read`, each among `--scope`).

```bash
# At create — one trust, both profiles:
thoryn workload-identity trusts create --name thoryn-cli-ci --repository thoryn-io/thoryn-cli \
  --owner-id 229451779 --repository-id 1361536515 --github-environment thoryn-provision-e2e \
  --ref refs/heads/main --github-hosted-runners-only --confirm-production \
  --scope "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write tenant:access.read tenant:access.write" \
  --plan-environment thoryn-provision-e2e-plan            # plan scopes derived: the three .read members

# Or later, on an EXISTING trust — the ONE additive mutation; the wi_ client, its owner relation and the
# committed connection.json all stay (nothing to re-paste). Set once: 409 plan_profile_already_set after that.
thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment thoryn-provision-e2e-plan \
  [--plan-scope "tenant:environments.read tenant:access.read"]
```

**The hub decides by the job token's `environment` claim** and mints only the matched profile's scopes: a
plan job asking for a write scope is refused at sign-in with `invalid_scope` and
`error_description: scope_outside_plan_profile` (an apply job asking beyond the trust's scopes:
`scope_outside_apply_profile`); a job in neither environment is `environment_mismatch`. Least privilege is
structural — no second trust has to be configured correctly for a plan token to be unable to write.

**One `connection.json`, no `auth.plan`, no `connection.plan.json`.** `thoryn login --connection` reads the
job's own OIDC `environment` claim and decides **one of three ways** (SSO-3702, SSO-3722):

| `auth.github.environment` | job's `environment` claim | scope sent | sign-in line |
|---|---|---|---|
| names the apply environment | equal to it | `auth.scopes`, exactly | `Profile: apply (GitHub environment '…' — the trust's scopes).` |
| names the apply environment | any other | **none** — the hub mints the plan profile | `Profile: plan (read-only) — …` |
| **absent** (no `github` block, or no `environment` in it) | present | **none** — the hub matches the profile from the claim (SSO-3700's empty-request rule); never `auth.scopes` blindly | `Profile: decided by the hub (connection.json names no apply environment — add auth.github.environment to decide locally; …)` |
| any | absent (not GitHub; a pod) | `auth.scopes`, exactly — unchanged | — |

The third row is the fix for thoryn-cicd run 38751382032, where a connection without its `github` block made the
plan job request the apply scopes and the hub answered `invalid_scope` / `scope_outside_plan_profile`. The contract
does not declare the plan scopes because it could add nothing the hub does not already enforce (at best it would ask
for less, at worst for a write the hub refuses). The sign-in line names the profile:

```text
Signed in (workload identity / client 'wi_10a7…' at https://thoryn.auth.stg.thoryn.org, as …).
Profile: plan (read-only) — this job runs in GitHub environment 'thoryn-provision-e2e-plan', not the trust's apply environment 'thoryn-provision-e2e', so no scope was requested and the hub minted the trust's plan profile. Writes are refused by design.
Scopes: tenant:environments.read tenant:applications.read tenant:access.read
```

`thoryn login --status` and `thoryn whoami` print the same `profile`, and a write refused in a plan session
says it is the plan profile at work rather than suggesting a login with more scopes. `trusts get` / `list`
render `planEnvironment`, `planScopes` and both `subjectPatterns` (apply, then plan). Since the plan runs as the
repository's **one** identity — the `owner` of what it provisions — the engine's ownership gate is green for
its own resources and stays `owned_elsewhere` for anyone else's (SSO-3659 / SSO-3673, unchanged).

GitHub only for now: a Forgejo job token has no `environment` claim (its selector is the forge-side App
story's), a Kubernetes trust has no plan jobs (`plan_profile_unsupported`). Needs oauthy SSO-3700 (hub) and
SSO-3701 (product-api) deployed; the dogfood migration of this repository's own trust is SSO-3704.

This retargets SSO-2879's `--workload-identity` (an operator-registered token exchange signed with a CI
key; its `--tenant`, `--wif-*` and `--subject-token` flags are gone).

#### Kubernetes — a pod pulls its own client secret (SSO-3684, parent SSO-3678)

A `--provider kubernetes` trust pins a **cluster's OIDC issuer, a namespace and a service account**
(oauthy #4095, ADR `2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull`). The pod's
credential is the **projected ServiceAccount token** Kubernetes already gives it (`iss` = the cluster,
`sub` = `system:serviceaccount:<namespace>:<serviceAccount>`, `aud` = the trust's audience). The reason to
want this is software that can only consume a `client_secret` — oauth2-proxy, Forgejo's OIDC login,
Grafana — in front of Thoryn SSO: the pod's **init container** signs in with the token and rotates the
application's secret into an in-memory volume the application reads. No client secret crosses a
repository, a CI secret store or a person.

```bash
# A PRIVATE cluster (k3s, kind, on-prem: Thoryn cannot reach its issuer) pins its PUBLIC key set; a managed
# cloud cluster (EKS, GKE, AKS) publishes its issuer — omit --jwks-file and Thoryn discovers the keys once.
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
thoryn workload-identity trusts create --provider kubernetes --name forge-oauth2-proxy \
  --issuer "$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)" \
  --namespace forge --service-account forge-oauth2-proxy --jwks-file cluster-jwks.json \
  --scope tenant:applications.write --confirm-production
# → prints the clientId (wi_…), audience, inlineKeyIds (never key material), the connection.json below and
#   the projected-volume + init-container snippet. A production trust must pin BOTH names: the CLI refuses
#   --confirm-production without them, as the API refuses `production_requires_service_account`; a sandbox
#   trust may pin the namespace only. --jwks-file must be a JWK Set of PUBLIC keys — a private parameter
#   (`d`, `p`, …) is refused before anything is sent.
```

The connection contract gains a **token source**: the identity token is read from a FILE on every exchange
(sign-in and renewal — Kubernetes refreshes the projected token in place), not from a GitHub runner:

```json
{
  "apiVersion": "thoryn.io/connection/v1",
  "workspace": { "slug": "thoryn" },
  "auth": {
    "method": "workload_identity",
    "provider": "kubernetes",
    "clientId": "wi_9a8b7c6d5e4f3a2b1c0d9e8f",
    "audience": "https://thoryn.auth.thoryn.io",
    "tokenSource": { "kind": "file", "path": "/var/run/secrets/tokens/thoryn/token" },
    "scopes": ["tenant:applications.write"],
    "kubernetes": { "issuer": "https://kubernetes.default.svc.cluster.local", "namespace": "forge", "serviceAccount": "forge-oauth2-proxy" }
  }
}
```

- `auth.provider` is `github_actions` (default) or `kubernetes`. `auth.tokenSource.kind` is
  `github_actions` (default when absent: `ACTIONS_ID_TOKEN_REQUEST_*`) or `file` (then `path` is
  required). A `kubernetes` provider REQUIRES a `file` token source; `auth.kubernetes` (the trust's pins,
  diagnostics only — like `auth.github`) belongs to it alone. The path is public configuration; the file's
  content is the credential and is never recorded (`tokens.json` keeps the path, never the token).
- The flag form is `thoryn login --workload-identity --client-id <wi_…> --audience <aud> --token-file <path>`.
- A missing, unreadable or empty token file fails closed naming the PATH (exit 73, nothing sent); the
  usual cause is a projected volume mounted elsewhere than the connection says.
- A refusal prints the **pod's** identity (`iss`, `sub`, `aud`, namespace, service account — never the
  token) and, with `auth.kubernetes` present, the pin that differs (`namespace: the trust pins 'forge';
  this pod runs in 'staging'`). The hub's own reasons (`namespace_mismatch`, `service_account_mismatch`,
  `claim_missing` for a legacy non-projected token, `unknown_signing_key` after a key rotation) are in the
  workspace audit log.
- The trust's client needs `manager` on the application whose secret it rotates (`thoryn access grant`) — or,
  with provisioning-as-code, declare `secretSink: { kind: workloadPull, trust: <trust name> }` on the
  application and `apply` converges that grant (SSO-3921; **deprecated** with the whole pod-pull path since
  SSO-3951 — see "Where a minted secret goes" below for the customer-managed default that replaces it).
  Rotation is a pod restart: the previous secret stays valid for 24 hours.

The complete, applyable manifest — ServiceAccount, the connection ConfigMap, the projected token volume
(`audience` = the trust's audience, `expirationSeconds: 3600`), the Thoryn init container
(`thoryn login --connection /etc/thoryn/connection.json && thoryn clients rotate-secret $APP_CLIENT_ID
--secret-file /shared/client-secret`), the in-memory `/shared` volume and oauth2-proxy reading
`--client-secret-file=/shared/client-secret` — is [`examples/kubernetes/`](examples/kubernetes/README.md).

### Project repositories — `thoryn project init` (SSO-3435, epic SSO-3304)

`thoryn project init` sets up a GitHub repository for Thoryn from the command line, with **your own
GitHub CLI (`gh`) and no GitHub App**. There are two kinds:

- **config** — the repository that manages your workspace's configuration: **tenant provisioning**
  (`apiVersion: thoryn.io/tenant/v1`, SSO-3962 — see "Two file parts" below). It gets two secret-less
  workload identity connections: **production** (manager of the workspace; a change reaches it only
  through a pull request a reviewer approved) and one **sandbox** (manager of that sandbox).
- **app** — a repository that connects one application to an existing **sandbox**: **application
  provisioning** (`apiVersion: thoryn.io/application/v1`). It gets one connection to that sandbox. It never
  gets a production trust; its production client is created from its own file under a creation slot a
  workspace admin approves.

What each connection gets comes from the template's `.thoryn/template.json`
(`thoryn.io/starter-template/v2`, published by thoryn-io/thoryn-starters): its exact scopes, its access
grant, and the GitHub Actions variables to set. This is the same contract the console's GitHub App
flow uses, so both set up a repository the same way.

**Before you start.** Sign in (`thoryn login --workspace <slug>`, which also selects that workspace; run
`thoryn workspace switch <slug>` only to act in another workspace you belong to). Install `gh` and run `gh auth login` as a GitHub user who can create repositories
for the owner, and who is an admin of an existing repository. Thoryn never sees your GitHub token: it
runs `gh` and `gh` authenticates on its own.

#### A config project

```bash
# A new private repository, created from thoryn-io/starter-config:
thoryn project init config --repo acme/thoryn-config \
  --reviewer alice --reviewer bob --confirm-production
# Optional: --sandbox <slug> picks (or creates) the sandbox. Default: the only sandbox, else a new `sandbox`.
```

```text
Set up the config project acme/thoryn-config for workspace acme.

  repository      created  acme/thoryn-config (private) from thoryn-io/starter-config
  codeowners      committed  .github/CODEOWNERS: @alice @bob own /.thoryn/environments/production/, /.github/workflows/, /.github/CODEOWNERS
  ruleset         created  thoryn-production-approval on main: pull request with 1 approval + code-owner review, stale approvals dismissed, no force-push or deletion, no bypass
  protection      set      GitHub environment thoryn-production: deploys from main only; required reviewers not offered by this GitHub plan (the ruleset carries the approval)
  environments    created  sandbox sandbox
  workload-trust  created  sandbox: starter-sandbox-1044556677 → wi_… (in sandbox)
  workload-trust  created  production: starter-production-1044556677 → wi_… (in production, GitHub environment thoryn-production)
  access          granted  client:wi_… manager environment:<id>
  access          granted  client:wi_… manager workspace:<id>
  variables       set      THORYN_ISSUER, THORYN_WORKSPACE, THORYN_SANDBOX_ENVIRONMENT, THORYN_SANDBOX_WIF_CLIENT_ID (repository); THORYN_PRODUCTION_WIF_CLIENT_ID (environment thoryn-production)
  provisioning    pending review  pull request pending review: https://github.com/acme/thoryn-config/pull/1 — .thoryn/environments/sandbox/connection.json (pending review), …

Next steps:
  1. Clone it: gh repo clone acme/thoryn-config
  2. GitHub's initial commit started a first workflow run before the variables existed, so its Thoryn jobs skipped. Re-run it …
  3. Provisioning files pending review: https://github.com/acme/thoryn-config/pull/1 — each connection's connection.json and starter provision.yaml. Merge it, and the repository converges its own configuration from then on …
  4. Production changes need a pull request to main approved by a code owner (alice, bob); only main deploys to the GitHub environment thoryn-production. (Environment reviewers are not offered by this GitHub plan.)
```

The rules match the console's flow. There is one production connection. `--reviewer` (1–6 GitHub
logins) and `--confirm-production` are required. You must be a manager of the workspace, and you must
be signed in as yourself: a person, not a machine identity. The production trust pins the repository's
immutable ids, the GitHub environment `thoryn-production` and the default branch.

**Production approval.** All of this is set up **before** anything is written in Thoryn:

1. **A reviewed pull request on the default branch.** A repository ruleset named
   `thoryn-production-approval` (adopted and updated on a re-run) requires a pull request with at least
   one approving review, requires a code-owner review, dismisses stale approvals on a new push, blocks
   force-pushes and deletion, and has **no bypass actors**.
2. **CODEOWNERS.** `.github/CODEOWNERS` makes the `--reviewer` logins the owners of production's
   configuration, the workflows, and the CODEOWNERS file itself, so no one can drop the approval by editing
   it without a reviewer. The file is exactly:

   ```text
   /.thoryn/environments/production/ @alice @bob
   /.github/workflows/ @alice @bob
   /.github/CODEOWNERS @alice @bob
   ```

   An existing, different CODEOWNERS is a conflict: the command stops unless you pass `--force`.
   - **With `--repo`, when this run creates the ruleset:** nothing was protected before, so CODEOWNERS is
     committed through the GitHub API first and the ruleset is enforced right after.
   - **With `--repo`, when the ruleset already exists:** an active ruleset is **never** disabled or weakened,
     not even with `--force`. That would put an unreviewed change on the default branch. The ruleset is
     brought back to the required shape and enforced first, which only tightens it; a disabled one is
     re-enforced. A CODEOWNERS change then goes through a pull request from the branch `thoryn/codeowners`
     (reused on a re-run), and the output says `CODEOWNERS update pending review: <PR url>`. The run
     continues, because the ruleset already requires an approved pull request.
   - **In an existing clone:** it is written to the working tree and reaches GitHub with your pull
     request.
3. **The production GitHub environment** accepts deployments from the default branch only.
4. **Environment reviewers**, when your plan offers them. GitHub offers required reviewers for a private
   repository only on GitHub Enterprise. On another plan it refuses them, and the environment is set up
   without them: the ruleset carries the approval. The output, and `productionApproval.mechanisms` in
   JSON (`pull_request_ruleset`, `environment_reviewers`), show which mechanisms are active.

Before it sets `THORYN_PRODUCTION_WIF_CLIENT_ID`, the CLI reads back the ruleset (it must be active) and
the environment.

| Repository | GitHub plan | Result |
|---|---|---|
| public | any | ruleset + CODEOWNERS + environment reviewers |
| private | Enterprise | ruleset + CODEOWNERS + environment reviewers |
| private | Pro or Team | ruleset + CODEOWNERS (no environment reviewers on this plan) |
| private | Free | **refused**: GitHub Free has no rulesets for private repositories |

#### An app project

```bash
# The sandbox must exist and you must manage it (thoryn env list):
thoryn project init app --stack express --environment dev --repo acme/web
# stacks: express | spring-boot | aspnet-core

# … and its PRODUCTION client, proposed on the workspace's config repository (SSO-3669):
thoryn project init app --stack express --environment dev --repo acme/web \
  --config-repo acme/thoryn-config --production-url https://web.acme.example
```

#### The app's production client — `--config-repo` + `--production-url` (SSO-3669) — DEPRECATED

> **Superseded (SSO-3962, oauthy ADR 2026-10-25 decision 1).** The app project owns its production client in its own
> `thoryn.io/application/v1` file — a second `kind: application` without `environment:` — created by its reviewed apply
> once a workspace admin approves a **creation slot** for the repository's identity (`thoryn access reserve
> client:<wi_…> application:<clientId>`, or the consent screen via `thoryn access approve`). The deploy reads the id
> from `thoryn provision apply --output json` / `thoryn clients list`. The two flags below still work for one release,
> against a config file still on `thoryn.io/provision/v1` (a `thoryn.io/tenant/v1` file refuses an `application`, exit 4
> `config_provision_file_unusable`); `publishTo` prints a `Warning:`. See "Two file parts" below.

An app repository is **sandbox-only**: it never gets a production trust, and its `.thoryn/provision.yaml` declares
only its sandbox client. Its **production** OAuth client is declared in the workspace's **config repository**, in
`.thoryn/environments/production/provision.yaml`, where every production change is a reviewed pull request plus an
approved production run (oauthy ADR `2026-10-13-production-clients-declared-in-the-config-project`, §1). With
`--config-repo <owner>/<name>` and `--production-url <https://…>`, `thoryn project init app` proposes that entry for
you **after** its sandbox steps succeeded, with your own `gh`:

- **One pull request, from the deterministic branch `thoryn/app-<app repository name>`.** A re-run updates the same
  branch and the same pull request; it never opens a second one. The config repository's default branch is never
  written, and the command never merges.
- **The entry**, converged by `name` (the app repository's name): added when absent — every other line of the file,
  comments included, is kept as it is — replaced when it differs (the file is then re-rendered from its parsed tree,
  so its comments are not kept; the output says so), and **nothing is proposed** when the default branch already
  declares it exactly:

  ```yaml
    - kind: application          # no `environment`: the production plane
      name: web                  # = the app repository's name
      spec:
        displayName: acme/web
        clientType: public       # PKCE proves the client; no secret exists anywhere
        grantTypes: [authorization_code]
        scopes: [openid, profile, email]
        redirectUris: ["https://web.acme.example/callback"]
        postLogoutRedirectUris: ["https://web.acme.example/signed-out"]
      publishTo:
        - kind: githubActionsVariable
          repository: acme/web   # the app repository
          environment: production
          name: THORYN_PRODUCTION_CLIENT_ID
  ```

  The redirect URIs are `--production-url` plus `/callback` and `/signed-out`: the paths every application
  starter registers in its shared `.thoryn/provision.yaml` (the template's `template.json` does not declare them).
  Edit them in the pull request if your deployment differs.
- **`publishTo`** (SSO-3668): on every approved production apply, the config project publishes the client's id to the
  app repository's `production` GitHub environment as the Actions **variable** `THORYN_PRODUCTION_CLIENT_ID`
  (a variable, never a secret — a client id is public). The app's production deploy job reads
  `${{ vars.THORYN_PRODUCTION_CLIENT_ID }}`; nothing production-related is written into the app repository.
- **The pull request body says what the reviewer approves**: a production public client, its redirect URIs, and
  where its id is published.
- **Pre-flight, before any write:** the config repository must be visible to your `gh` sign-in and its production
  file must take the entry. A config repository `gh` cannot see stops the run (exit 4, `config_repository_not_found`)
  with the by-hand steps — it is **never created** by this command (`thoryn project init config` does that). When
  `gh` is missing or signed out, the by-hand steps include this pull request.

The report carries it as `configProject` (`repository`, `file`, `branch`, `pullRequest`, `outcome`
`added | updated | declared`, `application`), and as the step `config-project` (`pending review`, `open` on a re-run
with nothing new, `declared` when the config repository already has it). Without the two flags the run is unchanged
and the last next-step says how to add the production client.

#### In an existing clone

Leave out `--repo` and run the command at the root of a clone of your GitHub repository, or pass
`--dir <path>`. `gh repo view` names the repository. The template's files are added to the working
tree:

- An existing file with the same content is skipped.
- An existing file with **different** content is never overwritten. The command lists the conflicts and
  stops **before any change**. `--force` overwrites them.
- Nothing is committed. The output ends with the `git add … && git commit … && git push` to run.

```bash
cd web && thoryn project init app --stack express --environment dev
```

#### The `.thoryn/` files it seeds

Once the trusts exist, the command seeds two files per connection, so the repository is in the
provisioning-as-code loop from its first commit (`thoryn provision plan` on a pull request,
`thoryn provision apply` on the default branch — oauthy ADR 2026-10-13). Both sit next to the
connection's `provisionFile` from `.thoryn/template.json`: `.thoryn/` for an app project,
`.thoryn/environments/<connection>/` for a config project.

- **`connection.json`** — who the repository is: a `workload_identity` connection contract
  (`thoryn login --connection .thoryn/connection.json`, no secret) with the trust's client id, audience
  and scopes, and its GitHub pins. It is derived from the trust and validated against the bundled
  connection schema before it is written. A re-run rewrites it when this repository's own copy differs
  (the trust was recreated); an identical one is left alone. A connection.json that is **not** this
  repository's — another repository's, or a `client_credentials` one — is a conflict like any other
  differing file: the command stops, and `--force` replaces it.
- **`provision.yaml`** — what the repository owns, as a starter in the same shapes
  `thoryn provision` already converges. An app project declares its OAuth client in its sandbox
  (`kind: application`, public with PKCE, a framework-default redirect URI to adjust). A config project's
  production section declares the workspace's sandbox environment (matched by its slug, named as it is);
  its sandbox section anchors on that sandbox by slug only — that connection holds
  `tenant:environments.read`, so nothing in the starter can need a write — and names the kinds to add
  (`loginMethods`, `federationMember`, `emailProvider`, `loginTheme`, `loginFlow`). It is seeded only
  when **absent** and never overwritten afterwards: from then on the file is in control.

Where they go depends on how the command ran:

| Run | The seeded files |
|---|---|
| in a clone | written to the working tree; they land with your commit or pull request |
| `--repo`, repository created by this run, **app** | committed to the default branch |
| `--repo`, repository created by this run, **config** | proposed in a pull request from the branch `thoryn/provisioning` (the approval ruleset protects the default branch by then); a re-run converges and names the same pull request |
| `--repo`, repository that already existed | not added — like the template's files; the output says whether they are present and how to add them (run inside a clone) |

#### Flags

| Flag | Kind | Meaning |
|---|---|---|
| `--repo <owner/name>` | both | The GitHub repository. It is created from the template when it does not exist, and used as it is when it does. Leave it out to work on the clone. |
| `--public` | both | Create the repository public. The default is private. Only with `--repo`. |
| `--dir <path>` | both | The clone's root. Only without `--repo`. |
| `--force` | both | Overwrite files that differ: the template's files and a foreign `connection.json` in a clone, or (config, `--repo`) propose replacing an existing `.github/CODEOWNERS`. `--force` never weakens the approval ruleset: under an existing ruleset the replacement is a pull request. It never overwrites an existing `provision.yaml`. |
| `--template <owner/repo>` | both | Start from another template repository, such as a mirror. The default is `thoryn-io/starter-<stack>`; for config, `thoryn-io/starter-config`. |
| `--sandbox <slug>` | config | The sandbox to configure. It is created when it does not exist. |
| `--reviewer <login>` | config | A GitHub user who approves every production run. Repeatable, 1–6, required. |
| `--confirm-production` | config | Required. The project gets a production workload identity that manages the workspace. |
| `--stack <stack>` | app | `express`, `spring-boot` or `aspnet-core`. |
| `--environment <sandbox>` | app | The existing sandbox the application connects to. `production` is refused. |
| `--config-repo <owner/name>` | app | The workspace's config repository. The app's production client is proposed on it as a pull request (branch `thoryn/app-<name>`, reused on a re-run). Requires `--production-url`. Never created here, never merged, never its default branch. |
| `--production-url <https://…>` | app | Where the app runs in production; the client's redirect URIs are `<url>/callback` and `<url>/signed-out`. https only, no query or fragment. With `--config-repo`. |
| `--output json\|yaml\|table`, `--json` | both | The report (steps, trusts, grants, variables, files, the seeded provisioning files, next steps) as JSON/YAML. |

Exit codes: `0` done · `1` not signed in to Thoryn · `2` product-api refused a call · `3` a `gh` step
failed · `4` a pre-flight check refused (nothing was changed) · `64` invalid flags.

#### What it runs on GitHub (your `gh`)

```text
gh --version ; gh auth status                                     # installed, signed in (output never shown)
gh api repos/<template>/contents/.thoryn/template.json             # the template's declaration (must be v2)
gh api repos/<owner>/<name> ; gh api users/<login>                 # the repository's ids; the owner / each reviewer
gh repo view --json nameWithOwner ; gh api repos/<template>/tarball # (clone only) the repository; the template's files
gh api --method POST repos/<template>/generate -f owner=… -f name=… -F private=… -f description=…
gh api repos/<o>/<r>/branches/<default>                              # (config, new repo) wait until GitHub has generated it
gh api repos/<o>/<r>/contents/.github/CODEOWNERS ; gh api --method PUT … --input -   # (config, --repo) the reviewers' CODEOWNERS (direct only when this run creates the ruleset)
gh api repos/<o>/<r>/git/ref/heads/thoryn/codeowners ; gh api --method POST repos/<o>/<r>/git/refs … ; gh api [--method POST] repos/<o>/<r>/pulls …   # CODEOWNERS change under an existing ruleset
gh api repos/<o>/<r>/rulesets ; gh api repos/<o>/<r>/rulesets/<id> ; gh api --method POST|PUT repos/<o>/<r>/rulesets[/<id>] --input -  # (config) thoryn-production-approval — read first, written only when not in shape
gh api repos/<o>/<r>/environments/thoryn-production                              # (config) read first
gh api --method PUT repos/<o>/<r>/environments/thoryn-production --input -      # (config) reviewers + branch policy, only when not in shape; again without reviewers on a billing-plan 422
gh api [--method POST|DELETE] repos/<o>/<r>/environments/thoryn-production/deployment-branch-policies[/<id>]
gh api repos/<o>/<r>/rulesets/<id> ; gh api repos/<o>/<r>/environments/thoryn-production   # (config) read back before its variable
gh variable list --repo <o>/<r> [--env thoryn-production] --json name,value       # read first
gh variable set <NAME> --body <value> --repo <o>/<r> [--env thoryn-production]   # only a variable that differs
gh api repos/<o>/<r>/contents/.thoryn/… ; gh api --method PUT repos/<o>/<r>/contents/.thoryn/… --input -   # (app, new repo) the seeded files
gh api repos/<o>/<r>/git/ref/heads/thoryn/provisioning ; gh api --method POST repos/<o>/<r>/git/refs … ; gh api [--method POST] repos/<o>/<r>/pulls …   # (config, new repo) the seeded files' pull request
gh api repos/<cfg> ; gh api repos/<cfg>/contents/.thoryn/environments/production/provision.yaml   # (app, --config-repo) pre-flight: the config repository and its production file
gh api repos/<cfg>/git/ref/heads/thoryn/app-<name> ; gh api --method POST repos/<cfg>/git/refs … ; gh api repos/<cfg>/contents/…?ref=thoryn/app-<name> ; gh api --method PUT repos/<cfg>/contents/… --input - ; gh api [--method POST] repos/<cfg>/pulls …   # (app, --config-repo) the production client's pull request — only what differs is written
```

On Thoryn it uses your own session and the public customer-plane API: `GET /api/v1/environments`,
`GET /api/v1/access/mine`, `POST /api/v1/environments` (config, only when the sandbox is missing),
`GET`/`POST /api/v1/workload-identity/trusts`, and `GET`/`POST /api/v1/access/grants` (a grant is read
first and posted only when missing).

#### Nothing half-done, and safe to re-run

Every check runs **before the first change**, on both sides. The checks are: the flags; your Thoryn
session and your reach (you manage the sandbox, or the workspace for config); `gh` installed and signed
in; the template (v2 and valid); the scope ceiling (a trust carries exactly the template's scopes, and
you can grant only scopes you hold); the repository (it resolves, or its owner exists); the reviewers
exist; file conflicts in a clone; and a conflicting trust.

A later step can still fail on something no check can see, such as GitHub refusing the ruleset for
the plan. The CLI then lists the steps it completed and stops. Every step can be repeated, so run
the same command again:

- The repository is re-used.
- The approval ruleset `thoryn-production-approval` is adopted and brought back to the required shape,
  and the environment protection too (other reviewers and extra branch policies are replaced).
- Trusts are adopted. A trust is found by its deterministic name, `starter-<connection>-<repository id>`.
  A trust the console's GitHub App flow created is found by its pins: the same repository id,
  GitHub environment, ref and scopes.
- Grants are read first; an existing grant is left alone. Variables are read first (`gh variable list`);
  only one that differs is set.
- Identical files are skipped; an existing `provision.yaml` is kept; this repository's own
  `connection.json` is rewritten only when it differs.
- The production client's pull request on the config repository (`--config-repo`) is reused: the branch
  `thoryn/app-<name>` is read first, its file committed only when it differs, the open pull request named again.

**A second run makes no write** — not to product-api, not to GitHub, not to the working tree. Every
step reads before it writes, and the report says `Checked the … project` instead of `Set up …`; in JSON,
`steps[].status` is `existing` / `adopted` / `in place` / `unchanged` / `kept` throughout.

#### Troubleshooting

| You see | Why, and what to do |
|---|---|
| `gh is not installed` / `gh is not signed in` (exit 4) | Nothing was changed. Install `gh` and run `gh auth login`, then re-run. The output also lists the commands it would run, with your workspace, issuer, sandbox and ids filled in, if you want to do it by hand. |
| `The template repository … has no .thoryn/template.json` or `declares apiVersion '…/v1'` (exit 4) | The published template is missing or older than this CLI. Nothing was changed. Re-run once the v2 template is published, or point `--template` at a repository that has one. |
| `These files already exist with different content: …` (exit 4) | Move them aside and re-run, or re-run with `--force` to overwrite them. |
| `Your session does not hold …` (exit 4) / `scope_not_grantable` (exit 2) | A trust can carry only scopes you hold. Run `thoryn login`: its default scopes include every scope the templates use. |
| `You do not manage sandbox …` / `needs you to manage the workspace` (exit 4) | Managers delegate. Ask a workspace admin for `thoryn access grant member:<you> manager environment:<id>` (or `workspace:<id>`). |
| `Production approval needs a reviewed pull request on the default branch, which GitHub Free does not support for private repositories.` (config; exit 4, or 3 when this run created the repository) | GitHub Free has no rulesets for a private repository, and a config project's production changes must go through a reviewed pull request. It is refused: there is no fallback. Use GitHub Pro, Team or Enterprise, or a public repository. This happens before anything is written in Thoryn, so nothing exists there. If `--repo` created the repository in this run, it is kept and the message names it. Delete it yourself (`gh repo delete <owner>/<name>`) if you do not want it. |
| `required reviewers not offered by this GitHub plan` (config, success) | Not an error. GitHub offers environment reviewers for a private repository only on GitHub Enterprise. The reviewed pull request (ruleset + CODEOWNERS) carries the approval. |
| `already has a different .github/CODEOWNERS` (config, exit 4) | Merge the three ownership lines into your CODEOWNERS and re-run, or re-run with `--force` to replace it. Once the approval ruleset exists, that replacement is a pull request. |
| `CODEOWNERS update pending review: <url>` (config, success) | The default branch is already protected, so the CLI does not commit to it: it opened (or reused) a pull request from `thoryn/codeowners`. Have a reviewer approve and merge it. |
| `Provisioning files pending review: <url>` (config, success) | The seeded `connection.json` + starter `provision.yaml` of each connection went through a pull request from `thoryn/provisioning`, because the approval ruleset protects the default branch. Merge it; the repository then converges its own configuration. A re-run converges and names the same pull request. |
| `These files already exist with different content: .thoryn/connection.json` (exit 4) | The clone has a connection.json that is not this repository's own (another repository's, or a `client_credentials` one). Move it aside, or re-run with `--force` to replace it with the trust's `workload_identity` contract. An existing `provision.yaml` is never a conflict: it is kept. |
| `the protection step failed — gh: …` (exit 3) | GitHub refused the environment for another reason. Most often you lack admin rights on the repository. The message is GitHub's own. |
| `cannot yet grant a machine client workspace-wide management` (exit 2, config) | The platform does not yet support `manager` on `workspace:<id>` for a client. Everything before it is kept and no variable is set. Re-run once it does. |
| `Trust 'starter-…' … exists but pins another …` (exit 4) | A trust with the deterministic name exists with other pins or scopes. Delete it (`thoryn workload-identity trusts delete <id> --environment <env>`) and re-run. |
| `GitHub does not show the config repository … to your gh sign-in` (app, exit 4, `config_repository_not_found`) | `--config-repo` names a repository that does not exist or that your `gh` login cannot see. Nothing was changed on either side. The command never creates the config repository: create it with `thoryn project init config --repo <owner>/<name> …`, or ask for access, and re-run. The output lists the by-hand steps (clone, branch `thoryn/app-<name>`, the entry to append, `gh pr create`). |
| `The production client cannot be added to <cfg>:.thoryn/environments/production/provision.yaml: …` (app, exit 4, `config_provision_file_unusable`) | The config repository's production file is not valid YAML, its `resources:` list is not the last top-level key, or the result would not validate. Nothing was changed. Fix the file on its default branch (or add the entry by hand — the output shows it) and re-run. |
| `Production client pending review: <url>` (app, success) | The entry went to the config repository as a pull request from `thoryn/app-<name>`. A reviewer of the config project merges it; the approved production run creates the client and publishes its id to this repository's `production` GitHub environment as `THORYN_PRODUCTION_CLIENT_ID`. If that publish cannot reach this repository, the output names the one `gh variable set` to run with the id from the production run's `apply --output json`. |
| `… the file was re-rendered and its comments are not kept` (app, success) | The config repository already declared this client with other values (another `--production-url`, say). Replacing an entry re-renders the file from its parsed tree, so its comments are lost on the branch; review the diff in the pull request. Adding an entry keeps every existing line. |

### Two file parts — tenant and application (SSO-3962, epic SSO-3960)

Per oauthy ADR `2026-10-25-provisioning-is-tenant-and-applications.md`, Thoryn's scope is two halves that are not
symmetric: a workspace **configures its tenant** (who can sign in, where users come from, how sign-in looks and
behaves, which policies apply) and lets **applications use that tenant** through standard OAuth 2.0 / OIDC. **An
application is a user of the tenant** — it references the tenant's roles and environments by name and defines nothing
about them. Provisioning as code is therefore two parts, and a project belongs to exactly one:

| | **Tenant provisioning** | **Application provisioning** |
|---|---|---|
| `apiVersion` | `thoryn.io/tenant/v1` | `thoryn.io/application/v1` |
| Owner | ONE config project per workspace | MANY app projects per workspace |
| Kinds | `environment`, `federationMember`, `user` (sandbox test users included), `loginMethods`, `loginFlow`, `loginTheme`, `emailProvider`, `customDomain`, `role`, `workloadIdentityTrust` | `application` (with `tokenClaims` + `roleMapping`, and the applications-API settings) |
| Relation | **defines** the tenant | **uses** the tenant: names roles / environments, never defines them |
| Identity | the config project's trust: broad `tenant:*` write; production through a reviewed PR | the app project's trust, confined to `tenant:applications.read`, `tenant:applications.write`, `tenant:access.read`; its production client created under a consent-approved **creation slot** (`thoryn access reserve` / `thoryn access approve`) |
| Who declares its trust | a person, once; the config project then owns and converges it | **the config project** (one `kind: workloadIdentityTrust` per app repository) — an app project never declares a trust, not even its own |

**A tenant file** (the config project's `.thoryn/environments/<section>/provision.yaml`):

```yaml
apiVersion: thoryn.io/tenant/v1
resources:
  - kind: environment
    name: dev
    spec: { slug: dev, displayName: "Sandbox dev" }
  - kind: loginMethods
    environment: dev
    spec: { methods: [password, passkey] }
  - kind: role
    name: editor
    environment: dev
    spec: { permissions: [docs:write] }
  - kind: user                                   # a sandbox TEST USER is tenant provisioning: who may sign in
    name: tester
    environment: dev
    spec: { email: tester@example.com, passwordEnv: TEST_USER_PASSWORD, emailVerified: true }
  - kind: workloadIdentityTrust                  # the CI identity of the app project acme/web, declared HERE
    name: web-ci
    environment: dev
    spec:
      provider: github_actions
      github: { repository: acme/web, environment: dev }
      scopes: [tenant:applications.read, tenant:applications.write, tenant:access.read, tenant:environments.read]
```

**An application file** (the app project's `.thoryn/provision.yaml`):

```yaml
apiVersion: thoryn.io/application/v1
resources:
  - kind: application
    name: web
    environment: dev                             # names the tenant's sandbox; never declares it
    spec:
      displayName: "acme/web"
      clientType: public
      grantTypes: [authorization_code, refresh_token]
      redirectUris: ["https://web.acme.example/callback"]
      tokenClaims:
        sources: [permissions, roles]
        roleMapping: { editor: Editors }         # role NAMES the tenant defines (kind: role in the config project)
  - kind: application                            # its PRODUCTION client — no `environment:` — created under a creation slot
    name: web-production
    spec:
      clientId: web-production
      displayName: "acme/web"
      clientType: public
      grantTypes: [authorization_code]
      redirectUris: ["https://web.acme.example/callback"]
```

**The engine refuses a kind from the other part before any call** (exit 64), naming the file's part, the kind's part
and the project it belongs in:

```text
Error: invalid provisioning file '.thoryn/provision.yaml':
  - resources[1] `role` is tenant provisioning; this is an application file (thoryn.io/application/v1). Declare it in the workspace's config project (it defines the tenant, and an application is a user of the tenant).
```

and the other way round: `` `application` is application provisioning; this is a tenant file (thoryn.io/tenant/v1).
Declare it in the application's own project ``. `thoryn project init config` seeds tenant files, `thoryn project init app`
an application file. The bundled schema is part-aware (`apiVersion` enum + a per-part `kind` enum).

**The trust-scopes rule follows the part** (`config.trust-scopes`, SSO-3926): an application file needs
`tenant:applications.read` + `tenant:access.read` to plan and `tenant:applications.write` to apply, **and nothing else**
— the workflow check and the plan preflight say so. A declared mechanism of the application's *own* object adds what it
strictly needs, and the rule names it: `tenant:environments.read` for a client in a sandbox (the sandbox's id for the
ownership check), `tenant:workload-identity.read` for a `federatedTrust` / `workloadPull` trust resolved by name,
`tenant:access.write` for a `grants:` block or a `workloadPull` sink's `manager` grant. A connection that declares a scope
an application file never needs (`tenant:users.write` on an app project, say) **fails** the check: the identity is wider
than its file — narrow the trust with `thoryn workload-identity trusts set-scopes`. A tenant file needs the union of its
kinds' scopes, as before.

**Migration — `thoryn.io/provision/v1` keeps working for one release.** `plan` / `apply` / `import` / `destroy` print a
`Warning:` on stderr naming the part the file should declare (all tenant kinds → `thoryn.io/tenant/v1`; only
applications → `thoryn.io/application/v1`), or — when it declares both — which resources are tenant provisioning and
which are application provisioning, and that it is two files. `thoryn provision split` writes them:

```bash
thoryn provision split                      # .thoryn/provision.yaml → .thoryn/tenant.provision.yaml + .thoryn/application.provision.yaml
# the tenant file goes to the workspace's config project, the application file stays in the app project;
# the source is left as it is (delete it once both are committed where they belong). Outputs are re-rendered,
# so the source's comments are not carried over; `thoryn provision plan --file <path>` on each is the check.
```

By hand, the recipe is the same: copy the `resources:` entries whose kind is in the tenant column into a file with
`apiVersion: thoryn.io/tenant/v1` in the config project, the `application` entries into a file with
`apiVersion: thoryn.io/application/v1` in the app project, and keep `environment:` / `secretSink.trust` / `federatedTrust`
as they are — they name the tenant's objects by slug / name, which is how an application file references what the tenant
defines. A fresh file written by `thoryn provision import --write` declares the part of its entries (both parts ⇒ the
mixed format, which warns).

**`publishTo:` is deprecated** (SSO-3668, ADR 2026-10-13 §2 — superseded by ADR 2026-10-25 decision 1): the app
project owns its production client in every environment, created under a creation slot, and its deploy reads the client
id from its own apply (`thoryn provision apply --output json`, `thoryn clients list`), not from a variable another
repository publishes. A file carrying it still publishes today and prints a `Warning:`; a later release refuses it. The
same goes for `thoryn project init app --config-repo` / `--production-url`, which propose the superseded shape (and only
work against a config file still on `thoryn.io/provision/v1` — a tenant file refuses an `application`).

### Least-privilege access grants (SSO-3113, epic SSO-3108)

A **grant** is `subject → relation → object`: `client:cli-ci manager environment:<id>` says the
machine client `cli-ci` may manage that one sandbox and nothing else. It is the unit a
**least-privilege CI identity** is confined with — instead of a machine client holding every
`tenant:*` scope across the whole workspace, it is made `manager` of exactly the sandbox it
provisions. Two surfaces, one grammar:

- **`thoryn access grant | revoke | list | mine`** — imperative, for a founder wiring things up
  or inspecting who can reach what. `list` needs `--object` and/or `--subject`; `mine` answers
  for the session's own subject (`{ "data": [ "environment:<id>", … ] }`).
- **`thoryn access reserve | reservations | release`** (SSO-3792) — application **creation slots**, which are
  not grants: a workspace admin approves that one workload identity creates one named application on one plane,
  once, within 30 days (`reserve client:<wi_…> application:<clientId> [--environment <slug>]`, `production` by
  default). The repository's own apply creates it and becomes its owner. `reservations` lists them (an admin sees
  every slot, anyone else its own; `--subject` narrows); `release application:<clientId>` releases one (the
  holder) or revokes it (an admin). Refusals: `409 application_exists` (grant `owner` instead),
  `409 application_slot_held` (another identity holds it), `409 reserved_client_id`, and one opaque `404` for
  "not an admin / not a trust's workload client / unknown environment". See "Creation slots" below.
- **`grants:` on a resource in `provision.yaml`** — declarative, converged by `provision apply`
  like any other field. The **object is implicit** (it derives from the live id the resource
  resolves to — `environment:<id>`, `application:<clientId>`, `user:<id>`,
  `federation_member:<id>`, and the per-environment singletons by their env slug —
  `email_provider:<envSlug>`, `login_theme:…`, `login_flow:…`, `login_methods:…`), so a file can
  never grant on an object it does not own:

  ```yaml
  - kind: environment
    name: ci
    spec: { slug: cli-ci, displayName: "thoryn-cli CI sandbox" }
    grants:
      - { subject: "client:cli-ci", relation: manager }   # the CI identity manages ONLY this sandbox
  ```

  After the resource exists (create / update / even a no-op), `apply` lists the object's grants
  (`GET /api/v1/access/grants?object=…`) and **POSTs the missing ones**. Grants are **additive by
  default** (SSO-3715, ADR 2026-10-15 §2): a live grant the block does not declare is shown as
  `present, not declared` (`plan` prints it, `--output json` carries it as `changes[].grantsUndeclared`)
  and left alone — there is no ledger of "this file granted it". With **`--prune`**, on every declared
  object the caller may delete (the owner rule below), the undeclared grants are **revoked** — except
  the `owner` tuple, workspace usersets (`workspace:<id>#admin`, any `workspace:` subject) and the
  caller's own subject. Grants on objects the file does not declare are never touched. Omit `grants:`
  to leave an object's grants unmanaged; `grants: []` declares none. `plan` prints the grant diff
  (`grant + client:cli-ci manager`, `grant - … (not declared; --prune)`) and counts it. A session
  without `tenant:access.write` **fails closed** with the scope named — the resource itself is live
  by then, so nothing is lost; re-run after `thoryn login --scope tenant:access.write` (or after
  granting the CI client that scope).

Since SSO-3182 the two scopes are part of the DEFAULT `thoryn login` scope set (the default set is
exactly the `cli` login client's registered scopes in `.thoryn/provision.yaml`, which the product side
deployed to the hub under SSO-3112), so a bare `thoryn login --workspace <slug>` can converge a file
with `grants:` — no hand-typed `--scope` list.

### A provisioned confidential client's secret (SSO-3113)

A confidential `application` (product-api's default `clientType`; a `client_credentials` machine
identity) is minted a **one-time `client_secret`** on create. Since SSO-3954 (oauthy ADR 2026-10-14 amended
2026-10-25, SSO-3951 — Thoryn owns the secret lifecycle, **the customer owns delivery**) `provision apply`
**discards** that value unless the resource declares a sink that delivers it (`kubernetesSecret` / `file`,
next section): the client is created, nothing is shown, written or granted, nothing is undelivered, and the apply
prints the person's step with the real id — `thoryn clients rotate-secret <clientId> --secret-file <path>`, then
store it in your secret manager or an operator-created Kubernetes Secret. `plan` marks such a create with
`(a client secret will be minted and discarded — managed by the customer: …)` and prints
`application <name>: secret: managed by the customer (…)`. The value never enters the plan, a log, or any channel.

`--secret-file <path>` / `--force-stdout` are the **fallback** of a declared `kubernetesSecret` / `file` sink that
cannot be reached (the same `SecretIo` channel as `thoryn clients create`: owner-only `0600`, a second one at
`<path>.<clientId>`, an interactive TTY with a `WARNING`, a non-interactive stdout refused without `--force-stdout`).
When a declared sink reaches neither, the client is **still created** and `apply` exits **65** naming
`thoryn clients rotate-secret <clientId> --secret-file <path>`.

### Where a minted secret goes — `secretSink:` (SSO-3659)

Per oauthy ADR `2026-10-13-provisioning-as-code-converge-github-app-and-fga-ownership.md` §5, **a secret is
delivered where it is consumed, never into a CI secret store**, and per the 2026-10-25 amendment of oauthy ADR
`2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull` (product-owner decision SSO-3951) **Thoryn
owns an application's client-secret lifecycle — mint, show once, rotate with the 24 h overlap, revoke, audit — and
the customer owns delivery into its runtime** (Vault / OpenBao, a cloud secret manager, External Secrets, an
operator-created Kubernetes Secret). A `secretSink:` says which of the four shapes a confidential application takes;
the value never enters the file, the plan, a log, or a `kubectl` argument.

**The default — the customer manages the secret (`customerManaged`, SSO-3954).** The forge's two login clients
(`thoryn-cicd/.thoryn/provision.yaml`), created by the repository's CI apply on a runner with no kubeconfig, no
`--secret-file` and no TTY:

```yaml
apiVersion: thoryn.io/provision/v1
resources:
  - kind: application
    name: forge-forgejo-login
    spec:
      displayName: "Forgejo login"
      grantTypes: ["authorization_code"]           # no clientType ⇒ confidential ⇒ a secret is minted on create
      redirectUris: ["https://forge.thoryn.org/user/oauth2/thoryn/callback"]
    # no secretSink ⇒ { kind: customerManaged } — the same, written out:
    # secretSink: { kind: customerManaged }
```

- **`plan`** marks the create `(a client secret will be minted and discarded — managed by the customer: a person mints
  it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and stores it in your secret manager …)` and
  prints `application forge-forgejo-login: secret: managed by the customer (…)`; the summary counts
  `N client secret(s) managed by the customer`. In `--output json`: `changes[].secretSink = { kind: customerManaged }`
  and `summary.customerManaged`.
- **`apply`** creates the client and **discards** the one-time value — never shown, written, logged or handed to a sink
  or channel (not even a `--secret-file` that is given) — grants nothing to anyone, reports nothing undelivered, and
  prints `application forge-forgejo-login: client secret discarded (never shown or stored) — managed by the customer:
  mint it with `thoryn clients rotate-secret <clientId> --secret-file <path>` and store it in your secret manager`.
  Exit 0 with no secret channel at all. A re-apply mints nothing. The unseen create-time secret is replaced by the
  person's rotation and expires with its 24 h overlap; nobody holds it.
- **The person's step (the runbook):** on a machine that reaches Thoryn and your secret store,
  `thoryn clients rotate-secret <clientId> --secret-file ./s --confirm <workspace-slug>`, store the file's value where
  the runtime reads it — e.g. `kubectl -n <ns> create secret generic <name> --from-file=client-secret=./s` — then delete
  the local file. Rotation: the same, then a rollout, inside the 24 h overlap.
- `thoryn provision workflow check` **passes** such a file on `config.secret-delivery`, with a notice per application
  that says exactly the above; a `kubernetesSecret` or `file` sink still fails that rule (nothing on a hosted runner
  can reach them). `config.trust-scopes`: a file of such applications needs `tenant:applications.read` /
  `tenant:applications.write` and `tenant:access.read` only.

**`workloadPull` — DEPRECATED (SSO-3921 → SSO-3951; removed by SSO-3953).** Rung 3 of the credential ladder — the
application's own pod minting its secret at start under a `kubernetes` workload-identity trust (see "The Thoryn init
container" above) — is no longer the customer story: it couples Thoryn to the customer's deployment platform (cluster
issuers, keys, namespaces, service accounts, manifests). The engine **still converges it** unchanged, and every `plan`
and `apply` prints `! application <name>: secretSink workloadPull is DEPRECATED (product-owner decision SSO-3951 …)`
on stderr (`--output json`: `warnings[]`; the workflow check: the rule's detail). What it did, for the record:

```yaml
    secretSink:
      kind: workloadPull
      trust: forge-forgejo                         # a kubernetes trust on the same plane, pinning the Forgejo pod's
                                                   # namespace + service account, carrying tenant:applications.write
```

The trust is either declared in the same file (same `environment`; a sandbox trust is created by this apply) or
already live — a **production** trust is created once by a person (`thoryn workload-identity trusts create
--provider kubernetes …`) and only looked up here by name.

- **`plan`** prints `application forge-forgejo-login: secret: pulled at runtime by trust forge-forgejo
  (workload client wi_…; apply discards the minted value)` on every plan of the application, and the grant
  it converges: `grant + client:wi_… manager` (the relation `thoryn clients rotate-secret` needs on the
  application, and the one under which the hub lets that workload client replace an in-flight secret —
  oauthy SSO-3696). In `--output json`: `changes[].secretSink` = `{ kind: workloadPull, trust,
  workloadClientId }` and `summary.pull`. A create is marked `(a client secret will be minted and discarded —
  the pods of trust forge-forgejo mint their own at start)`.
- **`apply`** creates the client and **drops** the one-time value — never printed, written, logged or handed to
  a sink — so nothing is undelivered: no `--secret-file`, TTY or `kubectl` is needed and the apply exits 0. It
  then converges `client:<wi_…> manager` on the application (with a declared `grants:` block it is part of the
  block, so `--prune` never revokes it; without one it is the only grant touched). A re-apply mints nothing and,
  with the grant in place, writes nothing.
- **The pod** signs in and runs `thoryn clients rotate-secret <clientId> --secret-file /shared/client-secret`
  (the init containers of [`examples/kubernetes/`](examples/kubernetes/README.md), deprecated with it); its
  rotation replaces the unseen secret the create minted.
- **Refused** at plan time, before any write: a trust that is neither declared nor visible in the application's
  plane (`workload_pull_trust_not_found`; a declared one this identity cannot see is `access_not_reachable`,
  `viewer` on it by name); a trust declared for ANOTHER plane (`workload_pull_trust_other_plane`); a trust that
  is not `provider: kubernetes` (`workload_pull_trust_not_kubernetes` — a CI job that fetches a secret to hand
  on is the courier again); a trust without `tenant:applications.write` (`workload_pull_scope_missing` — its
  pod's rotation would be a `403`). A `workloadPull` sink on a public or secret-less client is refused like any
  `secretSink:`.

**Leaving `workloadPull` — what the file does and what a person does (SSO-3954).** Dropping the sink from an
application, and the `workloadIdentityTrust` it named from the file, changes **nothing live by itself** when `prune`
and `destroy` are off (the reusable workflow's defaults): the application plans `noop` with no sink line (nothing is
minted for an existing client), the `manager` grant the sink converged is **not revoked** (the file declares no
`grants:`, so it manages none — not even `--prune` touches them), and the live trust is left alone. The grant and the
trust are a person's to remove, after the pull request that dropped them has merged and applied — the forge's own
sequence (`thoryn-cicd/.thoryn/README.md`, "Retiring the pod trusts"):

```bash
thoryn login --workspace <slug> --issuer <issuer>            # a workspace admin
thoryn workload-identity trusts list                         # the ids and wi_ clients of the pod trusts
thoryn access list --object application:<clientId>           # the manager relation the sink converged
thoryn access revoke client:<wi_ of the pod trust> manager application:<clientId>
thoryn workload-identity trusts delete <trust id> --yes --confirm <slug>
```

Do it in that order: a trust is deleted only once nothing in the file names it, and a production trust cannot be
re-created by the repository's identity. Then narrow the repository trust: with no trust declared and no sink, the
file no longer needs `tenant:workload-identity.read` / `.write` or `tenant:access.write`
(`thoryn workload-identity trusts set-scopes <trust> --scope …`, and `auth.scopes` of `connection.json` to match —
`config.trust-scopes` says which). The lint and the engine never make a person's deletion for them.

**From your own workstation, a sink can deliver.** A `kubernetesSecret` sink is for an apply an OPERATOR runs
with a `kubectl` context for the cluster (the reusable provisioning workflow has none):

```yaml
    secretSink:
      kind: kubernetesSecret
      namespace: forge                             # must already exist — thoryn never creates a namespace
      name: forgejo-thoryn-login                   # the Secret your Deployment mounts / envFrom's
      key: client-secret                           # the data key
```

A local or self-managed shape — an owner-only file next to the deployment that reads it:

```yaml
    secretSink:
      kind: file
      path: .secrets/forgejo-thoryn-login.secret   # 0600; an existing file is NOT overwritten unless `apply --force`
```

What `thoryn provision` does with it:

- **`plan`** prints the intended delivery as a line (`application forge-forgejo-login: deliver client
  secret → kubernetesSecret forge/forgejo-thoryn-login key client-secret`; in `--output json`,
  `changes[].secretSink` and `summary.deliver`) and marks the create `(a client secret will be minted and
  delivered to …)`. No secret exists at plan time: `plan` mints nothing and runs no `kubectl`.
- **`apply`** creates the client and only then delivers — so a sink that cannot be reached never costs
  anything: the client is live, and the next plan reads it. `kubernetesSecret` goes through **your own
  `kubectl`** (whatever context it is configured with; thoryn handles no cluster credential), the
  `install-forge` pattern with the value **on stdin, never on argv**:
  `kubectl version --client` → `kubectl get namespace <ns> -o name` (reachability and existence in one read)
  → `kubectl -n <ns> create secret generic <name> --from-file=<key>=/dev/stdin --dry-run=client -o yaml` →
  `kubectl -n <ns> apply -f -`. `file` is the same owner-only (`0600`) writer `--secret-file` uses, refusing
  to overwrite an existing file unless `apply --force`.
- **A sink that cannot be reached** (no `kubectl`, a wrong context, a missing namespace, RBAC, an existing
  file) is a reason, printed with the value redacted; the secret then falls back to `--secret-file` (or an
  interactive TTY). **When nothing reaches**, the client stays created and `apply` exits **65**
  with `undelivered_secrets`, naming the resource, the sink, the reason and the recovery:

  ```
  Error: undelivered_secrets — every resource was converged, but the client secret of 1 created application(s) could not be delivered:
    application/forge-forgejo-login (clientId 7f1c…) → kubernetesSecret forge/forgejo-thoryn-login key client-secret: namespace 'forge' is not reachable through the current kubectl context (…); thoryn never creates a namespace
      mint a new secret by hand: thoryn clients rotate-secret 7f1c… --secret-file <path>
  ```

  A secret is minted only on create, so the next `apply` of an existing client delivers nothing — the
  recovery is always `thoryn clients rotate-secret <clientId> --secret-file <path>` (production-clients ADR
  §3 tier 3), then placing that file's value yourself.

Rules the schema and the loader both enforce: `secretSink` sits on `kind: application` only and only on a
confidential one (`clientType: public` is minted nothing and is refused); it is refused on a `readOnly: true`
reference (nothing is minted for a dependency — the owning repository delivers); a `customerManaged` is exactly
`{ kind }`; a `kubernetesSecret` is exactly `{ kind, namespace, name, key }` with Kubernetes grammars (namespace:
RFC 1123 label; name: RFC 1123 subdomain; key: `[-._a-zA-Z0-9]+`); a `file` is exactly `{ kind, path }`; a
`workloadPull` is exactly `{ kind, trust }` with `trust` a resource name, and a trust declared in the same file must
sit on the application's plane, be `provider: kubernetes` and carry `tenant:applications.write`.

### Publishing an application's client id to the repository that deploys it (SSO-3668) — DEPRECATED

> **`publishTo:` is deprecated (SSO-3962; oauthy ADR 2026-10-25 supersedes ADR 2026-10-13 §1–§2) — accepted for one
> more release, then refused.** The application project owns its production client in every environment (created under
> a consent-approved creation slot), so there is no id to carry back: the deploy reads it from the app's own
> `thoryn provision apply --output json` or `thoryn clients list`. A file carrying `publishTo` still publishes today and
> `plan` / `apply` print a `Warning:` naming the resources; move the client to the app project's
> `thoryn.io/application/v1` file and drop the block. See "Two file parts — tenant and application" above. What follows
> describes the shipped-and-retiring behaviour.

Per oauthy ADR `2026-10-13-production-clients-declared-in-the-config-project.md` (SSO-3444), an
application repository stays sandbox-only: its **production** OAuth client is declared in the
workspace's **config repository**, converged by that repository's reviewer-protected production run,
and the resulting client id is **published to the application repository as a GitHub Actions
variable** on its `production` environment. The app's production deploy reads the variable at run
time; nothing production-related is written into the application repository, and it makes no Thoryn
call for the id. The declaration is a `publishTo:` block on the `application` resource — the output
sibling of the secret channel: the value is a client id, public by construction, so it is always a
**variable**, never a secret.

The config repository's `.thoryn/environments/production/provision.yaml` (no `environment:` means
the production plane; the example is the Express starter's `billing-web` app):

```yaml
apiVersion: thoryn.io/provision/v1
resources:
  # … the workspace's own production configuration (environments, sign-in methods, branding, …) …

  # Production OAuth client of the application repository acme/billing-web.
  # Owned by this repository: changing a redirect URI is a reviewed PR here plus an approved production run.
  - kind: application
    name: billing-web
    spec:
      displayName: "Billing web"
      clientType: public                 # PKCE proves the client; no secret exists anywhere
      grantTypes: ["authorization_code"]
      scopes: ["openid", "profile", "email"]
      redirectUris:
        - "https://billing.acme.example/callback"
      postLogoutRedirectUris:
        - "https://billing.acme.example/signed-out"
    publishTo:
      - kind: githubActionsVariable
        repository: acme/billing-web        # the app repository, reachable by the gh login that runs apply
        environment: production             # the app repository's GitHub environment; created if absent
        name: THORYN_PRODUCTION_CLIENT_ID   # the variable; upserted on every apply
```

What `thoryn provision` does with it:

- **`plan`** prints the pending publish as a line (`application billing-web: publish clientId →
  githubActionsVariable acme/billing-web (environment production) THORYN_PRODUCTION_CLIENT_ID`; in
  `--output json`, `changes[].publishTo`) and reaches no target — a pull-request check shows where the
  id will land.
- **`apply`** publishes **after** the resource is converged (the id is known), on **every** apply — an upsert, so a re-created client propagates without a second step and a
  variable someone changed by hand is repaired. The publisher is your own `gh` login:
  `gh variable set THORYN_PRODUCTION_CLIENT_ID --body <clientId> --repo acme/billing-web --env production`,
  creating the environment when it does not exist (bare, with no protection rules) and **never
  writing an existing environment** — its reviewers and branch policy stay what the app repository's
  admins set.
- **The target itself is the record** (SSO-3715): the plan / job summary shows where the id lands, and
  `apply --output json` carries the id (`resources[].id`).
- **A target the `gh` login cannot reach** (the repository is not visible, `gh` is not signed in, the
  environment cannot be created) is the apply error `publish_target_unreachable`, raised **after**
  convergence: the client exists, `--output json` still prints its id, the exit is non-zero, and the
  error names the one `gh variable set … --body <id> …` a human can run.

Rules the schema and the loader both enforce: `publishTo` sits on `kind: application` only (an
application's clientId is the one output a resource has); it is refused on a `readOnly: true` reference
(a reference publishes nothing — the owning repository does); each target is exactly
`{ kind, repository, environment, name }` with `repository` as GitHub `owner/name`, `name` matching
`[A-Z_][A-Z0-9_]*` outside the reserved `GITHUB_` prefix, and no two targets naming the same variable.

The app's production deploy job then runs in its `production` environment and reads
`${{ vars.THORYN_PRODUCTION_CLIENT_ID }}`, resolving the issuer from the discovery document as the
starters already do — see the oauthy guide *Declare an application's production client in the config
project* for the deploy-job shape.

### Secretless clients — `clientAuthenticationMethods`, `jwksUri` / `jwks`, `federatedTrust` (SSO-3689)

Per oauthy ADR `2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull.md` (the **credential
ladder**: secret-less by key, secret-less by platform identity, runtime pull, courier — most preferred first)
and ADR `2026-10-14-federated-client-authentication-for-login-clients.md` (rung 2), an `application`
declares **how it authenticates** at the token endpoint instead of being minted a secret by default:

```yaml
resources:
  # Rung 1 — the application's own key pair; only its PUBLIC half is declared.
  - kind: application
    name: billing-api
    spec:
      displayName: "Billing API"
      grantTypes: [client_credentials]
      clientAuthenticationMethods: [private_key_jwt]
      jwksUri: https://billing.acme.example/.well-known/jwks.json   # or an inline `jwks: { keys: [ { kty, kid, n, e } ] }` — exactly one of the two

  # Rung 2 — the workload's platform identity token IS the client assertion (ADR 2026-10-14 §11). Nothing is minted.
  - kind: workloadIdentityTrust
    name: billing-pods
    spec:
      provider: kubernetes
      kubernetes: { issuer: "https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE", namespace: billing, serviceAccount: billing-web }
      scopes: [tenant:applications.read]
      confirmProduction: true
  - kind: application
    name: billing-web
    spec:
      displayName: "Billing web"
      redirectUris: ["https://billing.acme.example/cb"]
      grantTypes: [authorization_code, refresh_token]
      clientAuthenticationMethods: [federated_assertion]
      federatedTrust: billing-pods          # the trust's NAME in the same environment — the engine resolves it to the id the API takes
```

- **The methods are a closed set:** `private_key_jwt`, `federated_assertion`, `client_secret_basic`, `none`.
  `client_secret_post` is deliberately **not declarable** (`invalid_client_authentication_method`): a secret in
  the request body is the courier rung. Omitted ⇒ product-api's default for the `clientType`
  (`client_secret_basic` for a confidential client, `none` for a public one) — the existing behaviour.
- **`private_key_jwt` needs the public key:** `jwksUri` (https) **xor** an inline `jwks`
  (`private_key_jwt_key_required` / `jwks_or_jwks_uri`). An inline set holds **public keys only** — a `d`, `p`,
  `q`, `dp`, `dq`, `qi`, `oth` or `k` member is `invalid_jwks` (a private key in a repository is a secret in the
  repository, exactly what the file exists to make impossible).
- **`federated_assertion` is refused client-side with the hub's own codes** (`FederatedLoginClientBinder` /
  product-api's `FederatedAssertionBindingValidator` answer the same tokens): it is the ONLY method
  (`federated_assertion_only_method`, also for `clientType: public` — a public client authenticates with
  `none`), grants beyond `authorization_code` / `refresh_token` are `federated_assertion_grant_not_allowed`
  (a workload that needs `client_credentials` uses the trust's own `wi_…` client; SSO-3767: the RFC 8693
  token-exchange grant is allowed only together with `allowTokenExchange: true` — see "Application settings"), `requireProofKey: false`
  is `federated_assertion_pkce_required`, a `jwks` / `jwksUri` is `federated_assertion_no_secret_or_key`,
  a missing `federatedTrust` is `federated_trust_required`, and a `federatedTrust` without the method is
  `federated_trust_without_method`. A trust that is missing, or declared in this file for ANOTHER
  environment, is the plan error **`federated_trust_not_found`** (a login client binds a trust of its own
  environment; the hub checks the same); `apply` refuses the plan before writing. **SSO-3774:** a trust this
  file DECLARES that the identity cannot see (the platform lists a trust only to who reaches it) is
  **`access_not_reachable`** instead, with `owner` on the trust by name as its fix; and **binding** a client to a
  trust (on a create, or an update that changes `federatedTrust`) needs `manager` on the TRUST as well — a
  trust the identity only views is `access_not_owned` (fix: `owner trust:<id>`), one another repository owns
  is `access_owned_elsewhere` (product-api SSO-3773 answers both as the opaque `federated_trust_not_found`;
  the plan says why).
- **No secret is minted or expected** for a `private_key_jwt` / `federated_assertion` client (the API answers
  `clientSecret: null`): `plan` prints no "will be minted", nothing reaches `--secret-file` or a sink, and a
  `secretSink:` next to such methods is `secret_sink_without_secret_method` — a sink is legal only when the
  declared methods include a secret-bearing one (`client_secret_basic`).
- **All three converge on UPDATE**, not only at create (the 2026-10-13 ADR's reading note): a changed
  method set or trust binding is one `PATCH` carrying exactly that field. **The key location is the
  exception you should know about:** product-api's `ApplicationResponse` does not render `jwksUri` / `jwks`
  yet (SSO-3716), and since SSO-3715 there is no receipt to remember what the file last sent, so the key
  location is **never diffed**: it is sent on create and **re-sent, idempotently, with every update** of the
  client (the plan's row says `key location declared — not readable from the API, re-sent with any update`).
  A changed `jwksUri` / `jwks` **alone** therefore plans no update until SSO-3716 lands — change it together
  with any rendered field, or re-send it by hand (`thoryn clients update`).
- **Order:** `apply` converges environments, then every `workloadIdentityTrust`, then everything else — so
  a client may bind a trust the same file declares; the plan shows the pending binding as
  `federatedTrust: (unset) → billing-pods (created by this apply)`. Removal is child-first: clients before
  the trust they bind.

### Application settings — token exchange, authorization detail types, session lifetime (SSO-3766, SSO-3767, SSO-3770)

These settings of an application are on the product API (oauthy, 2026-10-17; introspection and the token format
2026-10-18) and declarable on a
`kind: application`. Each is sent on create, read back from the live application and **converged on update**
with exactly the fields that differ. **An omitted setting keeps whatever the platform holds** — the file only
changes what it declares. `--prune` is unchanged: it removes resources, never a setting.

```yaml
resources:
  - kind: application
    name: portal
    environment: staging
    spec:
      clientId: acme-portal
      displayName: "Acme Portal"
      redirectUris: ["https://app.acme.example/login/oauth2/code/thoryn"]
      grantTypes: [authorization_code, refresh_token, "urn:ietf:params:oauth:grant-type:token-exchange"]
      # SSO-3767 — RFC 8693 token exchange (downscope a user's token, or enter another workspace the user belongs to).
      allowTokenExchange: true
      # SSO-3766 — the RFC 9396 authorization_details types the application may send at /oauth2/par and /oauth2/authorize.
      allowedAuthorizationDetailTypes: [openid_credential]
      # SSO-3770 — a 1 h idle window that ends 8 h after sign-in, however active the session is.
      refreshTokenTtlSeconds: 3600
      refreshTokenSlidingWindow: true
      refreshTokenAbsoluteMaxTtlSeconds: 28800
```

| Setting | Type, default | Converged as | Refused in the file (exit 2, before any read) | Refused by the API (at apply) |
|---|---|---|---|---|
| `allowTokenExchange` | boolean, `false` | a value | `token_exchange_requires_confidential_client` (`clientType: public` or method `none`), `token_exchange_grant_required` (the token-exchange grant is not in `grantTypes`) | `token_exchange_not_grantable` (403) — **predicted by the plan**, see below |
| `allowedAuthorizationDetailTypes` | list of strings, `[]` | a **set**: order is not drift; the declared list replaces the live one; `[]` clears it | not a list, an entry with a space (one type per entry), a duplicate | `unsupported_authorization_details_type` (400 — not in the server's discovery `authorization_details_types_supported`, plus `thoryn_access_grant`); `authorization_details_type_not_permitted` (403 — `thoryn_access_grant` outside the `thoryn` home workspace; no grant changes this) |
| `refreshTokenSlidingWindow` | boolean, `false` | a value | — | — |
| `allowTokenIntrospection` | boolean, `false` | a value | `token_introspection_requires_confidential_client` (`clientType: public` or method `none`) | `token_introspection_not_grantable` (403) — **predicted by the plan**, like `token_exchange_not_grantable` (same right, same production-plane note) |
| `accessTokenFormat` | `self-contained` \| `reference`, `self-contained` | a value | `invalid_access_token_format` (any other value) | — |
| `dpopAllowed` | boolean, `false` | a value | not a boolean | — |
| `dpopRequired` | boolean, `false` | a value | not a boolean | — |
| `refreshTokenAbsoluteMaxTtlSeconds` | integer seconds, 3600 – 7776000; live default 7776000 | a value | `token_ttl_out_of_range`; `session_lifetime_requires_sliding_window` (declared without `refreshTokenSlidingWindow: true` — the file states the session, it does not lean on the live window); `session_lifetime_below_refresh_ttl` (shorter than a declared `refreshTokenTtlSeconds`) | `session_lifetime_below_refresh_ttl` (shorter than the LIVE refresh TTL); `session_exceeds_tenant_policy` (longer than the environment authentication policy's `refreshClipSeconds` — the cap is named in the error) |

**Who may turn token exchange on.** With the setting on, an application that holds a user's token can obtain
fresh tokens for that user, including in other workspaces the user belongs to — a decision about the
environment. So turning it **on** for an existing application needs `manager` on the application's
**environment** (the workspace on the production plane); managing — even owning — the application is not
enough. `plan` asks before anything is written: the row is red with `token_exchange_not_grantable`, and the
"To fix" block (and `--fix-request`) names the right:

```text
1 resource(s) failed the ownership check — apply would refuse this plan:
  ! application portal: token_exchange_not_grantable — turning allowTokenExchange on for application/portal requires `manager` on its environment environment:env-1 — …
To fix — Option 1, with the CLI (a workspace admin):
  - manager on environment:env-1 for client:wi_…: token_exchange_not_grantable — …
      thoryn access grant client:wi_… manager environment:env-1
```

On the production plane the right is `manager` on the workspace, which is never granted to a repository
identity: the row carries a note instead — a workspace admin applies the file from their own session, or the
file drops the setting. **Turning it off, omitting it, or re-declaring the value the application already holds
is never refused.** A `federated_assertion` client may register the token-exchange grant too, only together
with `allowTokenExchange: true` (`federated_assertion_grant_not_allowed` otherwise).

**Introspection and reference tokens (SSO-3810 / SSO-3807).** `allowTokenIntrospection: true` lets an application
(a resource server) call RFC 7662 introspection at its workspace; the endpoint answers `active` only for tokens of
the same workspace and environment. An application that introspects reads the metadata of every token its
environment issues, so turning it **on** needs the same `manager` on the environment as token exchange, and the
plan predicts `token_introspection_not_grantable` the same way. `accessTokenFormat: reference` makes the token
endpoint issue the application opaque access tokens, which a resource server resolves through introspection;
any manager of the application may set it. Thoryn's own management API accepts `self-contained` tokens only.

**DPoP (SSO-3811).** `dpopAllowed: true` makes a DPoP proof the application presents bind its access token
(`token_type: DPoP`); without it a proof is ignored and the application gets Bearer tokens. `dpopRequired: true`
makes a proof mandatory — declare it only once every installation sends one. Neither is gated beyond managing the
application: a sender constraint widens nothing.

```yaml
  - kind: application
    name: orders-api
    environment: staging
    spec:
      displayName: "Orders API"
      clientType: confidential
      grantTypes: [client_credentials]
      scopes: [tenant:applications.read]
      allowTokenIntrospection: true
  - kind: application
    name: orders-mobile
    environment: staging
    spec:
      displayName: "Orders mobile"
      redirectUris: ["https://orders.acme.example/cb"]
      grantTypes: [authorization_code, refresh_token]
      accessTokenFormat: reference
```

**A refusal at apply names the resource, the code and the change** (`Error: application/portal:
session_exceeds_tenant_policy — … cap of 86400 seconds …`), never the "Required scope" hint a bare `403` would
otherwise print. Everything converged before it stays live; fix the cause and re-run.

### Roles and claims in the token — `kind: role`, `tokenClaims` (SSO-3941, SSO-3945)

The product API grants access through **RBAC roles** (`/api/v1/roles`) and puts a person's effective permissions — or
their role names, translated into the application's own vocabulary — into the tokens of an application that asks for
them (`/api/v1/applications/{clientId}/token-claims`). A provisioning file declares both; who holds a role is a
person-by-person act (`thoryn users roles add`, above).

```yaml
resources:
  - kind: role
    name: forge-maintainer          # the role's name — the converge key, unique per environment
    environment: staging            # omit for the production plane
    spec:
      description: "Maintains the forge"   # optional; omitted keeps the live description
      permissions: ["forge:maintain", "forge:read"]   # the FULL set ([] grants nothing)
  - kind: application
    name: forge
    environment: staging
    spec:
      clientId: forge
      displayName: "Forge"
      redirectUris: ["https://forge.acme.example/oauth2/callback"]
      tokenClaims:
        sources: [permissions]      # the user's effective permission names → claim `permissions`
```

An application that reads **roles** instead — the forge expects a `Maintainers` group, not Thoryn's role name — asks for the
`roles` source and maps the role onto its own name (SSO-3945, oauthy SSO-3943):

```yaml
  - kind: application
    name: forge
    environment: staging
    spec:
      clientId: forge
      displayName: "Forge"
      redirectUris: ["https://forge.acme.example/oauth2/callback"]
      tokenClaims:
        sources: [roles]                     # the user's role names → ID-token claim `roles`
        roleMapping:
          forge-maintainer: Maintainers      # Thoryn role → the value the forge receives
```

**`kind: role`.** Converged by `name` within its environment. `plan` reads the role and its permissions; the
permission set is compared as a **set** (order is not drift) and an `update` replaces it with exactly the declared list
(`PUT /api/v1/roles/{id}/permissions`). A permission the workspace does not have yet is **created** — permissions are
workspace-wide, so it then exists in every environment, and a removed role never deletes one. A permission is any
non-empty string except a reserved platform-scope namespace: a name whose first `:`-segment is `tenant`, `admin` or
`holder` (any case) is refused `permission_name_reserved`, by the file before any call and by product-api. So
`forge:maintain` and `invoices:read` are valid; `tenant:roles.write` is not.

A role is **not a platform access object** — product-api gates it on the token's `tenant:roles.read` / `.write` alone —
so the plan asks no ownership check for it, it cannot carry `grants:`, and `--prune` never finds one to remove. Like a
`user`, it goes **with its sandbox** (the environment hard-delete cascades) and `destroy` never removes one on the
production plane: the row names the call a person makes. `readOnly: true` works as for any kind: the role must exist and
match.

**`tokenClaims` on an application.** `sources` is the FULL set of claim sources, compared as a set; omitted ⇒
`[permissions]` (the server's default). `{ enabled: false }` switches claims in the token off. **An omitted `tokenClaims`
leaves whatever the platform holds** — like the other application settings, the file only changes what it declares.
On create it is switched on once the client exists (and its one-time secret has been delivered); on update only the
toggle is written, never the application. The source **names are passed through**: product-api decides which exist
(today `permissions`, `org`, `org_roles`, `pim`, `entitlements`, `guest`, `metadata:<key>`), so a source the platform
gains is declarable without a new CLI. A name it refuses fails the apply with its code, naming the field:

```text
Error: application/forge: spec.tokenClaims refused by the platform — unsupported_claim_source: Unsupported claim sources: … (the application itself is converged)
```

**`roleMapping` (SSO-3945).** Maps a Thoryn role name to the value the application receives in its `roles` claim. Without
a mapping every role name the user holds is emitted as-is; **with** one it is an **allowlist** — only mapped roles are
emitted, under their mapped values (`{}` lets none through), so an application never learns a role not meant for it. It
needs the `roles` source in `sources` (the default `[permissions]` does not have it).

**The platform's `PUT` replaces the whole configuration**, so the CLI sends `sources` AND `roleMapping` together on every
write — `"roleMapping": null` when the file declares none. **Omitting `roleMapping` therefore means "no mapping"**: a live
mapping the file does not declare is removed, and the plan says so before you apply:

```text
      application forge: tokenClaims: roleMapping removed — the file declares none and the PUT replaces the whole configuration: - forge-maintainer: Maintainers
```

The plan diffs `sources` (as a set) and `roleMapping` (as a map — key order is not drift) together and is a no-op only when
both match. A changed mapping is shown entry by entry — `+ role: value` added, `- role: value` removed,
`~ role: old → new` changed:

```text
      application forge: tokenClaims: sources [roles] → sources [roles,permissions]; roleMapping ~ forge-admin: admins → Admins, + forge-maintainer: Maintainers
```

The file refuses, before any call, exactly what product-api refuses (`400 invalid_role_mapping`), naming
`spec.tokenClaims.roleMapping`: more than 100 entries; a key (a role name) that is blank, longer than 200 characters, or holds
a control character; a value that does not match `^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$` or starts with `tenant:`,
`admin:` or `holder:` (any case); a mapping without the `roles` source; a mapping with `enabled: false`. A value must be a
YAML **string**: quote anything YAML would read as a number or boolean (`"1.10"`, `"0123"`, `"true"`), because the CLI
does not guess what you meant.

| Declares | to plan | to apply |
|---|---|---|
| `kind: role` | `tenant:roles.read` (no `tenant:access.read` — there is no ownership check) | `tenant:roles.write` (create, description, permission set, a missing permission) |
| `tokenClaims` | `tenant:applications.read` | `tenant:applications.write` |

### Declaring a workload-identity trust — `kind: workloadIdentityTrust` (SSO-3689)

The imperative twin is `thoryn workload-identity trusts create` (above). Declared, a trust is a resource
of its **environment** (no `environment:` ⇒ the production plane) with the provider's **pins**:

```yaml
resources:
  - kind: workloadIdentityTrust
    name: billing-ci                    # the trust's name on the API — the converge key, unique per environment
    environment: staging
    spec:
      provider: github_actions
      github:
        repository: acme/billing        # owner/name
        ownerId: 1234567                # GitHub's immutable ids — both or neither (looked up once for a public repository)
        repositoryId: 7654321
        environment: staging            # the GitHub environment the job must run in — REQUIRED for a production trust
        ref: refs/heads/main            # exact
        githubHostedRunnersOnly: true
      scopes: [tenant:applications.read, tenant:applications.write]
      plan:                             # SSO-3702 — the PLAN profile (github_actions only): a second GitHub environment whose
        environment: staging-plan       # jobs are minted read-only scopes only; must differ from github.environment
        # scopes: [tenant:applications.read]   # optional explicit .read subset of `scopes`; omitted ⇒ derived by the hub
  - kind: workloadIdentityTrust
    name: forge-main
    spec:
      provider: forgejo
      forgejo: { instanceUrl: "https://forge.example.org", owner: thoryn, ownerId: 7, repository: infra, repositoryId: 42, ref: refs/heads/main }
      scopes: [tenant:applications.write]
      confirmProduction: true           # production plane: its jobs act on production (production_confirmation_required otherwise)
  - kind: workloadIdentityTrust
    name: billing-pods
    spec:
      provider: kubernetes
      kubernetes:
        issuer: "https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE"
        namespace: billing              # namespace + serviceAccount: REQUIRED for a production trust
        serviceAccount: billing-web
        jwks: { keys: [ { kty: RSA, kid: t10j6Z4K, use: sig, alg: RS256, n: "…", e: AQAB } ] }   # PUBLIC keys only, for a cluster Thoryn cannot reach
      scopes: [tenant:applications.read]
      confirmProduction: true
```

What `thoryn provision` does with it:

- **Converge by name.** A trust of that name in the plane is a **no-op** (every DECLARED field must
  match: `provider`, `scopes` as a set, the pins; a field the file leaves out is not compared); absent, it
  is **created** (`POST /api/v1/workload-identity/trusts`, with the file's `repository: owner/name` as the
  API's `owner` + `repository`); a `409 workload_identity_trust_name_taken` between the lookup and the
  create converges onto the matching trust, as `project init` does. **A trust's pins never change:** a
  declared pin that differs from the live trust is the plan error
  **`workload_identity_trust_immutable`**, naming the fix — declare what is live, or
  `thoryn workload-identity trusts delete <id>` and re-apply to re-create it. **Its scopes change in place
  (SSO-3925):** when only `scopes` (and/or a live profile's `plan.scopes`) differ, the plan is an `update`
  that calls `PUT …/{id}/scopes` (`~ workloadIdentityTrust …: scopes changed in place`) — the id, the `wi_`
  client, its `owner` and every `connection.json` stay. A **narrowing** converges from CI. A **widening** is a
  person's act: from a `client:` identity the plan is red **`elevated_action_requires_person`** naming the
  `thoryn workload-identity trusts set-scopes <id> --scope …` line a workspace member runs (signed in with a
  passkey); for a person it is planned with the passkey note, and a sign-in that is not a fresh passkey one is
  refused at apply with the `thoryn login --acr-values … --max-age …` line. A derived plan profile (no
  `plan.scopes` declared) keeps the live scopes still inside the new `scopes`; with none left, name
  `plan.scopes`. A scope change together with a pin change is still `workload_identity_trust_immutable`. **On the production plane a
  changed pin set is a NEW trust, which a person creates** (SSO-3774; below): the engine never mutates a pin,
  and the plan says so. **Removal (SSO-3774):** the `client:` identity that **owns** a trust (`trust:<id>`)
  removes it with `destroy`, and `--prune` removes the owned trusts the file no longer declares — on the
  production plane behind `--confirm`, exactly like an owned application. Otherwise `destroy` removes a trust
  only **with its sandbox** (when the identity may remove the declared parent environment — the hard-delete
  cascades); a production trust it does not own (and any production trust, for a person) is never removed
  by `destroy` / `--prune` and the plan names `thoryn workload-identity trusts delete <id> --yes --confirm …`.
- **The one additive exception — `plan:` (SSO-3702).** A `github_actions` trust's plan profile is compared
  like a pin (`plan.environment`; `plan.scopes` only when the file lists them — a derived declaration
  matches whatever the hub derived), with one exception: a **declared profile on a live trust that has
  none** is a plain `update` that calls the additive `POST …/{id}/plan-profile` (`~ workloadIdentityTrust
  …: plan profile added`) — the `wi_` client, its `owner` relation and the consumer's `connection.json` stay. A live profile whose
  **environment** differs from the declared one is the red plan `workload_identity_trust_immutable` ("re-create the trust");
  differing `plan.scopes` change in place (above). The file refuses what the API refuses, with
  its codes: `plan_profile_unsupported` (not `github_actions`), `plan_profile_requires_environment`,
  `plan_environment_equals_apply`, `plan_scope_not_read_only`, `plan_scope_not_subset`, `plan_scopes_empty`.
  The printed `connection.json` is unchanged — one file serves both profiles (the hub decides by the job's
  `environment` claim); `plan` shows `plan-profile <env> [<scopes>]` on the trust's row and `import`
  renders a live profile with its scopes made explicit.
- **The plan row and `apply --output json`** carry the trust id, its **`wi_…` workload client**
  (`attributes.clientId`), its `audience` and `provider` — nothing secret exists on a trust.
- **The scope ceiling.** A trust may carry only `tenant:` scopes the **applying identity itself holds**
  (the hub's `403 scope_not_grantable`): a trust can never widen the reach of the repository that declares
  it. `plan` states the ceiling on every create; when the session's scopes are known (the token's `scope`
  claim — the CLI passes them) a trust that overreaches is a red plan with the hub's own code before any
  write; otherwise the hub refuses at apply and the error names the fix.
- **`apply` prints the consumer's `connection.json` — and never writes it.** The file belongs to the
  repository (or the workload) that signs in with the trust, not to the one that declares it:

  ```text
  + workloadIdentityTrust billing-ci: id=7f1c… clientId=wi_3f0c9a1b2d4e5f6a7b8c9d0e audience=https://acme.auth.thoryn.io/staging env=staging
      connection.json for the workload that signs in with this trust — not written by apply (it belongs to the consumer repository):
        { "apiVersion" : "thoryn.io/connection/v1", "workspace" : { "slug" : "acme" }, "auth" : { "method" : "workload_identity", "provider" : "github_actions", "clientId" : "wi_3f0c…", "audience" : "https://acme.auth.thoryn.io/staging", "scopes" : [ … ], "github" : { "owner" : "acme", "repository" : "billing", … } } }
  ```

  `plan` shows an existing trust's `clientId` and `audience` on its row. A `kubernetes` trust's document is
  the one `trusts create --provider kubernetes` prints (SSO-3684): `provider: kubernetes`, the file token
  source (`/var/run/secrets/tokens/thoryn/token`, the projected ServiceAccount token) and the cluster pins.
  For a `forgejo` trust `provider` is left out (the contract validates `github_actions` and `kubernetes`
  today; a Forgejo job presents its own Actions token as the `client_assertion`).
- **Ownership is asked per trust (SSO-3774; oauthy ADR `2026-10-16-repository-owned-workload-identity-trusts`).**
  A trust is a platform object of its own, **`trust:<id>`** (the hub's trust UUID): ownable (one `owner`, a
  `client:`, set by a workspace admin — `thoryn access grant client:<wi_…> owner trust:<id>` — or by
  creator-becomes-owner when CI creates it in a sandbox), contained in its environment. The gate asks the
  relation on `trust:<id>` **unioned with** the relation on its plane (`environment:<id>`, the workspace for the
  production plane — so every environment manager and workspace admin keeps managing every trust of the plane,
  and an existing trust whose parent edge is not stored yet stays reachable): `manager` ⇒ converge, unless the
  response's `owner` names another repository (`access_owned_elsewhere`, naming no subject); `viewer` ⇒ only a
  matching `readOnly: true` reference (`access_read_only` otherwise, fix `owner trust:<id>`); none ⇒
  `access_not_owned`. A repository confined below the workspace therefore converges exactly the trusts it owns.
  A trust the identity cannot see — the platform lists only what it reaches — plans as a create; if the file
  declares it on a plane this identity cannot fully read it is **`access_not_reachable`** with `owner` (or
  `viewer` for a `readOnly` reference) on the trust **by name** — `trust:<name>` in the fix request, `trust:<trust-id>`
  in the command (`thoryn workload-identity trusts list` shows the id; the consent page resolves the name as
  the admin). A trust cannot carry `grants:`, `publishTo:` or `secretSink:`.
- **A production trust is created by a person, once (SSO-3774, ADR Q2).** A `client:` identity (CI) never
  creates a trust on the production plane — even one that could: the plan row is
  **`workload_identity_trust_production_needs_person`**, a note (never a grantable right: "no trust creation" is
  outside the consentable set) carrying the founder's command — apply this file signed in as yourself, then
  `thoryn access grant <subject> owner trust:<trust-id>`. From then on CI converges it. Sandbox trusts are the
  repository's to create where it manages the environment.
- **A platform without trust objects** (product-api before oauthy S1) answers `400 invalid_type` for `trust:` on
  `/access/check` and `/access/mine` (that is what the engine detects, once), an opaque `404 not_found` for a grant
  naming `trust:`, and renders no `owner` field on a trust (absent, read as no owner): the engine falls back to the
  plane alone — the gate, `import` and the fixes of before (`manager` on the environment) — and prunes no trust.
- **`thoryn access grant … trust:<id>`** explains its two refusals on stderr: `400 trust_self_management` (oauthy
  I6 — the subject is that trust's OWN `wi_` client; no identity owns or manages the trust it signs in with: grant the
  repository identity that converges it), and a `404` (not a trust of this workspace — or a platform before trust
  objects, where a trust is reached through `manager environment:<id>`).
- **`import`** renders every trust it can see (`github` / `forgejo` / `kubernetes` pins, `scopes`,
  `confirmProduction` on the production plane) — as an entry the file converges when it manages it, `readOnly:
  true` for a viewer or a trust another repository owns. Inline Kubernetes keys are not rendered by the API: the entry carries a
  note to add `spec.kubernetes.jwks` by hand (`kubectl get --raw /openid/v1/jwks`).

**The structural limit — a file cannot declare its OWN bootstrap trust.** The identity that applies a
provisioning file is, in CI, a trust's `wi_…` client. That trust must exist before the first `apply`
can sign in (chicken-and-egg), so it is **created once by a person** (`thoryn workload-identity trusts
create`, or `thoryn project init`) and is never declared by the file it signs in: the engine refuses a
declared trust whose workload client is the applying identity (`workload_identity_trust_is_self` — a
file that owned it could `--prune` the identity it runs as), and `import` skips it with a note.
Everything else — the trusts of the applications, of other repositories, of the pods — is declared.

### Ownership is decided by your identity's reach (SSO-3659 / SSO-3673, epic SSO-3087)

Per oauthy ADR `2026-10-13-provisioning-as-code-converge-github-app-and-fga-ownership.md` §1/§2 (its
Amendment 4) and ADR `2026-10-13-platform-owner-relation-and-forward-check.md`, a repository converges
**only what it owns**, and "owns" is a relation in the platform authorization graph — never a naming
prefix, never something the file can claim by being written. The subject is the signed-in identity
itself (`client:<clientId>` for a workload-identity / client-credentials session, `member:<sub>` for a
person), derived from the token exactly as product-api derives it.

Before any write, `plan` and `apply` ask the platform **per object** — `POST /api/v1/access/check
{object, relation}` for the caller's own subject (scope `tenant:access.read`; a session without it
fails closed with the scope named): `manager` for a resource the file would change, `viewer` for a
`readOnly: true` reference, `manager` on the **parent** for a create — and gate every declared resource:

| what the platform answers for the live object | `plan` / `apply` |
|---|---|
| `manager` (direct, through the `owner` relation, or inherited through `parent` from its environment / workspace) | the normal converge (create / update / no-op) |
| `viewer` only | allowed only as `readOnly: true`; **any field diff** is `access_read_only`; declared without `readOnly` is `access_read_only` naming the fix |
| none | `access_not_owned` — not visible to this identity; cannot be imported or converged |
| does not exist yet | a create needs `manager` on the **parent** (`environment:<id>`, or the workspace for the production plane / an environment / the custom domain), checked on that parent object; creator-becomes-manager (and, for a `client:` creator, creator-becomes-**owner**) on the platform then makes the identity its manager — no grant step |
| the resource's `owner` is another identity | `access_owned_elsewhere` unless declared `readOnly: true` — the plan says "another repository", never who |

A failed gate is an `error` row in the plan (`--output json` → `changes[].error`, `changes[].access`,
`changes[].owner`), the plan exits **1** (a red check on a pull request), and `apply` refuses the
**whole** plan before writing anything — never a partial apply that owns the half it may touch.

**`readOnly: true`** on any kind means *"this repository depends on it and does not own it"*: the
resource is looked up live and must match the declared spec; it is never created, removed, or granted
on (`grants:`, `publishTo:`, `secretSink:` and `retain:` are refused on a reference).

**The platform is the ledger — what `destroy` and `--prune` may remove (SSO-3715, ADR
`2026-10-15-platform-is-the-ledger-no-committed-provisioning-receipt`).** There is **no receipt**:
nothing is written beside the file, committed or cached, so the plan a reviewer reads and the state
the platform enforces cannot diverge. The receipt-era "adopted, so never deleted" rail is retired with
it; the deletion authority is the platform's `owner` relation, evaluated by the engine before every
removal and re-checked by product-api on the `DELETE` (404, never widened):

| the signed-in identity | `destroy` / `--prune` removes a declared resource when |
|---|---|
| a **`client:`** (a repository's `wi_`) | `/access/check owner` is **true** for an `application` / `environment` — `manager` alone (inherited through a sandbox a founder created, or granted) never lets automation delete; thoryn-cli's own `environment/ci` (`owner: null`, CI is `manager` by grant) would stay on that ground alone — and is `retain: true` besides (SSO-3717) |
| a **`member:`** (a person) | they **manage** it and **nobody owns** it — people cannot own, and an owned resource belongs to its repository (`owned by a repository — change its file`) |
| any | a **non-ownable kind** (`user`, `federationMember`, the singletons, a `workloadIdentityTrust`) goes **with its sandbox** when the identity may remove the declared parent environment (the hard-delete cascades; no call of its own) — and is **never removed on the production plane** (left in place, reported with the explicit command) |
| any | an **environment** goes only when owned, after its children |
| any | **`retain: true`** on the resource: never — the destroy plan shows it as `retained by the file` (Terraform's `prevent_destroy`; the declared replacement for the adopted bit — intent in the reviewed file instead of history in a ledger). thoryn-cli's own `application/cli` and `environment/ci` declare it (SSO-3717), so its `provision-e2e` destroy removes exactly the per-run loopback client and asserts so from `destroy --output json` |

Every refusal is a `skip` row with the reason and the command a person would run (`thoryn clients delete
…`, `thoryn env delete <id> --confirm <slug>`, `thoryn domain remove --yes`, …; `--output json` →
`changes[].byHand`). `destroy` prints that plan first, then removes the `remove` rows child-first;
`--confirm <workspace-slug>` is still required for any production-plane removal, and automation never
runs `destroy` or `--prune`. **`--prune`** additionally removes the `application` / `environment` the
platform lists this `client:` identity as **owner** of (`GET /api/v1/access/mine?relation=owner`) and the
file no longer declares — the platform is the ledger of what a repository owns, so "owned but no longer
declared" needs no receipt; a person owns nothing, so their `--prune` prunes grants only (one note row
says so). **Converge keys are the identity of a resource:** declare `clientId` on an application (the
starters render `<repo>-<name>`) — two live matches of a display name are the red row
`converge_key_ambiguous` ("declare `clientId`"), never a create of a third.

**One owning repository per resource — a platform fact.** The platform model has an `owner` relation
on `application` and `environment`: at most **one** subject per object (a database invariant on the
platform; a second owner is `409 owner_already_set`, never a silent replace), implied into `manager`,
set at create time when the creator is a `client:` subject (the repository that provisions a resource
owns it — a person's create has no owner) or by a workspace admin with
`thoryn access grant <subject> owner <object>`. The product owner decided (2026-10-13) that an owner is
a **workload identity only** — people are managers and admins, never owners. The owner is rendered on
the application (`owner: { subject }`); when it is set and `/access/check` says this identity is not
it, the resource is `access_owned_elsewhere`. The plan row and `apply --output json` carry the owner the
platform reported (`owner`) — informational; the gate always asks the platform. A
`grants:` entry **cannot** carry `relation: owner`: the loader refuses it, naming the admin's fix — a
repository cannot claim ownership by writing YAML. Moving ownership is a workspace admin's
`thoryn access revoke <current> owner <object>`, then `thoryn access grant <new> owner <object>`.

The former `--peer-receipt` flag (other repositories' committed receipts as the ownership marker) was
removed with SSO-3673, and the receipt itself with SSO-3715: the platform's `owner` relation is the one
marker, and the platform's audit log the record of who applied.

**`thoryn provision import [--write]`** is the inverse of `plan`, bounded by the same relations: it
lists what the identity may reach (`GET /api/v1/access/mine` for `manager`, then `viewer` — the one
place the per-type listing is still used) and renders each live resource the file does not yet
declare as an entry — `manager` objects as entries the file converges (and, by the owner rule above, may
remove), `viewer` objects and objects the platform says another repository owns as `readOnly: true`.
Nothing the identity has no relation to is listed, so nothing it has no relation to can be imported;
the hub's rows stay the authority. Without `--write` it prints the YAML it would add (notes and
unrenderable objects on stderr); `--write` appends under the file's `resources:` list (the file is
created when absent) and re-validates it — the file is the only thing written. A `loginFlow` cannot be
rendered (its `templateId` is not recoverable from the active flow); write-only secrets
(`smtpPasswordEnv`, `clientSecretEnv`) must be added by hand before an update is converged.

Two facts worth knowing when reading the ADRs against the code: the public `POST /api/v1/fga/check` /
`list-objects` evaluate the **tenant's own** authorization model over the environment-partitioned
tenant tuple store, not the platform resource graph — `/api/v1/access/check` and `/api/v1/access/mine`
are that graph's check and list-objects, so the gate uses them (and `tenant:access.read`, not
`tenant:fga.*`). And an object the graph does not know yet (a singleton reset out of band, so without
its `parent` edge) is still gated by containment — `manager` on the parent — because the platform
re-checks every write server-side, so the engine can never admit a write the platform refuses.

### A red check names its fix — `--fix-request` (SSO-3710, SSO-3722, SSO-3723; epic SSO-3304)

A repository bound to Thoryn needs one-time rights before its App-dispatched plan can run: the **plan
profile** on its trust (SSO-3700), the **`owner`** relation on a resource it declares (SSO-3697),
`manager` on the parent environment of something it creates, or (SSO-3792) a **creation slot** for a
production application it declares and that does not exist yet. When one is missing the check run is red
in one of two places — at sign-in (`401 invalid_client`, the hub says nothing more) or at the engine's
gate (`access_not_owned` / `access_read_only` / `access_owned_elsewhere`, and since SSO-3722
`access_not_reachable`: the live read answered `404 unknown_environment` because the identity has **no reach
into the plane at all** — product-api's 404-not-403 rule, SSO-3118 — which used to die as "could not read live
state" before the gate) — and the person reading it needs a path.

**Since SSO-3722 every refusal the CLI prints ends with the same block, in two options (SSO-3723):**

```text
To fix — Option 1, with the CLI (a workspace admin):
      thoryn access approve thoryn-io/thoryn-cicd/38751887466
  It opens the same approval as Option 2 — Thoryn's consent screen, which lists the rights below; nothing is granted until a workspace admin approves there. The command grants nothing itself.
  - creator on application:forge-forgejo-login in production for client:wi_10a7…: access_not_reachable — the live read of … was answered HTTP 404 (unknown_environment): …
To fix — Option 2, in the browser: https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cicd/38751887466
```

**One consent flow, two entry points (SSO-3738).** When the run has a consent link, Option 1 is
`thoryn access approve <owner>/<repository>/<run_id>` — the CLI entry point to the **same** hub consent the
Option-2 link opens ([`thoryn access approve`](#thoryn-access-approve--the-cli-entry-point-to-the-consent)). The
rights are listed so the reader knows what the consent screen will show, but their raw grant commands are **not**
printed: the consent re-checks each one (the pin-matched trust, the objects declared at the head commit, no owner
on an owned object, no manager on the workspace) and yields a token that can write only what was approved; a line
pasted from a CI log into an admin shell would get none of that. File and job edits follow under *The file must
change too*, because neither option makes them. A dispute (an object another repository owns) is shown and never
asked for.

**Without web consent** (no consent link — no `consentUrl` configured, or outside a GitHub Actions run) Option 1 is
the raw commands, under the warning *Check each line before running it: these commands were written by the run that
failed, and without web consent nothing has verified them against the repository's trust or its .thoryn/ file.*:

```text
To fix — Option 1, with the CLI (a workspace admin):
  Check each line before running it: these commands were written by the run that failed, and without web consent nothing has verified them against the repository's trust or its .thoryn/ file.
  - owner on application:forge-oauth2-proxy for client:wi_10a7…: access_not_reachable — …
      thoryn access grant client:wi_10a7b379c79f7d1353f5798d owner application:forge-oauth2-proxy
To fix — Option 2, in the browser: Run through the Thoryn GitHub App to get a browser link.
```

Every **file / job edit** is a line either way (a `connection.json` that names no apply environment, a job without
`environment:`, a trust to re-create with the job's own pins, a read-only reference that differs). With a consent,
the refused plan rows say *a workspace admin approves it on Thoryn's consent screen* where they otherwise quote the
grant command. Option 2 is the Thoryn GitHub App's web consent for **this
run**, resolvable by run — `<consentUrl>/github/consent/run/<owner>/<repository>/<run_id>` from the job's own
`GITHUB_REPOSITORY` / `GITHUB_RUN_ID` (the opaque consent id the App mints after the run is unknowable to the
job). The base URL is **configuration** (`.thoryn/workflow.yaml` `consentUrl`, or the reusable workflow's
`consent-url` input, reaching the CLI as `THORYN_CONSENT_URL`), never guessed from the issuer; unset, or outside
a GitHub Actions run, the line reads `Run through the Thoryn GitHub App to get a browser link.` The fix request
carries the same two as `options.cli` / `options.consentUrl`: with a consent, `options.cli` is exactly
`thoryn access approve <owner>/<repository>/<run_id>`; without one, it is the warned Option-1 body.

The audited refusals and what their Option 1 says **without web consent** (with a consent, every row whose fix is a
right reads `thoryn access approve <owner>/<repository>/<run_id>` instead; file edits are unchanged):

| Refusal | Option 1 |
|---|---|
| no `ACTIONS_ID_TOKEN_REQUEST_*` / GitHub refused the job token | `job: add permissions: id-token: write …`; outside GitHub: `thoryn login` / `--client-credentials` |
| the token file is missing (a pod) | mount the projected token where `auth.tokenSource.path` says, or point the path at it |
| `invalid_client`, only the environment differs | the **plan_profile** item: `thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment <job env>` |
| `invalid_client`, the job declares no environment | `job: add environment: <the trust's> to the job` |
| `invalid_client`, a pin differs (repository, ids, ref, runner, namespace, service account) | the one `thoryn workload-identity trusts create --name <name> … --repository <job's> --owner-id … --repository-id … --github-environment <job's> --scope "…"` built from the job's own claims, then `trusts get <id> --connection` over `connection.json`; or align the job |
| `invalid_client`, no local difference | `thoryn audit query --event-type workload_identity.exchange_failed`, then the same re-create or alignment |
| `invalid_scope` / `scope_outside_plan_profile` | `connection.json: names no apply environment — add auth.github.environment: <apply env> (paste the github block from trusts get <id> --connection), or drop auth.scopes`; names the wrong one — set it to the trust's apply environment; flag form — drop `--scope` |
| `invalid_scope` / `scope_outside_apply_profile`, other `invalid_scope` | `auth.scopes` (or `--scope`) must be a subset of the trust's (`trusts get <id>` lists them) |
| token endpoint unreachable, unknown error | make the endpoint reachable from the runner / re-run, then the audit log |
| `access_not_owned`, `access_read_only` (a resource to own) | `thoryn access grant client:<wi_> owner <object>` |
| `access_not_owned` on a create | `thoryn access grant client:<wi_> manager environment:<id>` on a sandbox; on the production plane (SSO-3792) an application with a fixed `clientId` is the **creator** item `thoryn access reserve client:<wi_> application:<clientId> --environment production`; any other workspace parent is a note (never granted to a repository identity) — an application without a fixed id says to declare `spec.clientId` |
| `access_not_reachable` (404 on the live read) | SSO-3792: the **creator** item for a production application with a fixed `clientId` (never `owner` on something that may not exist — SSO-3787); `manager environment:<slug>` for a declared sandbox (with or without a fixed id); a workspace note on the production plane without a fixed id |
| `access_not_reachable` (a declared trust the identity cannot see — SSO-3774) | `thoryn access grant client:<wi_> owner trust:<trust-id>` (item object `trust:<name>`; `viewer` for a `readOnly` reference); asked ONCE even when the trust's row and the application naming it both need it |
| `workload_identity_trust_production_needs_person` | a note: a workspace admin applies the file as themselves, then `thoryn access grant client:<wi_> owner trust:<trust-id>` |
| `access_owned_elsewhere` | no command runs for you: declare it `readOnly: true`, or an admin moves the ownership (the reason carries revoke-then-grant) |
| `access_read_only` (a differing reference), `converge_key_ambiguous`, `workload_identity_trust_immutable` / `_is_self`, `scope_not_grantable`, `federated_trust_not_found` | a line naming the file edit (align the reference, declare `clientId`, declare what is live or delete the trust, drop the scope / the resource) |
| a refused or deferred removal (destroy / `--prune`) | the `by hand:` command on the plan row | Per oauthy ADR `2026-10-15-missing-rights-fix-path-cli-and-web-consent.md` §1 the job
writes **one file**, `thoryn-provision-request.json` (schema
`engine/src/main/resources/provision/fix-request.schema.json`), and the workflow uploads it as the run
artifact **`thoryn-provision-request`**. The Thoryn GitHub App reads that artifact and puts two options on
the failed check run, both leading to the hub's own consent screen (oauthy SSO-3737 / SSO-3755): `thoryn access
approve <owner>/<repository>/<run_id>` and the by-run consent link. Only where web consent is disabled does it relay
the request's raw commands, under *Check each line before running it*.

Both producers take the same opt-in `--fix-request <path>` (or the env var `THORYN_FIX_REQUEST` — the
spelling a workflow uses, because a release that predates the flag ignores a variable and refuses a flag);
exit codes are unchanged, and the request is never a credential — ids, names, commands:

- **`thoryn login --connection --fix-request`** — on **every** refusal that had a job token (SSO-3722). An
  `invalid_client` whose **only** local mismatch is the job's GitHub environment (the job runs in `<env>-plan`,
  the trust pins the apply environment and has no plan profile for the job's) is one `plan_profile` item with
  `thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment <job env>` (`<trust-id>`,
  because a refused sign-in holds no token; `thoryn workload-identity trusts list` resolves it). Any other
  shape — a repository id, a ref, a runner, no environment at all, a scope outside the profile — is a wrong pin
  or a file edit, not a missing right: `missing` stays empty and the edit is a `notes` line (the same line the
  log prints), so the App can still show it.
- **`thoryn provision plan|apply --fix-request`** — on a red plan, one item per `access_*` row that is a
  right: **`owner`** on an existing object this file is to own (`access_not_owned` on a live id, or
  `access_read_only` when the identity may only view it), **`manager`** on the parent `environment:<id>`
  of a refused create, **`viewer`** for a `readOnly: true` reference the identity cannot see; each with
  `thoryn access grant client:<wi_…> <relation> <object>`, the subject being the session's own. SSO-3792:
  **`creator`** — a creation slot — for a production application the file declares with a fixed `clientId`
  that the identity cannot see and may not create, with `thoryn access reserve client:<wi_…>
  application:<clientId> --environment production` (the item's `environment` is the plane). An object
  **another repository owns** (`access_owned_elsewhere`) is an `owner` item with **no command** — a dispute
  an admin decides (the reason carries the Owner ADR's revoke-then-grant). Rows that are **file** fixes — a
  read-only reference that differs from what is live, a trust the file cannot declare, a scope the
  identity does not hold, a create whose parent is the **workspace** (`manager` on the workspace is never
  granted to a repository identity) — are listed under `notes`, so the request says so. The trust's name
  and id are resolved only when the session may list trusts (`tenant:workload-identity.read`); a plan-profile
  session names its `wi_` client only.

#### Creation slots — a declared production application that does not exist yet (SSO-3792; absorbs SSO-3787)

Creating a production-plane application needs `manager` on the **workspace**, which a repository identity is
never granted (epic SSO-3108). Before SSO-3792 the plan of a file declaring a new production application asked
for `owner` on it — a right on nothing: the admin approved it on the consent screen and product-api answered
`not_found` (thoryn-cicd PR 34). A confined identity cannot tell **absent** from **invisible**, so the engine now
asks for the one thing that is grantable — a **creation slot** (oauthy ADR
`2026-10-17-consent-approved-application-creation-slots.md`):

1. **Red.** The plan row (`access_not_reachable`, or `access_not_owned` when the plane is visible) carries the
   `creator` item `thoryn access reserve client:<wi_…> application:<clientId> --environment production`. The
   Thoryn GitHub App relays it onto the check run and lists it on the run's consent screen ("Let
   *owner/repository* create the application *clientId* in *production*, and own it"); with a consent link the
   log's Option 1 is `thoryn access approve <owner>/<repo>/<run_id>` (SSO-3738), which opens that same screen, and
   without one it is the `reserve` command itself.
2. **Approve.** A workspace admin runs the command, or approves it on the hub's consent screen. The slot binds the
   **name**, the **plane** and the **holder** — not the spec; it lasts **30 days** and only the holder may use it.
3. **Green.** The next plan reads the slots once (`GET /api/v1/access/application-slots`, `tenant:access.read`,
   which the plan profile holds) and, for an unexpired slot this identity holds on that client id **and** plane,
   plans the row as `create — will create (reserved by a workspace admin; expires <date>)`. A slot on another
   plane, for another name, held by someone else, or expired leaves the row red with the same item (an expired
   slot's reason says so). A platform without slots answers `404`, read as "no slots".
4. **Apply.** The ordinary `POST /api/v1/applications` with the explicit `clientId`: product-api consumes the slot
   and the repository becomes the application's `owner`. A refusal is spelled out: `404` — the slot no longer
   admits the create (used, released, revoked, expired, or for another plane; re-plan, an admin reserves again);
   `409 client_id_taken` — someone created the name meanwhile, the slot is used up and never adopts it (grant
   `owner` instead).

What a slot does **not** lift: turning `allowTokenExchange` or `allowTokenIntrospection` on at create still needs
`manager` on the plane, so the plan refuses either under a slot (`token_exchange_not_grantable` /
`token_introspection_not_grantable`, a note) before any write; a `federatedTrust`
binding still needs `manager` on the trust; the new client's scopes are still capped at the identity's own.
Sandboxes keep `manager` on their environment (decision D3), an application without a fixed `clientId` keeps
the workspace note (now: "declare `spec.clientId` to make its creation approvable"), and production **trusts**
stay a person's act (`workload_identity_trust_production_needs_person`). If the name turns out to exist when the
admin approves, the App's callback answers `application_exists` and offers a follow-up consent for `owner` on
it (decision D1). An admin lists and revokes slots with `thoryn access reservations` / `thoryn access release
application:<clientId>`.

A `creator` item is a kind a consumer must know: the Thoryn GitHub App accepts it since oauthy SSO-3791, and
since then an unknown kind drops that ONE item rather than the whole request. The document's `version` stays
`1` — the change is additive (a new enum value) and no consumer dispatches on the version.

**One rendering.** The `cli` string of every item is the same text the CLI prints on stderr when there is no web
consent (the row reasons quote it; the `To fix — Option 1, with the CLI (a workspace admin):` block lists it with the
notes, under the check-each-line warning), and `options.cli` is that block's body. With a consent link (SSO-3738)
`options.cli` is exactly `thoryn access approve <owner>/<repository>/<run_id>` and `options.consentUrl` the Option 2
link; each item keeps its own `cli` as data. The document's shape is unchanged — `version` stays `1`: only what
`options.cli` holds moved, and the App does not read it (it renders its own two options from the run). The binding fields the file carries — `repository`, `run` — are hints: a consumer
takes them from GitHub's own record of the run and discards the body's copy.

```json
{ "version": 1, "cliVersion": "0.35.0",
  "repository": { "owner": "thoryn-io", "ownerId": 229451779, "repository": "thoryn-cli", "repositoryId": 1361536515 },
  "run": { "id": 38547022158, "headSha": "…", "jobEnvironment": "thoryn-provision-e2e-plan" },
  "workspace": "thoryn", "file": { "path": ".thoryn/provision.yaml", "sha256": "sha256:…" },
  "trust": { "name": null, "plane": "production", "applyEnvironment": null, "id": null, "clientId": "wi_10a7b379c79f7d1353f5798d" },
  "missing": [ { "kind": "owner", "object": "application:cli", "subject": "client:wi_10a7b379c79f7d1353f5798d", "environment": null,
                 "reason": "access_not_owned — this identity holds no relation on application:cli — …",
                 "cli": "thoryn access grant client:wi_10a7b379c79f7d1353f5798d owner application:cli" } ],
  "notes": [],
  "options": { "cli": "thoryn access approve thoryn-io/thoryn-cli/38547022158",
               "consentUrl": "https://app.thoryn.io/github/consent/run/thoryn-io/thoryn-cli/38547022158" } }
```

In a workflow, set the variable on the step that signs in and plans, and upload the file on failure (the
reusable `provisioning.yml` (SSO-3719) and the composite Action's `fix-request` input / output are the examples):

```yaml
      - name: Plan
        env:
          THORYN_FIX_REQUEST: ${{ runner.temp }}/thoryn-provision-request.json
          THORYN_CONSENT_URL: https://app.thoryn.io     # SSO-3723 — the "Option 2, in the browser" link's base; configuration
        run: |
          thoryn login --connection .thoryn/connection.json
          thoryn provision plan --file .thoryn/provision.yaml
      - name: Upload the fix request
        if: failure()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: thoryn-provision-request
          path: ${{ runner.temp }}/thoryn-provision-request.json
          if-no-files-found: ignore
          retention-days: 7
```

### `thoryn access approve` — the CLI entry point to the consent

SSO-3738 (oauthy ADR `2026-10-15-missing-rights-fix-path-cli-and-web-consent.md`, amendment and As built SSO-3737 /
SSO-3755). A red provisioning check names its fix in two options that lead to **one** approval — the hub's own
consent screen. Option 1 is this command; Option 2 is the link. A workspace admin runs:

```bash
thoryn access approve thoryn-io/thoryn-cicd/38751887466
# or, the link from the check run or the job log:
thoryn access approve https://starters.stg.thoryn.org/github/consent/run/thoryn-io/thoryn-cicd/38751887466
```

**It grants nothing.** It builds the run's by-run consent address,
`<base>/github/consent/run/<owner>/<repository>/<run_id>`, and opens it in your browser; with no browser
(`--no-browser`, `THORYN_NO_BROWSER=1`, an SSH session) it prints the address to open on any device — the same
pattern as `thoryn login`. It makes no API call and follows no redirect itself: the browser goes to the Thoryn
GitHub App's starters service, which rebuilds the request from GitHub's own record of the run and redirects to the
hub, which signs you in and shows each right. Nothing is written until you approve there, and then only with a token
that carries exactly the approved items. Which workspace, which rights and whether you may grant them are decided
there, not by the CLI.

**How the consent base URL is resolved**, first match wins:

1. a **consent URL** passed as the argument — it names its own base;
2. **`--consent-url <base>`** (`https://starters.<your Thoryn domain>`);
3. the **`consentUrl` of `.thoryn/workflow.yaml`** — the nearest one from the working directory up to the
   repository root, so running it inside the repository uses the address the job's own log printed;
4. **derived from your signed-in platform**: `https://starters.<platform domain>`, where the platform domain is the
   session's base issuer without its host label (`https://auth.stg.thoryn.org` ⇒ `https://starters.stg.thoryn.org`).
   A local hub, an IP address or a custom domain names no platform domain, so nothing is derived.

With none of them the command stops and names the two ways to pass the address. The line `(consent address from …)`
under the address says which source was used.

**Strict input.** `<owner>/<repository>/<run_id>` follows GitHub's grammar: an account name of letters, digits and
`-` (not starting with `-`), a repository name of letters, digits, `.`, `_` and `-` (never `.` or `..`), and a
positive run id. A consent URL must be `https://`, a DNS host, an optional port, an optional plain path prefix, and
end in exactly `/github/consent/run/<owner>/<repository>/<run_id>` — no user-info, query, fragment, percent-encoding,
backslash, whitespace or dot segment. The address handed to the browser is rebuilt from the validated parts, never
the string as typed. Anything else exits `64` and opens nothing.

| Error | Cause | Fix |
|---|---|---|
| `… is not <owner>/<repository>/<run_id>` / `… is not a GitHub Actions run id` | The argument is not the run reference the check run prints. | Copy it from the check run, or pass the consent link. |
| `… is not an https:// consent URL` / `… is not a consent URL` | An `http://` link, or one with a query, fragment, user-info or extra path. | Pass the link exactly as the check run shows it. |
| `--consent-url … is a full consent link` | The whole link was passed as the base. | Pass it as the argument instead. |
| `no consent address for …` | No argument URL, no flag, no `consentUrl` in the repository, and the session names no platform domain (or you are not signed in). | Pass the link, or `--consent-url https://starters.<your Thoryn domain>`, or `thoryn login`. |

`thoryn access grant` stays as the expert command, unchanged; the raw grant lines it would take are printed in a job
log only when the deployment has no web consent, under *Check each line before running it*.

### Configure the provisioning workflow — the stub, its inputs, `.thoryn/workflow.yaml` (SSO-3719, epic SSO-3304)

The Thoryn GitHub App plans every pull request that touches `.thoryn/` and applies every push to the default branch
by dispatching **one workflow file in your repository**: `.github/workflows/thoryn-provisioning.yml`. Since SSO-3719
that file is a **stub** — it forwards the App's inputs to the reusable workflow
`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml`, which does everything else. **You configure the workflow;
you never write one.** Every variation a repository legitimately needs is either an **input** of the reusable workflow
(the stub's `with:` block — the job shape) or a key of the committed **`.thoryn/workflow.yaml`** (what the jobs do at
run time). Both are validated by one command, which also prints the configuration the jobs will run with:

```bash
thoryn provision workflow check            # the stub + .thoryn/workflow.yaml, every rule PASS/FAIL with its fix; exit 0 / 4
thoryn provision workflow check --output json   # what the reusable workflow itself reads: rules, effective inputs, `config`
```

**Why there is no script hook.** A workflow file stays in your repository for exactly two reasons the App cannot take
over: the job's own GitHub **OIDC token is your repository's identity** (Thoryn never holds a credential to your
workspace), and the job's GitHub **environment is the review gate** (a required reviewer approves the apply before any
write-capable token can be minted — enforced by GitHub and the hub, not by the App). Both must stay inside the reusable
workflow, where the contract can hold them: a hand-edited job could move the sign-in out of the reviewed environment, or
pass a secret, and nothing would notice. So the stub carries no steps, and `.thoryn/workflow.yaml` refuses any key it
does not know. **When configuration is not enough, that is a product gap — tell us, we add the knob for everyone**
(the way `runs-on`, `timeout-minutes` and `files` below exist), and nobody writes shell into a CI identity.

#### The stub

```yaml
# .github/workflows/thoryn-provisioning.yml — dispatched by the Thoryn GitHub App; lint: thoryn provision workflow check
name: Thoryn provisioning
run-name: "Thoryn provisioning ${{ inputs.mode }} ${{ inputs.head_sha }} check-run:${{ inputs.check_run_id }}"

on:
  workflow_dispatch:
    inputs:
      mode:         { description: "plan or apply", required: true, type: choice, options: [plan, apply] }
      head_sha:     { description: "The commit to plan or apply", required: true, type: string }
      check_run_id: { description: "The App's check run", required: true, type: string }
      pr_number:    { description: "The pull request (plan only)", required: false, type: string, default: "" }

concurrency:
  group: thoryn-provisioning-${{ inputs.mode }}
  cancel-in-progress: false

permissions: {}

jobs:
  # thoryn-provisioning: apply-job
  provisioning:
    uses: thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0
    permissions:
      id-token: write      # mints the identity (the job's own OIDC token)
      checks: write        # completes the App's check run
      contents: read       # reads the checkout — nothing is ever written back
    with:
      mode: ${{ inputs.mode }}
      head_sha: ${{ inputs.head_sha }}
      check_run_id: ${{ inputs.check_run_id }}
      pr_number: ${{ inputs.pr_number }}
      plan-environment: acme-production-plan     # UNPROTECTED — the trust's plan profile is keyed on it
      apply-environment: acme-production         # REVIEWED — required reviewers; the trust pins it
```

The two environments are **yours**: a called job's `environment:` resolves against the calling repository, so your
required reviewers hold the apply and your trust's plan profile makes the plan read-only (one `connection.json`, one
identity — the hub reads the job token's `environment` claim). The `# thoryn-provisioning: apply-job` line is how the App
knows the workflow applies; the `run-name` is how it finds the run. Pin `uses:` to a `cli-v*` release (≥ cli-v0.36.0):
the same pin selects the CLI the jobs run (`job.workflow_ref`), so there is no second version to keep in step.

#### Inputs — the stub's `with:` block

| Input | Default | What it does |
|---|---|---|
| `mode`, `head_sha`, `check_run_id`, `pr_number` | — | forwarded verbatim as `${{ inputs.<name> }}`; the App's dispatch inputs |
| `plan-environment` | required | the unprotected GitHub environment the plan job runs in |
| `apply-environment` | required | the reviewed GitHub environment the apply job runs in |
| `issuer` | `https://auth.thoryn.io` | the platform base issuer (`THORYN_ISSUER` / `THORYN_HUB`); `https://auth.stg.thoryn.org` on staging |
| `cli-version` | the release `uses:` is pinned to | a `cli-v*` tag to run instead (≥ cli-v0.36.0) |
| `runs-on` | `ubuntu-latest` | a runner label, or a JSON array of labels for a **self-hosted** pool: `'["self-hosted", "linux", "x64"]'` (the runner needs bash, gh, jq, curl; Java is set up). A trust pinned "GitHub-hosted runners only" refuses a self-hosted job's token — that pin is yours to change on the trust |
| `timeout-minutes` | `30` | each job's timeout |
| `config` | `.thoryn/workflow.yaml` | where the run-time configuration lives |
| `consent-url` | `""` | SSO-3723 — base URL of the Thoryn GitHub App's browser consent (`THORYN_CONSENT_URL`): a red job's `To fix — Option 2, in the browser:` becomes `<url>/github/consent/run/<owner>/<repo>/<run_id>` and Option 1 `thoryn access approve <owner>/<repo>/<run_id>` (SSO-3738). Empty ⇒ `.thoryn/workflow.yaml` `consentUrl`, else the raw commands alone, under *Check each line before running it* |

#### Run-time configuration — `.thoryn/workflow.yaml`

Committed beside your provisioning files; absent ⇒ the defaults below; schema
`cli/src/main/resources/examples/workflow.schema.json`. **Unknown keys are refused, by name.**

| Key | Default | What it does |
|---|---|---|
| `apiVersion` | required | `thoryn.io/workflow/v1` |
| `files[]` | `[{file: .thoryn/provision.yaml, connection: .thoryn/connection.json}]` | **one or many** provisioning files — each a tenant file (`thoryn.io/tenant/v1`) or an application file (`thoryn.io/application/v1`, SSO-3962; the mixed `thoryn.io/provision/v1` warns for one release) — planned and applied in order, each signed in with its own connection (`connection` defaults to the `connection.json` beside the file — the layout `thoryn project init` and the App seed) |
| `env` | `{}` | extra environment variables for the CLI: **`THORYN_*` names only** (the CLI's own variables, and the `{{env.NAME}}` placeholders a provisioning file reads — SSO-3430), never one the workflow sets itself (`THORYN_ISSUER`, `THORYN_HUB`, `THORYN_FIX_REQUEST`, `THORYN_CONSENT_URL`, `THORYN_CI_PLAINTEXT_TOKENS`), never credential-shaped (`*_SECRET`, `*_PASSWORD`, `*_TOKEN`, `*_KEY` — this file is committed plaintext). Values are exported, never evaluated |
| `fixRequest` | `true` | upload the SSO-3710 fix request (`thoryn-provision-request`) when a job is red on a missing right, so the App names the fix on the check run |
| `consentUrl` | `""` | SSO-3723 — the base URL of the App's browser consent, exported to the CLI as `THORYN_CONSENT_URL` when the `consent-url` input is empty; every `To fix` block then carries `Option 2, in the browser: <consentUrl>/github/consent/run/<owner>/<repository>/<run_id>` and the fix request `options.consentUrl`, and Option 1 becomes `thoryn access approve <owner>/<repository>/<run_id>` (SSO-3738; the raw grant lines are printed only without it). `https://`, no query or fragment. Configuration — never guessed from the issuer |
| `apply.prune` | `false` | pass `--prune`: remove owned resources the file no longer declares |
| `apply.destroy` | `false` | run `thoryn provision destroy` after a successful apply — an ephemeral fixture (an e2e sandbox) |
| `apply.confirm` | `""` | the workspace slug confirming production-plane removals (the SSO-2413 gate) |
| `provider` | `github_actions` | the forge whose job token is the identity — see the gap below |

Removals are **never on by default**; a plan never removes anything whatever the file says (the plan profile's scopes
are read-only by construction).

Two files — a production file and a sandbox file — each with its own connection, planned on every pull request and
applied on `main`:

```yaml
# .thoryn/workflow.yaml
apiVersion: thoryn.io/workflow/v1
files:
  - file: .thoryn/environments/production/provision.yaml     # connection.json beside it
  - file: .thoryn/environments/sandbox/provision.yaml
env:
  THORYN_ENVIRONMENT: sandbox        # serves `environment: "{{env.THORYN_ENVIRONMENT}}"` in the sandbox file
```

A self-hosted pool with a longer timeout — in the stub's `with:`:

```yaml
    with:
      # … the forwarded four and the two environments …
      runs-on: '["self-hosted", "linux", "x64"]'
      timeout-minutes: 60
```

**What the check prints** is the contract, rule by rule (`dispatch.*` — what the App needs; `stub.*` — the stub;
`config.*` — the file), then the effective inputs and configuration. A hand-written workflow with its own jobs is
reported as **not the supported shape**: the check still says what the App would need from it (`custom.jobs`), but
Thoryn does not promote or support it; a `uses:` of any other reusable workflow cannot be verified at all.

#### The scopes a provisioning file needs — `config.trust-scopes` (SSO-3926)

A repository identity signs in with **two profiles of one trust**: the **plan profile** (the read-only scopes a job in
`plan-environment` is minted) and the trust's **scopes** (its apply profile, which `connection.json` `auth.scopes` lists
and the CLI requests exactly in `apply-environment`). What a file needs from each follows from what it declares, so the
CLI derives it — every scope is the gate product-api puts on the endpoint the engine calls:

| The file declares | to **plan** (plan profile) | to **apply** (the trust's scopes) |
|---|---|---|
| any resource | its kind's `.read` scope, and `tenant:access.read` (the ownership check) | its kind's `.write` scope (not for a `readOnly: true` reference) |
| `environment` / `application` / `user` / `federationMember` | `tenant:environments.read` / `tenant:applications.read` / `tenant:users.read` / `tenant:federation.read` | the matching `.write` |
| `emailProvider` / `loginTheme`, `loginFlow`, `loginMethods` / `customDomain` | `tenant:email.read` / `tenant:idp.read` / `tenant:domains.read` | the matching `.write` |
| `workloadIdentityTrust` | `tenant:workload-identity.read` | `tenant:workload-identity.write`, and every scope the trust carries (`spec.scopes` — the hub's ceiling, `scope_not_grantable`) |
| `role` (SSO-3941) | `tenant:roles.read` — and NOT `tenant:access.read`: a role is not a platform access object, so no ownership check is asked | `tenant:roles.write` |
| an application's `tokenClaims` | `tenant:applications.read` (already needed by the application) | `tenant:applications.write` |
| a `grants:` block | `tenant:access.read` | `tenant:access.write` |
| no `secretSink`, or `secretSink: { kind: customerManaged }` (SSO-3954, the default) | — (nothing beyond the application's own) | — (nothing is granted) |
| `secretSink: { kind: workloadPull }` (deprecated, SSO-3951) | `tenant:workload-identity.read` (the trust, by name) | `tenant:access.write` (the workload client's `manager` grant) |
| `spec.federatedTrust` | `tenant:workload-identity.read` (the trust, by name) | — |
| a resource in a sandbox | `tenant:environments.read` (to resolve the sandbox, for a create) | — |

`tenant:clients.read` / `.write` still satisfy `tenant:applications.*` (product-api's deprecated alias). Because `apply`
plans first, the trust's scopes must hold **both** columns; a plan profile can only hold scopes the trust holds.

**The rule follows the file's part (SSO-3962).** An **application file** (`thoryn.io/application/v1`) needs
`tenant:applications.read` + `tenant:access.read` to plan and `tenant:applications.write` to apply, and nothing else: the
verdict says so, names what a mechanism of the application's own object adds (a sandbox client's
`tenant:environments.read`, a `workloadPull` / `federatedTrust` trust's `tenant:workload-identity.read`, a `grants:`
block's `tenant:access.write`), and **fails a connection that declares a scope the file never needs** — an app project's
identity wider than its file (`tenant:users.write` on an application repository, say): narrow the trust with
`thoryn workload-identity trusts set-scopes`. A **tenant file** is the union of its kinds' scopes, the table above; a
mixed `thoryn.io/provision/v1` file is judged as a tenant file is.

**Three places say it, in one wording:**

- **`thoryn provision workflow check`** — rule `config.trust-scopes` holds every configured file against its
  `connection.json`: an APPLY scope missing from `auth.scopes` names the trust's scopes; a PLAN scope missing names the
  **plan profile** (a profile set without explicit `--plan-scope` is every `.read` scope of the trust, and an explicit one
  must be among them, so a read scope the connection does not list cannot be in the profile). The repository identity
  cannot read its own trust's profile — that takes `tenant:workload-identity.read`, the scope this rule is most often
  about — so the check derives it from the connection, and `provision plan` re-checks the token it is actually minted.
- **`thoryn provision plan` / `apply`** — before the first call, the scopes the file needs to plan are held against the
  session's token (a plan job's token IS its plan profile); `apply` then holds the writes its plan actually makes (a
  converged resource writes nothing, so needs no write scope). A scope only some plans need (resolving a sandbox for a
  create) never blocks up front.
- **A `403` that happens anyway** (a token whose scopes the CLI cannot read) is rendered the same way, never as the
  generic `could not read live state (HTTP 403: access_denied …)`.

```text
$ thoryn provision plan                      # in the plan job, a trust whose plan profile lacks it
Error: config.trust-scopes — this session's token does not carry 1 scope(s) .thoryn/provision.yaml needs to plan:
  - tenant:workload-identity.read — application/forge-oauth2-proxy (resolve secretSink.trust 'forge-oauth2-proxy-pod' by name); workloadIdentityTrust/forge-oauth2-proxy-pod (read its live state)
To fix: add tenant:workload-identity.read to the plan profile of trust wi_… — the read-only scopes a job in GitHub environment 'forge-plan' is minted. …
Nothing was read or written.
```

Exit `2`, like the `403` it replaces. Add the scope in place with `thoryn workload-identity trusts set-scopes <trust>
--scope <scope> --plan-scope <scope>` (SSO-3925): the trust keeps its id and `wi_` client, so `connection.json` and
ownership stay as they are. Narrowing works from CI; widening is a person's act with a recent passkey sign-in.

**Recorded gaps (not knobs, by design — tell us if you need them):**

- **Forgejo.** `provider: forgejo` is refused: a Forgejo workload identity trust exists on the hub (oauthy ADR 2026-10-13
  Amendment 3), but `thoryn login --connection` cannot exchange a Forgejo job token yet, and the App dispatches GitHub
  workflows only. Until then a Forgejo pipeline is a `client_credentials` connection, outside this workflow.
- **A step of your own** (a notification, an extra verification, a different CLI) is not configuration. The composite
  Action `.github/actions/provision` and the raw CLI still exist for the manual path (`provision-e2e.yml` is the
  example), but the App-dispatched workflow is the stub, full stop.

The contract itself — what the App sends, what the reusable workflow satisfies — is `docs/provisioning-workflow-contract.md`
(internal; pinned in code by `ProvisioningWorkflowContract`, enforced by the same engine the check runs).

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

### Which platform? (SSO-3182)

The CLI has **no built-in issuer** — it never defaults to `localhost`. `thoryn login` resolves the
platform BASE ISSUER (`https://<label>.<env>`) in this order:

1. `--issuer <url>`;
2. the `THORYN_ISSUER` environment variable (or its `THORYN_HUB` alias — see below);
3. the platform of your previous sign-in on this machine (so after the first `--issuer` login,
   `thoryn login --workspace <slug>` alone reaches the same platform);
4. a production issuer baked into the release — **not set yet** (the production domain is a product
   decision; `ThorynConfig.PLATFORM_HUB`).

With none of them the command exits 65 and tells you how to name one — it does not dial anything.

```bash
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org   # Thoryn staging
export THORYN_ISSUER=https://auth.stg.thoryn.org && thoryn login --workspace thoryn
thoryn login --workspace dev --issuer http://localhost:54702          # a platform on your own machine
```

### `--issuer` / `THORYN_ISSUER` — and the host word (SSO-3296, epic SSO-3289)

`--issuer` and `THORYN_ISSUER` are the **documented** names. `--hub` and `THORYN_HUB` remain accepted
aliases everywhere, so recipes, connection contracts and CI written before the rename keep working
unchanged — `hub` is the name of an internal component (a Maven module, a Helm chart, a Deployment),
never something a customer should have to learn.

The public authentication host is moving from `{slug}.hub.<domain>` to **`{slug}.auth.<domain>`**
(ADR `2026-09-22-public-issuer-host-auth-subdomain.md`). **The CLI does not hard-code either word.**
It reads the host label from whatever base issuer you point it at and reuses it:

| You pass | The workspace issuer becomes | The sign-in screens are at |
|---|---|---|
| `--issuer https://hub.stg.thoryn.org` | `https://acme.hub.stg.thoryn.org` | `https://acme.identity.stg.thoryn.org` |
| `--issuer https://auth.stg.thoryn.org` | `https://acme.auth.stg.thoryn.org` | `https://acme.auth.stg.thoryn.org/id` |

So one binary is correct before **and** after the staging cutover (SSO-3297) — no flag to set, no
re-release. Sandbox environments keep their **path** form either way:
`https://acme.auth.stg.thoryn.org/{env}`.

For a deployment whose base host uses neither word, name the label once with
`THORYN_TENANT_HOST_LABEL=<label>`; `auth` and `hub` stay recognised alongside it.

> **Staging moved to `auth.stg.thoryn.org` (SSO-3297).** The old `hub.stg.thoryn.org` hosts are
> retired: they answer every request with `410 issuer_retired`. See the next section if you signed in
> before the move.

### A retired issuer (SSO-3377)

`thoryn login` remembers the platform of your previous sign-in. If that platform has since moved its
sign-in host — staging's `hub.stg.thoryn.org` became `auth.stg.thoryn.org` — the remembered issuer can
only refuse you. Before it opens a browser, requests a device code or posts a grant, **every login mode**
(`--device-code`, `--client-credentials`, `--workload-identity`, `--connection`, and `thoryn operator
login`) asks the issuer's discovery document whether it is still served. A `410 issuer_retired` stops
the sign-in (exit 65) with the retired issuer named and, where the platform can be inferred
(`hub.<env>` → `auth.<env>`, `<slug>.hub.<env>` → `auth.<env>` with `--workspace <slug>`), the line
to run instead:

```text
Using hub https://hub.stg.thoryn.org (from your previous sign-in; pass --issuer to choose another).
Error: the issuer https://thoryn.hub.stg.thoryn.org has been retired (HTTP 410 issuer_retired) — This host has been retired. Use the issuer advertised in the current discovery document.
https://hub.stg.thoryn.org was remembered from your previous sign-in on this machine; the CLI does not change a saved issuer for you.
Sign in with the platform's current issuer:
    thoryn login --issuer https://auth.stg.thoryn.org --workspace thoryn
```

The CLI never rewrites a saved issuer on its own — which platform receives your credentials is your
call, made with `--issuer`. After that sign-in, later ones reuse the new issuer. A `--connection`
contract is told which env var to change instead (`Set THORYN_ISSUER=… and run … again`), since it
refuses `--issuer`. A `410` that does not say `issuer_retired` is reported as a plain "answered HTTP 410
Gone" with no suggestion.

A **workspace** that moved to its custom domain is different (SSO-3415): its platform host's `410` names
the new issuer, and a sign-in whose issuer the CLI derived from the workspace slug follows it once (see
[Custom domain](#custom-domain-sso-3303-epic-sso-3290)). The fleet-wide `hub.` → `auth.` move above names no successor and keeps
this guidance.

Commands that run on a session remembered from a retired issuer (a refresh, an API-key re-mint, a
`workspace switch` exchange, a hub call) print the same guidance instead of a bare `HTTP 401` or
`Hub returned 410: issuer_retired`.

```bash
# Default scopes (SSO-3182): EXACTLY the `cli` login client's registered set — openid,
# offline_access and the whole tenant-config surface (applications, clients, users,
# federation, audit, environments, email, idp, access, domains, keys, workload-identity, github-connections, roles).
# SSO-3856 — `tenant:github-connections.read|write` has no `thoryn` command yet: it is requested so a workspace
# admin HOLDS the family and can grant it onward (e.g. to a starter's client in a provisioning file; the hub grants
# it to `cli` in V206, which must be deployed before a CLI release requesting it). A bare login therefore authorizes
# `clients`, `federation`, `audit`, `env`, `workspace email-provider`, `branding`, `access`,
# `domain` and `provision apply` (including a file's `grants:` block) with no --scope list.
# `workspace` rides on SCOPE_openid (the hub /account surface). The hub mints only the
# scopes the signing-in admin actually holds.
# SSO-3104 — sign-in is always ON A WORKSPACE (`https://<slug>.<label>.<env>`, client `cli`,
# provisioned in the `thoryn` workspace by this repo's .thoryn/provision.yaml); the shared
# default tenant is not a sign-in target. `--workspace` or `export THORYN_WORKSPACE=<slug>`.
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org

# Grab the whole tenant-config scope set explicitly.
thoryn login --workspace thoryn --scope all-tenant-config

# Headless (no browser).
thoryn login --workspace thoryn --device-code
```

The wildcard `all-tenant-config` expands client-side per `ScopeRegistry.kt`
to the literal tenant-config scope set. The hub does NOT understand the
wildcard — it's a CLI ergonomic.

When a command rejects with `insufficient_scope`, the CLI prints the
exact `thoryn login --scope <required>` line to fix it.

## Non-interactive auth & tenant seeding (SSO-1553 / API-key SSO-2941)

For CI / automation there is a fully non-interactive path — no browser, no
second device:

```bash
# Service-account / API-key login (RFC 6749 §4.4 client-credentials). Credentials
# from env, NEVER argv. --issuer MUST be the tenant subdomain so the hub mints `tnt`.

# SSO-2941 — single-knob API key: one secret carries id + secret as "<id>:<secret>".
export THORYN_API_KEY="ci-bot:$CI_SERVICE_ACCOUNT_SECRET"
thoryn login --client-credentials \
  --issuer https://acme.auth.stg.thoryn.org \
  --scope "tenant:applications.write tenant:federation.write"

# Or split form — --client-id + THORYN_CLIENT_SECRET (or --client-secret-file <path>):
export THORYN_CLIENT_SECRET="$CI_SERVICE_ACCOUNT_SECRET"
thoryn login --client-credentials --client-id ci-bot \
  --issuer https://acme.auth.stg.thoryn.org \
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
`https://<slug>.<label>.<env>.thoryn.org` or product-api rejects the seed with `401
missing_tnt_claim`.

**Re-mint on expiry (SSO-2941).** A client-credentials token has no refresh token
(RFC 6749 §4.4.3), so instead of the refresh-token grant the CLI re-mints a fresh
token when the stored one nears expiry (or on a `401`), re-running the same grant
with the stored client id and the secret still in the environment
(`THORYN_API_KEY` / `THORYN_CLIENT_SECRET`). The secret is **never persisted** —
only the short-lived access token, the (public) client id, and an auth-mode marker
are stored — so re-mint works for the whole life of a CI job where the secret env
var is set. If the secret is no longer in the environment, re-mint prints a hint and
the operator re-runs `thoryn login --client-credentials`.

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

The **DPoP key** (below) follows the same rules and the same opt-in: a second
keychain entry (service `thoryn`, account `dpop-key`), or `dpop-key.json` beside
the token file under the CI fallback (`THORYN_DPOP_KEY_FILE` overrides the path).
Without a keychain and without the opt-in the CLI refuses to write the private
key in plaintext and simply sends no DPoP proof.

## Pushed authorization requests (PAR, SSO-3234)

When the hub advertises `pushed_authorization_request_endpoint` in its discovery
document, `thoryn login` sends the authorization request **back-channel** —
straight from the CLI to the hub over TLS — and opens the browser at a URL that
carries nothing but `client_id` and an opaque, single-use `request_uri`
([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)):

```
POST https://<workspace>.<label>.<env>/oauth2/par
  response_type=code&client_id=cli&redirect_uri=http://127.0.0.1:<port>/callback
  &scope=…&state=…&code_challenge=…&code_challenge_method=S256[&dpop_jkt=…]
  → 201 {"request_uri":"urn:ietf:params:oauth:request_uri:…","expires_in":90}

https://<workspace>.<label>.<env>/oauth2/authorize?client_id=cli&request_uri=urn%3A…
```

Without it, every one of those parameters travels through the browser: its
address bar, its history, its extensions, and anything on the path. The scopes
you are asking for, your loopback `redirect_uri`, PKCE's `code_challenge` and the
`dpop_jkt` naming your device key are all things you would rather nothing there
could read or rewrite. PAR is the FAPI 2.0 baseline for the same reason.

The CLI is a **public** client (`token_endpoint_auth_method=none`), so per
RFC 9126 §2 its `client_id` is the whole of its authentication on that POST; if a
client secret is configured, the push uses HTTP Basic instead.

The DPoP key is named with `dpop_jkt` in the POST body — RFC 9449 §10.1's first
mechanism, not the proof-header alternative — and it is the *same* key the login
path provisions and the token-request proof later signs with, whichever rung of
the [key ladder](#sender-constrained-tokens-dpop-sso-3199) it came from. The
authorize parameters are resolved once and then handed to whichever carrier is in
use, so the binding cannot differ between the two. The push itself carries no
proof header: the two mechanisms are an either/or (§10.1 requires them to agree
when both are sent), and a proof on a request that is not a grant would spend a
single-use `jti` for nothing.

**What happens when it is not available.** A hub that advertises no PAR endpoint,
a `5xx`, or a connection failure all fall back to the plain authorize URL with one
note on stderr — an older platform and an unwell one both still sign you in. A
**4xx does not fall back**: the hub understood the push and rejected it, so the
sign-in fails with the hub's error code. Retrying front-channel would hide a real
misconfiguration, and would let anything able to forge a single `400` strip PAR
off every sign-in and put the parameters back in the browser.

`thoryn status` tells you which one you will get:

```bash
thoryn status --output json
# …
# pushesAuthorizationRequest          true
# pushedAuthorizationRequestEndpoint  https://acme.auth.stg.thoryn.org/oauth2/par
```

## Sender-constrained tokens (DPoP, SSO-3199)

The CLI proves possession of a private key on every token request and every API
call, per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449). An access token
the hub binds to that key (`cnf.jkt`) is useless to anyone who steals the token
alone — which is the residual risk refresh-token rotation cannot close (RFC 9700
§2.2.2 accepts *either* rotation *or* sender-constraining; Thoryn ships both).

**What happens, concretely.**

* On first use the CLI generates a **per-installation** EC P-256 (ES256) key pair
  and stores the private key in the same secure store as your tokens. It is never
  printed, never written to a receipt, and never leaves the machine — only the
  public JWK travels, inside the proof.
* **Only against a platform that advertises DPoP** (SSO-3221). Before attaching a
  proof to a token request the CLI reads the hub's
  `/.well-known/openid-configuration` and looks for a non-empty
  `dpop_signing_alg_values_supported` — the field RFC 9449 §5.1 defines as the
  advertisement of DPoP support. One small `GET`, memoised per hub for the life
  of the process, and only on a command that reaches the token endpoint. No
  advertisement — or an unreachable hub — means no proof, which is exactly the
  wire shape of a CLI that had never heard of DPoP.
* Every request to `/oauth2/token` (login code redemption, `refresh_token`, the
  workspace-switch exchange, device-code polling, client-credentials) and every
  hub / gateway API call then carries a freshly signed `DPoP:` proof JWT
  (`typ: dpop+jwt`, `jwk`, `htm`, `htu`, `iat`, `jti`, plus `ath` when a bound
  token is presented).
* If a server demands a nonce (`use_dpop_nonce`, RFC 9449 §8) the CLI caches the
  `DPoP-Nonce` per origin and retries the request once, automatically.
* The token is presented as `Authorization: DPoP <token>` **only when the hub
  answered `token_type: DPoP`**; otherwise it stays `Bearer`.

> **Why the capability check exists.** `cli-v0.20.0` shipped the proof without
> one, on the argument that the presentation scheme is server-driven so nothing
> changes until the hub flips the `cli` client. That was true of the CLI and
> wrong about the hub: Spring Authorization Server binds the token and answers
> `token_type: DPoP` **as soon as a valid proof arrives**, whatever the client's
> `dpop_required` flag says. So the CLI's own proof flipped the answer, the CLI
> faithfully followed its own flip, and it began presenting `DPoP <token>` to
> resource servers that did not accept the scheme — every customer-plane call
> answered `401`, and every scheduled thoryn-examples run went red from
> 2026-09-19 04:23 UTC. The hub half of SSO-3221 stops binding unless the client
> opted in; this check is the redundant client half, because a released binary
> outlives any single platform version.

```bash
thoryn whoami --output table
# …
# dpopKeyThumbprint  9mS2kYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4IZcOC
# dpopBound          no (bearer token — the hub does not bind this client's tokens yet)
```

Once the hub marks the `cli` client `dpop_required` and binds `cnf.jkt`,
`dpopBound` reads `yes (cnf.jkt matches this installation's key)`. A `MISMATCH`
means the stored token belongs to another installation (or the key was rotated
since it was issued) — run `thoryn login` again.

**Rotating the key.** `thoryn logout` keeps the key by default: on its own it
authorises nothing, and keeping it means your next login re-binds to the same
`jkt`. `thoryn logout --rotate-key` discards it, so the next login generates a
new one and every token bound to the old thumbprint stops working — the right
move when handing the machine on or if the key may have leaked. It also **revokes
the device record that named the old key** (SSO-3270), so the account's device
list does not go on offering a machine that can no longer sign anything; the next
login registers the new key as a new device under the same name.

**Hub-side flip.** Requiring proofs is the *other half* of SSO-3199 and lives in
`oathy` (step 2): flip `dpop_required=true` on the `cli` client and require
`cnf.jkt`-bound tokens at product-api / api-gateway. It is deliberately a
separate, later change so CLIs released before it keep working; the minimum CLI
version for the flip is the first `cli-v*` release containing this feature.

### Devices (SSO-3228)

The key stays on the machine, so it stands in for the machine. When a login
produces a **bound** token, the CLI registers that key as a named **device** —
hostname by default, `thoryn login --device-name "alice work laptop"` to choose:

```bash
thoryn devices list
# NAME            ID   STATE       SESSIONS  LAST SEEN             WORKSPACES               NETWORKS
# alice-mbp       d-1  signed_in   2         2026-09-19T09:41:00Z  acme/production, acme/blue  203.0.113
# spare-desktop   d-2  idle        0         2026-09-02T11:00:00Z  -                        198.51.100
# (unregistered)  -    unregistered 1        2026-08-30T17:15:00Z  acme/production          192.0.2

thoryn devices revoke alice-mbp --reason "left on a train"
```

**STATE** (SSO-3271) is what the device is doing now — `signed_in` (live sessions
are bound to its key), `idle` (registered, none live), `revoked`, or
`unregistered` (a key with no device record). **SESSIONS** counts the live ones and
**WORKSPACES** names the workspace and plane each belongs to. A session is live
while it still holds an unexpired refresh or access token, so a machine whose
refresh token lapsed weeks ago reads `idle` — and revoking it may still report
ending sessions, because a revoke clears the dead rows too.

Against a hub older than SSO-3271 those columns read `-`: the CLI reads the new
fields tolerantly and never guesses `signed_in` from registration alone.

`thoryn whoami --check` asks the hub the same question about **this** machine. It
is the one online part of `whoami`, and opt-in for that reason — but it is the
only way to see a device someone revoked from elsewhere, because the access token
in your keychain goes on looking valid until it expires:

```bash
thoryn whoami --check --output table
# ...
# tokenStatus      valid (expires in 0h 42m)
# deviceState      revoked
# deviceSessions   0 live
# Notice: this device is revoked — the current access token is accepted until
#   2026-09-20T10:16:44Z; the next refresh will be refused. Run `thoryn login`
#   to register a new device.
```

Those two lines are both true and read as a contradiction, so `--check` explains
them (SSO-3279): a resource server checks the token's signature and expiry, not
the device register, so the token in your keychain keeps working until it expires
— what is already gone is the renewal. The exit code is unchanged (nothing has
failed yet), and `--output json|yaml` carries the sentence as a `deviceNotice`
field rather than as prose a script would have to match on.

Revoking ends **that machine's** sessions and refuses its key from then on; every
other machine you are signed in on keeps working. It cannot be undone for that
key — signing in from that machine again generates a new key and registers a new
device. The networks are coarse prefixes (IPv4 /24, IPv6 /48), the same record
the platform's own per-key anomaly signals read.

Registration never fails a sign-in: against a hub that does not have the endpoint,
or when the token is not bound, the CLI notes it on stderr and you are signed in
regardless — `thoryn devices list` simply shows that key as unregistered.

**Rotating the key revokes this device; the next login registers a new one**
(SSO-3270). The device record names the key, so discarding the key without it
would leave a row for a machine that can no longer sign anything:

```bash
thoryn logout --rotate-key
# Signed out (local tokens cleared).
# Device 'alice-mbp' revoked at the hub (2 sessions ended).
# DPoP key discarded — the next `thoryn login` generates a new one.
```

The revoke goes out **before** the key is discarded, because the hub requires it
to be signed by the very key being retired. Nothing there can fail the logout: an
unreachable hub, an already-ended session or an already-revoked device each print
one note naming `thoryn devices revoke <id>` to finish the job from another
machine, and the sign-out completes regardless. Plain `thoryn logout` keeps the
key, so it keeps the device — the next login re-binds to the same `jkt`.

### Key classes — where the private key lives (SSO-3227)

DPoP stops **token** theft: a stolen access token is useless without a proof
signed by your key. It does not, on its own, stop malware running as you on your
own workstation — that can simply ask the keychain to sign proofs. The answer is
a key the keychain cannot hand over and a signature that needs a human. The CLI
now picks the strongest option the machine actually supports and **tells you
which one it got**:

| class | where the private key lives | what it buys |
|---|---|---|
| `secure_element` | Apple Secure Enclave (macOS) | non-exportable — the key material never exists outside the secure hardware — and every signature requires user presence (Touch ID, Watch, or your password) |
| `software_keychain` | OS keychain (the SSO-3199 behaviour) | protects against token theft; a process running as you can still ask the keychain to sign |
| `ephemeral` | process memory only | nothing — see below |

```bash
thoryn whoami --output table
# …
# dpopKeyThumbprint  9mS2kYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4IZcOC
# dpopKeyClass       software_keychain — software key in the OS keychain (secure_element unavailable: …)
# dpopBound          yes (cnf.jkt matches this installation's key)
```

`thoryn status` reports `dpopKeyClass` too. When the CLI falls back, the line
carries **why** the stronger class was passed over — that reason is the half you
can act on.

**`ephemeral` never sends a proof.** A key that dies with the process cannot
honour a `cnf.jkt` minted at login on your *next* command, so binding a token to
one would break every subsequent invocation. On a machine with neither a secure
element nor a usable keychain the CLI therefore sends **no** proof at all — the
pre-SSO-3199 wire shape — and says so once. The class exists so `whoami` can
name that state rather than report nothing.

**Presence prompts: once per session, not per request.** All the proofs one
command mints (a token request plus its API calls) go through one key handle, so
a command asks at most once. Across commands the CLI keeps a timestamp of the
last presence-backed signature and stays quiet inside an idle window — 15 minutes
by default, `THORYN_DPOP_PRESENCE_IDLE_MINUTES` to change it — after which it
prints one line explaining the prompt you are about to see. Note the honest
boundary: *macOS* decides when LocalAuthentication actually shows its dialog, and
because each `thoryn` invocation is a separate short-lived process, the only
supported way to widen OS-side reuse (an `LAContext`) cannot outlive one command
either. Cross-process presence reuse needs a resident agent and is a follow-up.

**Never in CI.** A hardware key is refused outright when there is no interactive
terminal — `CI` is set, `THORYN_NON_INTERACTIVE` is set, or stdin/stderr are not
TTYs — because a pipeline cannot answer a fingerprint prompt. The CLI degrades to
the software keychain with a one-line notice rather than hanging on a dialog
nobody will see. (The check is `isatty(3)`, not `System.console() != null`: since
JDK 19 the latter returns non-null on a pipe, and `Console.isTerminal()` — the
correct API — is JDK 22, while this project ships on JDK 21.)

**Migration is on login, never mid-session.** An existing software key keeps
working untouched. Only `thoryn login` is allowed to *create* a hardware key, so
a session already signing with a software key keeps the key its live token is
bound to, and the upgrade lands on the next sign-in. `thoryn logout
--rotate-key` deletes the key of **every** class, plus the presence timestamp —
a migrated machine can hold both, and "rotate" has to mean nothing survives.

**Per-OS status, honestly.**

* **macOS — implemented.** Secure Enclave P-256 via `Security.framework`
  (`kSecAttrTokenIDSecureEnclave`, `SecAccessControlCreateWithFlags` with
  `kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence`, signing
  through `SecKeyCreateSignature`), bound with JNA — already a dependency, already
  in the native image, already how the keychain backend calls the same framework.
  **It does not engage in a released binary yet:** persisting a Secure Enclave key
  needs the calling binary to be code-signed with a keychain-access-group
  entitlement, and the published `thoryn` binaries are not signed or notarised.
  Without it macOS returns `errSecMissingEntitlement (-34018)` on the *store*
  step, the CLI reports that as the skip reason, and you get the software key.
  Code-signing the macOS binary is the follow-up that switches this on.
* **Windows / Linux — not built.** TPM via the Windows Hello platform crypto
  provider, and TPM2 via `tpm2-pkcs11`, are the intended backends. They are not
  stubbed in: neither can be built or exercised on the machine this was written
  on, and a backend that has never run is a claim rather than an implementation.
  They report `this platform has no supported secure element` and slot into the
  same `DpopKeyProvider` seam when they land, with nothing above it changing.

**`key_class` on the wire is telemetry only.** The proof header carries a
`key_class` hint so the platform can see how much of the fleet is hardware-backed.
It is **self-asserted by the client and must never be trusted**: any server making
an authorization decision on it would be trusting an attacker-chosen string. It
was verified to be safe to send against Spring Authorization Server's real proof
parser (`DPoPProofJwtDecoderFactory`) before being added.

## Session endpoints (SSO-2827)

`thoryn login` records the platform issuer (`--issuer`) and the customer-plane
gateway alongside the token, so the other commands default to them — you do
**not** need to repeat `--issuer` / `--gateway` on every call after signing in:

```bash
thoryn login --workspace acme --issuer https://auth.stg.thoryn.org  # records issuer + gateway for the session
thoryn workspace list                                              # uses the session issuer, no --issuer needed
thoryn clients list                                                # uses the session gateway, no --gateway needed
```

The session also remembers the WORKSPACE it signed in on, so when it can no longer be renewed the CLI
prints the exact line to fix it (`Run \`thoryn login --workspace acme\``) instead of a bare `HTTP 401`.

A sign-in also SELECTS that workspace (SSO-3927), so environment commands work straight away, with no
`thoryn workspace switch` in between:

```bash
thoryn login --workspace acme --issuer https://auth.stg.thoryn.org
# Signed in.
# Workspace 'acme' is selected; `thoryn env use <environment>` picks an environment in it.
thoryn env use production
```

Each sign-in replaces the previous selection, and an environment chosen with `env use` in another
workspace does not carry over. A login without `--workspace` selects the default workspace it
announces (`thoryn`). `login --connection` selects the contract's `workspace.slug`, and
`--workload-identity` selects `--workspace`, else the workspace its audience names. An API-key login at the
platform base issuer names no workspace, so it clears the selection.

The gateway is derived from the base issuer host (`<label>.<env>` → `api.<env>`, so both
`hub.stg.thoryn.org` and `auth.stg.thoryn.org` yield `api.stg.thoryn.org`); for a non-standard
topology set it explicitly at login with `--gateway <url>`. An explicit `--issuer` (or its `--hub`
alias) / `--gateway` on any command still overrides the session.

## Session renewal (SSO-2834 / SSO-2861 / SSO-3182)

The access token lives ~15 minutes. When a session carries a refresh token (interactive logins ask for
`offline_access`), the CLI renews it transparently — proactively near expiry and reactively on a `401`
— **before** a command runs and before a `workspace switch` token exchange, so a switched workspace
never outlives the home session. A client-credentials / API-key session has no refresh token by
design (RFC 6749 §4.4.3) and is re-minted from `THORYN_API_KEY` / `THORYN_CLIENT_SECRET`.

When renewal is impossible the CLI now says so, once, with the exact command:

```
Your sign-in session has expired and carries no refresh token, so it cannot be renewed.
Run `thoryn login --workspace thoryn` to sign in again.
```

**And then it stops (SSO-3568).** Having said that, the CLI makes no further
calls: the command exits non-zero with the sign-in instruction as its last
word, rather than going on to the gateway with a credential it has just
reported as dead. It used to continue, so the message a reader was left with
was whatever the server said to the doomed call next — in the reported case
`HTTP 401: invalid_token - DPoP proof has already been used.`, which reads like
an RFC 9449 protocol fault and sends you looking in entirely the wrong place.
On `--output json|yaml` the same guidance arrives as `hint`, beside the stable
`errorCode: session_cannot_be_renewed`, so a script can branch on "go and sign
in" instead of on a `401`. The exit code is unchanged.

**Public-client refresh tokens (hub, SSO-3185).** Spring Authorization Server withholds a refresh token
from a public client on the authorization-code grant; the hub issues one to the `cli` client anyway,
because it rotates and is replay-protected (RFC 9700 §2.2.2), so a loopback `thoryn login` renews like a
`--device-code` one. The CLI still prints a note right after a sign-in that received none (an older hub,
or a client without the opt-in).

### How long a sign-in lasts (SSO-3928)

A `thoryn login` session is the hub's `cli` client session. The hub sets its limits, not the CLI:

| Limit | Value | In practice |
|---|---|---|
| Access token | 15 min | Renewed automatically; you never see it. |
| Idle window | 72 h | A session not used for 72 hours ends. A night or a weekend away does not end it; any command renews it. |
| Maximum lifetime | 7 days from sign-in | However often you use it, sign in again once a week. |

(Set by the product owner on 2026-10-23, SSO-3930; until then the idle window was 8 h, so a session
left overnight ended — SSO-3928.) A workspace's authentication policy can only shorten these. The refresh token rotates on every renewal
and, where the machine holds a DPoP key, is bound to it, so a copied token is useless elsewhere. Two commands that renew
at the same moment are fine: the hub accepts the just-rotated token for 30 seconds and returns the same
successor.

When the hub ends the session, the CLI says why and when, from the hub's reason and the session's own
tokens:

```
Your sign-in session has ended: it was not used within the hub's idle window (last renewed 2026-10-20 18:31 UTC, 3 d 0 h ago). Run `thoryn login --workspace thoryn` to sign in again.
Your sign-in session has ended: it reached its maximum lifetime (signed in 2026-10-15 18:00 UTC, 7 d 0 h ago). Run `thoryn login --workspace thoryn` to sign in again.
```

A hub that gives no reason gets `the hub refused to renew it (invalid_grant)` with both times. A renewal
that failed for any other reason (the hub unreachable, a `5xx`) did not end the session and keeps the
neutral `Could not renew your sign-in session (…)`. If the token store cannot save a renewed session, the
CLI warns that the next command will need a sign-in: the refresh token it replaced is spent.

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

The former **`ci-signin`** recipe (SSO-2944, the workspace-less CI sibling) is **retired**
(SSO-3092): this repo's own CI converges `.thoryn/provision.yaml` with `thoryn provision apply`
(see below), and the `thoryn-examples` scenarios provision through their recipes' `provision:`
file. A recipe that needs a throwaway environment inside the workspace you signed in to declares
it in its provisioning file instead.

**Recipes reference a provisioning file (SSO-3100, epic SSO-3087).** The provisioning file
(`provision.yaml`, schema `engine/src/main/resources/provision/provision.schema.json`) is **leading**
for all the infrastructure a normal end user configures — environment (incl. a throwaway
sandbox), application, demo user, sign-in methods (`loginMethods`), look-and-feel
(`loginTheme`), `loginFlow`, `emailProvider`, `federationMember`. A recipe is the
**orchestration file** on top. In the product owner's words: *the provision file is about how to get
Thoryn up and running; the recipe file is about how to get an example configured — the extra steps beyond
the provisioning.* The recipe names its provisioning file under `provision:
./provision.yaml` (shipped next to `recipe.json` in the signed catalog bundle and in the
bundled resources) and carries only what is extra to *run* the example — params, any
extra `steps`, `verify`, `assets`. `steps` is optional when `provision` is set.

```yaml
apiVersion: thoryn.io/examples/v1
id: sandbox-signin
version: 1.0.0
summary: Sign in on a throwaway sandbox provisioned from provision.yaml.
provision: ./provision.yaml          # environment + application + user + loginMethods live here
params:
  - { name: workspaceSlug, prompt: "Standing workspace slug" }
  - { name: envSlug, prompt: "Sandbox slug", default: "sbx-{{generate.slug8}}" }
  - { name: demoPassword, prompt: "Demo user password", secret: true }
verify:
  - assert: applications.get
    id: "{{provision.application.rp.clientId}}"   # provisioned resources are addressable
    expect: { status: active }
```

`thoryn examples apply` (and `setup`) **provisions first**: it plans + applies the file with
the same converge engine as `thoryn provision apply` (create / update / no-op by converge
key — a re-apply issues no writes, a leftover sandbox is matched by its slug), then runs the
recipe's own steps and `verify`. The file's `{{env.NAME}}` placeholders and `<key>Env` secret
references resolve **first from the recipe's params** (so `passwordEnv: demoPassword` reads the
`secret: true` param, `slug: "{{env.envSlug}}"` reads `envSlug`) and **then from the process
environment**; secret values never reach a file or receipt. The recipe's **`params` section is
overridable by the example that runs it**, and a local `apply` **asks for each param**: a param
takes `--set`, else the **process env var of its own name** (`export envSlug=…`,
`export demoPassword=…` — the channel CI uses; a secret never rides on argv; either skips the
prompt), else the interactive prompt (a `secret: true` param is read without echo and its default
is never shown), else the recipe default — a generated secret default is revealed **once** after
apply so you can sign in with it (SSO-3102). What the file owns is exposed to
the recipe as `{{provision.<kind>.<name>.id}}` (plus `.slug` for an environment, `.email` for
a user, `.clientId` / `.redirectUri` for an application, `.methods` for `loginMethods`), the
first `environment` resource becomes the environment later steps and `examples run` target,
and every resource lands on the recipe receipt. No provisioning receipt is written (SSO-3715):
`thoryn examples teardown` runs the recipe's own teardown actions and **then destroys** what the
provisioning file declares and you may remove, planned live from the same file (the owner rule
above — a founder removes the sandbox and the clients nobody owns; users and singletons go with
the sandbox) child-first; a failed removal keeps the state so a re-run can retry. A recipe that creates its own
workspace (`hub.createWorkspace`) cannot also carry a provisioning file — the file targets the
caller's standing workspace. Recipes without `provision` behave exactly as before.

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

## Provisioning GitHub Action (SSO-2938 → SSO-2944 → SSO-3090)

`.github/actions/provision` is a reusable **composite Action** that configures the
product as a real customer against **shared staging**, using ONLY the product APIs
via this CLI and the two committed `.thoryn/` files (no DB seeding, no demo endpoints,
no imperative sign-in or provisioning — the product-boundary rule applied to CI).

**thoryn-cli is the reference consumer (SSO-3090).** A repository binds itself to
Thoryn with one folder, and this repo's own CI runs exactly that:

| File | Declares | Verb |
|---|---|---|
| `.thoryn/connection.json` | **who I am** — workspace slug and the **workload identity trust** CI signs in under: its `wi_…` client id, audience, GitHub pins and the exact scope set; no secret and no env var naming one (SSO-2948, SSO-3690) | `thoryn login --connection` |
| `.thoryn/provision.yaml` | **what I own** — desired-state resources: the CLI's login client `cli` and the sandbox `cli-ci`, both `retain: true` (SSO-3717), + a loopback OAuth client inside the sandbox (SSO-3088) | `thoryn provision plan / apply / destroy` |

The Action:

1. **downloads the released CLI** (`gh release download --pattern thoryn.jar` from the
   latest `cli-v*`, or the `cli-version` input) — it needs **cli-v0.36.0+**, the first
   release whose `apply` / `destroy` print `--output json` and write no receipt (SSO-3715),
   and fails loud on an older tag,
2. **signs in non-interactively** from the connection contract
   (`thoryn login --connection .thoryn/connection.json`). This repo's contract is
   `workload_identity` (SSO-3690): the job requests its own GitHub Actions OIDC token
   (`permissions: id-token: write`) and the CLI exchanges it under the `thoryn-cli-ci` trust — no
   secret exists anywhere. (A `client_credentials` contract instead receives its secret ONLY as the
   env var the contract names, never on argv.)
3. **converges the provisioning file** — `thoryn provision plan` (logged) then
   `thoryn provision apply --file .thoryn/provision.yaml --yes --output json`: the `cli` login
   client, the sandbox `cli-ci` inside the `thoryn` workspace and a public loopback client in it.
   Apply twice issues no writes; a resource left by a failed run is **matched** by its converge
   key, never duplicated (SSO-3089). **Nothing is written beside the file** (SSO-3715 / SSO-3717):
   the apply's JSON document is kept under `$RUNNER_TEMP` and exposed as `apply-result`; a receipt
   turning up next to the file fails the step (an older CLI),
4. **exposes** `workspace-slug` / `environment` / `client-id` / `issuer` as outputs, read from the
   apply's `resources[]` (kind / name / id / environment / action) — the `environment` row's slug,
   the first `application` row's id — and the issuer from `thoryn whoami` as before, and
5. **destroys on exit** (`thoryn provision destroy --file … --yes --output json`, `if: always()`,
   disable with `destroy: "false"`): child-first, owner-gated (SSO-3715) — the per-run loopback
   client the CI identity created (and so owns) goes; `cli` and `cli-ci` are `retain: true` and are
   shown as `retained by the file`; the standing workspace is never touched. The destroy's JSON
   document (`{destroyed, removed[], skipped[]}`) is exposed as `destroy-result`, and
   `provision-e2e.yml` **asserts** from it that exactly `application/loopback-rp` was removed and
   that `application/cli` + `environment/ci` were retained (SSO-3717 — the ADR's dogfood check,
   run rather than reasoned),
6. **names its fix when it fails** (SSO-3710): the Action resolves one path for the CLI's fix request
   (the `fix-request` input, default `$RUNNER_TEMP/thoryn-provision-request.json`), hands it to the
   sign-in and the apply steps through `THORYN_FIX_REQUEST`, and exposes it as the `fix-request`
   output. The **caller** uploads it — `actions/upload-artifact`, `if: failure()`, name
   `thoryn-provision-request`, `if-no-files-found: ignore` — as `provision-e2e.yml` and the reusable
   `provisioning.yml` do; see "A red check names its fix" above.

The demo caller is `.github/workflows/provision-e2e.yml` (manual `workflow_dispatch`).

**Consume it from another repository** (a `thoryn-examples` scenario, a customer
pipeline): check out *your* repo, then `uses: thoryn-io/thoryn-cli/.github/actions/provision@main`
with `client-secret`, `connection` and `file` pointing at *your* `.thoryn/` files (paths
resolve in the caller's workspace). The `secret-env` input must equal the env-var name
your `connection.json` declares in `auth.secretEnv`.

### CI provisioning setup (one-time)

Everything the run needs is committed, except the one thing a person must do once: create the
workload identity trust CI signs in under (SSO-3690 — the credential ladder's "courier: never";
the former `cli-ci` client and its `THORYN_CLI_CI_CLIENT_SECRET` repository secret are retired):

```bash
# 0) Sign in interactively as an admin of the `thoryn` workspace, on the production plane. The default
#    scope set already covers the six scopes the trust carries (SSO-3182); the hub only lets you grant
#    what you hold.
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org
thoryn env use production

# 1) Create the trust: this repository by its immutable GitHub ids, the e2e job's GitHub environment,
#    main only, GitHub-hosted runners, exactly the scopes .thoryn/connection.json requests.
thoryn workload-identity trusts create --name thoryn-cli-ci \
  --repository thoryn-io/thoryn-cli --owner-id 229451779 --repository-id 1361536515 \
  --github-environment thoryn-provision-e2e --ref refs/heads/main --github-hosted-runners-only \
  --scope "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write tenant:access.read tenant:access.write" \
  --confirm-production

# 1b) The plan profile (SSO-3702; SSO-3699 option B) — the App's read-only plan job runs in the UNPROTECTED
#     GitHub environment thoryn-provision-e2e-plan as this SAME trust. Add it at create (--plan-environment
#     thoryn-provision-e2e-plan, plan scopes derived) or later, additively, on the existing trust:
thoryn workload-identity trusts set-plan-profile <trust-id> --plan-environment thoryn-provision-e2e-plan
#     Nothing to re-paste: the wi_ client stays. (The dogfood migration of this repository's trust is SSO-3704.)

# 2) Paste the printed clientId (wi_…) into .thoryn/connection.json (auth.clientId) and into the sandbox's
#    grants: subject in .thoryn/provision.yaml; open a pull request. Then converge the grant and remove the
#    retired client in ONE reviewed apply: `thoryn provision apply --file .thoryn/provision.yaml --prune
#    --confirm thoryn --yes`, and delete the repository secret. Step by step: .thoryn/README.md.
# 3) Dispatch provision-e2e on main — it converges .thoryn/provision.yaml with zero secrets in the
#    repository, asserts the CI identity is confined, and removes what the run created on exit (the
#    sandbox is a long-lived fixture and stays).
```

No standing test user and no standing sandbox are needed any more: the provisioning file
creates (or matches) the sandbox and the client per run.

## Operator commands

`thoryn operator …` is the **operator plane** (oathy ADR
`2026-09-18-operator-workspace-ownership-transfer.md`, amended 2026-09-26 for custom domains;
docs `operate/operator-plane/`). It is not part of the customer product: an operator is an identity in
the platform home workspace `thoryn` that holds the explicit `platform:thoryn#operator` grant, appointed
only by the deployment value `productApi.operatorPlatformSubjects`.

Three things differ from every other command:

* **A separate session.** `thoryn operator login` signs in on the `thoryn` home with the public native
  client `thoryn-operator` (hub V174; loopback `http://127.0.0.1/callback`, any port) and stores the
  result in its own slot — keychain account `operator-tokens` (or `operator-tokens.json` next to
  `tokens.json` under `THORYN_CI_PLAINTEXT_TOKENS=1`). Your `thoryn login` session is never replaced,
  and no customer-plane command ever uses the operator token.
* **A passkey is required.** The hub mints `admin:*` scopes only to a passkey sign-in (`amr`
  `swk` / `hwk` / `webauthn`) of an identity with standing, and re-checks both on every call. The login
  sends `prompt=login` so an existing (possibly password) browser session is not reused — choose your
  passkey on the sign-in page. The token lasts 15 minutes and has no refresh token; sign in again when
  it expires.
* **No public address.** `/admin` is refused on every public host (edge deny Ingress +
  `AdminSurfaceExposureFilter`). The commands call the hub through a port-forward, default
  `--hub-url http://localhost:18080`, and refuse any URL that is not loopback, a single-label Service
  name or a `*.svc` name — an operator token is never sent to a public host.

```bash
# 1. Sign in as an operator (browser; choose your PASSKEY). Default scopes:
#    openid admin:custom-domains.manage admin:custom-domains.read
thoryn operator login --issuer https://auth.stg.thoryn.org
thoryn operator login --status          # validity, subject, scopes, "Passkey: yes"

# 2. In another terminal (needs cluster access):
kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080

# 3. Turn custom domains on for a workspace, and check it:
thoryn operator custom-domain entitle acme
# Custom domains ENABLED for workspace 'acme' (entitled: true). Its admins can now run `thoryn domain add <host>`.
thoryn operator custom-domain status acme
# Workspace 'acme' has no custom domain.   (until its admins claim one; then state, DNS records, last check)

thoryn operator custom-domain revoke acme   # off again; an existing domain is NOT removed
thoryn operator logout
```

Every `custom-domain` subcommand takes `--output json|yaml|table` / `--json`.

| Symptom | Meaning | Fix |
|---|---|---|
| `the hub is not reachable at http://localhost:18080` | No port-forward | Start `kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080` |
| `Refusing to send an operator token to '<host>'` | `--hub-url` is a public host | Use the port-forward address |
| `404 not_found` | The workspace does not exist, **or** your identity holds no operator standing here (the hub answers both with 404) | Check the slug; confirm your platform subject is in `productApi.operatorPlatformSubjects` |
| `403 operator_passkey_required` | The operator session was not a passkey sign-in | `thoryn operator login`, choose the passkey |
| `403 insufficient_scope` | The token lacks `admin:custom-domains.manage` (or `.read` for `status`) — e.g. minted before hub V185 | `thoryn operator login` again |
| login fails with `invalid_scope` | No operator standing, or not a passkey sign-in (the hub does not say which) | Confirm standing; sign in with the passkey |
| `Your operator session has expired` | 15-minute token, no refresh | `thoryn operator login` |

DPoP: the operator login uses the same DPoP path as `thoryn login`, but the hub binds only for clients
that participate, and `thoryn-operator` does not (not `dpop_required` / `dpop_allowed`, not in the
cutover list) — so its tokens are Bearer tokens today. Should the client ever be bound, the commands
present the token under `DPoP` with a proof whose `htu` is the port-forward URL, which is what the hub
(strict `htu`, reconstructed from the `Host` it receives) compares against.

### Platform-client scopes (`thoryn operator platform-scopes`)

A **platform client** is a workload the platform runs outside its own namespace (the provisioning service's
machine client, for example). It reaches product-api's `/api/v1/platform` surface with a `platform:` scope, which no
workspace admin, product service or provisioning file can grant. An operator does, with the hub capability
`admin:clients.platform-scopes` (oathy ADR `2026-10-19-operator-grants-platform-client-scopes.md`, runbook
`docs/content/operate/operator-plane/platform-client-scopes.mdx`). The hub enforces the rules; the CLI only calls it:

* **The platform home's production plane only.** The endpoints take no workspace, so another workspace's client
  cannot be named. A sandbox twin answers `404 client_not_found`.
* **A closed set of scopes:** `platform:trusted-issuers.read`, `platform:audit-events.append`,
  `platform:github-installations.sync`. Anything else is `400 unknown_platform_scope` / `not_a_platform_scope`.
* **A machine client.** A grant needs the `client_credentials` grant type (`409 machine_client_required`).
* **Idempotent and audited.** Each change writes `CLIENT_PLATFORM_SCOPE_GRANTED` / `…_REVOKED` on the home's
  audit chain with your subject and the `reason` / `ticket` you pass; a call that changes nothing writes no row.
* **Kept on ordinary updates.** A provisioning file or a console edit that replaces the client's scope list keeps
  its `platform:` scopes — and `thoryn provision plan` never shows them as drift (it leaves `platform:` / `admin:`
  scopes out of the comparison, and refuses a provisioning file that declares one: `reserved_scope`).

The scope is not in the operator login's default request (an operator token carries no power the operator is not
about to use, and an environment whose hub predates V207 would refuse it), so ask for it:

```bash
thoryn operator login --issuer https://auth.stg.thoryn.org --scope "openid admin:clients.platform-scopes"
kubectl -n thoryn port-forward svc/thoryn-hub 18080:8080        # in another terminal

thoryn operator platform-scopes get provisioning-m2m
thoryn operator platform-scopes grant provisioning-m2m platform:trusted-issuers.read --ticket SSO-3857 \
  --reason "the provisioning service reads the issuer registry"
thoryn operator platform-scopes revoke provisioning-m2m platform:trusted-issuers.read --ticket SSO-3857
```

**Declare, review, apply.** The grants a workload needs are declared in git, in the repository that owns the
workload (thoryn-provisioning's `.thoryn/platform-scopes.yaml`), and reviewed like any other change. `apply` reads
every declared client first and prints the plan, then grants what is missing and revokes what is extra. Clients
the file does not name are never touched; applying the same file again changes nothing, so a new environment
converges by applying it once.

```yaml
# .thoryn/platform-scopes.yaml
apiVersion: thoryn.io/platform-scopes/v1
ticket: SSO-3857                       # optional; on every audit row (at most 64 characters)
reason: "provisioning service grants"  # optional; on every audit row (at most 500 characters)
clients:
  - clientId: provisioning-m2m         # a client_credentials client of the home's production plane
    scopes:                            # EXACTLY the platform: scopes it should hold; [] removes them all
      - platform:trusted-issuers.read
      - platform:audit-events.append
      - platform:github-installations.sync
    # ticket / reason may also be set per client; --ticket / --reason override both
```

```bash
thoryn operator platform-scopes plan  -f .thoryn/platform-scopes.yaml      # = apply --dry-run; writes nothing
thoryn operator platform-scopes apply -f .thoryn/platform-scopes.yaml
# Platform-client scopes in the platform home workspace's production plane (1 client(s)):
#   ~ provisioning-m2m
#       + platform:trusted-issuers.read
#       + platform:audit-events.append
#       + platform:github-installations.sync
#   granted platform:trusted-issuers.read to provisioning-m2m
#   …
# Applied: 3 granted, 0 revoked, 0 client(s) unchanged.
```

The file accepts only `platform:` scopes, no workspace and no environment, and refuses unknown fields; every
problem is listed at once and nothing is sent. A refusal while reading the clients stops the run before any
write; a refusal part-way through the writes keeps what was done, and re-running the file finishes the rest.
`--output json|yaml` / `--json` print the plan (`grant`, `revoke`, `unchanged`, `applied`) as one document.

| Symptom | Meaning | Fix |
|---|---|---|
| `403 insufficient_scope` | The operator token lacks `admin:clients.platform-scopes` | `thoryn operator login --scope "openid admin:clients.platform-scopes"` |
| login fails with `invalid_scope` | No standing, not a passkey sign-in, or the hub predates V207 (`thoryn-operator` does not hold the scope yet) | Confirm standing and the hub version |
| `404 not_found` | No operator standing here, or the hub predates V207 (the surface is not routed) | Confirm your subject is in `productApi.operatorPlatformSubjects`; check the hub version |
| `404 client_not_found` | No such client in the home's **production** plane | Create it through the product first, in production |
| `409 machine_client_required` | The client has no `client_credentials` grant | Give it that grant through the product, or use a machine client |
| `400 unknown_platform_scope` | Not one of the three platform-client scopes | Check the spelling |
| `503 audit_unavailable` | The audit row could not be written, so the hub undid the change | Retry |

## Build

Requires a JDK 21+ on `PATH`. The Maven wrapper (`./mvnw`) pins Maven, so no
system Maven install is needed.

```bash
# Compile + tests
./mvnw test

# Shaded fat jar (run via java -jar)
./mvnw -DskipTests package
java -jar cli/target/thoryn.jar login --status

# GraalVM native image (SSO-733; per-OS/arch matrix on CI).
# Requires GRAALVM_HOME (or JAVA_HOME) to point at a GraalVM distribution
# with `native-image` installed.
./mvnw -Pnative -DskipTests package
./cli/target/thoryn workspace list --issuer https://auth.stg.thoryn.org
```

## Module layout

```
thoryn-cli/
├── pom.xml                                                  # reactor parent (SSO-3662): shared versions + plugin config
├── README.md                                                # this file
├── adrs/                                                    # decisions about this repository
├── examples/kubernetes/                                     # SSO-3684 the Thoryn init-container manifest (a pod pulls its own client secret)
├── engine/                                                  # io.thoryn:thoryn-provision-engine — the provisioning engine as a LIBRARY (SSO-3662)
│   ├── pom.xml
│   └── src/main/kotlin/com/devnow/thoryn/provision/
│       ├── ProvisionEngine.kt                               # plan / apply / destroy / import, the ownership gate + deletion authority (no receipt — SSO-3715), SecretSink
│       ├── ProvisionFile.kt + provision.schema.json         # the .thoryn/provision.yaml model
│       ├── FixRequest.kt + fix-request.schema.json          # SSO-3710 the fix request (missing rights + their commands) and its ONE renderer
│       ├── ProvisionApi.kt                                  # the product-api PORT the engine converges through
│       ├── AccessRefs.kt, CustomDomain.kt, ProductApiException.kt
│       └── (no picocli, no TTY, no CLI type — pinned by ProvisionEngineLibraryBoundaryArchTest)
└── cli/                                                     # io.thoryn:thoryn-cli — the picocli front end (shaded jar + native image)
    ├── pom.xml
    └── src/
    ├── main/kotlin/com/devnow/thoryn/cli/
    │   ├── ThorynMain.kt                                    # picocli root
    │   ├── auth/
    │   │   ├── DeviceCodeFlow.kt                            # RFC 8628
    │   │   ├── ClientCredentialsFlow.kt                     # SSO-1553 RFC 6749 §4.4 (non-interactive)
    │   │   ├── LoopbackRedirectServer.kt                    # RFC 8252 §7.3
    │   │   ├── PkceUtil.kt                                  # RFC 7636
    │   │   ├── TokenStore.kt + KeychainTokenStore.kt        # ADR 2026-04-25 §4
    │   │   ├── DpopKey.kt + DpopKeyStore.kt                 # SSO-3199 RFC 9449 installation key (ES256)
    │   │   ├── DpopSession.kt                               # SSO-3199 proof JWTs + DPoP-Nonce retry
    │   │   ├── DpopCapability.kt                            # SSO-3221 send proofs only where discovery advertises DPoP
    │   │   ├── Tokens.kt
    │   │   ├── WorkloadIdentityFlow.kt + WorkloadIdentityDiagnostics.kt  # SSO-3308 secret-less sign-in; SSO-3684 file token source (Kubernetes)
    │   │   └── ScopeRegistry.kt                             # SSO-959 scope wildcards
    │   ├── api/
    │   │   ├── ProductApiClient.kt                          # SSO-959 typed HTTP client
    │   │   └── OperatorHubClient.kt                         # SSO-3356 hub /admin operator surface (port-forward)
    │   ├── cmd/
    │   │   ├── LoginCommand.kt + LogoutCommand.kt
    │   │   ├── CommandSupport.kt                            # SSO-1552 shared token/output/error helpers
    │   │   ├── SecretIo.kt + FileSecrets.kt                 # SSO-1552 secret-safety (no-echo / --secret-file)
    │   │   ├── AccessCommand.kt                             # SSO-3113 `access grant|revoke|list|mine` (least-privilege grants)
    │   │   ├── ClientsCommand.kt                            # SSO-1552 clients CRUD + rotate-secret; SSO-3957 secret-state + a legible 409
    │   │   ├── FederationCommand.kt                         # SSO-1552 federation list/create/delete
    │   │   ├── WorkspaceCommand.kt                          # SSO-1552 workspace create/list/switch
    │   │   ├── TenantCommand.kt                             # SSO-1553 tenant seed (non-interactive provisioner)
    │   │   ├── SelectedWorkspaceStore.kt                    # SSO-1552 records the switched-into workspace
    │   │   ├── AuditCommand.kt                              # SSO-1552 audit query (config + auth events)
    │   │   ├── AuditReplayCommand.kt                        # SSO-940b
    │   │   ├── WorkloadIdentityCommand.kt                   # SSO-3308 `workload-identity trusts` (github_actions); SSO-3684 --provider kubernetes; SSO-3702 --plan-environment / set-plan-profile
    │   │   ├── connection/Connection.kt                     # SSO-2948 the connection contract (+ examples/connection.schema.json)
    │   │   ├── provision/FixRequests.kt                     # SSO-3710 --fix-request: runner context, trust resolution, the write
    │   │   └── operator/                                    # SSO-3356 `operator login|logout|custom-domain` (operator plane)
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
  changes needed. **A command's constructor must not open the token store (or
  any OS resource)** — the generator instantiates every command, and on a Linux
  build host without a keychain an eager store threw there, the generator wrote
  no config at all, and the shipped Linux binary could run no subcommand (SSO-3687;
  `by lazy` is the fix, `NativeReflectionConfigWithoutKeychainTest` the guard).
* Linux binaries link zlib statically (`-H:+StaticExecutableWithDynamicLibC`, profile
  `native-static-nolibc-linux`): glibc is their only shared dependency, which is what lets the
  container image run them on distroless/cc (SSO-3687). The build needs `libz.a` (`zlib1g-dev`).
* `java-keyring` + `JNA` reflection lives in
  `cli/src/main/resources/META-INF/native-image/com.devnow.thoryn.cli/` (the engine library's own
  entries live in `engine/src/main/resources/META-INF/native-image/io.thoryn/thoryn-provision-engine/`).
* All subcommands use only `java.net.http.HttpClient` + Jackson 3 + picocli,
  all of which are already native-image-ready.
* DPoP (SSO-3199) adds no dependency: the proof is signed with the JDK's own
  `KeyPairGenerator("EC")` / `Signature("SHA256withECDSA")`. Key *generation* is
  the one new JCA surface (verification via `SHA256withECDSA` already shipped in
  `Es256JwsVerifier`); `StoredDpopKey` is registered in `reflect-config.json`
  alongside `Tokens` so the keychain payload (de)serialises in the native image.

## Related

* `docs/modules/ROOT/pages/cli/index.adoc` — top-level user docs
* `docs/modules/ROOT/pages/cli/tenant-configuration.adoc` — SSO-1552 clients/federation/workspace/audit
* `docs/modules/ROOT/pages/cli/non-interactive-automation.adoc` — SSO-1553 client-credentials + tenant seed
* ADR `adrs/2026-04-25-customer-plane-product-api.md`
