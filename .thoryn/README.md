# `.thoryn/` — this repo's as-code binding to Thoryn (SSO-2951 + SSO-3090)

One folder, two halves, both **data** (schema-validated by the CLI), both committed. This repo is
the **reference consumer** of the very verbs it ships: a customer binds a repository to Thoryn with
the same two files and the same commands.

| File | Declares | Schema | Verb |
|---|---|---|---|
| `connection.json` | **who I am** — the `thoryn` workspace and the **workload identity trust** CI signs in under: the trust's `wi_…` client id, its audience, its GitHub pins and the exact scope set. No secret, no env var naming one (SSO-3690) | `cli/src/main/resources/examples/connection.schema.json` (SSO-2948) | `thoryn login --connection .thoryn/connection.json` |
| `provision.yaml` | **what I own** — the desired state: the CLI's own login client `cli` in the `thoryn` workspace (SSO-3104; this repository's CI identity is its platform `owner`, SSO-3697), plus a sandbox environment `cli-ci` — whose one grant makes the CI identity its `manager` — with a public loopback OAuth client inside it | `engine/src/main/resources/provision/provision.schema.json` (SSO-3088) | `thoryn provision plan / apply / destroy --file .thoryn/provision.yaml` |
| `trusts.provision.yaml` | **the one trust, declared** (SSO-3689 `kind: workloadIdentityTrust`; SSO-3697 / SSO-3705 / SSO-3704) — `thoryn-cli-ci`, adopted, production plane, with its two profiles: the reviewed apply environment and the **plan profile** `spec.plan` keyed on `thoryn-provision-e2e-plan` (read-only by construction). Applied by a **founder**, never by CI: a production-plane trust is reached through the workspace, and a file cannot declare its own bootstrap trust | the provision schema | `thoryn provision plan / apply --file .thoryn/trusts.provision.yaml` (founder session) |
| `provision.receipt.json` | the **ownership ledger** of `provision.yaml` — committed since SSO-3697, when the App's apply job opened it as a receipt pull request; since SSO-3717 / SSO-3719 the apply job opens none and since SSO-3715 (#132) the engine writes no receipt at all (the platform is the ledger, oauthy ADR 2026-10-15) — the committed copy is a leftover to delete | written by the engine | — |
| _(run artifact, never committed)_ `thoryn-provision-request` | the **fix request** (SSO-3710): when a job is red on a missing RIGHT — the trust's plan profile, `owner` on a declared resource, `manager` on a parent environment — the CLI writes `thoryn-provision-request.json` naming each right and the exact command a workspace admin runs; the workflows upload it `if: failure()` and the Thoryn GitHub App relays it onto the check run (two options: the commands, or a web consent — oauthy SSO-3711/3712) | `engine/src/main/resources/provision/fix-request.schema.json` | `thoryn login --connection --fix-request <path>` · `thoryn provision plan\|apply --fix-request <path>` (env `THORYN_FIX_REQUEST`) |
| `workflow.yaml` | **how the App-dispatched workflow runs** (SSO-3719): the run-time configuration the reusable workflow `thoryn-io/thoryn-cli/.github/workflows/provisioning.yml` reads — which provisioning files with which connections (one or many), `THORYN_*` env vars for the CLI, whether to upload the fix request, the apply toggles (`prune` / `destroy`, never on by default). This repository's copy states the defaults. Unknown keys are refused: a knob that is not there is a product gap, not a script | `cli/src/main/resources/examples/workflow.schema.json` | `thoryn provision workflow check` |

The provisioning Action (`.github/actions/provision`) runs, in order:

```bash
thoryn login --connection .thoryn/connection.json      # who I am — exchanges the job's own OIDC token, no secret
thoryn provision plan   --file .thoryn/provision.yaml  # what would change (read-only)
thoryn provision apply  --file .thoryn/provision.yaml --yes   # converge — twice = no writes
# … the job uses the outputs (environment, client-id, issuer) …
thoryn provision destroy --file .thoryn/provision.yaml --yes  # child-first; sandbox hard-delete cascades
```

The receipt (`provision.receipt.json`, written next to the file — **committed** since SSO-3697, see
"Provisioning from code"; every other `*.receipt.json` under `.thoryn/` stays git-ignored) is the ownership
ledger: `destroy` removes only what it records, and a resource that already existed when `apply`
ran is **adopted** (converged, never deleted). No secret ever lives in either file — and since
SSO-3690 none lives in the repository's GitHub settings either: `connection.json` is a
`workload_identity` contract, so there is no env var to name (a file that needed one would use
`passwordEnv` / `{{env.NAME}}` in `provision.yaml`, or `auth.secretEnv` in a `client_credentials`
connection).

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

Every later `apply` — CI signs in as the trust's client — **adopts** it by its fixed id and converges
its non-secret shape; adopted resources are never removed by `destroy`, so CI cannot delete the client
it depends on. Rotating it is editing this file.

> **This repository OWNS the login client's provisioning (product owner, 2026-10-14; SSO-3697).** The engine
> gates every resource on the signed-in identity's own platform reach (`POST /api/v1/access/check`,
> SSO-3659 / SSO-3673). The CI identity `client:wi_10a7b379c79f7d1353f5798d` (the `thoryn-cli-ci` trust) holds
> the platform **`owner`** relation on `application:cli` — owner ⇒ manager (oauthy ADR
> `2026-10-13-platform-owner-relation-and-forward-check`) — so `thoryn-provisioning.yml` converges the login
> client from `main` like every other declared resource, and **a change to the login client is a reviewed pull
> request to `provision.yaml`, not a founder command**. `owner` is a one-time admin grant from a founder's own
> session (below); it is deliberately *not* in the file's `grants:` block — the engine refuses
> `relation: owner` there (SSO-3673), a repository cannot claim ownership by writing YAML. This supersedes
> SSO-3690's interim `readOnly: true` + founder-granted `viewer` (revoked as redundant once `owner` is set).

## The CI identity is a workload identity trust (SSO-3690, parent SSO-3659; epic SSO-3108 for the confinement)

CI signs in as the **`wi_…` client of the `thoryn-cli-ci` trust**: a GitHub Actions workload identity trust
on the `thoryn` workspace's production plane (oauthy ADR 2026-09-22, SSO-3307/3308). The e2e job requests its
own OIDC token for the trust's audience and the CLI exchanges it (`thoryn login --connection`, a
`workload_identity` contract) for a short-lived token carrying the trust's scopes. **There is no secret**:
nothing minted, nothing pasted into a GitHub secret, nothing to rotate or leak. This is the credential
ladder of oauthy ADR `2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull.md` applied to
the repository that ships the ladder's tooling — rung 4, "courier: never", retired here.

It replaced **`cli-ci`** (SSO-3113), a confidential `client_credentials` client whose secret a founder minted
once with `apply --secret-file` and carried into the repository secret `THORYN_CLI_CI_CLIENT_SECRET` — a
courier with one hop. `cli-ci` in turn had replaced `app-63a0f52f-3d6`, a workspace-wide machine client minted
by the retired `thoryn provision ci-identity`, whose eight scopes reached every environment of the workspace.

What confines the trust's client (unchanged in shape from `cli-ci`):

- **Six scopes** — `tenant:environments.{read,write}` + `tenant:applications.{read,write}` (the kinds
  `provision.yaml` declares) + `tenant:access.{read,write}` (the `grants:` block: read to plan the diff, write
  to converge it; SSO-3659 — `read` is needed by every `plan`/`apply` regardless, because ownership is decided
  by the identity's own reach, `POST /api/v1/access/check`, before any write). **No** `tenant:users.*`,
  **no** `tenant:federation.*` — the file declares no `user` and no `federationMember`, so the identity gets
  no reach over either. The trust is created from exactly this list, so `connection.json`'s `auth.scopes`
  (the only committed statement of what the identity holds) must EQUAL the least-privilege set converging
  `provision.yaml` needs — `CiProvisionFileConformanceTest` and `CiConnectionConfinementTest` both assert it.
- **One declared grant** — `client:<wi_…> manager` on the `ci` **environment**, in the one `grants:` block of
  `provision.yaml` — the same identity plans and applies (SSO-3705). The loopback client inside the sandbox is covered
  by containment. `CiProvisionFileConformanceTest` pins that grant and that its subject is the very client
  `connection.json` signs in with (both pasted from one `trusts create`). Plus the one-time **`owner`** on
  `application:cli` (a platform relation, granted by a founder — never declarable here).
- **The trust's own pins** (oauthy hub `GithubActionsTrustPolicy`; mirrored in `connection.json`'s
  `auth.github` so the CLI can name the field that differs on a refused sign-in): the repository by its
  **immutable ids** (`ownerId 229451779`, `repositoryId 1361536515` — a rename or transfer does not carry
  them), the GitHub **environment `thoryn-provision-e2e`** the e2e job declares (a production-plane trust must
  pin one — D8; since SSO-3704 the trust also carries a **plan profile** keyed on `thoryn-provision-e2e-plan`,
  read-only — the same `wi_` client, minted fewer scopes there), **`ref: refs/heads/main`** (only a dispatch on
  `main` can sign in; a pull request never can), and **GitHub-hosted runners only**. `CiConnectionConfinementTest`
  holds the contract and the e2e workflow to these pins; `CiTrustsFileConformanceTest` holds the declared trust
  and its plan profile to them.
- **Scopes are the ceiling, the grant is the gate.** A scope says which API it may call; the grant says
  which object it may touch. `DELETE /api/v1/environments/<some other sandbox>` answers `404` however
  many scopes the token carries (ADR `2026-09-15-platform-resource-authorization-on-fga.md` §8).

The trust is a real product resource, created once through the product — never seeded. It is **declared
in `.thoryn/trusts.provision.yaml`** (SSO-3689's `kind: workloadIdentityTrust`, adopted by name) — a file a
**founder** applies, not `provision.yaml`, for two structural reasons the engine enforces: a production-plane
trust is reached through the **workspace** (`ProvisionEngine.gateTrust` — converging or adopting it needs
`manager` on the workspace, which the confined CI identity must never hold), and a file cannot declare the
trust its own identity signs in with (`workload_identity_trust_is_self`). In `provision.yaml` the trust is
only *referenced* — by the grant subject and by `connection.json`.

### A founder creates the trust once

The one bootstrap a person must do (the bootstrap limit of the ladder: a trust can only be created by someone
who already holds the scopes it will carry). Everything else is committed.

```bash
# 0) A thoryn workspace admin, on the PRODUCTION plane (the default `thoryn login` scope set already covers
#    the six scopes below — the hub only lets you grant what you hold). A selected sandbox would put the
#    trust on the wrong plane: make sure none is selected.
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org
thoryn env use production

# 1) Create the trust — production plane (no --environment), so it needs --confirm-production and a
#    GitHub environment pin; exactly the six scopes connection.json requests; the repository's immutable ids.
thoryn workload-identity trusts create --name thoryn-cli-ci \
  --repository thoryn-io/thoryn-cli --owner-id 229451779 --repository-id 1361536515 \
  --github-environment thoryn-provision-e2e --ref refs/heads/main --github-hosted-runners-only \
  --scope "tenant:environments.read tenant:environments.write tenant:applications.read tenant:applications.write tenant:access.read tenant:access.write" \
  --confirm-production
```

It prints the trust's `clientId` (`wi_…`), `audience` and a connection snippet. Then:

```bash
# 2) Paste the clientId into the TWO committed places (CiProvisionFileConformanceTest pins them equal) and
#    open a pull request with the change:
#      .thoryn/connection.json  →  auth.clientId
#      .thoryn/provision.yaml   →  resources[environment/ci].grants[0].subject  ("client:<wi_…>")
#    Confirm the printed audience is https://thoryn.auth.stg.thoryn.org (connection.json's auth.audience —
#    the thoryn workspace's issuer, no /{env} path; it only changes if the workspace moves to a custom domain).

# 3) Converge the sandbox's grant AND remove the retired cli-ci client — one reviewed apply, from the
#    founder's session, after the pull request is merged. --prune deletes exactly the owned resources the
#    file no longer declares: the one `application/ci` entry of your receipt (production plane → --confirm).
thoryn provision plan  --file .thoryn/provision.yaml --prune       # expect: "- application ci (cli-ci)" and
                                                                   #         "environment ci: grant + client:wi_… manager"
thoryn provision apply --file .thoryn/provision.yaml --prune --confirm thoryn --yes
#    Receipt effect: .thoryn/provision.receipt.json (git-ignored, local to you) drops its `application/ci`
#    entry; the `client:cli-ci manager` grant it recorded on the sandbox is revoked by the same apply.
#    No receipt owning cli-ci on this machine? Then --prune has nothing to remove: delete it directly,
#      thoryn clients delete cli-ci --confirm thoryn
#    NEVER `thoryn provision destroy` for this — it would also remove the sandbox and everything else the
#    receipt owns.

# 4) Delete the repository secret the retired client needed. Nothing replaces it.
gh secret delete THORYN_CLI_CI_CLIENT_SECRET -R thoryn-io/thoryn-cli

# 5) Validate: dispatch provision-e2e on main (the ref pin). It must sign in with zero secrets in the
#    repository, converge, assert confinement and destroy. The workspace audit log shows the wi_ client as the
#    actor (`thoryn audit list`). The GitHub environment `thoryn-provision-e2e` is created by that first run
#    if it does not exist yet; it holds no secret and no variable. (The plan profile's environment,
#    `thoryn-provision-e2e-plan`, is created by hand — see "Provisioning from code", step (c).)
```

To stop CI signing in at all: `thoryn workload-identity trusts delete <id> --confirm thoryn` — the client
stops authenticating at once; no secret to revoke, nothing to rotate.

## Provisioning from code — the App runs plan on pull requests and apply on `main` (SSO-3697, SSO-3704)

The repository provisions **itself** from code, the loop proven on thoryn-cicd (oauthy converge ADR
`2026-10-13-provisioning-as-code-converge-github-app-and-fga-ownership.md` §3 + Amendment 5), with **one identity**
for plan and apply (SSO-3699 option B, product owner 2026-10-14 — oauthy ADR
`2026-10-14-plan-identity-and-resource-ownership.md`). The manual `provision-e2e` dispatch stays as the manual path
(apply, confinement assertions, destroy).

**The workflow is a stub (SSO-3719).** `.github/workflows/thoryn-provisioning.yml` is ~25 lines: the App's four
`workflow_dispatch` inputs, the `run-name` carrying the check-run id, `permissions: {}`, the `# thoryn-provisioning:
apply-job` marker, and ONE job that `uses:` the **reusable workflow this repository ships** —
`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0` — with the two environments
(`thoryn-provision-e2e-plan`, `thoryn-provision-e2e`) and the staging issuer as `with:` inputs. What the jobs do at run time
is `.thoryn/workflow.yaml` (this repository's copy spells out the defaults). Both are linted by `thoryn provision workflow
check`, which the reusable workflow itself runs first in every job. The pin selects the CLI too: the called job reads
`job.workflow_ref` and downloads the `thoryn.jar` of that release, so there is no second version to keep in step. **To
change how this repository provisions, edit the stub's `with:` or `workflow.yaml` — never the jobs**; a knob that is
missing is a product gap (README "Configure the provisioning workflow"). The same stub is what a customer repository
keeps; the full contract between the App and the reusable workflow is `docs/provisioning-workflow-contract.md`.

**The developer story.**

1. You open a pull request that changes anything under `.thoryn/`. The Thoryn GitHub App opens a **"Thoryn
   provisioning plan"** check run and dispatches `.github/workflows/thoryn-provisioning.yml` with `mode=plan`
   (the PR head as `head_sha`; the run-name carries `check-run:<id>`). The stub calls the reusable workflow, whose
   `plan` job — in THIS repository's run, under this repository's environments — runs in the unprotected
   GitHub environment **`thoryn-provision-e2e-plan`** and signs in with the **same `connection.json`** as the
   apply — the one trust `thoryn-cli-ci`. What makes that sign-in read-only is the trust's **plan profile** on
   the hub (SSO-3700/SSO-3701; declared as `spec.plan` in `trusts.provision.yaml`, SSO-3704): the hub reads the
   `environment` claim of the job's own OIDC token and, for the `-plan` environment, mints `tenant:environments.read
   tenant:applications.read tenant:access.read` only — the `.read` members of the trust's scopes, derived. The CLI
   (`thoryn login --connection`, cli-v0.34.0 / SSO-3702) requests no scope outside the apply environment, so a plan
   job never asks for a write; the sign-in line reads `Profile: plan (read-only)`. It plans `provision.yaml` into
   the job summary — the owner of `application:cli` planning its own resource, so the `application/cli` row is
   green like the sandbox and loopback rows. The check is red when the file declares a resource this repository
   does not own, or when a dry run would fail — before merge.
2. The PR is reviewed and merged. The App opens **"Thoryn provisioning apply"** and dispatches `mode=apply`.
   The `apply` job (`# thoryn-provisioning: apply-job`) runs in the **reviewed** environment
   **`thoryn-provision-e2e`**: GitHub holds it for a required reviewer *before* any token can be minted. It
   signs in as `thoryn-cli-ci` with the `thoryn.jar` of the release the stub pins (`cli-v0.36.0`; `--prune` and
   `destroy` only if `.thoryn/workflow.yaml` says so — it does not), is minted the trust's six write-capable scopes,
   converges the file, and ends at **Applied**. Nothing is written back and no receipt pull request is opened
   (SSO-3717; oauthy ADR 2026-10-15 — the platform is the ledger): the job holds `contents: read` only.
3. A dispatched run executes on `main` in **both** modes (the OIDC `ref` is `refs/heads/main` either way), so
   the GitHub **environment is the only pin** separating "may read" from "may write" — and it separates two
   *profiles of one trust*, not two trusts: the plan profile can carry only `.read` scopes
   (`plan_scope_not_read_only`), whatever the workflow or the YAML says; the write scopes are minted only to a job
   in the reviewed environment; a job in neither environment is refused at the exchange. One trust, one `wi_`
   client, one connection file, one grant subject, one FGA subject in every audit row — nothing to paste twice.

**A red check names its fix (SSO-3710; oauthy ADR 2026-10-15-missing-rights-fix-path-cli-and-web-consent).** When
either job fails on a missing right, the CLI writes the **fix request** (`thoryn-provision-request.json`, asked for
through `THORYN_FIX_REQUEST` on the plan step and on the Action's sign-in / apply steps) and the workflow uploads it as
the run artifact `thoryn-provision-request`. Steps (a) and (b) below ARE its contents for this repository: a
`plan_profile` item with the `set-plan-profile` command when the plan job's exchange is refused for its environment,
an `owner` item with the `thoryn access grant … owner application:cli` command when the file declares a resource the
identity does not own. The App (SSO-3711) puts them on the check run as **Option 1 — CLI** (the commands, verbatim)
next to **Option 2 — Web consent** (SSO-3712: a workspace admin signs in and approves exactly what the repository
asks for; the App re-dispatches the plan on the same check run). Until the workflow pin moves to a release that
carries `--fix-request`, the variable is ignored and the upload step finds no file — the steps below are then the
founder's path, as before.

**Operator sequence, in order** (a founder: workspace `thoryn`, production plane, own session). Nothing here is
created by this repository's PR — these are the one-time actions the PR documents. Steps (a) and (b) are
idempotent: a step already done answers "nothing to do" (a `NOOP`/adopt plan, a 409 on the owner grant).

```bash
# (a) Give the ONE trust its plan profile — declaratively, from the committed file. The live trust has no profile
#     yet; the engine converges a declared `plan:` on such a trust through the single ADDITIVE set-plan-profile call
#     (SSO-3702): the wi_ client, its owner relation, its grant and connection.json all stay. Nothing to re-paste.
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org
thoryn env use production
thoryn provision plan  --file .thoryn/trusts.provision.yaml
#     expect ONE change, no error:
#       ~ workloadIdentityTrust thoryn-cli-ci: adds the plan profile (GitHub environment 'thoryn-provision-e2e-plan',
#         read-only scopes) through the one additive set-plan-profile call; the wi_ workload client wi_10a7… stays
#       workloadIdentityTrust thoryn-cli-ci: plan.environment: … → thoryn-provision-e2e-plan
thoryn provision apply --file .thoryn/trusts.provision.yaml --yes
#     prints "plan profile added — GitHub environment 'thoryn-provision-e2e-plan' is minted read-only scopes
#     tenant:environments.read tenant:applications.read tenant:access.read; wi_ client wi_10a7… unchanged".
#     Verify: `thoryn workload-identity trusts list` shows the pin `plan=thoryn-provision-e2e-plan` on thoryn-cli-ci.
#     A second plan of the file is a NOOP/adopt — the profile is converged, not re-set.
#     FALLBACK (imperative — the same additive API call, if you prefer not to apply the file):
#       thoryn workload-identity trusts set-plan-profile d3ec5a8f-fdc5-4e20-acd3-bad167308fca \
#         --plan-environment thoryn-provision-e2e-plan
#     (plan scopes DERIVED — the three .read members; `--plan-scope …` pins them explicitly. Set once: a trust that
#     already carries a profile answers 409 plan_profile_already_set.)

# (b) Ownership of the login client — the CI identity becomes the platform OWNER of application:cli (owner ⇒ manager);
#     then drop the SSO-3690 viewer grant it made redundant. SKIP if a founder already did this for SSO-3697: a
#     DIFFERENT current owner answers 409 owner_already_set (DELETE the current owner first, then POST); a `member:`
#     subject is 400 invalid_owner_subject; the same subject again is idempotent.
thoryn access grant  client:wi_10a7b379c79f7d1353f5798d owner  application:cli
thoryn access revoke client:wi_10a7b379c79f7d1353f5798d viewer application:cli

# (c) GitHub environments — thoryn-io/thoryn-cli → Settings → Environments:
#       * create `thoryn-provision-e2e-plan` with NO protection (a plan must run on every pull request; the trust's
#         plan profile is keyed on this exact name);
#       * on `thoryn-provision-e2e` add REQUIRED REVIEWERS (1–6). Do this BEFORE step (d): the reviewer gate is
#         GitHub's, not the App's — unprotected, the apply job starts at once (Amendment 5).

# (d) GitHub App — add thoryn-io/thoryn-cli to the *Thoryn Starters (staging)* installation (today it covers
#     thoryn-cicd only): GitHub → Settings → Applications → Thoryn Starters (staging) → Repository access.
#     The App sees .thoryn/ pull requests and pushes only once installed.

# (e) Verification — run it, do not reason it:
#       1. open a pull request touching .thoryn/ (a comment line will do): the App's "Thoryn provisioning plan" check
#          goes GREEN, its summary shows the plan job signed in with `Profile: plan (read-only)` and the three rows
#          `application/cli`, `environment/ci`, `application/loopback-rp` without an error — the `application/cli`
#          row included (the owner is the one planning it);
#       2. merge it: the App dispatches `mode=apply`, GitHub HOLDS the run in `thoryn-provision-e2e` for a required
#          reviewer; approve it — the job signs in with the write scopes, converges, and its summary ends at
#          "Applied" (no receipt pull request — the platform is the ledger, SSO-3717);
#       3. `thoryn audit list` shows wi_10a7… as the actor of both runs, the exchange rows naming
#          `profile=plan environment=thoryn-provision-e2e-plan` and `profile=apply environment=thoryn-provision-e2e`.
#     provision-e2e (the manual path) needs none of (a)–(d): dispatch it on main — expected green.
```

**What the first runs proved.** provision-e2e run 38547022158 signed in secretless as `wi_10a7b379c79f7d1353f5798d`
with the hub's SSO-3698 fix deployed (GitHub's *immutable subject*,
`sub` = `repo:thoryn-io@229451779/thoryn-cli@1361536515:environment:…`, is accepted), planned three adopts
(`environment/ci`, `application/cli`, `application/loopback-rp`) and then stopped on a placeholder grant subject
(`404 not_found — No such access-grant target`) that SSO-3705 removed; nothing else in the run was wrong. The App's
plan check has not run on this repository yet — step (e) is its first run.

> The receipt is committed (`.gitignore` un-ignores `.thoryn/provision.receipt.json`) because the App's receipt
> step is `git add -- ':(glob).thoryn/**/*.receipt.json'` — an ignored path would fail it. One consequence of
> two paths sharing one file: `provision-e2e`'s `destroy` removes what its checkout's receipt owns — the
> loopback client the App's apply created (the sandbox and `cli` are adopted, never removed); the next App
> apply re-creates it and the receipt PR records the new id. Expected churn, not a defect.

## Why the scopes are what they are

`auth.scopes` is the **machine set** — the six least-privilege scopes the `thoryn-cli-ci` trust carries. The
hub grants a workload identity token **only** the scopes requested, and the trust can carry no more than it
was created with, so this list is both the ceiling and the floor. It must **cover every resource kind
`provision.yaml` declares** (`environment` → `tenant:environments.write`, `application` →
`tenant:applications.write`) and it must **equal** the least-privilege set converging that file needs —
`CiProvisionFileConformanceTest` and `CiConnectionConfinementTest` assert both (SSO-3090, SSO-3690). The same
test pins the `cli` login client's scope list to **exactly** the tenant scopes the CLI's sources reference —
which is why `tenant:access.read` / `tenant:access.write` (SSO-3113) appear on it.

## Confinement

The credential is confined four ways, all server-side: the client's `tnt` claim locks it to the
`thoryn` workspace (cross-tenant → 404); the hub mints only the requested scopes, bounded by the trust's;
the provisioning file's `kind` allowlist bounds what `apply` can express; and — the one epic SSO-3108 adds —
the identity is `manager` of the `ci` sandbox only, so product-api refuses anything it does not manage
(404, never 403). On top of that the trust itself is confined to one repository, one ref, GitHub-hosted runners
and two GitHub environments — the reviewed one for the write scopes, the `-plan` one for the read-only plan profile
(oauthy ADR 2026-09-22 D2/D8; 2026-10-14 plan-identity ADR). Everything CI creates is **environment-scoped**
(inside the `cli-ci` sandbox), so `destroy` needs no production-plane confirmation — the production-plane
resource, the `cli` login client, is adopted by CI, never owned or removed. There is no secret to rotate; to
cut CI off, delete the trust. To isolate CI blast radius entirely, bind the contract to a dedicated
`thoryn-cli-ci` workspace instead — change `workspace.slug`, create the trust there and re-paste.

> A leaked `cli-ci` sandbox (a run that failed before `destroy`) is adopted — not duplicated — by the
> next `apply`, and adopted resources are never auto-deleted: remove it by hand with
> `thoryn env delete <id> --confirm cli-ci` if it should go.

## Workload identity — the staging sign-in check with no secret (SSO-3308)

`ci.yml`'s `workload identity sign-in (staging)` job signs in to shared staging **without any secret**:
it exchanges the job's own GitHub Actions OIDC token under a workload identity trust (`thoryn login
--workload-identity`) and runs a harmless read (`thoryn env list`), then signs in a second time to prove a
fresh job token is requested for every exchange. The trust is a real product resource, created once
through the product — never seeded — and the job skips with a notice until it exists.

This is a **second, separate trust** from `thoryn-cli-ci` above, and deliberately so: it lives in its own
sandbox (`cli-wif`) on the sandbox plane, carries only `tenant:environments.read`, and pins a GitHub
environment (`thoryn-staging-wif`) that a pull request may run in — exactly what the e2e's trust must NOT
be (production plane, write scopes, `main` only). Neither can be reused or widened into the other without
giving one job the reach of the other.

One-time setup (a `thoryn` workspace admin, once oathy #3787 / hub V192 is deployed to staging and a CLI
carrying SSO-3308 is installed):

```bash
thoryn login --workspace thoryn --issuer https://auth.stg.thoryn.org
thoryn env create cli-wif --name "thoryn-cli workload identity check"   # a sandbox only this check uses
thoryn workload-identity trusts create --environment cli-wif --name thoryn-cli-staging-check \
  --repository thoryn-io/thoryn-cli --github-environment thoryn-staging-wif \
  --github-hosted-runners-only --scope tenant:environments.read
# then store the printed clientId and audience as repository VARIABLES (public identifiers, not secrets):
gh variable set THORYN_WIF_CLIENT_ID -R thoryn-io/thoryn-cli --body '<clientId from the output>'
gh variable set THORYN_WIF_AUDIENCE  -R thoryn-io/thoryn-cli --body '<audience from the output>'
```

- The trust lives in its own sandbox (`cli-wif`), not in `cli-ci`: the provisioning run may hard-delete
  `cli-ci`, and a deleted environment takes its trusts with it.
- It pins the GitHub environment `thoryn-staging-wif`, which the job declares, so a pull request and a
  push to `main` present the same `sub`. It carries only `tenant:environments.read`.
- To stop the check, delete the trust (`thoryn workload-identity trusts delete <id> --environment cli-wif`)
  or unset either variable.
