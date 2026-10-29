# The provisioning workflow contract — v2 (SSO-3719, epic SSO-3304; v2: SSO-3991)

**Audience: Thoryn engineers.** This is the INTERNAL contract between the Thoryn GitHub App (oauthy
`starter-orchestrator`, converge ADR 2026-10-13 Amendments 1, 5–7) and the reusable workflow
`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml`. It is **not a customer authoring surface**: a customer
configures the workflow (README "Configure the provisioning workflow"), never writes one. The contract is pinned in code
by `cli/src/main/kotlin/com/devnow/thoryn/cli/cmd/provision/workflow/ProvisioningWorkflowContract.kt`, enforced by
`WorkflowCheck` (the engine behind `thoryn provision workflow check` and the dogfood conformance tests), and bumped
(`contractVersion`) when a rule changes what a valid stub or reusable workflow looks like.

## Why a workflow file exists at all

The job's own GitHub **OIDC token is the repository's identity** (exchanged by `thoryn login --connection` under the
workspace's workload identity trust), and the job's GitHub **environment is the review gate** the hub pins (a production
trust is pinned to a reviewed environment; the plan profile is keyed on an unprotected one — Amendments 5/6). Neither can
move into the App, which never holds a Thoryn credential. Everything else moved out of the customer's repository into
the reusable workflow. What a repository keeps is a **stub**.

## 1. What the App dispatches (`dispatch.*`)

The App dispatches the file at **`.github/workflows/thoryn-provisioning.yml`** (`ThorynFiles.WORKFLOW_PATH`) on the
default branch, in every mode, by `workflow_dispatch`:

| Input | Required | Type | Value |
|---|---|---|---|
| `mode` | yes | `choice` `[plan, apply]` (v1) or `[plan, apply, import]` (v2) | `plan` on a pull request touching `.thoryn/**`; `apply` on a push to the default branch; `import` after a config project's setup pull request is merged (v2, §7) |
| `head_sha` | yes | `string` | the commit to plan or apply (the PR head, or the pushed sha); for `import`, the setup pull request's merge commit |
| `check_run_id` | yes | `string` | the App's check run (*Thoryn provisioning plan* / *apply* / *Thoryn configuration import*) |
| `pr_number` | no (`default: ""`) | `string` | the pull request: plan; for `import`, the setup pull request |

and requires of the dispatched workflow:

- `run-name` contains **`check-run:${{ inputs.check_run_id }}`** — how the App finds the run (`workflow_run.completed`)
  to complete its check run;
- the line **`# thoryn-provisioning: apply-job`** (`ThorynFiles.APPLY_JOB_MARKER`) is present iff the workflow applies —
  the App dispatches `apply` only when it sees it. In a stub the marker sits above the `uses:` job; the reusable workflow
  carries it on its own apply job;
- top-level **`permissions: {}`**; the job(s) declare their own;
- **`dispatch.import-capable`** (v2) — the App dispatches `import` only to a file this rule passes **and** whose `mode`
  options include `import` (`--output json`: `importCapable: true`). A stub that does not offer `import` passes (it is
  never sent one). A stub that offers it must call the reusable workflow at **`cli-v0.51.0`**
  (`ProvisioningWorkflowContract.IMPORT_MINIMUM_RELEASE`) or newer, and must not set `cli-version` older than that —
  otherwise the rule FAILS: an older reusable workflow has no job gated on `import`, so the dispatch would run zero jobs
  and report green with nothing imported. A commit-SHA or branch pin cannot be dated and is UNVERIFIABLE. A hand-written
  workflow that offers `import` needs a job gated on it, in the plan job's environment, uploading `thoryn-import`;
- **`concurrency.group`** contains `${{ inputs.mode }}` and `cancel-in-progress: false` — a plan never waits on an
  apply, two applies never race, a held apply is never cancelled. The stub's top-level concurrency covers the called jobs
  (they are part of the caller's run), so the reusable workflow declares none;
- **no `secrets`** anywhere, and **no `${{ … }}` inside a `run:` block** (oauthy SSO-3635: a value interpolated into
  `run:` lands in the shell's source — every value reaches a script through `env:`).

## 2. The stub (`stub.*`) — the supported shape

```yaml
name: Thoryn provisioning
run-name: "Thoryn provisioning ${{ inputs.mode }} ${{ inputs.head_sha }} check-run:${{ inputs.check_run_id }}"
on:
  workflow_dispatch:
    inputs:          # exactly §1's four
concurrency:
  group: thoryn-provisioning-${{ inputs.mode }}
  cancel-in-progress: false
permissions: {}
jobs:
  # thoryn-provisioning: apply-job
  provisioning:
    uses: thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0
    permissions: { id-token: write, checks: write, contents: read }
    with:
      mode: ${{ inputs.mode }}
      head_sha: ${{ inputs.head_sha }}
      check_run_id: ${{ inputs.check_run_id }}
      pr_number: ${{ inputs.pr_number }}
      plan-environment: <unprotected GitHub environment>
      apply-environment: <reviewed GitHub environment>
      issuer: https://auth.thoryn.io      # optional, and the other optional inputs of §3
```

Two seeders write this stub: the Thoryn GitHub App (oauthy/thoryn-provisioning `ThorynFiles.kt`) and, for a config
project, `thoryn project init config` (SSO-3971: `plan-environment: <production environment>-plan`,
`apply-environment: <production environment>`, `issuer:` the signed-in platform, pinned to the CLI's own release —
`ProjectSeeds.configStubYaml`, held to this contract by `ProjectInitConfigWorkflowTest`).

- **one job**, carrying only `uses`, `with`, `permissions` (`name`/`if`/`needs` tolerated) — `runs-on`, `timeout-minutes`
  and the environments are inputs of the reusable workflow; steps and secrets have no place here;
- `uses:` is **`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@<ref>`** with `<ref>` a `cli-v*` tag ≥
  **cli-v0.36.0** (the first release shipping the reusable workflow) or a full commit sha — a branch is refused (it moves
  under you). A `uses:` of any other workflow is **unverifiable**: the check says so and tells you to run it on that file;
- `with:` forwards the four dispatch inputs **verbatim** (`${{ inputs.<name> }}`), passes `plan-environment` and
  `apply-environment` as **different** literal environment names, and may pass any other input of §3 as a literal that
  satisfies its grammar; **a key that is not an input is refused**, named;
- job `permissions` are **exactly** `id-token: write`, `checks: write`, `contents: read` (what the called jobs declare;
  a called job can only lower what the caller grants). No `contents: write`: nothing is written back (§4);
- **no `secrets:`** on the job.

A stub pinned to a tag that does not exist yet fails at **dispatch time** with GitHub's "workflow file issue" (zero
jobs), not at merge time — which is why the first App dispatch after the merge that lands `provisioning.yml` needs the
release tag it pins to have been cut.

## 3. The reusable workflow (`reusable.*`) — the called side

`on: workflow_call` with exactly these inputs (`ProvisioningWorkflowContract.REUSABLE_INPUTS`):

| Input | Required | Default | Grammar | Purpose |
|---|---|---|---|---|
| `mode`, `head_sha`, `check_run_id`, `pr_number` | first three | `pr_number: ""` | forwarded `${{ inputs.<name> }}` | §1 |
| `plan-environment` | yes | — | GitHub environment name | the **unprotected** environment the plan job runs in — the trust's plan profile is keyed on it |
| `apply-environment` | yes | — | GitHub environment name | the **reviewed** environment the apply job runs in — required reviewers hold the run before any token can be minted; the trust pins it |
| `issuer` | no | `https://auth.thoryn.io` | `https://` origin | platform base issuer → `THORYN_ISSUER` / `THORYN_HUB` |
| `cli-version` | no | `""` | `cli-vX.Y.Z` | empty ⇒ **the release the workflow was called at** (see below) |
| `runs-on` | no | `ubuntu-latest` | a label, or a JSON array of labels | self-hosted pools; the runner needs bash, gh, jq, curl (Java is set up) |
| `timeout-minutes` | no | `30` | positive integer | each job |
| `config` | no | `.thoryn/workflow.yaml` | relative path | the run-time configuration (§5) |
| `consent-url` | no | `""` | `https://` base URL, no query/fragment | SSO-3723 — `THORYN_CONSENT_URL` for the CLI: a red job's `To fix — Option 2, in the browser:` link, `<url>/github/consent/run/<owner>/<repo>/<run_id>`, and (SSO-3738) Option 1 `thoryn access approve <owner>/<repo>/<run_id>` for the same consent; empty ⇒ §5 `consentUrl`, else the raw CLI commands alone, under a check-each-line warning |

Jobs **`plan`**, **`apply`** and (v2) **`import`** (§7), each: `if: inputs.mode == '<mode>'`; `runs-on` from `inputs.runs-on`
(`startsWith(…, '[') && fromJSON(…) || …`); `timeout-minutes` from the input; **`environment: ${{ inputs.<mode>-environment }}`
— a called job's environment resolves against the CALLER**, so the caller's reviewers gate it and the caller's trust
pins it (the import job runs in `plan-environment`, §7); permissions exactly §2's three; first step `actions/checkout` at `${{ inputs.head_sha }}`; then set up Java,
download the release's `thoryn.jar`, run **`thoryn provision workflow check --file <stub> --config <config> --output json`**
(the stub from `github.workflow_ref` — the CALLER's workflow path — the config from the input; a red check fails the job
with each fix named) and act on its `config` object: for every `files[]` entry `thoryn login --connection <connection>` then
`thoryn provision plan|apply --file <file>` (`apply --yes`, `--prune` / `--confirm` only as configured), the plan/apply
output into the step summary; **`THORYN_FIX_REQUEST`** on the sign-in/plan/apply step, **`THORYN_CONSENT_URL`** exported on it
from `consent-url` else the config's `consentUrl` (SSO-3723), and an
`actions/upload-artifact` (pinned to a commit) step `if: failure() && <fixRequest>` uploading **`thoryn-provision-request`**
(`if-no-files-found: ignore`, `retention-days: 7`); the apply job ends at **Applied** (no receipt, §4). The apply job
carries `# thoryn-provisioning: apply-job`.

**Pinning the CLI to the called ref.** GitHub gives a called job one reference to its own file: **`job.workflow_ref`**
— "the full ref of the workflow file that defines the current job; for jobs defined in a reusable workflow, this refers to
the reusable workflow file", e.g. `thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@refs/tags/cli-v0.36.0`
(`job.workflow_sha` is its commit; `github.workflow_ref` / `github.job_workflow_sha` name the CALLER's workflow — the
latter is no longer documented). The workflow reads it through `toJSON(job)` (actionlint 1.7.12's schema predates the
property; the `job` context is small and secret-free) and, when the ref is `refs/tags/cli-v*`, downloads that release —
so one pin in the stub (`uses: …@cli-v0.36.0`) selects both the workflow and the CLI. Any other ref (`@main`, a sha)
falls back to the latest `cli-v*` release with a `::notice`. `cli-version` overrides either way. Not available on GHES
(the fallback applies).

## 4. Nothing is written back (`reusable.no-write-back`)

Per oauthy ADR `2026-10-15-platform-is-the-ledger-no-committed-provisioning-receipt` (SSO-3708; the orchestrator's
SSO-3717 shape): no `contents: write`, no `pull-requests`, no `git push` / `git commit` / `gh pr create` — in any job,
the import job included. Ownership is the platform's
`owner` relation, not a committed receipt. Removals are never automated unless the configuration says so (§5; both
toggles default off).

## 5. The run-time configuration — `.thoryn/workflow.yaml` (`config.*`)

Schema `cli/src/main/resources/examples/workflow.schema.json`; loader `WorkflowConfig` (unknown keys refused at every
level; each value's grammar checked). Absent ⇒ the built-in defaults. Keys: `apiVersion: thoryn.io/workflow/v1`,
`provider` (`github_actions` only — Forgejo is a recorded gap, see README), `files[] {file, connection}` (one or many; a
connection defaults to the `connection.json` beside its file), `env` (`THORYN_*` names only, not workflow-owned, never
credential-shaped; exported, never evaluated), `fixRequest` (default true), `consentUrl` (SSO-3723 — the browser
consent base URL, `https://` without query or fragment; `THORYN_CONSENT_URL` for the CLI when the `consent-url` input is
empty; default empty ⇒ the raw CLI commands alone, under a check-each-line warning; set ⇒ Option 1 is `thoryn access approve`, SSO-3738), `apply.prune` / `apply.destroy` (default false) / `apply.confirm`
(workspace slug).

`config.valid` (SSO-3970) also LOADS every file the configuration lists — each `files[].file` with the loader
`thoryn provision plan` uses, each `files[].connection` with the one `thoryn login --connection` uses. A file that is not
committed, is not valid YAML/JSON, declares an unknown `apiVersion`, or breaks a rule of its file (a kind from the other
part, SSO-3962, among them) fails `config.valid`, which names the file and the loader's reason. An `emailTemplate`'s
`spec.bodyFile` resolves next to its file, exactly as `thoryn provision plan` resolves it (SSO-4056: cli-v0.52.0 and
earlier read it with no directory and refused every body file). When none of the
configured provisioning files loads the detail says so ("no configured provisioning file loads, so nothing can be planned
or applied"). The rules that read the files (`config.secret-delivery`, `config.trust-scopes`) then fail as
`not checked: <file> could not be loaded (see config.valid)` — they never pass on the files that did load and never drop
out of the report. A configuration that lists no file at all says so on `config.valid` ("no provisioning files
configured"); today's schema refuses an empty `files:`, and an absent one means the default `.thoryn/provision.yaml`.

`config.secret-delivery` (SSO-3921, reshaped by SSO-3954) reads every configured provisioning file that is committed: the
apply job runs on a hosted runner with no kubeconfig, no `--secret-file` and no TTY. An application that MINTS a client
secret on create (confidential, `client_secret_basic` or no declared method; not `readOnly`) **passes** with no
`secretSink` or with `secretSink: { kind: customerManaged }` — the default since SSO-3954 (oauthy ADR 2026-10-14 amended
2026-10-25, SSO-3951: Thoryn owns the secret lifecycle, the customer owns delivery): `apply` discards the create's value,
grants nothing, and a person mints the secret (`thoryn clients rotate-secret <clientId> --secret-file …`) and stores it in
the customer's secret infrastructure. The rule's detail carries that notice per application — it is where the semantics are
explained, not a failure. Still red: a `kubernetesSecret` sink has no cluster to reach; a `file` sink writes onto a runner
that is gone when the job ends (green, the secret lost); the fix is to drop the sink. A `workloadPull` sink (rung 3, the
pod pull) passes but is reported DEPRECATED (SSO-3951; SSO-3953 removes it). A public or secret-less (`private_key_jwt`,
`federated_assertion`) client passes silently.

`config.trust-scopes` (SSO-3926) reads every configured `{file, connection}` pair that is committed and loads: the scopes
the file needs (derived from its kinds, `grants:` blocks, bindings and secret sinks — each the `@PreAuthorize` gate of the
product-api endpoint the engine calls; table in the README and in `ScopeRequirements`) are held against the connection's
`auth.scopes` — the trust's apply profile, which the apply job requests exactly — and the PLAN scopes against the trust's
plan profile as the connection implies it (a profile without explicit scopes is every `.read` scope of the trust; an
explicit one is a subset of them). A missing scope fails the rule naming the scope, the resources that need it, and the
profile to add it to. The repository identity cannot read its trust's profile (`tenant:workload-identity.read`), so the
rule derives it; `provision plan` holds the plan scopes against the minted token before its first call, and maps a scope
`403` (`access_denied` / `insufficient_scope`) to the same message. A file or connection that does not load fails the rule
as not checked (SSO-3970; the reason is on `config.valid`).

## 6. A hand-written workflow (`custom.*`) — unsupported

`thoryn provision workflow check` evaluates §1's rules plus one (`custom.jobs`: a job gated on each mode, in two different
environments, with `id-token: write` + `checks: write`, checking out `head_sha` first, uploading `thoryn-provision-request`
on failure) and labels the result **UNSUPPORTED**: this is what the App would need from it, not a shape Thoryn promotes.
The reason there is no script hook: the identity and the review gate must stay inside the reusable workflow, where the
contract can hold them. When configuration is not enough, file a product gap.

## Versioning

`contractVersion: 2` (SSO-3991). v1 → v2 changed what a valid stub may look like: `mode` may also offer `import`
(`dispatch.inputs` accepts `[plan, apply]` or `[plan, apply, import]`), with the new rule `dispatch.import-capable`;
the reusable workflow gained the `import` job (`reusable.jobs` now pins three jobs; new rule `reusable.import-job`). A
v1 stub is still valid and is never dispatched `import`. `--output json` gained `importCapable`. The rule ids above (`dispatch.*`, `stub.*`, `reusable.*`, `config.*`, `custom.*`, `common.*`) are
the stable names the check prints and `--output json` carries.

SSO-3738 did **not** bump it: what a valid stub or reusable workflow looks like is unchanged (same inputs, same
`consentUrl` key) — only the text a red job prints moved (Option 1 is `thoryn access approve <owner>/<repo>/<run_id>`
when a consent link exists). Nor did it bump the fix request's own `version` (still `1`): its shape is unchanged; only
what `options.cli` holds moved, and the App renders its own options from the run rather than reading that field.

SSO-3921 did **not** bump it either: the stub and the reusable workflow are unchanged. It adds `config.secret-delivery`,
which reads the provisioning FILES the configuration names — a repository whose file declares a secret-minting
application without `secretSink: { kind: workloadPull }` now fails the check, which is what its first CI apply would
have done (`undelivered_secrets`) or, with a `file` sink, silently lost.

SSO-3954 did **not** bump it: the stub and the reusable workflow are unchanged. It turns `config.secret-delivery`'s
no-sink case from a failure into a PASS with a notice (the customer manages the secret — the default), keeps the
`kubernetesSecret` / `file` failures, and reports `workloadPull` deprecated. A repository that was red only for lacking a
sink is green on the next run with no edit; one that declared `workloadPull` to satisfy the old rule can now drop the sink
(and the trust it named) and have a person revoke the grant and delete the trust — the README's "Leaving `workloadPull`".

SSO-3926 did **not** bump it: the stub and the reusable workflow are unchanged. It adds `config.trust-scopes`, which reads
the configured files AND their connections — a repository whose connection lacks a scope its file needs now fails the
check, which is what its plan job would have done mid-plan with `403 access_denied` (thoryn-cicd run 39917407017).

SSO-3970 did **not** bump it: the stub, the reusable workflow and the rule ids are unchanged. A configured file that does
not load used to pass `config.valid` (it only checked the file was committed) and silently drop `config.secret-delivery`
and `config.trust-scopes` from the report, so a project whose one file was broken printed "OK". Now it fails, as its
plan job would have. A repository that was green with a broken configured file is red on the next run, naming the file.

## 7. Contract v2 — `mode: import` (`dispatch.import-capable`, `reusable.import-job`)

**Status: implemented** in cli-v0.51.0 (SSO-3991; decided under SSO-3989 by the product owner on 2026-10-26; the
`provision import` changes it builds on are SSO-3990). The design and its reasons are thoryn-provisioning
`adrs/2026-09-30-starter-orchestrator-service.md`, *Amendment 2026-10-26* (§13). After a config project's setup pull
request is merged, the App dispatches an import on the default branch; the job imports the workspace's live configuration
as the repository's own read-only identity and hands the files to the App as an artifact; the App opens a pull request
with them, whose plan is all `noop`.

- **§1** — `mode` is `[plan, apply]` or `[plan, apply, import]`. `import` is dispatched only on the default branch, by the
  App, with `head_sha` = the setup pull request's merge commit, `check_run_id` = the *Thoryn configuration import* check
  run and `pr_number` = the setup pull request, and only to a file `dispatch.import-capable` passes with `import` offered
  (`importCapable: true`). The `run-name` and concurrency rules are unchanged; `import` gets its own group through
  `${{ inputs.mode }}`.
- **§2** — nothing else in the stub changes: same single job, same three permissions, no secrets. Opting in is two
  edits: `import` in the options, and the `uses:` pin at cli-v0.51.0 or newer.
- **§3 — the `import` job** (`reusable.jobs` + `reusable.import-job`): `if: inputs.mode == 'import'`;
  **`environment: ${{ inputs.plan-environment }}`**, so the hub mints the trust's read-only plan profile (never
  `apply-environment`); the same three permissions; checkout at `head_sha` with `persist-credentials: false`; the same
  CLI download (it also requires `provision workflow import-summary`, refusing an older `cli-version` by name) and the
  same `workflow check`. Then, for the i-th `files[]` entry: `thoryn login --connection <connection>`; copy the committed
  file to `$RUNNER_TEMP/thoryn-import/<file>`; `thoryn provision import --for-workflow <file> --config <config> --file
  <copy> --write --output json` into `<work>/<i>.import.json`; `thoryn provision plan --file <copy> --output json` into
  `<work>/<i>.plan.json` (its exit code into `<i>.plan.exit` — a preview that is not all `noop` is reported, not fatal).
  Finally `thoryn provision workflow import-summary` checks the artifact directory and writes `import-summary.json`
  (below). It never runs `provision apply` / `destroy`. It uploads **`thoryn-import`** (`actions/upload-artifact` pinned
  to a commit, `include-hidden-files: true` — the files live under `.thoryn/` — `if-no-files-found: error`,
  `retention-days: 7`, only on success), and on failure the same fix request as the plan job.
- **The artifact** — exactly each configured file at its repository path, **plus the body files a configured file
  references** (SSO-4042: an `emailTemplate`'s `spec.bodyFile`, relative to its file — staged from the checkout for a
  committed template, written by the import for a live one; SSO-4057: a `legalDocument`'s the same way, under
  `legal/`), plus `import-summary.json` at the root:

  ```json
  {
    "version": 1,
    "contractVersion": 2,
    "headSha": "<merge commit>",
    "files": [{
      "path": ".thoryn/environments/production/provision.yaml",
      "connection": ".thoryn/environments/production/connection.json",
      "apiVersion": "thoryn.io/tenant/v1",
      "bytes": 812,
      "sha256": "<hex of the file in the artifact>",
      "bodyFiles": ["emails/magic_link.html"],
      "imported": [{ "kind": "emailProvider", "name": "emailProvider", "environment": null, "readOnly": true, "note": "<why>" }],
      "notImported": ["user — 1 production-plane user(s) not imported: …"],
      "plan": { "exit": 0, "counts": { "create": 0, "update": 0, "remove": 0, "noop": 4, "…": 0 }, "allNoop": true, "notNoop": [] }
    }]
  }
  ```

  `notNoop` rows are `{kind, name, environment, action, fields}` — the NAMES of the fields that differ, never their values.
  The summary is a fixed field list (`ImportSummary`): no `spec`, no id, no value of the configuration; the files are what
  the CLI renders, a fixed field list per kind, and the API returns no secret. Bounds: 1 MiB per file, 1 MiB for the
  summary, 8 MiB for the artifact. The step refuses (exit 4, nothing uploaded) a stray file or symbolic link in the
  artifact directory (a file is not stray when a configured file names it as `bodyFile`; `bodyFiles` lists them, paths
  only), a configured file missing from it or not loading, a bound exceeded, a preview that did not run, and a
  `head_sha` that is not a commit — the shape the App validates on download (§13.4), refused here first.
- **§4** — unchanged. The import job holds `contents: read` and pushes nothing (`reusable.no-write-back` covers it); the
  App commits the files to its own branch.
- **What `provision import` does for this** (SSO-3990): renders only the target file's part, is scope-aware against the
  file's connection, routes each object to one configured file by plane, renders `emailProvider` / `federationMember`
  `readOnly`, never imports the repository's own trusts or production-plane users, imports sandbox test users, renders
  `role`, and guarantees import → plan is all `noop` for every kind it renders. See the README, "What `import` writes
  plans as all `noop`".
